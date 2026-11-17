import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import multer from 'multer';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const ROOT=path.dirname(fileURLToPath(import.meta.url));
const DATA=process.env.DATA_DIR||path.join(ROOT,'data'); fs.mkdirSync(DATA,{recursive:true});
const UPLOADS=path.join(DATA,'product-images'); fs.mkdirSync(UPLOADS,{recursive:true});
const db=new Database(path.join(DATA,'emprendemos.sqlite')); db.pragma('journal_mode=WAL'); db.pragma('foreign_keys=ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('customer','seller','driver','operator')), access_status TEXT NOT NULL DEFAULT 'active', business_name TEXT, business_address TEXT, phone TEXT, hours TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,seller_id INTEGER NOT NULL REFERENCES users(id),name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', price_cents INTEGER NOT NULL CHECK(price_cents>0),category TEXT NOT NULL DEFAULT 'Comida',photo_url TEXT NOT NULL DEFAULT '',available INTEGER NOT NULL DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,customer_id INTEGER NOT NULL REFERENCES users(id),seller_id INTEGER NOT NULL REFERENCES users(id),driver_id INTEGER REFERENCES users(id),status TEXT NOT NULL DEFAULT 'pending_payment',address TEXT NOT NULL,notes TEXT NOT NULL DEFAULT '',subtotal_cents INTEGER NOT NULL,delivery_fee_cents INTEGER NOT NULL DEFAULT 0,delivery_pay_cents INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL REFERENCES orders(id),product_id INTEGER REFERENCES products(id),name TEXT NOT NULL,qty INTEGER NOT NULL,unit_price_cents INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ratings(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL UNIQUE REFERENCES orders(id),driver_id INTEGER NOT NULL REFERENCES users(id),customer_id INTEGER NOT NULL REFERENCES users(id),stars INTEGER NOT NULL CHECK(stars BETWEEN 1 AND 5),comment TEXT NOT NULL DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL REFERENCES orders(id),driver_id INTEGER NOT NULL REFERENCES users(id),reporter_id INTEGER NOT NULL REFERENCES users(id),reason TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending_review',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS settlements(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL UNIQUE REFERENCES orders(id),driver_id INTEGER NOT NULL REFERENCES users(id),amount_cents INTEGER,status TEXT NOT NULL DEFAULT 'unconfigured',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);

// Verificación manual de repartidores. Archivos privados: nunca expuestos con express.static.
const ID_DIR=path.join(DATA,'driver-identity');fs.mkdirSync(ID_DIR,{recursive:true});
db.exec(`CREATE TABLE IF NOT EXISTS driver_verifications (
 driver_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 photo_file TEXT, document_file TEXT,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','changes_requested','rejected')),
 note TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_at TEXT, reviewed_by INTEGER REFERENCES users(id)
);`);
// Datos de motocicleta: tabla adicional, sin eliminar ni modificar registros anteriores.
db.exec(`CREATE TABLE IF NOT EXISTS driver_vehicles (
 driver_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 brand TEXT NOT NULL, model TEXT NOT NULL, color TEXT NOT NULL, plate TEXT NOT NULL,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);`);
function vehicle(id){return db.prepare('SELECT brand,model,color,plate,updated_at FROM driver_vehicles WHERE driver_id=?').get(id)||null;}
function vehicleValues(x){
 const brand=short(x?.brand,50),model=short(x?.model,50),color=short(x?.color,40),plate=short(x?.plate,16).toUpperCase().replace(/\s+/g,'');
 if(brand.length<2||model.length<1||color.length<2||!(/^[A-Z0-9-]{4,16}$/.test(plate)))return null;
 return {brand,model,color,plate};
}
function saveVehicle(id,v){db.prepare(`INSERT INTO driver_vehicles(driver_id,brand,model,color,plate) VALUES(?,?,?,?,?)
 ON CONFLICT(driver_id) DO UPDATE SET brand=excluded.brand,model=excluded.model,color=excluded.color,plate=excluded.plate,updated_at=CURRENT_TIMESTAMP`).run(id,v.brand,v.model,v.color,v.plate);}
function verification(id){return db.prepare('SELECT driver_id,status,note,updated_at,photo_file IS NOT NULL AS has_photo,document_file IS NOT NULL AS has_document FROM driver_verifications WHERE driver_id=?').get(id)||null;}
function isVerified(id){return !!db.prepare("SELECT 1 FROM driver_verifications WHERE driver_id=? AND status='approved' AND photo_file IS NOT NULL AND document_file IS NOT NULL").get(id);}
const idUpload=multer({storage:multer.memoryStorage(),limits:{fileSize:3*1024*1024,files:2}});
function photoExt(buf){if(buf.length>4&&buf[0]===255&&buf[1]===216&&buf[2]===255)return '.jpg';if(buf.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))return '.png';if(buf.toString('ascii',0,4)==='RIFF'&&buf.toString('ascii',8,12)==='WEBP')return '.webp';return null;}
function savePrivate(buf){const ext=photoExt(buf);if(!ext)throw new Error('Formato no permitido. Sube JPG, PNG o WEBP.');const file=crypto.randomUUID()+ext;fs.writeFileSync(path.join(ID_DIR,file),buf,{flag:'wx',mode:0o600});return file;}
const columns=db.pragma('table_info(users)');
if(!columns.some(c=>c.name==='customer_code'))db.exec('ALTER TABLE users ADD COLUMN customer_code TEXT');
const APP=express(); APP.disable('x-powered-by'); APP.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'"],imgSrc:["'self'",'https:','data:'],connectSrc:["'self'"]}}})); APP.use(express.json({limit:'50kb'})); APP.use(cookieParser()); APP.use(express.static(path.join(ROOT,'public')));
APP.use('/product-images',express.static(UPLOADS,{index:false,fallthrough:false,immutable:true,maxAge:'30d',setHeaders(res){res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Content-Security-Policy',"default-src 'none'; sandbox");}}));
APP.use('/api',rateLimit({windowMs:60_000,limit:200,standardHeaders:'draft-7',legacyHeaders:false}));
const authLimit=rateLimit({windowMs:15*60_000,limit:20,standardHeaders:'draft-7',legacyHeaders:false});
const fail=(res,status,error)=>res.status(status).json({error});
const normalize=x=>typeof x==='string'?x.trim():'';
const short=(x,n)=>normalize(x).slice(0,n);
const roles=['customer','seller','driver'];
const price=(x)=>Number.isSafeInteger(x)&&x>0&&x<=10000000;
const tokenHash=x=>crypto.createHash('sha256').update(x).digest('hex');
const demo=()=>process.env.PAYMENTS_MODE!=='production';
const settings=()=>({demo:demo(),sellerFee:process.env.SELLER_ACCESS_FEE_CENTS?Number(process.env.SELLER_ACCESS_FEE_CENTS):null,driverFee:process.env.DRIVER_ACCESS_FEE_CENTS?Number(process.env.DRIVER_ACCESS_FEE_CENTS):null,deliveryPay:process.env.DELIVERY_PAY_CENTS?Number(process.env.DELIVERY_PAY_CENTS):null});
const userView=u=>({id:u.id,name:u.name,email:u.email,role:u.role,access_status:u.access_status,business_name:u.business_name,business_address:u.business_address,phone:u.phone,hours:u.hours,customer_code:u.role==='customer'?u.customer_code:null,verification:u.role==='driver'?verification(u.id):null,vehicle:u.role==='driver'?vehicle(u.id):null});
function session(res,id){const t=crypto.randomBytes(32).toString('base64url');db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(tokenHash(t),id,Date.now()+30*86400000);res.cookie('emprendemos_session',t,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',path:'/',maxAge:30*86400000});}
function auth(req,res,next){const t=req.cookies.emprendemos_session;if(!t||typeof t!=='string')return fail(res,401,'Inicia sesión.');const u=db.prepare('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?').get(tokenHash(t),Date.now());if(!u)return fail(res,401,'Tu sesión terminó.');req.user=u;next();}
const only=(...allowed)=>(req,res,next)=>allowed.includes(req.user.role)?next():fail(res,403,'No tienes permisos para realizar esta acción.');
const active=(req,res,next)=>(req.user.role==='customer'||req.user.role==='operator'||req.user.access_status==='active')?next():fail(res,403,'Tu acceso aún no está habilitado.');
const changeStatus=(id,status)=>db.prepare('UPDATE orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status,id);
// Correos transaccionales: outbox persistente, envío mediante Resend.
// No se envían contraseñas, PIN, códigos de cliente, direcciones de entrega ni documentos.
db.exec(`CREATE TABLE IF NOT EXISTS email_outbox (
 id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 recipient TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL,
 event_key TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, sent_at TEXT, last_error TEXT
);`);
const mailEnabled=()=>Boolean(process.env.RESEND_API_KEY&&process.env.EMAIL_FROM);
const mailAddress=(email)=>typeof email==='string'&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)&&email.length<161;
function queueEmail(userId,eventKey,subject,body){
 if(!mailEnabled())return;
 const u=db.prepare('SELECT email FROM users WHERE id=?').get(userId);
 if(!mailAddress(u?.email))return;
 db.prepare('INSERT OR IGNORE INTO email_outbox(user_id,recipient,subject,body,event_key) VALUES(?,?,?,?,?)')
   .run(userId,u.email,subject.slice(0,160),body.slice(0,2000),eventKey);
}
function notifyOperator(eventKey,subject,body){
 const u=db.prepare("SELECT id FROM users WHERE role='operator'").all();
 for(const x of u)queueEmail(x.id,eventKey+':'+x.id,subject,body);
}
const siteUrl='https://emprendemosapp.com';
const notice=(text)=>text+'\n\nConsulta los detalles iniciando sesión en Emprendemos: '+siteUrl+'\nSi no reconoces esta actividad, contacta al equipo de Emprendemos.';
function orderNotice(id,status){
 const o=db.prepare('SELECT customer_id,seller_id,driver_id FROM orders WHERE id=?').get(id);
 if(!o)return;
 const labels={pending_payment:'Pedido registrado: pendiente de pago',paid:'Pedido pagado (demostración)',preparing:'Pedido en proceso',shipping:'Pedido en envío',doorstep:'Pedido en tu puerta',delivered:'Pedido entregado'};
 const label=labels[status]||'Actualización de pedido';
 for(const [role,userId] of [['customer',o.customer_id],['seller',o.seller_id],['driver',o.driver_id]]){
  if(userId)queueEmail(userId,'order:'+id+':'+status+':'+role,`Emprendemos · Pedido #${id}: ${label}`,notice(`El pedido #${id} cambió a: ${label}.`));
 }
}
// Avisos para nuevas entregas. Sin exponer domicilio ni datos del cliente.
// Clave unica por pedido/repartidor: no genera avisos duplicados al reintentar.
function notifyAvailableDrivers(orderId){
 const order=db.prepare(`SELECT o.id,s.business_name
  FROM orders o JOIN users s ON s.id=o.seller_id
  WHERE o.id=? AND o.status='preparing' AND o.driver_id IS NULL`).get(orderId);
 if(!order)return;
 const drivers=db.prepare(`SELECT u.id FROM users u
  JOIN driver_verifications v ON v.driver_id=u.id
  JOIN driver_vehicles m ON m.driver_id=u.id
  WHERE u.role='driver' AND u.access_status='active'
   AND v.status='approved' AND v.photo_file IS NOT NULL AND v.document_file IS NOT NULL`).all();
 for(const driver of drivers){
  queueEmail(driver.id,`new-delivery:${orderId}:driver:${driver.id}`,
   `Emprendemos · Nueva entrega disponible #${orderId}`,
   notice(`¡Hay una nueva entrega disponible!\n\nPedido #${orderId}\nNegocio: ${order.business_name||'Emprendemos'}\n\nIngresa a tu cuenta para consultar y aceptar la entrega. La dirección del cliente se muestra después de aceptarla.`));
 }
}
function queueRegistration(id,role){
 const label={customer:'cliente',seller:'vendedor',driver:'repartidor'}[role]||'usuario';
 queueEmail(id,'register:'+id,'Bienvenido a Emprendemos',notice(`Tu cuenta de ${label} se registró correctamente. ${role==='customer'?'Ya puedes explorar productos.':'La activación de acceso y, cuando corresponda, la revisión de identidad se gestionan desde tu cuenta.'}`));
 notifyOperator('new-account:'+id,'Emprendemos · Nuevo registro',notice(`Se registró una nueva cuenta de ${label} (#${id}).`));
}
let processingMail=false;
async function deliverPendingEmail(){
 if(processingMail||!mailEnabled())return;
 processingMail=true;
 try{
  const pending=db.prepare("SELECT * FROM email_outbox WHERE status='pending' AND next_attempt_at <= ? ORDER BY id LIMIT 10").all(Date.now());
  for(const item of pending){
   try{
    const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),10000);
    let resp;
    try{resp=await fetch('https://api.resend.com/emails',{
      method:'POST',signal:controller.signal,
      headers:{Authorization:`Bearer ${process.env.RESEND_API_KEY}`,'Content-Type':'application/json','User-Agent':'emprendemos/1.0','Idempotency-Key':`emprendemos-notice-${item.id}`},
      body:JSON.stringify({from:process.env.EMAIL_FROM,to:[item.recipient],subject:item.subject,text:item.body})
    });}finally{clearTimeout(timer);}
    if(resp.ok){db.prepare("UPDATE email_outbox SET status='sent',sent_at=CURRENT_TIMESTAMP,last_error=NULL WHERE id=?").run(item.id);}
    else {const body=(await resp.text()).slice(0,200);throw new Error(`HTTP ${resp.status}: ${body}`);}
   }catch(error){
    const attempts=item.attempts+1;
    const retry=Date.now()+Math.min(3600000,60000*2**Math.min(attempts,6));
    db.prepare('UPDATE email_outbox SET attempts=?,next_attempt_at=?,last_error=?,status=? WHERE id=?')
      .run(attempts,retry,String(error.message).slice(0,250),attempts>=8?'failed':'pending',item.id);
    console.error('No se pudo enviar aviso por correo #'+item.id, String(error.message).slice(0,180));
   }
  }
 }finally{processingMail=false;}
}
const mailWorker=setInterval(()=>{deliverPendingEmail().catch(e=>console.error('Error del trabajador de correos',e.message));},15000);
mailWorker.unref();
const orderFull=id=>{const o=db.prepare(`SELECT o.*,s.business_name AS seller_name,c.name AS customer_name,d.name AS driver_name FROM orders o JOIN users s ON o.seller_id=s.id JOIN users c ON o.customer_id=c.id LEFT JOIN users d ON o.driver_id=d.id WHERE o.id=?`).get(id);if(!o)return null;return {...o,driver_verified:o.driver_id?isVerified(o.driver_id):false,items:db.prepare('SELECT name,qty,unit_price_cents FROM order_items WHERE order_id=?').all(id),rated:!!db.prepare('SELECT id FROM ratings WHERE order_id=?').get(id)};};


APP.post('/api/driver/vehicle',auth,only('driver'),(req,res)=>{
 const v=vehicleValues(req.body);if(!v)return fail(res,400,'Completa marca, modelo, color y placa válida de tu motocicleta.');
 const old=vehicle(req.user.id);
 const changed=!old||['brand','model','color','plate'].some(k=>old[k]!==v[k]);
 const fn=db.transaction(()=>{
  saveVehicle(req.user.id,v);
  if(changed&&old){db.prepare("UPDATE driver_verifications SET status='pending',note='Datos de motocicleta actualizados; requiere nueva revisión.',updated_at=CURRENT_TIMESTAMP WHERE driver_id=?").run(req.user.id);queueEmail(req.user.id,'vehicle:'+req.user.id+':'+Date.now(),'Emprendemos · Motocicleta actualizada',notice('Se actualizaron los datos de tu motocicleta. Tu verificación puede requerir una nueva revisión.'));}
 });fn();res.json({ok:true,vehicle:v,review_required:changed&&!!old});
});
// Registro de fotografía de rostro y documento (ambos privados). Solicitud pendiente hasta revisión humana.
APP.post('/api/driver/identity',auth,only('driver'),(req,res,next)=>{
 idUpload.fields([{name:'face',maxCount:1},{name:'document',maxCount:1}])(req,res,err=>{
  if(!err)return next();
  if(err instanceof multer.MulterError){
   const message=err.code==='LIMIT_FILE_SIZE'?'Cada imagen debe pesar como máximo 3 MB.':
    err.code==='LIMIT_FILE_COUNT'?'Debes enviar solo dos imágenes (rostro e identificación).':
    err.code==='LIMIT_UNEXPECTED_FILE'?'Selecciona una foto del rostro y una identificación, una en cada campo.':
    'No se pudieron recibir las imágenes. Intenta de nuevo.';
   return fail(res,400,message);
  }
  return fail(res,400,'No se pudieron procesar las imágenes. Revisa los archivos e intenta de nuevo.');
 });
},(req,res)=>{
 if(!vehicle(req.user.id))return fail(res,400,'Primero registra los datos de tu motocicleta.');
 const face=req.files?.face?.[0],document=req.files?.document?.[0];
 if(!face||!document)return fail(res,400,'Necesitamos una foto de rostro y una identificación para solicitar revisión.');
 let fp,dp;try{fp=savePrivate(face.buffer);dp=savePrivate(document.buffer);}catch(e){if(fp)fs.rmSync(path.join(ID_DIR,fp),{force:true});return fail(res,400,e.message);}
 const old=db.prepare('SELECT * FROM driver_verifications WHERE driver_id=?').get(req.user.id);
 db.prepare(`INSERT INTO driver_verifications(driver_id,photo_file,document_file,status,note,reviewed_at,reviewed_by,updated_at)
 VALUES(?,?,?,'pending','',NULL,NULL,CURRENT_TIMESTAMP)
 ON CONFLICT(driver_id) DO UPDATE SET photo_file=excluded.photo_file,document_file=excluded.document_file,status='pending',note='',reviewed_at=NULL,reviewed_by=NULL,updated_at=CURRENT_TIMESTAMP`).run(req.user.id,fp,dp);
 for(const f of [old?.photo_file,old?.document_file])if(f)fs.rmSync(path.join(ID_DIR,f),{force:true});
 queueEmail(req.user.id,'identity-request:'+req.user.id+':'+Date.now(),'Emprendemos · Verificación recibida',notice('Recibimos tu solicitud de revisión de identidad. Te avisaremos cuando se revise.'));notifyOperator('identity-request:'+req.user.id+':'+Date.now(),'Emprendemos · Identidad pendiente',notice('Hay una solicitud nueva de verificación de repartidor que necesita revisión.'));res.json({verification:verification(req.user.id),note:'Solicitud recibida; un operador debe revisarla.'});
});
APP.get('/api/driver/photo/:id',auth,(req,res)=>{
 const driverId=Number(req.params.id);if(!Number.isSafeInteger(driverId))return fail(res,404,'No existe.');
 const permitted=req.user.role==='operator'||(req.user.role==='driver'&&req.user.id===driverId)||
 (req.user.role==='customer'&&!!db.prepare('SELECT 1 FROM orders WHERE customer_id=? AND driver_id=? LIMIT 1').get(req.user.id,driverId));
 if(!permitted)return fail(res,403,'Sin acceso a esta foto.');
 const v=db.prepare('SELECT photo_file,status FROM driver_verifications WHERE driver_id=?').get(driverId);
 if(!v?.photo_file||(req.user.role==='customer'&&v.status!=='approved'))return fail(res,404,'Fotografía no disponible.');
 const file=path.join(ID_DIR,path.basename(v.photo_file));if(!fs.existsSync(file))return fail(res,404,'Fotografía no disponible.');
 res.setHeader('Cache-Control','private, no-store');res.setHeader('X-Content-Type-Options','nosniff');res.type(path.extname(file)==='.png'?'png':path.extname(file)==='.webp'?'webp':'jpeg');res.sendFile(file);
});
APP.get('/api/operator/driver-document/:id',auth,only('operator'),(req,res)=>{
 const v=db.prepare('SELECT document_file FROM driver_verifications WHERE driver_id=?').get(req.params.id);
 if(!v?.document_file)return fail(res,404,'Identificación no disponible.');const file=path.join(ID_DIR,path.basename(v.document_file));if(!fs.existsSync(file))return fail(res,404,'No disponible.');
 res.setHeader('Cache-Control','private, no-store');res.setHeader('X-Content-Type-Options','nosniff');res.type(path.extname(file)==='.png'?'png':path.extname(file)==='.webp'?'webp':'jpeg');res.sendFile(file);
});
APP.post('/api/orders/:id/identity-report',auth,only('customer'),(req,res)=>{
 const o=db.prepare('SELECT * FROM orders WHERE id=? AND customer_id=? AND driver_id IS NOT NULL').get(req.params.id,req.user.id);
 if(!o)return fail(res,404,'Pedido no encontrado.');
 const already=db.prepare("SELECT 1 FROM incidents WHERE order_id=? AND reporter_id=? AND reason LIKE 'IDENTIDAD:%'").get(o.id,req.user.id);
 if(already)return fail(res,409,'Ya reportaste una diferencia de identidad en este pedido.');
 const labels={different:'La persona no coincide con la fotografía',substitute:'Llegó otra persona en su lugar',refused:'Se negó a identificarse',unsafe:'Me sentí inseguro durante la entrega'};
 const category=req.body?.category,details=normalize(req.body?.details);
 if(!Object.hasOwn(labels,category)||details.length<10||details.length>500)return fail(res,400,'Selecciona el motivo y describe lo ocurrido (10 a 500 caracteres).');
 db.prepare('INSERT INTO incidents(order_id,driver_id,reporter_id,reason) VALUES(?,?,?,?)').run(o.id,o.driver_id,req.user.id,'IDENTIDAD: '+labels[category]+' — '+details);
 notifyOperator('identity-report:'+o.id+':'+req.user.id,'Emprendemos · Reporte de identidad',notice(`Se recibió un reporte de identidad del pedido #${o.id}. Revísalo en el panel de operación.`));res.json({ok:true,note:'Reporte enviado a revisión humana.'});
});
APP.post('/api/operator/driver-review/:id',auth,only('operator'),(req,res)=>{
 const status=req.body?.status,note=short(req.body?.note,300);
 if(!['approved','changes_requested','rejected'].includes(status))return fail(res,400,'Estado incorrecto.');
 const v=db.prepare('SELECT * FROM driver_verifications WHERE driver_id=?').get(req.params.id);
 if(!v?.photo_file||!v?.document_file)return fail(res,409,'Faltan imágenes para revisar.');
 if(status==='approved'&&!vehicle(Number(req.params.id)))return fail(res,409,'El repartidor debe completar los datos de motocicleta antes de su aprobación.');
 db.prepare('UPDATE driver_verifications SET status=?,note=?,reviewed_at=CURRENT_TIMESTAMP,reviewed_by=?,updated_at=CURRENT_TIMESTAMP WHERE driver_id=?').run(status,note,req.user.id,req.params.id);
 queueEmail(Number(req.params.id),'driver-review:'+req.params.id+':'+status+':'+Date.now(),'Emprendemos · Estado de verificación',notice(`Tu solicitud de identidad cambió a: ${status}. Revisa tu cuenta para más detalles.`));res.json({ok:true});
});
APP.get('/api/config',(req,res)=>res.json(settings()));
APP.post('/api/register',authLimit,(req,res)=>{
 const {name,email,password,role,business_name,business_address,phone,hours}=req.body||{};
 const nm=short(name,70), em=short(email,160).toLowerCase(),pw=typeof password==='string'?password:'';
 if(nm.length<2||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)||pw.length<10||pw.length>128||!roles.includes(role))return fail(res,400,'Revisa nombre, correo, contraseña (mínimo 10 caracteres) y tipo de cuenta.');
 if(role==='seller'&&(short(business_name,100).length<2||short(business_address,250).length<6))return fail(res,400,'Agrega nombre y dirección del negocio.');
 if(role==='driver'&&short(phone,30).length<8)return fail(res,400,'Agrega teléfono de contacto.');
 const moto=role==='driver'?vehicleValues(req.body):null;
 if(role==='driver'&&!moto)return fail(res,400,'Completa marca, modelo, color y placa válida de tu motocicleta.');
 try {const access=role==='customer'?'active':'pending_payment';const r=db.prepare(`INSERT INTO users(name,email,password_hash,role,access_status,business_name,business_address,phone,hours) VALUES(?,?,?,?,?,?,?,?,?)`).run(nm,em,bcrypt.hashSync(pw,12),role,access,role==='seller'?short(business_name,100):null,role==='seller'?short(business_address,250):null,short(phone,30)||null,role==='seller'?short(hours,300)||'Horario por confirmar':null);if(role==='customer'){const code='EMP-'+crypto.randomBytes(4).toString('hex').toUpperCase();db.prepare('UPDATE users SET customer_code=? WHERE id=?').run(code,r.lastInsertRowid);}if(role==='driver')saveVehicle(r.lastInsertRowid,moto);session(res,r.lastInsertRowid);queueRegistration(r.lastInsertRowid,role);res.status(201).json({user:userView(db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid))});}
 catch(e){if(e.code?.startsWith('SQLITE_CONSTRAINT'))return fail(res,409,'Ese correo ya está registrado.');throw e;}
});
APP.post('/api/login',authLimit,(req,res)=>{const em=short(req.body?.email,160).toLowerCase(),pw=req.body?.password;const u=db.prepare('SELECT * FROM users WHERE email=?').get(em);if(!u||typeof pw!=='string'||!bcrypt.compareSync(pw,u.password_hash))return fail(res,401,'Correo o contraseña incorrectos.');session(res,u.id);if(process.env.EMAIL_NOTIFY_LOGINS!=='false')queueEmail(u.id,'login:'+u.id+':'+crypto.randomUUID(),'Emprendemos · Nuevo inicio de sesión',notice('Tu cuenta acaba de iniciar sesión.'));res.json({user:userView(u)});});
APP.post('/api/logout',auth,(req,res)=>{db.prepare('DELETE FROM sessions WHERE token_hash=?').run(tokenHash(req.cookies.emprendemos_session));res.clearCookie('emprendemos_session',{path:'/'});res.json({ok:true});});
APP.get('/api/me',auth,(req,res)=>res.json({user:userView(req.user)}));
APP.patch('/api/profile',auth,(req,res)=>{if(req.user.role!=='seller')return fail(res,403,'Solo vendedores.');const {business_name,business_address,phone,hours}=req.body||{};if(short(business_name,100).length<2||short(business_address,250).length<6)return fail(res,400,'Nombre y dirección obligatorios.');db.prepare('UPDATE users SET business_name=?,business_address=?,phone=?,hours=? WHERE id=?').run(short(business_name,100),short(business_address,250),short(phone,30),short(hours,300),req.user.id);res.json({ok:true});});
// Solo para pruebas: NO procesa dinero ni confirma transacciones reales.
APP.post('/api/demo-access',auth,only('seller','driver'),(req,res)=>{if(!demo())return fail(res,403,'La pasarela de pago todavía no está configurada.');if(req.user.access_status!=='pending_payment')return fail(res,409,'El acceso ya fue procesado.');db.prepare("UPDATE users SET access_status='active' WHERE id=?").run(req.user.id);queueEmail(req.user.id,'demo-access:'+req.user.id,'Emprendemos · Acceso activado',notice('Tu acceso de demostración fue activado. No se realizó ningún cobro real.'));res.json({ok:true,note:'Acceso de demostración; no se cobró dinero.'});});
// Fotos del vendedor: hasta 5 MB, JPG/PNG/WEBP/GIF, nombres aleatorios y persistencia en DATA_DIR.
const photoUpload=multer({storage:multer.memoryStorage(),limits:{fileSize:5*1024*1024,files:1,fields:0},fileFilter(req,file,cb){if(!['image/jpeg','image/png','image/webp','image/gif'].includes(file.mimetype))return cb(new Error('Elige una foto JPG, PNG, WEBP o GIF.'));cb(null,true);}});
const photoLimit=rateLimit({windowMs:60*60_000,limit:30,standardHeaders:'draft-7',legacyHeaders:false});
function imageExtension(b){if(b.length>=4&&b[0]===0xff&&b[1]===0xd8&&b[2]===0xff)return 'jpg';if(b.length>=8&&b.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))return 'png';if(b.length>=12&&b.toString('ascii',0,4)==='RIFF'&&b.toString('ascii',8,12)==='WEBP')return 'webp';if(b.length>=6&&['GIF87a','GIF89a'].includes(b.toString('ascii',0,6)))return 'gif';return null;}
APP.post('/api/product-image',auth,only('seller'),active,photoLimit,(req,res,next)=>photoUpload.single('photo')(req,res,e=>{if(e)return fail(res,400,e.code==='LIMIT_FILE_SIZE'?'La imagen supera 5 MB.':e.message);next();}),(req,res)=>{
 if(!req.file)return fail(res,400,'Selecciona una foto.');const ext=imageExtension(req.file.buffer);
 if(!ext)return fail(res,400,'El archivo no es una imagen compatible.');
 const count=db.prepare("SELECT COUNT(*) AS n FROM products WHERE seller_id=? AND photo_url LIKE '/product-images/%'").get(req.user.id).n;
 if(count>=100)return fail(res,409,'Has alcanzado el límite de 100 fotos publicadas.');
 const filename=crypto.randomUUID()+'.'+ext;fs.writeFileSync(path.join(UPLOADS,filename),req.file.buffer,{flag:'wx'});
 res.status(201).json({url:'/product-images/'+filename});
});
const photoUrlOk=u=>!u||/^https:\/\/[^\s]+$/i.test(u)||/^\/product-images\/[a-f0-9-]{36}\.(jpg|png|webp|gif)$/.test(u);
APP.get('/api/sellers',(req,res)=>res.json({sellers:db.prepare("SELECT id,business_name,business_address,hours,phone FROM users WHERE role='seller' AND access_status='active' ORDER BY business_name").all()}));
APP.get('/api/products',(req,res)=>res.json({products:db.prepare(`SELECT p.*,u.business_name,u.business_address,u.hours FROM products p JOIN users u ON p.seller_id=u.id WHERE p.available=1 AND u.access_status='active' ORDER BY p.id DESC`).all()}));
APP.get('/api/my-products',auth,only('seller'),(req,res)=>res.json({products:db.prepare('SELECT * FROM products WHERE seller_id=? ORDER BY id DESC').all(req.user.id)}));
APP.post('/api/products',auth,only('seller'),active,(req,res)=>{const {name,description,price_cents,category,photo_url}=req.body||{};if(short(name,100).length<2||!price(price_cents))return fail(res,400,'Nombre y precio válidos obligatorios.');const u=short(photo_url,500);if(!photoUrlOk(u))return fail(res,400,'La foto debe tener una dirección HTTPS.');const r=db.prepare('INSERT INTO products(seller_id,name,description,price_cents,category,photo_url) VALUES(?,?,?,?,?,?)').run(req.user.id,short(name,100),short(description,500),price_cents,short(category,40)||'Comida',u);res.status(201).json({id:r.lastInsertRowid});});
APP.patch('/api/products/:id',auth,only('seller'),active,(req,res)=>{const {name,description,price_cents,category,photo_url,available}=req.body||{};if(short(name,100).length<2||!price(price_cents))return fail(res,400,'Nombre y precio válidos obligatorios.');const u=short(photo_url,500);if(!photoUrlOk(u))return fail(res,400,'URL de foto inválida.');const r=db.prepare('UPDATE products SET name=?,description=?,price_cents=?,category=?,photo_url=?,available=? WHERE id=? AND seller_id=?').run(short(name,100),short(description,500),price_cents,short(category,40)||'Comida',u,available?1:0,req.params.id,req.user.id);if(!r.changes)return fail(res,404,'Producto no encontrado.');res.json({ok:true});});
APP.delete('/api/products/:id',auth,only('seller'),active,(req,res)=>{const r=db.prepare('DELETE FROM products WHERE id=? AND seller_id=?').run(req.params.id,req.user.id);if(!r.changes)return fail(res,404,'Producto no encontrado.');res.json({ok:true});});
APP.post('/api/orders',auth,only('customer'),(req,res)=>{
 const {items,address,notes}=req.body||{};if(!Array.isArray(items)||!items.length||items.length>30||short(address,250).length<8)return fail(res,400,'Indica productos y dirección de entrega.');
 let seller=null,sum=0;const lines=[];for(const i of items){const id=Number(i.id),q=Number(i.qty);if(!Number.isSafeInteger(id)||!Number.isSafeInteger(q)||q<1||q>20)return fail(res,400,'Cantidad no válida.');const p=db.prepare(`SELECT p.*,u.access_status FROM products p JOIN users u ON p.seller_id=u.id WHERE p.id=? AND p.available=1`).get(id);if(!p||p.access_status!=='active')return fail(res,409,'Un producto ya no está disponible.');if(seller!==null&&seller!==p.seller_id)return fail(res,400,'Cada pedido debe ser de un solo negocio.');seller=p.seller_id;sum+=p.price_cents*q;lines.push({p,q});}
 if(sum>100000000)return fail(res,400,'Pedido demasiado grande.');const create=db.transaction(()=>{const o=db.prepare('INSERT INTO orders(customer_id,seller_id,address,notes,subtotal_cents) VALUES(?,?,?,?,?)').run(req.user.id,seller,short(address,250),short(notes,300),sum);for(const {p,q} of lines)db.prepare('INSERT INTO order_items(order_id,product_id,name,qty,unit_price_cents) VALUES(?,?,?,?,?)').run(o.lastInsertRowid,p.id,p.name,q,p.price_cents);return o.lastInsertRowid;});const id=create();orderNotice(id,'pending_payment');res.status(201).json({order:orderFull(id)});
});
APP.post('/api/orders/:id/demo-pay',auth,only('customer'),(req,res)=>{if(!demo())return fail(res,403,'Pagos reales todavía no disponibles.');const o=db.prepare('SELECT * FROM orders WHERE id=? AND customer_id=?').get(req.params.id,req.user.id);if(!o||o.status!=='pending_payment')return fail(res,409,'Pedido no disponible para pagar.');changeStatus(o.id,'paid');orderNotice(o.id,'paid');res.json({order:orderFull(o.id),note:'Pago simulado: no se efectuó cargo.'});});
APP.get('/api/orders',auth,(req,res)=>{let q,params=[];if(req.user.role==='customer'){q='SELECT id FROM orders WHERE customer_id=? ORDER BY id DESC';params=[req.user.id];}else if(req.user.role==='seller'){q='SELECT id FROM orders WHERE seller_id=? ORDER BY id DESC';params=[req.user.id];}else if(req.user.role==='driver'){q="SELECT id FROM orders WHERE driver_id=? OR (driver_id IS NULL AND status='preparing') ORDER BY id DESC";params=[req.user.id];}else {q='SELECT id FROM orders ORDER BY id DESC';}res.json({orders:db.prepare(q).all(...params).map(x=>{const o=orderFull(x.id);if(req.user.role==='driver'&&!o.driver_id){o.address='Dirección visible después de aceptar el pedido';o.customer_name='Cliente';o.notes='';}return o;})});});
APP.post('/api/orders/:id/prepare',auth,only('seller'),active,(req,res)=>{const o=db.prepare('SELECT * FROM orders WHERE id=? AND seller_id=?').get(req.params.id,req.user.id);if(!o||o.status!=='paid')return fail(res,409,'Solo puedes comenzar pedidos pagados de tu negocio.');changeStatus(o.id,'preparing');orderNotice(o.id,'preparing');notifyAvailableDrivers(o.id);res.json({ok:true});});
APP.post('/api/orders/:id/claim',auth,only('driver'),active,(req,res)=>{if(!isVerified(req.user.id))return fail(res,403,'Debes completar la verificación de identidad antes de aceptar entregas.');if(!vehicle(req.user.id))return fail(res,403,'Primero registra los datos de tu motocicleta.');const r=db.prepare("UPDATE orders SET driver_id=?,status='shipping',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='preparing' AND driver_id IS NULL").run(req.user.id,req.params.id);if(!r.changes)return fail(res,409,'Pedido no disponible.');orderNotice(Number(req.params.id),'shipping');res.json({ok:true});});
APP.post('/api/orders/:id/doorstep',auth,only('driver'),active,(req,res)=>{const r=db.prepare("UPDATE orders SET status='doorstep',updated_at=CURRENT_TIMESTAMP WHERE id=? AND driver_id=? AND status='shipping'").run(req.params.id,req.user.id);if(!r.changes)return fail(res,409,'No puedes actualizar este pedido.');orderNotice(Number(req.params.id),'doorstep');res.json({ok:true});});
APP.post('/api/orders/:id/delivered',auth,only('customer'),(req,res)=>{const o=db.prepare("SELECT * FROM orders WHERE id=? AND customer_id=? AND status='doorstep'").get(req.params.id,req.user.id);if(!o)return fail(res,409,'Primero debe aparecer En tu puerta.');const pay=settings().deliveryPay;const fn=db.transaction(()=>{changeStatus(o.id,'delivered');if(o.driver_id)db.prepare('INSERT OR IGNORE INTO settlements(order_id,driver_id,amount_cents,status) VALUES(?,?,?,?)').run(o.id,o.driver_id,Number.isSafeInteger(pay)&&pay>=0?pay:null,'unconfigured');});fn();orderNotice(o.id,'delivered');res.json({ok:true,note:'Pago a repartidor pendiente de configurar y liquidar.'});});
APP.post('/api/orders/:id/rate',auth,only('customer'),(req,res)=>{const stars=Number(req.body?.stars),comment=short(req.body?.comment,400);const o=db.prepare("SELECT * FROM orders WHERE id=? AND customer_id=? AND status='delivered' AND driver_id IS NOT NULL").get(req.params.id,req.user.id);if(!o||!Number.isInteger(stars)||stars<1||stars>5)return fail(res,400,'Calificación inválida.');try{db.prepare('INSERT INTO ratings(order_id,driver_id,customer_id,stars,comment) VALUES(?,?,?,?,?)').run(o.id,o.driver_id,req.user.id,stars,comment);queueEmail(o.driver_id,'rating:'+o.id,'Emprendemos · Nueva calificación',notice(`Recibiste una nueva calificación por el pedido #${o.id}.`));res.json({ok:true});}catch(e){if(e.code?.startsWith('SQLITE_CONSTRAINT'))return fail(res,409,'Ya calificaste este pedido.');throw e;}});
APP.post('/api/orders/:id/report',auth,only('customer'),(req,res)=>{const reason=short(req.body?.reason,400);const o=db.prepare("SELECT * FROM orders WHERE id=? AND customer_id=? AND driver_id IS NOT NULL").get(req.params.id,req.user.id);if(!o||reason.length<10)return fail(res,400,'Escribe el problema de la entrega.');db.prepare('INSERT INTO incidents(order_id,driver_id,reporter_id,reason) VALUES(?,?,?,?)').run(o.id,o.driver_id,req.user.id,reason);notifyOperator('report:'+o.id+':'+Date.now(),'Emprendemos · Reporte de pedido',notice(`Se recibió un reporte del pedido #${o.id}. Revísalo en el panel.`));res.json({ok:true,note:'Reporte enviado a revisión. No se bloquea automáticamente al repartidor.'});});
APP.get('/api/driver-stats',auth,only('driver'),(req,res)=>{const x=db.prepare('SELECT COUNT(*) count,ROUND(AVG(stars),2) average FROM ratings WHERE driver_id=?').get(req.user.id);const incidents=db.prepare("SELECT COUNT(*) count FROM incidents WHERE driver_id=? AND status='confirmed'").get(req.user.id).count;const payments=db.prepare("SELECT COUNT(*) deliveries,COALESCE(SUM(CASE WHEN status='paid' THEN amount_cents ELSE 0 END),0) paid_cents FROM settlements WHERE driver_id=?").get(req.user.id);res.json({stats:{...x,confirmed_incidents:incidents,...payments,review_recommended:(x.count>=5&&x.average<3)||incidents>=2}});});
// Operación humana para seguridad, incidencias y pagos. No se habilita sin credenciales configuradas.
const oe=process.env.OPERATOR_EMAIL?.trim().toLowerCase(),op=process.env.OPERATOR_PASSWORD;
if(oe&&op&&op.length>=12){const existing=db.prepare('SELECT id FROM users WHERE email=?').get(oe);if(!existing)db.prepare("INSERT INTO users(name,email,password_hash,role,access_status) VALUES('Operación',?,?, 'operator','active')").run(oe,bcrypt.hashSync(op,12));}
APP.get('/api/operator/overview',auth,only('operator'),(req,res)=>res.json({accounts:db.prepare("SELECT id,name,email,role,access_status FROM users WHERE role IN ('seller','driver') ORDER BY id DESC").all().map(a=>({...a,verification:a.role==='driver'?verification(a.id):null,vehicle:a.role==='driver'?vehicle(a.id):null})),incidents:db.prepare(`SELECT i.*,u.name AS driver_name FROM incidents i JOIN users u ON i.driver_id=u.id ORDER BY i.id DESC`).all(),settlements:db.prepare('SELECT * FROM settlements ORDER BY id DESC').all()}));
APP.post('/api/operator/access/:id',auth,only('operator'),(req,res)=>{const status=req.body?.status;if(!['active','suspended','pending_payment'].includes(status))return fail(res,400,'Estado no válido.');const r=db.prepare("UPDATE users SET access_status=? WHERE id=? AND role IN ('seller','driver')").run(status,req.params.id);if(!r.changes)return fail(res,404,'Cuenta no encontrada.');queueEmail(Number(req.params.id),'access:'+req.params.id+':'+status+':'+Date.now(),'Emprendemos · Estado de acceso',notice(`El estado de tu cuenta cambió a: ${status}. Consulta tu panel.`));res.json({ok:true});});
APP.post('/api/operator/incident/:id',auth,only('operator'),(req,res)=>{const status=req.body?.status;if(!['confirmed','dismissed'].includes(status))return fail(res,400,'Estado no válido.');const r=db.prepare('UPDATE incidents SET status=? WHERE id=?').run(status,req.params.id);if(!r.changes)return fail(res,404,'Reporte no encontrado.');const item=db.prepare('SELECT reporter_id FROM incidents WHERE id=?').get(req.params.id);if(item)queueEmail(item.reporter_id,'incident:'+req.params.id+':'+status,'Emprendemos · Reporte actualizado',notice(`Tu reporte #${req.params.id} cambió de estado. Revisa la plataforma.`));res.json({ok:true});});
APP.get('/api/operator/email-status',auth,only('operator'),(req,res)=>res.json({enabled:mailEnabled(),counts:db.prepare('SELECT status,COUNT(*) count FROM email_outbox GROUP BY status').all()}));
APP.use('/api',(req,res)=>fail(res,404,'Ruta no encontrada.'));
APP.use((err,req,res,next)=>{console.error(err);fail(res,500,'Error interno del servidor.');});
APP.listen(Number(process.env.PORT||3000),()=>console.log('Emprendemos en funcionamiento. Modo de pagos:',demo()?'DEMOSTRACIÓN':'NO CONFIGURADO'));
