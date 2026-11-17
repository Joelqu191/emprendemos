/* Emprendemos: avisos visibles. No guarda datos privados en caché. */
self.addEventListener('install',event=>{self.skipWaiting();});
self.addEventListener('activate',event=>{event.waitUntil(self.clients.claim());});
self.addEventListener('push',event=>{
 let data={};try{data=event.data?.json()||{};}catch{}
 const title=String(data.title||'Emprendemos').slice(0,100);
 const body=String(data.body||'Tienes una actualización.').slice(0,180);
 const tag=String(data.tag||'emprendemos').slice(0,150);
 event.waitUntil(self.registration.showNotification(title,{body,tag,icon:'/icons/icon-192.png',badge:'/icons/icon-192.png',data:{url:String(data.url||'/?panel=orders')}}));
});
self.addEventListener('notificationclick',event=>{
 event.notification.close();
 const target=new URL(event.notification.data?.url||'/',self.location.origin);
 if(target.origin!==self.location.origin)return;
 event.waitUntil((async()=>{
  const tabs=await self.clients.matchAll({type:'window',includeUncontrolled:true});
  for(const tab of tabs){if(new URL(tab.url).origin===target.origin){await tab.navigate(target.href);return tab.focus();}}
  return self.clients.openWindow(target.href);
 })());
});
