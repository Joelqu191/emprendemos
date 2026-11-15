# Emprendemos 🌮

Prototipo funcional de mercado local de comida, para probar en teléfono o computadora. Clientes, vendedores, repartidores y operación. **NO procesa pagos reales ni envía transferencias.** El acceso y el pago de los pedidos son *simulaciones* claramente etiquetadas.

## Iniciar

1. Instalar Node.js 20 o posterior.
2. En la carpeta del proyecto: `npm install`
3. Ejecutar: `npm start`
4. Abrir `http://localhost:3000`.

Para Railway, subir **todos** los archivos a un repositorio GitHub (la carpeta `public` debe permanecer como carpeta), conectar el repositorio en Railway y montar un Volume en `/data`. En el servicio configurar `DATA_DIR=/data` y `NODE_ENV=production`. En el prototipo, `PAYMENTS_MODE=demo` (también es el valor implícito) activa los botones de simulación.

### Cuentas
- **Cliente:** se registra con correo, contraseña y código personal generado automáticamente, explora productos, crea pedido, simula pago, confirma entrega y califica.
- **Vendedor:** se registra con datos de local y horarios, activa acceso de demostración y administra productos, disponibilidad y pedidos.
- **Repartidor:** se registra, activa acceso de demostración, acepta pedidos en preparación, marca su llegada y consulta estadísticas.
- **Operación:** para revisión humana de reportes y suspensión/reactivación. Se crea una cuenta de operación al primer arranque con `OPERATOR_EMAIL` y `OPERATOR_PASSWORD` (mínimo 12 caracteres), configuradas en variables privadas de Railway. **No revelar credenciales.**

### Estados de pedido
`Pendiente de pago (solo para demo) → Pedido pagado → Pedido en proceso → Pedido en envío → Pedido en tu puerta → Entregado`.

### Límites y pendientes obligatorios antes de operar con dinero real
- Contratar e integrar proveedor de pagos que confirme cargos por **webhook firmado**, implemente reembolsos y maneje pagos a vendedores y repartidores. Nunca cambiar un pedido a "pagado" porque lo diga un navegador.
- Definir cuotas de acceso, tarifas de entrega y liquidación del repartidor, facturación/impuestos, comisiones y política de reembolsos. Las variables `SELLER_ACCESS_FEE_CENTS`, `DRIVER_ACCESS_FEE_CENTS`, `DELIVERY_PAY_CENTS` son solo parámetros informativos, **no ejecutan cobros ni transferencias**.
- Definir zona de cobertura, cálculo de distancia, tarifa de envío, asignación justa de repartidores, horarios estructurados, inventario, cancelaciones, resolución de disputas, privacidad y protección de datos de domicilios, política de retención de información y validación de vendedores/repartidores.
- No imponer suspensiones automáticas por una sola calificación. El demo marca como *revisión recomendada* cuando existen al menos 5 evaluaciones y promedio menor a 3, o al menos 2 incidentes confirmados por operación. Suspender requiere revisión humana. Debe existir apelación y criterios claros.
- El campo de foto usa enlaces HTTPS externos; aún **no** hay carga de archivos al servidor, ni geolocalización, seguimiento GPS, ni mensajes push. Estas funciones requieren configuración adicional.
- Antes de uso público: agregar verificación de correo, protección CSRF acorde a despliegue, validaciones y controles anti-fraude más completos, copias de seguridad y pruebas de carga. `PAYMENTS_MODE=production` **deshabilita la simulación**, pero no habilita cobros reales.

El proyecto puede alojarse en el mismo Railway **pero como un proyecto independiente de Mi Salón**, con su propia base de datos y volumen.
