# Backlog de Security Stories · SecureBank API

Cada historia funcional tiene al menos una security story asociada. Se priorizan según el riesgo del [threat model](threat-model.md): primero las de riesgo ALTO, y entre ellas las que se pueden explotar de forma trivial.

**Prioridad:** P1 = sprint actual · P2 = siguiente sprint · P3 = backlog
**Estado:** ✅ implementada con test · 🔄 en curso · ⏳ pendiente

## Historias funcionales y sus security stories

| Historia funcional | Security stories asociadas |
| :-- | :-- |
| HU-01 · Como cliente quiero iniciar sesión para operar mis cuentas | SS-01, SS-02, SS-04, SS-14 |
| HU-02 · Como cliente quiero consultar el saldo de mis cuentas | SS-06, SS-11 |
| HU-03 · Como cliente autenticado quiero transferir dinero entre cuentas | SS-03, SS-05, SS-10 |
| HU-04 · Como cliente quiero descargar reportes de movimientos | SS-12 |
| HU-05 · Como cliente quiero simular el interés de un crédito | SS-12 |
| HU-06 · Como visitante quiero ver una página de bienvenida | SS-13 |
| HU-07 · Como equipo queremos un repositorio y un pipeline seguros | SS-07, SS-08, SS-09 |

## Backlog priorizado

| Prio | ID | Security story | Criterio de aceptación (verificable) | Amenaza | Estado |
| :-: | :-: | :-- | :-- | :-: | :-: |
| P1 | **SS-10** | La aplicación debe rechazar toda transferencia cuyo `originAccount` no pertenezca al usuario autenticado. | Si el `sub` del JWT no es el dueño de `originAccount`: **403** + registro en el log. Test `test_transfer_desde_cuenta_ajena_es_403`. | AM-10 | ✅ |
| P1 | **SS-04** | La aplicación debe construir toda consulta SQL con parámetros, nunca concatenando entrada del usuario. | Login con `' OR '1'='1` → **401**. Semgrep sin hallazgos de SQLi. | AM-04 | ✅ (Sesión 5) |
| P1 | **SS-12** | La aplicación no debe ejecutar comandos de shell ni `eval()` con datos del usuario. | `/reportes/x.csv;id` → **400**. `/tasas/calcular?monto=__import__('os')` → **400**. Semgrep sin hallazgos. | AM-12 | ✅ (Sesión 5) |
| P1 | **SS-06** | La aplicación debe mostrar una cuenta solo a su dueño o a un administrador. | `GET /accounts/{id}` de otro cliente → **403**. | AM-06 | ✅ |
| P1 | **SS-14** | La aplicación debe guardar las contraseñas con un hash adaptativo y sal aleatoria. | El hash guardado no es MD5 (no tiene 32 hex) y cambia entre dos registros con la misma contraseña. | AM-14 | ✅ (Sesión 5) |
| P1 | **SS-07** | El repositorio no debe contener secretos, y todo push debe pasar por escaneo de secretos. | Secret scanning + push protection activos. La clave JWT se lee desde una variable de entorno sin valor por defecto en el código. | AM-07 | 🔄 |
| P2 | **SS-02** | La API debe aceptar solo JWT firmados con HS256 y vigentes. | Token con `alg: none`, firma inválida o expirado → **401**. | AM-02 | ✅ |
| P2 | **SS-11** | La API debe obtener el rol del usuario desde la BD y no desde el claim del token. | Un token de cliente con `role: admin` inyectado no accede a cuentas ajenas. | AM-11 | ✅ |
| P2 | **SS-03** | La API debe validar el monto en el servidor: entero, mayor que 0 y menor o igual al límite por operación. | `amount` negativo, decimal, texto o sobre el límite → **400**. | AM-03 | ✅ |
| P2 | **SS-13** | Toda salida HTML debe pasar por plantillas con autoescape. | `/bienvenida?name=<script>` devuelve `&lt;script&gt;`. | AM-13 | ✅ (Sesión 5) |
| P2 | **SS-05** | Toda transferencia debe quedar registrada con usuario, fecha y resultado. | Cada `POST /transfer` exitoso crea un movimiento con timestamp y cada intento rechazado queda en el log. | AM-05 | 🔄 |
| P3 | **SS-01** | El login debe bloquear temporalmente una cuenta después de 5 intentos fallidos en 15 minutos. | Al sexto intento → **429** durante 15 min. | AM-01 | ⏳ |
| P3 | **SS-08** | Los endpoints públicos deben tener rate limiting por IP. | Más de 60 req/min desde una IP → **429**. | AM-08 | ⏳ |
| P3 | **SS-09** | La API debe rechazar requests de más de 16 KB. | Body > 16 KB → **413**. | AM-09 | ✅ |
