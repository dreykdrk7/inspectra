# Espacios privados de equipo

Estado: **vertical inicial completado (`PROD-012`)**. No convierte Inspectra en
un SaaS multiempresa ni amplía la candidatura de despliegue actual, que sigue
siendo de administrador único.

## Modelo soportado

`INSPECTRA_AUTH_MODE=private_team_lightweight_users` habilita espacios privados
aislados dentro de un despliegue controlado. Requiere almacenamiento de
autenticación SQLite y un
`INSPECTRA_ADMIN_PASSWORD_HASH` soportado. En el primer arranque se provisionan:

- el espacio configurado por `INSPECTRA_TEAM_ORGANIZATION_NAME`;
- el administrador bootstrap con usuario `admin` y la contraseña representada
  por `INSPECTRA_ADMIN_PASSWORD_HASH`;
- una membresía `administrator` persistente.

El identificador interno de frontera del espacio bootstrap es `local-admin`.
Es una decisión de migración: los archivos, proyectos y trabajos creados antes
en modo local o administrador único siguen perteneciendo al mismo límite de
datos. No se muestra como selector ni se acepta desde el navegador.

Un administrador puede crear otro espacio desde la interfaz. La creación
produce un identificador opaco del servidor y añade al creador como
administrador; el navegador no elige ese ID. Cambiar de espacio exige una
mutación con CSRF, comprueba una membresía activa, revoca la sesión anterior,
crea otra sesión/CSRF y vuelve a cargar archivos, proyectos y trabajos usando
solo la nueva frontera. Un administrador de un espacio no obtiene lectura
global de los demás: debe tener membresía y seleccionarlo explícitamente.

Los roles iniciales son:

| Rol | Leer y exportar | Ejecutar/modificar | Gestionar miembros |
| --- | --- | --- | --- |
| `reader` | sí | no | no |
| `maintainer` | sí | sí | no |
| `administrator` | sí | sí | sí |

La autorización de backend es la autoridad. Un `reader` recibe `403` en toda
mutación de producto aunque fabrique una petición, y ninguna membresía concede
una excepción a CSRF, redacción, egress, autorización de alcance o límites de
análisis. No existe un bypass de «administrador global» para leer otro espacio.

Los responsables operativos de activos Active se eligen únicamente del
directorio vigente del espacio seleccionado. Ser responsable no cambia el rol:
un lector asignado continúa sin permisos de escritura. El backend vuelve a
validar todos los IDs en cada alta o renovación y responde de forma idéntica
ante una cuenta inexistente, revocada o perteneciente a otro espacio. Los
informes, la auditoría mínima y el historial de revisiones no exportan esos IDs
ni nombres de usuario.

## Invitaciones y revocación

Un administrador crea una invitación para un nombre de usuario y rol. Inspectra
muestra un token opaco de un solo uso una sola vez; en SQLite solo conserva su
SHA-256 con separación de dominio, caducidad, creador y estado. El token debe
compartirse por un canal aprobado. No se aceptan correo, URL de callback ni
destino aportado por el usuario.

Quien recibe el token define una contraseña de 12–256 caracteres. El backend la
deriva con PBKDF2-HMAC-SHA256 y el mismo mínimo de trabajo que el administrador;
nunca conserva ni registra contraseña o token en claro. Intentos de activación
y login comparten el límite persistente por cliente. Token desconocido,
caducado, revocado o reutilizado produce el mismo error.

Cambiar el rol o revocar una membresía invalida sus sesiones persistentes del
espacio afectado; las sesiones de otra organización no se revocan ni conceden
acceso al espacio abandonado. Antes
de revocar, la interfaz exige un preflight que resume cuántos activos Active
perderán esa asignación, cuántos quedarán sin responsable y cuántos proyectos
quedarán pendientes de reasignación, sin mostrar targets ni nombres de proyecto.
Al confirmar, las sesiones se invalidan antes de modificar la membresía. La baja
y su reconciliación eliminan también las vistas de remediación privadas o
compartidas creadas por la cuenta y cualquier predeterminado que las referencie.
La baja y la eliminación de asignaciones se serializan frente a altas, renovaciones y
reasignaciones de activos para que una carrera no reintroduzca al miembro
saliente. Si falla la reconciliación, la membresía se conserva y las sesiones
permanecen invalidadas; el administrador puede repetir la operación de forma
segura. Los eventos Active usan razones genéricas y no copian ID, username ni
target al historial. Las responsabilidades de proyecto se eliminan primero de
forma versionada y el estado pasa a `unassigned_attention`; no se transfiere
ownership silenciosamente. El endpoint canónico de preflight es
`/organization/members/{id}/responsibility-impact`; `active-impact` permanece
deprecado temporalmente para clientes anteriores.

La sesión también se contrasta con la membresía en cada petición; una fila
revocada manualmente no sigue dando acceso. Cuando la cuenta ya no conserva
ninguna membresía activa, Inspectra la desactiva, reemplaza username y hash de
contraseña por marcadores no reutilizables y conserva solo el ID opaco y las
membresías revocadas necesarias para integridad referencial. No se reasignan
proyectos ni acciones históricas a otra persona; una invitación posterior crea
una identidad nueva. El administrador bootstrap no puede
degradarse ni revocarse desde la interfaz, para evitar dejar el espacio sin vía
de administración.

Las invitaciones usadas, revocadas o caducadas se conservan 30 días por defecto
y después se eliminan por organización durante la limpieza manual o de arranque.
`INSPECTRA_TEAM_INVITATION_RETENTION_DAYS` admite 1–365 días. El resultado solo
incluye el número agregado eliminado; nunca token, hash, nombre, rol o creador.
Un restore elimina todas las invitaciones y sesiones inmediatamente.

## Aprobaciones de identidades públicas

En modo equipo, toda identidad de paquete que podría llegar a OSV necesita un
segundo consentimiento aislado por espacio. Un `maintainer` o `administrator`
propone un ecosistema y nombre exactos; solo un `administrator` puede aprobarlo.
La aprobación dura 7, 30 o 90 días, se versiona, caduca automáticamente y puede
revocarse de inmediato. El estado `pending`, `approved`, `expired` o `revoked`
es visible únicamente dentro del espacio activo.

Esta aprobación no convierte un nombre en público ni sustituye la política del
operador. Inspectra sigue exigiendo el lockfile/procedencia soportados, las
exclusiones privadas y, para PyPI, Go, Composer, Maven y NuGet, la allowlist
global correspondiente. Las variables globales autorizan al despliegue a usar
una identidad; no migran como aprobación de ningún tenant. Por tanto, ambos
gates deben permitir la identidad exacta. npm, Cargo y SBOM también requieren
aprobación del espacio en modo equipo aunque su procedencia local ya sea
admisible.

El backend relee el registro durable justo antes de construir cada lote OSV.
Una revocación concurrente cierra el lote completo sin abrir una petición. La
auditoría guarda acción, ID opaco, ecosistema y revisión, pero no el nombre del
paquete; informes globales y logs tampoco exportan las aprobaciones. Los nombres
sí se conservan en el SQLite de identidad porque el administrador debe poder
revisarlos: trátese ese archivo como metadata privada, inclúyase solo en backups
cifrados y elimínese conforme a la política del despliegue. El límite actual es
200 identidades retenidas por espacio; una identidad caducada o revocada puede
volver a proponerse como una revisión nueva sin crear otra fila.

## Amenazas cubiertas

- acceso anónimo o sesión sin membresía: denegado;
- manipulación de IDs de usuario o recurso: la organización procede de la
  sesión y los accesos directos siguen devolviendo no encontrado fuera de ella;
- escalada de `reader` o `maintainer`: matriz aplicada en middleware y rutas de
  administración;
- robo de base de datos: sesiones, CSRF, claves de cliente y tokens de
  invitación se guardan hasheados; las contraseñas se derivan con salt;
- replay de invitación y revocación tardía: consumo transaccional de un solo uso
  e invalidación de sesiones;
- enumeración básica de cuentas: login e invitación devuelven errores cerrados
  y el login desconocido ejecuta una verificación de coste equivalente;
- fuga en logs/respuestas: no se registran cuerpos, tokens, contraseñas, rutas o
  hashes; las respuestas de membresía contienen solo usuario, rol y fecha.
- confusión entre tenants o allowlist global: una aprobación se busca por
  organización+ecosistema+nombre exactos, caducidad vigente y política exterior
  idéntica; otro espacio, un homónimo o una revisión revocada fallan cerrados.

## Límites conocidos y siguientes pasos

- Los almacenes conservan `owner_id` como nombre histórico de la frontera. Los
  archivos, trabajos y proyectos nuevos materializan además
  `organization_id`, y la carga rechaza una discrepancia; aún falta una
  migración explícita y reversible de todos los derivados/bitácoras históricos.
- No hay borrado o renombrado de espacios. Un usuario con varias membresías
  entra primero en el espacio bootstrap si pertenece a él y luego puede cambiar
  de forma explícita; aún falta una preferencia de último espacio no sensible.
- OIDC privado opt-in dispone de un primer vertical preaprovisionado para
  `reader` y `maintainer`, documentado en `docs/oidc-federation.md`; solo se ha
  validado con IdP simulado. No hay correo, recuperación de cuenta, MFA,
  SAML/SCIM ni logout back-channel.
- La bitácora empresarial de cambios de rol e invitaciones depende de
  `PROD-013`; los logs HTTP agregados no sustituyen una auditoría de acciones.
- Antes de declarar el modo listo para despliegue se necesitan backup/restore,
  retención/eliminación, matriz exhaustiva de permisos (`PROD-109`) y un smoke
  de aislamiento con al menos dos espacios sobre el contenedor candidato.

`PROD-012` completa la frontera funcional mínima de identidad, organización y
roles. Hasta resolver los siguientes pasos enumerados, la guía de aceptación no
debe presentar el modo de equipo como candidatura empresarial validada.
