# Credenciales de automatización

Inspectra admite credenciales no interactivas solo en despliegues privados con autenticación configurada y estado SQLite (`self_hosted_single_admin` o `private_team_lightweight_users`). No están disponibles en el modo local sin autenticación.

## Contrato de seguridad

- Solo un administrador con sesión web y CSRF válido puede crear, listar o revocar credenciales.
- Cada credencial queda ligada a una organización y a un único proyecto. No puede enumerar proyectos, usuarios, archivos ni credenciales.
- Los ámbitos cerrados son `project:read`, `project:scan` y `report:read`. Las rutas no reconocidas se deniegan aunque aparezcan en versiones futuras de la API.
- El secreto se muestra una sola vez. SQLite conserva únicamente un SHA-256 con separación de dominio, el identificador, los ámbitos, la caducidad y metadatos mínimos de uso.
- La caducidad máxima es de 90 días, la revocación es inmediata y cada credencial admite como máximo 600 peticiones por hora. Solo se conserva el uso en bloques horarios, no un historial fino de peticiones. Los intentos inválidos devuelven un error genérico.
- Cada proyecto admite como máximo dos credenciales activas. Esta ventana permite rotar sin corte, pero impide acumular credenciales durante rotaciones sucesivas.
- Los eventos de creación y revocación se incorporan a la auditoría de producto sin incluir el secreto.

La credencial se envía como `Authorization: Bearer <token>`. El cliente oficial solo permite HTTPS, excepto HTTP sobre loopback para desarrollo. En producción, el operador debe terminar TLS mediante el perfil privado documentado y guardar el valor en el almacén de secretos de su plataforma CI; nunca debe incluirlo en el repositorio, argumentos de proceso o logs.

## Operación

1. Crea primero el proyecto mediante la interfaz o API autenticada.
2. Desde una sesión administrativa, solicita `POST /automation/tokens` con nombre, `project_id`, ámbitos y `lifetime_seconds` (entre 300 y 7.776.000).
3. Copia el campo `token` mostrado en la respuesta al almacén secreto del pipeline. `GET /automation/tokens` nunca vuelve a mostrarlo.
4. Revoca con `DELETE /automation/tokens/{id}` al rotar la credencial, retirar un pipeline o responder a una posible exposición.

Para rotar sin corte, crea la segunda credencial, guárdala, valida un pipeline
autorizado y solo entonces revoca la anterior. Si la validación falla, conserva
la anterior y revoca el reemplazo; no existe una revocación implícita. La UI
impide crear una tercera credencial activa y elimina el secreto del DOM cuando
se confirma que fue almacenado.

Los metadatos revocados o caducados se eliminan de forma owner-scoped durante
la limpieza de retención después de 30 días por defecto, configurable con
`INSPECTRA_AUTOMATION_TOKEN_RETENTION_DAYS` (1–365). Esta purga no elimina los
eventos mínimos de auditoría, sujetos a su propia retención. Un backup conserva
el estado SQLite y requiere rotación operativa después de restaurarlo.

La creación de una credencial no activa egress público ni autoriza objetivos activos. Las políticas de análisis, límites operativos y atestaciones del operador siguen aplicándose.
