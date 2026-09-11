# Ingesta segura de repositorios locales

## Decisión de arquitectura

Inspectra no clona repositorios. El proveedor inicial de `PROD-007` es Git
local a través de `inspectra-cli`: el cliente deriva una instantánea
reproducible del commit autorizado y el servidor recibe únicamente
`snapshot.tar`, el SHA-256 declarado, el commit completo, un nombre de proyecto
y, opcionalmente, una rama informativa validada.

Esta decisión evita introducir una superficie de proveedor remoto que no es
necesaria para analizar un repositorio ya disponible para el usuario o su CI.
No hay campo de URL/host, remote, ruta local, token Git, SSH key ni cabecera de
proveedor. El endpoint rechaza campos adicionales y duplicados. Incorporar un
proveedor de hosting en el futuro requeriría otra revisión de amenaza; no debe
reutilizar esta ruta ni relajar su contrato.

## Flujo inicial

1. En un despliegue autenticado, un administrador abre **Set up Git import** y
   crea un grant de importación. Se muestra una sola vez, expira en 15 minutos
   y solo autoriza `POST /projects/import/git-snapshot`.
2. El operador exporta el valor como `INSPECTRA_IMPORT_TOKEN` en una terminal
   sin tracing. En modo local confiable no se necesita grant.
3. `inspectra scan <ruta> --commit <revisión>` negocia primero el contrato
   público sin token. Después obtiene los blobs rastreados del objeto Git local
   mediante `git ls-tree`/`git cat-file`; no lee cambios del worktree.
4. La CLI excluye fuentes sensibles/generadas, no sigue symlinks ni submódulos,
   aplica límites y ejecuta Gitleaks con canario. Si el preflight no es
   concluyente, no sube nada.
5. Tras la confirmación explícita, la CLI envía el snapshot genérico. El
   servidor consume atómicamente el grant antes de conservar bytes, comprueba
   el digest, crea el proyecto con canal atestado `git_cli` y agenda el análisis
   limitado existente.
6. El directorio temporal de la CLI se elimina al salir del contexto, también
   ante error. El snapshot retenido pasa a la política normal de retención del
   proyecto.

Para ejecuciones posteriores se usa la credencial de automatización ligada al
proyecto y `/projects/{id}/ci/snapshots`; `INSPECTRA_IMPORT_TOKEN` no sustituye
`INSPECTRA_TOKEN` ni permite leer, listar, informar o modificar otro recurso.

## Amenazas cubiertas y controles

| Amenaza | Control |
| --- | --- |
| SSRF o proxy de red | El backend no recibe ni resuelve URL/host y la CLI nunca ejecuta fetch o clone. |
| Fuga de credencial Git | No existe campo de credencial; el grant se lee solo del entorno y se persiste como hash con dominio separado. |
| Reutilización o carrera | Grant de un uso, consumo mediante transacción `BEGIN IMMEDIATE`, TTL 5–30 minutos y máximo tres activos por organización. |
| Cruce de organización | La organización procede del grant autenticado o de la sesión, nunca del formulario. Archivo, proyecto y trabajo se crean con ese mismo owner. |
| Hooks, submódulos o ejecución | La CLI usa comandos Git de lectura con hooks deshabilitados, excluye gitlinks/symlinks y no ejecuta scripts ni gestores. |
| Worktree o archivo no rastreado | La fuente son blobs del commit; no se empaquetan cambios locales, ignorados ni `.git`. |
| Contenido alterado en tránsito | SHA-256 local declarado y verificado antes de crear el proyecto; un mismatch elimina la subida. |
| Rutas o secretos en logs | Archivo genérico, eventos por IDs opacos y vocabulario cerrado; stderr de Git y contenido no se registran. |
| Agotamiento | Límites locales de archivos/bytes/blob y límites de upload/análisis/tiempo/concurrencia del servidor. |

## Límites conocidos

- Solo se admite un repositorio Git que ya exista localmente y cuyo commit esté
  materializado. Un shallow/partial clone incompleto debe resolverse fuera de
  Inspectra.
- El grant es deliberadamente fail-closed: si la conexión falla después de
  consumirlo, un administrador debe emitir otro. No se conserva el secreto para
  reintentos.
- La rama no se usa para autorización ni identidad; el commit y SHA-256 son la
  evidencia reproducible. Se puede omitir.
- El servidor conserva el snapshot según la retención del proyecto; no promete
  borrado inmediato mientras el proyecto siga activo.
- No existe integración real con GitHub, GitLab, Bitbucket u otro proveedor y
  no debe presentarse como tal.

## Validación operativa

Ejecute primero `inspectra scan <ruta> --commit HEAD --dry-run`. Verifique que
commit, árbol, contadores, tamaño, digest y canario sean coherentes. En modo
privado emita el grant desde una sesión administrativa, expórtelo sin guardarlo
en history y ejecute la orden mostrada por la UI. El proyecto debe indicar canal
Git/CLI y el commit exacto; un segundo uso del grant debe devolver `401`.

Las pruebas ordinarias usan stores temporales, transporte ASGI y servidor
loopback simulado. No clonan ni acceden a Internet.
