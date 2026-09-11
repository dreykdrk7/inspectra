# Retención, privacidad y expurgo

Contrato de clasificación: `2026-09-10.7`. Contrato de limpieza y borrado:
`2026-09-10.1`. Contrato de backup: `2026-09-06.1`.

Inspectra separa la vida útil de las fuentes, los resultados, la inteligencia
pública y la trazabilidad administrativa. La política efectiva se puede
consultar, tras autenticarse cuando el despliegue lo requiere, en
`GET /privacy/retention` y en el panel **Data lifecycle**. La respuesta contiene
solo valores de configuración y semántica del ciclo de vida: nunca enumera
proyectos, paquetes, rutas, nombres de archivo ni contenido almacenado.

## Clases de datos

| Clase | Retención/eliminación | Backup y recuperación |
| --- | --- | --- |
| Fuentes subidas | 30 días por defecto o borrado explícito; un análisis activo las protege. Su eliminación no elimina el resultado retenido. | Incluidas como contenido sensible; restauradas. |
| Resultados terminales | 30 días por defecto o borrado de análisis/proyecto; nunca borra `queued`, `running` o `cancelling`. | Incluidos como metadatos sensibles; restaurados. |
| Inventario, cobertura y hallazgos locales | Embebidos; siguen exactamente al resultado y no tienen vida independiente. | Incluidos dentro del resultado; restaurados con él. |
| Evidencia de grafo aportada por CI | El artefacto Go crudo es efímero y no se persiste. Solo un recibo agregado y componentes corroborados siguen al resultado; el digest se conserva para binding e idempotencia. | Solo la proyección y el recibo forman parte del resultado restaurado; nunca el JSON, IDs o aristas originales. |
| Instantáneas normalizadas de vulnerabilidades | Siguen al resultado y se borran antes que él; datos públicos brutos no forman parte del snapshot. | Incluidas como metadatos sensibles; restauradas. |
| Caché de proveedores públicos | 1 día de frescura y 7 días máximos por defecto; compartida, digest-keyed y no owner-scoped. | Incluida pero regenerable; puede expirar tras restore. |
| Informes de proyecto, SBOM y bundles de evidencia Active descargables | Se producen por petición y no se persisten como exportación en el servidor. El informe mínimo de proyecto excluye identidad y detalle; el técnico requiere permiso/confirmación y sigue omitiendo secretos, rutas inseguras y fuente. El TAR y el informe técnico por activo contienen proyecciones redactadas; el informe semanal de cartera incluye deliberadamente los targets autorizados tras preflight y confirmación sensible. | No incluidos; descargas/caché del navegador y copias en sistemas de evidencia son externas y quedan bajo política del operador. |
| Planes duraderos de remediación | Snapshot owner-scoped acotado, con nombres de proyecto confirmados y sin rutas, contenido, comentarios ni actores. El artefacto expira automáticamente a los 7 días; metadatos fallidos, cancelados o expirados, a los 30. | Jobs y artefactos completados se incluyen como datos sensibles y conservan su vencimiento al restaurar; un plan en curso bloquea el backup. |
| Metadatos de proyecto | Hasta borrado explícito confirmado; la cascada no elimina automáticamente su subida independiente. | Incluidos como metadatos sensibles; restaurados. |
| Decisiones de hallazgos | Siguen al proyecto y se eliminan con su cascada owner-scoped. | Incluidas como metadatos sensibles; restauradas. |
| Bandeja pasiva de acciones | Sigue a los proyectos actuales. Retiene solo motivos cerrados, IDs opacos y marcas de lectura por usuario derivadas con SHA-256; la reconciliación retira señales resueltas y la cascada elimina las del proyecto. | Incluida como metadatos sensibles; restore valida organización y referencia de proyecto, y conserva el leído/no leído. |
| Metadatos y decisiones Active | Hasta borrado explícito del activo; incluye objetivo exacto, responsables, notas, baseline, triage y recibos sin target para repetición idempotente de lotes. Borrar cualquier miembro invalida y elimina el recibo de su lote completo. | Incluidos como metadatos sensibles; restaurados solo si todos los IDs opacos del lote siguen referenciando activos de la misma organización. |
| Revisiones de autorización Active | Append-only y ligadas al activo; se eliminan con su cascada explícita. | Incluidas con el activo; restauradas. |
| Verificaciones Active | Estados y digests de reto siguen al activo; el token en claro nunca es durable. | Incluidos como material derivado sensible; restaurados. |
| Ejecuciones y observaciones Active | 30 días por defecto para estados terminales, o borrado explícito del activo; el trabajo en curso nunca se elimina. | Incluidos como metadatos sensibles; restaurados. |
| Aprobaciones de cambios Active | Una solicitud accionable caduca a las 24 horas. Al consumirse, rechazarse, caducar o quedar interrumpida se elimina el target propuesto; el metadato cerrado restante se purga a los 90 días o con el activo. | Incluidas como material derivado sensible. Restore valida organización y referencias al activo; nunca contiene referencias de autorización, notas, responsables ni el payload completo. |
| Recibos de revisión semanal Active | Máximo 52 por organización y 400 días. Conservan periodo, corte, cobertura, resultado cerrado y HMAC con separación de dominio; nunca digest crudo, informe, target, actor, notas, comentarios ni resultados. | Incluidos como material derivado sensible junto con la clave HMAC privada; restore valida permisos, organización e integridad antes de publicar. |
| Workspaces de ejecución | Efímeros; limpieza al terminar/cancelar y recuperación al arrancar. | Excluidos; nunca restaurados. |
| Journals de recuperación | Efímeros y sin contenido; existen hasta completar snapshot/borrado y bloquean backup mientras estén pendientes. | Excluidos; nunca restaurados. |
| Actividad de producto | 90 días y 50.000 eventos globales por defecto; expira por organización eliminando solo un prefijo encadenado y avanzando su ancla. Ledger, entradas y cabeza siguen el evento; las exportaciones generadas no se retienen. | Eventos y ledger de integridad se incluyen como trazabilidad sensible; el preflight de backup verifica su relación y restore conserva la cadena. |
| Métricas privadas locales de adopción | Opt-in; contadores diarios globales con dimensiones cerradas y 90 días. No contienen IDs, rutas, payloads, timestamps ni duraciones exactas. Desactivar detiene nuevas observaciones; el operador puede borrar el SQLite offline. | Incluidas como metadato operativo sensible; restore valida schema/dimensiones y conserva únicamente agregados. |
| Sesiones y protección de login | Hashes acotados por TTL/ventana/bloqueo y revocación. | Incluidos en SQLite, pero restore revoca sesiones e intentos. |
| Credenciales de automatización | Máximo dos activas por proyecto durante una rotación; los metadatos revocados o caducados se purgan por organización tras 30 días por defecto. | Hash y metadatos incluidos; restore conserva credenciales, por lo que debe seguirse el procedimiento de rotación posterior. |
| Invitaciones de equipo | Los registros usados, revocados o caducados se purgan por organización 30 días después del estado terminal por defecto. | Incluidos como material derivado sensible; restore elimina todas las invitaciones. |
| Identidad y membresías de equipo | Una baja revoca el acceso y las asignaciones; sin otra membresía activa, pseudonimiza username y hash de contraseña. ID opaco y membresías revocadas persisten para integridad referencial. | Identidad y referencias incluidas; restore conserva identidades pero revoca sesiones. |
| Bundles de backup | Política, cifrado y expiración externos; la aplicación nunca los purga. | Son la copia externa y contienen fuente/estado sensible. |

La API no infiere esta tabla del contenido almacenado. Devuelve exactamente las
25 clases una vez cada una, con categoría, ámbito, forma de almacenamiento,
sensibilidad, relación padre, disparadores de borrado, inclusión en backup y
comportamiento de restore. No devuelve paths, nombres, paquetes, propietarios
ni conteos de datos existentes.

## Metadatos que identifican una fuente

El subcontrato `source_metadata_contract_version: 2026-09-09.2` separa la
retención interna de la presentación. Es una clasificación cerrada de cinco
campos y no una afirmación de que esos valores tengan la misma vida útil:

| Metadato | Uso y retención | Pantallas de proyecto | Informes/integraciones |
| --- | --- | --- | --- |
| Nombre original | Gestión autorizada de **Files** y registros internos heredados; sigue a cada registro que lo contiene. | Oculto. Un nombre de proyecto heredado que coincidía con el nombre derivado del ZIP se proyecta como nombre opaco. | Oculto. |
| SHA-256 del contenido | Integridad y reproducibilidad en fuente, proyecto y ejecución; sigue a cada registro que lo contiene. | Oculto. | Oculto. |
| ID interno de fuente | Autorización, propiedad y mutaciones concretas en **Files**; sigue a su registro. | Oculto; las respuestas de proyecto, instantánea y análisis lo omiten. | Oculto. |
| Referencia segura `snapshot-…` | Se deriva con separación de dominio desde el ID interno y no se persiste como dato nuevo. No es un hash del contenido. | Visible para distinguir instantáneas. | Visible para atribución sin publicar nombre o digest. |
| Canal de admisión | Enum cerrado fijado por el endpoint y la credencial efectiva; sigue al snapshot. Los commits históricos ambiguos permanecen `unknown_git_or_ci`. | Visible como archivo, Git/CLI, CI, SBOM o legacy no verificado. | Visible como procedencia no sensible; no contiene ruta, nombre, digest ni identidad. |

La respuesta owner-scoped de **Files** añade la misma referencia segura para
que el navegador pueda excluir una subida ya retenida sin volver a publicar el
ID en el proyecto. La eliminación de la subida no borra automáticamente copias de metadatos ya
retenidas por proyecto o análisis. La cascada o la retención de cada registro
son las que eliminan esos valores internos. La pantalla **Files** es la única
vista ordinaria que muestra deliberadamente nombre y digest de una subida al
propietario; no debe confundirse con una vista compartible de proyecto.

`INSPECTRA_UPLOAD_RETENTION_DAYS` e `INSPECTRA_JOB_RETENTION_DAYS` pueden ser
`0` únicamente en un entorno local deliberadamente no gestionado. El perfil
`private_tls_proxy` rechaza ambos valores deshabilitados. Un valor cero no
significa «no almacenar»: significa conservar hasta eliminación explícita.
`INSPECTRA_AUTOMATION_TOKEN_RETENTION_DAYS` controla entre 1 y 365 días cuánto
se conservan metadatos de credenciales ya revocadas o caducadas; no prolonga la
vigencia del bearer ni la retención independiente de los eventos de auditoría.
`INSPECTRA_TEAM_INVITATION_RETENTION_DAYS` controla entre 1 y 365 días cuánto se
conserva una invitación después de ser usada, revocada o expirar; el valor por
defecto es 30. La limpieza elimina la fila completa sin exponer hash, username,
rol o creador en respuestas, logs o auditoría.

## Ejecución manual

`POST /privacy/retention/run` no acepta cuerpo, parámetros, rutas ni selectores.
Requiere CSRF en los modos autenticados y rol administrador en espacios de
equipo. El backend deriva la organización exclusivamente de la sesión. La
acción:

1. evalúa resultados vencidos de la organización y elimina antes sus
   instantáneas normalizadas;
2. evalúa fuentes vencidas de la organización, preservando fuentes activas;
3. elimina entradas vencidas o inválidas de la caché pública compartida;
4. purga metadatos de credenciales inactivas solo de la organización activa;
5. purga invitaciones terminales vencidas solo de la organización activa;
6. expira actividad administrativa solo para la organización activa;
7. purga recibos semanales Active vencidos solo para la organización activa;
8. registra `retention.cleanup_run` sin rutas, nombres, contenido ni conteos en
   el historial administrativo.

Al arrancar, el modo de equipo aplica el mismo corte temporal a todas las
organizaciones. Un fallo queda como señal cerrada de mantenimiento y nunca
imprime token, hash, username ni detalle de SQLite. Restore elimina todas las
invitaciones y sesiones con independencia de su edad.

Cada clase devuelve `completed`, `disabled` o `failed`. Un fallo no oculta el
resultado de las demás clases y solo registra el tipo de excepción, nunca su
mensaje. La operación es reintentable: el borrado derivado se ejecuta antes de
eliminar su resultado, y las referencias a fuentes se marcan antes de eliminar
los bytes. No se ofrece borrado criptográfico ni garantía sobre bloques ya
copiados por snapshots del sistema de archivos.

La selección de resultados terminales no recorre el directorio completo en
estado estable. El índice privado schema v7 conserva únicamente metadatos
cerrados e índices parciales de retención; selecciona `completed`, `failed`
y `cancelled` con `updated_at` anterior o igual al corte, en orden estable y en
lotes internos de 100 (máximo técnico 500). El propietario es obligatorio en la
ejecución manual y opcional solo para el mantenimiento global de arranque.
Cada candidato se vuelve a leer y se comprueba por propietario, estado, fecha y
digest antes de borrar. El callback de evidencia derivada se ejecuta fuera del
lock global; si falla, el resultado autoritativo permanece para reintento. Tras
el callback se exige el mismo digest antes de eliminar, por lo que una
actualización concurrente, un resultado reciente o un job vivo nunca se borra.
Una interrupción deja los lotes no procesados indexados para el siguiente
arranque o ejecución manual.

Las tendencias históricas utilizan una proyección privada reconstruible
(`project_risk_trend_index.sqlite3`, schema v1) que sigue la retención de sus
resultados, snapshots públicos normalizados, proyectos y decisiones padre. Solo
conserva referencias opacas con separación de dominio, tiempos, digests,
dimensiones cerradas y contadores; no duplica nombres de proyecto/componente,
rutas, hallazgos, evidencia, comentarios, actores ni payloads. Admite hasta
250.000 análisis por organización y 256 MiB. Un cambio de las fuentes, un nuevo
proceso o una alteración del fichero obliga a reconstruir la partición desde la
autoridad; por tanto, borrar un padre no deja la proyección como fuente de verdad.

La marcación posterior de referencias de fuente usa el mismo índice privado:
proyecta solo `SHA-256("inspectra-job-source-reference-v1\\0" || file_id)` y un
bit cerrado de borrado, nunca el `file_id` en claro. La API interna acepta como
máximo 500 referencias y devuelve 100 jobs por lote. Cada resultado se valida
por owner, referencia real y digest dentro del lock compartido antes de marcarlo;
conjuntos mayores se dividen y una interrupción reanuda solo los pendientes.

Las relaciones retenidas por proyectos usan un SQLite privado separado
(`project_reference_index.sqlite3`, schema v1). Solo contiene ID de proyecto,
owner, digest del registro y digests con separación de dominio para baseline y
fuentes; omite nombre de proyecto/archivo, SHA-256 del contenido y referencias
crudas. `clear_baselines_for_analysis_ids` y `mark_source_file_deleted`
seleccionan 100 proyectos por lote, validan el JSON completo dentro del lock y
sincronizan cada escritura. El índice se adopta tras reinicio solo cuando
permisos, integridad y marcador del directorio coinciden; backup/restore vuelve
a contrastar todas sus filas y relaciones con los proyectos autoritativos.

La selección de fuentes vencidas usa otro SQLite privado
(`file_retention_index.sqlite3`, schema v1). Proyecta exclusivamente ID opaco de
fuente, owner, fecha de creación, nombre interno cerrado y digest del metadato;
no conserva nombre original, SHA-256 del contenido, bytes, ruta de usuario ni
referencias de proyecto. Consulta por owner y corte en lotes de 100 y admite el
máximo configurado de 1.024 fuentes protegidas por trabajos vivos. Cada
candidato, su protección dinámica, la marcación de relaciones derivadas, la
revalidación posterior del metadato y el borrado de bytes/registro se ejecutan
bajo el lock compartido mediante helpers que exigen que el caller ya lo posea.
Si el callback falla, la fuente se conserva; una protección o mutación aparecida
después de seleccionar evita el borrado. Una interrupción deja el índice y el
registro autoritativo disponibles para reanudar el lote siguiente. Adopción,
reconstrucción y restore vuelven a comprobar permisos, integridad, marcador y
correspondencia exacta con los metadatos JSON.

## Eliminación explícita de un proyecto

`GET /projects/{project_id}/deletion` ofrece una vista previa sin rutas, nombres
de archivo ni contenido. Distingue las clases que se eliminarán —proyecto y
baseline, trabajos terminales y resultados, snapshots de inteligencia,
decisiones de hallazgos, admisiones de snapshots y workspaces opacos— de las
que se conservarán. `DELETE /projects/{project_id}` exige
`{"deletion_confirmed": true}`, deriva organización y rol de la sesión y es
idempotente sin revelar si un identificador ausente pertenecía a otra
organización.

La operación se rechaza mientras exista un trabajo `queued`, `running` o
`cancelling`, o una admisión de snapshot pendiente. Antes de borrar se escribe
un journal privado y sin contenido bajo el lock del almacén. La marca bloquea
nuevas admisiones, oculta el proyecto y permite que un reintento o el siguiente
arranque termine la cascada; readiness falla cerrada mientras quede una
operación pendiente. Los derivados se eliminan antes que el metadato del
proyecto y los errores públicos/logs no incorporan el mensaje de excepción.

Las subidas originales se conservan deliberadamente: tienen un ciclo de vida
independiente en **Files** y un proyecto no puede demostrar que sea su único
consumidor. También se conservan la caché pública compartida sin identidad de
proyecto, la actividad administrativa mínima hasta su retención y cualquier
descarga, snapshot o backup externo bajo control del operador. La función no es
un borrado criptográfico. `PROD-120` queda pendiente y ya desbloqueada para
diseñar y ensayar una purga total de fuente y copias externas sin afectar a
otros propietarios.

## Eliminación explícita de un activo Active

`GET /active/assets/{asset_id}/deletion` devuelve un preflight owner-scoped que
solo contiene clases, disposiciones y conteos. El objetivo exacto, referencias
de autorización, notas, tokens y observaciones no se repiten en esa respuesta.
`DELETE /active/assets/{asset_id}` exige la confirmación literal
`{"confirmation":"DELETE ACTIVE ASSET"}` y elimina el agregado completo:
metadatos/target, responsables, notas, revisiones de autorización, verificaciones
y digests de reto, trabajos terminales, resultados, baseline y triage. Los
registros de aprobación asociados también se eliminan. Los
informes Active se renderizan por petición y no dejan artefactos de servidor.
También elimina cualquier recibo de repetición masiva que incluya el activo:
una repetición posterior no puede recrear silenciosamente el miembro borrado.

La operación queda bloqueada mientras exista un trabajo `queued`, `running` o
`cancelling`, o un reto de verificación pendiente. Preparación, admisión de
nuevos trabajos y comienzo de retos comparten el lock persistente: una vez
creado el journal no se admite trabajo nuevo y el activo queda oculto. La
cascada puede reanudarse tras una interrupción y solo elimina su journal después
de verificar que no quedan registros Active huérfanos.

Los eventos mínimos de producto se conservan hasta su expiración, pero se
desvinculan del target y de todos los jobs: recurso, correlación y metadata se
sustituyen por un recibo opaco de borrado sin valor de objetivo. Actor, acción,
resultado y fecha se mantienen para gobierno. El journal es efímero, no contiene
target ni contenido, hace fallar readiness de forma cerrada y bloquea el backup
hasta recuperarse. No existe borrado criptográfico ni se eliminan descargas,
backups o snapshots externos.

## Frecuencia y límites conocidos

No hay un planificador interno periódico. El mantenimiento ocurre al arrancar,
por acceso/escritura cuando el almacén lo contempla y cuando un administrador
lo solicita. Un despliegue siempre encendido debe programar una llamada
autenticada desde su plano de operación o ejecutar un reinicio de mantenimiento
controlado; esta automatización queda pendiente y no debe simularse con una
credencial embebida.

Inspectra no cifra el volumen en reposo ni gestiona KMS. La herramienta
administrativa de [copia y restauración fuera de línea](backup-restore.md)
produce un bundle privado, versionado y verificable, pero deliberadamente no lo
cifra: para datos reales se requiere volumen/destino cifrado, política de
expiración independiente, restauración ensayada y control de acceso del host.
El expurgo de la aplicación no elimina descargas, backups, snapshots, registros
de proxy ni copias externas.

## Validación operativa

- Consultar `GET /privacy/retention` y comparar sus valores con el archivo de
  entorno aprobado sin incluir secretos en la evidencia.
- Confirmar que la clasificación contiene exactamente cuatro metadatos de
  fuente y que solo `source_reference` está marcado para informes e
  integraciones.
- Crear únicamente fixtures sintéticos vencidos para dos organizaciones y
  comprobar que el mantenimiento de una no elimina datos propiedad de la otra.
- Mantener una ejecución sintética activa y verificar que su fuente no se
  elimina.
- Simular un fallo por clase y confirmar estado `partial`, ausencia de rutas en
  respuesta/logs y éxito de las clases restantes.
- Confirmar que el resultado eliminado pierde también detalle, informes, SBOM e
  instantáneas públicas, y que una línea base no queda apuntando a él.
- Previsualizar y eliminar un proyecto sintético con trabajos terminales,
  snapshots, triage y workspace; comprobar que deja de ser consultable y que la
  subida fuente continúa visible hasta eliminarla por su propia ruta.
- Interrumpir de forma simulada una cascada, reiniciar y verificar que el journal
  no contiene contenido, que readiness permanece no disponible y que la
  recuperación concluye de forma idempotente.
- Validar por separado la política de backup y ejecutar `verify` antes de un
  restore aislado: una copia externa no se considera purgada hasta que el
sistema de backup lo demuestre.

Los JSON/CSV de auditoría general redactada y de auditoría operativa Active se
generan bajo demanda y no se conservan en el servidor. Respetan la retención ya
aplicada al almacén de auditoría de producto, un periodo máximo de 365 días y un
máximo de 1.000 eventos/1 MiB por respuesta. La exportación general exige un
preflight ligado por SHA-256, confirmación y descarga dentro de cinco minutos;
además seudonimiza actores/recursos y omite organización, correlación y metadata.
La descarga pasa a ser responsabilidad del operador: el mantenimiento interno
no puede expurgar copias guardadas por el navegador, un proxy o un sistema
externo de evidencias.
Las políticas de recurrencia Active viven bajo `results/active_recurrences` y
retienen solo IDs opacos, capacidad/puerto autorizados, cadencia y referencias
a la revisión/verificación. El borrado explícito del activo elimina primero
todas sus políticas y verifica que no queden huérfanos; el preflight muestra el
recuento como `recurrence_policies`. No se retienen targets duplicados ni
expresiones de calendario libres. El contrato `2026-09-08.2` añade únicamente
zona IANA, días/horas cerrados, expiración de autorización y estado acotado de
reintento (contador, próxima elegibilidad, último resultado y marcas de tiempo).
No conserva errores libres, respuesta del runner, target, referencia de
autorización, rutas, secretos ni código. Una política legacy sin expiración
persistida se suspende al leerla hasta su reatestiguación explícita.

La cola de recurrencia dispone de una proyección privada separada
(`active_recurrence_index.sqlite3`, schema v1). Solo contiene IDs opacos de
organización/activo/política, estado cerrado, siguiente ejecución/reintento y
digest del JSON; quedan excluidos target, puerto/capacidad, actor, verification
ID y toda referencia o digest de autorización. La selección global devuelve
como máximo 16 políticas vencidas por tick en orden estable y vuelve a validar
el JSON, fechas, owner, estado, digest y ventana civil antes de admitir trabajo.
Listar, contar, suspender o borrar por activo usa el agregado owner-scoped sin
recorrer el resto de políticas. Cada mutación sincroniza la proyección; un
marcador de directorios permite adoptarla tras reinicio solo con permisos,
integridad y estado coincidentes. Backup/restore contrasta esquema, columnas y
cada fila con los JSON autoritativos.

El informe semanal de cartera Active (Markdown o JSON) también se genera solo
bajo demanda y nunca se escribe en el volumen de Inspectra. Su preflight no
contiene targets; la descarga confirmada sí incluye los objetivos exactos de
los activos autorizados incluidos, hasta 500, y queda ligada a un cutoff y
digest válidos durante cinco minutos. Requiere rol mantenedor o administrador.
El evento durable conserva únicamente acción, periodo de revisión y formato cerrados, no el
target, digest del informe ni contenido. La eliminación o retención interna no
puede retirar una copia ya descargada, enviada o guardada en un proxy: esa copia
debe tener una política externa de acceso, expiración y destrucción.

Los grafos CI Go y Cargo no se almacenan como artefactos. El trabajo terminal
retiene únicamente una proyección de componentes corroborados y recibos
agregados ligados por SHA-256/commit. Para Cargo se excluyen expresamente IDs de
nodo/target, nombres de features, raíces y aristas. Estos recibos se eliminan
con el resultado del análisis bajo su misma política de retención.

Composer graph uploads are ephemeral request bodies. Inspectra retains only the
artifact SHA-256, contract/commit binding, accepted/truncated/divergent state,
aggregate node/edge/match/cycle counts and projected relationship status. Raw
node IDs, root sets and edges, repositories, URLs, package hashes and producer
metadata are not retained.

Gradle graph uploads are also ephemeral. The result retains only the validated
artifact/contract/commit digests, closed scope coverage, aggregate counts and
projected direct/transitive status plus scope count for matched components. Raw
coordinates from the upload, node IDs, roots, edges, configuration names,
repositories, URLs, paths and build metadata are not retained. The receipt is
deleted with the analysis.
