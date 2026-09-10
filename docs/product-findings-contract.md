# Contrato normalizado de hallazgos de producto

## Uso en la cartera global

La cartera cuenta el estado efectivo de los hallazgos de la última ejecución
completada. Una decisión local `resolved` o `false_positive` deja de contribuir
al riesgo actual, pero no borra la evidencia append-only. Los hallazgos públicos
se mantienen como acciones pendientes hasta que el centro de remediación tenga
un contrato de triage equivalente; Inspectra no aplica por inferencia una
decisión local a otra huella.

Los cambios nuevo/persistente/resuelto solo se publican cuando baseline y
ejecución actual coinciden en proyecto, analizador, perfil de análisis, perfil
de ejecución y cobertura. Si disminuyen manifiestos, lockfiles, dependencias o
entradas observadas, el estado pasa a `not_comparable`: puede mostrar evidencia
actual, pero no declarar resolución. La cartera reutiliza las huellas
normalizadas y snapshots públicos ya persistidos; no vuelve a abrir el código
fuente para construir el panel.

Los resultados persistidos que contienen hallazgos usan, desde `PROD-003`, una
vista adicional llamada `normalized_findings`. No reemplaza el resultado propio
del analizador: permite a las vistas, comparaciones e informes posteriores
consumir un formato conservador y común.

## Versión y campos

La versión actual es `2026-09-05.1`. Cada elemento contiene:

- `id`: huella SHA-256 estable de la procedencia, regla, ubicación y evidencia
  ya redactada. Es un identificador de correlación, no un identificador CVE.
- `rule_id`, `source_audit_type`, `title` y `category` para explicar la regla y
  su origen.
- `severity` (`critical`, `high`, `medium`, `low` o `info`) y `confidence`
  (`high`, `medium`, `low` o `unknown`). Los valores que un analizador no
  declara no se adivinan: pasan a `info` y `unknown` respectivamente.
- `description`, `evidence`, `location` (`path` y/o `line`) y
  `recommendation`, cuando el analizador los proporciona. `location_status`
  distingue una ubicación `reported`, una ruta insegura
  `withheld_unsafe_path` y una ubicación `not_reported`.
- `references`, limitada a CVE, GHSA u OWASP con identificador válido y enlace
  HTTPS canónico de su fuente pública.

La envoltura también incorpora `normalized_findings_summary`, con el total y
los contadores por severidad y categoría.

## Límites de confianza y privacidad

Antes de normalizar, el almacenamiento aplica la redacción de resultados de
Inspectra. Por ello la huella y la vista normalizada no se derivan de un secreto
sin redactar. La fuente original sigue siendo sensible y se conserva conforme a
la política de retención del proyecto.

Una ruta se conserva solo si es relativa y portable dentro del proyecto. Se
normalizan separadores de Windows y se rechazan raíz Unix/Windows/UNC, URL,
traversal, segmentos vacíos o de punto y caracteres de control. Al rechazarla,
la ubicación se omite y se declara `withheld_unsafe_path`; ni la ruta original
ni su línea participan en la huella nueva. Los consumidores vuelven a aplicar
esta política al leer contratos heredados, cuya huella se conserva como
identificador histórico pero nunca se usa para revelar la ruta retenida.

Una referencia se conserva solo si la regla ya proporciona un identificador y
un enlace que coincide con las formas públicas permitidas (NVD/CVE, GitHub
Advisories u OWASP). Esta validación no consulta ni confirma una base externa
en tiempo de ejecución y **no convierte un indicador de higiene en una
vulnerabilidad confirmada**. El enriquecimiento de dependencias con una fuente
de advisories versionada y su evidencia reproducible se planificará como una
tarea de producto separada.

Al mostrar una acción de corrección, el cliente vuelve a validar la referencia
retenida antes de crear un enlace: exige HTTPS sin credenciales, fragmento ni
puerto, el dominio público permitido y la forma canónica que incorpora el
identificador. Los contratos heredados que no superan esa comprobación pueden
seguir mostrar el hallazgo, pero no generan un enlace accionable. Copiar una
recomendación copia exclusivamente el texto de `recommendation`; nunca agrega
evidencia, rutas, identificadores de proyecto, archivo ni metadatos de la
ejecución.

En los análisis de archivo de proyecto, el normalizador prefiere la copia del
hallazgo vinculada al manifiesto para conservar su ruta y elimina el duplicado
equivalente de la lista agregada. Los valores desconocidos, incompletos o
malformados se omiten o degradan de forma segura; nunca se inventan archivo,
línea, CVE ni recomendación.

## Comparación entre ejecuciones

La comparación de proyecto usa exclusivamente estas vistas normalizadas ya
persistidas, nunca el archivo ni el resultado bruto. Solo admite dos
ejecuciones completadas del mismo proyecto, propietario, tipo de analizador y
perfil. Si los perfiles difieren, si falta una vista compatible o si una
ejecución sigue pendiente, declara el límite en vez de clasificar hallazgos.

Los hallazgos con el mismo `id` son **persistentes**; si sus campos seguros
cambiaron, la respuesta enumera cuáles (por ejemplo, severidad). Un ID nuevo
en la ejecución objetivo es **nuevo**, y uno ausente de ella es **resuelto**.
Como la ruta y la evidencia redactada son parte de la huella, mover una regla o
cambiar su evidencia se muestra conscientemente como resuelto y nuevo, no como
una corrección confirmada. Los resultados truncados y las fuentes ya vencidas
se conservan como limitaciones explícitas de la comparación.

Los informes de proyecto reutilizan la misma lista y no consultan el resultado
original. El perfil mínimo, usado por defecto, publica únicamente agregados de
riesgo, workflow, cobertura e inteligencia pública: no incluye nombres,
identificadores internos, ubicaciones, evidencia, identidad de componentes o
advisories ni texto libre. El perfil técnico requiere permiso y confirmación en
un `POST` protegido por CSRF. Solo entonces añade el detalle normalizado, vuelve
a redactar los textos y descarta una ubicación absoluta, con `..` o de estilo
Windows: un informe no debe convertir un registro histórico mal formado en una
fuga de rutas del host. No existe enlace público de informe y este contrato no
expone JSON ni SARIF.

## Ciclo de vida y excepciones revisables

Desde `PROD-011`, cada hallazgo normalizado puede tener un estado de trabajo:
`open`, `in_review`, `accepted`, `false_positive` o `resolved`. La evidencia
del analizador no se edita ni se elimina. Cada decisión crea un registro
inmutable y enlazado con el anterior mediante proyecto, hallazgo, regla,
actor y fecha. La API deriva esos identificadores del recurso autorizado; el
cliente no puede asignar una decisión a otro hallazgo o proyecto.

Las transiciones admitidas son deliberadamente explícitas:

- `open` puede pasar a revisión, riesgo aceptado, falso positivo o resuelto;
- `in_review` puede reabrirse o pasar a cualquiera de los estados finales;
- `accepted` puede reabrirse, volver a revisión o resolverse;
- `false_positive` y `resolved` pueden reabrirse o volver a revisión.

### Lotes recuperables de remediación

El contrato de acción masiva `2026-09-09.2` exige una clave de idempotencia
generada por el cliente. Inspectra la liga a la organización, actor, grupo,
revisión y selección exacta, pero persiste únicamente digests opacos. Un
diario privado establece el estado `prepare`; las decisiones de ese lote no
son visibles hasta publicar atómicamente su recibo de commit. Si el proceso se
interrumpe después del prepare, el siguiente arranque termina la misma
operación y `/ready` permanece degradado mientras exista un diario que no pueda
recuperarse.

Repetir exactamente la solicitud devuelve las decisiones originales con
`replayed=true`; reutilizar la clave con otro payload falla cerrado. Journals y
recibos no contienen motivo, comentario, username ni evidencia. Un backup
fuera de línea incluye solo los recibos ya comprometidos y rechaza cualquier
operación pendiente; tras restaurar se conserva el replay sin duplicar el
historial append-only.

### Vistas guardadas de remediación

El contrato `2026-09-09.1` permite guardar hasta 20 vistas por cuenta. Una
vista conserva exclusivamente los filtros cerrados de prioridad, tipo de
evidencia, ecosistema, alcance de dependencia, estado de workflow y orden. No
admite ni persiste texto de búsqueda, cursor, tamaño de página, proyecto,
análisis o hallazgo. El nombre se limita a 3–60 caracteres portables y se
normaliza; aun así se considera dato privado y nunca entra en auditoría ni
logs.

La colección completa queda limitada a 1.000 vistas y 2 MiB por organización,
en un archivo regular de enlace único publicado con modo `0600`; symlinks,
hardlinks, exceso de tamaño, referencias rotas o cruces de organización fallan
cerrados.

Cada usuario interactivo puede crear vistas privadas y elegir una vista propia
o compartida como predeterminada. Solo maintainer y administrator pueden
publicar una vista para el workspace; compartir nunca cruza la organización.
Una cuenta solo borra sus propias vistas. Al revocar a un miembro se eliminan
sus vistas y todas las referencias predeterminadas que apuntaban a ellas. Los
tokens de automatización no acceden a preferencias interactivas.

La interfaz aplica la vista predeterminada sin restaurar búsquedas libres,
distingue `private` de `workspace` y mantiene utilizables los filtros actuales
si el almacén falla. Backup/restore valida la organización y el contrato de
cada colección; la vista materializada nunca sustituye la evidencia ni las
decisiones append-only.

### Planes duraderos de remediación

El contrato de job y artefacto `2026-09-09.1` permite preparar una exportación
de carteras grandes sin mantener una petición HTTP abierta. Crear el plan exige
confirmar explícitamente que el resultado contiene nombres de proyecto. La
clave de idempotencia queda ligada por digest a organización y filtros; nunca se
persiste en claro. Se admiten como máximo dos planes en curso y cien registros
por organización.

El job fija un `cutoff_at` y la revisión opaca del índice de proyectos, pagina
100 proyectos por vez y carga una única fotografía de decisiones. Si cambia el
índice, aparece una decisión posterior al cutoff o se rompe una fuente, el job
falla sin publicar un artefacto parcial. Puede cancelarse; tras un reinicio un
job en ejecución vuelve a cola hasta tres veces y una cancelación pendiente se
cierra como cancelada. Reintentar crea una identidad nueva enlazada al intento
anterior.

El artefacto privado conserva hasta 100.000 proyectos procesados, 2.000 grupos,
5.000 ocurrencias y 16 MiB. Declara todo truncado y las limitaciones de
cobertura. JSON y CSV se renderizan exclusivamente desde el mismo artefacto
inmutable y comparten su SHA-256 de snapshot. Incluyen los nombres de proyecto
confirmados y evidencia normalizada necesaria para remediar, pero omiten rutas,
código o contenido fuente, comentarios de decisiones e identidades de actores.
Solo la organización autorizada puede consultar o descargar el plan.

Los artefactos expiran a los siete días; los metadatos terminales fallidos,
cancelados o expirados se purgan a los treinta. Backup/restore incluye y valida
jobs y artefactos completados, pero rechaza una copia mientras haya planes
`queued`, `running` o `cancelling`. El índice y el artefacto son proyecciones:
los proyectos, análisis, inteligencia y decisiones siguen siendo la fuente
autoritativa.

Toda transición exige un motivo. Las excepciones `accepted` y
`false_positive` requieren además una confirmación explícita en la interfaz y
una fecha de revisión UTC obligatoria, posterior al momento de la decisión y
como máximo a 366 días. Al vencer, el estado efectivo pasa a `in_review` sin
reescribir el historial. Un registro legado sin fecha también falla de forma
segura a `in_review`: se conserva como evidencia histórica, pero nunca actúa
como excepción indefinida. Renovar, cambiar o revocar una
excepción exige una nueva decisión. El contrato limita el texto, vuelve a
redactarlo antes de persistirlo y no incluye comentarios libres en logs ni en
informes exportados.

En modo de equipos, solo `owner` y `maintainer` pueden registrar decisiones;
un `reader` conserva acceso de lectura. Una asignación solo puede apuntar a un
miembro activo de la organización actual. En modos sin equipos la asignación,
si existe, queda limitada al operador actual. Los controles de propietario,
organización, proyecto y ejecución se aplican antes de resolver el hallazgo,
por lo que un ID conocido de otro ámbito responde como recurso inexistente.

Las respuestas de hallazgos incluyen un resumen por estado, cuántos hallazgos
necesitan revisión y una señal distinta `review_overdue` cuando fue una fecha
de excepción la que venció. Las comparaciones incorporan el estado actual
de cada hallazgo nuevo, resuelto o persistente. Los informes Markdown, HTML y
PDF muestran estado, responsable, razón de la última decisión y fecha de
revisión, pero nunca el comentario libre. Estos metadatos explican el triage;
no alteran la clasificación técnica ni prueban que el riesgo haya desaparecido.

Cada proyecto admite como máximo 10.000 decisiones y cada hallazgo 100. El
almacenamiento rechaza de forma cerrada registros dañados o incompatibles. Esta
implementación es un historial local append-only, no sustituye todavía a un
registro empresarial firmado o a una política de retención/backup verificable.

El mismo historial admite hallazgos públicos normalizados con identidad
`pvf_<sha256>`, siempre que la API vuelva a resolver esa identidad dentro del
snapshot de inteligencia del análisis y proyecto autorizados. Los identificadores
heredados no canónicos siguen siendo legibles, pero no son mutables. El centro de
remediación agrupa estas evidencias sin mezclar el estado técnico con el triage:
un estado `resolved` que aún aparece en el análisis actual se presenta como
`awaiting_reanalysis` o `still_detected`, nunca como riesgo corregido.

Las acciones transversales requieren la revisión exacta del grupo y de cada
ocurrencia, una revisión de grupo vigente y confirmación explícita. Se limitan a
25 hallazgos distintos y se persisten como lote append-only atómico; un fallo de
validación, transición, concurrencia o almacenamiento no deja decisiones
parciales. La asignación continúa limitada a un miembro activo de la organización
y los textos se redactan antes de persistir. El evento de auditoría registra solo
grupo, cantidad, estado y actor, no comentarios, rutas, evidencia ni contenido.

## Agregación temporal y resolución verificada

Las tendencias de organización no comparan fotografías arbitrarias. Cada evento
`new`, `persistent` o `resolved` procede de dos análisis consecutivos retenidos
del mismo proyecto, con perfil de ejecución idéntico, listas válidas y cobertura
equivalente. La inteligencia pública exige además snapshots `ready` en ambos
lados. Las transiciones sin predecesor, perfil, cobertura compatible o evidencia
válida se contabilizan como exclusiones; nunca se convierten en ceros o mejoras.

El tiempo hasta primera revisión parte de la primera observación retenida dentro
del periodo y de la primera decisión append-only posterior. El tiempo hasta
resolución solo se mide cuando el ID deja de aparecer en un análisis comparable;
un estado manual `resolved` por sí solo no cierra la muestra. La respuesta
publica denominadores y tamaño de muestra, no inventa un SLA ni infiere exposición
o despliegue. CVSS, KEV, cobertura y estado de workflow siguen siendo dimensiones
separadas.

Estos hechos se materializan en un índice privado reconstruible para evitar
cargar hasta 250.000 resultados completos por organización en cada petición.
La proyección guarda únicamente referencias con separación de dominio, fechas,
digests, dimensiones cerradas, contadores y muestras de duración. No conserva
nombres de proyecto o componente, rutas, IDs/texto de hallazgo, evidencia,
recomendaciones, comentarios, actores ni payloads de proveedor. Cada proceso
nuevo y cada revisión de fuente distinta obliga a reconstruir; una consulta
caliente valida una muestra acotada de digests autoritativos. La cartera actual
y sus nombres siguen fuera de esta proyección y conservan el límite explícito
de `PROD-241`.

## Evidencia de relaciones de dependencias

El inventario `2026-09-10.1` puede incorporar un recibo Go `2026-09-10.1`
aportado por CI. `accepted` significa que commit, snapshot, único root
`go.mod`/`go.sum`, nodos, raíces y alcanzabilidad coincidieron; `truncated`
conserva las mismas comprobaciones pero hace inconclusa la completitud;
`divergent` conserva solo contadores y una razón cerrada y no añade identidades.
Los ciclos se informan como propiedad del grafo, no como vulnerabilidad.

El alcance `direct` o `transitive` y `relationship_status` son evidencia de
relación, no de procedencia pública, afectación ni explotabilidad. OSV solo puede
consultarse después mediante su política independiente. Comparaciones e
informes consumen la misma proyección persistida; nunca reconstruyen relaciones
a partir de `// indirect`. El JSON original, IDs de nodo, raíces y aristas no se
persisten ni se exportan.

Cargo usa un recibo separado `2026-09-10.2`. Además del binding anterior,
corrobora cada crate contra un único `Cargo.lock` v3/v4 de fuente oficial y
exige roots exactos para las declaraciones resolubles. La proyección añade solo
`enabled_feature_count` y `target_variant_count`; nombres de features, target
IDs, node IDs y aristas no cruzan la persistencia. Un root cuyo rango no se
resuelva de manera inequívoca, una identidad ajena al lock o un nodo
inalcanzable produce `divergent`; truncación y ciclos permanecen explícitos.
La evidencia Cargo tampoco concede procedencia pública ni sustituye OSV.

## Compatibilidad

Los consumidores deben comprobar la versión antes de depender de campos nuevos.
La ausencia de `normalized_findings` significa que ese resultado no expuso una
lista compatible en el momento de persistirse; no significa que la ejecución no
tenga observaciones. Los informes especializados existentes siguen leyendo el
resultado de origen hasta que el informe de proyecto los reúna.

Composer graph evidence changes only local relationship scope. Contract
`2026-09-10.3` does not establish Packagist provenance and therefore cannot by
itself make a component eligible for public advisory egress. Divergent or
truncated evidence must remain explicitly inconclusive in findings and reports.

Gradle contract `2026-09-10.4` changes only local relationship scope for exact
coordinates already present in the retained lock inventory. Its aggregate
receipt declares `relationship_origin: ci_reported`, closed scope coverage and
truncation/divergence. It does not create a vulnerability finding, interpret
the Gradle DSL or attest Maven Central provenance.

NuGet graph contract `2026-09-10.5` changes only local relationship scope and
target-variant count for exact identities already present in the retained
`packages.lock.json` v1 projection. Target IDs remain opaque and are never
persisted. Its receipt records `relationship_origin: ci_reported`; it does not
create a finding, execute restore/MSBuild or attest NuGet.org. Divergent and
truncated evidence remains explicitly inconclusive.

NuGet version semantics contract `2026-09-10.1` defines one package identity
for OSV correlation: one to four bounded numeric segments, normalized leading
zeros and missing minor/patch, omitted zero revision/build metadata, and
case-insensitive prerelease labels with numeric label ordering. Event bounds
and fixed versions are normalized by the same function. Unsupported or
ambiguous forms produce `unknown`; they never establish a clean result. The
PVI envelope exposing this behavior is `2026-09-10.6`.
