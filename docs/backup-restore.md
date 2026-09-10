# Copia y restauración fuera de línea

Contrato de backup: `2026-09-06.1`; layout: `1`.

Su inclusión y comportamiento de restauración se reflejan también en las
veinticinco clases del contrato de ciclo de vida `2026-09-10.7`; la política
consultable no sustituye este runbook ni extiende la purga a copias externas.

Inspectra dispone de una herramienta administrativa local para crear, verificar
y restaurar una copia coherente de su directorio de datos. No es una API ni una
acción de la interfaz: solo debe ejecutarla quien controla el host y el volumen
persistente. La herramienta no abre sockets ni acepta URL, repositorios o rutas
procedentes de un proyecto.

La auditoría de producto se copia junto con su ledger encadenado por
organización. El preflight recalcula cada digest, secuencia, enlace, ancla y
cabeza; un evento alterado, insertado, reordenado o eliminado invalida la copia
antes de publicarla. Tras restore, `GET /audit/integrity` debe devolver `valid`
o `empty` antes de confiar en el historial. Una cadena inválida no se reconstruye
automáticamente: se conserva el volumen afectado para investigación y se
restaura una copia verificada en un destino nuevo.

## Qué protege y qué no

Una copia completa contiene las fuentes subidas, resultados, proyectos,
inventarios e inteligencia normalizada, caché pública, decisiones, actividad
mínima y, si existe, el SQLite de identidad/autenticación. Por ello es un
artefacto **altamente sensible**: aunque las sesiones, CSRF, claves de intento e
invitaciones se almacenan como hashes, esos hashes y los password hashes siguen
requiriendo protección. El payload también conserva nombres de proyecto y de
archivo presentes en los registros.

El comando exige confirmar expresamente que:

- la aplicación está detenida y el almacén no recibe escrituras;
- se entiende que la copia contiene datos sensibles;
- el destino está en almacenamiento cifrado y con acceso restringido.

La herramienta crea directorios con modo `0700` y archivos con `0600`, pero no
implementa cifrado, KMS, subida remota ni rotación. El operador debe usar un
volumen cifrado o envolver posteriormente el bundle con cifrado autenticado. El
SHA-256 del manifiesto detecta corrupción accidental; no sustituye una firma ni
protege frente a alguien capaz de modificar payload y manifiesto.

Se incluyen únicamente `uploads/`, `results/` y el SQLite configurado bajo
`runtime/`. Los recibos comprometidos de lotes de remediación bajo
`results/remediation_batches/` forman parte del estado autoritativo: el
preflight comprueba organización, conjunto exacto de decisiones y digest de
cada registro para que un restore conserve el replay idempotente. Se excluyen deliberadamente locks, workspaces, journals de
operaciones pendientes, configuración externa, `.env`, claves TLS, logs del
proxy, descargas del navegador y snapshots/backups del operador. No se sigue
ningún symlink ni hardlink y no se lee nada fuera del directorio de datos. Una
fuente sensible dentro de una subida autorizada sí forma parte de la copia
completa: excluirla produciría una restauración incoherente.

Las colecciones `results/remediation_saved_views/` también se incluyen. Pueden
contener nombres elegidos por usuarios y preferencias de seguridad, por lo que
son sensibles aunque el contrato prohíba búsquedas libres, cursores y IDs de
proyecto/análisis/hallazgo. El preflight valida filename/organización, límites,
ownership y referencias de vista predeterminada antes de aceptar la copia.

La bandeja pasiva bajo `results/project_action_inbox/` forma parte del backup
porque sus marcas de lectura son estado de usuario durable. Solo contiene
motivos y destinos cerrados, IDs opacos, fechas y digests de lector; no incluye
nombres de proyecto, evidencia ni texto libre. El preflight limita cada
colección a 2 MiB/2.000 eventos, rechaza enlaces o schema inválido y verifica
que cada proyecto siga existiendo dentro de la misma organización. Restore
conserva las marcas; una reconstrucción administrativa posterior las reinicia.

Los jobs y artefactos de planes duraderos bajo
`results/remediation_plan_jobs/` y `results/remediation_plan_artifacts/` también
se incluyen como metadatos sensibles. El preflight rechaza cualquier plan en
cola, ejecución o cancelación, un artefacto ausente/huérfano, un digest distinto,
un cruce de organización o permisos/tipo/enlaces inseguros. Solo un plan
completado puede tener artefacto y restore conserva su expiración original; no
renueva los siete días ni reconstruye el contenido desde un estado posterior.

Los recibos semanales Active bajo
`results/active_weekly_review_receipts/` también se incluyen como material
derivado sensible. El preflight exige directorio `0700`, ficheros regulares
`0600`, una clave HMAC privada de 32 bytes y colecciones acotadas cuya firma y
organización coincidan. El raw digest del snapshot, targets, informe, actores,
notas y resultados no forman parte de esas colecciones. Restaurar únicamente
los JSON sin su clave invalida deliberadamente el almacén; restaurar ambos
conserva la verificación local y la caducidad original.

Los derivados privados `results/active_asset_index.sqlite3`,
`results/active_job_index.sqlite3` y
`results/active_verification_index.sqlite3`, además de
`results/project_reference_index.sqlite3` y
`results/project_risk_trend_index.sqlite3` y su reloj derivado
`results/risk_trend_source_clock.sqlite3`, junto con
`results/project_portfolio_priority_index.sqlite3`, se incluyen porque aceleran la
cartera, tendencias y el resumen semanal. El primero contiene identidades canónicas
privadas; el índice de jobs proyecta todos los trabajos para preservar cuotas
globales exactas, pero solo conserva IDs opacos, estado cerrado, tiempos,
digests y, para Active, la clave de idempotencia ya derivada por SHA-256. Los
otros derivados tampoco guardan targets, claves sin hash, resultados,
referencias de autorización ni material de desafíos. Para los índices de
identidades, jobs, activos y proyectos, el preflight verifica integridad,
versión, conjunto exacto de tablas, ownership, relaciones y digests contra
todos los JSON fuente; rechaza companions
`-wal`/`-shm`/`-journal`, filas huérfanas, omitidas, añadidas o cruzadas. Tras
restaurar, el primer uso vuelve a construir cada índice desde los JSON
validados. Por tanto, aceleran consultas pero nunca sustituyen la fuente de
verdad ni autorizan recuperar datos que no estén en ella.

El índice de tendencias schema v2 se valida como una proyección privada y
reconstruible: SQLite debe estar quiescente, con modo privado, tamaño máximo de
256 MiB, siete tablas exactas, integridad y claves foráneas válidas, una revisión
fuente digerida y como máximo 250.000 hechos por organización. Solo conserva
referencias opacas/digeridas, fechas, dimensiones cerradas, contadores y muestras
de duración; nunca nombres de proyecto/componente, rutas, texto, evidencia,
comentarios, actores o cuerpos de proveedor. La séptima tabla es un diario de
refresco sin contenido: owner, revisiones opacas, estado cerrado, tiempos,
contador y causa controlada. Un claim `rebuilding` restaurado vuelve a `queued`;
no se adopta como terminado ni se exporta una proyección stale como actual.

El reloj de fuentes de tendencias schema v1 también es reconstruible y está
limitado a 16 MiB y 10.000 claves de owner derivadas por SHA-256. El preflight
exige modo `0600`, dos tablas exactas, epoch y revisión fuente de 64 caracteres,
generaciones monotónicas y ausencia de companions SQLite. No conserva etiquetas
de tenant, nombres, rutas ni contenido. Los metadatos de directorio cambian al
copiar/restaurar, por lo que el arranque posterior al restore rota el epoch y
reconstruye las particiones de forma perezosa; el bundle no convierte ese reloj
en autoridad ni promete conservar una proyección como current entre máquinas.

Si el opt-in de métricas locales está activo, el bundle incluye también
`results/adoption_metrics.sqlite3`. Se valida como SQLite quiescente `0600`,
schema v1 exacto, máximo 16 MiB/8.192 filas y solo dimensiones cerradas de
flujo/fase/resultado/intervalo, fecha diaria y contador. No se aceptan columnas
o valores libres. El fichero no contiene IDs ni payloads, pero sigue revelando
volumen diario de uso y debe tratarse como metadato operativo sensible.

El índice de prioridad de cartera schema v2 es también privado y reconstruible,
con máximo de 256 MiB y 20.000 hechos por organización. El preflight exige el
conjunto exacto de cuatro tablas, integridad SQLite/foránea, revisión y digests
válidos, cardinalidad completa de hechos y tokens de prefijo, tiempos válidos y
permisos `0600`. Solo admite IDs opacos, contadores/estados cerrados, digests,
tiempos, ordinales y tokens HMAC: una columna adicional, nombre, ruta, evidencia
o topología incompleta invalida la copia. Tras restore se reconstruye antes de
usarse y cada resultado visible se contrasta con la autoridad JSON.
La clave opcional `INSPECTRA_PORTFOLIO_INDEX_HMAC_KEY` nunca forma parte del
bundle; solo se conserva su marcador HMAC no reversible. Restore debe inyectar
exactamente la misma clave o, con todos los backends detenidos, descartar este
único SQLite derivado y sus companions antes de permitir una reconstrucción.
Mezclar workers con claves antigua y nueva falla cerrado; no se admite una
rotación rolling. Esta clave resuelve solo la interoperabilidad de tokens del
índice y no convierte la cola JSON local en coordinación multiworker soportada.

El índice de proyectos añade únicamente IDs opacos, owner, microsegundos de
actualización, digest del registro y relaciones de baseline/fuente con separación
de dominio. La responsabilidad actual se proyecta solo como digest HMAC con
separación de dominio; el ID de miembro y su username no aparecen en SQLite.
El registro JSON autoritativo conserva el historial versionado necesario para
reconstruir la responsabilidad y el estado de atención tras una baja. No
contiene nombres, filenames, hallazgos ni código en el índice. El preflight
verifica también el esquema exacto, tiempo y digest contra cada proyecto; una
versión anterior, columna añadida o fila manipulada se rechaza. Los cursores de listado no se
persisten y deben reiniciarse tras restore.

La misma proyección de jobs acelera el historial paginado y por ello conserva el
ID opaco de proyecto cuando existe. El cursor del historial no se persiste ni se
incluye en backup: tras reinicio o restore el cliente debe volver a solicitar la
primera página. El preflight contrasta también `project_id` con cada JSON
autoritativo antes de aceptar el bundle.

Los metadatos autoritativos de proyecto incluyen el canal cerrado de admisión
de cada snapshot. Backup y restore lo preservan byte-semánticamente; no se
recalcula desde el commit, branch, filename ni tipo de job. Un snapshot legacy
sin canal continúa sin canal en almacenamiento y se presenta conservadoramente
como `unknown_git_or_ci` cuando contiene commit.

## Precondición fuera de línea

1. Deshabilitar nuevas cargas y egress, esperar o cancelar las ejecuciones y
   comprobar que todas son `completed`, `failed` o `cancelled`.
2. Detener el backend. Detener el proxy o dejarlo en mantenimiento para que
   ningún usuario interprete el periodo como operativo.
3. Confirmar que ningún proceso alternativo comparte el directorio. La marca
   `--offline-confirmed` es una atestación del operador, no detección mágica de
   procesos.
4. El preflight rechaza trabajos `queued`/`running`/`cancelling`, workspaces no
   vacíos, journals de snapshot/borrado de proyecto, remediación o activo Active y companions SQLite
   `-wal`/`-shm`/`-journal`. También rechaza registros inválidos, referencias
   rotas, cruces de owner/organización, symlinks, hardlinks y entradas
   temporales. Los journals pendientes de un alta Active masiva también
   bloquean la copia; sus recibos ya comprometidos se incluyen y solo son
   válidos cuando cada ID opaco referencia un activo de la misma organización.
   Las colecciones de aprobación de cambios Active también se incluyen: el
   preflight exige fichero privado, tenant coincidente y referencias solo a
   activos del mismo tenant. Los targets de solicitudes terminales ya deben
   estar redactados conforme al contrato antes de copiarse.

Los locks de storage y actividad se toman durante la copia como defensa
adicional, pero no convierten una copia online en soportada: identidad,
inteligencia pública y futuros almacenes no comparten hoy una transacción
global.

Si la validación devuelve `invalid_storage_reference` por divergencia de un
índice Active, no edite la copia. Mantenga Inspectra fuera de línea, conserve el
árbol fuente, arranque la misma versión sobre una copia de trabajo para que
reconstruya los índices, deténgala de nuevo y cree un backup nuevo. Un índice con
permisos amplios, symlink/hardlink, tamaño superior a 256 MiB o SQLite inválido
falla cerrado; no se reutiliza como evidencia.

## Crear y verificar una copia

El destino debe no existir, estar fuera del directorio fuente y residir en un
volumen cifrado. Ejemplo desde el checkout y su entorno Python verificado:

```bash
PYTHONPATH=backend .venv/bin/python -m app.backup_cli create \
  --data-dir /srv/inspectra/data \
  --destination /mnt/inspectra-encrypted/backups/inspectra-2026-09-06 \
  --offline-confirmed \
  --sensitive-data-confirmed \
  --encrypted-destination-confirmed
```

Si `INSPECTRA_AUTH_STATE_DB_PATH` usa una ubicación distinta de la estándar,
debe seguir dentro de `runtime/` y pasarse como ruta relativa:

```text
--auth-state-relative-path runtime/private/auth.sqlite3
```

El resultado seguro informa contrato, ID opaco, número de archivos, bytes,
digest agregado y presencia de auth state; nunca muestra paths del host,
proyectos, propietarios, nombres de archivo ni contenido. Verificación
independiente:

```bash
PYTHONPATH=backend .venv/bin/python -m app.backup_cli verify \
  --backup /mnt/inspectra-encrypted/backups/inspectra-2026-09-06 \
  --sensitive-data-confirmed
```

El bundle es un directorio con `manifest.json` y `payload/`. El manifiesto
versionado enumera solo paths relativos, tamaño y SHA-256, declara las clases
incluidas/excluidas y registra las versiones de esquema encontradas. Límites
duros actuales: 100.000 archivos, 1 GiB por archivo y 20 GiB agregados.

## Restaurar sin mezclar estados

La restauración solo acepta un directorio destino inexistente. Verifica
primero el conjunto exacto, todos los tamaños y digests; copia a un staging
privado; migra únicamente auth schema `1` a `2`; comprueba SQLite, referencias y
ownership; revoca todas las sesiones, intentos de login e invitaciones; y solo
entonces publica el directorio mediante rename atómico. Un error elimina el
staging creado por la operación y nunca modifica ni sustituye datos activos.

```bash
PYTHONPATH=backend .venv/bin/python -m app.backup_cli restore \
  --backup /mnt/inspectra-encrypted/backups/inspectra-2026-09-06 \
  --target-data-dir /srv/inspectra/data-restored-2026-09-06 \
  --offline-confirmed \
  --sensitive-data-confirmed
```

Después se debe apuntar el montaje a ese directorio nuevo, mantener el árbol
anterior intacto para rollback, arrancar la misma versión de Inspectra y
verificar `/health`, `/ready`, login nuevo y listados owner-scoped. Ninguna
sesión o invitación anterior debe funcionar. Los esquemas auth distintos de
`1`/`2` y team identity distinto de `1` se rechazan; no existe migración de
datos de producto más allá de sus contratos JSON actuales. Los activos,
verificaciones y jobs Active se validan por organización y referencia: una
verificación o ejecución que apunte a un activo ausente o de otro owner hace
fallar la copia/restauración cerradamente.

## Ensayo sintético reproducible

Antes de usar una copia de datos autorizados, el operador puede validar el
procedimiento con `drill`. Este subcomando **no acepta un directorio de datos de
Inspectra ni archivos del usuario**: genera dos propietarios, dos fuentes, dos
proyectos, actividad, triage, inteligencia deshabilitada y estado de acceso
exclusivamente sintéticos. Dentro de un workspace privado prueba la copia,
verificación, rechazo por checksum, ausencia de publicación parcial, restore,
límites de ownership, integridad y revocación; después elimina todo el workspace.
No abre conexiones de red y deja el egress deshabilitado.

El padre debe existir, estar fuera de una instancia activa y encontrarse en un
volumen cifrado/efímero controlado por el operador. Las tres marcas son
atestaciones deliberadas; no se infieren del filesystem:

```bash
PYTHONPATH=backend .venv/bin/python -m app.backup_cli drill \
  --workspace-parent /mnt/inspectra-encrypted/recovery-drills \
  --offline-confirmed \
  --synthetic-data-only-confirmed \
  --encrypted-workspace-confirmed
```

La salida JSON acotada contiene versiones de contrato, conteos, bytes, checks
booleanos y tiempos por fase. No contiene el path del workspace, nombres de
fuente/proyecto, propietarios, hashes, password, sesión, CSRF o invitación. Un
éxito exige `checksum_rejection_verified`, `corrupt_restore_not_published`,
`owner_boundaries_verified`, `source_integrity_verified`,
`retained_records_verified`, `source_rollback_preserved`,
`egress_disabled_verified` y
`workspace_cleanup_verified` a `true`; `active_instance_modified` y
`external_network_used` deben ser `false`. `observed_data_loss_records: 0`
describe solo la fixture congelada.

Medición de referencia local del 2026-09-06: 13 archivos, 132.546 bytes,
`total_ms: 398.012` dentro del ensayo y 0,78 s de proceso completo. Es una
observación reproducible sobre datos pequeños, **no** un RPO/RTO, capacidad ni
SLA. La configuración externa queda excluida y debe reponerse/verificarse por
separado. El arranque de una instancia restaurada, health/readiness/TLS y el
cambio real de montaje pertenecen a la aceptación operativa posterior.

## Fallos, privacidad y limpieza

Los errores de CLI son códigos estables (`checksum_mismatch`,
`active_jobs_present`, `invalid_ownership_boundary`, etc.) y no incorporan el
path recibido ni el mensaje interno. No deben conservarse trazas con argumentos
de línea de comandos si la política del host registra paths. Tras una prueba:

- eliminar el staging restaurado solo después de confirmar el rollback;
- expirar la copia según su política independiente;
- comprobar también snapshots del filesystem, descargas y logs externos;
- no afirmar borrado criptográfico ni purga de una copia sin evidencia del
  sistema que realmente la almacena.

No se publica RPO ni RTO. El ensayo sintético aporta tiempos observados y cero
registros perdidos en una fixture congelada; solo una prueba sobre el volumen y
tamaño autorizados podrá fundamentar objetivos operativos reales.
Las políticas Active recurrentes se incluyen como metadatos operativos. La
validación de restore exige que organización, activo y último job referenciado
pertenezcan al mismo límite de propietario; una referencia cruzada o huérfana
invalida el backup completo.
