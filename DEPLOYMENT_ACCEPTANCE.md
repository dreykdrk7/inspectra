# Candidatura de despliegue y aceptación de Inspectra

## Estado canónico actual

- **Última aceptación real de proyecto: GO acotado.** La segunda ejecución de
  `PROD-117`, con la fuente B autorizada, validó OSV oficial y CISA KEV dentro
  del alcance documentado más abajo. No validó GHSA/NVD reales, estabilidad,
  publicación ni despliegue externo.
- **Última validación funcional remota: verde y no publicada.** El commit
  `7f7614cc2c2024aaa90506841bf05b576c4bdb38` pasó CI; el tip documental
  posterior `e40b61124023613ca39d89f0195ce46de6f7b066` no cambia producto. La
  versión sigue siendo `0.3.0-beta.1`, sin merge, tag ni release.
- **Cambios posteriores: requieren una aceptación nueva.** Un árbol de trabajo
  distinto, especialmente si contiene cambios sin confirmar, no hereda esos
  veredictos. Debe fijarse por commit, repetir las puertas y el flujo aplicable,
  y registrar un acta antes de considerarlo desplegable.

Los `NO-GO` posteriores permanecen como hitos históricos fechados, no como el
estado global actual. En particular, la primera ejecución de `PROD-117` con la
fuente A terminó `NO-GO` porque no contenía una versión exacta correlacionable;
ese resultado no fue reescrito ni se interpretó como una consulta real.

## Alcance de la candidatura

La primera candidatura será privada, de un único administrador y detrás de
HTTPS. No es una configuración multiempresa ni una autorización para exponer
Inspectra públicamente. El flujo aceptado será: iniciar sesión, cargar un ZIP
autorizado, crear el proyecto, seguir el análisis pasivo, revisar inventario y
cobertura, activar OSV solo si el operador aprueba la salida mínima, comparar
dos instantáneas, exportar un informe y eliminar los datos de prueba según la
política documentada.

El vertical inicial de `private_team_lightweight_users` desarrollado en
`PROD-012` conserva organización/roles y `PROD-013` añade su bitácora mínima,
pero queda fuera de esta primera candidatura hasta completar backup/restore,
retención por derivado, matriz integral de permisos y una prueba con dos
espacios. Su presencia en el código no autoriza habilitarlo en el host de
aceptación.

El adaptador NVD CVE-exacto está validado únicamente con fixtures y transportes
simulados y permanece desactivado por defecto mediante un control separado. Las
aceptaciones históricas reales de OSV y CISA se documentan más adelante; GHSA y
NVD no se consultaron. Toda futura prueba real debe registrar por separado si
cada fuente se contactó y respondió. KEV solo puede enriquecer por CVE exacto
un hallazgo ya correlacionado; nunca determina que un paquete sea vulnerable.

## Validación local acumulada de la revisión de trabajo

El 2026-09-06 se validó la capa operativa sin desplegar ni usar un proyecto
real. La recuperación durable se separó en 796/796 y 211/211 por grupos, y pasó
1.007/1.007 de forma conjunta. Tras añadir admisión global/por propietario, la
última regresión pasó 1.011/1.011 backend (15,56 s), 412/412 runner/estáticas
(5,39 s), 38 archivos y 277/277 pruebas frontend (18,89 s), build con bundle
inicial 311,6/322 KiB (7,51 s); `compileall`, Compose
base/privado y comprobación de diff. No hubo pruebas omitidas, Internet ni
proveedor real. El frontend se validó desde una copia temporal de la misma
fuente porque la instalación existente no permite escribir
`node_modules/.vite-temp`. Estos resultados son evidencia del árbol de trabajo,
no el acta de candidatura. La inteligencia pública se revisó en la aplicación
real con API y datos sintéticos a 320/768/1440 px, sin desbordamiento ni errores
de consola, y con `ready`/`stale` diferenciados; las tres fuentes continuaron
simuladas. Siguen pendientes imágenes, digests, smoke TLS, el ensayo medido de
backup/restore,
revisión visual de los demás recorridos y reversión en el host aislado.

La estabilización `PROD-122` elevó la regresión a 1.019/1.019 backend
(16,90 s) y 420/420 runner/guardas (6,09 s); frontend volvió a pasar 277/277
(19,15 s) y build 311,6/322 KiB (7,29 s). Se construyeron localmente backend,
`audit-tools` y `network-tools`. Un smoke sintético de la imagen final ejecutó
`audit-tools` con red `none`, raíz de solo lectura y tmpfs dedicado: el digest
de la fuente coincidió, el contrato fue `2026-09-06.1`, el endpoint de red
respondió 404, `/app/data` no existía, el tmpfs quedó vacío y al final solo
seguía Uvicorn. Compose renderizado confirmó que ninguno de los runners monta
datos y que solo `network-tools` pertenece a la red de egress. Esta evidencia
tampoco constituye una candidatura: no se ensayaron TLS, backup/restore,
reversión ni proyecto real autorizado.

`PROD-073` añade una bitácora privada e idempotente para altas de nuevas
instantáneas y el límite `INSPECTRA_PROJECT_MAX_SOURCE_SNAPSHOTS` (100 por
defecto). Una interrupción entre el proyecto y el job se completa con los IDs
ya reservados antes de recuperar la cola; una repetición compatible no duplica
historial. La clave en claro, nombres y rutas no se conservan en la bitácora.
Pasaron 1.023/1.023 pruebas backend (26,44 s), 420/420 runner/guardas (6,17 s),
278/278 frontend (20,11 s), build/presupuesto 311,8/322 KiB (10,45 s),
`compileall`, Compose base/privado y diff. Este cambio no modifica todavía el
estado de candidatura.

`PROD-011` añade triage append-only sin reescribir hallazgos: transiciones,
actor, razón redactada, asignación autorizada y excepciones con revisión futura.
La validación pasó 1.050/1.050 backend, 420/420 runner/guardas y 290/290
frontend; la revisión local sintética cubrió 1440/768/390/320 px, persistencia
de fecha, historial, filtros, comparación e informe. Esto no completa la
candidatura: la bitácora consultable (`PROD-013`), privacidad/retención,
backup/restore y rollback siguen pendientes y no se usó un proyecto real.

`PROD-013` añade una bitácora mínima por organización para acciones de sesión,
equipo, proyecto, análisis, inteligencia pública, triage y exportación. La
consulta paginada deriva el ámbito de la sesión y en modo equipo requiere rol
administrador; los intentos denegados quedan registrados sin cuerpo ni nombre.
La retención por defecto es 90 días y el límite 50.000 eventos. El contrato
excluye código, evidencia, rutas, URLs, paquetes, nombres, hashes, cookies,
tokens y credenciales. Pasaron 1.058 pruebas backend, 420 de runner/guardas,
292 frontend, build/presupuesto y revisión responsive sintética. El ensayo de
restore/expurgo sigue pendiente y este resultado no convierte el borrador en
candidatura.

`PROD-020` hace visible el ciclo de nueve clases de datos y añade una purga
administrativa sin selectores: fuentes/resultados pertenecen solo a la
organización activa, los snapshots normalizados se eliminan antes que su job y
la caché compartida solo contiene respuestas públicas bajo claves digest. Un
fallo se informa por clase sin mensaje sensible. Pasaron 1.063 backend, 420
runner/guardas y 295 frontend, además de build/presupuesto, Compose y revisión
responsive. La prueba detectó y corrigió un deadlock real de almacenamiento.
`PROD-036` añade después una cascada recuperable por organización: una vista
previa declara las clases eliminadas y retenidas, la confirmación bloquea
trabajos activos, un journal sin contenido impide nuevas admisiones y el
arranque reanuda fallos parciales. Proyecto/baseline, trabajos terminales,
inteligencia, triage, admisiones y workspaces desaparecen; la subida fuente,
caché pública, actividad mínima y copias externas mantienen su ciclo de vida
propio. Pasaron 1.069 pruebas backend, 420 runner/guardas y 298 frontend, además
de build, Compose, `compileall` y diff; una revisión local sintética comprobó
desktop/móvil y el éxito de borrado. Siguen pendientes scheduler, purga total de
fuente/copias, restore, reversión y backup externo; por ello todavía no existe
candidatura.

`PROD-040` aporta ya el contrato operativo de copia/restauración offline
`2026-09-06.1`: preflight de quiescencia, allowlist del árbol durable, manifiesto
versionado, conjunto exacto de SHA-256, verificación semántica y owner/org,
staging privado, publicación a directorio nuevo, migración auth 1→2 y revocación
de sesiones/intentos/invitaciones. Pasaron 17 pruebas dirigidas, 1.087 backend y
420 runner/guardas con fixtures sintéticos. El bundle contiene fuentes y hashes
de credenciales, no está cifrado por la aplicación y sus checksums no son una
firma; falta ejecutar `PROD-064` en volumen cifrado, medirlo y ensayar el cambio
de montaje/rollback. Por ello esto todavía no es una candidatura desplegable.

`PROD-054` añade una alternativa sin salida para avisos públicos. Un operador
puede importar un bundle JSON local, acotado y vinculado a un SHA-256 exacto;
Inspectra valida el contrato completo y activa atómicamente un snapshot cuya
identidad y frescura se muestran en el flujo de proyecto. La operación y su
rollback están descritos en `docs/offline-advisory-snapshots.md`. Esta vía no
autoriza ni simula una consulta real a OSV, GHSA, NVD o CISA KEV, y el checksum
no es una firma de procedencia.

`PROD-060` separa liveness y readiness. La última regresión pasó
1.030/1.030 backend (15,42 s) y 420/420 runner/guardas (6,08 s), además de
`compileall`, Compose base/privado y diff, sin omisiones. Un smoke local aislado
confirmó `ready`, degradación `503` al detener un runner mientras `/health`
seguía disponible y recuperación posterior; los recursos temporales se
eliminaron y los logs no contenían los marcadores sensibles buscados. Un primer
intento con una única red Docker interna no ofrecía una ruta desde el host al
puerto publicado y se descartó como evidencia; el segundo usó una red interna
para runners y otra de acceso local solo para el backend. No hubo Internet,
proveedor ni proyecto real. La nueva señal reduce el riesgo operativo, pero no
sustituye TLS, backup/restore, reversión ni la aceptación autorizada.

## Acta local de candidatura — 2026-09-06

Esta acta acredita una candidatura **local**, construida desde el árbol de
trabajo sin commit, tag, push ni publicación de imágenes. La identidad
reproducible observada es `HEAD`
`8e72f1e704f1fa05ff6cf72a70a697fda01b7d83` más SHA-256 agregado
`007cfa6782293603e75c8bbf646aab628ef7c60c6c626de89a14ce32d6c43d58`
de 649 archivos versionados/no ignorados, ordenados por nombre e incluyendo
nombre y digest individual. La huella excluye `data/` y esta propia acta para
evitar datos runtime y autorreferencia. En otro host deben reconstruirse las
imágenes desde ese mismo conjunto o promoverse posteriormente por un mecanismo
inmutable autorizado.

Entorno observado: Docker Engine 29.7.2 y Docker Compose 5.5.0. Las imágenes
locales finales fueron:

| Servicio | ID local de imagen | Tamaño observado |
| --- | --- | --- |
| `backend` | `sha256:0809cc012b780b4b23d184f22bbfd148980afa923567193e712b201caf528322` | 177.505.063 bytes |
| `audit-tools` | `sha256:a7f3b2f831650e357f9335b4895909000200083109f325266670f31f0eb19841` | 299.055.157 bytes |
| `network-tools` | `sha256:e1c6f17c379e2b896b7a4ec7a1bbc5df0d69b54a495f5045635685395785b5a5` | 299.055.157 bytes |
| `frontend` | `sha256:5fb5e6649501faab0d09161308c43e688bbe0274b290aca50e33e9aa2680ed34` | 165.554.482 bytes |
| `proxy` | manifiesto declarado `caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648`; ID local `sha256:af555904a0961945f16bb323a501457b13a4f7e9bde969b145b97da80b38ecbe` | 62.858.332 bytes |

Validación ejecutada sobre el árbol final:

- backend: 1.096/1.096 pruebas en 37,57 s, RSS máximo 88.716 KiB;
- runner y guardas: 423/423 pruebas en 6,05 s, RSS máximo 70.328 KiB;
- frontend: 44 archivos y 306/306 pruebas en 22,23 s, RSS máximo
  581.596 KiB; build TypeScript/Vite en 7,77 s y bundle inicial
  317,4/322 KiB;
- `compileall` en 0,20 s; configuración Compose base, privada y de aceptación
  válida y sin avisos; `git diff --check` correcto;
- cinco lockfiles Python sin vulnerabilidades conocidas mediante
  `pip-audit 2.10.1`; `npm audit --package-lock-only --audit-level=high` sin
  vulnerabilidades; Gitleaks sin fugas en 351 commits ni en los 187,68 MB del
  árbol actual;
- no hubo pruebas omitidas. La primera pasada backend terminó, no se bloqueó:
  detectó una referencia `archive` inexistente en un fixture. Se corrigió a
  `first_archive`, pasó el caso dirigido y después la suite completa.

Una repetición adicional intentada después de eliminar el entorno temporal no
llegó a recoger casos: `/usr/bin/python3.12 -m venv` falló dentro de
`ensurepip`, por lo que no existían `pip` ni `pytest`. Ese intento ejecutó cero
pruebas, no se atribuye al sandbox y no se cuenta como validación. La pasada
completa anterior sí usó Python 3.12 con los locks instalados. Tras los cambios
exclusivamente documentales se volvieron a comprobar con herramientas estándar
los 124 estados/prioridades en ambos backlogs, las dos configuraciones Compose
y `git diff --check`, todos sin divergencias ni errores.

El smoke TLS usó exclusivamente
`tests/fixtures/demo/passive-alpha/archives/demo-archive-app-config.zip`, una
CA local confiada solo por el cliente del smoke y egress de advisories
deshabilitado. En 1.117,271 ms verificó frontend, `/health`, `/ready`, cabeceras,
frontera anónima, login genérico, cookie `Secure`/`HttpOnly`/`SameSite=Strict`,
CSRF, proyecto/análisis completado, 14 clases de retención, informe redactado y
borrado de proyecto y fuente. El resumen declaró
`external_provider_contacted: false`.

La recreación controlada detuvo la pila en 1.410,684 ms y recuperó readiness en
12.953,615 ms usando los mismos IDs de imagen y el mismo montaje. La sesión,
un proyecto sintético, su fuente y un resultado terminal sobrevivieron; las
proyecciones de proyecto/trabajo no expusieron IDs de fuente y **Files** mantuvo
solo su referencia operativa autorizada. Después se eliminaron proyecto y
fuente y quedaron cero cargas y cero workspaces. Al detener únicamente
`audit-tools`, `/health` siguió en 200 y `/ready` pasó a 503 con
`analysis_runners=unavailable`, sin host, ruta, ID ni excepción; tras
reiniciarlo, readiness volvió en 1.328,546 ms.

Los límites efectivos observados fueron 1 CPU/512 MiB/256 PID para backend,
1 CPU/512 MiB/128 PID para `audit-tools`, 0,5 CPU/256 MiB/64 PID para
`network-tools`, 0,5 CPU/128 MiB/64 PID para frontend y
0,5 CPU/128 MiB/64 PID para el proxy. Runners y frontend no montan datos; el
runner de archivos no tiene egress, el de red no monta datos y solo el proxy
publica `127.0.0.1:18080/18443`. Tras el cleanup, el directorio `0700` de UID
1000 contenía únicamente SQLite, locks vacíos y 26 eventos de actividad mínima:
59.907 bytes, sin cargas ni workspaces. El análisis de logs no encontró los
marcadores exactos de credencial, archivo, digest o ruta temporal; la única
aparición genérica de «password» fue el mensaje de Caddy sobre instalar su CA
local, no un valor de aplicación.

Tras conservar la evidencia, la pila candidata se detuvo y eliminó en 1,47 s,
incluidos sus cinco contenedores de aplicación/proxy, dos volúmenes de Caddy,
cuatro redes aisladas, directorio de datos, CA y archivo de entorno temporales.
No quedó ningún recurso con el prefijo de proyecto `inspectra-rc-prod116`; los
nueve contenedores ajenos que ya estaban activos no se modificaron. Las imágenes
locales identificadas arriba se conservaron para poder reconstruir la prueba.

El ensayo de recuperación de `PROD-064` valida backup, corrupción, restore,
revocación, límites de propietario y limpieza con datos sintéticos; la
recreación anterior valida el montaje y el arranque de esta candidatura. No se
afirma rollback de una versión anterior: no existe todavía un artefacto previo
inmutable autorizado, y crear/publicar uno vulneraría el límite de no hacer
push ni despliegue. Antes de promover esta candidatura, el operador debe
conservar por digest la versión anterior y ejecutar el procedimiento de
reversión de este documento sobre almacenamiento cifrado.

La revisión visual se hizo con el mismo código y datos sintéticos a 1440, 768 y
320 px mediante frontend/backend HTTP local. El navegador integrado rechazó
correctamente la CA local de la candidatura y no se alteró el trust store para
forzarlo; por eso esa evidencia visual se mantiene separada del smoke TLS. No
hubo desbordamiento de documento ni errores de consola, el foco fue visible y
los filtros CVE/CVSS y enlaces oficiales funcionaron. OSV, GHSA y CISA KEV
siguen en estado **adaptador validado solo con fixtures**: esta acta no los
presenta como integraciones reales.

Decisión local: la pila es una candidatura verificable para iniciar la prueba
con un proyecto autorizado. El despliegue real permanece **no-go** hasta
completar los campos de autorización, almacenamiento cifrado, perímetro/DNS/TLS
válido, backup previo y digest de la versión anterior. Cualquier activación de
OSV/GHSA/KEV debe registrarse por fuente y no cambia de estado por existir este
smoke.

## Acta de aceptación real `PROD-117` — 2026-09-06

### Fuente autorizada y preflight

La búsqueda no destructiva encontró una sola copia de la fuente autorizada A. Se
eligió `[ruta local autorizada A redactada]` porque es la raíz Git más interna y
coincide exactamente con ese directorio; no se tomó como proyecto el repositorio
Git padre de `[directorio local redactado]`. Antes y después de la aceptación el worktree tuvo
cero cambios y el commit fue
`[commit autorizado A redactado]`.

`git ls-tree` enumeró 65 entradas rastreadas. Dos entradas `.env*` rastreadas se
excluyeron expresamente. La instantánea final tuvo 63 archivos regulares, cero
symlinks y ninguna entrada `.env` o `.git`; no incorporó ignorados, no
rastreados, dependencias instaladas ni artefactos del worktree. Dos archivos TAR
generados independientemente desde `HEAD`, con orden, propietario y marcas de
tiempo normalizados, midieron 450.560 bytes y produjeron el mismo SHA-256:
`[SHA-256 de snapshot A redactado]`.

El preflight efectivo de secretos encontró 20 coincidencias, revisadas sin
copiar sus valores al acta: 18 pertenecían a datos repetidos de pruebas y dos a
ejemplos documentales de cabeceras de autorización. No encontró una credencial
operativa confirmada, URL con credenciales, clave privada, clave Cloud ni token
GitHub. Una dirección de contacto en contenido documental se mantuvo local. El
preflight descubrió que la configuración anterior de Gitleaks no cargaba sus
reglas por defecto; `SEC-020` activó las reglas, añadió un canario bloqueante y
allowlists por huella revisada antes de volver a crear la instantánea. No se
ejecutó código, script, instalador ni gestor de paquetes de `fuente autorizada A`.

### Candidatura y flujo ejercitado

La segunda pasada completa, posterior a la corrección responsive, usó estas
imágenes locales y luego las eliminó:

| Servicio | ID local ejercitado |
| --- | --- |
| `backend` | `sha256:f040d70c7fca4817bcc8137aa568e577e6f41bdae683fc63c288efa1fda28791` |
| `audit-tools` | `sha256:62b89221a38fe93faed56faf7fa5d15401468b56301c58559b5bd8c41c5b6e28` |
| `network-tools` | `sha256:4147569d761e8a4d3e754c3116516a1cc35844de5df44ffd9da3ab22b8c6a8f4` |
| `frontend` | `sha256:e06eeebbc98d97fb24f79c19d8129b3a3517c42103bd620b85a095ebc764b500` |
| `proxy` | `sha256:af555904a0961945f16bb323a501457b13a4f7e9bde969b145b97da80b38ecbe` |

Se verificaron TLS con CA local, health/readiness, login de administrador único,
cookie segura, CSRF, denegación anónima `401` y proyecto inexistente `404`. La
fuente se cargó con un nombre operativo genérico y la vista de proyecto utilizó
solo una referencia `snapshot-…`. Dos análisis `project_archive_basic`
terminaron con contrato `2026-09-06.3`, worker `2026-09-06.1` y causa
`completed`; ambos produjeron 4 indicadores informativos locales. El inventario
detectó un manifiesto `requirements.txt`, 3 dependencias directas PyPI
declaradas como rangos, cero lockfiles y cero versiones exactas o componentes
consultables. No se interpretó esta cobertura como ausencia de vulnerabilidades.

La comparación reproducible produjo 0 hallazgos nuevos, 0 resueltos y 4
persistentes. La comparación pública quedó `not_comparable`, con la limitación
explícita de que ambos snapshots OSV no eran resultados frescos completos. Los
informes Markdown, HTML y PDF midieron respectivamente 6.968, 12.294 y 9.156
bytes e incluyeron alcance y límites; no incluyeron el nombre del repositorio,
ruta original, nombre de archivo operativo, hash privado ni ruta temporal.

La pila se eliminó y recreó con el mismo montaje. Persistieron sesión, proyecto,
dos análisis completados y el estado de inteligencia `disabled`. Al detener
`audit-tools`, `/ready` respondió `503/not_ready`, una ejecución terminó
`failed/runner_unavailable` con mensaje público genérico y, tras recuperar el
runner, readiness volvió a `200/ready`; un reintento explícito enlazó el ID
fallido mediante `retry_of_job_id` y terminó `completed`. Todos los estados
terminales dejaron cero entradas de workspace.

### Inteligencia pública y resultado de seguridad

El backend conservó `INSPECTRA_PUBLIC_ADVISORY_EGRESS_ENABLED=false`, solo las
redes internas/de acceso local y ningún puerto publicado. El overlay autorizado
de egress nunca se aplicó, porque el inventario tenía 0 identidades exactas:

- **OSV:** no consultado. El adaptador sigue implementado y validado únicamente
  con fixtures; esta ejecución registró `disabled`, 3 componentes excluidos y
  0 consultas.
- **GitHub Security Advisories:** no consultado, conforme a la prohibición
  expresa; no se usó token de GitHub.
- **CISA KEV:** no descargado. Sin un CVE correlacionado previamente por OSV no
  existía un hallazgo válido que enriquecer; KEV no se usó para inferir
  vulnerabilidad.
- **Vulnerabilidades encontradas:** ninguna vulnerabilidad pública pudo
  determinarse. Esto significa **no evaluado por falta de versión exacta**, no
  «cero vulnerabilidades». Solo se observaron los 4 indicadores informativos de
  higiene/cobertura locales.

No salió de la máquina nombre de proyecto, ruta, código, archivo, hash, usuario,
dominio, secreto ni identidad de componente. Los logs finales (7.442 bytes) y
los tres informes tuvieron cero coincidencias para los marcadores privados
buscados y cero patrones de cabecera/token/credencial. No se conservó respuesta
externa porque no hubo proveedor contactado.

### Validación, incidencias y revisión visual

- Python 3.12: 1.520/1.520 pruebas en 35,08 s, sin casos omitidos; `compileall`
  pasó con cache fuera del repositorio.
- Frontend: 44 archivos y 306/306 pruebas en 24,76 s; build TypeScript/Vite y
  presupuesto inicial 317,4/322 KiB correctos.
- Cinco `pip-audit` y `npm audit --package-lock-only --audit-level=high`: sin
  vulnerabilidades conocidas en los locks de Inspectra.
- Compose base, privado, aceptación sin egress y forma autorizada con overlay:
  válidos. El overlay conecta únicamente backend a su red externa dedicada.
- Gitleaks: canario detectó la fuga sintética esperada y el historial completo
  de 351 commits/7,84 MB no tuvo fugas no exceptuadas; `git diff --check` pasó.

Se registraron, sin ocultarlos, intentos que ejecutaron cero pruebas: la suite
frontend local no pudo escribir `.vite-temp` por permisos residuales y se
repitió completa en una imagen limpia; dos intentos Python fallaron antes de
pytest por `tmpfs` no ejecutable y ausencia de `/usr/bin/time`, tras lo que el
comando corregido ejecutó las 1.520 pruebas; `pip-audit` necesitó mover su caché
desde una raíz de solo lectura a `/tmp` y después completó las cinco auditorías.
Ninguno de esos intentos se contó como aprobado.

La revisión de navegador encontró un desbordamiento global real de 349 px en un
viewport de 320 px, causado por IDs técnicos largos en tarjetas de hallazgo.
`PROD-126` lo corrigió sin usar `overflow-x:hidden`. Tras reconstruir la imagen,
el documento midió 305/305 px a 320, 753/753 a 768 y 1.425/1.425 a 1.440; las
tablas conservaron scroll local, el foco mostró contorno sólido de 3 px y la
consola quedó sin errores/avisos. Se recorrieron onboarding, proyecto,
historial/error, inventario, inteligencia deshabilitada, resultados,
comparación e informes.

### Limpieza y veredicto

La vista previa y cascada final eliminaron 1 proyecto, 4 análisis, 4 snapshots
de inteligencia y 4 workspaces; la fuente se eliminó por separado. La API
confirmó 0 proyectos, 0 archivos y 0 workspaces. Después se eliminaron los dos
stacks Compose, sus dos volúmenes Caddy, redes, nueve imágenes temporales, datos,
CA, cookies, credenciales, informes temporales, copia visual y ambas
instantáneas. La comprobación posterior dio 0 contenedores, 0 volúmenes, 0
redes, 0 imágenes y 0 raíces temporales con los prefijos de aceptación. El
repositorio original conservó el mismo `HEAD` y cero cambios. La eliminación es
lógica y verificable; no se promete borrado físico forense sobre capas
copy-on-write o almacenamiento SSD.

**Veredicto: NO-GO.** La candidatura demuestra el flujo local, el aislamiento y
la degradación segura, pero no satisface la aceptación obligatoria de OSV real.
Para repetir `PROD-117` sin ejecutar el proyecto se necesita autorización para
otro commit rastreado del mismo proyecto que incluya un lockfile npm/PyPI
soportado con versiones exactas, o para un SBOM/artefacto de resolución exacta,
inmutable y previamente revisado. Hasta entonces la tarea queda bloqueada y
ningún proveedor debe activarse.

## Segunda aceptación real `PROD-117`: fuente autorizada B — 2026-09-06

### Fuente inmutable y preflight

La fuente autorizada fue exclusivamente el objeto Git
`[commit autorizado B redactado]` de
`[ruta local autorizada B redactada]`. Git confirmó el objeto `commit`, el árbol
`[árbol Git autorizado redactado]` y el blob
`[blob Git autorizado redactado]` para
`apps/web/package-lock.json`; el JSON retenido en el commit declaró
`lockfileVersion: 3`. No se usó el checkout, `git stash`, dependencias
instaladas, ignorados, no rastreados ni `.git`, y no se ejecutó código, script,
instalador o gestor de paquetes del proyecto.

El archivo se creó desde `git archive` del commit y después se aplicó la misma
lista local de exclusión revisada en dos construcciones independientes. Se
excluyeron 83 artefactos o datos no necesarios y dos `.env.example`; el
resultado tuvo 1.417 archivos regulares, cero symlinks y cero nombres `.env*` o
`.git`. Dos TAR canónicos de 12.871.680 bytes fueron idénticos:

```text
SHA-256 [SHA-256 de snapshot B redactado]
```

Gitleaks, con sus reglas completas y sin red, terminó con código 0 y cero
hallazgos; el canario independiente produjo exactamente el hallazgo sintético
esperado. La comprobación adicional de datos personales solo encontró dos
dominios reservados para ejemplos y cero dominios inesperados. Una heurística
textual de palabras parecidas a credenciales produjo falsos positivos y no se
usó como sustituto de Gitleaks ni se declaró aprobada. No se expuso ninguno de
sus valores en esta acta.

El worktree de la fuente autorizada B sí recibió actividad concurrente ajena a esta
aceptación. Antes de la tercera pasada registraba `HEAD`
`[HEAD previo redactado]`, 9 entradas de estado, digest de
estado `[digest de estado previo redactado]`
y digest de diff rastreado
`[digest de diff previo redactado]`.
Durante la prueba pasó a `HEAD`
`[HEAD posterior redactado]`, 9 entradas, digest
`[digest de estado posterior redactado]`
y diff
`[digest de diff posterior redactado]`;
el índice permaneció vacío (`e3b0c442…`). Inspectra no escribió ni leyó esos
cambios: todos los bytes analizados procedían del commit autorizado. El
checkpoint inmediatamente anterior a la limpieza y el posterior fueron
idénticos. Esta acta no atribuye la deriva al sandbox ni afirma inmutabilidad de
un checkout modificado por otro proceso; sí acredita la identidad exacta de la
fuente analizada y que la aceptación no tocó el repositorio.

Una verificación documental posterior, todavía sin leer ni mostrar el contenido
de los cambios, observó nueva actividad concurrente: `HEAD` seguía en
`[HEAD posterior redactado]`, pero el estado pasó a 17 entradas
con digest
`[digest de estado intermedio redactado]` y el
diff rastreado a
`[digest de diff intermedio redactado]`; el
índice continuó vacío. Esto ocurrió después del par de checkpoints idénticos de
la aceptación. No se intentó revertir, guardar ni interpretar esa actividad
ajena.

En el corte final, dos checkpoints consecutivos volvieron a coincidir entre sí:
`HEAD` `[HEAD posterior redactado]`, 21 entradas, digest de
estado `[digest de estado final redactado]`,
digest de diff rastreado
`[digest de diff final redactado]` e
índice vacío. La evolución de 9 a 17 y después 21 entradas acredita que el
checkout estaba siendo modificado en paralelo, no que Inspectra lo usara: la
fuente y todos sus controles siguieron referidos al commit/tree/blob anteriores.

### Candidatura y recorrido completo

La pasada final utilizó estas imágenes locales, construidas desde el árbol de
Inspectra y eliminadas al terminar:

| Servicio | ID local ejercitado |
| --- | --- |
| `backend` | `sha256:2bae608d96d4d56a186f1e7236ca5cf14dbc29c1023d8cfecf394fa0675c063b` |
| `audit-tools` | `sha256:1a8fac78a7227749896c95ad01a61f8b6523a6c6429fff0cba2e411b654d7d47` |
| `network-tools` | `sha256:242afa467cef96d7df524c89f4cf745af2df321f6d519816831023c99d1b397f` |
| `frontend` | `sha256:bfc3b5263e74fabeb59ab0457c08d7419321cd6efd03e91e3ba035c523f5ffe5` |

El primer arranque del arnés detectó interpolación de `$` en el hash de la
contraseña antes de usar la candidatura. Se eliminó esa pila y sus volúmenes y
se regeneró el entorno escapando los caracteres para Compose. Fue un fallo del
arnés, no una relajación de autenticación. La candidatura definitiva verificó
TLS con CA efímera, health/readiness, login, cookie segura y CSRF; el acceso
anónimo a proyectos respondió 401 y un proyecto ajeno/inexistente respondió
404.

Se importó el TAR bajo un nombre operativo genérico. Tres análisis
`project_archive_basic` terminaron `completed` con contrato
`2026-09-06.3`, worker aislado `2026-09-06.1`, los mismos 28 indicadores
locales y el mismo digest de fuente. El inventario fue reproducible: 590
componentes, 581 resoluciones exactas de `package-lock.json` v3, 9 declaraciones
sin versión exacta, 3/3 manifiestos y 1/1 lockfile procesados, sin truncado. De
las resoluciones exactas, 369 identidades npm no scopeadas tenían procedencia
pública admisible; 212 paquetes scopeados se retuvieron como
`private_namespace` y nunca se construyó una consulta para ellos. No hubo
workspace, Git/URL/local o identidad ambigua enviada.

Con el egress deshabilitado, el endpoint registró 369 componentes
`unavailable`, cero consultas y cero hallazgos, sin confundirlo con resultado
limpio. El overlay se activó explícitamente y solo añadió al backend a
`inspectra_public_advisory_egress`; frontend, proxy y ambos runners tuvieron
cero pertenencias a esa red.

### OSV real, KEV y ausencia de falsos negativos operativos

OSV oficial respondió en 12.652 ms a 15 lotes y dejó el snapshot `ready`:
369/369 identidades consultadas, 12 componentes afectados, 357 no afectados,
0 indisponibles y 33 hallazgos componente/advisory. Fueron 28 IDs de advisory
únicos, 25 CVE únicos y 33 casos con versión corregida publicada. La
distribución conservada fue 1 crítico, 12 altos, 6 medios, 1 bajo y 13 con
CVSS aún desconocido; 20 conservaron puntuación. Los nombres de componentes y
la lista completa de identificadores no se reproducen en esta acta para no
convertir el informe de aceptación en un inventario del proyecto.

La API oficial devolvió referencias resumidas. La corrección `PROD-127`
permitió `vulns` omitido como vacío e hidrató cada ID desde la ruta fija del
mismo host. La reconciliación posterior comprobó 28 IDs en `querybatch`, 28
documentos de detalle y 28 IDs normalizados: cero perdidos, cero añadidos y cero
detalles ausentes. Una segunda ejecución produjo 0 nuevos, 0 resueltos y 33
persistentes y reutilizó 15 lotes frescos con cero conexiones salientes.

CISA KEV oficial respondió en 232 ms después de la correlación OSV. Evaluó 30
hallazgos con CVE exacto como `not_listed`, dejó 3 sin CVE como `not_evaluated`
y no marcó explotación conocida. KEV no creó hallazgos ni decidió que una
versión fuera vulnerable. GitHub Security Advisories no se consultó y no se
usó token de GitHub; continúa como adaptador validado solo con fixtures.

La captura pasiva de metadatos mostró únicamente TLS hacia `api.osv.dev`
(43 SYN al destino resuelto) y `www.cisa.gov` (1 SYN), sin DNS/SNI inesperado.
Los logs, cachés de proveedor e informes tuvieron cero coincidencias con nombre
de repositorio, ruta local, commit autorizado, SHA-256 de la instantánea o
contraseña de aceptación. El cliente real no conservó payload de consulta: las
respuestas se almacenaron bajo claves unidireccionales y los snapshots
normalizados no incluyeron ruta, código, proyecto o propietario.

Para comprobar la caída, se retiraron reversiblemente 43 entradas de caché OSV
y una de KEV y se desconectó la única red pública del backend. La nueva consulta
quedó `degraded`: 15 lotes fallidos, 369 componentes `unavailable`, 0
`not_affected` y 0 hallazgos. Tras recrear el backend con el overlay autorizado,
OSV volvió a `ready` con los mismos 33 hallazgos y KEV volvió a evaluar 30+3.
Así, una indisponibilidad no produjo un falso negativo ni una falsa resolución.

### Resultados, persistencia y experiencia

La segunda ejecución reprodujo 0/0/28 hallazgos locales y 0/0/33 públicos. Se
registró una decisión append-only `in_review`; después del reinicio completo
persistieron 1 proyecto, 2 análisis en ese momento, 33 hallazgos y el reparto
de triage 27 abiertos/1 en revisión. Los informes Markdown, HTML y PDF midieron
80.278, 117.631 y 97.977 bytes, incluyeron alcance, OSV, CVSS, fixes, KEV y
triage, y tuvieron cero marcadores privados. El PDF comenzó con una firma PDF
válida. El tercer análisis añadió la prueba de degradación/recuperación.

La revisión visual usó una copia efímera sin egress a 1440×1000, 768×900 y
320×780. El documento midió exactamente 1425/1425, 753/753 y 305/305 px; las
tablas conservaron scroll local. Se probaron inventario/no correlacionables,
política de egress, snapshot actual/degradado, filtro Critical (1/33), búsqueda
vacía (0/33 con recuperación), detalle CVSS/rangos/fixes/fuentes/KEV, triage,
comparación e informes. Un defecto móvil del layout de informe y el vocabulario
engañoso «advisories» frente a ocurrencias se corrigieron en `PROD-128` y se
repitió la matriz. La superficie disponible no expuso consola en esta pasada;
no se presenta una afirmación de consola limpia.

### Pruebas, limpieza y veredicto

- Backend Python 3.12: 1.523/1.523 pruebas, 0 fallos, errores u omitidas,
  31,095 s según JUnit. Una primera orden de repetición ejecutó cero casos
  porque comprobó como ejecutable en el host un symlink absoluto válido solo
  dentro del contenedor; se corrigió la precondición y no se contó como pasada.
- Frontend: 89/89 archivos y 307/307 pruebas; build TypeScript/Vite correcto y
  bundle inicial 317,4/322 KiB.
- Cuatro composiciones (base, privada, aceptación aislada y overlay autorizado),
  `compileall` y `git diff --check`: correctos.
- Gitleaks: historial 0; subconjunto de 221 archivos de producción 0; canario
  detectado. El escaneo bruto del árbol enumeró 102 señales, todas clasificadas
  en pruebas/fixtures/documentos sintéticos (55) o bytecode/caché generada (47),
  sin hallazgo de producción pendiente.

Tras sincronizar la documentación se repitieron 15/15 regresiones de estilos en
un contenedor Node 22 sin red, con el repositorio de solo lectura y la caché de
Vite en `tmpfs`; también pasaron directamente las 22/22 aserciones estáticas de
workflow/Compose bajo Python 3.12, más diff y espacios finales. Tres intentos
preliminares no ejecutaron casos y no se contabilizan como pruebas: el venv
local conservado era Python 3.10 sin `pytest`, Node directo no inicia un test de
Vitest y el caché host `.vite-temp` era de solo lectura para el usuario. No se
atribuyeron al sandbox ni a un fallo del producto, no se cambiaron permisos y la
repetición aislada anterior fue la evidencia válida.

La vista previa de borrado enumeró la cascada antes de confirmarla. La API
eliminó 1 proyecto, 3 análisis, 3 árboles de snapshots normalizados, 1 decisión
de triage y 3 workspaces; la fuente se eliminó aparte. Confirmó 0 proyectos, 0
archivos, 0 cargas, 0 trabajos y 0 workspaces. Después se retiraron las pilas,
dos volúmenes Caddy, redes, 17 tags de imagen, cachés, CA, cookies, informes,
credencial, copia visual y tres raíces temporales. Un primer borrado no pudo
retirar el venv propiedad de `root`; se eliminó exclusivamente ese directorio
desde un contenedor sin red y la comprobación final dio 0 contenedores, 0
volúmenes, 0 redes, 0 tags y 0 rutas temporales con el prefijo de aceptación.
No se alteró la fuente autorizada B. No se promete borrado físico forense en almacenamiento
copy-on-write/SSD.

La auditoría de cierre detectó después un ayudante de captura ya detenido
(`[contenedor temporal de captura redactado]`, salida 0) que no aparecía en la
comprobación anterior. Se identificó por nombre/estado, se eliminó de forma
explícita y se repitió el inventario: 0 contenedores, volúmenes, redes, imágenes
o rutas temporales asociados a la fuente autorizada B o a su aceptación.

**Veredicto: GO para desplegar esta candidatura de Inspectra en un entorno
controlado y repetir una aceptación autorizada.** OSV y CISA KEV quedan
validados realmente solo dentro del alcance anterior; GHSA real sigue
prohibido/no validado. Este GO no declara una versión estable ni autoriza
publicación, push, PR o despliegue externo. El siguiente corte requiere revisar
y consolidar el árbol Git de Inspectra, elegir una versión posterior coherente,
actualizar la documentación canónica, obtener CI remoto verde y resolver
`SEC-012` con autorización explícita.

Actualización del corte `0.3.0-beta.1` (2026-09-10): la consolidación local,
reescritura mínima del historial inédito, publicación de rama y PR borrador
fueron autorizadas posteriormente. `SEC-012` y `PROD-130` quedaron completadas
tras la ejecución CI verde
[34520803043](https://github.com/dreykdrk7/inspectra/actions/runs/34520803043)
sobre `ef046a1fe2d8468aed6bfa83315ab7ae687bf922`. El veredicto sigue limitado a
una candidatura técnicamente validada: no hubo merge, tag, release, publicación
de paquetes ni despliegue.

## Configuración segura mínima

- Host Linux dedicado o aislado, Docker Engine y Compose compatibles con
  `read_only`, `tmpfs`, `cpus`, `mem_limit`, `pids_limit` y `!reset`.
- Solo los puertos 80/443 del proxy accesibles; backend, frontend y runner sin
  publicación directa. Restringir el acceso además con firewall, VPN o red
  privada.
- Directorio `data/` persistente, propiedad de UID 1000, modo `0700` y sin
  permisos de grupo/otros. Copia de seguridad cifrada antes de la prueba.
- Archivo de entorno privado fuera del repositorio y con modo `0600`. Debe
  contener `INSPECTRA_PUBLIC_HOST`, `INSPECTRA_TLS_EMAIL` y un
  `INSPECTRA_ADMIN_PASSWORD_HASH` compatible. No debe contener código, tokens
  de repositorio ni secretos del proyecto. El hash debe escribirse completo
  entre comillas simples, por ejemplo
  `INSPECTRA_ADMIN_PASSWORD_HASH='pbkdf2_sha256$<iteraciones>$<salt>$<digest>'`:
  Compose interpola los `$` de un valor sin comillas y alteraría la credencial.
  El preflight debe renderizar la configuración sin mostrar el valor y fallar
  ante cualquier aviso de interpolación.
- Perfil `private_tls_proxy`, autenticación `self_hosted_single_admin`, estado
  de sesión SQLite dentro de `/app/data`, cookie
  `Secure`/`HttpOnly`/`SameSite=Strict`, CORS HTTPS exacto y retenciones de
  archivos/trabajos mayores que cero. El override privado fija estos controles
  y el backend debe rechazar cualquier deriva.
- Mantener todas las capacidades Active deshabilitadas. La composición ordinaria
  de aceptación conserva el egress público deshabilitado y todas sus redes
  internas durante importación, análisis y preflight. Solo después de una
  autorización por fuente se puede añadir
  `docker-compose.acceptance-egress.yml`, fijando
  `INSPECTRA_ACCEPTANCE_PUBLIC_ADVISORY_EGRESS_ENABLED=true`; ese overlay conecta
  únicamente el backend a `inspectra_public_advisory_egress`. No concede salida
  a frontend, proxy, `audit-tools` ni `network-tools`. Las rutas HTTPS y hosts
  siguen siendo constantes del cliente de aplicación y este no acepta proxy de
  entorno. Cuando exista un firewall de egress del host, su allowlist debe
  contener exclusivamente los hosts autorizados para esa ejecución; no incluya
  GitHub si GHSA no fue autorizado.
- Mantener `INSPECTRA_ACCEPTANCE_NVD_ENABLED=false` salvo autorización expresa
  para NVD. Habilitarlo solo permite `services.nvd.nist.gov` y consultas por un
  CVE exacto ya correlacionado; no autoriza búsqueda por CPE, paquete o proyecto.
- Retirar egress exige volver a fijar la variable a `false`, recrear la pila sin
  `docker-compose.acceptance-egress.yml` y comprobar en la configuración
  renderizada que el backend ya no pertenece a la red externa dedicada.
- Dejar `INSPECTRA_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES` con exclusiones de
  nombres/prefijos internos. `INSPECTRA_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES`
  debe quedar vacío salvo atestación expresa de cada paquete PyPI público.
  `INSPECTRA_PUBLIC_ADVISORY_PUBLIC_GO_MODULES` debe quedar igualmente vacío
  salvo atestación exacta y autorizada de módulos Go ya coincidentes entre
  `go.mod` y `go.sum`; nunca debe contener esquema, credencial, comodín o ruta
  local.
- Para Cargo, no existe una allowlist positiva configurable: solo una entrada
  exacta de `Cargo.lock` v3/v4 con la fuente literal oficial fija de crates.io
  es elegible. Añadir nombres internos a
  `INSPECTRA_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES` con prefijo `cargo:`. Antes
  de habilitar egress, verificar en el inventario que Git, path, workspace,
  alias y registries alternativos figuran como no correlacionables y que no se
  conserva `source`, checksum ni locator.
- Mantener `INSPECTRA_PUBLIC_ADVISORY_PUBLIC_COMPOSER_PACKAGES` vacío salvo
  atestación expresa de cada nombre público `vendor/package`. `composer.lock`
  no prueba Packagist: revisar que el mismo root no declare `repositories` y
  que inventario/PVI muestran como locales todas las identidades no atestadas.
  Nunca copiar URLs, tokens, `source`, `dist`, hashes o referencias del proyecto
  a la configuración.
- Mantener `INSPECTRA_PUBLIC_ADVISORY_PUBLIC_MAVEN_PACKAGES` vacío salvo
  atestación expresa de cada coordenada pública lowercase `group:artifact`.
  `gradle.lockfile` no prueba Maven Central ni otro repositorio público:
  comprobar que el inventario conserva el alcance como no reportado y que no
  persiste configuraciones, URLs, credenciales ni contenido del DSL. No ejecutar
  Gradle o Maven durante la aceptación.
- Mantener `INSPECTRA_PUBLIC_ADVISORY_PUBLIC_NUGET_PACKAGES` vacío salvo
  atestación expresa de cada nombre público normalizado. `packages.lock.json`
  v1 no prueba NuGet.org: revisar que versiones divergentes entre targets,
  entradas `Project`, múltiples `*.csproj` en un root y versiones no soportadas
  permanecen locales. Nunca copiar feeds, TFM, rangos solicitados, hashes,
  rutas o credenciales a la configuración; no ejecutar `dotnet` ni restore.
- Fijar `INSPECTRA_PROJECT_MAX_SOURCE_SNAPSHOTS` según la retención y capacidad
  aprobadas (1–10000; 100 por defecto). El límite no purga historial, por lo que
  almacenamiento, backup y procedimiento de apertura de un nuevo proyecto
  deben dimensionarse antes de la aceptación.
- Fijar `INSPECTRA_PRODUCT_AUDIT_RETENTION_DAYS` y
  `INSPECTRA_PRODUCT_AUDIT_MAX_EVENTS` según la política aprobada (90 días y
  50.000 por defecto). Incluir el subárbol `results/product_audit` en backup,
  restore, expurgo y comprobación de privacidad.
- Consultar `GET /audit/integrity` como administrador antes y después de backup/
  restore. Debe devolver `valid` o `empty`, con cabeza de 64 hexadecimales y
  sin IDs de evento/actor/recurso. `invalid` es `NO-GO`: detener escrituras,
  preservar el volumen para investigación y restaurar una copia verificada en
  un directorio nuevo; no regenerar el ledger afectado. Un primer
  `bootstrap_performed=true` sobre eventos legacy solo atestigua cambios desde
  ese instante y debe quedar anotado en la aceptación.
- Abrir el panel **Data lifecycle** y contrastar sus valores con la política
  aprobada. Debe mostrar exactamente las 15 clases del contrato
  `2026-09-08.1`, incluida la clase de credenciales de automatización, además
  de inventarios embebidos, auth/identidad, journals y bundles externos.
  Confirmar que la cascada de proyecto elimina metadatos y
  decisiones pero conserva la subida fuente; verificar además que el servidor
  no persiste exportaciones y que caché pública, cifrado y backups tienen
  responsabilidades y retenciones independientes.
- Confirmar que el subcontrato de metadatos de fuente enumera exactamente
  nombre, digest, ID interno y referencia segura; solo la referencia
  `snapshot-…` puede aparecer en vistas de proyecto e informes. Verificar que
  nombre y SHA-256 siguen disponibles únicamente en **Files** para gestión
  explícita del propietario y no en historial, comparación ni Raw JSON de una
  ejecución de proyecto.

## Servicios y límites esperados

| Servicio | Necesario | Límite base verificable |
| --- | --- | --- |
| `proxy` | sí | único punto de entrada TLS; 0,5 CPU, 128 MiB, 64 PID; filesystem raíz solo lectura |
| `frontend` | sí | 0,5 CPU, 128 MiB, 64 PID, `/tmp` 32 MiB |
| `backend` | sí | 1 CPU, 512 MiB, 256 PID, `/tmp` 64 MiB |
| `audit-tools` | sí | 1 CPU, 512 MiB, 128 PID, tmpfs dedicado 64 MiB; sin volumen de datos ni egress; un subproceso efímero por fuente |
| `network-tools` | sí para auditorías web/DNS | 0,5 CPU, 256 MiB, 64 PID, `/tmp` 32 MiB; sin volumen de datos; único runner pasivo con egress |
| `active-tools` | no | fuera de esta aceptación |

Para proyecto se esperan, salvo decisión registrada: carga y workspace de 20
MiB, timeout de 60 s, 5.000 entradas, 200 MiB descomprimidos declarados, 25
manifiestos, 1 MiB por manifiesto, 5 MiB agregados, 5 lockfiles, 2.000 paquetes
y 4.000 aristas por lockfile. Cada fuente usa el contrato de worker
`2026-09-06.1`: máximo 20 MiB de entrada, 55 s de pared, 45 s de CPU por
proceso, 384 MiB de memoria, 32 MiB por archivo creado, 64 descriptores, 32
procesos y 4 MiB de resultado; solo puede existir una fuente en el runner a la
vez. Se mantiene concurrencia backend máxima de 4, hasta 128
trabajos persistidos en curso globales y 32 por propietario. El límite por
propietario nunca puede superar el global. El perfil persistido y el resultado
del runner deben coincidir; un `429` de admisión debe ser recuperable y no
revelar conteos ni actividad ajena.

## Preparación y comprobaciones previas

1. Revisar el árbol de trabajo y fijar la revisión candidata sin publicar ni
   hacer push durante este encargo. Registrar el commit solo cuando exista una
   decisión posterior autorizada.
2. Ejecutar Python 3.12, las suites backend y runner, las pruebas frontend,
   build y presupuesto, auditorías de dependencias, `docker compose config` de
   base y privado, y escaneo de secretos. Cualquier caso omitido o fallo es
   motivo de no-go.
3. Construir imágenes desde los lockfiles y bases ancladas. Registrar digests,
   tamaños y resultado de healthchecks; no usar etiquetas flotantes.
4. Validar que `data/` no tiene permisos de grupo/otros y que la ruta SQLite se
   resuelve dentro de ese directorio.
5. Con el backend detenido y todos los trabajos terminales, crear una copia con
   el contrato `2026-09-06.1` mediante `app.backup_cli create` en un volumen
   cifrado, ejecutar `verify` y restaurar a un directorio nuevo con
   `app.backup_cli restore`. Confirmar checksums/ownership y que sesiones,
   intentos e invitaciones quedan revocados. Antes, ejecutar
   `app.backup_cli drill` en un padre cifrado controlado: el ensayo sintético
   de `PROD-064` ya verificó 13 archivos/132.546 bytes, rechazo de corrupción,
   cero publicaciones parciales, dos owners aislados, revocación y limpieza en
   0,78 s de proceso (398,012 ms internos). Son datos de referencia, no un SLA.
   No restaurar encima de los datos activos ni confundir el ensayo sintético con
   el arranque/TLS/readiness de la instancia candidata.
6. Renderizar la configuración combinada con el archivo de entorno privado y
   comprobar que no aparecen puertos directos, credenciales ni variables
   Active habilitadas. La salida de error debe estar vacía: cualquier aviso de
   variable no definida indica probablemente un hash sin comillas y es no-go.

No hay migración manual de base de datos de producto en esta versión. El
restore admite auth schema `1`/`2`, migra `1` a `2` y rechaza versiones futuras;
team identity admite solo schema `1`. Los proyectos, jobs y snapshots continúan
en almacenamiento JSON local y se validan sin una migración transformadora.
Esta arquitectura es una limitación explícita para alta disponibilidad y uso
multiusuario.

## Arranque y salud

La ejecución futura usará ambos archivos Compose y el archivo de entorno
privado. Primero se validará la configuración; después se construirán e
iniciarán los servicios. Los criterios mínimos son:

- todos los servicios necesarios alcanzan estado healthy/started sin bucle de
  reinicio;
- `https://<host>/api/health` responde `200` como vida del proceso y
  `https://<host>/api/ready` responde `200` solo cuando almacenamiento, ambos
  runners fijos, admisión y recuperación/limpieza están preparados. Forzar
  runner caído, cola saturada, escritura fallida u orphan sintético debe dar
  `503` con estados agregados, nunca host, ruta, owner, conteo o error bruto;
- la portada carga por HTTPS, las cabeceras defensivas están presentes y no hay
  puertos directos de backend/frontend;
- el login incorrecto devuelve un error genérico y activa el límite tras los
  intentos configurados; el login correcto crea cookie Secure/HttpOnly/SameSite
  y las mutaciones sin CSRF se rechazan;
- logs de arranque y petición no contienen contraseña, cookie, CSRF, archivo de
  entorno, cuerpo, nombre/ruta del ZIP ni contenido del proyecto.

## Proyecto real autorizado

La fuente autorizada A fue autorizada expresamente por su propietario el 2026-09-06. Se usó
el commit y la instantánea reproducible identificados en el acta anterior, tras
excluir `.env*` y revisar localmente las 63 entradas admitidas. La autorización
permitía OSV solo para npm/PyPI exactos y CISA KEV únicamente por CVE ya
correlacionado; GHSA y credenciales GitHub quedaron prohibidos. El inventario no
aportó una versión exacta, por lo que ninguna consulta fue elegible. Los datos
se eliminaron al terminar y cualquier repetición exige una nueva fuente exacta
autorizada; la autorización original no permite fabricar un lockfile ni ejecutar
el gestor de paquetes del proyecto.

## Flujo de aceptación y resultados esperados

1. Crear el primer proyecto desde un ZIP autorizado. Debe aparecer un trabajo
   `queued` con propietario/proyecto correctos, perfil versionado y sin ruta del
   host.
2. Observar `running` y probar una cancelación. Debe pasar por `cancelling`,
   terminar `cancelled`, registrar `cancelled_by_owner`, matar el grupo de
   procesos y eliminar tanto el workspace backend como el tmpfs del worker.
   Reintentar debe crear otro ID con `retry_of_job_id` y conservar el anterior.
3. Completar una ejecución. Debe registrar inicio/fin, `completed`, contratos
   de límites y aislamiento coincidentes, ausencia del workspace temporal y
   directorio de worker vacío. Reiniciar antes de
   que un segundo trabajo salga de `queued` debe revalidarlo, conservar su ID y
   registrar contador/fecha de recuperación. Reiniciar cuando ya esté `running`
   debe producir `application_restart`, sin resultado parcial, y permitir un
   nuevo intento. Un apagado ordenado durante ejecución debe registrar
   `application_shutdown` después de esperar la cancelación y limpiar.
4. Revisar inventario: distinguir exactos, rangos, transitivos y no
   correlacionables. Un componente sin procedencia pública no puede salir ni
   aparecer como «sin vulnerabilidades».
5. Con egress aún deshabilitado, la UI debe mostrar `disabled` y no debe existir
   tráfico DNS/HTTPS de advisories. Después de aprobación, habilitarlo y
   comprobar que OSV recibe solo ecosistema, nombre normalizado y versión.
6. Registrar OSV como integración real validada solo si responde el host oficial.
   Registrar GHSA/CISA por separado si fueron consultados. Confirmar que KEV se
   muestra separado de CVSS y únicamente sobre CVE previo exacto.
7. Crear una segunda instantánea autorizada y comparar. Solo declarar
   nuevo/resuelto/persistente cuando perfil y cobertura sean comparables.
8. Registrar una decisión sobre un hallazgo, confirmar que otro rol solo puede
   leerla y crear una excepción con revisión futura. Debe sobrevivir a recarga,
   aparecer en comparación/informe y volver a requerir revisión al vencer sin
   modificar la evidencia ni incluir el comentario libre en logs o informes.
9. Exportar Markdown/HTML/PDF. Deben incluir alcance, límites, frescura,
   evidencia pública y recomendaciones, sin Raw JSON, ruta privada, nombre del
   ZIP, SHA-256 del contenido, secreto ni contenido fuente; deben atribuir la
   instantánea únicamente mediante la referencia segura.
10. Consultar `GET /privacy/retention`, ejecutar la purga debida sin cuerpo ni
   parámetros y verificar el resultado por clase. Una organización sintética
   distinta y una fuente ligada a un trabajo activo deben permanecer; un
   resultado vencido debe perder también snapshots e informes. Revisar por
   separado el backup, que no queda purgado por esta acción.
11. Sobre un proyecto sintético terminal, revisar el alcance de eliminación y
   comprobar que un trabajo activo la bloquea. Confirmar después que proyecto,
   trabajos, hallazgos, informes y triage dejan de estar disponibles, que la
   subida sigue en **Files** y que repetir la petición es seguro. En el ensayo
   previo a candidatura, simular además una interrupción y verificar que
   readiness falla cerrada hasta que el arranque termina el journal.
12. Revisar los recorridos a 320, 768 y 1440 px, con teclado y comprobación axe:
   onboarding, proyecto, ejecución, cancelación/error/vacío, inventario,
   inteligencia, detalle, comparación e informes.

## Privacidad y ausencia de fugas

Capturar y revisar, en un entorno controlado, DNS/HTTPS saliente, logs de los
cuatro servicios, respuestas API, caché de advisories, jobs, informes y nombres
de archivos. Buscar marcadores sintéticos colocados en una ruta, nombre de ZIP
y archivo no analizado. Ningún marcador puede aparecer fuera de la fuente
autorizada; el egress solo puede contener identidades públicas aprobadas. No se
guardan cuerpos brutos de proveedor en el snapshot normalizado y la telemetría
solo conserva proveedor/estado/intentos/tamaño.

## Go/no-go

Es no-go si falla una prueba, un límite no coincide, un workspace queda tras un
estado terminal, aparece un dato sensible, hay un puerto o egress no aprobado,
una fuente simulada se presenta como real, la reversión no se puede ensayar o
el proyecto no está expresamente autorizado. La candidatura solo existe cuando
el acta contiene revisión/digests, comandos, tiempos, resultados y responsable.

## Reversión y limpieza

1. Deshabilitar egress y detener nuevas cargas. Esperar o cancelar trabajos y
   confirmar sus estados terminales.
2. Detener la revisión candidata sin eliminar volúmenes. Conservar una copia
   cifrada de diagnóstico solo si la política y el propietario lo autorizan.
3. Restaurar imágenes/revisión y configuración anteriores por digest. Restaurar
   datos únicamente desde la copia verificada a un directorio nuevo con el
   procedimiento de `docs/backup-restore.md`, cambiando el montaje de forma
   atómica; nunca mezclar esquemas o árboles parcialmente.
4. Iniciar la versión anterior, comprobar salud/login/listado owner-scoped y
   confirmar que no se reanudan trabajos interrumpidos como completados.
5. Para limpiar la prueba, previsualizar y ejecutar primero la cascada del
   proyecto y verificar ausencia de proyecto, jobs, workspaces, snapshots,
   triage e informes. Eliminar después la subida por su ruta independiente y
   documentar caché pública, actividad y cualquier copia externa retenida.
   `PROD-120` está completada y aporta la cascada recuperable verificable, pero
   la aplicación no promete secure erase físico ni eliminar automáticamente
   fuentes compartidas o copias externas; la limpieza completa sigue exigiendo
   revisar el volumen y la custodia de backups.

La reversión se considerará ensayada solo cuando se hayan registrado duración,
estado de los datos y comprobaciones posteriores sin usar el proyecto real
antes de su autorización.
