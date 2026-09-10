# Frontend visual review

Use this review for a change that affects layout, visual hierarchy, responsive
behaviour, a core user flow, or visible loading/error/empty states. It is a
deliberate manual gate alongside the automated frontend suite; it does not
replace accessibility tests or functional tests.

## Planes duraderos de remediación — PROD-218 (2026-09-09)

Una instancia local desechable, con egress público deshabilitado, importó el
ZIP sintético canónico y añadió un único resultado sintético normalizado. El
recorrido abrió el centro de remediación, confirmó la divulgación de nombres de
proyecto, creó un plan, observó la transición desde cola hasta **Plan ready** y
descargó JSON desde el snapshot inmutable. La interfaz mostró cutoff, 1/1
proyectos, 1 grupo, 1 ocurrencia, vencimiento y el prefijo de su digest; los
logs HTTP contenían solo rutas de la API local y no hubo llamadas a proveedor.

Se revisaron 1440×900, 768×900 y 320×900. El plan midió 1341/1341, 669/669 y
245/245 píxeles de `clientWidth/scrollWidth`; su lista móvil midió 219/219. La
primera pasada sí descubrió un desborde global móvil 330/305, ajeno al artefacto
pero visible en el recorrido: el botón de proyecto reciente imponía al grid de
onboarding su ancho intrínseco. `project-start-copy` usa ahora una columna
`minmax(0, 1fr)` y el botón puede partirse; la repetición terminó 305/305, foco
visible de 3 px y consola sin errores o avisos. Una regresión estática protege
esas reglas y las pruebas de componente cubren carga, vacío, progreso, fallo,
caducidad, confirmación y descarga.

La revisión utilizó exclusivamente datos sintéticos. Al finalizar se cerraron
la pestaña y Vite y se eliminaron el contenedor, volumen, red y directorio
temporal; no quedaron recursos con el prefijo `inspectra-prod218-visual-`.

## Saved remediation views — PROD-217 (2026-09-09)

A disposable local instance with public egress disabled exercised the
Remediation center at 1440×900, 768×900 and 320×760. The journey created a
private view, made it the account default, reloaded the application and
confirmed that selection. Loading, empty state, expanded form,
private/workspace labels, disabled actions, native focus and browser console
were inspected.

The first pass found that the new JSON was published as `0644` and that the
mobile checkbox inherited full width, causing four pixels of internal
overflow. After correction, records publish as `0600`; tablet measured page
753/753 and picker 643/643, while mobile measured page 305/305 and
picker/form 219/219 with a 22×22 checkbox. Console errors/warnings were empty.
Viewport, tabs, local servers, ports and containers were reset; both temporary
data directories were moved to the recoverable local trash.

## Safe data and capture handling

Use only the synthetic fixtures in `tests/fixtures/demo/passive-alpha/`. Do not
upload production archives, real credentials, customer data, or screenshots
that expose them. Save local captures under `visual-review/`; that directory is
ignored by Git. Attach only the minimum redacted screenshots needed for code
review through the team's approved review channel.

## Repeatable review flow

1. Start an isolated local stack, using alternate ports if the defaults are in
   use:

   ```bash
   INSPECTRA_BACKEND_HOST_PORT=18000 INSPECTRA_FRONTEND_HOST_PORT=15173 docker compose up --build
   ```

2. Open `http://localhost:15173`, wait for the backend status to become
   available, and capture the dashboard at each viewport in the matrix below.
   Use browser/device emulation or a browser window sized to the exact CSS
   width. Keep browser zoom at 100%.
3. Upload `archives/demo-archive-app-config.zip`, start one passive archive
   review, then select its completed result. Capture the result view at the
   same viewport widths. If a controlled error, loading, or empty state was
   changed, capture that state as well.
4. Review the captures against the checklist, run `make test-frontend
   build-frontend`, and include the outcome in the pull request description.
   Stop the local stack when finished.

## Capture matrix

| Surface | Desktop | Tablet | Narrow mobile |
| --- | --- | --- | --- |
| Dashboard with advanced audits closed | 1440 px | 768 px | 320 px |
| Project workspace with retained history | 1440 px | 768 px | 320 px |
| Selected job result and exports | 1440 px | 768 px | 320 px |
| Changed loading, error, or empty state | 1440 px when applicable | 768 px when applicable | 320 px when applicable |

## Review checklist

- No content overlaps, clips unintentionally, or creates a horizontal page
  scrollbar at 1440, 768, or 320 px. Dense tables and compact navigation may
  scroll only inside their labelled container.
- The primary workflow and its current step remain visible before advanced
  controls; the advanced-audits disclosure accurately communicates its state.
- Inputs, primary actions, error messages, empty states, and loading feedback
  are understandable without relying only on colour or placeholders.
- Keyboard focus is visible and ordered sensibly. Data tables retain headers,
  their mobile scroll hint, and an operable horizontal scroll region when
  needed.
- At 320 px, summary data, tool output, export controls, and result evidence
  remain readable or safely scrollable; no secret-like or raw target data is
  introduced by the capture.
- A selected result still has a visible transition while its deferred report is
  loading and remains navigable after it resolves.

## Review record template

```text
Visual review
Change: <pull request or commit>
Fixtures: tests/fixtures/demo/passive-alpha/archives/demo-archive-app-config.zip
Captured: dashboard + selected result at 1440 / 768 / 320 px
Changed states: <loading/error/empty state or not applicable>
Outcome: <approved or follow-up issue ID>
Automated checks: make test-frontend build-frontend
```

## Registro — 2026-09-05: recorrido de proyecto sintético

- **Alcance:** dashboard, espacio de trabajo retenido y resultado seleccionado
  del archivo `demo-archive-app-config.zip`, sin egress público y sin volver a
  cargar datos. Se usó el navegador local con zoom al 100 % a 1440, 980 y 640
  px; la revisión se puede repetir con el flujo anterior y el mismo fixture.
- **Hechos comprobados:** el dashboard mantiene la acción principal y sus
  límites a los tres anchos; el workspace conserva una línea temporal,
  cobertura y estados de inteligencia desactivada sin desbordar la página; el
  resultado toma foco al abrirse, anuncia su actualización y las tablas densas
  mantienen su región desplazable y su aviso.
- **Defecto encontrado y corregido:** a 1440 px, las etiquetas largas de
  métricas de límites podían conservar su ancho intrínseco e invadir el valor
  del mismo par. Las etiquetas de `summary-list` y `compact-list` ahora se
  reducen y parten por un límite seguro. La prueba de componente cubre una clave
  larga y `frontend/tests/styles.test.mjs` protege la regla de contención.
- **Resultado visual:** tras reconstruir el stack local, no hubo solapamiento
  de pares etiqueta/valor ni scroll horizontal de página a 640 px. A 980 y 640
  los grupos se apilan antes de perder legibilidad. Las capturas contienen solo
  el fixture sintético y no se conservan como artefactos del repositorio.
- **Seguimiento de privacidad:** los IDs y hashes completos siguen visibles en
  el detalle técnico por diseño actual. `PROD-075` debe clasificarlos y definir
  presentación mínima/divulgación explícita antes de habilitar informes o
  integraciones de equipo.

## Registro — 2026-09-05: perfil de ejecución persistido

- **Alcance:** superficie modificada de resultado de proyecto, usando el ZIP
  sintético `demo-archive-app-config.zip` en una pila local con egress público
  desactivado. Se creó una ejecución local para comprobar que el perfil no era
  solo un fixture de interfaz.
- **Hechos comprobados:** la respuesta de creación y el resultado completado
  contenían el mismo contrato/reglas/perfil/límite de admisión/concurrencia. A
  980 px el par de metadatos se alinea con el resto del resumen; a 640 px el
  valor se adapta a la columna sin recorte ni scroll horizontal de página
  (`scrollWidth == clientWidth == 625`).
- **Límites:** esta revisión no reevalúa la privacidad de los IDs/hash de la
  ficha, que sigue asignada a `PROD-075`; tampoco convierte el perfil en prueba
  de una cola durable o de procedencia binaria del runner.
- **Automatización asociada:** las pruebas de componente cubren tanto el perfil
  legado como el persistido; la suite frontend pasó con 38 archivos/261 pruebas
  y el build mantuvo 310,6 KiB dentro del presupuesto inicial de 322 KiB.

## Registro — 2026-09-05: línea base de regresión guardada

- **Alcance:** comparación de dos ejecuciones del mismo ZIP sintético
  `demo-archive-app-config.zip` en el proyecto local `Execution profile
  fixture`. Se creó una segunda ejecución, se guardó la anterior como línea
  base y se recargó el historial para comprobar la selección por defecto.
- **Hechos comprobados:** la vista diferencia la política guardada de una
  comparación ad hoc, muestra la versión de política y la insignia **Saved
  Project Baseline**, conserva las métricas nuevo/resuelto/persistente y ofrece
  una acción explícita para retirar la política. A 1265 px el panel no tuvo
  desborde (`scrollWidth == clientWidth == 1215`); a 640 px el documento tampoco
  tuvo scroll horizontal (`625 == 625`) y los selectores y acciones se apilaron
  de forma legible.
- **Límites:** la revisión usa datos sintéticos locales y no prueba borrado por
  retención programada ni egress de advisories. La privacidad de hashes e IDs
  técnicos sigue cubierta por `PROD-075`.
- **Automatización asociada:** backend/runner completos y 38 suites/262 pruebas
  frontend pasaron; el build dejó el bundle inicial en 311,0 KiB de 322 KiB.

## Registro — 2026-09-05: comparación consciente de cobertura

- **Alcance:** la misma comparación owner-scoped de dos ejecuciones del ZIP
  sintético `demo-archive-app-config.zip`, en la pila local reconstruida con
  egress de advisories desactivado. Se revisó la nueva tarjeta de cobertura y
  el estado equivalente sin cargar ni cambiar una fuente adicional.
- **Hechos comprobados:** a 1265 px, la comparación conservó la base guardada,
  las métricas persistentes y dos tarjetas de cobertura con 1/1 manifiestos,
  1/1 lockfiles y 3 dependencias. No hubo desborde horizontal de página. A
  640 px, ambas tarjetas se apilaron a 530 px de ancho dentro de la cuadrícula,
  también sin desborde horizontal. El navegador local no registró errores de
  consola.
- **Límite y seguridad:** el estado `changed` se valida con fixtures y pruebas
  de interacción, no alterando los resultados sintéticos retenidos. La vista
  solo recibe contadores y estados agregados; no muestra bytes, rutas, secretos
  ni datos de proveedor. La eliminación futura por clase de derivado continúa
  en `PROD-062`.
- **Automatización asociada:** pasaron 1.348 casos backend/runner, 38
  archivos/264 pruebas frontend, build/presupuesto 311,1/322 KiB, Compose y
  `git diff --check`.

## Registro — 2026-09-06: inteligencia pública priorizada (`PROD-113`)

- **Alcance:** aplicación y API reales ejecutadas localmente sobre una copia
  temporal del proyecto sintético `demo-archive-app-config.zip`. El snapshot
  de inteligencia se construyó con `MockTransport` y fixtures sintéticos de
  OSV, GitHub y CISA; durante la revisión el navegador realizó únicamente GET
  contra la API local. No se contactó ningún proveedor ni se modificó `data/`.
- **Recorrido:** espacio de trabajo → inventario exacto/no correlacionable →
  estado de egress atestado → pasos OSV/GitHub/KEV → resumen priorizado →
  filtros → primera evidencia expandida → snapshot histórico caducado. Se
  comprobó que KEV aparece como señal independiente sobre un CVE previo y no
  como fuente de correlación de paquete.
- **Matriz visual:** 1440, 768 y 320 px con zoom al 100 %. En los tres anchos la
  página terminó con `scrollWidth == clientWidth` (1425, 753 y 305 px útiles),
  la primera tarjeta fue el CVE con señal KEV y quedó abierta, la segunda quedó
  contraída y no hubo errores o advertencias de consola. El foco de búsqueda
  conservó un contorno visible.
- **Defecto encontrado y corregido:** a 320 px, la cuadrícula implícita de la
  lista de hallazgos comunes tomaba el ancho mínimo de un identificador largo y
  ensanchaba la página 8 px. La lista usa ahora una columna `minmax(0, 1fr)` y
  las tarjetas pueden reducirse; una prueba estática protege esa contención.
- **Estados:** se revisaron visualmente `ready` y un histórico `stale` de solo
  lectura. `disabled`, `degraded`, `not_requested`, sin componentes
  correlacionables, carga y error están cubiertos por fixtures/pruebas de
  componente; no se presentan como validación contra fuentes reales.
- **Automatización asociada:** 38 archivos/277 pruebas frontend en 18,89 s,
  TypeScript/Vite y presupuesto inicial 311,6/322 KiB en 7,51 s. El árbol
  original no ejecuta Vite directamente porque `node_modules/.vite-temp` no es
  escribible; se validó una copia exacta con las mismas dependencias instaladas.

## Registro — 2026-09-06: espacios privados de equipo (`PROD-012`)

- **Alcance:** acceso en modo `private_team_lightweight_users`, panel del
  espacio bootstrap, invitación de un solo uso, creación y cambio a un segundo
  espacio, comprobación de su estado vacío y regreso al espacio inicial. Solo
  se usaron identidades y almacenamiento temporal sintéticos; no se cargó un
  proyecto ni se habilitó egress.
- **Matriz visual:** 1440, 768, 390 y 320 px con zoom al 100 %. El documento no
  tuvo desbordamiento horizontal (`1425 == 1425`, `753 == 753`, `375 == 375` y
  `305 == 305` píxeles útiles). A 768 px el foco alcanzado por teclado conservó
  un contorno sólido de 3 px; a 320 px los formularios se apilaron sin recorte.
- **Hechos comprobados:** el encabezado y el panel muestran nombre de espacio y
  rol en vez del identificador opaco; crear un espacio rota la sesión, selecciona
  el nuevo límite y vuelve a cargar proyectos vacíos. El selector permite volver
  al espacio bootstrap. El token sintético solo apareció tras crear la
  invitación y desapareció al cambiar de contexto. No hubo errores ni avisos de
  consola.
- **Privacidad y limpieza:** la consola/red local solo mostró rutas HTTP y
  códigos, nunca contraseña, token ni cuerpo. Se cerraron frontend/backend y la
  base temporal con el token se movió a la papelera al terminar. Las capturas no
  se conservaron en el repositorio.
- **Automatización asociada:** pasaron 286/286 pruebas frontend en 22,26 s y el
  build TypeScript/Vite en 13,82 s, con bundle inicial 314,6/322 KiB. Las pruebas
  de componentes cubren axe, estados por rol, invitación y limpieza de campos.

## Registro — 2026-09-06: triage y excepciones revisables (`PROD-011`)

- **Alcance:** proyecto local sintético con dos hallazgos y dos ejecuciones
  completadas, preparado exclusivamente en un directorio temporal. Se recorrió
  lista → detalle → decisión → excepción con fecha → historial → filtro →
  comparación → informe. El egress permaneció deshabilitado y no se usó un
  proyecto real ni una respuesta de proveedor.
- **Matriz visual:** 1440, 768, 390 y 320 px con zoom al 100 %. El documento no
  tuvo desbordamiento horizontal (`1425 == 1425`, `753 == 753`, `375 == 375` y
  `305 == 305` píxeles útiles). A 320 px el panel, filtros y formulario quedaron
  dentro de 273/239/191 px respectivamente; el foco de búsqueda conservó un
  contorno sólido de 3 px.
- **Hechos comprobados:** razón, actor, asignación, estado y fecha sobreviven a
  la recarga; el historial muestra seis eventos sintéticos sin editar el
  resultado. El filtro oculta el hallazgo abierto al elegir `accepted`. La
  comparación mostró 1 nuevo, 1 resuelto y 1 persistente y conservó `Risk
  accepted` en el persistente. El informe Markdown incluyó resumen, razón y
  `2099-03-17T14:45:00+00:00`, sin el comentario libre.
- **Defectos encontrados y corregidos:** `needs_review` se rotulaba como fecha
  vencida incluso para una revisión manual sin fecha; el contrato distingue
  ahora `review_overdue`. Además, `datetime-local` no retenía el valor tras una
  segunda interacción del navegador; el control escucha el evento nativo de
  entrada y la repetición conservó `2099-03-17T14:45` antes y después de la
  confirmación.
- **Automatización asociada:** 1.050/1.050 pruebas backend, 420/420
  runner/guardas, 290/290 frontend, axe sobre lectura y formulario editable,
  build/presupuesto 314,9/322 KiB, `compileall`, Compose base/privado y diff.
  Las capturas no se conservaron en el repositorio y el entorno temporal se
  elimina al terminar la revisión.

## Registro — 2026-09-06: actividad administrativa mínima (`PROD-013`)

- **Alcance:** modo de equipo privado y almacenamiento sintético temporal;
  inicio de sesión administrador → panel de actividad → filtro exacto → estado
  sin coincidencias → restauración de la lista. No se cargó un proyecto, no se
  habilitó egress y no se contactó ningún proveedor.
- **Matriz visual:** 1440, 768, 390 y 320 px al 100 %. El documento mantuvo
  `scrollWidth == clientWidth` en 1425, 753, 375 y 305 px útiles. El panel quedó
  dentro de 705 px a tablet, 343 px a móvil y 273 px en el ancho mínimo; el
  campo de filtro ocupó 343 px a 390 sin desbordar.
- **Hechos comprobados:** el panel explica qué no registra, muestra retención,
  actor/rol, recurso opaco, resultado, correlación y contexto allowlisted. Un
  filtro sin coincidencias ofrece salida clara y el foco del botón conservó un
  contorno sólido de 3 px. La captura de escritorio y el snapshot semántico
  fueron reproducibles; la captura móvil del navegador no estuvo disponible,
  por lo que no se presenta como evidencia visual guardada. Tampoco se afirma
  consola limpia en esta revisión.
- **Automatización asociada:** axe cubre estados poblado/error/vacío; pasaron
  42 archivos/292 pruebas frontend y el build dejó 315,4/322 KiB. El entorno y
  su base sintética se eliminan tras cerrar esta sesión de revisión.

## Registro — 2026-09-06: ciclo de datos y expurgo (`PROD-020`)

- **Alcance:** aplicación y API locales reales con un directorio temporal vacío
  y egress deshabilitado. Se recorrió política cargada → confirmación destructiva
  → purga → resultado por clase. No se cargó ni analizó un proyecto real y no se
  contactó ningún proveedor.
- **Matriz visual:** 1440, 768, 390 y 320 px al 100 %. El documento mantuvo
  `scrollWidth == clientWidth` en 1425, 753, 375 y 305 px útiles. La cuadrícula
  pasó de tres a dos y una columna; el panel quedó en 705/343/273 px y el botón
  ocupó 346/343/273 px sin corte. Se capturaron escritorio y móvil.
- **Hechos comprobados:** la política distingue nueve clases, muestra frescura
  y retención de caché por separado y declara que cifrado y backups son externos.
  La acción está deshabilitada hasta la confirmación; después muestra hora,
  cuatro clases evaluadas y conteos sintéticos. El checkbox enfocado conservó
  contorno sólido de 3 px y offset de 2 px.
- **Estados complementarios:** solo lectura por rol, carga, error, parcial y
  valores deshabilitados están cubiertos por tres pruebas de componente y axe;
  autorización/CSRF/entrada vacía están cubiertos en backend. No se afirma
  consola limpia porque esa capacidad no estuvo disponible en esta revisión.
- **Automatización asociada:** 43 archivos/295 pruebas frontend pasaron en
  20,30 s; build TypeScript/Vite y presupuesto inicial 315,9/322 KiB en 7,57 s.
  El entorno temporal se elimina al cerrar la sesión de revisión.

## Registro — 2026-09-06: borrado recuperable de proyecto (`PROD-036`)

- **Alcance:** frontend y API locales reales con el ZIP sintético
  `demo-archive-app-config.zip`, egress deshabilitado y un directorio de datos
  temporal. Se recorrió proyecto → revisión de alcance → confirmación → borrado
  → actualización del workspace. El runner no estaba iniciado, por lo que la
  ejecución terminó de forma controlada con `runner_unavailable`; no se usó
  Internet, proveedor ni proyecto real.
- **Matriz visual:** escritorio a 1440 px y móvil a 390 px, zoom al 100 %. La
  vista mostró las clases que se eliminan, conservan y no se persisten en dos
  columnas que pasan a una. En móvil el documento mantuvo
  `scrollWidth == clientWidth == 375`, la acción ocupó el ancho disponible y el
  checkbox enfocado mostró contorno sólido de 3 px con offset de 2 px.
- **Hechos comprobados:** la acción permaneció bloqueada hasta revisar alcance y
  confirmar. Tras ejecutarla, el proyecto desapareció y el estado anunció que
  sus derivados fueron eliminados mientras la subida seguía bajo la política
  de **Files**. Las pruebas cubren además trabajo activo, rol de solo lectura,
  propietario cruzado, reintento, fuente vencida, interrupción, journal y
  recuperación de arranque.
- **Defecto descubierto:** los paneles de inventario, hallazgos e inteligencia
  describen como «queued or running» una ejecución ya `failed`. Se registra
  como tarea P1 independiente para distinguir fallo/cancelación/ausencia de
  resultado sin prometer que el análisis sigue activo.
- **Automatización asociada:** 1.069 pruebas backend, 420 runner/guardas y 44
  archivos/298 pruebas frontend; build inicial 317,0/322 KiB. El navegador no
  ofreció capacidad de consola en esta revisión, por lo que no se afirma que la
  consola estuviera limpia. Las capturas no se conservaron en el repositorio.

## Registro — 2026-09-06: estados terminales derivados (`PROD-123`)

- **Alcance:** workspace, inteligencia pública, hallazgos e inventario con el
  ZIP sintético `demo-archive-app-config.zip`, API/frontend locales y egress
  deshabilitado. El fallo `runner_unavailable` se produjo realmente al mantener
  el runner ausente. Como el fallo terminaba antes de que la petición de
  cancelación pudiera competir, el estado cancelado usado solo para revisar la
  presentación se creó mediante el mismo `JobStore.mark_cancelled` ejercitado
  por las pruebas; no se presenta como validación visual de la carrera de
  cancelación.
- **Hechos comprobados:** los tres paneles muestran `Analysis failed without a
  usable result` para `failed` y `Analysis was cancelled` para `cancelled`.
  Ninguno los llama activo; ofrecen elegir un snapshot completado o reintentar
  desde el historial. Inteligencia deshabilita las tres consultas y separa su
  banner operativo del aviso terminal. No aparece el error interno del runner.
- **Matriz visual:** 1440 y 390 px al 100 %. En móvil el documento conservó
  `scrollWidth == clientWidth == 375`; cards, selects y acciones se apilaron sin
  recorte. La navegación por teclado produjo un foco sólido de 3 px con offset
  de 2 px. Fallo y cancelación usan texto e iconografía/estructura, no solo
  color.
- **Automatización asociada:** una prueba ASGI recorre los tres endpoints con
  ambos estados y marcadores de ruta/secreto; 36 pruebas dirigidas de los tres
  paneles incluyen axe. Pasaron 1.070 backend (21,69 s), 420 runner/guardas
  (6,22 s), 44 archivos/304 frontend (21,10 s) y build 317,2/322 KiB (8,03 s).
  Dos comandos frontend iniciales no ejecutaron casos por directorio y opción
  `--run` duplicada; se corrigieron y no se atribuyeron al sandbox. La capacidad
  de consola del navegador no estaba disponible y no se afirma consola limpia.

## Registro — 2026-09-06: clasificación completa del ciclo de datos (`PROD-062`)

- **Alcance:** frontend y API locales reales sobre el directorio temporal
  sintético ya usado por la revisión; egress permaneció deshabilitado. Se
  recorrió carga de política → agrupación de las catorce clases → apertura de
  detalles de fuente, identidad y backup → confirmación sin ejecutar la purga.
  No se contactó proveedor ni se cargó o analizó un proyecto real.
- **Matriz visual:** 1440 × 1000 y 390 × 844 px al 100 %. En móvil se
  materializaron 14 cards; `scrollWidth` fue 375 frente a `innerWidth` 390,
  con extremos de cards entre 16 y 359 px. La cuadrícula pasó de tres columnas
  a una, estados y acciones se apilaron y los detalles no produjeron desborde.
- **Hechos comprobados:** la vista muestra `14 classes classified`, el contrato
  de backup, la independencia entre fuente/resultado/proyecto/copia externa y
  los cuatro grupos. Los detalles explican almacenamiento, sensibilidad,
  backup, restore y disparador de borrado. La revisión detectó y corrigió una
  descripción falsa: el restore no elimina identidades/membresías; las conserva
  y descarta sesiones, intentos e invitaciones. La UI final muestra ese límite y
  `not applicable` como borrado actual de identidad. El checkbox enfocado tuvo
  contorno sólido de 3 px y offset de 2 px; la acción permaneció sin ejecutar.
- **Automatización asociada:** 25 pruebas dirigidas backend y 63 frontend
  pasaron antes de la revisión; la regresión final y sus tiempos se registran en
  `TODO_PRODUCTO.md`. El primer intento de sincronización frontend no ejecutó
  pruebas por una ruta relativa incorrecta y el primer reinicio visual no llegó
  a arrancar por omitir el paquete local `active_runner`; ambos se repitieron
  con configuración correcta y no se atribuyeron al sandbox. La capacidad de
  consola del navegador no estaba disponible y no se afirma consola limpia.

## Registro — 2026-09-06: privacidad de metadatos de fuente (`PROD-075`)

- **Alcance:** API y frontend locales sobre datos exclusivamente sintéticos,
  con egress deshabilitado. Se revisaron política de datos, tabla de proyectos,
  workspace/historial y detalle técnico de una ejecución vinculada. La vista
  **Files** se mantuvo como único flujo explícito autorizado para gestionar el
  nombre original y el digest interno; no se contactó proveedor ni se analizó
  un proyecto real.
- **Matriz visual:** 1440 × 1000 y 390 × 844 px al 100 %. El documento no tuvo
  desborde (`scrollWidth == clientWidth`: 1425 en escritorio y 375 en móvil).
  La tabla conserva su desplazamiento horizontal intencional; el workspace se
  apila en móvil y la acción enfocada mostró contorno sólido de 3 px con offset
  de 2 px.
- **Privacidad comprobada:** proyecto e historial mostraron únicamente
  `snapshot-0d70c833e2808977`; no contenían nombres `.zip`/`.tar` ni valores de
  64 hexadecimales. El detalle técnico y su JSON visible incluyeron la referencia
  segura, pero no las claves `file_id`, `source_sha256`, `hashes` u
  `original_filename`. La política presentó cuatro reglas: nombre, digest e ID
  interno retenidos/ocultos según su finalidad y referencia segura compartible.
- **Defecto detectado y corregido:** una recarga en caliente conservó en memoria
  una respuesta anterior al contrato `2026-09-06.3`; el nuevo panel intentó
  recorrer `source_metadata` ausente y dejó la aplicación en blanco. El panel
  ahora falla de forma cerrada con un error accionable, mantiene ocultos los
  metadatos y conserva el resto de la política. Una prueba de regresión con una
  respuesta antigua cubre el caso. Tras una recarga limpia con contratos
  coincidentes, el registro del navegador no mostró errores nuevos.
- **Automatización asociada:** 44 archivos/306 pruebas frontend pasaron en
  22,24 s; build TypeScript/Vite y presupuesto inicial 317,4/322 KiB pasaron en
  8,22 s. La revisión dirigida previa pasó 64/64 pruebas. Las suites backend
  (1.087) y runner/guardas (420), ejecutadas después del cambio de contrato y
  antes de esta corrección exclusivamente frontend, permanecen válidas.

## Registro — 2026-09-06: candidatura local y flujo de inteligencia (`PROD-116`)

- **Alcance y separación de evidencias:** la pila candidata se validó por TLS
  local con un cliente que confió exclusivamente su CA efímera. El navegador
  integrado rechazó esa CA y no se desactivó la validación ni se alteró el
  almacén de confianza. La revisión visual usó el mismo árbol actual mediante
  frontend/backend HTTP locales y datos sintéticos ya preparados; no valida
  certificado, proveedor público ni proyecto real.
- **Recorrido:** dashboard y espacio de trabajo → hallazgos → inventario y
  cobertura → política de egress deshabilitada → pasos OSV/GitHub/KEV →
  advisories retenidos → búsqueda por CVE → filtro CVSS → fuentes oficiales →
  comparación e informes. Los hallazgos públicos proceden de fixtures y no se
  presentan como respuestas reales.
- **Matriz visual:** 1440 × 1000, 768 × 900 y 320 × 780 px al 100 %. El documento
  conservó `scrollWidth == clientWidth` (1425, 753 y 305 px útiles). Las tablas,
  navegación segmentada y controles densos se desplazan solo dentro de sus
  contenedores etiquetados; no hubo contenido fuera de una región acotada.
- **Interacción y accesibilidad:** buscar `CVE-2025-1234` ocultó el advisory de
  `lodash`; seleccionar **Critical** conservó solo el CVE crítico. Los enlaces
  mostrados fueron HTTPS hacia GitHub Advisory, NVD, CISA KEV y OSV, con
  `target=_blank` y `rel="noopener noreferrer"`. La navegación por teclado
  produjo `:focus-visible` con contorno sólido de 3 px. La consola solo registró
  conexión de Vite y el aviso informativo de React DevTools, sin errores.
- **Resultado:** el panel explica que el egress está deshabilitado, diferencia
  snapshot actual/degradado/caducado, mantiene KEV separado de CVSS y aclara que
  KEV no crea un hallazgo. A 320 px la jerarquía, copy y acciones siguen
  legibles y apilados. No se detectó un defecto visual nuevo; no se conservaron
  capturas en el repositorio.
- **Automatización asociada:** 44 archivos/306 pruebas frontend en 22,23 s,
  build y presupuesto 317,4/322 KiB en 7,77 s; la regresión incluye axe para
  dashboard, lifecycle, inteligencia y estados de error/vacío.

## Registro — 2026-09-06: aceptación real Eventora (`PROD-117`/`PROD-128`)

- **Alcance:** copia efímera de la candidatura y de los datos normalizados de la
  aceptación Eventora, con el egress de la copia visual deshabilitado. Se
  recorrieron dashboard, workspace e historial, inventario/cobertura,
  correlaciones retenidas, inteligencia actual y degradada, búsqueda/filtros,
  detalle público, hallazgos y triage, comparación e informes. La copia no
  realizó consultas de proveedor ni conservó capturas en el repositorio.
- **Matriz responsive:** 1440 × 1000, 768 × 900 y 320 × 780 px al 100 %. El
  documento conservó `scrollWidth == clientWidth` en 1425/1425, 753/753 y
  305/305 px. Las tablas deliberadamente anchas permanecieron dentro de sus
  regiones con scroll local. En el resultado completo a 320 px,
  `.report-layout` y las cuatro primeras secciones midieron 239 px dentro de
  305 px útiles, sin barra global.
- **Cobertura y estados:** la UI mostró política de egress del operador
  deshabilitada, 590 componentes, 369/369 consultados en el snapshot retenido,
  33 hallazgos verificados y 33 fixes publicados. El selector histórico mostró
  por separado el refresco `degraded`, advirtió que la cobertura era parcial y
  que un vacío no era ausencia de riesgo. El desglose de correlación mantuvo
  visibles los componentes no correlacionables y su razón.
- **Interacción:** el filtro Critical redujo la lista a 1/33; una búsqueda sin
  coincidencias mostró 0/33, acción **Clear filters** y explicación. El detalle
  abierto separó CVSS, intervalos afectados, versiones corregidas, aliases,
  fechas, OSV y KEV. KEV `not listed` incluyó expresamente que no demuestra
  ausencia de explotación. La comparación mostró 0 nuevos, 0 resueltos y 33
  persistentes; el triage conservó 1 hallazgo `In review` con historial y
  formulario de decisión.
- **Defectos corregidos:** la primera inspección detectó que las tarjetas del
  informe podían ensanchar el documento móvil y que algunos contadores llamaban
  «advisories verificados» a ocurrencias por componente. Se añadieron límites
  `minmax(0, 1fr)`/wrapping en el layout del informe y se cambió el vocabulario
  a «verified findings», sin ocultar overflow. La segunda pasada completa
  produjo las medidas anteriores y una regresión CSS protege el caso.
- **Automatización asociada:** 89 archivos/307 pruebas frontend, build
  TypeScript/Vite y presupuesto inicial 317,4/322 KiB. La API confirmó también
  que triage, snapshots e informes sobrevivían al reinicio. La superficie de
  navegador disponible no expuso un registro de consola en esta pasada, por lo
  que no se afirma una comprobación de consola; no aparecieron banners de error
  inesperados y todas las interacciones terminaron correctamente.

## Registro — 2026-09-08: portada por intención (`PROD-165`)

- **Alcance:** candidatura local servida desde el código actual y un backend con
  almacenamiento temporal vacío; no se cargaron archivos, no se habilitó
  egress y no se contactó ningún proveedor. Se revisaron la portada de primera
  visita, los tres caminos de incorporación, los disclosures administrativo y
  de auditorías especializadas, y el foco de las entradas Archivo/SBOM. El
  recorrido recurrente proyecto → CI se verificó con la prueba de integración
  de interfaz y su fixture owner-scoped.
- **Matriz reproducible:** navegador al 100 % con viewport CSS exacto de
  1440×900, 768×1024 y 320×740. En los tres casos
  `documentElement.scrollWidth - clientWidth == 0`; la cuadrícula pasó de tres
  columnas de 439 px a una columna de 671/245 px. Las capturas locales
  `prod-165-home-{1440,768,320}.png` se guardaron bajo el directorio ignorado
  `docs/visual-review/` y no contienen proyectos, rutas, credenciales ni datos
  de cliente. SHA-256: 1440 `4fccf02baaad16f2bb3dab67a89af759a16b44e9cd7262273d23856798f4fb51`,
  768 `3fa31b1c14e8e4d88edffb7808280ae6c97c18a89bc226813551533d1112eaa7`
  y 320 `ab05d94825c6219c09b0ca4b361ee2a26598cbd5cd4824ff6c43e44212948629`.
- **Hechos comprobados:** un usuario nuevo alcanza Archivo o SBOM con una sola
  acción; CI permanece inhabilitado con explicación hasta existir un proyecto
  de archivo. Archivo selecciona ese tipo y enfoca el input descrito por el
  límite de autorización; SBOM enfoca `sbom-import-file`. El fixture recurrente
  abre el proyecto y enfoca `ci-setup`, preservando `#project=<id>` en la URL.
  Administración parte cerrada; las auditorías URL/dominio/activas quedan en
  un disclosure separado del análisis de proyectos. No hubo errores ni avisos
  en la consola del navegador.
- **Fricción medida:** el estado anterior ofrecía una única entrada genérica al
  flujo de proyecto y dejaba SBOM como formulario separado y CI dentro del
  workspace; no se conservó una medición temporal instrumentada de ese árbol
  intermedio y no se inventa una cifra «antes». En la candidatura, las tres
  decisiones están rotuladas en el primer viewport: Archivo y SBOM requieren
  exactamente un clic hasta el control enfocado; un usuario recurrente requiere
  un clic para abrir proyecto+CI. A 1440 px los tres CTA comienzan en la primera
  pantalla (tarjetas en y=364, alto=194) y no exigen recorrer las auditorías
  especializadas. Esta es la métrica reproducible usada, no una estimación de
  segundos dependiente del operador.
- **Defectos encontrados y corregidos:** la ruta SBOM asumía la presencia de
  `scrollIntoView`; ahora degrada sin error. El foco de CI podía adelantarse a
  la carga diferida y ahora lo solicita el panel al montar. El foco de Archivo
  dependía de un `requestAnimationFrame` susceptible de throttling en segundo
  plano y ahora es inmediato. Los CTA de entrada pasaron de 36 a un mínimo de
  44 px de alto; la repetición midió 44/44/44 px en los tres.
- **Automatización asociada:** `App`, `ProjectCiSetupPanel` y
  `ProjectWorkspacePanel` pasan 70/70 pruebas, incluidas primera visita,
  recurrente, teclado y axe; TypeScript no informa errores. La suite y build
  globales se registran en el backlog al cerrar la validación de candidatura.

## Active control verification review — 2026-09-09

- **Fixture and boundary:** a fresh local backend used trusted-local auth,
  `INSPECTRA_ACTIVE_ASSET_VERIFICATION_ENABLED=true` and an ephemeral data
  directory. The only asset was the synthetic `demo.example.test`; no Active
  capability or external transport was enabled or invoked.
- **Flow exercised:** empty Active center → guided registration → details →
  one-time manual challenge → explicit second attestation → `verified` state.
  The screen kept authorization and control verification semantically separate,
  exposed the one-time/digest rule and offered revocation.
- **Responsive evidence:** document `scrollWidth/clientWidth` was `305/305`,
  `753/753` and `1425/1425` at 320, 768 and 1440 px. The verification panel
  remained within the Active card (209, 298 and 624 px respectively).
- **Defect found and corrected:** verification selects/buttons initially
  measured 19/36 px high on mobile. An Active-scoped minimum was added; the
  repeated measurements were 44 px at all three viewports without hiding
  overflow globally.
- **Accessibility and console:** the component passed axe in both disabled and
  completed-verification states; the browser console contained no errors or
  warnings. Backend fixtures and frontend mocks remain Internet-independent.

## Active operations center review — 2026-09-09

- **Fixture and boundary:** the same ephemeral trusted-local environment retained
  one synthetic `.test` asset and its manual control signal. All five live
  capabilities remained operator-disabled; no execution or external transport
  was invoked.
- **Flow exercised:** center load → organization summary → status/capability/date
  controls → capability filter with no matches → restore view → expand asset →
  inspect authorization, verification and empty execution history. A simulated
  summary failure is covered separately and leaves the asset workflow usable.
- **Responsive evidence:** at 320, 768 and 1440 CSS pixels the document measured
  `305/305`, `753/753` and `1425/1425` client/scroll width. The expanded card
  measured `241/241`, `673/673` and `1326/1326` card/grid width. Every Active
  button, input and select measured at least 44 px high.
- **Defect found and corrected:** the first desktop pass constrained an expanded
  asset to one half of a two-column grid, compressing verification and posture.
  Expanded cards now span the grid while collapsed assets retain the compact
  portfolio view; the second pass showed no global overflow at any viewport.
- **Accessibility and deterministic coverage:** the component passes axe with
  both operator-disabled and completed-verification states. Eight frontend tests
  cover summary, filtering, partial-summary degradation, registration,
  asset-bound execution, history/triage/export, read-only access and verification.
  Backend summary fixtures prove organization isolation and bounded partial
  reporting. No Internet or non-synthetic target was used.

## Active asset deletion review — 2026-09-08

- **Fixture and boundary:** a fresh trusted-local instance used one synthetic
  `.test` asset and an ephemeral data directory. All Active execution and
  remote-verification gates remained disabled; no capability, target or
  external provider was contacted.
- **Flow exercised:** expand asset → request the owner-scoped preflight → review
  the target-free deletion manifest → acknowledge the irreversible action →
  delete → return to the explicit empty portfolio. The API then returned no
  assets and the retained product audit contained only the deletion receipt and
  closed action/result metadata.
- **Responsive evidence:** at 320, 768 and 1440 CSS pixels the document measured
  `305/305`, `753/753` and `1425/1425` client/scroll width. The deletion panel
  remained within its card at `209/209`, `641/641` and `1294/1294` pixels. Its
  buttons measured at least 44 px and the DOM contained no exact target.
- **Defects found and corrected:** long disposition pills and the destructive
  button initially widened the mobile panel; a pre-existing responsible-account
  button then widened the expanded card. Active-scoped wrapping and bounded
  mobile controls removed both overflows without globally hiding content. A CSS
  regression test protects these containment rules.
- **Accessibility, persistence and cleanup:** ready and blocked preflight states
  pass axe, and deterministic component tests cover confirmation and retryable
  failure. The browser emitted only the development server's missing
  `favicon.ico` request; no application error was observed. After deletion,
  storage contained zero matches for the synthetic target/reference canaries;
  temporary screenshots and runtime data were not retained.

## Active evidence bundle review — 2026-09-08

- **Fixture and boundary:** a fresh trusted-local instance contained one
  synthetic `.test` asset and no execution. All Active and verification gates
  were disabled; the browser exercised only localhost. Backend tests and the
  offline validator ran with `--network none`; no target or provider was
  contacted.
- **Flow exercised:** open specialized audits → expand the asset → review the
  export redaction boundary → select 30/90/365 days or all retained history →
  download the TAR → validate it without extraction. Two downloads and a third
  after backend restart were byte-identical (`d9d8cf…8af3d`); the six-entry
  manifest validated and a binary canary scan found no target, authorization
  reference or note.
- **Responsive evidence:** at 320, 768 and 1440 CSS pixels the document measured
  `305/305`, `753/753` and `1425/1425` client/scroll width. The expanded card
  measured `241/241`, `673/673` and `1326/1326`; the evidence block measured
  `209/209`, `641/641` and `1294/1294`. Desktop/tablet used a 240 px period
  column and mobile stacked to one 209 px column. The export block did not
  repeat the exact target.
- **Defect found and corrected:** both export links initially measured only
  19 px high. Active-scoped link styling raised Markdown and TAR actions to
  44 px at every viewport; the period select also measured 44 px. A static CSS
  regression and the component's axe pass protect the corrected state.
- **Console and evidence handling:** the only severe browser entry was the
  development server's missing `favicon.ico`; there was no application error.
  Screenshots and the synthetic TAR/runtime directory were used only for this
  review and removed afterwards.

## Active operational audit export review — 2026-09-08

- **Fixture and boundary:** a fresh private-team instance reused one synthetic
  `.test` Active asset. All five execution capabilities, control verification
  and public-advisory egress remained disabled; only localhost UI/API traffic
  occurred. The administrator selected the asset after opening the collapsed
  workspace controls.
- **Flow exercised:** sign in → open product activity → select fixed period and
  owner-scoped asset → review counts/truncation/privacy → expose JSON/CSV
  downloads. An independent authenticated localhost request obtained both
  formats: JSON was 991 bytes, CSV 840 bytes and both contained one bounded
  event. Canary scans found zero target, authorization reference, note, raw
  asset ID, account ID or organization ID occurrences.
- **Responsive evidence:** at 320, 768 and 1440 CSS pixels, the complete page
  stayed within the 320/768/1440 inner viewport (`scrollWidth` 311/753/1425).
  The audit card was 279/673/1345 px with identical client/scroll width. After
  correction, both selects, the preflight button and both download links
  measured 44 px high at every viewport; mobile controls stacked to 248 px and
  links to 224 px.
- **Defects found and corrected:** the first pass measured controls at
  19/19/36 px, so export-scoped 44 px minima and a static CSS regression were
  added. A separate supported-mode check found the product audit hidden from an
  authenticated single administrator despite backend authorization; the App
  gate now exposes it in `self_hosted_single_admin`, with a focused regression.
- **Accessibility, errors and cleanup:** ready and `no_matches` component states
  pass axe; failed preflight and unavailable asset directory have actionable,
  content-free states. The live browser console contained no warning/error.
  Temporary cookies, exports, runtime state and the synthetic asset are removed
  after the review; no screenshot is retained.

## Active paginated portfolio review — 2026-09-08

- **Fixture and boundary:** a fresh trusted-local instance contained 55 exact,
  long synthetic `.test` assets. All five execution gates, control verification
  and public-advisory egress remained disabled. The browser and API used only
  loopback; no capability or external target was contacted.
- **Flow exercised:** load 24 → load 48 → load all 55, then search one exact
  identity and a six-record prefix. All 55 headings were unique. The first
  continuation preserved focus on the enabled load button; the terminal page
  moved focus to its status message because a disabled button cannot retain
  keyboard focus. Filters and loaded records survived successful continuation,
  while deterministic tests preserve the current page on a failed continuation.
- **Responsive evidence:** at 320, 768 and 1440 CSS pixels the page measured
  `305/305`, `753/753` and `1425/1425` client/scroll width. The Active section
  measured 273, 705 and 1,377 px respectively. Long identities wrapped inside
  cards; filters and final page controls stacked on mobile. Every Active input,
  select and button measured 44 px and the browser console was empty.
- **Defects found and corrected:** the first browser pass lost keyboard focus
  after paging. Focus restoration now runs after the committed loading state,
  with a visible status focus target on the final page and regressions for
  success/failure. A second pass found exact targets in access-log query strings;
  the UI now sends a closed, CSRF-protected JSON body to
  `POST /active/assets/search`. The repeated server log contains only that fixed
  path, never the target or cursor.
- **Scale and limits:** a no-network backend fixture with 2,005 records for one
  owner and a second owner completed a 100-record page in 3.16 s and below the
  128 MiB test budget. It covers signed owner/filter-bound cursors, manipulation,
  concurrent insertion, stable recency cutoff and response below 1 MiB. This
  proves bounded response/DOM behavior, not indexed storage performance; the
  follow-up backlog records that limitation. Browser screenshots and the
  synthetic runtime directory were not retained.

## Active large-portfolio UX review — 2026-09-08

- **Fixture and boundary:** a fresh local runtime contained 2,005 synthetic
  `.test` assets with long but valid DNS labels. No Active capability was
  executed and no external target/provider was contacted. Disabled and
  unconfigured states came from real local configuration; degraded and ready
  states used a targetless, local-only health-contract fixture on a dedicated
  Docker network.
- **Scale flow:** the browser loaded 24 records and deterministic component
  fixtures continued 24 → 48 → 72 → 96. At 96 the control became
  `Refine filters to continue`, focus moved to the explanatory status and the
  DOM remained capped. Exact server-side search retrieved record 2,005 outside
  that window. The isolated test completed the scale, focus and axe assertions
  in 1.59 s (3.66 s while the complete frontend suite ran in parallel), below
  its 5 s budget.
- **State matrix:** the UI showed 5 disabled capabilities, then one unavailable,
  one degraded and one ready DNS capability under their respective local
  contracts. The 500-of-2,005 bounded aggregate was labelled `Partial portfolio
  summary`. Stopping the dedicated backend before a continuation produced the
  actionable page error, retained all 24 visible records and returned focus to
  `Load next 24 assets`.
- **Responsive and stability evidence:** 320/768/1440 CSS pixels measured
  `305/305`, `753/753` and `1425/1425` client/scroll width. The Active section
  measured 273/705/1,377 px; toolbar columns stacked to 241 px on mobile and
  cards remained 24 per page. Long identities wrapped without internal
  overflow and every visible input, select and button was at least 44 px. At
  320 px, section/toolbar/card/scroll stayed exactly 273/241/241/305 px before
  and after refresh.
- **Defects found and corrected:** an older slow filter response could replace
  a newer view; generation-bound response handling now discards it. Unlimited
  repeated continuation could eventually render the complete portfolio; one
  view is now capped at 96 while exact/prefix filters remain available. The
  card toggle now says `Close details` when open and exposes `aria-controls`.
  Deterministic regressions cover all three behaviours.
- **Accessibility, console and cleanup:** axe reports no violation on the
  96-card state, page completion/error focus remains visible, and the section
  exposes `aria-busy`. The browser console contained no warning/error. Tabs,
  viewport override, dedicated ports, containers, Docker network and all 2,005
  synthetic records were removed; pre-existing Inspectra containers were not
  changed.

## Active batch registration review — 2026-09-08

- **Fixture and boundary:** a fresh local instance received one bounded JSON
  inventory with three synthetic `.test` domains. All Active execution gates,
  verification and public-advisory egress remained disabled. The real local
  preflight, commit and identical replay returned three ready rows, three stable
  asset IDs and `replayed: true` on the second commit; fixed access-log paths
  contained no target or filename.
- **Review and transaction states:** deterministic component tests exercise
  file selection, five-count dry-run summary, per-row table, digest,
  confirmation, commit/replay, invalid rows, unsupported format and oversize
  rejection. Commit is disabled until every row is ready and the whole-batch
  authorization statement is checked. The browser driver cannot construct a
  file-system `DataTransfer`, so actual upload/commit was exercised through the
  same local API with `curl`; this limitation is explicit and is not presented
  as an interactive browser upload pass.
- **Responsive and accessibility evidence:** after correcting the native file
  input overflow, 320/768/1440 CSS pixels measured client/scroll widths
  `305/305`, `753/753` and `1425/1425`. The expanded batch section measured
  `241/241`, `673/673` and `1326/1326`; the picker stayed within 209 px on
  mobile and every visible form control measured at least 44 px. The dry-run
  component passes axe and the real browser console contained no warning or
  error.
- **Privacy and cleanup:** durable state contained three asset records, one
  372-byte target-free replay receipt and two closed audit events. Checks found
  no preflight token, original filename or raw idempotency key. Browser tabs,
  local services, three assets, receipt, audit events and the temporary runtime
  directory were removed after review; no screenshot was retained.

If a review reveals a visual, accessibility, or flow defect, record it in
`TODO.md` with priority, affected viewport/state, acceptance criteria, and a
link to the redacted review evidence if the team retains it.

## Active recurring-review UX review — 2026-09-08

- **Fixture and boundary:** a fresh local volume held one synthetic `.test`
  domain with an immutable authorization revision and manual verification. The
  scheduler and DNS capability backend gates were enabled only for this local
  instance; `active-tools` was deliberately unavailable and no capability,
  DNS, HTTP, TLS, Nmap or public provider request was executed.
- **Flow exercised:** the organization banner exposed the recurrence opt-in;
  asset detail showed empty state and explicit cadence consent; creation
  produced the bound revision, next eligibility and closed reason; pause and
  resume completed through the real API. A backend restart retained exactly one
  active policy bound to revision 1. Component fixtures additionally cover
  operator-disabled, invalid-contract/error and confirmed deletion states.
- **Defect found and corrected:** after creating a policy, the form initially
  continued to offer its exact capability/port tuple and delegated rejection to
  the backend. The final UI detects the existing tuple, explains how to
  pause/resume/remove it and disables duplicate submission; a deterministic
  regression verifies the target-free request and both confirmations.
- **Responsive/accessibility evidence:** at 320/768/1440 CSS pixels the page
  measured client/scroll `305/305`, `753/753` and `1425/1425`; the recurrence
  region measured 209/641/1,294 px. Every visible recurrence button measured
  44 px, labels and status were exposed semantically, axe found no violations
  in disabled and managed states, and the real browser console had zero errors.
- **Cleanup:** viewport override and browser tab were reset/closed. Only the
  specifically named local frontend/backend containers, three disposable image
  tags, recurrence test volume and synthetic records were removed; pre-existing
  Inspectra containers and repository data were not changed.

## Active weekly-window and backoff review — 2026-09-08

- **Fixture and boundary:** a fresh disposable volume held one synthetic
  `.example.test` asset, immutable authorization and manual control
  verification. Recurrence and the DNS-inventory backend gate were enabled;
  the isolated runner was absent. No capability, target request or public
  advisory request ran, and the final job count remained zero.
- **Flow exercised:** the real local API/UI created a Tuesday 16:00–18:00
  `Europe/Madrid` policy under contract `2026-09-08.2`, showed its local window,
  UTC-backed next instant, authorization end and empty retry state, then paused
  it. A backend restart retained exactly one paused policy. The UI explained
  that pause has no scheduled instant, resumed against the current revision and
  recalculated a next instant inside the same window. The persisted recurrence
  JSON was 1,168 bytes, used the closed schema and did not contain the target;
  backend logs did not contain the synthetic target.
- **Defects found and corrected:** the operations banner still described only
  UTC cadence and now names the weekly IANA-timezone window. A paused card still
  displayed its stale eligibility timestamp and now states that resume
  recalculates the next window. Both have deterministic regressions.
- **Visual/accessibility evidence:** the final in-app browser at a 1,280 CSS-px
  viewport showed the complete recurrence card/form without page or region
  horizontal overflow (`1,265/1,265` and `1,134/1,134` client/scroll widths),
  with all interactive rows 44 px high and zero console warnings/errors. The
  browser viewport API acknowledged 320/768 overrides but repeatedly retained
  `innerWidth=1280`; those sizes are therefore not claimed as new visual passes.
  Existing responsive coverage from `PROD-192` remains valid, while the changed
  states pass 21 directed component tests including axe.
- **Cleanup:** the viewport override was reset and every review tab closed. The
  two named containers, disposable volume/network, both temporary image tags
  and all nine temporary response/build files—including the one-time challenge
  token—were removed and their absence verified. Pre-existing containers,
  volumes, images and repository data were not changed.

## Active action-inbox review — 2026-09-08

- **Fixture and boundary:** a disposable local instance held one synthetic
  `.example.test` asset whose recorded authorization expires within seven days.
  Every Active capability and recurrence gate remained disabled; verification
  was enabled only as visible operator policy and its remote runner was absent.
  No capability or public-provider request was made. The live summary returned
  one target-free `authorization_expiring` action under contract
  `2026-09-09.2`.
- **Flow exercised:** the inbox showed the recorded reason, `Scheduled`
  priority, exact due interval and existing asset label. Selecting `Review
  renewal` wrote only the opaque asset fragment, expanded the owner-scoped
  detail and moved keyboard focus to it. Reload preserved both that deep link
  and the locally selected priority filter. Selecting `High` produced a clear
  filtered-empty state without changing the underlying action.
- **Responsive and accessibility evidence:** at 320 px, client/scroll widths
  were `305/305`, inbox/action widths `241/209` px and its three visible
  controls were 44 px high. At 768 px, client/scroll widths were `753/753`, the
  inbox was 673 px wide and both filters were 44 px high. At 1,280 px,
  client/scroll widths were `1,265/1,265` and the focused detail was 1,134 px
  wide. The mixed component fixture passes axe, stable API/DOM count, keyboard
  focus, partial and deep-link regressions. The browser console capability was
  unavailable in this run, so console cleanliness is not claimed; the visible
  flow exposed no application error.
- **Privacy and limits:** the live summary contained opaque action/asset IDs,
  closed codes, dates and counts only; neither synthetic target nor
  authorization reference appeared in backend logs. The UI explicitly states
  that ordering is not an SLA or vulnerability conclusion. The initial offline
  image-build attempts stopped in dependency-install layers and are not counted
  as product validation; current code was mounted read-only into existing local
  runtime images for the review.
- **Cleanup:** the viewport was reset and the review tab closed. Only containers,
  network, images and the temporary data directory prefixed `inspectra-prod182`
  were removed; the already-running Inspectra stack and repository data were
  not changed.

## Bounded analysis-history review — 2026-09-08

- **Fixture and boundary:** a disposable local backend/frontend used 51
  synthetic retained jobs and no project source. All requests stayed on
  `127.0.0.1`; no Active capability, target, package source or public provider
  was contacted. The first page contained 50 jobs and disclosed an exact total
  of 51.
- **Flow exercised:** the real UI loaded the first page through
  `POST /jobs/search`, stated `Showing 50 of 51`, then appended the signed second
  page without replacing existing rows. The request body, rather than the URL,
  carried the cursor. On success keyboard focus moved to the Jobs table region;
  deterministic component coverage also verifies that a continuation error
  keeps the loaded rows and makes the failure actionable. The project timeline
  uses the equivalent owner/project-scoped POST and has the same append/focus
  regression.
- **Defect found and corrected:** visual measurement found 36 px targets in
  segmented navigation and icon-only controls. Their minimum interactive size
  is now 44 px while retaining the existing visual system; the history controls
  and table remained contained after the correction.
- **Responsive/accessibility evidence:** at 320/768/1440 CSS pixels the page
  measured client/scroll widths `305/305`, `753/753` and `1425/1425`; the main
  history section measured `273/273`, `705/705` and `1377/1377`. All visible
  buttons measured at least 44 px, 51 rows remained available after continuation
  and the browser console contained no warnings or errors.
- **Cleanup:** viewport override and the review tab were reset/closed; the two
  local services were stopped, ports 18091 and 4174 were verified closed, and
  the exact disposable directory `/tmp/inspectra-prod199-visual.dkJz99` was
  removed. No screenshot or synthetic job record was retained.

## Deep project-history selector review — 2026-09-08

- **Fixture and boundary:** a disposable local project held 52 completed
  synthetic archive analyses inside the configured retention window; analysis
  1 was the saved baseline and analysis 52 the latest. Egress and every Active
  capability remained disabled. The browser contacted only the local frontend
  and backend.
- **Flow exercised:** workspace timeline, findings, inventory, public
  intelligence and comparison each loaded 50 recent summaries. Comparison
  resolved the old saved baseline directly and showed 51/52 without returning
  its result payload. Four independent `Load older analyses` actions reached
  52/52, retained their controls and allowed all three snapshot selectors plus
  the baseline selector to choose analysis 1. Loading an old public-intelligence
  view did not trigger OSV, GitHub or CISA requests.
- **Defect found and corrected:** the disabled `All retained analyses loaded`
  label inherited `white-space: nowrap` and produced 11 px of internal overflow
  in comparison at 320 px. The shared history control now wraps, has a bounded
  width and keeps a 44 px minimum target. The first fixture attempt used dates
  outside retention and was discarded after startup correctly reduced 52 jobs
  to 43; it is not counted as product validation.
- **Responsive/accessibility evidence:** final page client/scroll widths were
  `305/305`, `753/753` and `1425/1425` at 320/768/1440. Findings, inventory,
  intelligence and comparison panels each had identical client/scroll widths
  (`237/237` or `271/271` mobile, `669/669` or `703/703` tablet and
  `1341/1341` or `1375/1375` desktop). History buttons measured 44 px and the
  browser console contained no warnings or errors. The deep-baseline component
  fixture also passes axe.
- **Privacy and cleanup:** access logs contained only fixed routes plus opaque
  project/analysis identifiers; no filename, path, cursor, source bytes or
  target appeared in continuation requests. The viewport was reset, the tab
  closed, both services stopped, ports 18092/5173 verified closed and the exact
  `inspectra-prod200-visual.pXXiFn` fixture removed.

## Deep Active execution-history review — 2026-09-08

- **Fixture and boundary:** a disposable local instance held 52 terminal
  executions for one synthetic `.example.test` Active asset, including an old
  saved baseline, plus a second asset with no executions. Verification,
  recurrence, capabilities and public-advisory egress remained off; the browser
  contacted only `127.0.0.1`.
- **Flow exercised:** the detail initially disclosed and rendered 50 of 52
  retained executions. `Load older executions` appended the final two without
  replacing rows; the terminal control became `aria-disabled`, remained
  focusable and announced `All retained executions are loaded`. The old baseline
  remained usable, and the second asset showed an explicit 0/0 empty state.
- **Defects found and corrected:** native `disabled` removed focus when the final
  page loaded; the control now uses an announced disabled state with a guarded
  handler. A newer concurrent insert changed the later-page total; the signed
  cursor now carries an immutable initial cutoff. The posture grid also caused
  16 px of page overflow at 320 px; bounded grid tracks and children removed it.
- **Responsive/accessibility evidence:** at 320/768/1440 CSS pixels the document
  measured client/scroll widths `305/305`, `753/753` and `1425/1425`. The history
  contained 52 rows, controls measured at least 44 px, the narrow table scrolled
  internally instead of the page, final focus was retained and the browser
  console had no warnings or errors. Component tests cover axe, continuation,
  direct baseline, empty/error/loading states and terminal focus.
- **Privacy and cleanup:** access logs used fixed routes plus opaque asset/job
  identifiers; cursor and filters stayed in the POST body. The viewport was
  reset, tab closed, services stopped, ports 18093/5174 verified closed, and the
  exact temporary fixture plus Python cache were removed. No screenshot,
  capability result or synthetic record was retained.

## Active weekly portfolio report review — 2026-09-09

- **Fixture and boundary:** a disposable trusted-local backend contained one
  synthetic `.test` asset expiring within 14 days; a second fresh data root
  exercised the empty portfolio. Every Active capability, verification,
  recurrence and public-advisory egress gate remained disabled. The browser
  contacted only the local frontend and backend.
- **Flow exercised:** prepare 7-day preflight → inspect exact denominators,
  sensitivity and digest → confirm target-bearing export → download JSON bound
  to that digest. Backend shutdown produced a retryable connection state without
  blanking the Active center; the fresh root produced an explicit `no assets`
  snapshot. Component fixtures independently cover 30 days, partial 501/500
  coverage, stale digest, read-only role and both formats without Internet.
- **Defects found and corrected:** the live download originally failed because
  credentialed CORS did not expose `X-Inspectra-Snapshot-SHA256`; the fixed
  response-header allowlist now exposes only that target-free digest header and
  an API regression protects it. The consent checkbox/text wrapped as separate
  flex items at tablet width; a scoped two-column grid keeps them aligned. A
  stopped backend exposed `Failed to fetch`; the UI now gives a closed,
  actionable retry message.
- **Responsive and accessibility evidence:** ready state at 320/768/1440 CSS
  pixels measured document client/scroll widths `305/305`, `753/753` and
  `1425/1425`; panel client/scroll widths were `241/241`, `673/673` and
  `1326/1326`. No descendant overflow was detected and every visible report
  control measured at least 44 px. Empty and connection-error states were also
  exercised at 320 px without overflow. Ready, partial, empty and reader
  fixtures pass axe; the live console contained no warnings or errors before
  the deliberate backend shutdown.
- **Privacy and retention:** the preflight DOM did not contain the exact target;
  the downloaded report contained it only after explicit confirmation. Notes
  and the authorization-reference canaries were absent from both formats in
  backend regressions. The response is not persisted by Inspectra; browser
  downloads are operator-managed sensitive copies. The tab and viewport were
  reset, ports 18094/5175 were closed and the exact disposable runtime directory
  was permanently removed; no capture or synthetic application record is
  retained.

## Global project portfolio review — 2026-09-09

- **Fixture and boundary:** a disposable trusted-local data root contained
  three synthetic projects with critical, high and low local findings, complete
  and partial coverage, and one legacy commit-attributed source. Public-advisory
  egress and all Active capabilities remained disabled. The browser contacted
  only the frontend on `127.0.0.1:5174` and backend on `127.0.0.1:8011`.
- **Flow exercised:** the portfolio rendered three explainably ordered cards,
  separate KEV/CVSS counts, baseline and freshness state, coverage denominators,
  pending actions and the ambiguous Git/CLI-or-CI disclosure. Selecting `High`
  produced exactly the Customer portal result through the body-only closed
  filter. `Open project` restored the project workspace at an opaque deep link.
- **Responsive/accessibility evidence:** desktop showed a two-column card grid
  with the nine controls arranged without collision. At the mobile override the
  browser measured `375/375` document client/scroll width and a 343 px panel;
  filters, metrics, facts and actions collapsed to one column, with no page
  overflow or clipped action. Component axe coverage and keyboard/focus behavior
  are exercised by `ProjectPortfolioPanel.test.tsx`.
- **Scale and failure evidence:** an isolated backend projection of 2.000
  synthetic projects returned its 24-item first page in 0,753 s with 84.328 KiB
  RSS. Deterministic tests cover a signed continuation, a concurrent mutation
  (`409`) that preserves already loaded rows, invalid/tampered cursors, another
  owner, empty/no-match/error states and stale public evidence. This is not an
  enterprise SLA; the 5.000-project guard and unpaged legacy list remain explicit
  follow-up work.
- **Cleanup:** the viewport override was reset, the temporary browser tab and
  both local services were closed, and `/tmp/inspectra-portfolio-visual.khmVHI`
  was moved to the desktop trash. No screenshot or synthetic application record
  was retained in the repository.

## Materialized project portfolio review — 2026-09-10

- **Fixture and boundary:** a disposable trusted-local root contained three
  synthetic projects representing critical, high and incomplete evidence.
  Backend `127.0.0.1:8012` and Vite `127.0.0.1:5176` were the only contacted
  origins; public-advisory egress and Active capabilities remained disabled.
- **Flow exercised:** contract `2026-09-10.2` rendered the explainable priority
  order, exact totals, private-materialization disclosure and actionable cards.
  Entering the `Customer` prefix and applying the closed body filter returned
  exactly one high-priority project while retaining the organization total of
  three. The page exposed no source filename or digest.
- **Responsive/accessibility evidence:** the desktop panel kept nine controls,
  six metrics and two-column cards aligned. At the 375×812 override the measured
  document width was `360/360` client/scroll pixels; filters, metrics, disclosure
  and cards collapsed to one column with a full-width action and no horizontal
  overflow. The DOM exposed labelled regions, controls, status and definition
  lists, and the browser console contained zero warnings/errors. Automated axe
  coverage remains in `ProjectPortfolioPanel.test.tsx`.
- **Scale and failure evidence:** the deterministic 20.000-project/two-owner
  fixture measured 5,379 s for both cold tenant rebuilds, 0,264 s warm p95,
  271.699 bytes incremental Python peak and a 116.727.808-byte SQLite index.
  Tests also cover semantic fact and prefix-topology corruption, restart rebuild,
  time-bound refresh, owner isolation, cursor invalidation and equivalence with
  the authoritative closed-signal projection. These are local regression guards,
  not a production SLA.
- **Cleanup:** the viewport override and browser tab were reset/closed, both
  local services stopped, ports 8012/5176 verified closed, the disposable
  container removed and `/tmp/inspectra-prod241-visual.XytnVF` moved to the
  desktop trash. No screenshot or synthetic application record is retained.

## Cross-project remediation review — 2026-09-09

- **Fixture and boundary:** a disposable trusted-local data root contained three
  synthetic projects, three public OSV-shaped findings for one common npm/CVE
  action and three local configuration findings. Public egress and all Active
  capabilities remained disabled. The browser contacted only the frontend on
  `127.0.0.1:5176` and backend on `127.0.0.1:18095`.
- **Flow exercised:** explainable group order; CVSS versus KEV wording; exact
  installed versions, range/fix/scope and affected-project disclosure; selection
  of two occurrences in one group; explicit action consent; one reviewable risk
  acceptance with a future date; JSON and CSV report controls and response
  digests; and persistence of that decision after a clean backend restart.
- **Defect found and corrected:** the generic form-label grid overrode the
  confirmation control, visually separating its checkbox from the consent text.
  A scoped two-column rule now keeps the 22 px checkbox and text associated at
  desktop and mobile widths. Component axe coverage protects the resulting form.
- **Responsive evidence:** document client/scroll widths were `305/305`,
  `753/753` and `1425/1425` at 320/768/1440 CSS pixels. The remediation panel was
  `703/703` at 768 and `1375/1375` at 1440; cards collapsed from two columns to
  671 px single-column cards. Visible primary controls were at least 44 px high,
  while native checkboxes remained 22 px. No private source filename appeared in
  the DOM.
- **Failure, privacy and cleanup:** deterministic tests cover empty, filtered,
  reader, stale-revision, rollback and legacy-ID states. Backend access logs
  exposed only fixed routes and opaque IDs, never source paths, recommendation
  contents or decision comments. The viewport was reset, tab closed, services
  stopped, ports verified closed and the exact temporary data root moved to the
  desktop trash. Browser blob exports left no file in the user's Downloads
  directory; no screenshot or synthetic record was retained in the repository.

## Organization risk trends review — 2026-09-09

- **Fixture and boundary:** a disposable trusted-local root contained two
  synthetic projects and three comparable retained analyses each, with local and
  OSV-shaped normalized evidence. Public egress and every Active capability were
  disabled. The browser contacted only `127.0.0.1:5177` and `127.0.0.1:18096`.
- **Flow exercised:** developer, security and executive tabs; 90-day/7-day
  period; new/resolved bars; ecosystem and source-type breakdowns; priority
  project navigation; expanded denominators/exclusions; explicit project-name
  consent and a real executive CSV response. The response digest was
  `56ac4c31b9b6ff280c968521d1361fd85f042a877a8bb885b5e61b09d064fcf8`.
- **Defects found and corrected:** axe found `aria-label` on a generic graph
  container; it now has an explicit image role. TypeScript rejected ES2021-only
  `replaceAll`; compatible regular-expression replacements preserve the current
  build target. At 320 px, the header action squeezed its introduction and was
  stacked. The post-export SHA-256 caused a 557 px panel overflow and now wraps
  within 239 px.
- **Responsive/accessibility evidence:** after correction, document widths were
  `305/305`, `753/753` and `1425/1425`; trend-panel widths were `271/271`,
  `703/703` and `1375/1375`. All visible panel buttons measured at least 44 px.
  Component axe and all three profile interactions passed; metrics explicitly
  disclose excluded transitions and samples.
- **Cleanup:** the viewport was reset, browser tab closed, both services stopped,
  ports 18096/5177 verified closed and the exact temporary root was moved to the
  desktop trash. Browser blob download left no matching file in Downloads. No
  network provider, project code or package manager was executed.

## Vulnerability intelligence and finding triage accessibility review — 2026-09-09

- **Fixture and boundary:** a disposable local instance imported a ZIP made
  only from the tracked safe sanitizer fixture (`package.json`,
  `requirements.txt` and `docker-compose.yml`), SHA-256
  `4aa1c25bbc85…`. Its passive analysis produced two informational normalized
  findings. Public-advisory egress, NVD and every Active network capability
  remained disabled; no project code, script, installer or package manager ran.
- **Flow exercised:** open the synthetic project; read the explicit
  `Not checked`/operator-egress-disabled intelligence state; confirm OSV, GitHub
  and CISA KEV actions are unavailable; filter two project findings down to one;
  clear filters; expand a finding; and record a synthetic `Risk accepted`
  decision only after a future review date and explicit acknowledgement. The
  retained analyzer evidence remained unchanged.
- **Defects found and corrected:** axe found an invalid `h2`→`h4` jump in the
  lifecycle detail, now `h3`. In a real browser, clearing filters removed the
  clicked button after the animation-frame focus call and left focus on `body`;
  focus restoration now runs after React commits the cleared filter state.
  At 320 px, intrinsic grid tracks in finding detail/remediation and an
  unbreakable ecosystem sequence caused page overflow; bounded tracks,
  breakable copy and wrapping actions remove it.
- **Responsive and accessibility evidence:** filters use semantic fieldsets and
  hidden legends; result counts are polite live status text separate from the
  interactive clear action; result collections and detail workflow are named.
  The restored search input showed a 3 px amber focus outline with 2 px offset.
  Final document client/scroll widths were `305/305`, `753/753` and
  `1425/1425` at 320/768/1440 CSS px; intelligence, findings and lifecycle
  panels did not escape their containers. The browser console had no warning or
  error. Deterministic ready/degraded/error intelligence fixtures and the
  integrated findings view pass axe without Internet.
- **Privacy and cleanup:** only the local frontend/backend/runner were used; no
  provider action could be activated. No screenshot was retained. The viewport
  override was reset, tab closed, services stopped, ports 15180/18100/8081
  verified closed, ephemeral containers absent and
  `/tmp/inspectra-prod114-visual.oXEUE2` removed, including its synthetic
  decision and source archive.

## Durable project listing review — 2026-09-09

- **Fixture and boundary:** a disposable trusted-local data root contained 51
  synthetic archive-backed projects and no retained analyses. Public-advisory
  egress and every Active capability remained disabled; the browser contacted
  only the frontend on `localhost:15173` and backend on `localhost:18080`.
- **Flow exercised:** the projects table initially disclosed `Showing 50 of 51
  projects`, rendered exactly 50 workspace actions and offered one `Load more
  projects` control. Activating it preserved the existing rows, reached 51/51
  and removed the terminal continuation control. A fresh deep link opened
  project `00000000000000000000000000000001`, which was outside the first page,
  while the table remained at 50/51. A malformed private-looking project
  fragment was cleared locally and generated no project-detail request.
- **Responsive/accessibility evidence:** at 320 CSS px the document measured
  `305/305` body scroll/client width inside a 320 px viewport, so it did not
  overflow horizontally. The deliberately wide projects table measured
  `237/672` client/scroll width and stayed inside its named, keyboard-focusable
  horizontal scroll region. Desktop and mobile captures showed readable rows,
  source references without filenames and coherent actions; all three browser
  paths completed with zero console errors.
- **Defect found and corrected:** review of the signed continuation contract
  found that a non-canonical Base64URL alias could decode to the same signed
  cursor bytes. Decoding now requires canonical round-trip encoding, and a
  regression mutates only unused pad bits to prove the alias is rejected with
  the closed invalid-cursor response.
- **Privacy and cleanup:** the backend access log contained fixed listing routes
  and opaque project identifiers only. The viewport was reset, all temporary
  tabs closed, services stopped, ports 15173/18080 verified closed and the exact
  fixture plus captures moved to the desktop trash. No screenshot or synthetic
  application record was retained in the repository.

## Stable project responsibility review — 2026-09-09

- **Fixture and boundary:** a disposable trusted-local instance imported the
  tracked synthetic `demo-archive-app-config.zip` fixture and created one
  project. Public-advisory egress remained disabled; the analysis runner was
  intentionally absent, so the retained job degraded to its controlled failed
  state. No project code, script, installer or package manager was executed.
- **Flow exercised:** a direct project link resolved the authoritative project,
  the workspace showed `Unassigned`, selecting `local-admin` enabled the
  optimistic update, and the resulting accountable member stayed visible after
  a backend restart. Copy explicitly separated this role from finding
  assignees. Backend/unit fixtures separately cover team-member departure and
  the `unassigned_attention` reader view.
- **Defect found and corrected:** the first real browser mutation failed before
  reaching the route because the closed CORS method set omitted `PUT`. The
  supported/default/Compose contract now adds only `PUT`; arbitrary methods
  remain impossible, and the preflight regression asserts `GET, POST, PUT,
  DELETE`. The same browser flow then completed successfully.
- **Responsive/accessibility evidence:** component tests cover mutation,
  optimistic timestamp, reader view, member-departure attention and axe. At
  1440 px the responsibility/controls align in one bounded card; at 320 px they
  stack, the select/button remain usable and copy wraps without clipping.
  Semantic region, heading, label and status text were present in browser DOM.
- **Privacy and cleanup:** the member ID was not placed in access URLs or audit
  metadata, and the private index stores only its keyed digest. No screenshot
  was retained. The viewport override was reset, tab closed, frontend stopped,
  disposable container removed, ports 8000/5173 verified closed and the exact
  temporary data root moved to the desktop trash.

## Passive project action inbox review — 2026-09-10

- **Fixture and boundary:** a disposable trusted-local instance imported only
  the tracked synthetic `demo-archive-app-config.zip`; its bounded passive
  runner completed locally. Public-advisory egress stayed disabled and no
  external project, package manager, installer or project code ran.
- **Flow exercised:** the owner-scoped portfolio produced two closed reminders
  (`pending_triage` and `no_baseline`); the UI opened the exact project via its
  opaque deep link, marked one reminder read, refreshed to 1/2 unread, and an
  administrator rebuild restored 2/2 unread as documented. The inbox remained
  visibly separate from Active operations.
- **Responsive/accessibility evidence:** at 1280×720 the two actions used a
  readable horizontal card/action layout. At 390×844 controls and cards stacked
  without clipping; body/document scroll width was 375 CSS px inside a 390 px
  viewport. Buttons remained full-width and the adjacent portfolio stayed
  bounded. The live count, named region, checkbox, headings and action labels
  were present; axe passed in component tests and the real browser console had
  zero warnings/errors.
- **Privacy and cleanup:** the 857-byte store was mode `0600`; searching it for
  the synthetic project name, archive name and source SHA-256 returned no
  match. It retained only closed fields and opaque/digested identities. The
  viewport override was reset, tab closed, frontend stopped, exact backend and
  runner containers removed, test network removed, and the validated temporary
  root `/tmp/inspectra-prod107-JiDBsx` emptied and removed. No provider was
  contacted and no synthetic application data remains.
