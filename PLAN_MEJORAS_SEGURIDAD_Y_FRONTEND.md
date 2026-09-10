# Plan de mejoras de seguridad y frontend

Fecha del análisis: 2026-09-04. Este documento es un diagnóstico de referencia, no una aprobación para exponer el servicio fuera de un entorno controlado. El estado de ejecución posterior y su evidencia se mantienen en `TODO.md`.

## Resumen ejecutivo

Inspectra es un MVP local-first compuesto por un backend FastAPI, un ejecutor Python aislado en contenedor, almacenamiento local de ficheros y resultados JSON, y un frontend React/Vite. El código ya contiene controles valiosos: límites de carga y de archivos de archivo, validación de firmas, filtros de propietario cuando hay autenticación, CSRF para mutaciones autenticadas, redacción en informes, límites de red para auditorías web y contenedores sin privilegios, de solo lectura y con capacidades eliminadas. Los informes HTML escapan valores y el ejecutor evita extraer archivos de los archivos subidos.

Las cinco prioridades son:

1. Hacer seguro por defecto el `docker-compose.yml`: hoy publica frontend y backend en todas las interfaces, mientras el modo predeterminado es `trusted_local_no_auth`.
2. Endurecer la sesión para despliegues HTTPS: la cookie de administración se emite con `Secure=False` y no hay una configuración ni una comprobación de arranque que lo impida fuera de localhost.
3. Actualizar el árbol npm bloqueado: `npm audit --package-lock-only` informa 5 vulnerabilidades (1 crítica y 4 altas), incluida Vitest 3.2.4 y Vite 6.4.2.
4. Establecer una cadena reproducible de dependencias, imágenes, pruebas y escaneo: Python se resuelve desde rangos sin lockfile, las imágenes base no están fijadas por digest y no hay automatización CI versionada.
5. Reordenar el frontend como flujo de trabajo, y no como una única página densa: mejorar jerarquía, navegación a resultados, accesibilidad semántica y estados de carga/error antes de plantear cambios estéticos grandes.

Alcance revisado: estructura del repositorio, README y alcance de seguridad, Compose y Dockerfiles, dependencias y lockfile npm, backend/API/autenticación/almacenamiento, ejecutores, redacción y exportaciones, frontend y CSS, y pruebas presentes. Se validó sintácticamente `docker compose config`. No se construyeron imágenes ni se ejecutaron pruebas: el checkout no contiene dependencias instaladas (`pytest` y `vitest` no están disponibles en el host). Tampoco se revisaron secretos o configuración reales del servidor, un proxy inverso, una imagen ya construida, logs de producción ni un despliegue activo.

Límites deliberados: no se propone convertir el MVP en SaaS, multitenancy, un escáner público ni una reescritura de React o del runner. Las tareas se limitan a cerrar el despliegue privado/local, su cadena de entrega y los recorridos existentes de carga, auditoría, resultados y exportación.

## Hallazgos confirmados

### C-01 — El Compose por defecto expone una API sin autenticación

- **Severidad:** alta; crítica si el host es accesible por una red no confiable.
- **Evidencia:** `docker-compose.yml:56-57` y `:160-161` publican `8000:8000` y `5173:5173` sin IP de loopback. Docker Compose resuelve esa forma como publicación de ingreso en todas las interfaces. A la vez, `backend/app/config.py` fija `trusted_local_no_auth` como valor predeterminado y `backend/app/main.py:221-243` deja pasar todas las rutas sensibles en ese modo.
- **Impacto:** un tercero con conectividad al host puede leer/listar/borrar datos y lanzar las operaciones disponibles, incluidas cargas y auditorías de destino. CORS no protege llamadas directas a la API.
- **Áreas afectadas:** `docker-compose.yml`, `backend/app/config.py`, `backend/app/main.py`, documentación de despliegue.
- **Solución recomendada:** perfil local que enlace explícitamente a `127.0.0.1`; perfil privado separado con proxy TLS, autenticación obligatoria y backend no publicado directamente. Añadir una guardia de arranque que rechace el modo sin autenticación cuando se seleccione un perfil expuesto.

### C-02 — La cookie de sesión no puede marcarse como `Secure`

- **Severidad:** alta para cualquier despliegue HTTPS/autenticado fuera de localhost.
- **Evidencia:** `backend/app/auth.py:258-265` define `secure=False` por defecto; `backend/app/main.py:156` invoca esa función sin argumento y `:874-881` emite el valor resultante. No existe un ajuste de entorno ni una comprobación de proxy/TLS en `Settings`.
- **Impacto:** si se usa `self_hosted_single_admin` con HTTP, o con una terminación TLS mal integrada, la cookie puede viajar sin el atributo `Secure`; se debilita la confidencialidad de la sesión. `HttpOnly`, `SameSite=Lax`, CSRF y hash PBKDF2 sí están presentes, pero no sustituyen `Secure`.
- **Áreas afectadas:** `backend/app/auth.py`, `backend/app/config.py`, `backend/app/main.py`, proxy inverso y guía de operación.
- **Solución recomendada:** hacer explícita la política de cookie segura; exigir `Secure` en el perfil privado y fallar al arrancar ante una combinación insegura. Diseñar de forma acotada la confianza en cabeceras del proxy, sin aceptar `X-Forwarded-*` de cualquier cliente.

### C-03 — El lockfile npm resuelto contiene cinco avisos de seguridad

- **Severidad:** alta en la estación de desarrollo/CI; crítica condicionada para Vitest si se expone su UI/API en los escenarios descritos por el aviso.
- **Evidencia:** `frontend/package-lock.json` resuelve `vitest` 3.2.4, `vite` 6.4.2, `postcss` 8.5.15, `browserslist` 4.28.2 y `nanoid` 3.3.12. `npm audit --package-lock-only` devolvió 1 crítica y 4 altas, con corrección disponible.
- **Impacto:** el contenedor final del frontend no incluye dependencias de desarrollo, por lo que no se debe presentar como vulnerabilidad confirmada del servidor estático final. Sí afecta a desarrollo, builds y CI; Vite está configurado con `server.host = "0.0.0.0"` en `frontend/vite.config.ts`.
- **Áreas afectadas:** `frontend/package.json`, `frontend/package-lock.json`, `frontend/vite.config.ts`.
- **Solución recomendada:** actualizar el conjunto Vite/Vitest y las transitivas bloqueadas a versiones corregidas; verificar build y pruebas antes de aceptar el lockfile nuevo. No usar UI/API de Vitest ni el servidor Vite en una red no confiable.

### C-04 — La entrega Python y de imágenes no es reproducible ni auditable por versión exacta

- **Severidad:** media-alta.
- **Evidencia:** los cuatro `requirements*.txt` usan rangos amplios y no hay lockfile Python. Los Dockerfiles usan etiquetas mutables `python:3.12-slim` y `node:22-alpine`, y ejecutan `pip install` durante cada build. No hay configuración CI, Dependabot/Renovate ni script de auditoría versionados.
- **Impacto:** dos builds pueden resolver paquetes e imágenes distintas; no se puede atribuir un CVE a la imagen que se desplegará ni reproducir de forma fiable una corrección. El análisis de vulnerabilidades Python queda incompleto por esta razón.
- **Áreas afectadas:** `backend/requirements*.txt`, `tools/requirements.txt`, `docker/active-tools/requirements.txt`, los tres Dockerfiles Python, `frontend/Dockerfile` y raíz del repositorio.
- **Solución recomendada:** generar locks con hashes para cada artefacto Python, fijar imágenes por digest y añadir generación de SBOM/escaneo de dependencias e imágenes en CI.

### C-05 — Los datos sensibles persisten localmente sin política operativa de retención ni trazabilidad de ejecución

- **Severidad:** media.
- **Evidencia:** las cargas y resultados se guardan bajo `data/` mediante `backend/app/storage.py` y se montan en el host (`docker-compose.yml:54-55`). La eliminación manual de fichero y de trabajos completados/fallidos existe, pero no se encontró configuración de retención, tarea programada ni limpieza de huérfanos. Tampoco hay logger de aplicación; `tools/active_runner/audit_log.py` solamente devuelve un diccionario y no se invoca en tiempo de ejecución.
- **Impacto:** archivos originales —que el propio frontend advierte que no se sanitizan—, resultados y estado de autenticación SQLite opcional pueden quedar más tiempo del esperado. En un incidente no habrá una pista de auditoría estructurada suficiente, y un log futuro mal diseñado podría filtrar valores redaccionados hoy.
- **Áreas afectadas:** `data/`, `backend/app/storage.py`, `backend/app/auth_state_sqlite.py`, servicios de backend y Compose.
- **Solución recomendada:** definir clases de retención y permisos de volumen; implementar una limpieza idempotente y un registro estructurado con lista de campos permitidos, sin cuerpos, cookies, tokens, contenido de archivos ni JSON de informes.

### C-06 — Los trabajos en segundo plano no tienen recuperación persistente

- **Severidad:** media (fiabilidad y claridad de datos).
- **Evidencia:** las rutas de auditoría añaden trabajo a `FastAPI.BackgroundTasks` en `backend/app/main.py:950-1379`; los trabajos se guardan en JSON, pero no hay cola, lease, cancelación ni reconciliación al arrancar.
- **Impacto:** un reinicio durante una auditoría puede dejar estados `queued` o `running` que no se completan; el frontend sigue haciendo polling cada 3 segundos y puede transmitir un estado engañoso.
- **Áreas afectadas:** `backend/app/main.py`, `backend/app/services.py`, `backend/app/storage.py`, `frontend/src/App.tsx`.
- **Solución recomendada:** sin introducir una plataforma de colas todavía, añadir al arranque una reconciliación conservadora a estado fallido/reintentable con código controlado, timestamp y una acción de reintento explícita donde sea seguro.

### C-07 — La accesibilidad y la navegación del frontend dependen de estado visual y de una vista monolítica

- **Severidad:** media (accesibilidad y experiencia; no es un fallo de autorización).
- **Evidencia:** `frontend/src/App.tsx` tiene 1.786 líneas y concentra carga, filtros, formularios, polling, listado y detalle. Varios campos dependen de `placeholder` sin `label` asociado (por ejemplo `:878-885`, `:916-923`, `:942-956`, `:1136-1142`, `:1217-1223`); los controles segmentados sólo cambian clase CSS, sin `aria-pressed` ni patrón de tabs (`:846-856`, `:1124-1134`, `:1205-1236`); el detalle se conserva sólo en `selectedJob` en memoria. `frontend/src/styles.css` no define `:focus-visible`. Las tablas se desplazan horizontalmente en móvil en lugar de tener una presentación alternativa.
- **Impacto:** lectores de pantalla no reciben el nombre o estado de varios controles, el foco de teclado no es visible de forma garantizada, al recargar se pierde el resultado seleccionado y el usuario recorre una página muy larga antes de llegar a la acción o a su resultado.
- **Áreas afectadas:** `frontend/src/App.tsx`, `frontend/src/styles.css`, `frontend/index.html`, componentes de informes.
- **Solución recomendada:** extraer secciones de flujo, usar URL para seleccionar trabajo, aplicar etiquetas y estados ARIA, foco y regiones vivas; conservar la API y componentes de informe existentes.

### C-08 — La interfaz mezcla idiomas y estados, y el feedback accionable queda disperso

- **Severidad:** baja-media.
- **Evidencia:** `frontend/index.html` declara `lang="en"`, mientras `App.tsx` alterna textos ingleses y españoles. Hay errores locales, globales y avisos con `role="status"`, pero no una estrategia homogénea de `aria-live`, reintento, foco ni confirmación posterior a una acción. En móvil, las nueve métricas se apilan y las listas de archivos/trabajos siguen siendo tablas anchas (`styles.css:132-146`, `:795-844`).
- **Impacto:** mayor carga cognitiva, mensajes que pasan inadvertidos y uso incómodo en pantallas pequeñas; la calidad percibida no corresponde al nivel de controles del backend.
- **Áreas afectadas:** `frontend/index.html`, `frontend/src/App.tsx`, `frontend/src/styles.css`.
- **Solución recomendada:** escoger un idioma principal con glosario, normalizar componentes de feedback y priorizar contenido/acciones por contexto y viewport.

## Riesgos probables que requieren validación

Estos puntos tienen indicios en código, pero no se declaran como vulnerabilidades explotables hasta probarlos en un entorno aislado.

| Riesgo | Indicio | Cómo validarlo de forma acotada | Acción si se confirma |
| --- | --- | --- | --- |
| DNS rebinding en las auditorías web (SSRF) | `tools/runner/main.py:1095-1139` valida DNS y luego crea `HTTPConnection/HTTPSConnection` con el hostname, que puede resolver de nuevo. El runner también está en la red interna y de salida. | Prueba aislada con un dominio controlado que devuelva primero una IP pública de prueba y después una IP privada de laboratorio; confirmar en captura de red si la conexión posterior sale hacia la segunda IP. No usar metadatos cloud ni redes reales. | Conectar a la IP ya validada preservando `Host`/SNI, revalidar cada salto y limitar la salida de red del runner. |
| CORS permisivo por error de configuración | `INSPECTRA_CORS_ORIGINS` acepta texto arbitrario y el middleware usa `allow_credentials=True`, `allow_headers=["*"]`. El Compose actual no usa comodín. | Ejecutar pruebas de integración con `Origin` permitido, no permitido y `*`, con sesión activa, e inspeccionar todas las cabeceras CORS y preflight. | Rechazar `*`, normalizar orígenes y cubrir la política con pruebas de arranque. |
| Rate limit detrás de proxy | El login usa `request.client.host` (`backend/app/main.py:303-307`) y se ignoran cabeceras forwarded; el README prevé proxy inverso. | Desplegar un proxy de laboratorio y verificar qué IP llega a Uvicorn; probar bloqueo de dos clientes distintos. | Declarar proxies confiables de forma explícita o aplicar rate limit en el proxy, nunca confiar en cabeceras de cualquier origen. |
| Redacción incompleta en variantes reales | Hay redacción específica y muchas pruebas sintéticas, pero los archivos originales, copias, backups y valores fuera de los patrones conocidos no se pueden evaluar estáticamente. | Ejecutar un corpus sintético versionado con secretos de distintos formatos, revisar API, UI, cuatro exportaciones, SBOM y logs; buscar los marcadores después de cada ejecución. | Corregir la capa que filtra antes de persistir/publicar y añadir el caso como regresión. |
| CVE Python/de SO no detectados | Las versiones efectivas dependen de builds futuros y de tags de imagen mutables. | Construir en CI con lockfile, generar SBOM e inventario de paquetes de SO y ejecutar un escáner contra el digest producido. | Actualizar sólo los paquetes/imagen afectados y conservar el informe de escaneo asociado al release. |

## Mejoras preventivas recomendadas

- Añadir cabeceras de seguridad en el proxy o en el servidor estático: CSP ajustada a la SPA, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, protección de framing y una política de permisos mínima. Validar la CSP en vez de copiar una genérica.
- Usar perfiles de Compose para local, privado y desarrollo, con ejemplos de variables sin secretos. No almacenar el hash de administrador en el repositorio ni en una imagen.
- Añadir `.dockerignore` para backend y tools; excluir `.env*`, datos, caches, resultados y material de claves de todo contexto de build. Mantenerlo como defensa en profundidad aunque los `COPY` actuales sean selectivos.
- Limitar concurrencia y tamaño total por petición en el borde para cargas y auditorías, después de cerrar la exposición por defecto. Los límites por archivo existentes no sustituyen un límite de solicitudes.
- Mantener HTML/XML/PDF y React con sus escapados actuales; incluir pruebas de regresión de XSS y de inyección de contenido de informe al tocar exportaciones.

## Vulnerabilidades conocidas y fuentes públicas

El resultado de `npm audit --package-lock-only` en este checkout fue: 5 vulnerabilidades, 1 crítica y 4 altas. Las versiones de esta tabla son las **resueltas** por `frontend/package-lock.json`, no sólo los rangos de `package.json`. Las cinco son dependencias de desarrollo/build; no se incluyeron pruebas de que lleguen al contenedor estático final. La prioridad combina severidad publicada y exposición real del repositorio.

| Dependencia / tecnología | Versión detectada | CVE o GHSA | Fuente enlazada | Impacto potencial y relevancia | Prioridad | Mitigación |
| --- | --- | --- | --- | --- | --- | --- |
| `vitest` | 3.2.4 | CVE-2026-47429 / [GHSA-5xrq-8626-4rwp](https://github.com/advisories/GHSA-5xrq-8626-4rwp) | [GitHub Advisory](https://github.com/advisories/GHSA-5xrq-8626-4rwp) | Lectura y ejecución arbitraria si se expone la UI/API; el aviso afecta `<3.2.6`. El script actual no arranca UI, pero la versión es vulnerable. | P1 | Subir al menos a 3.2.6, actualizar lockfile, no exponer UI/API y ejecutar pruebas. |
| `vite` | 6.4.2 | CVE-2026-53571 / [GHSA-fx2h-pf6j-xcff](https://github.com/advisories/GHSA-fx2h-pf6j-xcff) | [GitHub Advisory](https://github.com/advisories/GHSA-fx2h-pf6j-xcff) | Bypass de `server.fs.deny` en Windows/NTFS cuando el dev server se expone; el proyecto fija `host: 0.0.0.0` y el aviso afecta `<=6.4.2`. | P1 | Subir a 6.4.3 o superior compatible; limitar el host del servidor dev a loopback salvo necesidad explícita. |
| `postcss` (transitiva) | 8.5.15 | CVE-2026-73646 / [GHSA-r28c-9q8g-f849](https://github.com/advisories/GHSA-r28c-9q8g-f849) | [GitHub Advisory](https://github.com/advisories/GHSA-r28c-9q8g-f849) | Lectura de `.map` mediante `sourceMappingURL` controlado; afecta `<=8.5.17`. No se observó procesamiento de CSS subido por usuarios, por lo que la alcanzabilidad actual parece baja. | P1 | Resolver a 8.5.18 o superior a través de la actualización del árbol Vite; no procesar CSS no confiable antes de corregir. |
| `browserslist` (transitiva) | 4.28.2 | CVE-2026-73088 / [GHSA-73wf-gq98-2v4g](https://github.com/advisories/GHSA-73wf-gq98-2v4g); CVE-2026-73089 / [GHSA-c83g-rgw3-j3cx](https://github.com/browserslist/browserslist/security/advisories/GHSA-c83g-rgw3-j3cx) | [GitHub Advisory: crash/prototype write](https://github.com/advisories/GHSA-73wf-gq98-2v4g), [GitHub Advisory: memoria](https://github.com/browserslist/browserslist/security/advisories/GHSA-c83g-rgw3-j3cx) | Crash/prototype write con estadísticas no confiables y crecimiento de memoria por consultas variables; ambas afectan `<=4.28.6`. Relevancia principalmente de build/CI. | P1 | Actualizar a 4.28.7 o superior mediante el árbol transitivo; prohibir estadísticas externas no revisadas en CI. |
| `nanoid` (transitiva) | 3.3.12 | CVE-2026-67214 / [GHSA-28wg-ghj8-5hjv](https://github.com/advisories/GHSA-28wg-ghj8-5hjv); CVE-2026-67213 / [GHSA-2v37-7h3g-55p8](https://github.com/advisories/GHSA-2v37-7h3g-55p8) | [GitHub Advisory: tamaño negativo](https://github.com/advisories/GHSA-28wg-ghj8-5hjv), [GitHub Advisory: tamaño cero](https://github.com/advisories/GHSA-2v37-7h3g-55p8) | Bucle de CPU con tamaños no validados; afecta `<3.3.18` en la rama 3.x. No hay uso directo de generadores no seguros en el código del proyecto. | P1 | Resolver a 3.3.18 o superior como parte de la actualización auditada; revisar el árbol para confirmar que no se llama a APIs no seguras con entrada externa. |
| Paquetes Python y paquetes de SO | Rangos, no versión efectiva; imágenes `python:3.12-slim` y `node:22-alpine` sin digest | No determinable honestamente sin un build/SBOM | [Docker: pin de imágenes base](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions) | Un nuevo build puede traer versiones distintas y CVEs distintos. No equivale a “sin vulnerabilidades”. | P1 | Bloquear dependencias, fijar digest, generar SBOM y escanear la imagen producida en cada release. |

## Plan de tareas priorizado

### P0 — críticas: resolver antes de despliegues relevantes

#### P0-1 — Separar el perfil local del perfil privado y cerrar la exposición por defecto

- **Problema que resuelve:** C-01; la configuración cómoda para local publica una API sin autenticación en todas las interfaces.
- **Área o archivos afectados:** `docker-compose.yml`, nuevos overrides/perfiles de Compose, `backend/app/config.py`, `README.md` y guía de despliegue.
- **Criterio de aceptación verificable:** `docker compose config` del perfil local muestra sólo `127.0.0.1:8000` y `127.0.0.1:5173` (o no publica backend); el perfil privado exige autenticación y proxy TLS; una prueba de arranque rechaza `trusted_local_no_auth` si se solicita el perfil expuesto.
- **Riesgo de no realizarla:** exposición de archivos, trabajos y superficie de auditoría a la red del host.
- **Estimación relativa:** M.
- **Dependencias o bloqueos:** decidir el modo de acceso privado (VPN o proxy inverso) y los nombres de host reales.

#### P0-2 — Aplicar una política de cookie y proxy segura para `self_hosted_single_admin`

- **Problema que resuelve:** C-02; el atributo `Secure` no se puede imponer.
- **Área o archivos afectados:** `backend/app/auth.py`, `backend/app/config.py`, `backend/app/main.py`, pruebas de autenticación y configuración del proxy.
- **Criterio de aceptación verificable:** en perfil privado el `Set-Cookie` incluye `HttpOnly`, `Secure`, `SameSite` y vida esperada; el arranque falla ante configuración privada insegura; las pruebas cubren login, logout, expiración, CSRF y acceso detrás de un proxy confiable simulado.
- **Riesgo de no realizarla:** robo o reutilización de sesión en un despliegue mal terminado en TLS.
- **Estimación relativa:** M.
- **Dependencias o bloqueos:** P0-1 y la decisión explícita de cómo se identifica un proxy confiable.

### P1 — alto impacto: siguiente iteración

#### P1-1 — Corregir el árbol npm vulnerable y endurecer el servidor de desarrollo

- **Problema que resuelve:** C-03 y las cinco entradas de la tabla de vulnerabilidades.
- **Área o archivos afectados:** `frontend/package.json`, `frontend/package-lock.json`, `frontend/vite.config.ts`, documentación de desarrollo.
- **Criterio de aceptación verificable:** versiones corregidas en lockfile; `npm ci`, `npm audit --omit=dev` y `npm audit` sin los cinco avisos identificados; `npm run build` y `npm run test:run` pasan; Vite sólo usa `0.0.0.0` con una opción explícita y documentada.
- **Riesgo de no realizarla:** compromiso o filtración en desarrollo/CI, especialmente al exponer Vite o Vitest.
- **Estimación relativa:** S.
- **Dependencias o bloqueos:** disponer de un entorno Node reproducible; revisar compatibilidad de Vite/Vitest tras el bump.

#### P1-2 — Bloquear dependencias e imágenes y añadir una puerta de entrega de seguridad

- **Problema que resuelve:** C-04 y la imposibilidad de evaluar CVEs Python/SO por versión efectiva.
- **Área o archivos afectados:** requirements y sus locks, Dockerfiles, configuración CI nueva, SBOMs de release.
- **Criterio de aceptación verificable:** cada imagen se construye desde digests y locks con hashes; CI publica SBOM y resultados de `pip-audit`/equivalente, auditoría npm y escáner de imagen; una vulnerabilidad alta/crítica nueva bloquea el merge o exige una excepción fechada y revisada.
- **Riesgo de no realizarla:** builds irreproducibles y parches de seguridad no verificables.
- **Estimación relativa:** M.
- **Dependencias o bloqueos:** P1-1 para el frontend y elección de herramienta de lock/escaneo compatible con el hosting CI.

#### P1-3 — Eliminar el TOCTOU DNS en el flujo de auditoría web

- **Problema que resuelve:** riesgo probable de DNS rebinding/SSRF.
- **Área o archivos afectados:** `tools/runner/main.py`, pruebas del runner, Compose/red de salida.
- **Criterio de aceptación verificable:** una prueba de rebinding controlada no consigue una conexión privada después de una resolución pública; cada redirección y recurso auxiliar se conecta sólo a una IP previamente validada, conservando hostname/SNI y límites actuales.
- **Riesgo de no realizarla:** acceso desde el contenedor de egress a servicios internos si un hostname cambia de resolución.
- **Estimación relativa:** M.
- **Dependencias o bloqueos:** laboratorio DNS/HTTP aislado; no habilitar auditorías web públicas hasta concluir la prueba.

#### P1-4 — Definir retención, permisos de volumen y logging seguro

- **Problema que resuelve:** C-05; acumulación de originales/resultados y ausencia de trazabilidad operativa.
- **Área o archivos afectados:** `backend/app/storage.py`, servicios, `auth_state_sqlite.py`, Compose, documentación operativa.
- **Criterio de aceptación verificable:** política explícita por clase de dato; limpieza idempotente probada con ficheros, resultados y estado de auth vencidos; volumen con permisos mínimos; logs JSON permiten identificar operación, resultado y correlación sin contener cuerpos, URLs sensibles, cookies, tokens, hashes de contraseña ni JSON de informe.
- **Riesgo de no realizarla:** persistencia excesiva de secretos y diagnóstico insuficiente o filtrador durante incidentes.
- **Estimación relativa:** M.
- **Dependencias o bloqueos:** acordar periodos de retención y backup; no prometer borrado seguro de copias externas.

#### P1-5 — Reorganizar el dashboard en flujos y hacer enlazables los resultados

- **Problema que resuelve:** C-07/C-08; la página concentra todas las acciones y el resultado se pierde al recargar.
- **Área o archivos afectados:** `frontend/src/App.tsx`, nuevos componentes de sección, `api.ts`, CSS y pruebas de UI.
- **Criterio de aceptación verificable:** navegación clara entre “Cargar y revisar”, “Auditorías de destino autorizadas” y “Resultados”; un URL/estado de ruta abre un `jobId` existente tras recarga; crear un trabajo selecciona y enfoca su resultado; no cambia ningún contrato de API.
- **Riesgo de no realizarla:** operaciones equivocadas, navegación lenta y percepción de herramienta inacabada al crecer el número de auditorías.
- **Estimación relativa:** M.
- **Dependencias o bloqueos:** conservar los componentes de informe existentes y definir la jerarquía de acciones activas frente a pasivas.

#### P1-6 — Corregir semántica, foco y feedback accesible de formularios y filtros

- **Problema que resuelve:** C-07; controles sin nombre/estado accesible y foco no visible.
- **Área o archivos afectados:** `frontend/src/App.tsx`, paneles activos, `styles.css`, pruebas frontend.
- **Criterio de aceptación verificable:** todos los inputs tienen `label`/nombre accesible; selectores segmentados usan tabs o `aria-pressed`; botones sólo de icono tienen nombre; existe `:focus-visible` con contraste suficiente; errores y finalización se anuncian una vez y mueven el foco de forma predecible; pruebas automáticas de accesibilidad no reportan violaciones críticas.
- **Riesgo de no realizarla:** usuarios de teclado o lector de pantalla no pueden completar de forma fiable cargas y auditorías autorizadas.
- **Estimación relativa:** M.
- **Dependencias o bloqueos:** P1-5 para no rehacer dos veces la estructura de la pantalla.

#### P1-7 — Añadir cabeceras de borde y un contrato de despliegue privado

- **Problema que resuelve:** la SPA y el backend no emiten política de seguridad HTTP; el servidor estático propio sólo fija tipo y cache.
- **Área o archivos afectados:** proxy recomendado o `frontend/docker-static-server.mjs`, Compose y runbook.
- **Criterio de aceptación verificable:** escaneo de cabeceras sobre HTTPS confirma CSP revisada, `nosniff`, política de frame, `Referrer-Policy` y política de permisos; no se rompe carga de SPA, exportaciones ni login; backend no queda expuesto directamente en perfil privado.
- **Riesgo de no realizarla:** defensas de navegador inconsistentes y despliegues que omiten controles por depender sólo de documentación.
- **Estimación relativa:** S.
- **Dependencias o bloqueos:** P0-1 y decisión proxy vs. servidor estático.

### P2 — calidad y refuerzo: planificables

#### P2-1 — Recuperar trabajos interrumpidos y clarificar la operación en curso

- **Problema que resuelve:** C-06 y polling sin estado de recuperación.
- **Área o archivos afectados:** `backend/app/main.py`, `services.py`, `storage.py`, `App.tsx`.
- **Criterio de aceptación verificable:** reiniciar durante una tarea deja un estado terminal controlado/reintentable; no hay trabajos eternamente activos; la UI explica qué ocurrió y muestra reintento sólo donde sea seguro.
- **Riesgo de no realizarla:** resultados ambiguos y acumulación de trabajos bloqueados.
- **Estimación relativa:** M.
- **Dependencias o bloqueos:** política de idempotencia por auditoría.

#### P2-2 — Convertir tablas densas en vistas responsivas y resumir primero lo accionable

- **Problema que resuelve:** tablas horizontales y nueve métricas apiladas en móvil; informes extensos sin una vista rápida homogénea.
- **Área o archivos afectados:** `frontend/src/styles.css`, listados de `App.tsx`, `PassiveReportShell.tsx` y reportes de trabajo.
- **Criterio de aceptación verificable:** a 320, 768 y 1440 px se ven estado, nombre, fecha y acción sin scroll horizontal crítico; las columnas secundarias se ocultan o aparecen en detalle; cada informe prioriza estado, hallazgos, límites/redacción y siguiente acción antes del JSON.
- **Riesgo de no realizarla:** baja legibilidad de resultados y uso móvil deficiente.
- **Estimación relativa:** M.
- **Dependencias o bloqueos:** P1-5.

#### P2-3 — Normalizar componentes de estado y lenguaje de interfaz

- **Problema que resuelve:** C-08; mezcla de idiomas, estados y errores locales/globales.
- **Área o archivos afectados:** `frontend/index.html`, `App.tsx`, componentes de panel/reporte y CSS.
- **Criterio de aceptación verificable:** idioma principal y `lang` coherentes; glosario único para estados, acciones y severidad; componente reutilizable para vacío/carga/error/éxito con reintento cuando proceda; no se muestran mensajes técnicos sin contexto de acción.
- **Riesgo de no realizarla:** confusión en flujos de autorización y pérdida de confianza en los resultados.
- **Estimación relativa:** S.
- **Dependencias o bloqueos:** decisión del idioma objetivo.

#### P2-4 — Añadir CI mínima y una matriz de pruebas reproducible

- **Problema que resuelve:** pruebas presentes pero no ejecutables desde el checkout actual y sin puerta automática de calidad.
- **Área o archivos afectados:** CI nueva, `pyproject.toml`, `package.json`, documentación de contribución.
- **Criterio de aceptación verificable:** un clone limpio ejecuta con comandos documentados las suites Python y frontend detectadas, además de build TypeScript/Vite y `docker compose config`; CI conserva resultados y falla ante regresiones.
- **Riesgo de no realizarla:** se introducen fallos de seguridad/UI sin señal temprana y no se puede repetir la validación de un release.
- **Estimación relativa:** M.
- **Dependencias o bloqueos:** P1-1 y P1-2 para fijar entornos y dependencias.

#### P2-5 — Añadir `.dockerignore` y pruebas de contexto de build

- **Problema que resuelve:** defensa en profundidad frente a inclusión accidental de `.env`, datos o claves en los contextos backend/tools.
- **Área o archivos afectados:** `backend/.dockerignore`, `tools/.dockerignore`, `frontend/.dockerignore`, pruebas estáticas.
- **Criterio de aceptación verificable:** los tres contextos excluyen secretos, `data/`, caches y resultados; una prueba falla si se elimina una exclusión crítica; el build sigue completando.
- **Riesgo de no realizarla:** filtración accidental a capas/caché de build tras añadir un `COPY` amplio.
- **Estimación relativa:** S.
- **Dependencias o bloqueos:** ninguno.

### P3 — mejoras opcionales: sólo si queda capacidad

#### P3-1 — Extraer una capa de presentación compartida para informes

- **Problema que resuelve:** mantenimiento costoso por muchos renderizadores de informe y un `App.tsx` grande.
- **Área o archivos afectados:** `frontend/src/*JobReport.tsx`, helpers de reportes y pruebas.
- **Criterio de aceptación verificable:** tarjetas, tablas, badges, panel de límites/redacción y errores controlados se reutilizan sin alterar la forma de los informes ni perder pruebas de redacción.
- **Riesgo de no realizarla:** inconsistencias visuales y cambios lentos; no es bloqueo de seguridad.
- **Estimación relativa:** L.
- **Dependencias o bloqueos:** P1-5, P1-6 y una línea base visual aprobada.

#### P3-2 — Añadir una revisión visual automatizada de regresión

- **Problema que resuelve:** CSS responsive y múltiples informes se prueban sobre todo por DOM, no por apariencia.
- **Área o archivos afectados:** entorno de pruebas frontend y snapshots visuales de rutas/estados sintéticos.
- **Criterio de aceptación verificable:** capturas aprobadas para escritorio y móvil de carga, lista vacía, error, trabajo en curso y reporte con hallazgos; cambios de snapshot requieren revisión humana.
- **Riesgo de no realizarla:** degradación visual silenciosa al modificar componentes compartidos.
- **Estimación relativa:** M.
- **Dependencias o bloqueos:** P2-4 y datos de demostración sintéticos estables.

## Frente de frontend y vistas

La mejora visual de mayor retorno no es una reescritura ni añadir una biblioteca de diseño: es reducir la densidad de decisiones de la pantalla actual y hacer evidente dónde está el usuario en el flujo.

Prioridad propuesta:

1. **Jerarquía de producto (P1):** dejar en primer plano el estado del backend, una acción principal de carga/revisión y los trabajos recientes. Mover auditorías de red autorizadas a una sección claramente etiquetada con sus confirmaciones; mantenerlas disponibles, pero no mezcladas visualmente con la carga pasiva.
2. **Resultado como destino (P1):** seleccionar/crear un trabajo debe actualizar URL, desplazar y enfocar el encabezado del resultado. Mostrar arriba estado, hora, fuente/objetivo redactado, número de hallazgos, límites alcanzados y exportaciones; Raw JSON permanece desplegable y secundario.
3. **Formularios seguros y comprensibles (P1):** etiquetas persistentes, ayuda de formato, validación antes de enviar, confirmaciones inequívocas para tráfico activo y mensajes de error junto al control. Deshabilitar debe explicar qué falta, no sólo cambiar opacidad.
4. **Accesibilidad tangible (P1):** foco visible, orden de tabulación, nombres accesibles, estados de filtro anunciables y errores/éxitos en regiones vivas. Añadir una prueba automática con axe y un recorrido manual de teclado.
5. **Responsive medible (P2):** sustituir tablas de seis columnas por tarjetas o columnas prioritarias en móvil; limitar las métricas a las más útiles en la cabecera y ofrecer el resto bajo “Ver métricas”. Validar a 320/768/1440 px.
6. **Consistencia y confianza (P2):** un solo idioma y glosario, colores de estado consistentes, escalas tipográficas de informe y avisos distinguidos entre “información”, “límite”, “acción requerida” y “error”. Mantener el mensaje de redacción y de alcance de las auditorías, pero cerca de la acción relevante.

Métricas de éxito acotadas: completar una carga y abrir su resultado sin scroll de búsqueda; abrir un trabajo por URL tras recarga; cero violaciones críticas de accesibilidad automatizada; todos los formularios completables por teclado; y ninguna tabla con información/acción crítica fuera de pantalla a 320 px.

## Plan de validación

1. **Configuración y despliegue:** ejecutar `docker compose config` para cada perfil; comprobar explícitamente enlaces, redes, volúmenes de solo lectura, capacidades y ausencia de puertos de backend en perfil privado. Probar desde otra máquina/namespace que el perfil local no escucha fuera de loopback.
2. **Autenticación y autorización:** regresiones de login, logout, expiración, bloqueo temporal, CSRF, propietario correcto/incorrecto, exportaciones y borrados. Inspeccionar `Set-Cookie` sobre HTTPS y probar que la configuración insegura falla antes de servir tráfico.
3. **Seguridad de entrada y red:** conservar las pruebas de límites de cargas/archivos y redacción; añadir pruebas de CORS, proxy confiable y DNS rebinding de laboratorio. Verificar que no aparecen secretos sintéticos en API, UI, Markdown, HTML, XML, PDF, SBOM ni logs.
4. **Dependencias e imágenes:** desde un entorno limpio, instalar desde lockfiles, ejecutar auditoría npm y Python, generar SBOM y escanear los digests de imagen realmente producidos. Guardar los resultados con el release.
5. **Backend y runner:** ejecutar la suite Python con sus dependencias de desarrollo fijadas; añadir pruebas de reinicio/reconciliación si se implementa P2-1; validar los contratos de runner con fixtures sin tráfico externo no autorizado.
6. **Frontend:** ejecutar typecheck/build y Vitest; añadir axe a los formularios, filtros, tablas y detalle; recorrer manualmente con teclado carga, filtros, creación de trabajo, auto-refresh, error, exportación y logout.
7. **Visual y responsive:** revisar capturas o navegador a 320, 768 y 1440 px en estados vacío, carga, error, en curso, completado y con hallazgos. Contrastar foco y contraste con una herramienta de accesibilidad antes de aceptar cambios CSS.
8. **Cierre de iteración:** no marcar una tarea como completada sólo por cambiar código. Exigir su criterio de aceptación, revisión de configuración efectiva, resultados de pruebas y una breve nota de riesgo residual o excepción fechada.
