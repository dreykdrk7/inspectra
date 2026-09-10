# TODO — seguridad, calidad técnica y frontend

Fuente de verdad operativa derivada de `PLAN_MEJORAS_SEGURIDAD_Y_FRONTEND.md`.
Actualizado: 2026-09-06.

## Reglas de prioridad

- **P0:** bloquea un despliegue relevante o expone datos, sesiones o servicios.
- **P1:** reduce de forma importante el riesgo o mejora un flujo principal en la siguiente iteración.
- **P2:** refuerzo planificable de calidad, resiliencia o experiencia.
- **P3:** mejora opcional, solo cuando no desplace trabajo de prioridad superior.

Cada tarea se trabaja de una en una. Al completarla, su evidencia se añade en el propio bloque y se revisan sus dependientes.

`PROD-121` completó el vertical OSV con procedencia pública verificable para
npm y PyPI y validó sus enriquecimientos GHSA/KEV. `poetry.lock` 2.1 sigue
local-only y nunca habilita egress. CISA KEV nunca determina por sí solo que un
paquete sea vulnerable: solo añade una señal de explotación conocida a un CVE
ya correlacionado.

## P0 — críticas

### SEC-001 — Exponer Docker Compose solo en loopback por defecto

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** Los puertos `8000` y `5173` se publican actualmente sin IP de enlace. Cambiar el valor por defecto a `127.0.0.1` evita que una ejecución local quede disponible en toda la red por error.
- **Archivos o áreas implicadas:** `docker-compose.yml`, `README.md`, pruebas estáticas de Compose en `tools/tests/`.
- **Criterios de aceptación verificables:** `docker compose config --quiet` es correcto y su configuración renderizada publica backend y frontend como `127.0.0.1:<puerto>:<puerto>` cuando no se proporcionan variables de entorno; existe una prueba o comprobación automatizable que evita la regresión; la documentación describe el comportamiento.
- **Riesgo de no resolverla:** exposición no intencionada del panel y API de administración a la LAN o Internet según el host.
- **Estimación:** S
- **Dependencias:** ninguna.
- **Evidencia de validación al completarla:** 2026-09-04: `docker compose config --quiet` pasó y la configuración renderizada mostró `host_ip: 127.0.0.1` para los destinos 8000 y 5173. Se ejecutó `test_public_compose_ports_bind_to_loopback_by_default` mediante Python; `git diff --check` pasó.

### SEC-002 — Definir acceso privado explícito para despliegues no locales

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** El modo `trusted_local_no_auth` y los puertos publicados no deben reutilizarse para acceso remoto. Ofrecer una configuración/documentación separada para proxy TLS y autenticación, con una guarda que impida combinaciones inseguras conocidas.
- **Archivos o áreas implicadas:** `docker-compose.yml`, configuración de despliegue, `backend/app/config.py`, `backend/app/main.py`, `README.md` y pruebas.
- **Criterios de aceptación verificables:** existe una ruta de despliegue privada documentada con TLS gestionado por proxy y autenticación requerida; el arranque rechaza o advierte de forma accionable las combinaciones declaradas inseguras; las pruebas cubren la guarda de configuración.
- **Riesgo de no resolverla:** el entorno local sin autenticación puede terminar publicado como servicio compartido.
- **Estimación:** M
- **Dependencias:** SEC-001 completada.
- **Evidencia de validación al completarla:** 2026-09-05: `docker compose -f docker-compose.yml -f docker-compose.private.example.yml config --quiet` pasó con valores de prueba; la salida JSON confirmó backend/frontend sin puertos y proxy en 80/443, perfil `private_tls_proxy`, auth single-admin, CORS HTTPS y API `/api`. El `Caddyfile` validó con `caddy:2.11.4-alpine` (digest `sha256:5f5c8640…d58648`). Se añadieron guardas de perfil y pruebas unitarias; la ruta de aceptación y rechazo se ejecutó directamente con `PYTHONPATH=backend`. `compileall`, prueba estática Compose y `git diff --check` pasaron. La suite pytest dirigida no pudo ejecutarse porque el checkout no tiene pytest instalado (`No module named pytest`).

### SEC-003 — Asegurar cookies de sesión y política de proxy

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** La cookie se crea con `secure=False` y no hay una política explícita de proxy confiable. Las sesiones deben requerir HTTPS fuera del modo local y la aplicación debe procesar cabeceras reenviadas únicamente desde proxies definidos.
- **Archivos o áreas implicadas:** `backend/app/auth.py`, `backend/app/config.py`, `backend/app/main.py`, `backend/tests/test_backend.py`, documentación de despliegue.
- **Criterios de aceptación verificables:** la configuración diferencia desarrollo local y despliegue HTTPS; las cookies externas incluyen `Secure`, `HttpOnly` y `SameSite` adecuado; se prueban los atributos y la política de proxy; los valores por defecto conservan el flujo local documentado.
- **Riesgo de no resolverla:** robo o reutilización de sesión en tráfico no cifrado y confianza indebida en cabeceras de proxy.
- **Estimación:** M
- **Dependencias:** SEC-002 completada.
- **Evidencia de validación al completarla:** 2026-09-05: el perfil `private_tls_proxy` exige `INSPECTRA_SESSION_COOKIE_SECURE=true`; login y logout emiten la cookie con `Secure`, `HttpOnly` y `SameSite=lax`. La imagen backend arranca Uvicorn con `--no-proxy-headers`, por lo que no procesa cabeceras reenviadas sin una futura lista de confianza explícita. Pasaron `docker compose ... config --quiet`, pruebas de configuración directa, prueba estática de Compose, `compileall` y `git diff --check`. En un contenedor efímero con pytest de desarrollo se ejecutó `pytest ... -k 'private_tls_proxy or secure_session_cookie'`: 6 passed (un aviso no bloqueante por caché pytest en montaje de solo lectura).

### SEC-019 — No revelar entradas rechazadas en respuestas de validación

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** FastAPI/Pydantic devuelve por defecto el valor `input` de un error de validación. La API acepta metadatos de proyecto y la interfaz muestra el `detail` de una respuesta fallida; por tanto, un secreto incluido por error en un campo inválido o no admitido puede volver al cliente y quedar expuesto en capturas, soporte o registros del navegador.
- **Archivos o áreas implicadas:** manejador HTTP de `backend/app/main.py`, contratos de entrada, `backend/tests/test_backend.py`, interfaz de errores de `frontend/src/api.ts` y documentación de seguridad.
- **Criterios de aceptación verificables:** todo `RequestValidationError` responde `422` con un detalle genérico y estable que no contiene valores de entrada, rutas privadas ni estructura Pydantic; el identificador de petición y controles de autenticación/CSRF se conservan; una prueba inyecta una cadena secreta en un campo extra y demuestra que no aparece ni en JSON ni en texto de la respuesta.
- **Riesgo de no resolverla:** revelación de tokens, URLs con credenciales u otros datos sensibles al rechazar una solicitud, con propagación posterior a UI, herramientas de soporte o logs de cliente.
- **Estimación:** S
- **Dependencias:** ninguna.
- **Evidencia de validación al completarla:** 2026-09-05: se registró un
  manejador global de `RequestValidationError` que responde siempre `422` con
  un detalle estable y no conserva ni registra los valores rechazados. La
  regresión inyecta un token en `repository_url` como campo extra de proyecto y
  verifica su ausencia tanto del JSON/texto de respuesta como del evento de
  auditoría, además de conservar `X-Request-ID`. Pasaron la prueba dirigida y
  la suite completa de `backend/tests` y `tools/tests` en Python 3.12, junto a
  `compileall`; el único aviso fue la caché de pytest no escribible en el
  montaje de solo lectura.

### SEC-020 — Demostrar que Gitleaks carga las reglas de detección

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** El preflight autorizado de `PROD-117` demostró que `.gitleaks.toml` solo declaraba una allowlist y no extendía las reglas predeterminadas. Una prueba negativa contra los fixtures inseguros terminó sin hallazgos, por lo que el escaneo de historial y las evidencias previas podían ofrecer falsa confianza aunque el proceso se ejecutase correctamente.
- **Archivos o áreas implicadas:** `.gitleaks.toml`, `Makefile`, `.github/workflows/ci.yml`, pruebas estáticas de seguridad, README y evidencias de `SEC-010`, `SEC-015` y `PROD-117`.
- **Criterios de aceptación verificables:** la configuración activa explícitamente el conjunto de reglas predeterminado; un objetivo reproducible y CI exigen que un fixture sintético fuera de la ruta allowlisted sea detectado con el código de salida esperado; las pruebas estáticas impiden retirar esa extensión o la prueba negativa; el historial de Inspectra y la instantánea filtrada de `fuente autorizada A` se vuelven a escanear con la política corregida antes de cualquier egress.
- **Riesgo de no resolverla:** secretos reales podrían llegar a contextos de build, artefactos de análisis o una consulta externa mientras CI y el preflight notifican falsamente una ejecución limpia.
- **Estimación:** S
- **Dependencias:** ninguna; bloquea la continuación de `PROD-117`.
- **Evidencia de validación al completarla:** 2026-09-06: el control negativo inicial confirmó el defecto al aceptar 696 bytes de fixtures inseguros sin reglas activas. `.gitleaks.toml` extiende ahora explícitamente las reglas predeterminadas; `make verify-secret-scanner` ejecuta el contenedor v8.30.1 fijado por digest, sin red, en solo lectura y con privilegios retirados, y solo pasa cuando el fixture sintético aislado produce un hallazgo/código 5 (1.007 bytes, 1 hallazgo). CI ejecuta el mismo canario. Las 51 coincidencias históricas preexistentes se revisaron como ejemplos sintéticos o falsos positivos acotados a pruebas y documentación y se fijaron por huella exacta en `.gitleaksignore`, de modo que hallazgos futuros en esos mismos archivos no quedan excluidos; el nuevo escaneo revisó 351 commits/7,84 MB sin hallazgos no justificados. Pasaron 21 pruebas estáticas y `git diff --check`. La instantánea reiniciada de `fuente autorizada A` también se escaneó con las reglas corregidas: 20 coincidencias, todas limitadas a contraseñas repetidas de pruebas y dos ejemplos de cabecera en README; no se detectaron URLs con credenciales, claves privadas/Cloud/GitHub ni archivos de credenciales. Una dirección de contacto en documentación quedó local y no forma parte del payload permitido. No hubo egress durante la corrección ni el preflight.

## P1 — alto impacto

### SEC-004 — Actualizar dependencias frontend con vulnerabilidades conocidas

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** El `package-lock.json` resolvía versiones afectadas de Vitest, Vite, PostCSS, Browserslist y nanoid. La auditoría reportó vulnerabilidades, incluidas críticas en Vitest.
- **Archivos o áreas implicadas:** `frontend/package.json`, `frontend/package-lock.json`, configuración Vite/Vitest y pruebas frontend.
- **Criterios de aceptación verificables:** las versiones bloqueadas dejan de estar afectadas por los avisos aplicables: [GHSA-5xrq-8626-4rwp](https://github.com/advisories/GHSA-5xrq-8626-4rwp), [GHSA-v6wh-96g9-6wx3](https://github.com/advisories/GHSA-v6wh-96g9-6wx3), [GHSA-fx2h-pf6j-xcff](https://github.com/advisories/GHSA-fx2h-pf6j-xcff), [GHSA-fxqj-rqcc-2cmp](https://github.com/advisories/GHSA-fxqj-rqcc-2cmp), [GHSA-r28c-9q8g-f849](https://github.com/advisories/GHSA-r28c-9q8g-f849), [GHSA-c83g-rgw3-j3cx](https://github.com/advisories/GHSA-c83g-rgw3-j3cx), [GHSA-73wf-gq98-2v4g](https://github.com/advisories/GHSA-73wf-gq98-2v4g), [GHSA-28wg-ghj8-5hjv](https://github.com/advisories/GHSA-28wg-ghj8-5hjv) y [GHSA-2v37-7h3g-55p8](https://github.com/advisories/GHSA-2v37-7h3g-55p8). `npm audit --package-lock-only` no informa hallazgos de estas cadenas; build y pruebas pasan.
- **Riesgo de no resolverla:** ejecución o desarrollo sobre dependencias con fallos de seguridad conocidos y cadena de suministro envejecida.
- **Estimación:** M
- **Dependencias:** ninguna.
- **Evidencia de validación al completarla:** 2026-09-05: lockfile actualizado a Vitest 3.2.7, Vite 6.4.3, PostCSS 8.5.28, Browserslist 4.28.9 y nanoid 3.3.18 (más sus transitivas necesarias). `npm audit --package-lock-only --json` informó 0 vulnerabilidades. En una copia temporal completa, `npm ci`, `npm run test:run` (29 archivos, 201 pruebas) y `npm run build` pasaron. El build emitió una advertencia de bundle inicial superior a 500 kB, registrada en PERF-001.

### SEC-005 — Bloquear versiones e imágenes y automatizar escaneo de dependencias

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** Las dependencias Python se instalan sin bloqueo reproducible y las imágenes base Docker usan etiquetas flotantes. No hay CI que detecte vulnerabilidades o regresiones antes de integrar cambios.
- **Archivos o áreas implicadas:** `backend/requirements.txt`, `tools/requirements.txt`, Dockerfiles, configuración CI y documentación de desarrollo.
- **Criterios de aceptación verificables:** dependencias Python transitorias e imágenes base quedan reproducibles con una estrategia documentada; CI ejecuta pruebas, build/lint disponibles y auditorías de dependencias; un cambio vulnerable o una prueba fallida hace fallar la comprobación correspondiente.
- **Riesgo de no resolverla:** builds no reproducibles, incorporación silenciosa de versiones vulnerables y regresiones no detectadas.
- **Estimación:** L
- **Dependencias:** SEC-004 completada.
- **Evidencia de validación al completarla:** 2026-09-05: se fijaron las dependencias directas y los cuatro lockfiles Python para Python 3.12; las imágenes Python, Node, Caddy y las directivas Dockerfile se anclaron por digest. Se añadió CI que ejecuta pytest, pruebas/build/auditoría npm, `pip-audit` de los lockfiles y validación Compose. El hallazgo `CVE-2025-71176` / [GHSA-6w46-j5rx-g56g](https://github.com/advisories/GHSA-6w46-j5rx-g56g) de pytest se corrigió a 9.0.3. `pip-audit` informó “No known vulnerabilities found” para los cuatro lockfiles; una ejecución CI-equivalente de pytest en Python 3.12 terminó con código 0; `docker compose build backend audit-tools frontend`, el build del scaffold `active-tools`, las pruebas estáticas de Docker/Compose y `git diff --check` pasaron.

### SEC-006 — Evitar rebinding DNS en las peticiones HTTP de herramientas

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** La URL se valida antes de que la conexión HTTP resuelva el host de nuevo. Un DNS controlado puede devolver después una IP interna o local.
- **Archivos o áreas implicadas:** `tools/runner/main.py`, pruebas de runner y documentación de límites SSRF.
- **Criterios de aceptación verificables:** la conexión usa una IP validada o revalida la IP justo antes de conectar, conserva el `Host`/SNI correcto cuando aplique y las pruebas cubren respuestas DNS cambiantes, IPv4, IPv6 y redirecciones.
- **Riesgo de no resolverla:** acceso de herramientas a servicios internos o metadatos cloud eludiendo el filtro SSRF.
- **Estimación:** M
- **Dependencias:** ninguna.
- **Evidencia de validación al completarla:** 2026-09-05: se añadió una resolución validada por conexión y el transporte HTTP/HTTPS se fija a una IP aceptada sin perder el hostname original de `Host`/SNI; la misma política se aplica a la inspección TLS y a las lecturas de `robots.txt`/`security.txt`. Las pruebas unitarias cubren rebinding simulado, IPv4, IPv6, preservación de hostname y SNI; `pytest tools/tests/test_runner.py -k 'pins_dns_validated_address or pins_validated_address'` pasó (3 pruebas) y `-k web_basic` pasó (11 pruebas, incluidas redirecciones y recursos auxiliares). `compileall` y `git diff --check` pasaron.

### SEC-007 — Establecer retención, redacción y observabilidad de datos sensibles

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** Los resultados pueden persistir evidencias con tokens o cabeceras y no existe una política de retención ni logging estructurado operativo.
- **Archivos o áreas implicadas:** modelos/repositorios de `backend/app/`, `tools/active_runner/audit_log.py`, directorio `data/`, configuración y documentación.
- **Criterios de aceptación verificables:** existe una política configurable de retención y borrado; los campos sensibles se redactan antes de persistir o registrar; logs estructurados incluyen correlación y no secretos; pruebas cubren la redacción y la expiración.
- **Riesgo de no resolverla:** fuga o conservación indebida de información sensible y diagnósticos insuficientes ante incidentes.
- **Estimación:** L
- **Dependencias:** SEC-003 para el modelo de despliegue externo.
- **Evidencia de validación al completarla:** 2026-09-05: se añadieron retenciones independientes de 30 días para originales y trabajos terminales, aplicadas al inicio del backend y configurables mediante `INSPECTRA_UPLOAD_RETENTION_DAYS` e `INSPECTRA_JOB_RETENTION_DAYS`; los trabajos activos protegen su fuente y los trabajos conservados se marcan cuando su original caduca. El perfil privado rechaza retención desactivada. Cada persistencia de trabajo ejecuta una redacción defensiva final para valores sensibles y los eventos de archivo, trabajo, limpieza y petición se emiten como JSON sin cuerpos, URLs ni secretos, con ID de correlación y cabecera `X-Request-ID`. Las pruebas cubren configuración, caducidad, protección de trabajos activos, marcado de origen eliminado, redacción persistida y logs. En Python 3.12 efímero pasaron 838 pruebas backend/runner; `compileall` y `git diff --check` pasaron (solo aviso no bloqueante de caché pytest de montaje de solo lectura).

### SEC-008 — Endurecer CORS, límites de entrada y concurrencia

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** CORS permite credenciales y cabeceras amplias; los límites de entrada y ejecución merecen una política explícita en lugar de depender solo de valores implícitos.
- **Archivos o áreas implicadas:** `backend/app/main.py`, `backend/app/config.py`, esquemas/rutas, runner y pruebas.
- **Criterios de aceptación verificables:** orígenes, métodos y cabeceras permitidos son mínimos y configurables; las rutas rechazan entradas fuera de límites documentados; existen límites verificables de concurrencia/tasa por el mecanismo elegido; las pruebas cubren solicitudes permitidas y denegadas.
- **Riesgo de no resolverla:** abuso de API, consumo descontrolado de recursos o ampliación accidental del perímetro entre orígenes.
- **Estimación:** M
- **Dependencias:** SEC-002 y SEC-003.
- **Evidencia de validación al completarla:** 2026-09-05: CORS con credenciales quedó limitado por defecto a orígenes HTTP(S) explícitos, `GET`/`POST`/`DELETE` y `Content-Type`/`X-CSRF-Token`. Los orígenes se normalizan y rechazan comodines, rutas, credenciales, consultas y fragmentos; las variables de métodos/cabeceras solo pueden restringir la lista segura, no ampliarla. Las peticiones web y de dominio rechazan valores de más de 2048 y 253 caracteres, respectivamente. Todas las ejecuciones de auditoría en segundo plano comparten un semáforo por proceso configurable de 1 a 16 (por defecto, 4). Pasaron 15 pruebas dirigidas de CORS/límites/concurrencia y la regresión completa de backend/runner (851 pruebas); `compileall`, `docker compose config --quiet` y `git diff --check` también pasaron. El único aviso fue la caché de pytest no escribible en el volumen de solo lectura del contenedor de pruebas.

### SEC-014 — Permitir configurar CORS seguro en el perfil Compose local

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** `docker-compose.yml` fija `INSPECTRA_CORS_ORIGINS` a `http://localhost:5173`, de modo que las variables validadas por el backend para origen, métodos y cabeceras no pueden aplicarse desde el despliegue Compose base. La comprobación visual en un puerto alternativo confirmó el síntoma como `Failed to fetch` por CORS.
- **Archivos o áreas implicadas:** `docker-compose.yml`, documentación de configuración y pruebas estáticas de Compose.
- **Criterios de aceptación verificables:** el perfil local conserva sus valores restrictivos por defecto, pero permite sobrescribir los orígenes, métodos y cabeceras CORS exclusivamente mediante las variables que valida el backend; `docker compose config` demuestra valores por defecto y valores personalizados; no se permite ampliar las listas seguras desde Compose.
- **Riesgo de no resolverla:** un despliegue local o de integración con un origen legítimo distinto falla de forma opaca, fomentando cambios manuales o relajación de CORS.
- **Estimación:** S
- **Dependencias:** SEC-008 completada.
- **Evidencia de validación al completarla:** 2026-09-05: el Compose base reenvía `INSPECTRA_CORS_ORIGINS`, `INSPECTRA_CORS_ALLOWED_METHODS`, `INSPECTRA_CORS_ALLOWED_HEADERS` e `INSPECTRA_AUDIT_MAX_CONCURRENCY` con los valores locales restrictivos como predeterminados. La configuración renderizada confirmó una personalización de origen, `POST`, `Content-Type` y concurrencia 2; las validaciones backend mantienen el rechazo de valores que amplíen la lista segura. Pasaron 11 pruebas de configuración CORS y seguridad estática de Compose, además de `git diff --check`. Una vista previa aislada con origen `http://127.0.0.1:15173` y backend en `18000` mostró `inspectra-backend` sin `Failed to fetch`, confirmando el preflight/configuración efectiva. Los contenedores e imagen temporales se eliminaron tras la comprobación.

### UX-001 — Clarificar navegación, ejecución y resultados del flujo principal

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** La pantalla principal concentra navegación, filtros, acciones y resultados en `App.tsx`, con selección de URL solo en memoria. Se necesita hacer predecible el recorrido crear/ejecutar/revisar y preservar el contexto útil.
- **Archivos o áreas implicadas:** `frontend/src/App.tsx`, componentes/estilos frontend, pruebas.
- **Criterios de aceptación verificables:** la navegación comunica la vista activa semánticamente; los flujos principales tienen estados de carga, error, vacío y éxito inequívocos; al recargar se preserva o restaura de forma deliberada el contexto permitido; pruebas cubren al menos un recorrido principal y un error recuperable.
- **Riesgo de no resolverla:** confusión operativa, pérdida de contexto y baja confianza percibida en el producto.
- **Estimación:** L
- **Dependencias:** SEC-004 si actualizar tooling modifica los tests.
- **Evidencia de validación al completarla:** 2026-09-05: se añadió una guía de cuatro etapas con navegación semántica y `aria-current`, estados actuales y anclas a creación, trabajos y resultado. Las acciones de carga y selección ahora confirman el siguiente paso; el resultado seleccionado recibe foco y su ID se conserva exclusivamente como `#job=<id>` en la URL, sin persistir contenido. Al recargar se restaura el trabajo si sigue disponible y, si no, se limpia el enlace y se muestra una acción recuperable. El resultado seleccionado se refresca al cambiar el estado del trabajo en la lista. Se añadieron pruebas para restauración, enlace caducado y creación de auditoría web; pasaron las 203 pruebas de frontend (29 archivos) y `npm run build`. Una revisión visual local confirmó la semántica de navegación, estados vacíos y controles bloqueados; el backend quedó deliberadamente inaccesible en el puerto alternativo por CORS, hueco registrado en SEC-014. El build conserva la advertencia de bundle de 633.96 kB, ya registrada en PERF-001.

### UX-002 — Corregir accesibilidad de controles y formularios esenciales

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** Los controles segmentados no exponen estado ARIA, los campos se apoyan en placeholder y no hay estilo de foco visible dedicado.
- **Archivos o áreas implicadas:** `frontend/src/App.tsx`, `frontend/src/styles.css`, pruebas frontend.
- **Criterios de aceptación verificables:** cada campo tiene etiqueta accesible; botones/grupos comunican nombre y estado; la interfaz se puede recorrer con teclado con foco visible; no aparecen violaciones críticas en el escaneo de las vistas principales.
- **Riesgo de no resolverla:** exclusión de personas que usan teclado o tecnologías asistivas, errores de formulario y menor calidad profesional.
- **Estimación:** M
- **Dependencias:** UX-001 para evitar rehacer controles durante la reestructuración.
- **Evidencia de validación al completarla:** 2026-09-05: los campos principales de carga, URL, dominio, candidatos, dry-run, probe y búsquedas recibieron etiquetas accesibles; los controles segmentados y filtros exponen su estado con `aria-pressed`; y el botón solo-icono de trabajo tiene nombre explícito. Se incorporó foco visible consistente y una utilidad para etiquetas solo de lector de pantalla. `axe-core` 4.13.0 quedó fijado en el lockfile y la prueba del tablero inicial no encontró violaciones críticas (el contraste se excluye porque JSDOM no lo calcula de forma fiable). Pasaron 205 pruebas frontend (29 archivos), build TypeScript/Vite, `npm audit --package-lock-only` con 0 vulnerabilidades y `git diff --check`. Se mantiene la advertencia de bundle inicial de 635.08 kB, registrada en PERF-001.

### SEC-009 — Definir cabeceras de seguridad en el borde HTTP

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** Falta una política explícita de cabeceras de seguridad para una exposición mediante proxy TLS.
- **Archivos o áreas implicadas:** configuración de proxy/despliegue, frontend/backend y documentación.
- **Criterios de aceptación verificables:** la ruta privada aplica CSP proporcionada al contenido real, `X-Content-Type-Options`, `Referrer-Policy`, política de permisos y HSTS solo bajo HTTPS; pruebas o comprobaciones HTTP validan su presencia y CSP no rompe la aplicación.
- **Riesgo de no resolverla:** defensas de navegador ausentes frente a carga de contenido inesperado, fugas de referencias y configuraciones inseguras.
- **Estimación:** M
- **Dependencias:** SEC-002 y SEC-003.
- **Evidencia de validación al completarla:** 2026-09-05: el proxy privado Caddy aplica HSTS de un año en el vhost HTTPS, CSP same-origin sin `unsafe-inline`, `nosniff`, denegación de framing, `Referrer-Policy`, `Permissions-Policy`, COOP y CORP; se elimina la cabecera `Server`. `caddy validate` aceptó el Caddyfile y 8 pruebas estáticas de seguridad de Compose pasaron. Con upstreams HTTP efímeros y aislados se verificó mediante `curl --insecure` la presencia de la política en respuestas HTTPS 200 y 404. La configuración privada de Compose también validó con valores sintéticos obligatorios y `git diff --check` pasó. Los contenedores y red temporales se eliminaron.

## P2 — calidad y refuerzo

### PERF-001 — Reducir el peso del bundle inicial de frontend

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** El build actual genera un bundle JavaScript inicial de 630.81 kB (133.08 kB gzip) y Vite advierte que excede 500 kB. La carga de una interfaz de auditoría no debe penalizar el primer acceso con vistas de informes que aún no se usan.
- **Archivos o áreas implicadas:** `frontend/src/App.tsx`, componentes de informes, configuración Vite y pruebas de frontend.
- **Criterios de aceptación verificables:** las vistas pesadas o no iniciales se cargan bajo demanda cuando sea viable; el build queda bajo el umbral acordado o el presupuesto se justifica y se controla explícitamente; la navegación, estados de carga y pruebas de rutas diferidas funcionan.
- **Riesgo de no resolverla:** carga inicial más lenta, peor experiencia en redes limitadas y degradación de calidad percibida.
- **Estimación:** M
- **Dependencias:** UX-001 y ENG-001 para conservar flujos y pruebas reproducibles.
- **Evidencia de validación al completarla:** 2026-09-05: los 27 componentes de informe se extrajeron de `App.tsx` a `JobResultReport.tsx`, cargado con `React.lazy` únicamente al abrir un trabajo. La transición mantiene un estado accesible `Loading redacted job report…` y la prueba existente de restauración de resultado por URL espera la carga diferida antes de verificar el informe. Se añadió `frontend/scripts/check-initial-bundle-budget.mjs`, ejecutado obligatoriamente por `npm run build`, con un presupuesto explícito de 320 KiB para el único chunk inicial. En una copia limpia de Node 22.21.1 Alpine pasaron `npm ci`, 30 archivos/210 pruebas de Vitest y build: chunk inicial de 293,9 KiB (300,97 kB; 82,12 kB gzip) y chunk diferido de informes de 336,21 kB (51,16 kB gzip). El presupuesto pasó y Vite dejó de emitir la advertencia de 500 kB.

### REL-001 — Recuperar trabajos y limpiar estados tras reinicios

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** Los trabajos dependen de un registro en memoria y pueden quedar incoherentes después de reiniciar procesos.
- **Archivos o áreas implicadas:** servicios de trabajos y persistencia en `backend/app/`, UI de ejecuciones y pruebas.
- **Criterios de aceptación verificables:** al reiniciar se marcan o recuperan de forma explícita los trabajos no terminales; no se muestran como activos si no pueden reanudarse; las pruebas simulan el reinicio y verifican el estado final.
- **Riesgo de no resolverla:** resultados ambiguos, trabajos aparentando ejecutarse y pérdida de trazabilidad.
- **Estimación:** M
- **Dependencias:** SEC-007 si la política de datos cambia la persistencia.
- **Evidencia de validación al completarla:** 2026-09-05: al arrancar el backend, `JobStore.recover_interrupted_jobs()` convierte exclusivamente los estados persistidos `queued` y `running` a `failed`, elimina cualquier resultado parcial y registra el error retryable «Audit interrupted by application restart. Run it again.». También emite un evento JSON por trabajo sin destino, cuerpo ni secretos. La prueba de ciclo de vida crea trabajos de un proceso previo, arranca el `lifespan`, confirma la recuperación de ambos activos, la eliminación del resultado parcial, la conservación de un trabajo completado y los eventos de auditoría. La regresión completa de backend/runner pasó con 1.194 pruebas en Python 3.12 y `git diff --check` pasó.

### UX-003 — Mejorar responsive y legibilidad de tablas, evidencias e informes

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** La información de seguridad puede ser extensa y necesita jerarquía, adaptación móvil y acceso progresivo sin ocultar decisiones importantes.
- **Archivos o áreas implicadas:** `frontend/src/App.tsx`, `frontend/src/index.css`, componentes de resultados e informes, pruebas visuales/manuales.
- **Criterios de aceptación verificables:** las vistas principales se revisan a 320 px, 768 px y escritorio sin desbordes; tablas y evidencias tienen alternativa legible; severidad, estado y acciones conservan jerarquía y contraste; se documentan capturas o pruebas de los tamaños acordados.
- **Riesgo de no resolverla:** resultados difíciles de interpretar, especialmente en pantallas pequeñas, y pérdida de calidad percibida.
- **Estimación:** M
- **Dependencias:** UX-001 y UX-002.
- **Evidencia de validación al completarla:** 2026-09-05: revisión visual de escritorio mediante navegador y comprobaciones automatizadas de los breakpoints de tablet (980 px) y móvil (hasta 640 px). Las tablas de archivos y trabajos ahora conservan una anchura legible, se desplazan horizontalmente solo cuando hace falta, anuncian la acción de desplazamiento en móvil, tienen `caption`, cabeceras de columna y región enfocables con teclado. A 640 px, los pares de resumen pasan a una columna y las evidencias `pre` quedan acotadas y desplazables. Se añadieron pruebas de semántica de tablas y de las reglas responsive. En una copia limpia de Node 22.21.1 Alpine pasaron `npm ci`, 30 archivos/208 pruebas de Vitest y `npm run build`; permanece únicamente la advertencia conocida de bundle inicial de 635.77 kB, registrada en PERF-001. `git diff --check` pasó.

### UX-004 — Unificar idioma, terminología y mensajes de estado

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** La interfaz mezcla español e inglés y los mensajes de estado/error no siguen una taxonomía consistente.
- **Archivos o áreas implicadas:** textos y componentes en `frontend/src/`, respuestas/mensajes backend que se presenten al usuario y pruebas.
- **Criterios de aceptación verificables:** se define un idioma principal y glosario breve; acciones, severidades y mensajes usan terminología coherente; cada error visible indica qué ocurrió y la acción de recuperación cuando exista.
- **Riesgo de no resolverla:** interpretación incorrecta de hallazgos y experiencia poco cohesionada.
- **Estimación:** S
- **Dependencias:** UX-001.
- **Evidencia de validación al completarla:** 2026-09-05: inglés definido y documentado como idioma principal en `docs/frontend-language.md`, con glosario de audit/job/finding/result/active audit/unavailable y reglas para estados y errores. Se tradujeron las advertencias de consulta y las tres confirmaciones de autorización que permanecían en español. El cliente conserva detalles de API controlados y redactados, pero deja de mostrar excepciones locales no controladas: ofrece «Unable to complete the request. Refresh the page and try again.». Las pruebas cubren ambos casos, formularios y advertencia de URL. La búsqueda de los textos españoles retirados no devolvió coincidencias; en una copia limpia `make test-frontend build-frontend` pasó con 30 archivos/209 pruebas y build. `git diff --check` pasó; la advertencia de bundle sigue en PERF-001.

### UX-007 — Aplicar divulgación progresiva a los flujos de auditoría avanzados

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** La revisión visual de la pantalla inicial confirmó que el área «Create an audit» muestra de forma continua cargas pasivas, análisis web, varios flujos de red activos y paneles de configuración especializada. Esta densidad oculta el recorrido principal y hace más difícil distinguir una auditoría habitual de una capacidad con tráfico o requisitos de autorización adicionales.
- **Archivos o áreas implicadas:** `frontend/src/App.tsx`, paneles de auditoría activa, estilos, pruebas de accesibilidad y recorrido visual.
- **Criterios de aceptación verificables:** la pantalla inicial prioriza los flujos frecuentes y pasivos; los flujos avanzados/activos se agrupan tras una divulgación explícita con contexto de riesgo; teclado y lectores de pantalla pueden abrir/cerrar los grupos y conocen su estado; los contratos, confirmaciones y mensajes de disponibilidad no cambian; pruebas cubren apertura, cierre y un flujo avanzado.
- **Riesgo de no resolverla:** sobrecarga cognitiva, baja percepción de madurez y mayor probabilidad de que un operador inicie o interprete mal un flujo de mayor impacto.
- **Estimación:** M
- **Dependencias:** UX-001 y UX-002 completadas; coordinar los textos con UX-004.
- **Evidencia de validación al completarla:** 2026-09-05: los flujos pasivos y frecuentes permanecen visibles en «Create an audit»; dry-run, probes y capacidades activas quedan agrupados bajo «Advanced and active audits» con una explicación de autorización/tráfico y un botón semántico `Show/Hide advanced audits`. El grupo usa `aria-expanded`, `aria-controls`, `aria-describedby` y `hidden`, conserva los contratos y confirmaciones existentes, y se reorganiza a una columna en tablet/móvil. Se añadieron pruebas para el cierre/apertura y se actualizó cada recorrido activo de integración para abrir el grupo antes de actuar. En una copia limpia pasaron 30 archivos/210 pruebas frontend y el build. La revisión en navegador con el stack Compose alternativo confirmó `hidden=true`/`aria-expanded=false` inicialmente y `hidden=false`/`aria-expanded=true` tras activar el control; backend también respondió `ok`. `git diff --check` pasó. La advertencia de bundle queda registrada en PERF-001.

### ENG-001 — Consolidar ejecución reproducible de pruebas y validaciones

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** El checkout actual no incluye entornos instalados para ejecutar `pytest` ni Vitest, lo que impide validar localmente las suites existentes con una instrucción corta y reproducible.
- **Archivos o áreas implicadas:** requisitos de desarrollo, `package.json`, documentación y automatización CI.
- **Criterios de aceptación verificables:** un desarrollador puede preparar el entorno y ejecutar pruebas backend, runner y frontend mediante comandos documentados; los comandos no dependen de estado manual oculto; CI los invoca.
- **Riesgo de no resolverla:** cambios sin validar, fricción de contribución y divergencia entre desarrollo y CI.
- **Estimación:** M
- **Dependencias:** SEC-005.
- **Evidencia de validación al completarla:** 2026-09-05: se añadió un `Makefile` con preparación aislada de Python, instalación npm por lockfile, pruebas, builds, auditorías y validación de ambos perfiles Compose. CI invoca ahora los mismos objetivos `make` en lugar de duplicar comandos. README documenta `make validate`, objetivos individuales y los overrides `PYTHON`/`VENV`. En copias limpias se ejecutó `make test-python PYTHON=python VENV=/tmp/inspectra-venv` (1.197 pruebas) y `make test-frontend build-frontend` (30 archivos/208 pruebas y build). Las 14 pruebas estáticas de workflow/Compose pasaron; `make validate-compose validate-compose-private`, `make --dry-run validate` y `git diff --check` pasaron. El aviso de bundle inicial sigue registrado en PERF-001.

### SEC-010 — Añadir exclusiones de contexto Docker y revisar secretos versionados

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** `backend/` y `tools/` no tienen `.dockerignore`, lo que amplía el contexto de build y el riesgo de incluir archivos no previstos. La prevención de secretos debe ser verificable.
- **Archivos o áreas implicadas:** `.dockerignore` de servicios, `.gitignore`, documentación y escaneo de secretos.
- **Criterios de aceptación verificables:** cada build usa un contexto mínimo con exclusiones para entornos, caches, datos y secretos; un escaneo de secretos revisa el historial/árbol según la herramienta elegida y queda integrado en la validación; la documentación indica cómo gestionar secretos locales.
- **Riesgo de no resolverla:** inclusión accidental de datos o credenciales en imágenes y aumento innecesario de superficie de build.
- **Estimación:** S
- **Dependencias:** SEC-005 para integrar el escaneo en CI.
- **Evidencia de validación al completarla:** 2026-09-05: se añadieron `.dockerignore` específicos a backend, herramientas y frontend con exclusiones para entornos, claves, certificados, cachés, pruebas y datos locales; el build de `active-tools`, que usa el contexto raíz, quedó con una allowlist explícita de solo su Dockerfile, lockfile y paquete aislado. `.gitignore` protege formatos locales de entornos y claves sin ocultar los fixtures sintéticos ya versionados. CI ejecuta Gitleaks CLI sobre historial completo (`fetch-depth: 0`) y README documenta la gestión y respuesta ante secretos. Los builds, configuraciones Compose y comprobaciones estáticas indicadas pasaron. **Corrección de evidencia, 2026-09-06:** `SEC-020` demostró que la configuración original no cargaba reglas y que el resultado anterior no probaba ausencia de fugas. La política corregida activa las reglas predeterminadas, conserva siete excepciones por ruta para fixtures sintéticos, revisa 51 coincidencias antiguas por huella exacta y añade un canario bloqueante; el historial de 351 commits/7,84 MB pasó de nuevo con el detector efectivo.

### SEC-015 — Asegurar que el escaneo de secretos funciona en repositorios de organización

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** La acción oficial Gitleaks v2 usada por CI requiere licencia también para repositorios de organización. El repositorio actual es personal, por lo que la configuración es válida hoy, pero una transferencia o adopción corporativa puede convertir el escaneo en un fallo de CI sin cobertura efectiva.
- **Archivos o áreas implicadas:** `.github/workflows/ci.yml`, secretos/configuración del repositorio, documentación de contribución y alternativa OSS si procede.
- **Criterios de aceptación verificables:** se documenta y provisiona la licencia necesaria de forma segura para organizaciones, o se adopta una alternativa mantenida que ejecute el escaneo de historial sin licencia comercial; una ejecución en el contexto elegido confirma que el trabajo examina el historial y falla ante una fuga sintética no permitida.
- **Riesgo de no resolverla:** adopciones en organizaciones pueden desactivar, omitir o dejar permanentemente fallido el control de secretos.
- **Estimación:** S
- **Dependencias:** SEC-010 completada.
- **Evidencia de validación al completarla:** 2026-09-05: la Action de Gitleaks v2 se sustituyó por el CLI oficial MIT, para evitar su requisito de licencia en organizaciones. CI monta el checkout completo en solo lectura y usa la imagen v8.30.1 fijada por digest; las pruebas estáticas impiden volver a la Action o introducir `GITLEAKS_LICENSE`. **Corrección de evidencia, 2026-09-06:** el control negativo original no era suficiente porque `.gitleaks.toml` sustituía las reglas predeterminadas. `SEC-020` activó esas reglas y añadió `make verify-secret-scanner`, que demuestra fuera de la allowlist que un fixture sintético genera exactamente el código bloqueante esperado. Tras revisar y fijar por huella los ejemplos históricos, el escaneo completo de 351 commits/7,84 MB y 21 pruebas estáticas pasaron.

### SEC-017 — Fijar el entorno de la herramienta de auditoría Python

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** `make audit-python` instalaba `pip-audit` sin versión ni dependencias fijadas. Por tanto, la misma validación podía ejecutar código diferente y cambiar de resultado entre ejecuciones sin modificación del repositorio.
- **Archivos o áreas implicadas:** `Makefile`, lockfile de la herramienta, CI/documentación y pruebas de flujo de desarrollo.
- **Criterios de aceptación verificables:** el ejecutable y sus dependencias están fijados en un lockfile separado; `make audit-python` instala solo ese lockfile y también lo audita; CI conserva el mismo objetivo y una prueba impide regresar a una instalación sin versión.
- **Riesgo de no resolverla:** menor reproducibilidad de CI, variación inesperada de controles de seguridad y mayor exposición de cadena de suministro para la herramienta que revisa dependencias.
- **Estimación:** S
- **Dependencias:** SEC-005 y ENG-001 completadas.
- **Evidencia de validación al completarla:** 2026-09-05: `tools/requirements-audit.lock` fija `pip-audit` 2.10.1 y sus 27 dependencias transitivas; `make audit-python` lo instala desde ese archivo y audita también el lock de la propia herramienta. La prueba estática exige el lock, la instalación y la auditoría. En un entorno Python 3.12 limpio se auditaron los cinco lockfiles (backend, desarrollo, runner, active-tools y audit) sin vulnerabilidades conocidas. `make --dry-run audit-python` confirmó los comandos compartidos de CI. Durante la validación se detectó el bootstrap mutable de `pip`, registrado y resuelto en SEC-018.

### SEC-018 — Fijar la versión de `pip` usada para crear el entorno de validación

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** `setup-python` ejecutaba `pip install --upgrade pip` sin versión. Ese primer paso podía modificar el resolvedor y el código ejecutado en CI aunque todos los lockfiles posteriores permanecieran iguales.
- **Archivos o áreas implicadas:** `Makefile`, documentación de desarrollo, pruebas de flujo de desarrollo y CI que invoca `make`.
- **Criterios de aceptación verificables:** el bootstrap instala una versión explícita de `pip`; existe un override deliberado y documentado; las pruebas protegen la referencia exacta y el flujo de auditoría se ejecuta correctamente desde un entorno limpio.
- **Riesgo de no resolverla:** builds menos reproducibles y cambios no revisados en el resolvedor o instalador de dependencias de CI.
- **Estimación:** S
- **Dependencias:** ENG-001 completada.
- **Evidencia de validación al completarla:** 2026-09-05: `Makefile` declara `PIP_VERSION ?= 26.2.1` y crea el entorno con `pip==$(PIP_VERSION)`; README documenta el override exclusivamente para actualizaciones revisadas y una prueba estática bloquea el regreso a un upgrade sin versión. En un entorno Python 3.12 limpio se confirmó `pip 26.2.1`, `pip check` sin requisitos rotos y 17 pruebas estáticas de flujo/Docker. Con ese bootstrap explícito, `pip-audit` informó “No known vulnerabilities found” en los cinco lockfiles. `make --dry-run audit-python` mostró exactamente la versión fijada y el mismo flujo que CI.

### SEC-016 — Hacer efectiva la URL de API al configurar puertos Compose alternativos

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** El cliente Vite se compila con `VITE_API_BASE_URL`, pero el Compose actual solo la entrega como variable de entorno en tiempo de ejecución al servidor estático. Al cambiar `INSPECTRA_BACKEND_HOST_PORT`, el navegador conserva `http://localhost:8000` y la aplicación muestra el backend como inaccesible. La incidencia se confirmó durante la revisión visual en `127.0.0.1:15173` con backend en `18000`.
- **Archivos o áreas implicadas:** `docker-compose.yml`, `frontend/Dockerfile`, servidor estático o configuración de cliente, documentación de despliegue y pruebas de configuración/integación.
- **Criterios de aceptación verificables:** la URL de API se inyecta de manera deliberada en build o en tiempo de ejecución sin relajar CORS; una ejecución Compose con puertos alternativos permite que frontend consulte `/health`, archivos y trabajos del backend; la configuración por defecto local y el perfil privado conservan su comportamiento; existe una prueba automatizable contra la regresión.
- **Riesgo de no resolverla:** instalaciones locales, de integración o con puertos personalizados quedan aparentemente rotas y pueden inducir atajos inseguros de CORS o cambios manuales no reproducibles.
- **Estimación:** M
- **Dependencias:** SEC-014 completada.
- **Evidencia de validación al completarla:** 2026-09-05: el Compose local pasa ahora `VITE_API_BASE_URL` como argumento de build y lo deriva de `INSPECTRA_BACKEND_HOST_PORT`; asimismo, el origen CORS local predeterminado se deriva de `INSPECTRA_FRONTEND_HOST_PORT`. `docker compose config --quiet` pasó y su renderizado con backend `18000` y frontend `15173` mostró la API `http://localhost:18000`, CORS `http://localhost:15173` y ambos puertos en loopback. En el stack real, `GET /health` y el preflight devolvieron respuesta correcta, incluido `Access-Control-Allow-Origin: http://localhost:15173`; la revisión en navegador de `http://localhost:15173` mostró backend `ok` y la URL `http://localhost:18000`. El perfil privado conservó el build same-origin `/api` al validar su Compose con valores sintéticos. Las 12 pruebas estáticas de Compose/Docker pasaron; README documenta que se debe reconstruir el frontend y cómo configurar un host distinto sin abrir CORS.

### SEC-011 — Ampliar corpus de redacción y pruebas de datos sensibles

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** La redacción existente debe comprobarse contra formatos reales y variantes de credenciales antes de confiar en ella para resultados o logs.
- **Archivos o áreas implicadas:** utilidades de redacción backend/runner, fixtures de pruebas y documentación de límites.
- **Criterios de aceptación verificables:** fixtures cubren tokens Bearer, cookies, cabeceras API comunes, claves con formatos conocidos, URLs con credenciales y entradas malformadas; las pruebas prueban que no se conservan secretos completos y que los falsos positivos aceptables están documentados.
- **Riesgo de no resolverla:** fuga de secretos pese a disponer de una capa de redacción parcial.
- **Estimación:** M
- **Dependencias:** SEC-007.
- **Evidencia de validación al completarla:** 2026-09-05: se detectó y corrigió una ruta de fuga defensiva: `redact_url_query` preservaba userinfo de URL en registros heredados y cadenas malformadas, y el almacenamiento no clasificaba `X-Api-Key` ni varias cabeceras equivalentes como claves sensibles. Backend y runner eliminan ahora userinfo antes de persistir o mostrar y mantienen la redacción de la consulta; el almacenamiento cubre cabeceras de autorización, cookie, API, auth y CSRF. La redacción activa añade Bearer/Basic, cookies, cabeceras habituales y formatos AWS, GitHub, GitLab, Stripe y Slack. Se añadieron 18 pruebas dirigidas para cabeceras, cookies, URLs con credenciales normales/malformadas, valores de proveedor y metadatos seguros; la suite completa pasó con 1.192 pruebas en Python 3.12. Los builds de backend/audit-tools y `git diff --check` pasaron. README documenta cobertura, falsos positivos permitidos y el límite de que el archivo original sigue siendo sensible.

### SEC-012 — Anclar las acciones de GitHub Actions por SHA verificado

- **Prioridad:** P2
- **Estado:** bloqueada
- **Descripción y motivo:** La nueva CI usa etiquetas móviles de acciones de terceros y de GitHub. Aunque las etiquetas facilitan actualizaciones, no fijan el contenido exacto que ejecuta la cadena de suministro.
- **Archivos o áreas implicadas:** `.github/workflows/ci.yml`, documentación de contribución y proceso de actualización de acciones.
- **Criterios de aceptación verificables:** cada acción externa se referencia por SHA de commit completo y conserva un comentario con su versión legible; existe un procedimiento documentado para renovar y verificar esos SHA; el workflow sigue validando en GitHub Actions.
- **Riesgo de no resolverla:** una modificación comprometida o inesperada de una etiqueta puede ejecutar código distinto en CI sin cambiar el repositorio.
- **Estimación:** S
- **Dependencias:** SEC-005 completada.
- **Evidencia de validación al completarla:** 2026-09-05: las etiquetas oficiales se verificaron contra sus repositorios: checkout v4.4.0 → `11d5960a326750d5838078e36cf38b85af677262`, setup-python v5.6.0 → `a26af69be951a213d495a4c3e4e4022e16d87065` y setup-node v4.4.0 → `49933ea5288caeca8642d1e84afbd3f7d6820020`. El workflow usa solo SHA completos con comentarios de versión y una prueba estática prohíbe referencias `@v*`. La antigua Action Gitleaks se eliminó en SEC-015; el escaneo usa ahora la imagen CLI v8.30.1 fijada por digest, por lo que no añade otra Action mutable. Las guardas estáticas y `git diff --check` pasaron. Bloqueo externo: falta la primera ejecución real en GitHub Actions (push o PR) para confirmar que el runner remoto acepta todas las acciones e imagen ancladas; no se creó un push ni se disparó un workflow desde este entorno.

### SEC-013 — Hacer reproducibles los paquetes del sistema instalados en imágenes

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** Las imágenes base ya usan digest, pero los `apt-get install` siguen resolviendo paquetes según el estado cambiante del repositorio de Debian. Esto deja variación en builds y dificulta investigar cambios de suministro.
- **Archivos o áreas implicadas:** `backend/Dockerfile`, `tools/Dockerfile`, `docker/active-tools/Dockerfile`, estrategia de build y documentación.
- **Criterios de aceptación verificables:** la estrategia elegida fija o registra de forma reproducible los paquetes de sistema y sus fuentes; reconstrucciones controladas informan las mismas versiones esperadas; la imagen conserva las herramientas necesarias y los builds pasan.
- **Riesgo de no resolverla:** builds no deterministas y menor trazabilidad ante una vulnerabilidad o regresión del sistema base.
- **Estimación:** M
- **Dependencias:** SEC-005 completada; decidir el mecanismo de repositorio/snapshot compatible con las imágenes.
- **Evidencia de validación al completarla:** 2026-09-05: `audit-tools` y `active-tools` usan el snapshot inmutable de Debian `20260824T000000Z`, junto a la imagen Python fijada por digest. Las firmas del archivo Debian se conservan; solo se desactiva la caducidad prevista de metadatos archivados. `docs/system-package-snapshots.md` documenta la política, el procedimiento de actualización y las versiones esperadas: `file` 1:5.46-5, `libimage-exiftool-perl` 13.25+dfsg-1, `poppler-utils` 25.03.0-5+deb13u4, `qpdf` 12.2.0-1 y `nmap` 7.95+dfsg-3. Se añadieron guardas estáticas para impedir que Dockerfiles y documentación diverjan. Los dos builds `--no-cache` pasaron y `dpkg-query` confirmó esas cinco versiones; pasaron 18 pruebas estáticas de Docker/Compose y `git diff --check`.

## P3 — mejoras opcionales

## Evolución de producto

Este bloque convierte la base pasiva ya reforzada en un producto de análisis de proyectos. Se parte de la arquitectura actual: archivos subidos y trabajos pasivos acotados, con propiedad por operador y retención. La primera vía admitida será un archivo de proyecto subido por el usuario; no se aceptarán rutas arbitrarias del servidor ni se clonarán repositorios o se pedirán credenciales hasta que exista un diseño de aislamiento específico. `SEC-012` se conserva bloqueada y queda fuera de cualquier cambio de esta línea sin autorización explícita.

### P0 — verticales de producto utilizables

### PROD-001 — Incorporar un archivo de proyecto y ejecutar su primera revisión trazable

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** Como desarrollador, quiero subir un archivo ZIP/TAR propio, convertirlo en un proyecto con identidad estable y arrancar su primera revisión pasiva desde una sola acción para no tener que recordar qué trabajo corresponde a cada código fuente. Es el mecanismo seguro equivalente ya compatible con el producto; no acepta rutas locales del host, URLs de repositorio ni credenciales.
- **Archivos o áreas implicadas:** modelos y almacenamiento de `backend/app/`, rutas de proyectos y creación de trabajos en `backend/app/main.py`, cliente y paneles de `frontend/src/`, pruebas backend/frontend y documentación de uso/arquitectura.
- **Criterios de aceptación verificables:** `POST /projects` acepta exclusivamente un `source_file_id` de tipo `archive` perteneciente al operador actual y crea un proyecto con nombre seguro, hash SHA-256 y metadatos inmutables de la fuente; en la misma operación crea una ejecución `project_archive_basic` asociada y encolada. `GET /projects` y `GET /projects/{id}` están aislados por propietario y muestran el último estado de ejecución sin exponer archivos ajenos. La interfaz permite crear el proyecto desde un archivo comprimido, comunica cola/error/éxito, muestra el proyecto y permite abrir el trabajo inicial. El borrado o la retención de la fuente conserva el historial redactado y marca la fuente como eliminada. Las pruebas cubren flujo correcto, tipo incorrecto, propietario incorrecto, nombre inválido, fallo controlado, CSRF y regresión visual/accesible del panel.
- **Riesgo de no resolverla:** Inspectra seguirá siendo una colección de archivos y trabajos inconexos, sin una entrada segura y comprensible para evaluar un proyecto real.
- **Estimación:** L
- **Dependencias:** ninguna; reutiliza `SEC-001`, `SEC-007`, `SEC-008` y `REL-001` completadas.
- **Evidencia de validación al completarla:** 2026-09-05: se añadieron `ProjectRecord` y `ProjectStore` owner-scoped en `data/results/projects`, sin rutas de host, URLs de repositorio ni credenciales. `POST /projects` solo acepta un archivo previamente validado de tipo `archive` del operador actual, conserva nombre seguro, SHA-256 y fuente inmutable, crea y asocia en la misma operación un trabajo `project_archive_basic`; `GET /projects` y `GET /projects/{id}` exponen exclusivamente el proyecto y último trabajo del propietario. El borrado y la retención de la fuente marcan el proyecto sin conservar sus bytes. La UI incorpora el botón `Create project & analyze`, estados de creación/error/éxito, panel de proyectos, estado de última ejecución y acceso a su resultado. Pasaron las pruebas backend de creación, tipo inválido, propietario distinto, payload no admitido, CSRF y retención; la suite completa backend/runner pasó en Python 3.12 efímero con caché de bytecode en `/tmp`; en Node 22.21.1 Alpine pasaron 30 archivos/211 pruebas y `npm run build` (bundle inicial 297,4 KiB / 320 KiB). `git diff --check` pasó. El stack Compose aislado con el fixture sintético `demo-archive-app-config.zip` completó archivo → proyecto → trabajo → resultado/exportaciones y se eliminó al finalizar, junto con sus datos temporales.

### PROD-002 — Modelo de ejecuciones de proyecto, estado reproducible y cancelación cooperativa

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** Como usuario de un proyecto, quiero iniciar una nueva ejecución sobre una instantánea identificada, seguir sus fases y recibir errores recuperables para saber qué se analizó y poder repetirlo. La cancelación solo se añadirá si el runner puede cooperar sin dejar procesos o resultados ambiguos.
- **Archivos o áreas implicadas:** orquestación de trabajos y runner, modelo/API de proyectos, frontend de seguimiento, retención, logs y pruebas de reinicio/cancelación.
- **Criterios de aceptación verificables:** cada ejecución conserva proyecto, hash de fuente, perfil de analizadores y, cuando el analizador lo declare, su versión; también conserva hora, estado terminal y error público. Un reinicio no deja ejecuciones aparentando estar activas; se puede relanzar la misma instantánea desde la UI; si se implementa cancelación, solo afecta trabajos propios en cola/ejecución, termina de forma idempotente y queda auditada. El panel muestra estados de cola, ejecución, éxito, fallo, interrupción y —si aplica— cancelación con siguiente acción clara. Las pruebas simulan runner lento, error, reinicio, reintento y autorización cruzada.
- **Riesgo de no resolverla:** análisis no reproducibles, seguimiento ambiguo y confianza insuficiente para uso de equipo.
- **Estimación:** L
- **Dependencias:** PROD-001 completada.
- **Evidencia de validación al completarla:** 2026-09-05: `JobRecord` y sus resúmenes guardan `project_id`, `source_sha256` y `analysis_profile`; `POST /projects/{id}/analyses` vuelve a encolar exclusivamente la fuente archivada retenida y comprobada contra el SHA del proyecto, mientras `GET /projects/{id}/analyses` devuelve el historial owner-scoped. Se evita la duplicación de una ejecución activa del mismo proyecto, el contador y último trabajo se actualizan, y una fuente eliminada/caducada responde `409` con la acción de cargar una nueva instantánea. La UI añade `Run again`, bloqueada para fuente eliminada o ejecución activa, y ahora refresca también los proyectos durante el seguimiento automático para que no queden estados obsoletos. No se implementó cancelación: el runner actual no dispone de señal cooperativa ni confirmación de limpieza segura; el reinicio conserva el comportamiento previo de fallo explícito y reintentable. Pasaron 17 pruebas backend relacionadas con proyecto y la suite completa backend/runner en Python 3.12 efímero; en Node 22.21.1 Alpine pasaron 30 archivos/213 pruebas y build (298,3 KiB / 320 KiB). La comprobación Compose/browser creó un proyecto con fixture sintético, verificó el trabajo completado, ejecutó de nuevo la misma instantánea, confirmó dos análisis con idéntico SHA y el refresco de estado; se eliminaron contenedores y datos temporales. `git diff --check` pasó.

### PROD-003 — Normalizar hallazgos pasivos en un contrato de producto

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** Como responsable técnico, quiero recibir hallazgos comparables aunque provengan de reglas distintas, con severidad, confianza, evidencia y una recomendación accionable, en lugar de interpretar formatos específicos de cada analizador.
- **Archivos o áreas implicadas:** contratos de resultados, `tools/runner/`, normalizadores backend, redacción, informes y pruebas/fixtures sintéticos.
- **Criterios de aceptación verificables:** el contrato normalizado contiene ID estable de regla, categoría, severidad, confianza, título, evidencia redactada, archivo/línea cuando exista, recomendación y referencias CVE/GHSA/OWASP solo cuando estén verificadas; conserva la procedencia y los límites de cobertura. Los analizadores ya presentes de secretos, dependencias, configuraciones e infraestructura alimentan el contrato sin ejecutar código del archivo. Los resultados desconocidos o malformados degradan de forma segura y no inventan ubicaciones ni vulnerabilidades. Las pruebas cubren cada categoría, redacción, IDs estables y compatibilidad de exportación.
- **Riesgo de no resolverla:** resultados difíciles de priorizar, informes inconsistentes y falsos niveles de certeza.
- **Estimación:** L
- **Dependencias:** PROD-001; la representación de fases de PROD-002 puede evolucionar en paralelo sin bloquear el contrato.
- **Evidencia de validación al completarla:** 2026-09-05: `backend/app/finding_normalization.py` añade una vista versionada (`normalized_findings`) y un resumen por severidad/categoría sin sustituir el resultado específico de cada analizador. El almacenamiento redacta primero y solo después calcula la huella de correlación, evitando que el ID derive de un secreto sin redactar. El normalizador prefiere la copia de hallazgos anidada en cada manifiesto para conservar ruta y elimina el duplicado agregado; las entradas incompletas degradan a `info`/`unknown` sin inventar ubicación. CVE, GHSA y OWASP solo se incluyen cuando identificador, HTTPS y fuente canónica concuerdan; no se realiza ni se afirma una consulta externa. `docs/product-findings-contract.md` explica contrato, privacidad y límites. Pasaron 43 pruebas dirigidas de normalización y la suite completa `backend/tests` + `tools/tests` al 100 % en Python 3.12 efímero; `compileall` de los módulos modificados pasó. La futura consulta de advisories reproducible queda separada en `PROD-010`.

### P1 — experiencia, comparación y colaboración

### PROD-004 — Panel de resultados de proyecto con filtros, detalle y estados de decisión

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** Como desarrollador, quiero abrir un proyecto y entender primero el riesgo más relevante, filtrar/buscar hallazgos y llegar a su evidencia y corrección sin recorrer JSON o informes técnicos dispersos.
- **Archivos o áreas implicadas:** rutas de consulta de hallazgos, componentes frontend, estilos responsive, accesibilidad, enlaces profundos y pruebas de interacción/visual.
- **Criterios de aceptación verificables:** la vista de proyecto ofrece resumen por severidad/categoría, búsqueda, filtros combinables, agrupación y detalle con evidencia redactada, ubicación, recomendación y referencias; comunica estados vacío, sin coincidencias, carga, error y resultados truncados; mantiene teclado, foco, contraste y comportamiento a 320/768/1440 px. Las pruebas cubren navegación por teclado, filtros, detalle, enlace profundo y estados de error/vacío.
- **Riesgo de no resolverla:** los hallazgos existentes no se convierten en decisiones o correcciones rápidas.
- **Estimación:** L
- **Dependencias:** PROD-002 y PROD-003 completadas.
- **Evidencia de validación al completarla:** 2026-09-05: se añadió `GET /projects/{project_id}/findings`, que vuelve a comprobar propietario, proyecto y ejecución relacionada, responde con estados explícitos (`ready`, pendiente, sin ejecución completada o sin hallazgos) y solo serializa el contrato normalizado y ya redactado. El panel `ProjectFindingsPanel` permite elegir instantánea, consultar resumen, buscar, combinar filtros, expandir detalle, abrir el trabajo y restaurar el proyecto con `#project=…`; sus referencias se validan también en cliente antes de convertirse en enlaces. Se actualizaron tipos/API, estilos responsive y la guía de proyectos. Pasaron las pruebas dirigidas de autorización/redacción/normalización, la suite completa `PYTHONPATH=backend:tools pytest backend/tests tools/tests -q` en Python 3.12 y frontend (31 archivos/216 pruebas) más `npm run build` en Node 22. La comprobación visual con Compose confirmó los servicios sanos y `GET /health` desde el host; el navegador integrado no pudo acceder a puertos loopback por `ERR_BLOCKED_BY_CLIENT`, una limitación de ese entorno que queda cubierta por el flujo de revisión visual documentado. `git diff --check` pasó y se eliminó el stack temporal y su lock efímero.

### PROD-005 — Historial y comparación entre ejecuciones de un proyecto

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** Como equipo, quiero comparar dos ejecuciones de la misma fuente/proyecto para distinguir hallazgos nuevos, resueltos y persistentes y priorizar el cambio reciente.
- **Archivos o áreas implicadas:** persistencia de ejecuciones/hallazgos normalizados, API de comparación, frontend de historial y pruebas de estabilidad.
- **Criterios de aceptación verificables:** el historial se limita al proyecto y propietario actuales, conserva instantánea y perfil de análisis; una comparación marca nuevo/resuelto/persistente con IDs de regla/evidencia estables y declara los límites cuando una regla no estuvo disponible. No se comparan proyectos ni propietarios distintos. Las pruebas usan dos instantáneas sintéticas y cubren cambios de archivo, severidad, redacción y acceso cruzado.
- **Riesgo de no resolverla:** falta de trazabilidad de mejora/regresión y revisiones manuales costosas.
- **Estimación:** L
- **Dependencias:** PROD-002, PROD-003 y PROD-004 completadas.
- **Evidencia de validación al completarla:** 2026-09-05: se añadió `GET /projects/{project_id}/comparisons`, que solo resuelve dos ejecuciones del mismo proyecto y propietario y responde con 404 genérico ante un ID ajeno o malformado. Compara únicamente ejecuciones completadas de igual tipo/perfil, sobre `normalized_findings` persistidos y redactados: marca nuevo, resuelto o persistente y enumera cambios seguros de campos, incluida severidad. Declara límites por truncamiento, fuente expirada, perfil distinto, pendiente o contrato ausente. La nueva interfaz permite escoger baseline y comparación, muestra métricas/grupos/detalle de evidencia redactada y enlaza a ambos informes completos. Pruebas dirigidas cubrieron propietario cruzado, ID inválido, dos IDs iguales, severidad, ruta, redacción y no comparabilidad; pasaron la suite Python completa, 32 archivos/218 pruebas frontend, build TypeScript/Vite y presupuesto inicial de 318,4 KiB/320 KiB. `docker compose config --quiet` y `git diff --check` pasaron.

### PROD-006 — Informe de proyecto para decisión ejecutiva y corrección técnica

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** Como responsable de seguridad, quiero exportar un informe de una ejecución con resumen de riesgo y detalle técnico trazable sin tener que reconstruirlo a partir de varios trabajos.
- **Archivos o áreas implicadas:** generación de informes, permisos de descarga, frontend de exportación, redacción y pruebas de formatos.
- **Criterios de aceptación verificables:** desde una ejecución de proyecto se exportan al menos Markdown y HTML/PDF con resumen ejecutivo, alcance/limitaciones, severidades, hallazgos detallados, evidencia redactada, recomendaciones y referencias; los nombres de archivo no filtran rutas ni secretos; exportar requiere propietario, respeta la retención y no incluye Raw JSON por defecto. Las pruebas verifican contenido, redacción, autorización y errores de exportación.
- **Riesgo de no resolverla:** difícil adopción por equipos que necesitan compartir resultados verificables.
- **Estimación:** M
- **Dependencias:** PROD-003 y PROD-004 completadas.
- **Evidencia de validación al completarla:** 2026-09-05: se añadieron exportaciones owner-scoped `GET /projects/{project_id}/analyses/{analysis_id}/report/{markdown|html|pdf}` y controles que rechazan ejecución pendiente, ajena o sin contrato normalizado. Los informes combinan resumen ejecutivo, severidades, instantánea/perfil, cobertura/retención y hallazgos técnicos con recomendación y referencias públicas; usan únicamente datos normalizados y vuelven a redactar texto/retener rutas inseguras. Los nombres emplean IDs opacos, no el archivo fuente. El explorador muestra enlaces de exportación cuando la instantánea está lista; la guía y contrato lo documentan. Pruebas dirigidas cubren tres formatos, PDF, HTML escapado, secreto/ruta/filename ausentes, análisis pendiente y cruce de proyecto; pasaron la suite Python completa, 32 archivos/219 pruebas frontend, build y presupuesto 319,2 KiB/320 KiB, `docker compose config --quiet` y `git diff --check`.

### P2 — ampliación controlada y preparación empresarial

### PROD-007 — Incorporación de repositorios mediante una integración de solo lectura diseñada

- **Prioridad:** P2
- **Estado:** pendiente
- **Descripción y motivo:** Como equipo, quiero analizar un repositorio autorizado sin descargarlo manualmente, pero la integración debe evitar que una URL, token o clone convierta al servidor en un proxy de red o exponga credenciales.
- **Archivos o áreas implicadas:** diseño de proveedor/credenciales, validación de URLs, aislamiento de checkout, configuración, UI y documentación de despliegue.
- **Criterios de aceptación verificables:** antes de implementar, existe una decisión de arquitectura con proveedor inicial, permisos mínimos, token efímero/cifrado o secret manager, allowlist de hosts, límites de clone/tamaño/tiempo, checkout sin hooks ni submódulos por defecto, borrado verificable y auditoría sin secretos. La implementación posterior solo admite repositorios explícitamente autorizados y crea la misma instantánea inmutable que PROD-001. Pruebas cubren URL/host no permitidos, tokens redactados, límites, aislamiento y borrado.
- **Riesgo de no resolverla:** el producto no cubre el flujo de repositorio; implementarlo sin estos controles introduce SSRF, fuga de tokens o ejecución de código no confiable.
- **Estimación:** L
- **Dependencias:** PROD-001, PROD-002 y una revisión de amenaza aprobada.
- **Evidencia de validación al completarla:** pendiente.

### PROD-008 — Límites, aislamiento y trazabilidad operativa por proyecto

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** Como administrador, quiero que cada análisis de proyecto consuma recursos acotados y conserve una traza útil sin mezclar fuentes, resultados ni credenciales entre operadores.
- **Archivos o áreas implicadas:** configuración, colas/runner, almacenamiento, observabilidad, documentación de operación y pruebas de concurrencia.
- **Criterios de aceptación verificables:** existen límites configurables de tamaño descomprimido, archivos, bytes, tiempo, concurrencia y espacio temporal por ejecución; cada espacio de trabajo está aislado por ID de ejecución y se limpia ante éxito, error, cancelación o reinicio; logs incluyen correlación/proyecto/ejecución sin nombres de ruta ni secretos; los límites fallan con errores públicos recuperables. Las pruebas cubren agotamiento, limpieza, cruce de propietario y recuperación.
- **Riesgo de no resolverla:** agotamiento de recursos, contaminación entre proyectos y evidencia operativa insuficiente en despliegues de equipo.
- **Estimación:** L
- **Dependencias:** PROD-001 y PROD-002 completadas.
- **Evidencia de validación al completarla:** 2026-09-06: el contrato
  `2026-09-06.1` conserva admisión, timeout, concurrencia, workspace,
  expansión, entradas, manifiestos y lockfiles. La fuente se copia a
  `workspaces/<job-id>/source.archive`, se comprueba por tamaño/SHA-256 y se
  limpia en éxito, error, cancelación o reinicio. El runner rechaza deriva de
  límites; Compose acota CPU, memoria, PID y `/tmp` de backend y runner. La
  cancelación owner-scoped es idempotente, el reintento crea un ID nuevo con
  linaje y un reinicio descarta resultados parciales con
  `application_restart`. API, UI e informes exponen tiempos, contrato y causa
  mediante vocabulario fijo; logs/errores omiten cuerpo, ruta host y excepción
  interna. Validación final: 997/997 backend en 15,7 s; 412/412 runner/estáticas
  en 5,8 s; 271/271 frontend en 20,15 s; build y presupuesto 311,6/322 KiB;
  `compileall`, Compose base/privado y `git diff --check`. La primera suite se
  detuvo por una expectativa de contrato obsoleta, no por sandbox; cinco
  regresiones posteriores se reprodujeron aisladas y corrigieron. El
  `node_modules/.vite-temp` del workspace produjo `EACCES`; frontend se validó
  con la misma fuente en la copia temporal escribible. No hubo Internet,
  proveedor ni proyecto real. `PROD-122` registra que `audit-tools` aún monta
  todo `data/` en solo lectura y que falta aislamiento fuerte por ejecución.

### P3 — mejoras de adopción cuando haya capacidad

### PROD-009 — Perfiles de análisis por stack y reglas de calidad técnica

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** Como equipo, quiero seleccionar un perfil explícito para mi stack y recibir reglas de calidad técnica relevantes sin que el producto ejecute código ni active un análisis genérico opaco.
- **Archivos o áreas implicadas:** detección pasiva de stack, perfiles de reglas, UI de configuración, documentación y fixtures.
- **Criterios de aceptación verificables:** cada perfil declara reglas, cobertura, límites y versiones; solo activa analizadores pasivos soportados; el resultado registra el perfil para reproducibilidad; la UI explica qué se incluye/excluye y permite una opción segura predeterminada. Pruebas cubren detección, perfil desconocido y compatibilidad de informes/comparación.
- **Riesgo de no resolverla:** cobertura poco adaptada a stacks comunes y expectativas ambiguas de los equipos.
- **Estimación:** M
- **Dependencias:** PROD-002, PROD-003 y PROD-008 completadas.
- **Evidencia de validación al completarla:** 2026-09-09: se añadió el catálogo
  cerrado `2026-09-09.1` con un único perfil seguro y honesto
  `project_archive_basic`, selección de reglas solo por manifiestos soportados,
  seis familias de reglas, stacks npm/PyPI/Go/Rust/PHP/JVM/.NET, exclusiones, red deshabilitada y prohibición
  de ejecutar código/gestores. El preflight sin fuente publica el perfil y los
  límites efectivos; cada job ya conserva nombre, ruleset y límites inmutables,
  y la comparación rechaza perfiles distintos. La UI presenta el perfil seguro,
  ruleset, reglas y exclusiones antes de elegir archivo. Pasaron 10 pruebas
  backend dirigidas en contenedor sin red/raíz de trabajo de solo lectura,
  incluidas catálogo desconocido, persistencia, incompatibilidad y API; 17/17
  pruebas del runner confirmaron detección y límites por stack. Se corrigió
  además el catálogo obsoleto que omitía Cargo/Composer/Gradle/NuGet y mostraba
  Yarn a la vez como resuelto y no resuelto. Pasaron 3/3
  pruebas de UI con `axe`; build frontend y presupuesto inicial (293,1/322 KiB),
  y `git diff --check`. No se ejecutó proyecto ni se contactó proveedor.

### Registro sincronizado de evolución de producto

Los criterios completos, flujo, riesgos y evidencia requerida de estas tareas
figuran en `TODO_PRODUCTO.md`; este registro conserva el estado que debe
mantenerse sincronizado con la fuente de verdad general.

| ID | Prioridad | Estado | Tamaño | Dependencias principales |
| --- | --- | --- | --- | --- |
| PROD-010 | P1 | completada | L | PROD-003 completada; diseño de egress de PROD-008 |
| PROD-011 | P1 | completada | L | PROD-004 y PROD-012 completadas |
| PROD-012 | P1 | completada | L | revisión de amenaza completada; desbloquea PROD-011/013/109 |
| PROD-015 | P1 | completada | L | PROD-008 completada; trazabilidad local existente |
| PROD-017 | P1 | completada | M | PROD-004 completada; desbloqueó PROD-030 |
| PROD-013 | P2 | completada | M | PROD-012 completada |
| PROD-014 | P2 | completada | L | PROD-003; PROD-008; PROD-009 |
| PROD-016 | P2 | completada | L | PROD-003; PROD-008; PROD-009 |
| PROD-018 | P2 | completada | M | PROD-003; PROD-006; PROD-009. Evidencia 2026-09-09: catálogo SPDX raíz cerrado, política exacta inmutable, CycloneDX/SPDX con licencia de dependencia desconocida, UI y deduplicación; 28 backend + 27 runner + 7 frontend, build/bundle/Compose/compile/diff sin red. |
| PROD-019 | P2 | completada | L | Materializada por PROD-131–136, PROD-155 y PROD-157 |
| PROD-020 | P2 | completada | L | PROD-008, PROD-012 y PROD-013 completadas |
| PROD-021 | P3 | pendiente | M | PROD-011; PROD-012; PROD-013 |
| PROD-022 | P3 | pendiente | M | PROD-005; PROD-006; PROD-012 |
| PROD-023 | P1 | completada | M | PROD-003, PROD-004 y PROD-005 completadas |

### Auditoría de producto y backlog Módulo 3 — 2026-09-05

**Correspondencia de módulos:** el módulo activo es **Módulo 3 — Inteligencia
de vulnerabilidades públicas** (`PROD-024` en adelante); el núcleo que ya lo
alimenta es **Módulo 2 — Proyectos y resultados** (`PROD-001`…`PROD-006`,
`PROD-023`). Las tarjetas detalladas, con flujo, criterios, riesgos,
estrategia de pruebas y evidencia obligatoria, figuran en `TODO_PRODUCTO.md`.
Sus estados deben actualizarse en ambos documentos en el mismo cambio. La
auditoría confirmó que la base inicial solo exportaba requisitos declarados de
tres manifiestos; ahora también conserva identidades exactas aptas para la
correlación OSV opt-in por ejecución. `PROD-026`…`PROD-029` completan egress
seguro, contrato, hallazgos OSV y CVSS trazable; GHSA, KEV, frescura,
deduplicación y estados de correlación ya están implementados. `PROD-017` y
`PROD-030` completaron el onboarding y la exploración accesible de inteligencia
de dependencias. `PROD-059` completó el verificador de postura segura de
despliegue no local; `PROD-044` cerró el prevuelo, `PROD-046` el enlace de
corrección y `PROD-045` la aceptación reproducible. `PROD-052` completó la
validación previa a caché de feeds; `PROD-049` cerró aliases y locators no
registry y `PROD-055` cerró namespaces privados y procedencia pública.
`PROD-101` añadió el motor local determinista, `PROD-118` preserva intervalos
OSV discontinuos y `PROD-102` estabiliza la identidad de hallazgos.
`PROD-119` dejó resuelto el preflight reproducible de Python para los
lockfiles. La
fotografía de 2026-09-05 de `npm audit --package-lock-only --omit=dev` y
`pip-audit` de los lockfiles no informó vulnerabilidades conocidas de Inspectra;
no equivale a cobertura de proyectos analizados.

| ID | Prioridad | Estado | Tamaño | Dependencias principales |
| --- | --- | --- | --- | --- |
| PROD-024 | P1 | completada | M | PROD-001/002/003/023 completadas |
| PROD-025 | P1 | completada | L | PROD-024 |
| PROD-026 | P1 | completada | M | PROD-024; revisión egress/PROD-008 |
| PROD-027 | P1 | completada | L | PROD-024; PROD-026 completada |
| PROD-028 | P1 | completada | L | PROD-025, PROD-026, PROD-027 completadas |
| PROD-029 | P1 | completada | L | PROD-027, PROD-028, PROD-004/006 |
| PROD-030 | P1 | completada | L | PROD-024, PROD-029, PROD-017 completadas |
| PROD-031 | P1 | completada | M | PROD-026, PROD-027, PROD-029 completadas |
| PROD-032 | P1 | completada | L | PROD-026, PROD-027, PROD-028, PROD-029 completadas |
| PROD-033 | P1 | completada | L | PROD-026, PROD-027, PROD-015 completadas |
| PROD-034 | P2 | completada | L | Materializada por PROD-033/050/051/053/065/096/099/104 |
| PROD-035 | P1 | completada | M | PROD-004/006/023; complementa PROD-017 |
| PROD-036 | P2 | completada | M | PROD-008, PROD-013 y PROD-020 completadas |
| PROD-037 | P2 | completada | M | Materializada por módulos de dominio posteriores; guarda no-red y estrategia atribuible verificadas |
| PROD-038 | P2 | completada | L | Materializada por PROD-131–136, PROD-152/153/155/157/159/163; criterios reconciliados y validados offline |
| PROD-039 | P3 | pendiente | L | PROD-012, PROD-013, PROD-014 |
| PROD-040 | P2 | completada | L | PROD-008, PROD-012, PROD-020 |
| PROD-041 | P1 | completada | L | PROD-001/002/005/023; PROD-008 |
| PROD-042 | P1 | completada | M | PROD-002; amplía PROD-015 |
| PROD-043 | P1 | completada | S | PROD-001 completada |
| PROD-044 | P2 | completada | M | PROD-035 |
| PROD-045 | P2 | completada | M | PROD-043/004/005/006/024; coordinar PROD-037 |
| PROD-046 | P2 | completada | S | PROD-004/023; PROD-041 |
| PROD-047 | P1 | completada | M | PROD-025, PROD-023 |
| PROD-048 | P1 | completada | L | PROD-025, PROD-047, PROD-029 completadas |
| PROD-049 | P2 | completada | M | PROD-025, PROD-026, PROD-023 |
| PROD-050 | P1 | completada | M | PROD-027, PROD-028 completadas |
| PROD-051 | P1 | completada | M | PROD-027, PROD-029, PROD-032 completadas |
| PROD-052 | P2 | completada | M | PROD-026, PROD-027 |
| PROD-053 | P2 | completada | M | PROD-033, PROD-050, PROD-029 |
| PROD-054 | P2 | completada | L | PROD-027, PROD-033, PROD-040 completadas |
| PROD-055 | P2 | completada | M | PROD-026, PROD-028, PROD-049 |
| PROD-056 | P2 | completada | S | PROD-027, PROD-037 |
| PROD-057 | P1 | completada | M | PROD-002; PROD-015 |
| PROD-058 | P1 | completada | L | PROD-008 y PROD-015 completadas; PROD-012 antes de multiusuario |
| PROD-059 | P1 | completada | M | modos actuales; PROD-012/040 |
| PROD-060 | P2 | completada | M | PROD-015, PROD-058 |
| PROD-061 | P2 | completada | M | PROD-003, PROD-057, PROD-040 completadas |
| PROD-062 | P2 | completada | L | PROD-036, PROD-040, PROD-013 |
| PROD-063 | P2 | completada | S | Exportación general redactada, confirmada y ligada a snapshot; PROD-013 cubre registro/consulta. Evidencia 2026-09-10: contrato `2026-09-10.1`, 1.000 eventos/1 MiB, preflight de cinco minutos, pseudónimos org-scoped, JSON/CSV, UI y auditoría mínima; backend 1.548/1.548 y frontend 410/410 offline, build 299,1/322 KiB, compileall/Compose/diff. |
| PROD-064 | P2 | completada | M | PROD-040, PROD-062 |
| PROD-065 | P1 | completada | M | PROD-005, PROD-041, PROD-057 |
| PROD-066 | P1 | completada | L | reconciliada con PROD-011; bitácora completa en PROD-013 |
| PROD-067 | P2 | completada | L | Materializada por PROD-133 y PROD-157 |
| PROD-068 | P2 | completada | M | Materializada por PROD-134–136 y PROD-155 |
| PROD-069 | P2 | completada | M | Materializada por PROD-136 y PROD-155 |
| PROD-070 | P2 | completada | L | Materializada por PROD-134–136 |
| PROD-071 | P3 | pendiente | L | PROD-015, PROD-026, PROD-067, PROD-068 |
| PROD-072 | P3 | pendiente | M | PROD-013, PROD-062 |
| PROD-073 | P1 | completada | L | PROD-008, PROD-015; extiende PROD-041 |
| PROD-074 | P1 | completada | M | PROD-041/042; SEC-019 completada; auth actual |
| PROD-075 | P2 | completada | M | PROD-036, PROD-062; PROD-041 |
| PROD-076 | P1 | completada | M | PROD-041, PROD-042, PROD-023 |
| PROD-077 | P2 | completada | M | PROD-076; UX-003 |
| PROD-078 | P1 | completada | S | Ninguna; control documental sincronizado |
| PROD-079 | P1 | completada | M | PROD-024, PROD-025, PROD-047 completadas |
| PROD-080 | P1 | completada | M | PROD-079; prepara PROD-028 |
| PROD-081 | P1 | completada | L | PROD-025, PROD-047; prepara PROD-048 |
| PROD-082 | P2 | completada | L | PROD-081, PROD-087 |
| PROD-083 | P2 | completada | L | PROD-087; coordina PROD-049 |
| PROD-084 | P2 | completada | L | PROD-079, PROD-080, PROD-087 |
| PROD-085 | P2 | completada | M | PROD-079, PROD-080, PROD-087. Evidencia 2026-09-09: Pipfile/Pipfile.lock v6 mismo-root, agrupado y local-only; fuentes/hashes/URLs descartados, no-egress verificado; 50 runner + 13 matriz + 1 PVI + 2 preflight + 24 frontend, build/Compose/compile/diff. |
| PROD-086 | P2 | completada | M | PROD-024, PROD-075. Evidencia 2026-09-09: parser `requirements-lines-v2-hash-summary`, resumen agregado sin digest/URL/ruta/credencial, UI e informe; 53 runner + 26 backend dirigidas, suites completas Python 1.883/1.883 y frontend 396/396, build 293,1/322 KiB, compileall/Compose/diff. |
| PROD-087 | P2 | completada | M | PROD-035; coordina PROD-081…086 |
| PROD-088 | P1 | completada | M | PROD-026, PROD-055, revisión PROD-008 |
| PROD-089 | P2 | completada | M | PROD-026, PROD-052, PROD-088 |
| PROD-090 | P1 | completada | L | PROD-026, PROD-027, PROD-079, PROD-088 |
| PROD-091 | P2 | completada | M | PROD-090, PROD-052, PROD-053 |
| PROD-092 | P2 | completada | M | PROD-027, PROD-088; reconciliada con PROD-032 |
| PROD-093 | P2 | completada | M | PROD-027 y PROD-088; PROD-098 consume evidencia CPE sin bloquear |
| PROD-094 | P2 | completada | M | PROD-031, PROD-093, PROD-099 completadas |
| PROD-095 | P2 | completada | M | PROD-027, PROD-032, PROD-088 |
| PROD-096 | P2 | completada | L | PROD-027, PROD-092, PROD-093, PROD-095 completadas |
| PROD-097 | P2 | completada | M | PROD-029; PROD-096 consume este contrato |
| PROD-098 | P2 | completada | L | PROD-079, PROD-093, PROD-095 |
| PROD-099 | P2 | completada | L | PROD-033, PROD-054, PROD-061 completadas |
| PROD-100 | P2 | completada | M | PROD-033, PROD-053, PROD-099 completadas |
| PROD-101 | P1 | completada | L | PROD-027, PROD-079, PROD-080; prepara PROD-028/050 |
| PROD-102 | P1 | completada | M | PROD-003, PROD-101; prepara PROD-065/066 |
| PROD-103 | P2 | completada | M | PROD-066, PROD-109 |
| PROD-104 | P2 | completada | M | PROD-035, PROD-057, PROD-065 |
| PROD-105 | P2 | completada | L | Implementada por PROD-147 |
| PROD-106 | P2 | completada | M | PROD-006, PROD-075, PROD-109 y PROD-069. Evidencia 2026-09-10: `GET` genera únicamente el perfil mínimo agregado, sin nombres/IDs/rutas/evidencia/componentes/advisories/texto libre y con nombre genérico; el perfil técnico exige `POST`, confirmación literal, CSRF y maintainer/admin o bearer `report:read`, mantiene redacción y ambos usan `private,no-store`. UI accesible separa perfiles y reader solo ve mínimo. JSON/SARIF/enlace público no existen y un query no eleva el perfil. Pasaron 15 pruebas auth/report dirigidas, 17 de auditoría/smoke, backend completo 1.563/1.563 y frontend 412/412; axe, build 300,0/322 KiB, `compileall`, Compose base/privado y diff-check. La primera suite detectó la nueva ruta ausente del inventario de mutaciones; se añadió con regresión CSRF y la repetición pasó. Sin Internet. |
| PROD-107 | P2 | completada | M | PROD-042, PROD-065, PROD-066. Evidencia 2026-09-10: bandeja pasiva owner-scoped derivada de cartera, 2.000 eventos/100 lectores, leído durable por usuario, deduplicación/reconciliación, reconstrucción admin, reader+CSRF, auditoría mínima, API/UI accesible, backup/restore y cascada de proyecto. Solo persiste IDs opacos, enums/fecha y digests de lector; nombre/evidencia/ruta/secreto quedan fuera. Retención `2026-09-10.4` clasifica 22 clases. Backend 1.573/1.573, frontend 59 archivos/415 pruebas, axe, build 300,9/322 KiB, compileall, Compose base/privado y diff-check. Recorrido sintético local desktop/móvil: 2→1→2 no leídos, deep link correcto, 375/375 px sin overflow, consola vacía y limpieza completa; sin Internet. |
| PROD-108 | P2 | completada | L | Materializada por PROD-145 y PROD-147 |
| PROD-109 | P2 | completada | L | PROD-012, PROD-013 |
| PROD-110 | P2 | completada | L | PROD-061, PROD-063, PROD-109. Evidencia 2026-09-10: ledger encadenado owner-scoped, retención/anclas, rotación, verificador admin y fail-closed en lectura/export/backup; 45 dirigidas, backend 1.555/1.555, frontend 410/410, build 299,1/322 KiB, compileall/Compose/diff. |
| PROD-111 | P2 | completada | M | PROD-017, PROD-043, PROD-076 |
| PROD-112 | P2 | completada | L | Materializada por PROD-133–135 y PROD-153 |
| PROD-113 | P1 | completada | L | PROD-029, PROD-030 y PROD-050 completadas; PROD-094/097 no bloquean datos ausentes |
| PROD-114 | P2 | completada | M | PROD-077, PROD-103, PROD-113 |
| PROD-115 | P2 | completada | M | PROD-053, PROD-060, PROD-089, PROD-100, PROD-109 |
| PROD-116 | P1 | completada | L | PROD-059, PROD-060, PROD-064, PROD-075 |
| PROD-117 | P1 | completada | M | fuente autorizada B; aceptación real OSV/KEV, degradación, UI y limpieza completadas con GO acotado |
| PROD-118 | P1 | completada | M | PROD-027, PROD-101; coordina PROD-099 |
| PROD-119 | P1 | completada | S | Ninguna; coordina validaciones de PROD-116 |
| PROD-120 | P2 | completada | M | Cascada recuperable implementada y validada |
| PROD-121 | P1 | completada | L | PROD-026, PROD-027, PROD-028, PROD-033, PROD-079, PROD-084 |
| PROD-122 | P1 | completada | L | PROD-008 y PROD-015 completadas; PROD-012 antes de multiempresa |
| PROD-123 | P1 | completada | S | PROD-015, PROD-030, PROD-035 y PROD-042 completadas |
| PROD-124 | P2 | completada | M | PROD-012, PROD-013, PROD-062; coordina PROD-109. Evidencia 2026-09-10: purga terminal tenant-scoped/arranque, baja pseudonimizada, sesiones acotadas al espacio y contrato 21 clases; backend 1.561/1.561, frontend 410/410, build 299,1/322 KiB, compileall/Compose/diff. |
| PROD-125 | P0 | completada | S | PROD-026, PROD-116 y autorización expresa de proveedor |
| PROD-126 | P0 | completada | S | PROD-113, PROD-123 y revisión visual de PROD-117 |
| PROD-127 | P0 | completada | S | PROD-026, PROD-090 y validación real de PROD-117 |
| PROD-128 | P0 | completada | S | PROD-113, PROD-126 y revisión visual de PROD-117 |
| PROD-129 | P1 | completada | L | PROD-117/127/128 completadas; consolidación local autorizada el 2026-09-10 |
| PROD-130 | P1 | en progreso | M | PROD-129 y SEC-012; autorización remota limitada concedida, PR borrador abierto y CI remoto en corrección tras un fallo frontend reproducible |
| PROD-131 | P1 | completada | L | PROD-043, PROD-073 y flujo archive-backed completados |
| PROD-132 | P1 | completada | M | PROD-131 completada |
| PROD-133 | P1 | completada | L | PROD-012, PROD-013; implementa PROD-067 |
| PROD-134 | P1 | completada | L | PROD-132, PROD-133 y PROD-073; implementa PROD-068 |
| PROD-135 | P1 | completada | L | PROD-104, PROD-112, PROD-134; implementa PROD-070 |
| PROD-136 | P1 | completada | M | PROD-069, PROD-135 |
| PROD-137 | P1 | completada | L | PROD-003, PROD-024 y límites de ingestión existentes |
| PROD-138 | P1 | completada | L | PROD-027, PROD-079 y PROD-137 |
| PROD-139 | P1 | completada | L | PROD-027, PROD-079 y PROD-137 |
| PROD-140 | P2 | completada | L | PROD-025, PROD-079, PROD-137 |
| PROD-141 | P2 | completada | L | PROD-025, PROD-079, PROD-137 |
| PROD-142 | P2 | completada | L | PROD-025, PROD-079, PROD-137 |
| PROD-143 | P2 | completada | L | PROD-025, PROD-079, PROD-137 |
| PROD-144 | P2 | completada | L | PROD-025, PROD-079, PROD-137 |
| PROD-145 | P1 | completada | L | PROD-065, PROD-104, PROD-108 |
| PROD-146 | P1 | completada | L | PROD-046, PROD-048, PROD-066 y PROD-145 |
| PROD-147 | P2 | completada | L | PROD-105, PROD-145 y PROD-146 completadas |
| PROD-148 | P1 | completada | L | PROD-012, PROD-013 y controles Active existentes |
| PROD-149 | P1 | completada | L | PROD-148 y módulos Active soportados |
| PROD-150 | P1 | completada | M | PROD-149 |
| PROD-151 | P2 | completada | M | Primeros tres verticales del Ciclo 6 completados |
| PROD-152 | P1 | completada | M | PROD-131/132 completadas; no requiere publicación |
| PROD-153 | P1 | completada | M | PROD-133/134/135/136 completadas |
| PROD-154 | P1 | completada | L | PROD-137/138/139 completadas |
| PROD-155 | P1 | completada | S | PROD-136 completada |
| PROD-156 | P1 | completada | M | PROD-132 y contratos de capabilities existentes |
| PROD-157 | P1 | completada | M | PROD-133 y política de retención |
| PROD-158 | P1 | completada | M | PROD-138/139 completadas |
| PROD-159 | P2 | completada | S | PROD-008, PROD-132 y cancelación backend existentes |
| PROD-160 | P2 | completada | M | PROD-131/132/134/135 |
| PROD-161 | P2 | completada | M | PROD-152 |
| PROD-162 | P2 | completada | M | Observabilidad existente; privacidad por diseño validada offline |
| PROD-163 | P2 | completada | S | PROD-131/132 |
| PROD-164 | P1 | completada | M | PROD-137/138/139 completadas |
| PROD-165 | P1 | completada | L | PROD-111 y verticales 1–3 completadas |
| PROD-166 | P1 | completada | M | PROD-137/138/139 y PROD-154 completadas |
| PROD-167 | P2 | bloqueada | M | PROD-161, PROD-130 y runners macOS/Windows autorizados |
| PROD-168 | P0 | completada | S | Regresiones descubiertas al validar PROD-154/157/158/165 |
| PROD-169 | P1 | completada | M | PROD-150 |
| PROD-170 | P1 | completada | L | PROD-148 |
| PROD-171 | P1 | completada | L | PROD-148, PROD-149, PROD-150 y PROD-170 |
| PROD-172 | P2 | completada | L | PROD-170, PROD-171 y límites operativos Active |
| PROD-173 | P1 | completada | M | PROD-171, PROD-174, PROD-175 |
| PROD-174 | P0 | completada | S | Descubierta por PROD-173; identidad de equipo existente |
| PROD-175 | P0 | completada | M | Descubierta por PROD-173; runner Active existente |
| PROD-176 | P1 | completada | M | PROD-148, PROD-170, PROD-185 completada |
| PROD-177 | P1 | completada | S | PROD-148 y directorio de equipo |
| PROD-178 | P1 | completada | L | PROD-148, política de retención y borrado por proyecto |
| PROD-179 | P1 | completada | M | PROD-171, PROD-175 |
| PROD-180 | P2 | completada | M | PROD-176, auditoría y roles de equipo |
| PROD-181 | P2 | completada | M | PROD-148, PROD-177, PROD-184 |
| PROD-182 | P2 | completada | M | PROD-171, PROD-176, PROD-183 completadas |
| PROD-183 | P1 | completada | L | PROD-008, PROD-149, PROD-175 |
| PROD-184 | P1 | completada | M | PROD-149, PROD-171, PROD-183 completada |
| PROD-185 | P1 | completada | M | PROD-148, PROD-149 |
| PROD-186 | P2 | completada | M | PROD-169, PROD-185 |
| PROD-187 | P1 | completada | L | PROD-170, PROD-175 |
| PROD-188 | P1 | completada | L | PROD-171 y almacenamiento Active |
| PROD-189 | P2 | completada | M | PROD-169, PROD-185 y auditoría de producto |
| PROD-190 | P2 | completada | M | PROD-172, PROD-176, PROD-183, PROD-184 completadas |
| PROD-191 | P1 | completada | M | PROD-177 y ciclo de miembros de equipo |
| PROD-192 | P2 | completada | M | PROD-171, PROD-188 completada |
| PROD-193 | P2 | completada | L | PROD-188 completada |
| PROD-194 | P2 | completada | S | PROD-188; coordinación de compatibilidad API |
| PROD-195 | P2 | completada | M | PROD-178 y PROD-181 completadas |
| PROD-196 | P2 | completada | L | PROD-182, PROD-193 y stores Active durables |
| PROD-197 | P1 | completada | L | PROD-196 completada |
| PROD-198 | P1 | completada | M | PROD-184 y PROD-196 completadas |
| PROD-199 | P1 | completada | L | PROD-196 y PROD-198 completadas |
| PROD-200 | P1 | completada | M | PROD-199 completada |
| PROD-201 | P1 | completada | L | PROD-198, PROD-199 y PROD-200 completadas |
| PROD-202 | P1 | completada | M | PROD-201 completada |
| PROD-203 | P1 | completada | M | PROD-178, PROD-193 y PROD-202 completadas |
| PROD-204 | P1 | completada | M | PROD-170, PROD-193 y PROD-203 completadas |
| PROD-205 | P1 | completada | L | PROD-178, PROD-186, PROD-199 y PROD-204 completadas |
| PROD-206 | P1 | completada | L | PROD-198, PROD-202 y PROD-205 completadas |
| PROD-207 | P1 | completada | L | PROD-202 y PROD-206 completadas |
| PROD-208 | P1 | completada | L | PROD-193, PROD-206 y PROD-207 completadas |
| PROD-209 | P1 | completada | L | PROD-206, PROD-207 y PROD-208 completadas |
| PROD-210 | P1 | completada | L | PROD-172, PROD-190, PROD-198 y PROD-209 completadas |
| PROD-211 | P1 | completada | L | PROD-182, PROD-189, PROD-205 y PROD-210 completadas |
| PROD-212 | P2 | completada | M | PROD-211 y retención/auditoría completadas |
| PROD-213 | P2 | completada | M | PROD-134 y PROD-145 completadas |
| PROD-214 | P2 | completada | L | PROD-145 y PROD-208 completadas |
| PROD-215 | P2 | completada | M | PROD-012, PROD-145 y PROD-146 completadas |
| PROD-216 | P2 | completada | M | PROD-146 completada y estrategia de recuperación |
| PROD-217 | P2 | completada | M | PROD-146 completada y preferencias owner-scoped |
| PROD-218 | P2 | completada | L | PROD-146 completada e índice duradero PROD-214 |
| PROD-219 | P2 | completada | L | PROD-147 completada e índice duradero PROD-214 |
| PROD-220 | P1 | completada | L | PROD-012, PROD-026 y verticales multi-ecosistema |
| PROD-221 | P2 | completada | M | PROD-140 y contrato de artefactos CI |
| PROD-222 | P3 | pendiente | S | PROD-140 y evidencia de demanda real |
| PROD-223 | P2 | completada | M | PROD-141 y contrato de artefactos CI |
| PROD-224 | P3 | pendiente | S | PROD-141 |
| PROD-225 | P2 | completada | M | PROD-141 y contrato GHSA oficial verificado |
| PROD-226 | P2 | completada | M | PROD-143 y contrato CI |
| PROD-227 | P3 | pendiente | M | PROD-143 y evidencia de demanda |
| PROD-228 | P3 | pendiente | S | PROD-143 |
| PROD-229 | P2 | completada | M | PROD-142 y PROD-243 completadas |
| PROD-230 | P2 | completada | M | PROD-142 completada; corpus oficial revisado |
| PROD-231 | P2 | completada | M | PROD-137, PROD-138, PROD-139, PROD-142 y PROD-230 completadas |
| PROD-232 | P3 | pendiente | S | PROD-142 |
| PROD-233 | P1 | completada | S | índices y paginación Active existentes |
| PROD-234 | P2 | completada | M | PROD-144 y contrato de artefactos CI |
| PROD-235 | P2 | completada | M | PROD-144 y corpus NuGet oficial revisado |
| PROD-236 | P3 | pendiente | S | PROD-144 |
| PROD-237 | P3 | pendiente | M | PROD-097 y corpus oficial CVSS v4 |
| PROD-238 | P2 | bloqueada | M | PROD-098; requiere evidencia primaria, acceso externo autorizado y aprobación de dos revisores |
| PROD-239 | P2 | completada | S | Auditoría de criterios heredados y evidencia posterior |
| PROD-240 | P1 | completada | S | Hallazgo durante PROD-214; almacenamiento local |
| PROD-241 | P2 | completada | L | PROD-214 y proyecciones de jobs/lifecycle |
| PROD-242 | P2 | completada | L | PROD-219 completada; coordinar con PROD-241 |
| PROD-243 | P2 | completada | M | PROD-221, PROD-223 y PROD-226 completadas |
| PROD-244 | P2 | completada | M | PROD-221, PROD-223 y PROD-226 completadas |
| PROD-245 | P2 | completada | S | PROD-239 completada |
| PROD-246 | P2 | completada | M | PROD-241; despliegue soportado continúa single-worker |
| PROD-247 | P2 | completada | S | PROD-216 y gate backend reproducible |
| PROD-248 | P2 | completada | L | PROD-242; coordinar stores autoritativos y PROD-241 |
| PROD-249 | P2 | completada | S | PROD-037, PROD-152 y PROD-155; suite CLI integrada y lock de test completo |

**Evaluación P3 del ciclo empresarial (2026-09-10):** no se promociona ninguna
de `PROD-222`, `224`, `227`, `228`, `232`, `236` o `237`. El repositorio no
contiene demanda autorizada para escapes Go ni versiones Composer avanzadas;
las evoluciones de Cargo/Composer/Gradle/NuGet exigen corpus oficial nuevo; y
CVSS v4 exige el corpus oficial FIRST y fronteras de redondeo. Bajo el ciclo
offline actual, implementar cualquiera implicaría inventar equivalencias o
declarar evidencia no revisada. Los subconjuntos actuales fallan cerrados.

**Evidencia PROD-159 (2026-09-10):** `inspectra scan
--cancel-on-interrupt` conserva el default de dejar el análisis remoto en curso
y solicita una sola cancelación owner/project/analysis-scoped únicamente tras
timeout o `Ctrl-C`. La admisión CI replayed nunca se cancela. Los estados cerrados
`confirmed_cancelling`, `confirmed_cancelled`, `not_confirmed`,
`skipped_replayed` y `not_requested` aparecen junto al enlace; 401/409 no
reemplazan los códigos 6/130 ni exponen el cuerpo del servidor. Pasaron 65/65
pruebas CLI offline, incluidas rutas HTTP, token, replay, timeout, interrupción y
salida JSON, más 2/2 backend para bearer/cancelación idempotente. `compileall`
pasó con caché temporal; el primer runtime incompleto quedó documentado: 22
pruebas no-Git pasaron y 19 no arrancaron por ausencia exacta de `git`; la suite
se repitió con Git y dependencias fijadas locales, sin Internet.

**Evidencia PROD-054 (2026-09-09):** importador administrativo offline con
contrato estricto `2026-09-09.1`, SHA-256 aportado fuera de banda, cuotas,
vigencia máxima de 30 días y publicación/rollback atómicos. Acepta únicamente
respuestas acotadas OSV/GHSA/NVD/CISA ya vinculadas a consultas exactas,
convierte identidades a claves digest y rechaza scopes npm privados, JSON con
claves duplicadas, feeds parciales, respuestas cruzadas, corrupción y
expiración. El backend con egress deshabilitado recorrió OSV y los tres
enriquecimientos desde un snapshot activo sin una petición HTTP; API/UI muestran
el ID y la frescura, y el runbook documenta que checksum no equivale a firma ni
a integración real. Validación Docker Python 3.12 con `--network none`:
backend 1.374/1.374 y runner 451/451; frontend 56 archivos/383 pruebas, build y
presupuesto 291,2/322 KiB; también pasaron `compileall`, Compose base,
privado, aceptación y aceptación-egress, y `git diff --check`. No hubo Internet,
tokens, proyecto real, push ni PR.

**Evidencia PROD-096 (2026-09-09):** contrato PVI `2026-09-09.3` con una matriz
cerrada de procedencia para once campos de decisión. Cada contribución conserva
proveedor, ID público, fecha disponible, estado y digest sin repetir valores ni
exponer proyecto; OSV sigue primario, GHSA puede corroborar/contradecir o estar
retirado, NVD participa en CVSS/CWE/fechas pero mantiene CPE `unmapped`, KEV solo
informa explotación conocida y el boletín allowlisted es apoyo. UI e informe
muestran la traza y no eligen ganador en `conflicting`; snapshots heredados la
reconstruyen en memoria. Regresiones cubren fix GHSA incompatible, retirada,
CVSS NVD distinto sin reemplazo, CPE, KEV y reporte. Pasaron 49 pruebas dirigidas,
backend completo 1.375/1.375 en Docker Python 3.12 `--network none`, frontend 56
archivos/383 pruebas, TypeScript/build y 291,2/322 KiB, `compileall`, Compose y
`git diff --check`. Runner 451/451 ya había pasado sin cambios en esa capa. No
hubo Internet ni integración real nueva.

**Evidencia PROD-061 (2026-09-09):** cada resultado nuevo se redacta y
normaliza antes de sellarse con un SHA-256 canónico ligado al contrato, job,
propietario, organización, proyecto, tipo de análisis y perfiles. La envolvente
permanece fuera del contrato público; la API solo expone `valid` o `unknown`.
Una discrepancia de resultado o identidad falla cerrada con `409` genérico antes
de validar el modelo, por lo que informes y comparaciones no consumen el dato;
los registros heredados sin sello siguen legibles pero nunca se presentan como
verificados. UI, informe y runbook explican el estado y que el digest no es una
firma frente a un atacante privilegiado. Regresiones cubren redacción previa,
reordenación JSON, manipulación de resultado/propietario, legado y metadato
malformado sin fuga de ruta. Pasaron 44 pruebas dirigidas y 1.380/1.380 pruebas
backend completas en Docker Python 3.12 con `--network none`; también
`compileall` con caché temporal, Compose base/privado/aceptación/egress y
`git diff --check`. Frontend completo (56 archivos/383 pruebas) y build
291,2/322 KiB ya habían pasado tras el cambio de UI; runner 451/451 permanece
sin cambios. No hubo Internet, push, PR ni despliegue.

**Evidencia PROD-099 (2026-09-09):** contrato PVI `2026-09-09.4`. Cada fuente
retiene estado, razón, tiempos, número de respuestas, SHA-256 del conjunto
ordenado de digests y, cuando aplica, el ID del snapshot offline; no se añade
otra copia de cuerpos, consultas ni identidad de proyecto. Cada revisión PVI se
sella sobre su representación normalizada, ID y fecha; la lectura vuelve a
calcular el checksum y una alteración falla cerrada antes de API, comparación o
informe. El legado sin sello queda `unknown`. UI e informe muestran checksum y
procedencia acotados. El importador offline rechaza ahora explícitamente una
reimportación y conserva la activación/rollback como operación separada.
Regresiones cubren corrupción, JSON reordenado, legado, reimportación, historial,
fuente offline y API owner-scoped. Pasaron 51 pruebas dirigidas, 1.383/1.383
backend y 56 archivos/383 pruebas frontend; build/presupuesto 291,2/322 KiB,
`compileall`, Compose base/privado/aceptación/egress y `git diff --check`.
Runner 451/451 permanece sin cambios. Todo se ejecutó sin Internet; no hubo
push, PR ni despliegue.

**Evidencia PROD-100 (2026-09-09):** se reconcilió la caché existente y se
cerró su hueco operativo. TTL y retención siguen evaluándose con reloj
inyectable: un proveedor caído puede reutilizar únicamente evidencia validada
dentro de retención, marcada `stale`; agotada esa ventana, el componente queda
`unavailable`, nunca limpio. Tres operaciones consecutivas con timeout, 429 o
indisponibilidad abren ahora un circuito local por proveedor durante 30 s; las
peticiones siguientes no abren socket y exponen la razón controlada
`provider_circuit_open`. Una respuesta válida tras el cooldown recupera el
circuito. UI/informe conservan fecha, expiración, digest y causa sin URL,
identidad ni diagnóstico bruto. Pruebas cubren fresco, stale, expirado, caída,
circuito y recuperación. Pasaron las pruebas dirigidas de egress/PVI/reporting,
1.385/1.385 backend completas sin red, 24 pruebas frontend dirigidas y build
291,2/322 KiB; la regresión frontend completa anterior del mismo cambio de UI
fue 56/383. También pasaron `compileall`, cuatro variantes Compose y
`git diff --check`. Runner 451/451 no cambió. Sin Internet, push, PR ni
despliegue.

**Evidencia PROD-094 (2026-09-09):** el contrato KEV
`2026-09-09.2` valida de forma estricta la raíz, las diez claves públicas de
cada entrada, `count`, `catalogVersion`, límites y fechas antes de permitir que
una respuesta entre en caché. Rechaza cambios de esquema y fechas futuras; un
catálogo con más de siete días se presenta como `provider_catalog_stale`. Si el
proveedor falla, conserva únicamente una señal exacta ya normalizada
(`known_exploited` o `not_listed`) con frescura degradada, sin reinterpretarla
como severidad ni crear vulnerabilidades: KEV sigue siendo enriquecimiento por
CVE previamente correlacionado. La caché validada sobrevive a reinicios dentro
de su retención y el circuito sigue siendo intencionadamente local al proceso.
Pasaron 138 pruebas dirigidas, la suite Python completa al 100 % (1.841 casos
recopilados, sin Internet), 56 archivos/384 pruebas frontend, TypeScript/Vite,
presupuesto inicial 291,2/322 KiB, `compileall`, Compose base/privado y
`git diff --check`.

**Evidencia PROD-188 (2026-09-08):** el contrato paginado owner-scoped usa
`POST /active/assets/search` con cuerpo cerrado y CSRF, 24 registros por defecto
y máximo 100. Los filtros de estado, capacidad, recencia y prefijo/exacto se
resuelven en servidor. El cursor HMAC process-local queda ligado a propietario,
filtros, cutoff y clave estable; manipulación, reutilización entre organizaciones
o cambio de filtro fallan de forma genérica, y una inserción concurrente no
duplica registros. La interfaz preserva filtros, registros y foco al continuar o
fallar y nunca coloca target/cursor en URL ni access log. Fixture de 2.005 activos
más segundo owner: 3,16 s, menos de 128 MiB y respuesta menor de 1 MiB. Revisión
visual 320/768/1440: 305/305, 753/753 y 1425/1425 px de client/scroll, controles
de 44 px y consola limpia. Pasaron backend 1.214/1.214 y tools 439/439 sin red,
frontend 337/337 con axe, build 281,5/322 KiB, Compose, compileall y diff-check.
Los recursos sintéticos fueron eliminados. El límite O(N) del store de ficheros
y la ruta heredada no acotada quedan trazados en PROD-193 y PROD-194.

**Evidencia PROD-192 (2026-09-08):** un fixture determinista y un runtime local
recorrieron 2.005 activos sintéticos. El DOM queda acotado a 24→48→72→96
tarjetas y después exige refinar filtros; búsqueda exacta recuperó el registro
2.005. Se corrigieron la carrera de respuestas antiguas, el render acumulativo
sin límite y el toggle ambiguo, ahora `Close details` con `aria-controls`.
Estados disabled/unavailable/degraded/ready se reprodujeron con configuración y
health contracts locales targetless; resumen parcial y error de continuación
son explícitos, el segundo conserva 24 tarjetas y devuelve el foco. En
320/768/1440, client/scroll fue 305/305, 753/753 y 1425/1425; sección
273/705/1.377, controles ≥44 px y geometría móvil idéntica antes/después del
refresh. Axe y la escala pasaron en 1,59 s aislado/3,66 s en suite (presupuesto
5 s); dirigidas 37/37, frontend completo 339/339 y build 281,5/322 KiB. Consola
limpia y recursos sintéticos eliminados. No hubo capacidad ni egress externo.

**Evidencia PROD-181 (2026-09-08):** alta JSON/CSV cerrada con 50 filas/128 KiB,
dry-run en memoria y token de cinco minutos ligado a actor, organización y bytes.
Cada fila queda lista, inválida, duplicada o ya registrada; cualquier corrección
bloquea todo el commit. La transacción usa lock, journal target-free, rollback,
recovery, IDs deterministas y replay exacto sin persistir original, filename,
token ni clave. Backup/restore valida recibos y el borrado de un miembro invalida
el replay completo. Un recorrido local real registró/reprodujo tres `.test`; la
matriz 320/768/1440 quedó contenida, con controles ≥44 px, axe y consola limpia.
El driver no pudo construir `DataTransfer`: el upload real se ejercitó por la API
local y el review interactivo con fixture de componente, límite registrado sin
convertirlo en éxito visual. Pasaron 91 dirigidas, backend 1.221/1.221 y tools
439/439 sin red, frontend 341/341, TypeScript/build 281,9/322 KiB, Compose base,
privado y Active, compileall y diff-check. Recursos sintéticos eliminados.

**Evidencia PROD-172 (2026-09-08):** contrato owner-scoped y target-free
`2026-09-08.1`, scheduler default-off, CRUD API/UI, cadencias de 7/14/30 días,
jitter estable 1–900 s, topes 500 políticas/organización y 16 vencidas/tick,
admisión idempotente y revalidación de revisión, última verificación, capacidad,
runner y cuotas. Renovación/revocación suspende; los intervalos perdidos colapsan
en uno. Borrado, backup/restore y auditoría quedaron integrados. Una revisión
visual encontró y corrigió la oferta duplicada en UI. Validación: backend
1.226/1.226 y tools 439/439 en Docker `--network none`; frontend 343/343,
TypeScript/build y bundle 283,0/322 KiB; compileall, Compose base/privado/Active
standalone y diff-check. Recorrido sintético local creó, persistió tras reinicio,
pausó y reanudó; 320/768/1440 sin overflow, controles 44 px y consola limpia.
No se ejecutó ninguna capacidad ni se contactó un objetivo/proveedor externo;
contenedores, imágenes, volumen, pestaña y datos sintéticos fueron eliminados.

**Evidencia PROD-190 (2026-09-08):** contrato recurrente `2026-09-08.2` con
zona IANA, ventana semanal cerrada, no-cruce de medianoche, DST explícito
(salto inexistente omitido; hora ambigua incluida una vez como ventana real),
jitter estable, backoff exponencial persistido de 5 min hasta 6 h + 0–60 s y
colapso sin catch-up. Próxima ejecución/reintento nunca se admite fuera de la
ventana o después de la autorización; legacy sin expiración se suspende hasta
reatestiguación. CAS y clave de ocurrencia estable cubren dos instancias. Logs
solo incluyen ID opaco, resultado cerrado, contador y estado de retry. Pasaron
8/8 dirigidas y 1.230/1.230 backend, 439/439 tools en Docker sin red; frontend
344/344 antes de los dos ajustes visuales y 21/21 dirigidas después, axe,
TypeScript/build y bundle 283,0/322 KiB; compileall con caché `/tmp`, Compose
base/privado/Active standalone y diff-check. Recorrido local sintético
crear→pausar→reiniciar→reanudar retuvo una política, cero jobs y un JSON
target-free de 1.168 B; no hubo capacidad ni egress. Se corrigieron el banner
UTC incompleto y la fecha engañosa al pausar. El viewport real 1.280 px quedó
sin overflow, controles 44 px y consola limpia; la API de viewport retuvo
1.280 pese a aceptar overrides, por lo que no se inventa una nueva matriz
móvil. Contenedores, volumen, red, imágenes, pestañas, token y temporales se
eliminaron y verificaron ausentes.

**Evidencia PROD-182 (2026-09-08):** el resumen Active `2026-09-09.2` expone
una cola owner-scoped de máximo 100 acciones, ordenada por urgencia y fechas,
con truncado/origen parcial explícitos y sin target, referencia, ruta, texto
libre ni datos de usuario. Solo el último estado por activo/capacidad queda
accionable; éxito posterior y triage cerrado eliminan el trabajo resuelto sin
borrar la comparación histórica. La UI añade prioridad/edad reproducibles desde
`generated_at`, preferencias locales, estados vacío/parcial/error y deep link
por ID opaco que abre el detalle owner-scoped y mueve el foco. Pasaron 14/14
pruebas backend dirigidas, 1.233/1.233 backend y 439/439 tools en Docker sin red,
21/21 frontend dirigidas y 347/347 completas con axe, TypeScript/build y bundle
inicial 283,0/322 KiB; compileall, Compose base/privado/Active y diff-check.
Revisión real sintética: cola→filtro vacío→detalle→recarga a 320/768/1.280 px,
sin overflow (305/305, 753/753, 1.265/1.265), controles 44 px y foco/hash
restaurados. El contrato vivo no contenía el target y los logs tampoco; no se
ejecutó capacidad ni egress. Recursos `inspectra-prod182-*` eliminados y el
stack preexistente quedó intacto. Intentos auxiliares sin imagen/dep offline o
con Compose incompleto no se cuentan como validación.

**Evidencia PROD-194 (2026-09-08):** el inventario estático confirma cero
consumidores propios de `listActiveAssets`; el cliente fue retirado y todas las
pruebas usan `POST /active/assets/search`. El `GET /active/assets` autenticado
es ahora un tombstone explícito `410`, marcado deprecated en OpenAPI, con
`Deprecation`, `Sunset`, enlace al sucesor y `no-store`; ignora parámetros y no
refleja entradas. La guía documenta cuerpo/cursor/CSRF y advierte que una URL
mal formada aún podría quedar en proxies previos. Regresiones cubren contrato,
cabeceras, OpenAPI, canario no reflejado y sesiones revocadas. Pasaron 4/4
dirigidas, backend 1.233/1.233 y frontend 347/347, TypeScript/build y bundle
282,8/322 KiB; tools 439/439 sin red permanecen válidas. Uvicorn real recibió
alta, búsqueda exacta por cuerpo y tombstone: sus tres logs solo mostraron rutas
fijas, nunca el canario. Contenedor y datos `inspectra-prod194-*` eliminados.

**Evidencia PROD-201 (2026-09-08):** el esquema privado v4 ya resuelve el
conteo global, la existencia owner/proyecto, los IDs opacos de recuperación y
el último análisis completado mediante SQL parametrizado. Los conteos y la
readiness cargan cero JSON; el último análisis carga exactamente uno y el
historial de activo como máximo 500, siempre con validación de owner, relación y
digest. El fixture de 20.000 jobs/dos propietarios verificó resultados exactos,
columnas sin target/fuente/resultado/autorización y p95 warm <250 ms. La primera
suite completa se detuvo tras 264 casos por una doble adquisición reproducible
del lock en admisión; se separó el helper para llamadores que ya poseen el lock.
La segunda terminó 1.253/1.254 al revelar un fixture legacy que escribía JSON
por fuera del store; el fixture ahora reproduce la resincronización obligatoria
de una restauración/migración aprobada. La tercera alcanzó 1.254/1.254 sin
fallos; también pasaron las pruebas dirigidas, `compileall` y diff-check, sin
red. Frontend permanece sin cambios y conserva 354/354+axe y build
285,0/322 KiB de PROD-200.

**Evidencia PROD-202 (2026-09-08):** el esquema v5 selecciona por índice todos
los estados `queued/running/cancelling` en orden estable y abre exactamente un
JSON por candidato; recuperación, reanudación Active/proyecto y protección de
fuentes ya no recorren jobs terminales. Los `file_id` se derivan del registro
validado, no se añaden al índice. Un marcador cerrado del estado del directorio
permite a un proceso nuevo adoptar el SQLite `0600` tras validar esquema,
integridad y coincidencia; mismatch/restauración reconstruye y JSON inválido
falla cerrado. El fixture de 20.000 jobs prohíbe `glob`, reinicia el store,
carga 4 candidatos por operación y exige p95 warm <500 ms. Pasaron 6/6 del
índice, 32/32 de índice+backup+retención+ciclos de arranque, 9/9 de recuperación
de lifecycle y backend completo 1.254/1.254; el único helper interno de cuota
modificado después pasó su regresión de carrera. `compileall` y diff-check
correctos, sin red. Frontend permanece sin cambios (354/354+axe; build
285,0/322 KiB).

**Evidencia PROD-203 (2026-09-08):** preview y orphan-check usan una consulta
exhaustiva del índice por activo, distinta de la ventana UI de 500. Cada fila se
valida contra owner, activo y digest antes de preparar el journal; una colisión
cross-owner falla cerrada. El fixture de 20.000 jobs conserva 1.000 del agregado,
prohíbe `glob`, exige p95 warm <500 ms y comprueba lecturas proporcionales. Las
pruebas de borrado cubren recuperación interrumpida y cero residuos. Pasaron
15/15 dirigidas y backend completo 1.255/1.255; `compileall` y diff-check
correctos, sin red. Frontend permanece sin cambios (354/354+axe; build
285,0/322 KiB).

**Evidencia PROD-204 (2026-09-08):** el índice de verificaciones v3 ofrece un
historial exhaustivo owner/activo en orden estable y valida cada JSON por owner,
activo y digest. Inicio de challenge, rate-limit, supersession, preview y borrado
usan esa consulta; latest conserva su selección acotada. Un marcador fuente
cerrado permite adoptar el SQLite `0600` tras reinicio solo si esquema,
integridad y estado coinciden; mismatch reconstruye y corrupción falla cerrada.
El fixture de 10.000 verificaciones/dos owners reinicia el store, prohíbe glob
de la organización, carga 101/10.000 registros y exige p95 warm <500 ms. Pasaron
33/33 dirigidas y backend completo 1.255/1.255; `compileall` y diff-check
correctos, sin red. Frontend permanece sin cambios (354/354+axe; build
285,0/322 KiB).

**Evidencia PROD-205 (2026-09-08):**
`POST /active/assets/{asset_id}/executions/search` pagina 50/100 ejecuciones con
un total exacto fijado por el corte inicial y un cursor HMAC ligado a
propietario, activo, filtros, corte y posición; una inserción concurrente más
reciente no modifica ese universo. La selección directa devuelve solo
`JobListItem` y normaliza activo/job ajeno a `404`. Postura carga la ventana
reciente, declara el cálculo acotado a 500 y resuelve una baseline antigua de
forma directa; informe y exportación usan la selección completa del activo, y
el bundle declara 505 ejecuciones del periodo, 100 incluidas y truncado exacto.
Revocar un activo con 501 jobs vivos los cancela todos mediante el índice. Los
fixtures de escala cubren 20.000 jobs, 1.001 del activo, dos propietarios,
cursor manipulado/transferido, inserción concurrente, baseline >500 y lecturas
proporcionales. Pasaron backend 1.257/1.257, frontend 355/355 con axe, pruebas
CSS 19/19, build 285,2/322 KiB, `compileall` y diff-check, sin Internet. La
revisión local cargó 50→52 y el estado vacío a 320/768/1440 px, conservó foco,
controles de 44 px y consola limpia. Se corrigieron pérdida de foco al terminar,
total inestable entre páginas y 16 px de overflow móvil. Servicios y datos
sintéticos fueron eliminados.

**Evidencia PROD-206 (2026-09-08):** el índice privado schema v6 añade índices
parciales por fecha y propietario para seleccionar solo jobs
`completed/failed/cancelled` vencidos, en orden estable y lotes de 100 (máximo
500). Cada JSON se valida por owner, estado, `updated_at` y digest; después del
callback se exige el mismo digest antes de borrar. Un fallo deja el job
reintentable y una mutación concurrente a `running`, un job vivo antiguo, una
inserción reciente y un vencido de otro owner permanecen intactos. El fixture
reiniciado de 20.000 jobs prohíbe `glob`, selecciona 137 elegibles como 100+37,
elimina 136 tras la carrera, exige p95 <500 ms por lote y pico <32 MiB, con dos
lecturas autoritativas por candidato. Pasaron índice+retención 11/11 y backend
completo 1.258/1.258 (código 0), `compileall`, CSS 19/19 y diff-check, sin red.
Frontend no cambió y conserva 355/355+axe y build 285,2/322 KiB de PROD-205.

**Evidencia PROD-207 (2026-09-08):** active-job-index schema v7 proyecta solo un
SHA-256 con separación de dominio de `file_id` y el bit cerrado
`source_deleted`; no conserva la referencia cruda. La selección acepta hasta
500 referencias y devuelve lotes de 100, owner-scoped cuando corresponde. En el
fixture reiniciado de 20.000 jobs, 137 relaciones se marcaron como 100+37 con
dos lecturas autoritativas por candidato; el job de otro owner quedó intacto,
`glob` estuvo prohibido y ninguno de cuatro IDs de fuente apareció en SQLite.
Una interrupción inyectada tras la primera de tres escrituras se reanudó con las
dos pendientes. Pasaron 35/35 pruebas dirigidas y backend 1.258/1.258 con código
0; también `compileall` y diff-check, sin red. Frontend permanece sin cambios y
conserva la validación de PROD-205.

**Evidencia PROD-208 (2026-09-08):** el nuevo índice privado de proyectos schema
v1 guarda solo project ID, owner, digest de registro y digests separados por
dominio de baseline/fuentes; nombres, SHA de contenido e IDs crudos no aparecen.
Las limpiezas seleccionan 100 proyectos por lote y validan owner, relación y
digest dentro del lock antes de cada escritura. El fixture reiniciado de 5.000
proyectos/dos owners procesó 137 como 100+37, preservó el proyecto extranjero,
prohibió `glob`, exigió p95 <500 ms y pico <32 MiB, y tras una interrupción 1/3
reanudó exactamente dos pendientes. Backup/restore valida las nuevas columnas
del índice de jobs y las tres tablas del índice de proyectos; alteraciones de
digest/estado se rechazaron antes de reconstruir desde JSON. Pasaron 29/29
dirigidas y backend 1.259/1.259 con marcador y código explícitos 0, además de
`compileall` y diff-check, sin red. La primera suite también llegó al 100 %, pero
su handle desapareció antes de capturar el exit y no se cuenta como aprobada.

**Evidencia PROD-209 (2026-09-08):** el índice privado de fuentes schema v1
proyecta solo file ID opaco, owner, fecha, nombre almacenado cerrado y digest de
metadato; no contiene nombre original, SHA de contenido ni bytes. El fixture
reiniciado de 10.000 fuentes/dos owners prohibió `glob`, conservó fuentes
protegidas estática y dinámicamente y la fuente extranjera, y eliminó 135
elegibles en lotes 100+36. La comprobación final de protección, callbacks de
jobs/proyectos, revalidación y borrado comparten un único lock con helpers
lock-owned; un callback fallido conserva la fuente. Se exigieron p95 <500 ms,
pico <32 MiB y ausencia de dos canarios sensibles en SQLite. Backup rechazó una
fila manipulada y el store la reconstruyó desde JSON autoritativo. Pasaron 32/32
dirigidas y backend 1.260/1.260 con marcador y código explícitos 0, además de
`compileall` y diff-check, sin red. Frontend no cambió y conserva 355/355+axe y
build 285,2/322 KiB de PROD-205.

**Evidencia PROD-210 (2026-09-09):** el índice de recurrencia schema v1 contiene
solo organization/asset/schedule IDs opacos, estado, próxima ejecución/reintento
y digest de registro; su esquema exacto y los canarios verifican que no copia
target, capacidad/puerto, actor, verification ID ni material de autorización.
Cada candidato se carga y valida contra JSON, owner, activo, estado, fechas,
digest y ventana antes del dispatch. Fixture reiniciado: 10.000 políticas/20
organizaciones, 16 vencidas y agregado de 101; sin recorrido de directorio de
organización, p95 <500 ms, pico <32 MiB, aislamiento y borrado exacto. Dos ticks
sincronizados produjeron un único job durable y una sola transición CAS. Backup
rechazó `status` manipulado y el store reconstruyó desde JSON. Pasaron 38/38
dirigidas y backend 1.262/1.262 con salida 0, `compileall` y diff-check sin red.
La primera ejecución completa llegó al 100 % pero su wrapper usó la variable
reservada zsh `status`; no se contó y se repitió con marcador correcto.

**Evidencia PROD-211 (2026-09-09):** el contrato `2026-09-09.1` ofrece un
preflight target-free y una exportación confirmada Markdown/JSON con el mismo
digest, corte reproducible y límites de 500 activos, 2.000 jobs, 100 acciones,
100 recurrencias y 1 MiB. Solo maintainer/admin exporta; reader puede revisar el
preflight sin descargar. El informe excluye notas, referencias/digests de
autorización, retos, identidades, rutas, resultados crudos y respuestas de
runner; el evento de auditoría conserva únicamente formato y periodo. La
revisión visual reproducible a 320/768/1440 corrigió la exposición CORS del
digest, el wrap del consentimiento y mensajes de red; el resultado quedó sin
overflow, con controles de al menos 44 px, consola limpia y estados
ready/parcial/vacío/error. Pasaron 1.704/1.704 pruebas backend (253,98 s;
224.120 KiB), 361/361 frontend con axe, build 286,2/322 KiB, dirigidas 14/14,
`compileall`, Compose y diff-check, todo sin Internet. Fixture y servicios
locales fueron eliminados y los puertos quedaron cerrados. La reauditoría no
encontró otra P0/P1 desbloqueada del alcance Active; `PROD-212` queda pendiente
P2 como recibo target-free y `PROD-180` conserva su refuerzo P2. No se altera
ninguna tarea bloqueada.

**Evidencia PROD-212 (2026-09-10):** el contrato `2026-09-10.1` permite a
maintainer/admin registrar `reviewed` o `follow_up_required` sobre el digest y
corte vigentes del informe semanal, mientras reader solo consulta y verifica.
El store privado conserva como máximo 52 recibos/400 días por organización,
con revisión CAS, idempotencia y HMAC separado por dominio; no persiste digest
crudo, target, notas, identidades ni resultados. Verificación offline, purga,
backup/restore, auditoría mínima y fallo cerrado ante clave, permisos, symlink,
integridad o almacenamiento inválidos quedaron integrados. Las regresiones
cubren roles, dos organizaciones, replay/carrera, estado obsoleto, retención,
restore y canarios. Un recorrido local sintético registró dos recibos, verificó
uno tras reinicio y ejercitó historia/loading/vacío/error a 320/768/1440; se
corrigió la cuadrícula móvil y no hubo overflow ni errores de consola. La
validación descubrió un deadlock reproducible por lock anidado y dos
expectativas exhaustivas obsoletas (allowlist reader y clases de retención): se
añadió reentrada acotada al mismo hilo/path y se actualizaron las pruebas sin
relajar controles. Pasaron 256/256 pruebas Active dirigidas, 868/868 de
`test_backend.py`, la colección integral backend+tools de 2.051 pruebas con
salida 0 (316,32 s; 30.208 KiB RSS del proceso Docker), 419/419 frontend con
axe y el build (302,5/322 KiB), además de `compileall`, Compose base/privado/
Active y `git diff --check`, todo sin red. Servicios y datos sintéticos fueron
eliminados; los bloqueos protegidos permanecen intactos.

**Evidencia PROD-200 (2026-09-08):** los cuatro paneles especializados usan
páginas de 50 y continuación explícita; un endpoint GET owner/project-scoped
resuelve una selección retenida y devuelve solo `JobListItem`, nunca el resultado
completo. Comparación incorpora directamente una línea base guardada fuera de
la primera página; IDs inexistentes, de otro proyecto u otro propietario son el
mismo 404. Fixtures de 52/105 análisis cubren página 51+, baseline antigua,
deduplicación, cursor solo en cuerpo, selección de hallazgos/inventario/
inteligencia y fallo 503 recuperable sin perder opciones; seleccionar inteligencia
antigua no dispara OSV/GHSA/KEV. Pasaron 45 pruebas frontend dirigidas, una API
dirigida más controles de auth, backend 1.254/1.254 y frontend 354/354 con axe;
TypeScript/build quedó en 285,0/322 KiB, `compileall` y diff-check correctos. El
recorrido local real llegó de 50/51 a 52/52 en los cuatro paneles y seleccionó
el análisis 1. La revisión visual detectó 11 px de overflow interno a 320 px y
lo corrigió; la matriz final 320/768/1440 no mostró overflow, los controles
midieron 44 px y la consola quedó limpia. El primer fixture, fuera de retención,
se descartó y repitió correctamente. No hubo egress; pestaña, servicios, puertos,
datos y temporales se eliminaron y verificaron ausentes.

**Evidencia PROD-199 (2026-09-08):** la proyección privada de jobs usa esquema
v4 y añade únicamente `project_id` opaco a sus campos cerrados. Los contratos
`POST /jobs/search` y `POST /projects/{project_id}/analyses/search` admiten 50
registros por defecto y 100 como máximo, filtros cerrados y cursor HMAC ligado
a propietario, filtros y corte; un cursor manipulado, reutilizado por otro
propietario o con filtros distintos falla genéricamente. El orden estable
`created_at, id` evita duplicados al insertar trabajo nuevo. Cada página carga
y valida solo sus JSON seleccionados; un fixture de 20.000 jobs/dos propietarios
verificó total exacto, aislamiento y p95 cálido <500 ms. Ambos GET heredados
quedan acotados a 100 con deprecación, `no-store` y enlace al sucesor. Portada y
proyecto muestran cargados/total, continúan sin reemplazar filas y devuelven el
foco; la revisión local 50→51 a 320/768/1440 midió 305/305, 753/753 y 1425/1425
px, controles ≥44 px y consola limpia. El review detectó objetivos de 36 px y
los corrigió. Pasaron 26 pruebas dirigidas, la regresión de seguridad 10/10,
backend 1.254/1.254, frontend 350/350 con axe, TypeScript/build (284,8/322 KiB),
`compileall` y diff-check. No hubo red; servicios, puertos y fixture temporal se
eliminaron. Un intento con `pytest` fuera del entorno no ejecutó casos y la
suite se repitió con Python 3.12 y dependencias bloqueadas.

**Evidencia PROD-198 (2026-09-08):** la proyección privada de jobs usa esquema
v3 e incluye todos los trabajos para contar de forma exacta los estados
`queued/running/cancelling`; para Active añade únicamente activo opaco y clave
de idempotencia ya derivada por SHA-256. Las cuotas generales y las cuatro
dimensiones Active consultan agregados bajo el mismo lock de alta; el replay
owner-scoped carga y valida como máximo un JSON. Fixture determinista de 20.000
jobs/dos propietarios confirmó tres trabajos globales en curso, separación de
los dos Active, cero lecturas JSON para cupos, exactamente una por replay y p95
cálido <250 ms. El esquema comprobado no contiene target, autorización,
resultados ni clave cruda. Pasaron 92/92 pruebas dirigidas de índice, Active y
backup, y 1.252/1.252 backend completas; `compileall` y `git diff --check`
correctos. Frontend 348/348+axe, build 282,8/322 KiB y tools 439/439 continúan
válidos desde `PROD-197` al no cambiar esas capas. Todo se ejecutó sin red.

**Evidencia PROD-197 (2026-09-08):** contrato summary `2026-09-09.4` y estrategia
`priority_then_recency`: autorización expirada, última verificación/ejecución
fallida, próxima caducidad y último resultado degradado preceden el relleno por
recencia. El éxito más nuevo suprime el fallo antiguo, owner ajeno no influye y
el conjunto sigue limitado a 500 activos/2.000 jobs/500 verificaciones. Una
autorización no vigente o capacidad retirada ya no ofrece retry/reverificación
imposible; conserva renovación y evidencia histórica. Fixtures >500 prueban
orden/truncado estable y señales antiguas. Recorrido local con 503 activos
mostró primero expiración y fallo de 20 días; 320/768/1440 midieron
305/305, 753/753 y 1425/1425 sin overflow, controles ≥44 px y consola limpia.
Backend 1.251/1.251 en 64,31 s, frontend 348/348+axe, build 282,8/322 KiB,
tools 439/439, Compose base/privado/aceptación y diff-check pasaron sin red.
Backend, Vite, índices y fixture temporal fueron eliminados; no hubo capacidad
Active, target externo, push, PR, tag, release ni despliegue.

**Evidencia PROD-196 (2026-09-08):** el resumen obtiene contadores exactos de
activos y total de jobs Active desde proyecciones SQLite privadas `0600`, con
límite de 256 MiB y JSON como autoridad. Materializa como máximo 500 activos,
2.000 jobs y una última verificación por activo; cada JSON seleccionado se
valida contra owner, relación y digest. La disponibilidad de admisión dejó de
releer el historial. Mutaciones, borrado, otro proceso, corrupción y reinicio
sincronizan o reconstruyen; JSON/topología insegura falla cerrado. Readiness y
backup validan versión, tablas exactas, filas/digests y restore de los tres
índices. Fixtures de dos owners con 10.005 activos, 20.000 jobs y 10.000
verificaciones limitan lecturas a 500/2.000/500, p95 warm <1 s y pico <128 MiB.
La UI distingue totales exactos de detalle operativo acotado. Validación final:
backend 1.247/1.247 en 69,91 s, tools 439/439, frontend 348/348 con axe, build y
bundle inicial 282,8/322 KiB, `compileall`, Compose base/privado/aceptación y
`git diff --check`. Una primera invocación de Compose de aceptación no validó
nada por faltar `INSPECTRA_ACCEPTANCE_DATA_DIR`; se registró y se repitió con
las variables obligatorias. No hubo red, capacidad Active ni objetivo externo.

**Evidencia PROD-193 (2026-09-08):** SQLite actúa como índice derivado privado
`0600` (máximo 256 MiB); los JSON Active siguen siendo la fuente de verdad. La
primera operación/readiness migra o reconstruye desde JSON, y todas las
mutaciones lo sincronizan bajo el lock cross-process. La consulta exacta,
prefijo, estado, capacidad, recencia y cursor solo selecciona IDs owner-scoped;
cada JSON devuelto se relee y verifica por digest. Divergencia, versión antigua,
DB corrupta, escritura interrumpida y artefactos SQLite huérfanos se reparan;
JSON autoritativo inválido o permisos amplios fallan cerrado. Backup verifica
filas/capacidades/digests y restore reconstruye. La regresión con 10.005 activos
de dos owners exige p95 local <500 ms, memoria <128 MiB y como máximo 101 JSON
leídos por página de 100; pasó junto con carreras, reinicio, alta, renovación,
asignación, admisión, baseline, triage, revocación y borrado. Suite backend
final 1.240/1.240, tools 439/439, frontend 348/348, build 282,8/322 KiB,
`compileall`, Compose base/privado/aceptación y `git diff --check`, sin red.
La primera pasada final no ejecutó ningún caso: colección detectó un
`SyntaxError` por un paréntesis omitido en `index_ready`; se corrigió y se
repitió desde cero. Otra pasada verde tardó ~215 s por reconstrucción eager en
cada fixture; el índice pasó a inicialización lazy segura y la pasada final
completó el 100 % en ~50 s. Ninguna de esas pasadas parciales se contó como
validación superada.

**Evidencia PROD-195 (2026-09-08):** el alta individual y masiva comparte ahora
una exclusión atómica owner-scoped: rechaza una identidad canónica ya existente,
incluidos registros ocultos por borrado, y bloquea toda admisión mientras una
eliminación de esa organización permanece interrumpida. Dos stores concurrentes
solo admiten una alta; la recuperación del journal desbloquea una nueva identidad.
Los duplicados heredados se conservan, bloquean un duplicado adicional y se
exponen solo como contadores agregados en operaciones (`contract_version`
`2026-09-08.3`), con aviso accesible y sin identidad/target. Pasaron 23 pruebas
dirigidas, 8/8 de borrado, 64/64 del store Active y la suite backend completa
1.237/1.237; tools 439/439, frontend 348/348, build 282,8/322 KiB,
`compileall`, Compose base/privado/aceptación con valores sintéticos y
`git diff --check`. La prueba de cartera conserva 2.005 identidades válidas en
lotes de 50 (17 s) y deja el coste de indexación durable en `PROD-193`. No hubo
egress ni cambios en las tareas bloqueadas.

**Evidencia PROD-189 (2026-09-08):** contrato `2026-09-08.1` con preflight
explícito y descargas JSON/CSV exclusivamente administrativas, periodos fijos de
7/30/90/365 días, filtro de activo owner-scoped, selección máxima de 1.000
eventos y respuesta máxima de 1 MiB. Evento, actor y recurso son seudónimos
estables ligados a la organización; solo pasan rol, acción/resultado cerrados y
coordenadas de revisión válidas. Target, referencia, notas, IP, correlación,
metadata y evidencia quedan fuera. Dos organizaciones, lector denegado,
truncado, recurso desconocido, periodo/formato inválidos, vacío y errores tienen
regresión. En una instancia privada sintética, preflight + JSON 991 B + CSV
840 B conservaron un evento y cero de seis canarios. La matriz visual
320/768/1440 quedó contenida; selects, botón y enlaces miden 44 px después de
corregir 19/19/36 px, sin errores de consola. El panel queda disponible también
al administrador único autenticado. Pasaron backend 1.211/1.211 y tools
439/439 en Docker `--network none`, frontend 335/335+axe, TypeScript/build
281,1/322 KiB, Compose base/privado/Active standalone y `git diff --check`.
Cookies, descargas, datos, contenedor, puertos y capturas sintéticas fueron
eliminados. Contrato y límites documentados en `docs/product-audit.md`,
`docs/active-operations.md`, arquitectura, retención y revisión visual.

**Evidencia PROD-148 (2026-09-09):** contrato cerrado `2026-09-09.1`, store
owner/org-scoped y API interactiva registran un único dominio/host/IP/origen
canónico con capacidades, protocolos, puertos, autorización de hasta 366 días,
responsables, notas estructuradas y timeline append-only. Wildcards, CIDR,
userinfo, paths/query, credenciales y notas con patrones sensibles fallan antes
de persistir. La UI incorpora centro Active, alta guiada, búsqueda, filtros,
estados carga/vacío/error, detalle y revocación inmediata; lectores quedan en
solo lectura. Validación: backend dirigido 25/25 (incluye dos organizaciones,
expiración y material sensible), frontend 65/65 con App y axe, TypeScript sin
errores. Contrato y límites en `docs/active-operations.md`; no hubo tráfico de
red, targets externos, push ni PR.

**Evidencia PROD-149 (2026-09-09):** la ruta única
`POST /active/assets/{id}/executions` solo admite capacidad, puerto TLS opcional
y reconfirmación literal; el servidor deriva target/perfil, revalida autorización
al admitir y antes del adaptador, limita DNS sin AXFR/subdominios y persiste
asset/contrato con target redactado. Revocar durante Nmap cancela la espera y
produce estado terminal auditable. Las rutas live con target libre están
retiradas por defecto mediante un opt-in de compatibilidad separado, y la UI ya
no renderiza sus formularios. Backend Active: 506/506 al 100 % en 9,55 s
(incluye 7 del vertical); frontend App+centro 56/56 y TypeScript.
Una primera ejecución se alargó por contaminación real de estado global desde
el fixture de revocación; se detuvo, se aisló al atributo exacto y se corrigió
con restauración automática de `monkeypatch`, tras lo cual la repetición pasó.
Sin targets externos ni red.

**Evidencia PROD-150 (2026-09-09):** `active_posture.py`, las rutas de postura
y el centro Active ofrecen timeline y comparación owner/org-scoped únicamente
entre ejecuciones terminales de la misma capacidad y contrato. Un baseline
explícito o las dos últimas ejecuciones comparables producen señales acotadas
de puertos, DNS, cabeceras HTTP y TLS con cobertura, errores, truncado e
incompatibilidad visibles. La interfaz mantiene la frontera semántica:
“nuevo”, “persistente”, “cambiado” o “desaparecido” son observaciones y no
demuestran una vulnerabilidad ni su resolución. Validación: 439/439 pruebas
backend Active seleccionadas, 5/5 del centro frontend y `tsc --noEmit`; sin
red ni objetivos externos.

**Evidencia PROD-169 (2026-09-09):** cada activo admite seleccionar un baseline
compatible, guardar triage estructurado (`needs_review`, `accepted`,
`investigating` o `dismissed`) y exportar un informe Markdown owner-scoped. El
informe incluye autorización, cobertura, comparabilidad y diferencias acotadas,
sin comandos, salida cruda ni elevar observaciones a vulnerabilidades. Las
regresiones backend cubren baseline, triage e informe; el frontend cubre el
recorrido completo y descarga con credenciales de sesión. Comparte la evidencia
de validación 439/439 backend, 5/5 frontend y TypeScript correcto de PROD-150.

**Evidencia PROD-170 (2026-09-09):** la verificación de control está desactivada
por defecto y separada de la autorización. El contrato ofrece atestación manual,
TXT fijo, HTTP `/.well-known/inspectra-verification` y una frontera para un
adaptador privado gestionado. El token se muestra una vez; solo persiste su
SHA-256, con TTL 15 minutos, cinco retos/hora y vigencia máxima de 90 días sin
superar la autorización. HTTP fija la conexión a la IP global prevalidada para
evitar una segunda resolución, no sigue redirects y limita 3 s/512 bytes; los
resultados crudos no se almacenan. Pasaron 18/18 pruebas específicas, 539/539
de configuración/Active/auditoría, 6/6 frontend, TypeScript y axe. El flujo
sintético local terminó en `verified`; a 320/768/1440 no hubo overflow, los
controles midieron al menos 44 px y la consola quedó limpia. Sin red externa.

**Evidencia PROD-171 (2026-09-09):** el endpoint agregado owner/org-scoped y el
centro Active muestran autorizaciones, caducidad, control opcional, ciclo de
jobs, cambios comparables, configuración booleana y acciones pendientes sin
objetivos, IDs ni evidencia cruda. El resumen se limita a 500 activos/2.000
jobs y publica estado parcial; su fallo no bloquea la lista ni las acciones por
activo. Filtros de estado, capacidad y antigüedad, carga/vacío/error/parcial,
detalle expandido, roles y métodos compatibles quedan cubiertos. Pasaron 20/20
pruebas backend dirigidas, 8/8 frontend, axe y TypeScript. Revisión local con
un único `.test`, capacidades live deshabilitadas y cero red: documento sin
overflow a 320/768/1440 (`305/753/1425` px), tarjeta expandida igual a su grid
(`241/673/1326` px) y controles >=44 px. Contrato y registro reproducible en
`docs/active-operations.md` y `docs/frontend-visual-review.md`.

**Evidencia PROD-174 (2026-09-09):** la primera reauditoría en modo
`private_team_lightweight_users` reprodujo un 422 al alta porque `team-admin`
no cabía en el patrón de actores. Se separaron los espacios de nombres:
`team-admin` es válido exclusivamente como actor/owner/responsable, mientras
organizaciones siguen limitadas a `local-admin` o 32 hex. La repetición completó
login, alta, reto manual, dos ejecuciones DNS simuladas, postura, baseline,
triage, informe, lectura y denegación de escritura reader, revocación y 409
posterior en 0,79 s; ningún password ni challenge apareció en JSON persistido.
Una regresión dedicada rechaza además actor, responsable y organización
arbitrarios. Sin red externa.

**Evidencia PROD-175 (2026-09-09):** la reauditoría detectó que DNS inventory,
DNS OSINT, HTTP headers y TLS aún abrían red desde el backend. Las cuatro
capacidades registradas cruzan ahora rutas/perfiles fijos de `active-tools`, sin
fallback, con doble opt-in, destino interno validado, 8 s/256 KiB/cuatro
llamadas, sin redirects y con rechazo de target/salida cruda. Revocar cancela
la petición y persiste estado `cancelled` redactado. Pasaron 29/29 regresiones
dirigidas, 427/427 de tools y 1.150/1.150 de backend en contenedores sin red;
ambas configuraciones Compose, la importación ASGI y enumeración de rutas de la
imagen bajo read-only/network-none y `git diff --check` pasaron. Imagen local
efímera:
`sha256:7f1d04b3fc4898123b0f45fcea909ba7074ee31977f26f19e4686e0b5e288b56`.

**Evidencia PROD-185 (2026-09-08):** cada alta crea una revisión append-only
con ID, secuencia y digest SHA-256 ligados al activo y alcance estructurado; los
jobs conservan esos tres campos y las actualizaciones posteriores no pueden
reemplazarlos. La segunda lectura previa al runner exige la misma revisión y
falla con `409` si cambió. Registros históricos sin revisión permanecen
`legacy / unknown`, se muestran como tales y no ejecutan hasta reatestiguarse.
Postura, comparación, auditoría mínima, UI e informe trazan la revisión sin
exportar el objetivo exacto. Pasaron 25/25 pruebas Active/postura iniciales,
31/31 Active/postura/auditoría tras el último ajuste, la suite backend completa
de 1.155 casos, frontend 321/321, build/TypeScript y presupuesto de bundle
(278,9/322 KiB), todo sin red. La revisión local a 1440 y 320 px confirmó cero
overflow global; la tabla móvil queda acotada a scroll horizontal y el estado
legacy no ofrece botón de ejecución. Datos y contenedores sintéticos fueron
eliminados. `SEC-012`, `PROD-129`, `PROD-130` y `PROD-167` siguen bloqueadas y
sin cambios.

**Evidencia PROD-176 (2026-09-08):** `POST /active/assets/{id}/renew`
añade bajo lock una revisión inmutable y una sola entrada de historial, con
clave privada de idempotencia, comparación optimista de la revisión vigente y
conflicto cerrado ante carreras o reutilización con otro contenido. La revisión
conserva si hubo ampliación, incluso tras eventos posteriores. Caducados solo
vuelven mediante reatestiguación; revocados nunca se reactivan; toda capacidad,
protocolo o puerto añadido exige confirmación separada y la vigencia máxima es
366 días. API, auditoría, informe y UI omiten target, referencia y cuerpo en la
telemetría exportable. Pasaron 39 pruebas dirigidas, la suite Python completa
de 1.590 casos en contenedor read-only/sin red, frontend 322/322 y TypeScript.
El build aislado produjo un bundle inicial de 285.825 bytes dentro del límite
de 322 KiB. El recorrido real sintético registró, amplió y renovó en localhost;
la revisión visual a 320/1440 px confirmó el historial `r1/r2`, la confirmación
específica y cero overflow en el módulo. Viewport, datos, contenedor y build
temporales fueron eliminados. El primer comando de pruebas con un `.venv` sin
pytest y la caché Vite root-owned no ejecutó casos; la repetición canónica en
contenedor y con `configLoader=runner` es la evidencia válida.

**Evidencia PROD-177 (2026-09-08):** alta y renovación validan hasta 20
responsables contra los miembros activos de la organización actual; en modo
local solo admiten al operador vigente. Administrador, mantenedor y lector son
asignables, pero la responsabilidad no altera permisos y un lector asignado
continúa recibiendo `403` al escribir. IDs inexistentes, revocados y de otra
organización producen el mismo `422` sin eco; los modelos persistidos rechazan
identidades malformadas. La UI obtiene el directorio owner-scoped, permite
selección accesible, preserva la asignación si el directorio falla y no incluye
identidades en revisión, informe o auditoría. Pasaron 43 pruebas dirigidas de
Active/identidad/auditoría, la suite Python 1.593/1.593 sin red, frontend
323/323, TypeScript y build (285.917 bytes/322 KiB). Un recorrido real local en
modo equipo creó admin, maintainer y reader, asignó al lector y verificó DOM sin
identidades ajenas; 320 px mantuvo 273/273 px y 1440 px 1.425/1.425 px. Se
eliminaron contenedor, sesiones, base SQLite, activo y credenciales sintéticas.

**Evidencia PROD-180 (2026-09-10):** la política opcional de cuatro ojos queda
desactivada por defecto y solo se habilita en modo de equipo privado. Alta,
ampliación, renovación y revocación ordinaria exigen una solicitud ligada al
digest exacto, aprobación de un administrador distinto y consumo de un solo
uso por el solicitante original; expira en 24 horas y un reinicio interrumpe
cualquier aplicación en curso sin replay. La revocación urgente `security_hold`
permanece disponible al administrador y auditada; los lotes se bloquean cuando
la política está activa. Los estados terminales eliminan target y payload,
quedan acotados a 90 días y el lector no puede enumerar aprobaciones. Backup,
restore, retención y borrado Active cubren el nuevo store privado `0600`.
Durante el recorrido local se corrigieron el header CORS específico y la
recarga obsoleta tras consumir una aprobación. Pasaron 2.044/2.044 pruebas
Python en 76 archivos bajo Docker sin red (`496,07 s`, pico 30.264 KiB),
416/416 frontend en 59 archivos, build/budget 301,8/322 KiB, `compileall`,
Compose base/privado/Active autónomo y `git diff --check`. La revisión visual
real recorrió alta, renovación y revocación a 320/768/1440 sin overflow ni
errores de consola; el reinicio conservó un activo revocado y tres aprobaciones
consumidas sin targets. Store/auditoría no contenían canarios y contenedor,
datos, cookies, puertos y credenciales sintéticas fueron eliminados. No hubo
capacidad Active, proveedor, egress, proyecto real, push, PR ni despliegue.

**Evidencia PROD-191 (2026-09-08):** la baja administrativa incorpora un
preflight agregado sin targets ni identidades, invalida primero todas las
sesiones del miembro y serializa la revocación/reconciliación con altas,
renovaciones y reasignaciones Active. Los activos conservan historial genérico
append-only, eliminan el ID saliente y muestran `Unassigned` cuando no queda
otro responsable; la reasignación valida miembro vigente, confirmación y CAS
sin crear una revisión de autorización. Un fallo revierte la membresía pero
mantiene sesiones invalidadas para permitir un reintento seguro. Pasaron 7/7
regresiones backend específicas, 47/47 Active/identidad/auditoría y la suite
backend+tools completa de 1.597 casos en contenedor read-only y sin red.
Frontend pasó 325/325, TypeScript y build (286.371 bytes de JS inicial). La
primera revisión visual local descubrió que la tarjeta quedaba obsoleta tras la
baja; se añadió invalidación del contexto Active y una regresión, y el recorrido
se repitió desde cero: invitación, alta asignada, impacto 1/1/0, baja y detalle
`Unassigned` con dos eventos. 320/768/1440 px quedaron sin overflow (279/279,
705/705 y 1.377/1.377). Instancia, datos y credenciales sintéticas se eliminaron.
Una invocación que añadió `cli/tests` a la imagen backend falló en colección por
ausencia del paquete CLI/jsonschema; se separó y no se presentó como validación
superada. `SEC-012`, `PROD-129`, `PROD-130` y `PROD-167` siguen bloqueadas.

**Evidencia PROD-173 (2026-09-09):** dos ciclos sintéticos completos y roles
admin/maintainer/reader recorrieron alta, control manual, ejecución aislada,
postura, baseline, triage, informe, lectura, denegación, revocación y bloqueo
posterior; la repetición dirigida pasó sin red. La revisión encontró y cerró
`PROD-174` y `PROD-175`, y documentó la matriz honesta de controles, estados
parciales y límites en `docs/active-weekly-adoption-review.md`. Se añadieron
17 tareas no duplicadas (`PROD-176`–`PROD-192`) sobre renovación, miembros,
retención, readiness, cola durable, cuotas, revisión de autorización, egress de
verificación, escala y UX; no se presentan como capacidades implementadas.
La validación final pasó 320/320 pruebas frontend, TypeScript, build Vite,
`compileall`, auditorías Python/npm sin vulnerabilidades conocidas, Compose
default/private/Active, canario Gitleaks, sincronización de estados y diff-check.

**Evidencia PROD-154 (2026-09-08):** el endpoint owner-scoped
`POST /projects/{id}/sbom-revisions`, el store y el workspace implementan
revisión CycloneDX/SPDX compatible, normalización sin original, idempotencia
`clave+digest`, replay, avance atómico y cleanup ante fallo. Se validaron carrera
de dos peticiones, replay/conflicto, formato incompatible, rollback entre fases,
aislamiento de owner, inventario y comparación: backend dirigido 3/3; frontend
67/67 (incluye App, axe y estados); TypeScript sin errores; build Vite reproducible
con bundle inicial 327.294/329.728 bytes. Contrato operativo documentado en
`docs/sbom-import.md`; la clave solo se retiene como hash interno y no aparece en
respuestas.

**Evidencia PROD-158 (2026-09-08):** el contrato SBOM `2026-09-08.1`
recorre relaciones CycloneDX/SPDX de forma acotada, tolera ciclos y duplicados,
y conserva `reported|not_reported|truncated` en componente, correlación y
hallazgo. La UI, priorización, recomendación, comparación e informe no presentan
un alcance incierto como directo/transitivo. Backend dirigido 57/57; frontend
35/35; TypeScript correcto; casos deterministas de raíz ausente, ciclo,
duplicado y grafo truncado.

**Evidencia PROD-164 (2026-09-08):** preflight no-egress obligatorio con
token owner-scoped de un solo uso, TTL 300 s y almacén en memoria de 256
admisiones que retiene solo hashes. La respuesta contiene exclusivamente
formato/versión/contadores; la importación exige los mismos bytes y cambiar el
archivo invalida la atestación en UI. Backend dirigido 35/35 (digest distinto,
single-use, expiración, owner, límite y cero stores tras preflight); frontend
62/62 con App, estado parcial y axe; TypeScript correcto; build 327.509/329.728
bytes. Límites multiworker y reintento documentados en `docs/sbom-import.md`.

**Evidencia PROD-166 (2026-09-08):** `ProjectView.source_type=archive|sbom`
se deriva del contrato interno sin exponer nombres. Listado, workspace,
remediación y comparación distinguen “archive snapshot” de “SBOM revision”; un
SBOM oculta el asistente CI de archivos y el selector ZIP/TAR, y ofrece su
revisión compatible. Backend dirigido 6/6 con matriz archive/SBOM; frontend
80/80 con App, workspace, formularios, findings y comparación; `tsc` correcto.
Contrato documentado en `docs/product-projects.md`.

**Evidencia PROD-165 (2026-09-08):** la portada ofrece tres entradas por
intención (Archivo, CI y SBOM), proyectos recientes y límites de seguridad
antes de las superficies densas. Administración parte cerrada y las auditorías
URL/dominio/activas quedan en un disclosure especializado. Archivo y SBOM se
alcanzan con una acción y foco en el control correcto; CI se explica como
bloqueado para primera visita o abre el workspace recurrente, enfoca
`ci-setup` y conserva el deep link. Revisión real 1440/768/320: cero overflow,
CTA de 44 px y consola limpia. Pasaron 70/70 pruebas dirigidas con axe/teclado,
48 archivos/322 pruebas frontend, `tsc` y build con bundle inicial
328.334/329.728 bytes. Evidencia reproducible en
`docs/frontend-visual-review.md`.

**Evidencia PROD-168 (2026-09-08):** la validación final identificó que el
hash interno de idempotencia SBOM entraba como campo extra al convertir
`JobRecord` en `JobDetailView`, rompiendo lecturas de jobs, y que smoke/recovery
seguían comparando 14 clases aunque el contrato vigente contiene 15. La primera
pasada llegó al 100 % y listó 74 fallos encadenados. La
proyección excluye ahora el hash, una regresión consulta el detalle de la
revisión y confirma que no se serializa, y las puertas usan versión
`2026-09-08.1` y contador central; el resumen tipado del drill declara también
esa versión. Tras 11/11 dirigidas y una actualización de
expectativa de los tres contadores de certeza de `PROD-158`, la tercera pasada
backend completó 1.117/1.117. No se cambió `SEC-012`.

**Evidencia sincronizada del Ciclo 6 (2026-09-06):** `PROD-131`–`PROD-139`
materializan tres verticales utilizables: CLI Git, CI/CD y SBOM. La regresión
final ejecutó backend y herramientas al 100 %, CLI 13/13, frontend 309/309 y
build con bundle 318,7/322 KiB. La revisión visual en 1265×710 y 390×844
detectó y corrigió un solapamiento del formulario SBOM; no quedó desborde móvil.
`PROD-151` documenta los recorridos y las fricciones en
`docs/adoption-review-cycle-6.md`. No hubo egress, push, PR, tag, release ni
despliegue; `SEC-012`, `PROD-129` y `PROD-130` permanecen bloqueadas.

**Evidencia sincronizada `PROD-152`/`PROD-156` (2026-09-08):** la CLI dispone
de versión única, `doctor`, wheel/sdist byte-reproducibles, SBOM y checksums; los
artefactos se instalaron sin el repositorio en Python 3.12. El handshake
anónimo y sin token declara contratos cerrados y se ejecuta antes de cualquier
lectura Git, Gitleaks o upload; servidor antiguo, malformado o incompatible
falla cerrado. Pasaron 21 pruebas CLI, la prueba backend dirigida del endpoint,
`compileall` y `diff-check`. No se publicó ningún artefacto ni se contactaron
proveedores de vulnerabilidades.

**Evidencia del vertical CLI del Ciclo 7 (2026-09-08):** instalación desde
wheel en Python 3.12 limpio → perfil válido → `doctor` listo con Git 2.47.3 y
Gitleaks 8.30.1 → dry-run → handshake → análisis local completado. Dry-run y
upload conservaron el digest `eb832131…`; policy terminó honestamente con
código 9 por cobertura incompleta del fixture mínimo, no como falso verde. La
primera pasada con fixture inválido se descartó y repitió desde cero. Se
verificaron y eliminaron 7 registros, 3 contenedores, red y temporales. Detalle
redactado en `docs/adoption-review-cycle-7.md`. La reconstrucción final produjo
wheel `c269cb60f144f843ef9c0b7936c33fd7fde5986d1f5cd9210a05857f627a7b0e`,
sdist `17d496f21a40824762fb7dadb19ce83f3415fa6a5696c34964a23627f2b364eb`
y SBOM `0a04dc27d39d082ff767a4c4ac3b905f7502035820488705751145dec56726ae`;
`SHA256SUMS` y la instalación aislada de ambos formatos pasaron. La suite CLI
final quedó en 34/34.

**Evidencia sincronizada de `PROD-116` (2026-09-06):** la candidatura local
privada se construyó como cinco imágenes identificadas y se ejecutó en una pila
Compose aislada, con TLS local, puertos solo loopback, redes y límites efectivos
de CPU/memoria/PID para todos los servicios. El smoke sintético verificó salud,
readiness, cabeceras, auth/CSRF, cookie Strict, proyecto/análisis, privacidad,
14 clases, informe y cleanup sin proveedor. Se probó persistencia tras
recreación, `503` seguro con un runner ausente y recuperación posterior. Pasaron
1.096 pruebas backend, 423 runner/guardas, 44 archivos/306 frontend, build y
presupuesto 317,4/322 KiB, `compileall`, tres Compose sin avisos, cinco auditorías
Python, auditoría npm, Gitleaks sobre historia/árbol y diff, sin omisiones. La
matriz visual 1440/768/320 no tuvo desborde ni errores de consola. El acta,
límites, tiempos, imágenes, go/no-go y reversión están en
`DEPLOYMENT_ACCEPTANCE.md`. No hubo push, PR, proveedor, despliegue externo ni
proyecto real.

**Evidencia sincronizada de `PROD-117` (2026-09-06, fuente autorizada B):** se analizó
exclusivamente el commit autorizado
`[commit autorizado B redactado]`; dos TAR canónicos de 1.417
archivos y 12.871.680 bytes produjeron SHA-256
`[SHA-256 de snapshot B redactado]`.
El `package-lock.json` v3 pertenecía al commit y el preflight completo de
Gitleaks terminó con 0 hallazgos y canario detectado, sin ejecutar proyecto ni
gestor. El inventario retuvo 590 componentes: 369 npm exactos/no scopeados
consultables, 212 scopeados bloqueados como privados y 9 sin versión exacta.
OSV oficial respondió a 15 lotes: 12 componentes afectados, 357 no afectados,
33 hallazgos (28 advisories/25 CVE), 33 fixes y 0 indisponibles. CISA KEV
oficial evaluó solo esos hallazgos: 30 CVE no listados, 3 sin CVE no evaluados,
0 explotados; GHSA real/token permanecieron prohibidos. La captura mostró solo
`api.osv.dev` y `www.cisa.gov`, sin destinos inesperados ni marcadores privados.
Se probaron caché sin tráfico, comparación 0/0/33, triage, informes, reinicio,
degradación con 369 `unavailable`/0 `not_affected`, recuperación y UI
1440/768/320. Pasaron 1.523/1.523 backend y 307/307 frontend, build
317,4/322 KiB, cuatro Compose, `compileall`, diff y Gitleaks de
historia/producción. La cascada y retirada final dejaron 0 proyectos, archivos,
workspaces, contenedores, volúmenes, redes, imágenes y temporales. El checkout
de la fuente autorizada B cambió concurrentemente durante la prueba, pero nunca se leyó ni
modificó: los dos checkpoints alrededor de la limpieza fueron idénticos y la
fuente quedó ligada al objeto Git. Veredicto **GO acotado de candidatura**, no
versión estable; acta completa en `DEPLOYMENT_ACCEPTANCE.md`.

**Evidencia sincronizada de `PROD-012` (2026-09-06):** el modo de equipo
persistente incorpora espacios aislados, invitaciones caducables de un solo
uso, roles administrador/mantenedor/lector, revalidación de membresía,
revocación de sesiones y cambio de espacio con rotación de sesión/CSRF. Los
archivos, trabajos/listados y proyectos materializan `organization_id` y
rechazan divergencias con la frontera histórica. Las pruebas cubren dos
organizaciones, acceso cruzado, permisos, replay, credenciales no persistidas,
migración SQLite y estados frontend. Pasaron 1.039/1.039 casos backend (31,21
s), 420/420 de runners/guardas (6,94 s), 286/286 frontend (22,26 s), build y
presupuesto 314,6/322 KiB (13,82 s), `compileall`, ambos Compose y diff. La
revisión visual sintética recorrió login, invitación y cambio/regreso de espacio
a 1440/768/390/320 px, sin desborde ni consola con avisos y con foco visible.
No hubo Internet, proveedor, proyecto real, push ni PR. El modo de equipo no se
declara aún candidato empresarial: auditoría, matriz exhaustiva, retención y
smoke multiempresa permanecen en sus tareas específicas.

**Evidencia sincronizada de `PROD-113` (2026-09-06):** el panel de
inteligencia pública hace visible la política de egress, frescura y naturaleza
inmutable del snapshot; explica el flujo OSV/GHSA/KEV y mantiene KEV como señal
independiente sobre CVE ya correlacionado. Prioriza sin mezclar CVSS y KEV,
reduce la densidad con detalles contraíbles y ofrece filtros restablecibles,
estados accionables y enlaces públicos defensivos. Fixtures cubren estados
vacíos, deshabilitado, parcial, caducado, carga y error; axe pasó. Una revisión
visual con aplicación/API locales, copia de datos sintéticos y adaptadores
simulados verificó 320/768/1440 px, foco, tarjeta prioritaria, histórico `stale`,
consola vacía y ausencia de scroll horizontal. La revisión descubrió y corrigió
un desborde móvil de 8 px en la cuadrícula común de hallazgos. Pasaron 38
archivos/277 pruebas frontend (18,89 s), TypeScript/Vite y presupuesto
311,6/322 KiB (7,51 s), sin Internet ni proveedor real. Los estados OSV, GHSA
y CISA KEV siguen siendo «adaptador validado únicamente con fixtures».

**Evidencia sincronizada de `PROD-122` (2026-09-06):** `audit-tools` ya no
monta `data/` ni pertenece a la red de egress. El backend verifica y transporta
una sola fuente sin propietario/proyecto/ruta, rechaza destinos de runner
alternativos y usa HTTP sin proxies de entorno. Cada solicitud queda serializada
en un subproceso efímero con fuente `0400`, directorio `0700`, entorno mínimo,
tmpfs dedicado y límites atestados de pared/CPU/memoria/archivo/descriptores/
procesos/fuente/resultado; timeout y cancelación matan el grupo y la limpieza es
idempotente. `network-tools` queda separado, sin volumen, y rechaza archivos.
Pasaron 1.019/1.019 backend (16,90 s), 420/420 runner/guardas (6,09 s),
277/277 frontend (19,15 s), build 311,6/322 KiB (7,29 s), imágenes y smoke
sintético sin red: SHA correcto, contrato `2026-09-06.1`, endpoint de red 404,
tmpfs vacío, `/app/data` ausente y solo Uvicorn vivo. No hubo proveedor,
Internet, proyecto real, push ni PR; `PROD-012` sigue bloqueando cualquier
afirmación multiempresa.

**Evidencia sincronizada de `PROD-073` (2026-09-06):** el navegador genera una
clave opaca de 128 bits al confirmar una nueva instantánea y la reutiliza tras
un fallo incierto. El backend solo guarda su SHA-256 en una bitácora privada
`2026-09-06.1`, reserva IDs de instantánea/job antes de modificar el proyecto y
completa la misma operación tras fallo o reinicio; una colisión incompatible
devuelve `409`. `INSPECTRA_PROJECT_MAX_SOURCE_SNAPSHOTS` limita el historial a
100 por defecto (1–10000) y nunca lo purga para hacer sitio. Pruebas cubrieron
dos hilos, owner/hash, contador, clave sin persistir, interrupción exacta entre
proyecto/job, recuperación al arrancar, colisión, límite y reintento UI estable.
Pasaron 1.023/1.023 backend (26,44 s), 420/420 runner/guardas (6,17 s),
278/278 frontend (20,11 s), build/presupuesto 311,8/322 KiB (10,45 s),
`compileall`, Compose base/privado y `git diff --check`. La primera invocación
frontend falló por ejecutarse desde la raíz sin `package.json`; se corrigió el
directorio y la validación completa terminó sin omisiones. No se usaron
Internet, proveedor ni proyecto real.

**Evidencia sincronizada de `PROD-060` (2026-09-06):** `/health` queda como
señal mínima de vida y `/ready` comprueba, con tiempo acotado, almacenamiento
privado, los dos runners internos de destino fijo, capacidad global de
admisión y ausencia de admisiones/workspaces huérfanos. La respuesta y los logs
solo contienen códigos agregados; no incluyen host, ruta, configuración,
propietario, conteo ni error bruto. Las sondas HTTP ignoran proxies de entorno,
no siguen redirecciones y rechazan respuestas mayores de 4 KiB o contratos
incompatibles. Pasaron 1.030/1.030 pruebas backend (15,42 s), 420/420 de runner
y guardas estáticas (6,08 s), `compileall`, Compose base/privado y
`git diff --check`, sin pruebas omitidas. Un smoke local aislado confirmó
`ready` → runner detenido/`not_ready` con liveness disponible → `ready` tras
recuperación, y se verificó la limpieza de contenedores, redes y volumen
temporales. Un intento previo con una única red interna no permitía alcanzar el
puerto desde el host y se descartó expresamente como validación; no fue un fallo
de la aplicación ni se atribuyó al sandbox. No hubo Internet, proveedor ni
proyecto real.

**Evidencia sincronizada de `PROD-015`:** 2026-09-06: cola de proyecto
persistida y revalidada al arrancar (propietario/proyecto/snapshot/perfil/hash),
contador de recuperación, rechazo seguro de fuente/contrato incoherente,
`application_restart` para trabajo ya iniciado y `application_shutdown` tras
cancelar/esperar/limpiar. Backend 796/796 + 211/211 por grupos y 1.007/1.007
conjunto (18,10 s), runner/estáticas 412/412 (5,48 s), frontend 271/271 y build
311,6/322 KiB; `compileall`, Compose base/privado y diff pasaron, sin Internet
ni proyecto real. La ficha completa y sus límites están en `TODO_PRODUCTO.md`.

**Evidencia sincronizada de `PROD-058`:** 2026-09-06: admisión atómica bajo
el lock de persistencia con límites configurables global `128` y por propietario
`32`; cuenta `queued/running/cancelling`, libera al terminar y devuelve `429`
fijo/`Retry-After` sin conteos. Pruebas cubren dos propietarios, límite global,
recreación del store/reinicio, liberación, carrera concurrente y creación de
proyecto sin registro parcial cuando el cupo ya está lleno. Perfil de ejecución
`2026-09-06.2`, UI e informe exponen solo los límites configurados. Pasaron
1.011/1.011 backend (15,56 s), 412/412 runner/estáticas (5,39 s), 272/272
frontend (19,33 s), build 311,6/322 KiB, `compileall`, Compose base/privado y
diff, sin Internet ni proyecto real.

### PROD-122 — Worker con montaje y cuota fuerte por ejecución

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** el workspace opaco actual evita mezcla lógica, pero
  `audit-tools` todavía puede leer todo el volumen `data/`; un producto para
  equipos necesita un worker que solo reciba la fuente y artefactos de su job.
- **Archivos o áreas implicadas:** orquestación/runner, almacenamiento, leases,
  runtime de contenedores, configuración, observabilidad, pruebas y runbook.
- **Criterios de aceptación verificables:** cada worker recibe únicamente la
  fuente verificada de una ejecución en un staging `0400` sin montar `data/` y
  devuelve un resultado acotado, con cuotas
  CPU/memoria/PID/disco/tiempo atestadas; cleanup idempotente tras éxito,
  cancelación, timeout, kill y reinicio. Una prueba con dos propietarios impide
  enumerar o leer el workspace ajeno y confirma que no queda proceso/montaje.
- **Riesgo de no resolverla:** un runner comprometido podría leer fuentes de
  otras ejecuciones pese al montaje global de solo lectura.
- **Estimación:** L
- **Dependencias:** PROD-008 completada; PROD-015; PROD-012 antes de afirmar
  aislamiento multiempresa.
- **Evidencia de validación al completarla:** 2026-09-06: se retiró el montaje
  global y se separaron runners de archivo/no-egress y red/egress con roles que
  fallan cerrados. El transporte solo incluye bytes base64 acotados, tamaño,
  SHA-256, ID y límites; nunca owner, proyecto o ruta, y los destinos internos
  son fijos con `trust_env=False`. El worker efímero aplica `RLIMIT` y límites
  Compose/tmpfs, serializa fuentes, mata el grupo al cancelar/expirar y limpia
  incluso restos/symlinks sin seguirlos. Perfil `2026-09-06.3`, resultado e
  informe conservan el contrato seguro; 422 ya no refleja el cuerpo rechazado.
  Validación: backend 1.019/1.019 (16,90 s), runner/guardas 420/420 (6,09 s),
  frontend 277/277 (19,15 s), build 311,6/322 KiB (7,29 s), `compileall`,
  Compose base/privado, diff e imágenes. Smoke Docker sintético sin red ni
  volumen confirmó digest, endpoint de red 404, tmpfs vacío y ningún proceso
  hijo restante. No se usó Internet, proveedor o proyecto real.

**Ciclo de producto — Ronda 1 (2026-09-05):** se auditó el recorrido archivo
autorizado → proyecto → ejecución → hallazgos/inventario → comparación →
informe. Se mantienen los límites sin rutas de host, repositorios o
credenciales. `PROD-041`…`PROD-046` registran las brechas accionables de
continuidad de instantáneas, recuperación, confirmación de alcance, cobertura,
aceptación y corrección; `PROD-046`, `PROD-045`, `PROD-052` y `PROD-049` están
completadas. `PROD-055` protege namespaces privados y procedencia antes de
egress. `PROD-101` ya cerró el motor local de correlación determinista y
`PROD-118` preserva intervalos OSV discontinuos y `PROD-102` separa huella
estable de evidencia mutable. `PROD-119` exige Python 3.12 antes de resolver
los lockfiles. `PROD-057` está completada: cada job nuevo conserva un perfil de
ejecución tipado e inmutable, comparación/informe expresan su compatibilidad y
los históricos siguen explícitamente limitados. `PROD-065` está completada: la
línea base explícita está versionada, aislada por propietario y no queda
colgando tras borrar su job. `PROD-053` está completada: cada refresco de
inteligencia normalizada queda retenido e inmutable, es seleccionable y
exportable por ID opaco, y una vista histórica no puede iniciar egress; no se
retienen cuerpos crudos ni se habilitó red real. Pasaron 1.337 pruebas Python,
38 suites/263 pruebas frontend, build/presupuesto 311,1/322 KiB, Compose y
diff. Tras revisar las P1 pendientes, todas dependen de capacidades aún
bloqueadas; la siguiente tarea única viable debe elegirse entre las P2 con
dependencias satisfechas y quedar trazada en `TODO_PRODUCTO.md`.
Criterio: permiso y trazabilidad antes que automatización o comodidad.
`PROD-043` queda completada: la creación exige la confirmación
efímera `authorization_confirmed: true`, sin conservar texto libre; backend,
33 suites/221 pruebas frontend, build 320,0/320 KiB y `git diff --check`
pasaron. El detalle de controles y evidencia está en `TODO_PRODUCTO.md`.

**Ciclo de producto — Ronda 2 (2026-09-05):** se auditó el inventario del
Módulo 3, sus parseres pasivos y la cadena de futura correlación. Se detectó que
los lockfiles se ven como señales, pero aún no son evidencia de versión. La
secuencia `PROD-025`…`PROD-056` separa resolución, identidad, resultado,
proveniencia, límites de feeds y operación offline. `PROD-026` completa la
frontera de egress con un valor deshabilitado por defecto, pero no consulta una
fuente desde el producto hasta que termine el contrato `PROD-027`. `PROD-025`
queda completada: el inventario asocia una versión
resuelta solo con `package-lock.json` npm v2/v3 de la misma raíz y dependencia
registry directa; no instala paquetes, no consulta red y no retiene URL,
integridad o tránsito. El contrato/UI muestran cobertura y motivos seguros de
exclusión. Backend+runner completos, 33 suites/222 pruebas frontend, build
320,0/320 KiB, Compose config y diff check pasaron; detalle en
`TODO_PRODUCTO.md`.

**Ciclo de producto — Ronda 3 (2026-09-05):** se revisaron auth, ownership,
stores, ejecución en memoria, límites, retención, observabilidad y despliegue.
`PROD-057`…`PROD-064` separan reproducibilidad, admisión, configuración de
arranque, salud, integridad, ciclo de datos, bitácora y recuperación. No se
declara cola durable ni aislamiento multiempresa hasta cumplir sus dependencias.
`PROD-059` queda completada: el perfil privado falla de forma segura si no usa
estado SQLite persistente dentro de datos o si esos directorios permiten acceso
de grupo/mundo. `PROD-057` ya completó sobre el almacenamiento actual el perfil
inmutable, sin prometer cola durable; `PROD-058` sigue dependiente de admisión
atómica y de la base organizativa. `PROD-052` ya refuerza los límites de proveedor antes de caché y
`PROD-049` evita transformar locators no registry en una identidad pública.
`PROD-055` ya excluye namespaces privados sin infraestructura durable y
`PROD-101` separa la decisión local de correlación de egress, `PROD-118`
preserva los intervalos OSV discontinuos, `PROD-102` estabiliza los hallazgos y
`PROD-119` alinea el bootstrap Python con CI. Se revisan las P1 restantes.

**Ciclo de producto — Ronda 4 (2026-09-05):** se revisaron adopción recurrente,
comparación, informes, triage y vías de integración. `PROD-065`…`PROD-072`
formalizan línea base, decisiones, contratos, CI e integraciones con controles
previos. `PROD-041` queda completada: el recorrido local ya puede añadir una
instantánea inmutable autorizada, analizarla y conservar ambos hashes para
comparación e informes.

**Evidencia `PROD-041` (2026-09-05):** la API owner-scoped añade una fuente
archivada autorizada como nueva instantánea sin mutar hashes históricos, rechaza
una ejecución activa, tipo inválido, propietario distinto y hash duplicado, y
mantiene la marca de eliminación por instantánea. La interfaz ofrece el flujo
**Add snapshot** con confirmación, estado vacío y selectores identificados por
hash. Pasaron `backend/tests`, `tools/tests`, compilación Python, 34 suites/225
pruebas frontend, build (321,0/322 KiB), `docker compose config --quiet` y
`git diff --check`; detalle completo en `TODO_PRODUCTO.md`.

**Ciclo de producto — Ronda 5 (2026-09-05):** se comprobó que la nueva fuente
es inmutable y owner-scoped, pero su persistencia/trabajo aún no es atómica ni
idempotente y no tiene límite por proyecto; `PROD-073` lo prioriza sin ocultar
el riesgo. `PROD-074` convierte CSRF/ownership de todas las mutaciones en una
matriz de regresión y `PROD-075` controla la exposición de nombres de archivo.
Tras las cinco revisiones comienza la fase profunda de UX. `PROD-076` queda
completada: el espacio de trabajo y línea temporal de proyecto ya concentran
hash, retención, estado seguro y siguiente acción sobre los contratos validados.
`PROD-073` quedó completada posteriormente con bitácora privada, recuperación
idempotente y límite de historial; la observación de la ronda se conserva como
trazabilidad histórica, no como estado pendiente.
`SEC-012` continúa bloqueada y sin cambios.

**Evidencia `PROD-104` (2026-09-05):** la comparación archive-backed ahora
expone dos resúmenes agregados y un estado `equivalent`/`changed`/`unknown`.
Un resumen ausente o un cambio de límites, entradas, manifiestos, lockfiles o
dependencias devuelve `not_comparable` y nunca clasifica hallazgos como nuevos
o resueltos; la eliminación posterior de los bytes se muestra aparte y no
reescribe la cobertura ya capturada. Pasaron 1.348 casos backend/runner, 38
archivos/264 pruebas frontend, `compileall`, build/presupuesto 311,1/322 KiB,
Compose, diff y revisión sintética local a 1265/640 px sin desborde ni errores
de consola. El detalle está en `TODO_PRODUCTO.md` y

**Evidencia `PROD-089` (2026-09-05):** el cliente de advisories conserva sus
destinos internos fijos y, antes de abrir el transporte, vuelve a validar
método, HTTPS, host y ruta exactos; puerto, credenciales en URL, query y
fragmento se rechazan como fuente no disponible, con cero intentos y sin
registrar el endpoint. `MockTransport` cubrió HTTP, host ajeno, userinfo,
query, fragmento e IP local, además de 302, 400, 503, 504 y `ReadTimeout`;
solo los fallos transitorios se reintentaron y nunca se expuso el cuerpo del
proveedor. Pasaron 37 pruebas dirigidas, 1.358 casos backend/runner,
`compileall`, `docker compose config --quiet` y controles de espacios en
blanco, sin Internet. `SEC-012` sigue bloqueada y sin cambios.

**Evidencia `PROD-091` (2026-09-05):** `querybatch` ahora completa únicamente
las continuaciones OSV marcadas por token y reconstruye el orden original. Los
tokens no salen de la ejecución actual, del cuerpo cacheado, snapshots, logs ni
informes; solo se conserva el conteo seguro de páginas. El límite de cuatro
páginas/4.000 advisories por identidad, token hostil, fallo de continuación o
presupuesto agotado terminan como cobertura degradada, no como ausencia de
vulnerabilidades. Pasaron fixtures con `MockTransport`, la integración de
correlación paginada, 1.362 casos backend/runner, 38 archivos/264 pruebas
frontend, build 311,1/322 KiB, Compose reconstruido y `/health`, sin Internet.

**Evidencia `PROD-095` (2026-09-05):** una política interna y versionada puede
etiquetar un enlace como boletín oficial solo para componentes/rutas revisados,
HTTPS sin credenciales, puerto, query ni fragmento, y el GHSA ya conservado
como alias. La primera entrega se limita a rutas de security advisories de
React y Lodash: no sigue enlaces, no añade egress y no interpreta changelogs o
dominios parecidos como evidencia. Panel e informe lo muestran como apoyo sin
cambiar la corrección, el rango o CVSS de OSV/GHSA. Pasaron 1.366 casos
backend/runner, 38 archivos/264 pruebas frontend y build 311,1/322 KiB, sin
Internet. `SEC-012` sigue bloqueada y sin cambios.

**Evidencia `PROD-092` (2026-09-05):** la reauditoría eliminó una duplicación
de backlog, sin añadir un segundo adaptador. El vertical ya completado en
`PROD-032` consulta solo un GHSA que el snapshot OSV conserva, mediante el
endpoint fijo de GitHub, y conserva evidencia, retirada y conflictos por
separado. Sus fixtures y `MockTransport` cubren campos ausentes, conflicto,
retirada, respuesta ambigua y redacción sin Internet. `PROD-096` queda como el
consumidor posterior de esa evidencia. `SEC-012` sigue bloqueada y sin cambios.

**Evidencia `PROD-082` (2026-09-06):** el parser de `pnpm-lock.yaml` acepta
solo el subconjunto v9 (`lockfileVersion: '9.0'`, importador raíz y versiones
directas semver exactas) y escanea el YAML antes de cargarlo: anchors, aliases,
tags, claves duplicadas/no textuales, formato/versiones no soportados y más de
20.000 tokens quedan fuera con razones controladas. No ejecuta pnpm ni retiene
`specifier`, `resolution`, integridad, tarball o peer suffix. El contrato de
inventario/preflight `2026-09-05.8` presenta una resolución local misma-raíz
sin purl, grafo transitivo ni procedencia pública; una prueba de PVI confirma
que OSV no recibe ese componente. Pasaron pruebas dirigidas, la suite completa
`backend/tests tools/tests`, `compileall`, 38 archivos/266 pruebas frontend,
build con 311,1/322 KiB, `docker compose config --quiet`, Compose reconstruido
y `/health`; sin consultas a proveedores. `SEC-012` sigue bloqueada y sin
cambios.

**Evidencia `PROD-083` (2026-09-06):** el runner reconoce únicamente la
gramática de Yarn Classic v1 con la cabecera `# yarn lockfile v1`, hasta 20.000
líneas. Conserva nombre npm válido, versión semver exacta y un digest opaco de
selector para exigir la misma declaración y root; no retiene selector,
`resolved`, integridad, URL, dependencia transitiva o alias/protocolo. Berry
(`__metadata:`), tabulaciones, líneas excesivas, versiones y gramática inválida
quedan como cobertura no procesada, nunca como un resultado limpio. El contrato
de inventario/preflight y matriz `2026-09-06.1` muestran la resolución local
sin purl ni procedencia pública; PVI comprueba que OSV no recibe el componente.
Pasaron pruebas dirigidas, la suite completa `backend/tests tools/tests`,
`compileall`, 38 archivos/267 pruebas frontend, build 311,1/322 KiB, Compose y
HTTP local de frontend/backend. Sin consultas a proveedores. `SEC-012` sigue
bloqueada y sin cambios.

**Evidencia `PROD-084` (2026-09-06):** el runner acepta exclusivamente
`poetry.lock` TOML con `[metadata].lock-version = "2.1"` y un máximo de
paquetes configurado. Reduce cada entrada a nombre PyPI normalizado, versión
exacta y etiqueta local-only; no ejecuta Poetry ni conserva `package.source`,
URL, referencias, archivos, hashes, grupos, marcadores, aristas ni content hash.
El inventario/preflight/matriz `2026-09-06.2` solo resuelven una declaración
directa del mismo root si hay una única versión; duplicados o ausencias quedan
sin resolver y Poetry no crea purl ni egress. Pasaron pruebas dirigidas de
runner, asociación/ambigüedad/cobertura/PVI, `compileall`, frontend completo
(38 archivos/268 pruebas) y build con presupuesto 311,1/322 KiB. La regresión
Python completa no se ejecutó en este sandbox porque una prueba heredada que
abre TCP local falla con `PermissionError`; los cambios cubiertos usaron
fixtures y `MockTransport`, sin Internet. `SEC-012` sigue bloqueada y sin
cambios; la prioridad pasa a `PROD-121`, sin iniciar más parsers.

**Evidencia `PROD-121` (2026-09-06):** la configuración añade
`INSPECTRA_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES`, una lista vacía por defecto
de hasta 100 nombres PyPI exactos normalizados; rechaza URL, índices, rutas,
comodines y credenciales. Solo un `pyproject.toml` de la ejecución con pin
directo `==` que coincide con su versión exacta, no cae en
`PRIVATE_PACKAGE_RULES` y está atestado localmente puede producir el payload
OSV mínimo `PyPI`/nombre/versión. La atestación no se persiste ni se registra;
Poetry 2.1 sigue sin purl ni egress. El snapshot PVI `2026-09-06.1` conserva
solo la procedencia segura `operator_attested_public_pypi`; informe y panel no
exponen ruta, índice, lockfile ni código. La comparación de ejecuciones añade
un bloque separado que solo clasifica advisories públicos con cobertura
equivalente y ambos snapshots OSV `ready` y frescos; ausencia, legado,
degradación o dato caducado queda explícito y no genera un falso «resuelto».
Las pruebas con `MockTransport` verifican OSV PyPI y rechazo no atestado, GHSA
por alias, KEV solo por CVE ya correlacionado, informes y comparación sin
Internet. Pasaron 23 pruebas backend dirigidas y `compileall`; en una copia
temporal pasaron las 38 suites/270 pruebas frontend y TypeScript/Vite con
presupuesto de bundle 311,1/322 KiB. `docker compose config --quiet` y
`git diff --check` pasaron. La suite backend completa se intentó bajo el
sandbox pero quedó sin salida adicional tras el 14 %; se interrumpió de forma
controlada y no se cuenta como una validación completa.

**Evidencia `PROD-087` (2026-09-05):** el contrato de inventario
`2026-09-05.7` incorpora una matriz de cobertura fija y versionada para npm,
pnpm, Yarn y flujos Python. Declara de forma separada manifiesto y lockfile
`parsed`/`detected_not_parsed`/`not_detected`, alcance directo/transitivo y un
motivo controlado; no persiste ruta, URL, integridad, contenido ni error bruto.
API, panel e informe comparten la proyección segura y los snapshots anteriores
la derivan sin mutarlos. Pasaron 8 pruebas backend dirigidas, la suite
backend/runner, `compileall`, 38 archivos/265 pruebas frontend, build
311,1/322 KiB, `docker compose config --quiet`, Compose reconstruido y
`/health`; sin Internet. `SEC-012` sigue bloqueada y sin cambios.
`docs/frontend-visual-review.md`.

**Evidencia `PROD-074` (2026-09-05):** el backend declara el contrato de las
mutaciones crear, repetir, añadir instantánea y borrar fuente. Una matriz ASGI
verifica anónimo `401`, sesión sin CSRF `403`, recorrido propietario con CSRF,
otro propietario `404`, ID malformado seguro y campos extra `422` sin reflejar
secretos. La repetición tiene ahora contrato de cuerpo vacío y no ignora un
payload inesperado. Pasaron 7 pruebas dirigidas, la suite completa backend/runner
en Python 3.12 y `compileall`; frontend completo (35 suites/229 pruebas), build
y presupuesto 321,6/322 KiB también pasaron.

**Evidencia `PROD-047` (2026-09-05):** el inventario `2026-09-05.3` clasifica
por componente la asociación del manifiesto npm con su lockfile como coincidente,
sin pareja o ambigua. Solo una pareja `package.json`/`package-lock.json` npm
parseada en la misma raíz relativa puede aportar una resolución; workspaces,
duplicados, gestores mezclados y rutas inseguras no la aportan. El panel muestra
conteos y estado sin exponer topología adicional. Pruebas dirigidas cubrieron
raíz/subproyecto, workspace, duplicado, gestores mezclados, falta de lockfile y
traversal, además de la ruta owner-scoped existente. Pasaron backend/runner
completos, `compileall`, frontend completo (35 suites/230 pruebas) y build con
presupuesto 321,6/322 KiB.

**Evidencia `PROD-035` (2026-09-05):** hallazgos e informes muestran cobertura
agregada segura: manifiestos y lockfiles detectados/parseados, dependencias,
truncamiento, fuente eliminada y limitaciones controladas. La API no entrega
rutas, errores ni resultado bruto. Pasaron pruebas dirigidas de contrato y UI,
la suite backend/runner completa, `compileall`, configuración Compose y diff
check; el build frontend y presupuesto de 322 KiB pasaron.

**Evidencia `PROD-076` (2026-09-05):** el panel diferido **Open workspace**
concentra instantáneas, análisis, estado seguro y una línea temporal de hashes
owner-scoped, sin repetir archivos en la historia. Se corrigió el desborde de
la cuadrícula a 980 px con `minmax(0, 1fr)` y guardas de estilos. Pasaron 35
suites/229 pruebas frontend, build 321,6/322 KiB, Compose config y diff check;
la revisión local con fixture sintético pasó a 1440/980/640 px. Detalle en
`TODO_PRODUCTO.md`.

**Evidencia `PROD-024` (2026-09-05):** se persistió el inventario declarado
seguro `2026-09-05.1` para ejecuciones de proyecto, se añadió API owner-scoped y
panel con cobertura/búsqueda sin egress. Pasaron backend+runner completos,
frontend completo (33 archivos/221 pruebas), build 319,7/320 KiB, Compose config
y diff check. El detalle y los límites de correlación están en `TODO_PRODUCTO.md`.

**Evidencia `PROD-026` (2026-09-05):** `public_advisory_egress.py` fija los
únicos tres destinos aprobados (OSV, GitHub Global Security Advisories y CISA
KEV), usa HTTPS, `trust_env=False`, no sigue redirecciones y no acepta URL,
host, ruta, cabecera ni payload de usuario. El modo está desactivado en la
configuración y Compose; al activarlo solo puede enviar la identidad mínima
normalizada de paquete/versión. Las respuestas tienen timeout, límite de bytes,
concurrencia, reintentos, caché con clave irreversible/TTL y fallback marcado
explícitamente como obsoleto. La telemetría excluye identidad, proyecto, ruta y
respuesta. Pasaron 9 pruebas deterministas con `MockTransport`, la regresión
completa `backend/tests tools/tests` en Python 3.12, `compileall`, ambos perfiles
de `docker compose config` y `git diff --check`; la guía
`docs/public-vulnerability-intelligence.md` documenta la activación, amenazas y
el requisito externo de firewall por FQDN. La prueba involuntaria inicial contra
OSV se eliminó antes de esta validación: la suite final no abrió Internet.

**Evidencia `PROD-027` (2026-09-05):** `public_advisories.py` define el
contrato `2026-09-05.1` para OSV. Valida la correspondencia por paquete,
identificador, referencias HTTPS sin credenciales, fechas, CVE/GHSA, rangos,
versiones corregidas, CVSS y retirada; un cuerpo malformado, hostil o asociado a
otro paquete se mantiene como error de fuente y no como cobertura limpia. Las
duplicaciones exactamente iguales se eliminan, pero evidencia de rango distinta
no se fusiona. El fixture local cubre resultado válido, retirada, JSON incoherente,
duplicación y entradas hostiles; pasaron 13 pruebas de frontera/contrato sin red,
`compileall` y `git diff --check`.

**Evidencia `PROD-028` (2026-09-05):** el recorrido OSV ya es un vertical de
proyecto owner-scoped. Selecciona únicamente paquetes registry npm/PyPI con
versión exacta y purl reconstruida desde la identidad mínima segura, usa el
transporte/cache de `PROD-026`, valida el lote contra el contrato de
`PROD-027` y vuelve a comprobar localmente el rango antes de persistir un
hallazgo. El snapshot separado conserva solo el resultado normalizado, estado,
frescura/cobertura y errores controlados; no conserva JSON de proveedor, ruta,
propietario, hash ni requisito original. La API exige autenticación/CSRF para
ejecutarlo, la interfaz presenta carga/vacío/error/egress desactivado/evidencia
normalizada y los informes usan únicamente el snapshot persistido. Pasaron 17
pruebas dirigidas de egress/contrato/correlación y API sin Internet, la suite
completa `backend/tests tools/tests` en Python 3.12, `compileall`, ambos
Compose, `git diff --check`, 36 suites/234 pruebas frontend y build con 314,0/
322 KiB inicial. La revisión visual local con el fixture sintético
`demo-archive-app-config.zip` comprobó a 1440 y 640 px el proyecto completado,
el botón bloqueado por defecto y el aviso de egress; no abrió una conexión a
OSV.

**Evidencia `PROD-029` (2026-09-05):** los snapshots OSV conservan el vector
del proveedor y, únicamente para CVSS 3.0/3.1 válido, exponen una puntuación
base/banda marcada como derivada. Vector v4, inválido o ausente sigue como
`unknown`, nunca `none`; los snapshots heredados se leen con valores seguros.
El panel e informe muestran prioridad, origen, rangos, corrección, fechas y
recomendación, sin convertir CVSS en una señal KEV. Pasaron 16 pruebas backend
dirigidas, regresión completa `backend/tests tools/tests`, `compileall`, ambos
Compose y `git diff --check`; en copia temporal, 36 suites/234 pruebas frontend
y build/presupuesto 314,0/322 KiB.

**Evidencia `PROD-032` (2026-09-05):** GitHub se consulta exclusivamente por
un GHSA ya retenido por OSV, validado antes de salir, contra el endpoint fijo
de Global Security Advisories; `per_page=1`, cabeceras y versión de API se
construyen internamente. No se envían paquete, versión, proyecto, ruta, archivo,
código ni secreto. El contrato rechaza respuesta múltiple, retirada, identificador
distinto, componente/rango incompatibles e información incompleta; mantiene la
evidencia GHSA separada —rangos, corrección, CVSS, fechas, referencias y digest—
sin sustituir OSV. Panel e informe lo hacen visible. Pasaron 16 pruebas backend
dirigidas, la regresión `backend/tests tools/tests` en Python 3.12, `compileall`,
ambos Compose y `git diff --check`; en copia temporal, 36 suites/234 pruebas
frontend y build/presupuesto 314,2/322 KiB. Solo hubo fixtures/`MockTransport`,
sin Internet. Diseño contrastado con la documentación oficial:
https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28.
El siguiente paso previsto tras esta evidencia fue `PROD-031`, ya completada
más abajo. La frescura de `PROD-033` y la deduplicación, conflictos y retirada
de `PROD-051` también quedaron completadas posteriormente.

**Evidencia `PROD-031` (2026-09-05):** CISA KEV ya es un vertical separado:
una instantánea OSV completada permite consultar exclusivamente el catálogo JSON
fijo de CISA, sin enviar identificador de proyecto, archivo, ruta, paquete,
versión, CVE, cabecera de usuario ni secreto. El catálogo se normaliza con
contrato versionado y solo se relaciona con CVE exactos ya retenidos; no infiere
CPE, producto ni explotación local, y no altera CVSS ni la evidencia OSV/GHSA.
Cada señal conserva fuente canónica, versión/fecha de catálogo, alta, fecha
límite y acción requerida; `not_listed`, `unavailable` y `not_evaluated` se
presentan sin afirmar “no explotado”. Cuando no hay CVE, no abre egress. El
feed oficial tenía 1.696.769 bytes el 2026-09-05, por lo que el máximo estricto
predeterminado se ajustó a 2 MiB (su tope configurado) para que el proveedor
aprobado sea utilizable; si crece, falla de forma controlada. Pasaron 12 pruebas
backend dirigidas, la regresión completa `backend/tests tools/tests` en Python
3.12, `compileall`, Compose normal y privado con valores de fixture, `git diff
--check`, 36 suites/234 pruebas frontend y build/presupuesto 314,4/322 KiB.
Solo hubo fixtures y `MockTransport`, sin consulta de advisory real durante las
pruebas. `PROD-033` ya formaliza frescura, caducidad y recuperación multifuente;
`PROD-051` ya expresa conflictos y retirada sin fusionar evidencia incompatible.
`PROD-050` ya distingue resultados de correlación sin convertir ausencia o caída
de fuente en un negativo. `PROD-048` completó la priorización de dependencias
directas, transitivas y opcionales; `PROD-017` completó la guía de incorporación
accesible y responsive, y `PROD-030` cerró la exploración de advisories.
`PROD-059` reforzó el arranque privado, `PROD-044` añadió un prevuelo de
cobertura sin inspeccionar archivos, `PROD-046` enlazó una corrección local y
`PROD-045` añadió aceptación determinista; `PROD-052` cerró la validación de
respuestas públicas, `PROD-049` la privacidad de locators, `PROD-101` el motor
local, `PROD-118` los intervalos OSV, `PROD-102` la identidad estable y
`PROD-119` el bootstrap Python; se seleccionará la siguiente P1 viable.

**Evidencia `PROD-059` (2026-09-05):** `private_tls_proxy` exige ahora
`INSPECTRA_AUTH_STATE_STORE=sqlite`, una base resuelta dentro de
`INSPECTRA_DATA_DIR` y directorios persistentes sin permisos de grupo/mundo;
los errores no imprimen secretos. Pasaron 9 pruebas dirigidas de perfil privado,
`compileall` y la suite backend/runner en Python 3.12, ambos `docker compose
config -q`, build/arranque aislado de backend con `/health` 200 y
`git diff --check`. La imagen también cargó el perfil privado con un volumen
temporal 0700 y estado SQLite. No se expuso ningún servicio público.

**Evidencia `PROD-046` (2026-09-05):** los detalles y comparaciones de
hallazgos normalizados muestran guía de corrección solo cuando hay una
recomendación o referencia canónica revalidada en el cliente. Copiar transmite
exclusivamente `recommendation`, nunca evidencia, ubicación, archivo, proyecto
ni metadatos; los enlaces requieren HTTPS sin credenciales/fragmento/puerto y
forma canónica de NVD/CVE, GitHub Advisories u OWASP. La interfaz declara que
la guía no es un veredicto de explotación ni prueba de remediación, y conduce a
una nueva instantánea autorizada sin editar código ni transmitir contenido.
Pasaron 38 suites/258 pruebas frontend, TypeScript/Vite y presupuesto
310,3/322 KiB, `git diff --check` y build local Docker. La revisión visual local
abrió un hallazgo sintético, el detalle y el formulario de nueva instantánea;
el formulario informó correctamente que falta un archivo distinto autorizado.

**Evidencia `PROD-045` (2026-09-05):** la aceptación ASGI usa ZIPs sintéticos
y un adaptador de análisis no-op para recorrer preflight, subida, rechazo de
confirmación ausente, creación autorizada, transición a resultado fixture,
hallazgos normalizados, inventario, informe Markdown redactado, segunda
instantánea y comparación. No ejecuta archivo, worker ni egress de advisories;
comprueba la ausencia de secreto y ruta de host en todas las respuestas
retenidas. Pasaron la prueba dirigida, `compileall`, la suite backend/runner
completa en Python 3.12 y `git diff --check`; el comando reproducible quedó
documentado en `docs/product-projects.md`.

**Evidencia `PROD-052` (2026-09-05):** el egress de advisories exige JSON
explícito y valida la forma raíz antes de persistir: OSV debe corresponder al
lote y no superar 100 vulnerabilidades por componente; GHSA se limita a un
advisory y CISA KEV a 5.000 entradas. HTML, JSON inválido, forma inesperada y
colecciones excesivas se descartan sin cuerpo, se notifican con un código
controlado y degradan la fuente como `invalid_source_data`; la caché se versionó
a `2026-09-05.2`. Las fixtures `MockTransport` comprueban además que no llega
cuerpo al log ni al disco. Pasaron las suites dirigidas de egress/OSV/GHSA/KEV,
`compileall`, la suite completa `backend/tests tools/tests`, `docker compose
config --quiet`, `git diff --check` y reconstrucción del backend con `/health`
correcto; no se hizo ninguna consulta a Internet.

**Evidencia `PROD-049` (2026-09-05):** el parser npm ya identifica aliases por
discrepancia entre ruta/nombre y clasifica enlaces, VCS y URLs ajenas al
registry npm público como no registry incluso si declaran versión. Esas entradas
no reciben versión/purl, no se envían a OSV y su `resolved`, destino de alias,
host, token o ruta se retira de resultado de proyecto, snapshot de inteligencia
y exportaciones CycloneDX/SPDX. La interfaz muestra su categoría y la frontera
local-only. Pasaron pruebas dirigidas backend/runner/PVI/egress, frontend
completo offline, `compileall`, la suite completa `backend/tests tools/tests`,
Compose, `git diff --check`, build 310,3/322 KiB y backend Docker con `/health`
correcto; no se hizo egress de advisories.

**Evidencia `PROD-055` (2026-09-05):**
`INSPECTRA_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES` acepta exclusivamente
exclusiones locales `exact`/`prefix`/`scope` y rechaza comodines, URL, rutas,
credenciales y valores vacíos. El egress usa esas reglas antes de construir el
lote y no conserva la regla ni el nombre excluido fuera del inventario local; la
cobertura se limita a `private_namespace`. Un `package-lock` npm sin resolución
HTTPS explícita de `registry.npmjs.org` ya no se clasifica como registro público:
queda `unknown`, por lo que Módulo 3 solo consulta componentes npm exactos con
esa procedencia y pareja segura. Pasaron pruebas simuladas de
payload/log/configuración/procedencia, `compileall`, suites backend/runner
completas, Compose, diff, frontend offline 38/259, build 310,3/322 KiB y backend
Docker `/health`; sin Internet. `PROD-101` queda en progreso.

**Evidencia `PROD-101` (2026-09-05):** el nuevo motor local
`vulnerability_correlation.py` recibe solo componente exacto y advisory ya
normalizado y devuelve `affected`, `not_affected` o `unknown` con razón
acotada, sin abrir sockets, leer archivos ni invocar egress. El flujo OSV lo
usa tanto para crear hallazgos como para mantener una respuesta que no puede
verificarse como `unavailable`, nunca como negativo. Corrige además el rango
OSV sin límite superior (`introduced=0`) como afectado. Pasaron pruebas puras e
integración OSV, `backend/tests tools/tests`, `compileall`, Compose, diff y
backend Docker `/health`; sin Internet. Durante la revisión se descubrió
`PROD-118`, ya en progreso, para no colapsar intervalos OSV discontinuos.

**Evidencia `PROD-118` (2026-09-05):** el contrato público OSV `2026-09-05.2`
descompone eventos ordenados en intervalos separados y acotados (25 intervalos,
50 eventos por rango), por lo que una reintroducción posterior se evalúa en vez
de perderse al tomar solo el primer `fixed`. Una secuencia fuera de orden,
malformada o por encima del límite queda marcada incompleta; el motor devuelve
`unknown`, la instantánea se degrada y nunca afirma `not_affected`. Pasaron
fixtures de reintroducción/límite/orden hostil, integración OSV, suite
backend/runner, `compileall`, Compose, diff y Docker `/health`; sin Internet.
`PROD-102` y `PROD-119` quedan completadas; se depuran las P1 pendientes para
seleccionar la siguiente que no duplique un vertical ya entregado.

**Evidencia `PROD-102` (2026-09-05):** la nueva huella `pvf_…` se calcula solo
desde proveedor, advisory público, PURL reconstruido, versión exacta y versiones
de contrato/regla; `evidence_digest` conserva los cambios de referencias,
fechas, rangos o severidad sin cambiar el ID. Los snapshots antiguos quedan
legibles con `fingerprint_version=legacy_evidence_digest`; API, informe,
documentación y tipos frontend lo reflejan sin rutas privadas. Pasaron 32 casos
dirigidos, la suite completa `backend/tests tools/tests`, `compileall`, Compose,
diff, imagen Docker backend y frontend temporal (38 archivos/259 pruebas y
build 310,3/322 KiB). Las suites no consultaron Internet.

**Evidencia `PROD-119` (2026-09-05):** el `python3` local es 3.10.12,
pero los lockfiles se resolvieron con Python 3.12 y contienen `websockets==17.1`;
`check-python-version` ahora rechaza 3.10 con código 2 y una instrucción para
elegir Python 3.12 antes de crear un entorno o usar pip. Con Python 3.12.14,
un venv temporal frío resolvió los locks y `make test-python` pasó 1337 pruebas;
la prueba estática, `compileall`, Compose y diff también pasaron.

**Evidencia `PROD-057` (2026-09-05):** cada job nuevo persiste el perfil
tipado `contract_version`, `profile_name`, `ruleset_version`, límite de carga y
concurrencia del backend; no admite claves extra ni identificadores con URL o
ruta. El store no permite que una actualización posterior reescriba esa
evidencia, los registros históricos siguen sin relleno retroactivo y la
comparación devuelve `not_comparable` ante perfiles distintos o ausencia de un
solo perfil. El detalle y el informe de proyecto muestran solo el resumen
seguro. Pasaron `backend/tests/test_execution_profile.py` y
`backend/tests/test_backend.py` con Python 3.12, las 4 pruebas estáticas de
workflow, `docker compose config --quiet`, `git diff --check`, 38 archivos/261
pruebas frontend y build 310,6/322 KiB. Un proyecto creado desde el ZIP
sintético documentado mostró el perfil persistido a 980 y 640 px, sin
desbordamiento horizontal y con egress público desactivado.

**Conciliación `PROD-088` y `PROD-090` (2026-09-05):** la auditoría del
vertical M3 confirmó que ambas tareas pendientes ya estaban cubiertas por los
incrementos implementados. `PublicAdvisoryEgressClient` solo construye el lote
OSV fijo a partir de identidad aprobada; fixtures verifican payload mínimo,
namespaces/locators privados excluidos, caché de clave irreversible y logs sin
payload. El normalizador vincula cada respuesta al orden del lote, rechaza
conteos/formas parciales y degrada en vez de emitir un negativo. La suite de
1337 pruebas ejecutada con Python 3.12 incluye esas regresiones, sin consultas
a proveedores públicos.

**Evidencia `PROD-111` (2026-09-05):** el aviso visible ofrece una muestra
sintética como elección manual desde `tests/fixtures/demo/passive-alpha/`, sin
lectura ni carga automática y sin prometer CVE o explotabilidad. Conserva la
redacción `[REDACTED]`, explica borrar el archivo y los trabajos de demostración
y declara que el historial conserva metadatos conforme a su política. La guía
en `docs/product-projects.md` fija el ZIP sugerido, el resultado esperado y el
límite de purga; `PROD-120` cubre la eliminación total futura. `App.test.tsx`
comprueba copy, foco y límites: pasaron 38 archivos/259 pruebas de frontend,
build y presupuesto 310,6/322 KiB, sin llamadas a proveedores.

**Evidencia `PROD-077` (2026-09-05):** la revisión reproducible con el fixture
`demo-archive-app-config.zip`, egress público desactivado y zoom 100 % recorrió
dashboard, espacio de trabajo y resultado a 1440, 980 y 640 px. Confirmó foco
en `#results`, anuncio `aria-live` y exportaciones antes de Raw JSON; a 640 no
hubo scroll horizontal de página. Detectó que una etiqueta de límite técnica
podía invadir su valor a 1440 px. `ProjectArchiveJobReport` marca ahora las
etiquetas y `styles.css` permite a `dt` contraerse y partirse; la nueva prueba
de componente y la guarda de estilos evitan la regresión. Tras reconstruir
Compose, las tres anchuras no mostraron solapamiento. Pasaron 38 archivos/260
pruebas frontend, build y presupuesto 310,6/322 KiB, 4 pruebas estáticas de
workflow, `docker compose config --quiet` y `git diff --check`; los detalles
están en `docs/frontend-visual-review.md`. `PROD-075` recibe el seguimiento de
presentación mínima de IDs y hashes, sin registrar una fuga confirmada.

**Evidencia `PROD-017` (2026-09-05):** el dashboard incorpora una guía visible
antes de las métricas para el recorrido instantánea autorizada → carga de archivo
→ creación/análisis del proyecto → resultados. El CTA selecciona Archive y
lleva el foco al selector con la explicación de límites: no ejecuta código,
instala dependencias, clona repositorios ni transmite código a proveedores
públicos. La revisión visual local con
`tests/fixtures/demo/passive-alpha/archives/demo-archive-app-config.zip`
recorrió la creación segura hasta el espacio de trabajo, hallazgos, inventario y
panel público con egress desactivado; no hubo avisos de consola. A 320, 768 y
1440 px no hubo desbordamiento horizontal de página. Durante la revisión se
corrigieron el ancho intrínseco del selector de archivos, filtros compactos y la
regla CSS que anulaba visualmente `hidden` en auditorías avanzadas. En una copia
temporal pasaron 36 suites/243 pruebas frontend, TypeScript/Vite y el presupuesto
316,4/322 KiB; ambos `docker compose config -q` (normal y privado con fixtures)
y `git diff --check` pasaron.

**Evidencia `PROD-030` (2026-09-05):** el panel de inteligencia pública permite
buscar advisory/CVE/GHSA, componente, versión y recomendación ya normalizados y
filtrar el snapshot retenido por CVSS, señal KEV, consenso de evidencia y alcance
directo/transitivo/opcional. Conserva recuento y estado vacío de filtros, la
frescura/degradación explícita y no solicita datos adicionales. Los enlaces se
validan de nuevo en el navegador: solo HTTPS sin credenciales, fragmento,
`localhost` o IP; una referencia insegura queda oculta. La revisión local del
panel con egress desactivado verificó mensajes, foco y acciones a 320/768/1440
px sin desbordamiento horizontal; descubrió y corrigió la anchura intrínseca de
selectores y acciones largas en móvil. Las fixtures cubren filtros combinados,
datos obsoletos, referencias hostiles y axe sin violaciones. En una copia
temporal pasaron 36 suites/250 pruebas frontend, TypeScript/Vite y presupuesto
316,4/322 KiB; ambos Compose con valores fixture y `git diff --check` pasaron.
No se habilitó egress ni se hizo consulta pública real.

**Evidencia `PROD-033` (2026-09-05):** la caché pública ya separa TTL (24 h
por defecto) de retención máxima (7 días, máximo 30), con reloj inyectable y
validación de que la retención no sea menor que el TTL. Al vencerse, la respuesta
pública desechable se elimina y no sirve de fallback; antes, una caída conserva
los hallazgos normalizados anteriores como cobertura `degraded` con fecha,
caducidad y razón limitada por fuente. Panel e informe no muestran diagnósticos
ni identidad consultada, y los snapshots anteriores siguen siendo legibles. La
evidencia completa y los comandos constan en `TODO_PRODUCTO.md`.

**Evidencia `PROD-051` (2026-09-05):** se conserva OSV como evidencia primaria
y GHSA como fuente secundaria aislada. Incompatibilidad de corrección o CVSS y
retirada GHSA pasan a un estado explicable en panel/informe sin fusionar rangos;
la retirada es histórica y no se presenta como corroboración actual. Las pruebas
deterministas cubren conflicto, retirada y URL hostil, junto con las regresiones
backend/frontend y Compose documentadas en `TODO_PRODUCTO.md`.

**Evidencia `PROD-050` (2026-09-05):** cada componente ya conserva una única
salida `affected`, `not_affected`, `not_correlatable` o `unavailable`, con razón
sin texto de proveedor. Una respuesta vacía válida no se confunde con una caída
o rango no verificable, y los recuentos aparecen en panel e informe. La
comparación histórica queda asignada explícitamente a `PROD-034`.

**Evidencia `PROD-010` (sincronizada el 2026-09-05):** el vertical original de
enriquecimiento reproducible quedó materializado de forma trazable en
`PROD-026`…`PROD-029`, `PROD-031`…`PROD-033`, `PROD-050` y `PROD-051`: egress
opt-in fijo, caché/versionado, normalización OSV/CVE/GHSA, fallos degradados,
fixtures sin red y UI/informes seguros. Se corrige su estado heredado para no
mantener dos backlogs contradictorios.

**Evidencia `PROD-011` y reconciliación `PROD-066` (2026-09-06):** Inspectra
conserva decisiones append-only por organización/proyecto/huella/regla con
transiciones explícitas, actor, motivo obligatorio, texto limitado y redactado,
asignación autorizada y revisión futura opcional de excepciones. Distingue una
revisión manual de una excepción vencida, reconstruye la cadena por enlaces y
rechaza historia manipulada; el resultado del analizador permanece inmutable.
Lista, filtros, detalle, comparación e informes consumen el estado. Pasaron
1.050 pruebas backend (23,92 s), 420 runner/guardas (6,49 s), 290 frontend
(20,98 s), build/presupuesto 314,9/322 KiB, `compileall`, ambos Compose y diff.
La revisión visual sintética recorrió decisión, fecha, historial, filtro,
comparación e informe a 1440/768/390/320 px sin scroll horizontal y con foco de
3 px. Se corrigieron una etiqueta de vencimiento falsa y la pérdida de fecha
del control nativo. Una invocación frontend inicial desde la raíz no ejecutó
pruebas por directorio incorrecto; se repitió correctamente y no se atribuyó al
sandbox. `PROD-066` queda satisfecho por este mismo vertical, sin duplicarlo;
la bitácora consultable/retención continúa separada en `PROD-013`, ahora en
progreso. No hubo Internet, proveedor ni proyecto real.

**Evidencia `PROD-013` (2026-09-06):** la actividad de alto valor se conserva
en un contrato mínimo por organización con archivos `0600`, retención y
capacidad acotadas, consulta paginada/filtrable solo administrativa y eventos
para sesión, equipo, proyecto, análisis, inteligencia, triage, exportación y
borrado de fuente. Una allowlist excluye nombres, cuerpos, código, evidencia,
rutas, URL, paquetes, hashes, cookies, tokens y credenciales; el expurgo no
sigue symlinks y el fallo de escritura produce una señal sin contexto sin
romper la acción primaria. Pasaron 1.058/1.058 backend (22,79 s), 420/420
runner/guardas (6,01 s), 42 archivos/292 frontend (20,67 s), build/presupuesto
315,4/322 KiB, `compileall`, ambos Compose y diff. La primera regresión aisló
una prueba de timeout que sometía un `fsync` real a 10 ms; se hizo determinista
y la suite final pasó. Tres invocaciones frontend desde la raíz no ejecutaron
por ausencia de `package.json` y se repitieron en la copia escribible correcta.
La revisión sintética cubrió filtro, vacío, rol administrador, foco de 3 px y
1440/768/390/320 sin desborde; no se afirmó consola limpia porque la capacidad
no estaba disponible. Sin Internet, proyecto real, push ni PR. `PROD-020` pasa
a ser la siguiente tarea viable de la cadena de privacidad/retención necesaria
para `PROD-036`, `PROD-040`, `PROD-062`, `PROD-075` y la candidatura.

**Evidencia `PROD-020` (2026-09-06):** el contrato visible separa fuentes,
resultados y snapshots normalizados, caché pública, exportaciones bajo demanda,
metadatos, triage, workspaces y actividad; declara honestamente que cifrado de
volumen y backups son responsabilidad del operador. La purga manual acepta cero
selectores, deriva la organización de la sesión, protege ejecuciones activas,
elimina evidencia pública derivada antes del job y devuelve resultado por clase
sin mensajes sensibles. La caché compartida solo selecciona documentos públicos
de clave digest. Una prueba reveló un interbloqueo real al entrar de nuevo en el
lock de storage durante el borrado derivado (69,51 s hasta interrupción); se
movieron callbacks fuera del lock y se revalida antes de borrar. Pasaron
1.063/1.063 backend (21,11 s), 420/420 runner/guardas (5,99 s), 43 archivos/295
frontend (20,30 s), build/presupuesto 315,9/322 KiB (7,57 s), `compileall`,
Compose base/privado y diff. Una primera regresión frontend encontró una
expectativa de cinco llamadas obsoleta; la repetición completa pasó. La revisión
visual sintética cubrió política, confirmación y resultado a 1440/768/390/320,
sin desborde y con foco sólido de 3 px. No hubo Internet, proveedor ni proyecto
real. Scheduler, cifrado aplicativo y backup externo siguen pendientes.

**Evidencia `PROD-036` (2026-09-06):** la vista previa y cascada owner/org-scoped
eliminan proyecto/baseline, trabajos terminales y resultados, snapshots de
inteligencia, triage, admisiones y workspaces, pero conservan expresamente la
subida fuente, caché pública, actividad mínima y copias externas. Un trabajo
activo bloquea el inicio; un journal `0600` sin contenido oculta el proyecto,
cierra admisiones, se reanuda al arrancar y mantiene readiness no disponible.
Pasaron 1.069 backend (38,72 s; 88.204 KiB RSS), 420 runner/guardas (6,23 s;
67.688 KiB RSS), 44 archivos/298 frontend (20,70 s; 574.408 KiB RSS), build
317,0/322 KiB (7,82 s), `compileall`, Compose base/privado y diff. La revisión
local sintética cubrió 1440/390 px, foco y éxito sin Internet/proveedor/proyecto
real; la consola no estaba disponible. El defecto de mensaje terminal hallado
se registra en `PROD-123`; en ese punto la purga total estaba bloqueada en
`PROD-120`, ahora pendiente tras completar la clasificación.

**Evidencia `PROD-040` (2026-09-06):** la nueva CLI administrativa offline
crea, verifica y restaura un bundle `2026-09-06.1` sin añadir una superficie
HTTP. Exige atestación de parada, sensibilidad y destino cifrado; incluye la
fuente necesaria para una recuperación coherente, resultados/derivados y
SQLite, y excluye locks, workspaces, journals y configuración/secretos externos.
Falla ante trabajo no terminal, WAL, symlink/hardlink, límite, checksum,
referencia rota o cruce de organización. Verifica semántica además del conjunto
exacto de digests; restaura a staging privado/directorio nuevo, migra auth 1→2,
revoca sesiones/intentos/invitaciones y no publica un árbol parcial. El runbook
declara cifrado/KMS externos, checksum sin autenticidad y RPO/RTO aún no
medidos. Pasaron 17 pruebas dirigidas (2,54 s; 62.164 KiB RSS), 1.087/1.087
backend (23,97 s; 88.724 KiB RSS), 420/420 runner/guardas (6,08 s; 67.760 KiB
RSS), `compileall`, Compose base/privado y diff, sin omisiones, red, proveedor,
proyecto real ni despliegue. El ensayo operativo permanece en `PROD-064`; la
clasificación `PROD-062`, siguiente bloqueo en ese momento, ya está completada.

**Evidencia `PROD-062` (2026-09-06):** el contrato `2026-09-06.2` clasifica
exactamente 14 clases con almacenamiento, sensibilidad, retención, borrado,
backup y restore, sin exponer rutas, nombres, paquetes ni conteos. La vista las
agrupa y hace explícitas las vidas independientes de fuente, resultado,
proyecto, descarga y backup. Se corrigió durante la revisión que restore
conserva usuarios/membresías pero descarta sesiones, intentos e invitaciones.
Pasaron 22 pruebas backend y 63 frontend dirigidas, 1.087/1.087 backend (23,34
s; 88.540 KiB RSS), 420/420 runner/guardas (6,06 s; 68.008 KiB RSS), 44
archivos/304 frontend (21,27 s; 579.760 KiB RSS), build/presupuesto 317,2/322
KiB (7,92 s), `compileall`, Compose base/privado y diff. La revisión local
1440×1000/390×844 comprobó 14 cards, ausencia de desborde y foco de 3 px, sin
ejecutar purga, usar red/proveedor/proyecto real ni afirmar consola limpia.
`PROD-120` queda desbloqueada; se añadió `PROD-124` para el ciclo de identidad.

### PROD-123 — Estados terminales exactos en inventario, hallazgos e inteligencia

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** los paneles de inventario, hallazgos e inteligencia
  pública describen una ejecución `failed` como si siguiera `queued` o
  `running`. El usuario necesita distinguir espera, fallo, cancelación y
  resultado completo ausente, con una acción recuperable coherente.
- **Archivos o áreas implicadas:** contratos/API de proyecto,
  `ProjectComponentInventoryPanel`, `ProjectFindingsPanel`,
  `ProjectVulnerabilityIntelligencePanel`, tipos, pruebas y guía visual.
- **Criterios de aceptación verificables:** los tres paneles distinguen estados
  activos, `failed`, `cancelled` y completado sin contrato; no muestran error
  interno, ruta o contenido y ofrecen reintentar/seleccionar otra ejecución
  cuando proceda. Contratos heredados degradan honestamente. Pruebas backend,
  componentes y axe cubren cada estado y una revisión visual reproduce fallo y
  cancelación en desktop/móvil con datos sintéticos.
- **Riesgo de no resolverla:** espera o reintentos innecesarios, diagnóstico
  inseguro y pérdida de confianza por estados contradictorios.
- **Estimación:** S
- **Dependencias:** PROD-015, PROD-030, PROD-035 y PROD-042 completadas.
- **Evidencia de validación al completarla:** 2026-09-06: backend y frontend
  separan `analysis_pending`, `analysis_failed` y `analysis_cancelled` en
  inventario, hallazgos e inteligencia. Una prueba ASGI con marcador sensible
  valida los tres endpoints y ambos terminales; un aviso compartido ofrece
  elegir snapshot/reintentar sin error bruto y la inteligencia no permite
  consultas. Pasaron 1.070 backend (21,69 s), 420 runner/guardas (6,22 s), 44
  archivos/304 frontend (21,10 s), 36 dirigidas con axe y build 317,2/322 KiB
  (8,03 s), más `compileall`, Compose y diff. La revisión sintética a 1440/390
  px confirmó fallo/cancelación, ausencia de desborde y foco de 3 px; no hubo
  Internet/proveedor/proyecto real y no se afirmó consola limpia. La cancelación
  visible se preparó por el mismo store probado porque el runner ausente fallaba
  antes de aceptar la carrera. Dos comandos frontend iniciales se corrigieron
  tras no ejecutar casos por ruta/opción, sin atribuirlo al sandbox.

**Evidencia `PROD-048` (2026-09-05):** el contrato `2026-09-05.6` solo marca
`direct`, `transitive` u `optional` cuando el manifiesto o el grafo npm v2/v3
acotado lo prueban. La deduplicación prefiere el alcance más accionable sin
convertir un nodo transitivo en directo; panel, filtro, informe y recomendación
explican la cadena/resolución a actualizar para transitivos y la activación para
opcionales. Pasaron 22 pruebas dirigidas backend/runner, 11 de paneles, la
regresión completa `backend/tests tools/tests`, `compileall`, ambos Compose,
36 suites/237 pruebas frontend, build/presupuesto 314,4/322 KiB y `git diff
--check`, siempre con fixtures/transportes simulados.

### PROD-124 — Retención y baja segura de invitaciones e identidades de equipo

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** el modo de equipo conserva usuarios, membresías y
  hashes de invitación sin un ciclo integral de baja y purga. Debe retirar
  acceso obsoleto y datos derivados sin romper ownership ni la trazabilidad
  administrativa mínima.
- **Archivos o áreas implicadas:** autenticación SQLite, equipos/invitaciones,
  sesiones, retención, auditoría, backup/restore, UI, documentación y pruebas.
- **Criterios de aceptación verificables:** existe una ventana documentada para
  purgar invitaciones usadas/revocadas/caducadas; nunca se expone token/hash; la
  baja revoca sesiones, respeta organización y último administrador, conserva
  referencias necesarias de forma explícita y se refleja en la política.
- **Riesgo de no resolverla:** acceso residual, retención innecesaria de
  material derivado de credenciales o pérdida accidental de propiedad/auditoría.
- **Estimación:** M
- **Dependencias:** PROD-012, PROD-013 y PROD-062; coordina PROD-109.
- **Evidencia de validación al completarla:** 2026-09-10: configuración
  `INSPECTRA_TEAM_INVITATION_RETENTION_DAYS` cerrada a 1–365 días (30 por
  defecto), purga de invitaciones terminales por organización y al arranque,
  sin serializar token/hash/username/rol/creador. La baja revoca solo sesiones
  del espacio, conserva otras membresías y, al quedar sin ninguna, desactiva y
  pseudonimiza username/hash mientras mantiene referencias opacas; último
  administrador sigue protegido. Contratos de ciclo de vida/limpieza subieron
  a `2026-09-10.3`/`2026-09-10.1` con 21 clases y UI explicable. Pasaron 24
  pruebas dirigidas de identidad/retención/restore/smoke, 5 de API/config/lifespan,
  9 frontend y la regresión Active aislada; suites completas backend
  1.561/1.561 y frontend 410/410, build 299,1/322 KiB, `compileall`, Compose
  base/privado y diff-check. El primer backend completo falló porque una prueba
  interceptaba el invalidator global heredado; se actualizó para exigir el
  ámbito organizativo y la repetición completa pasó. No hubo red, proveedor,
  proyecto externo ni promesa de borrado físico forense.

### PROD-023 — Restringir ubicaciones normalizadas a rutas seguras de proyecto

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** El normalizador actual acepta cualquier texto como `location.path`; aunque los analizadores de archivo lo producen como ruta relativa, una instantánea heredada o un adaptador futuro podría incluir una ruta absoluta o con traversal y hacer que las vistas de resultados la divulguen. Los informes de `PROD-006` ya la retienen defensivamente, pero el contrato común debe garantizarlo en origen.
- **Archivos o áreas implicadas:** `backend/app/finding_normalization.py`, contratos/API de hallazgos y comparación, componentes de resultados, fixtures y documentación de privacidad.
- **Criterios de aceptación verificables:** solo se conserva una ruta relativa normalizada, sin raíz Unix/Windows/UNC, `..`, controles ni URL; una ubicación insegura se sustituye por un estado explícito sin alterar evidencia ni filtrar el original. Las huellas, comparación e informes tienen una estrategia de compatibilidad versionada y pruebas cubren Linux, Windows, UNC, traversal y registros heredados.
- **Riesgo de no resolverla:** una futura fuente o dato heredado puede filtrar rutas internas a la interfaz, exportación o comparación.
- **Estimación:** M
- **Dependencias:** PROD-003, PROD-004 y PROD-005 completadas.
- **Evidencia de validación al completarla:** 2026-09-05: contrato `2026-09-05.1` normaliza barras y conserva únicamente rutas relativas sin raíz, esquema URL, traversal, segmentos ambiguos ni controles. Declara `location_status` (`reported`, `withheld_unsafe_path`, `not_reported`) y deja de incluir ubicación/línea insegura en la huella nueva. El lector aplica la misma política a contratos históricos antes de alimentar resultados, comparación o informe; las interfaces muestran la retención de forma explícita. Pruebas cubrieron Linux, Windows, UNC, traversal, URL, NUL, normalización portable, contratos heredados, panel/comparación/informe y no filtración; también pasaron las suites completas, build, presupuesto, Compose config y diff check.

### UX-005 — Extraer la presentación de informes de `App.tsx`

- **Prioridad:** P3
- **Estado:** completada
- **Descripción y motivo:** `frontend/src/App.tsx` concentra gran parte de la interfaz, lo que aumenta el coste de cambios futuros y dificulta probar componentes.
- **Archivos o áreas implicadas:** `frontend/src/App.tsx`, nuevos componentes de informes/resultados y pruebas.
- **Criterios de aceptación verificables:** la vista de informes se organiza en componentes con responsabilidades claras, interfaces tipadas y pruebas de interacción; no cambia el comportamiento salvo mejoras documentadas de UX/accesibilidad.
- **Riesgo de no resolverla:** mantenimiento lento y regresiones al modificar vistas densas.
- **Estimación:** L
- **Dependencias:** UX-001, UX-002 y UX-003.
- **Evidencia de validación al completarla:** 2026-09-05: completada junto con PERF-001. `App.tsx` delega la selección de los 27 formatos de informe a `JobResultReport.tsx`, un límite tipado que concentra las reglas de presentación y se carga bajo demanda. Los componentes de informe existentes conservan sus contratos y las pruebas de App, de informes y de restauración por URL pasaron en una copia limpia (30 archivos/210 pruebas), junto con el build de producción y su presupuesto de bundle.

### UX-006 — Incorporar regresión visual y revisión asistida de interfaz

- **Prioridad:** P3
- **Estado:** completada
- **Descripción y motivo:** No hay evidencia de una práctica repetible para detectar regresiones visuales en las pantallas de mayor valor.
- **Archivos o áreas implicadas:** tooling de frontend, CI, fixtures/datos de demostración y documentación.
- **Criterios de aceptación verificables:** las rutas principales se capturan a tamaños definidos; el cambio visual significativo se revisa deliberadamente en CI o en un flujo documentado; las imágenes/datos no contienen información sensible.
- **Riesgo de no resolverla:** deterioro progresivo de responsive, contraste y jerarquía sin detectarlo durante el desarrollo.
- **Estimación:** M
- **Dependencias:** ENG-001, UX-003 y UX-004.
- **Evidencia de validación al completarla:** 2026-09-05: se añadió `docs/frontend-visual-review.md`, un flujo obligatorio para cambios de interfaz con capturas de dashboard y resultado a 1440, 980 y 640 px, checklist de layout/foco/tablas/estados y plantilla de evidencia. El flujo obliga a usar el fixture sintético `demo-archive-app-config.zip`; las capturas locales se guardan en `visual-review/`, excluido de Git, y solo se adjuntan versiones mínimas y redactadas a revisión. Una guarda estática verifica fixture, matriz, validación frontend y exclusión. La revisión de escritorio con el stack Compose aislado confirmó backend disponible y ausencia de desbordamiento horizontal; las reglas tablet/móvil ya están cubiertas por pruebas responsive. En copias limpias pasaron 16 pruebas de documentación/Docker, 30 archivos/210 pruebas de frontend y el build con presupuesto. El stack temporal, sus redes y su lock efímero se eliminaron.

### PROD-075 — Privacidad de metadatos de fuente e historial

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** retener internamente nombre y digest ayuda a la
  integridad, pero mostrarlos por defecto en proyecto, historial o informes
  facilita correlacionar una fuente y revelar cliente, rama o topología.
- **Archivos o áreas implicadas:** modelos/proyecciones de proyecto y trabajo,
  almacenamiento, informes, frontend, política de retención, documentación y
  pruebas.
- **Criterios de aceptación verificables:** proyecto, historial, comparación,
  informe e integración usan una referencia segura derivada y no exponen nombre,
  digest ni ID de fuente; **Files** conserva su gestión explícita owner-scoped;
  la política clasifica los cuatro metadatos y contratos incompletos fallan
  cerrados sin dejar la aplicación en blanco.
- **Riesgo de no resolverla:** exposición persistente de etiquetas privadas,
  digest correlacionable o identificadores internos al compartir vistas/exportes.
- **Estimación:** M
- **Dependencias:** PROD-036 y PROD-062 completadas; complementa PROD-041.
- **Evidencia de validación al completarla:** 2026-09-06: contrato de retención
  `2026-09-06.3`, proyecciones API y UI usan `snapshot-…`; las pruebas negativas
  cubren nombre hostil y ausencia de `file_id`, `source_sha256`, `hashes` y
  `original_filename`. La revisión visual local sintética a 1440 × 1000 y 390 ×
  844 confirmó privacidad, responsive y foco visible. Detectó una respuesta
  antigua retenida durante recarga en caliente que producía pantalla blanca; se
  añadió degradación cerrada y regresión accesible. Pasaron backend 1.087,
  runner/guardas 420, frontend 44 archivos/306 pruebas, build y presupuesto
  317,4/322 KiB, `compileall`, Compose y diff. Sin Internet, proveedor, proyecto
  real ni despliegue. Detalle en `TODO_PRODUCTO.md` y
  `docs/frontend-visual-review.md`. Durante el smoke posterior de `PROD-116` se
  detectó que listados/detalle aún proyectaban `file_id` y que proyecto/
  snapshot exponían `source_file_id`: se cerraron esas proyecciones y **Files**
  recibió un modelo específico que conserva su ID solo en ese flujo
  owner-scoped. La regresión final cubre creación, historial, reintento,
  snapshot, detalle e informe sin esos IDs.

### PROD-064 — Ensayo de recuperación de datos y configuración operativa

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** una copia no constituye recuperación hasta probar
  corrupción, restore, aislamiento, revocación, rollback y limpieza sobre un
  flujo repetible sin ampliar la exposición de datos.
- **Archivos o áreas implicadas:** backup/restore y CLI, fixture/ensayo
  sintético, pruebas, runbook y aceptación de despliegue.
- **Criterios de aceptación verificables:** el ensayo no acepta datos reales,
  trabaja bajo un padre privado/cifrado atestado, no abre red, rechaza checksum
  inválido sin publicar un target, restaura dos owners aislados, verifica clases
  retenidas y egress deshabilitado, revoca acceso y elimina su workspace. La
  salida es acotada y los tiempos no se presentan como SLA.
- **Riesgo de no resolverla:** copia aparentemente válida pero irrecuperable,
  mezcla de propietarios, acceso restaurado o restos sensibles del ensayo.
- **Estimación:** M
- **Dependencias:** PROD-040 y PROD-062 completadas; desbloquea PROD-116.
- **Evidencia de validación al completarla:** 2026-09-06: `app.backup_cli drill`
  recorrió 13 archivos/132.546 bytes, corrupción y restore válido, dos owners,
  triage/auditoría/inteligencia/14 clases, una sesión e invitación revocadas,
  cero registros perdidos y cleanup. Midió 398,012 ms internos/0,78 s de proceso,
  solo como observación. Pasaron 23 pruebas dirigidas con bloqueo de sockets,
  backend 1.093/1.093 (25,01 s), runner/guardas 420/420 (6,12 s), frontend 44
  archivos/306 pruebas y build 317,4/322 KiB de la iteración anterior,
  `compileall`, Compose base/privado y diff. Sin Internet, proyecto real,
  instancia activa ni despliegue; el arranque/TLS/readiness queda en PROD-116.

### PROD-125 — Egress opt-in utilizable en la candidatura de aceptación

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** el perfil ordinario de aceptación aísla todas sus redes y Compose fija el egress público del backend a `false`. El cliente OSV/KEV está en el backend, por lo que una aceptación autorizada no puede alcanzar los proveedores aunque la política de aplicación sea correcta. Debe existir una ampliación separada que no abra la candidatura por defecto.
- **Archivos o áreas implicadas:** nuevo overlay Compose de egress para aceptación, configuración del backend, redes de la candidatura, pruebas estáticas y `DEPLOYMENT_ACCEPTANCE.md`.
- **Criterios de aceptación verificables:** la pila de aceptación sin el overlay continúa sin red pública y con egress desactivado; el overlay requiere activación explícita, conecta solo el backend a una red externa dedicada y no concede salida a frontend, proxy, `audit-tools` ni `network-tools`; la configuración renderizada prueba ambas variantes; la documentación exige autorización y apagar/recrear la pila para retirar la red.
- **Riesgo de no resolverla:** la prueba real falla siempre o un operador relaja la red completa de forma improvisada, ampliando el riesgo de fuga y haciendo falsa la evidencia de proveedores consultados.
- **Estimación:** S
- **Dependencias:** `PROD-026` y `PROD-116` completadas; autorización expresa de OSV/CISA KEV recibida para `PROD-117`.
- **Evidencia de validación al completarla:** 2026-09-06: `docker-compose.acceptance-egress.yml` quedó como cuarto overlay separado y exige `INSPECTRA_ACCEPTANCE_PUBLIC_ADVISORY_EGRESS_ENABLED`; sin él, el backend conserva `false` y no pertenece a ninguna red externa. Con la autorización, solo backend recibe `inspectra_public_advisory_egress`; `audit-tools`, `network-tools`, frontend y proxy no la comparten, y las tres redes previas continúan internas. La guía describe el orden preflight/activación/retirada y no presenta la red como autorización de proveedor. Ambas composiciones se renderizaron a JSON y se comprobaron programáticamente; pasaron 18 pruebas estáticas de Compose/seguridad y `git diff --check`. No se realizó egress ni se arrancó la fuente real durante esta tarea.

### PROD-126 — Eliminar el desborde horizontal del recorrido de proyecto a 320 px

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** la revisión visual real de `PROD-117` midió `document.scrollWidth=349` con viewport de 320 px y mostró una barra horizontal global en el espacio de proyecto. El propio panel de inteligencia cabe, por lo que debe identificarse y corregirse la estructura exterior sin ocultar el overflow legítimo de tablas.
- **Archivos o áreas implicadas:** estilos/layout responsive del frontend, paneles del workspace de proyecto, pruebas de regresión visual/estática y documentación de revisión.
- **Criterios de aceptación verificables:** dashboard, workspace, inteligencia, inventario, comparación y resultados tienen ancho de documento menor o igual al viewport a 320, 768 y 1440 px; tablas anchas conservan scroll dentro de su contenedor; foco y contenido no se recortan; existe una prueba que protege el selector causante y la revisión en navegador se repite.
- **Riesgo de no resolverla:** navegación móvil defectuosa, controles parcialmente fuera de pantalla y baja confianza en el producto durante onboarding y triage.
- **Estimación:** S
- **Dependencias:** `PROD-113` y `PROD-123` completadas; descubierto por la aceptación `PROD-117`.
- **Evidencia de validación al completarla:** 2026-09-06: la inspección de cajas en navegador aisló el desborde en el primer hijo de `.project-finding-toggle`: el identificador `requirements_dependency_not_exactly_pinned` imponía 302 px dentro de una tarjeta de 237 px. Se permitió encoger al grid interno y partir únicamente sus descendientes técnicos; no se añadió `overflow-x:hidden`. La prueba estática dirigida pasó 14/14 en una imagen de test limpia sin red y el build de producción pasó TypeScript, Vite y el presupuesto inicial (317,4/322 KiB). Sobre la imagen reconstruida, el workspace real midió documento/contenido 305/305 px a viewport 320, 753/753 a 768 y 1425/1425 a 1440; ocho encabezados muestreados tuvieron `scrollWidth=clientWidth`, las tablas mantuvieron `overflow-x:auto` local, el foco de teclado conservó contorno sólido de 3 px y la consola no registró errores ni avisos.

### PROD-127 — Compatibilidad estricta con respuestas resumidas de OSV

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** la API oficial de OSV puede devolver entradas de
  `querybatch` que contienen únicamente el identificador de la vulnerabilidad,
  mientras el fixture histórico incluía el advisory completo. Inspectra debía
  hidratar esas referencias desde el endpoint oficial fijo sin aceptar destinos
  dinámicos, perder los límites del transporte ni convertir la respuesta válida
  en una ausencia de vulnerabilidades.
- **Archivos o áreas implicadas:** `backend/app/public_advisory_egress.py`,
  pruebas del transporte/adaptador, contrato y documentación de inteligencia
  pública.
- **Criterios de aceptación verificables:** una respuesta de lote admite tanto
  `vulns` ausente como una lista válida; cada ID resumido que supera el patrón y
  el límite se consulta exclusivamente en `https://api.osv.dev/v1/vulns/{id}`
  con el mismo transporte HTTPS, sin redirecciones y acotado. IDs inválidos,
  duplicados o excesivos degradan de forma segura; las pruebas ordinarias usan
  adaptadores simulados y cubren respuesta vacía, resumen e hidratación.
- **Riesgo de no resolverla:** falso negativo masivo ante el proveedor oficial
  aunque la consulta fuese válida, o ampliación de SSRF/consumo al seguir una
  referencia externa no validada.
- **Estimación:** S
- **Dependencias:** `PROD-026`, `PROD-090` y aceptación real `PROD-117`.
- **Evidencia de validación al completarla:** 2026-09-06: el cliente acepta el
  formato observado de `querybatch`, valida/deduplica un máximo de 250 IDs y
  obtiene el detalle únicamente del host/ruta OSV compilados en código. Las
  regresiones simuladas pasaron dentro de la suite backend completa
  (1.523/1.523). La repetición real sobre la fuente autorizada B normalizó 28 IDs únicos, 25
  CVE y 33 ocurrencias de componente, con 0 discrepancias entre los IDs de lote,
  los detalles almacenados y el resultado normalizado; el tráfico capturado solo
  alcanzó `api.osv.dev`.

### PROD-128 — Presentación móvil e indicadores semánticos de inteligencia

- **Prioridad:** P0
- **Estado:** completada
- **Descripción y motivo:** la revisión de aceptación encontró que la rejilla
  del informe podía imponer ancho global a 320 px y que dos vistas denominaban
  “advisories” a ocurrencias de hallazgo por componente. Debían caber en móvil y
  distinguir conteos sin sugerir una cardinalidad o cobertura incorrectas.
- **Archivos o áreas implicadas:** `frontend/src/styles.css`, panel de
  inteligencia, comparación, informes backend, pruebas y guía visual.
- **Criterios de aceptación verificables:** informes y resultados pueden
  encoger dentro del viewport y partir texto técnico sin ocultar tablas; los
  contadores visibles hablan de hallazgos verificados cuando cuentan
  componente/advisory y no de advisories únicos. Pruebas protegen las reglas y
  textos; la revisión reproduce dashboard, workspace, detalle, comparación e
  informe a 320, 768 y 1440 px.
- **Riesgo de no resolverla:** controles/evidencia inaccesibles en móvil y
  decisiones de riesgo basadas en un contador mal interpretado.
- **Estimación:** S
- **Dependencias:** `PROD-113`, `PROD-126` y datos reales de `PROD-117`.
- **Evidencia de validación al completarla:** 2026-09-06: las rejillas usan
  columnas reducibles, los hijos de informe no fuerzan ancho y el texto técnico
  puede partirse; la prueba de estilos pasó en las 307 pruebas frontend y el
  build quedó en 317,4/322 KiB. En navegador, el informe y sus secciones midieron
  239 px dentro de 305 px útiles a viewport 320; la página coincidió con el
  ancho disponible a 320/768/1440 y las tablas conservaron desplazamiento local.
  Panel, comparación e informes usan ya “hallazgos verificados”.

### PROD-129 — Preparar un corte local coherente y revisable

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** tras el GO acotado, el siguiente paso es consolidar
  una candidatura local identificable: revisar el árbol completo, resolver la
  versión única del producto y alinear la documentación canónica sin declarar
  todavía una versión estable.
- **Archivos o áreas implicadas:** árbol Git de Inspectra, metadatos de versión
  backend/frontend, README, arquitectura, seguridad, despliegue y notas de
  candidatura.
- **Criterios de aceptación verificables:** el conjunto de cambios autorizado
  está revisado y atribuible, no incluye residuos de aceptación ni secretos;
  todas las superficies muestran una versión coherente y la documentación
  canónica describe exactamente capacidades, límites y proveedores validados.
  La candidatura se identifica por un commit local reproducible y vuelve a
  superar las puertas de validación, sin push ni publicación.
- **Riesgo de no resolverla:** construir o comunicar una release desde un árbol
  heterogéneo, con versión engañosa o cambios no revisados.
- **Estimación:** L
- **Dependencias:** `PROD-117`, `PROD-127` y `PROD-128` completadas. La
  consolidación local y la versión `0.3.0-beta.1` fueron autorizadas el
  2026-09-10; CI remoto y cualquier publicación permanecen fuera de alcance.
- **Evidencia de validación al completarla:** 2026-09-10: rama local creada
  desde `8e72f1e704f1fa05ff6cf72a70a697fda01b7d83` conservando exactamente el
  árbol inicial (`db9de357…` antes/después). El inventario clasifica 357 rutas:
  351 incluidas y seis excluidas como entorno/runtime, sin submódulos, cambios
  de modo ni material ambiguo. La serie local separa núcleo, frontend, CLI,
  documentación/release y fingerprints sintéticos; el tip que contiene esta
  evidencia es la identidad candidata, sin tag ni referencia remota.
  Gitleaks dejó limpio el historial completo y el canario detectó su señal; las
  53 señales del árbol previo a commits quedaron clasificadas como material
  sintético explícito en 25 pruebas/fixtures/documentos. La regresión del tip
  pasó 1.613 pruebas backend, 481 de herramientas, 65 CLI y 420 frontend,
  además de `compileall`, TypeScript, build, presupuesto 302,7/322 KiB, seis
  variantes Compose, `pip check`, sincronización de backlogs/versión y
  `git diff --check`. Cinco locks Python no reportan vulnerabilidades conocidas.
  La auditoría npm descubrió y se corrigió
  `CVE-2026-84373 / GHSA-82fw-gwwq-j7x9` con Vitest y `@vitest/mocker` 4.1.11;
  instalación limpia Node 22, pruebas y auditoría posterior quedaron verdes.
  Dos construcciones independientes produjeron los mismos SHA-256:
  wheel `fd3012ef…`, sdist `b35c7287…`, SBOM `666a5b90…` y `SHA256SUMS`
  `aef8d96d…`; el wheel se instaló y verificó offline fuera del repositorio.
  El smoke TLS sintético del commit candidato terminó en 1.296,506 ms con
  salud/readiness, cabeceras, auth/cookie/CSRF, análisis, privacidad, egress
  apagado, 25 clases de retención, informes y cleanup; no contactó proveedores.
  Al retirar el runner, health siguió 200 y readiness pasó 503; la recuperación
  volvió a 200. La limpieza final dejó cero contenedores, volúmenes, redes,
  imágenes y temporales del candidato. El primer intento de suite agotó 512 MiB
  exactos de `/tmp`; se aisló por grupos y la repetición con 2 GiB pasó. Dos
  intentos de smoke ejecutaron cero flujo por dependencia cliente ausente y CA
  `0600`; se diagnosticaron y la pasada válida se repitió completa. No hubo
  push, PR, tag, release, publicación ni despliegue.

### PROD-130 — Validar CI remoto y cerrar la puerta de release

- **Prioridad:** P1
- **Estado:** en progreso
- **Descripción y motivo:** una candidatura destinada a equipos necesita que
  sus comprobaciones se reproduzcan en CI sobre el commit exacto y que las
  acciones de terceros estén ancladas antes de autorizar cualquier publicación.
- **Archivos o áreas implicadas:** `.github/workflows/ci.yml`, `SEC-012`,
  documentación de release, evidencias CI y checklist de despliegue.
- **Criterios de aceptación verificables:** `SEC-012` se ejecuta solo tras
  autorización explícita; las acciones quedan ancladas a SHA verificado; CI
  remoto ejecuta pruebas, build, auditorías y guardas sobre el commit exacto del
  corte, sin secretos innecesarios, y conserva enlaces/evidencia verificables.
  Un fallo impide etiquetar o desplegar.
- **Riesgo de no resolverla:** cadena de suministro mutable o divergencia entre
  la candidatura probada localmente y la que se pretenda publicar.
- **Estimación:** M
- **Dependencias:** `PROD-129` y `SEC-012`; requiere autorización explícita para
  cambiar `SEC-012` y para cualquier push/PR. Ambas autorizaciones fueron
  concedidas el 2026-09-10 para este ciclo remoto limitado.
- **Evidencia de validación al completarla:** en progreso; con autorización
  explícita se reescribió exclusivamente la serie local inédita, sin bypass ni
  force-push. La rama remota y el PR borrador #1 apuntan al commit exacto
  `3d912d2e8196c5185b8e378fd3e04ca692b99a01`. El primer CI remoto dejó verdes
  Compose, Gitleaks (historial y canario) y Python; frontend instaló sin
  vulnerabilidades y ejecutó las 420 pruebas, pero cuatro esperas asíncronas de
  `App.test.tsx` fallaron bajo carga antes de permitir build/audit. El caso se
  reprodujo con Node 22/Vitest 4.1.11 y cuatro CPU (419/420): el DOM ya mostraba
  la sesión autenticada, pero una transición secundaria superó el segundo
  implícito. Cuatro aserciones de transición usan ahora un presupuesto local de
  5 s, sin relajar el resto de la suite; dos repeticiones completas pasaron
  420/420, build 302,7/322 KiB y `npm audit` cero vulnerabilidades. Pendiente
  repetir todas las puertas en CI; no se promoverá una ejecución parcial. No
  hubo tag, release, publicación ni despliegue; `SEC-012` sigue bloqueada hasta
  disponer de evidencia remota completa.

### PROD-179 — Readiness efectivo del runner por capacidad

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** la consola Active debía distinguir una política
  backend habilitada de un runner realmente disponible y con su gate equivalente
  habilitado, sin convertir una consulta de estado en tráfico de análisis.
- **Archivos o áreas implicadas:** cliente interno `active-tools`, servicio y
  contrato de health, resumen de operaciones Active, interfaz, estilos, pruebas,
  Compose y documentación operativa.
- **Criterios de aceptación verificables:** las cinco capacidades combinan ambos
  gates en estados cerrados `disabled`, `ready`, `degraded` o `unavailable`; el
  health no acepta target, no ejecuta capacidades, no sigue redirecciones y se
  limita a 2 segundos/4 KiB; un fallo no oculta el registro pero bloquea ejecutar;
  URL, host, path y target internos no aparecen en API, DOM ni logs de producto.
- **Riesgo de no resolverla:** mostrar una capacidad como utilizable cuando el
  runner no puede admitirla, fallar tarde en operación o filtrar topología interna.
- **Estimación:** M
- **Dependencias:** PROD-171 y PROD-175 completadas.
- **Evidencia de validación al completarla:** 2026-09-08: el runner real bajo
  `--network none` devolvió 657 B con cinco gates off y 687 B con cinco gates on,
  siempre con cero peticiones/ejecuciones; un query con target quedó bloqueado sin
  eco. El recorrido sintético en navegador confirmó
  `degraded → ready → unavailable → ready`, registro legible durante la caída,
  ejecución deshabilitada salvo `ready`, cero topología visible y ausencia de
  overflow a 320/768/1440 (documento 305/305, 753/753 y 1425/1425 px). Esa revisión
  descubrió y corrigió el resumen obsoleto tras alta/mutaciones. Fixtures cubren
  timeout, conexión, redirect, exceso de tamaño, JSON, identidad y capacidades
  incompletas/desalineadas; axe dirigido no encontró violaciones. Validación final:
  backend+tools 1.609/1.609 con red deshabilitada, frontend 326/326, TypeScript,
  build (bundle inicial 279,7/322 KiB), Compose base/privado/Active y diff-check.
  Los cuatro ficheros sintéticos, contenedores, red, datos y navegador se limpiaron;
  no hubo ejecución Active, objetivo real, push, PR ni despliegue.

### PROD-183 — Cola durable, progreso y recuperación de ejecuciones Active

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** una ejecución Active debía sobrevivir a la petición
  que la admite, poder cancelarse desde otra petición/worker, recuperarse solo
  cuando todavía no había empezado y reintentarse sin duplicar tráfico.
- **Archivos o áreas implicadas:** `backend/app/main.py`, `models.py`,
  `storage.py`, contrato Active, API y centro frontend, pruebas, README,
  arquitectura y runbook Active.
- **Criterios de aceptación verificables:** job persistido antes del runner;
  `queued → running → completed|failed|cancelled` con fase cerrada; claim atómico;
  cancelación owner/asset-scoped corta el runner incluso si llega a otro worker;
  recovery solo de `queued` tras revalidar revisión/perfil; retry enlazado e
  idempotente; ningún target, clave o digest privado en API/log/report.
- **Riesgo de no resolverla:** timeouts del navegador podían ocultar el estado,
  duplicar observaciones, impedir cancelación y reejecutar tráfico incierto tras
  reinicio.
- **Estimación:** L
- **Dependencias:** `PROD-008`, `PROD-149` y `PROD-175`, completadas.
- **Evidencia de validación al completarla:** 2026-09-08: la API devuelve el job
  inicial `queued` y lo ejecuta fuera de la petición; el store hace CAS bajo lock,
  conserva el contrato inmutable y solo un worker gana una carrera de dos. Replay
  exacto reutiliza ID sin nuevo evento/runner y conflicto devuelve `409`; cancel
  persiste antes de señalar, se observó desde un worker simulado distinto y
  descartó parciales; retry creó un ID enlazado y fue idempotente. Startup retomó
  un `queued` válido y rechazó revisión alterada sin llamar al runner; `running`
  interrumpido quedó fallido, no reejecutado. Pasaron 42/42 pruebas Active,
  1.185/1.185 backend y 429/429 runner/guardas con Docker `--network none`, y
  327/327 frontend con axe; TypeScript/build y bundle inicial 280,2/322 KiB;
  Compose base/privado/Active y `git diff --check`. Revisión visual local real con
  runner indisponible mostró `queued`, `running`, `cancelling` y `failed`, bloqueo
  de retry por readiness, acciones y tabla con scroll local; documento/body sin
  overflow a 320 (305/305), 768 (753/753) y 1440 (1425/1425) px. Vista, contenedor,
  imagen y datos sintéticos temporales fueron eliminados. No hubo egress de tests,
  capacidad/target real, push, PR ni despliegue.

### PROD-184 — Cuotas Active por organización y límites operativos

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** la cola durable necesitaba límites Active propios
  para impedir que una organización, activo o capacidad agotase el runner y la
  red, manteniendo una respuesta recuperable sin revelar carga ajena.
- **Archivos o áreas implicadas:** configuración backend, admisión persistente
  de jobs, revocación/cancelación, resumen de operaciones, centro frontend,
  Compose, pruebas y documentación operativa.
- **Criterios de aceptación verificables:** límites conservadores globales, por
  organización, activo y capacidad; replay idempotente y admisión dentro del
  mismo lock; carrera multiworker sin sobre-admisión; `429`/`Retry-After`
  uniforme sin recuentos, targets o revisiones; ningún runner contactado al
  rechazar; cuota consumida durante `queued/running/cancelling` y liberada solo
  en estado terminal; resumen/UI únicamente `ready|saturated` y bloqueo de
  nuevas ejecuciones sin ocultar resultados existentes.
- **Riesgo de no resolverla:** abuso o carrera entre workers podía monopolizar
  recursos, crear tráfico por encima de los límites o filtrar indirectamente la
  actividad de otros equipos.
- **Estimación:** M
- **Dependencias:** `PROD-149`, `PROD-171` y `PROD-183`, completadas.
- **Evidencia de validación al completarla:** 2026-09-08: defaults 16 global,
  4/organización, 2/activo y 4/capacidad, relaciones fail-closed al arrancar y
  variables Compose documentadas. Ocho stores/workers concurrentes contra un
  activo produjeron exactamente una admisión; los límites global/org/capacidad
  devolvieron el mismo `429` y el log cerrado no incluyó IDs de activo. Un store
  recreado respetó el cupo persistido; fallo/cancelación terminal lo liberó, y
  revocación dejó un runner activo en `cancelling` hasta descartar parciales.
  La ruta saturada no llamó al runner. Pasaron 55/55 pruebas Active dirigidas,
  1.191/1.191 backend y 429/429 tools en Docker `--network none`; frontend
  328/328 con axe, TypeScript/build y bundle inicial 280,2/322 KiB. Compose
  base/privado/Active y `git diff --check` correctos; no se ejecutó ninguna
  capacidad, target externo, push, PR, tag, release ni despliegue.

### PROD-187 — Egress de verificación de control aislado en runner

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** las verificaciones públicas DNS TXT y HTTP
  well-known debían abandonar el backend privilegiado y ejecutarse solo dentro
  de `active-tools`, con un segundo gate operativo y revocación efectiva.
- **Archivos o áreas implicadas:** store/flujo de verificación Active, cliente
  interno, health del runner, nueva frontera `active_runner/verification.py`,
  Compose, centro frontend, documentación y pruebas.
- **Criterios de aceptación verificables:** backend sin DNS/socket/HTTP live;
  doble opt-in backend/runner; ruta y contrato internos fijos; destino derivado
  del activo, sin input público; resolución acotada, IP global fijada, 3 s,
  512 B, sin redirects ni proxy ambiental; respuesta únicamente booleana/código
  cerrado; revocación local o cross-worker cancela y descarta; token/target/raw
  response ausentes de respuesta, persistencia, auditoría e informes.
- **Riesgo de no resolverla:** un backend más privilegiado conservaba superficie
  SSRF/egress y una revocación podía dejar tráfico vivo o filtrar el reto.
- **Estimación:** L
- **Dependencias:** `PROD-170` y `PROD-175`, completadas.
- **Evidencia de validación al completarla:** 2026-09-08: DNS/HTTP se movieron a
  `/active/asset-verification` en `active-tools`; health incluye su gate separado
  y la UI solo ofrece métodos remotos si ambos opt-ins están listos. El cliente
  usa ruta fija, `trust_env=False`, sin redirects, 4 s/1 KiB para la frontera
  interna; el runner limita la operación a 3 s/512 B, hasta 8 respuestas DNS y
  una IP global fijada. Fixtures cubren gate off, esquema hostil, userinfo/path,
  destino privado, redirect, exceso de tamaño, respuesta inconsistente,
  timeout/error y canarios. Una verificación lenta fue revocada concurrentemente,
  su tarea recibió cancelación y el token no quedó persistido. Pasaron 70/70
  pruebas dirigidas, backend 1.197/1.197 y tools 439/439 en Docker
  `--network none`, frontend 328/328 con axe, TypeScript/build y bundle inicial
  280,2/322 KiB; Compose y diff-check correctos. Imagen real local
  `sha256:9dbe4b8…f1d3e9` mostró gate off/on y cero peticiones en health bajo
  `--network none`, y fue eliminada. No hubo verificación/target externo, push,
  PR, tag, release ni despliegue.

### PROD-178 — Retención y borrado Active owner-scoped

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** activos, verificaciones, revisiones y resultados
  necesitaban un borrado explícito coherente con la política, sin conservar
  targets ni romper la auditoría mínima permitida.
- **Archivos o áreas implicadas:** contrato y servicio de borrado Active,
  stores de activos/verificaciones/jobs, admisión, API/UI, auditoría de producto,
  retención, backup/restore, estilos, pruebas y documentación.
- **Criterios de aceptación verificables:** preflight owner-scoped y sin target;
  confirmación exacta; trabajo vivo/reto pendiente bloquea; journal reanudable;
  admisión y mutaciones cerradas durante el proceso; cascada sin huérfanos;
  auditoría anonimizada; política, backup y restore conocen las clases Active;
  recorrido accesible y responsive.
- **Riesgo de no resolverla:** retención indefinida o borrado parcial podía
  revelar infraestructura, dejar retos/resultados huérfanos o conservar una
  auditoría capaz de reconstruir el activo.
- **Estimación:** L
- **Dependencias:** `PROD-148`, retención y borrado de proyectos existentes.
- **Evidencia de validación al completarla:** 2026-09-08: contrato de retención
  `2026-09-10.1` con 19 clases, preflight/DELETE, journal write-ahead y cascada
  idempotente implementados. Fallo entre fases, recovery, backup/restore, otro
  owner, trabajo vivo, reto pendiente y journal hostil tienen regresiones.
  Pasaron backend 1.206/1.206 y tools 439/439 en Docker `--network none`, frontend
  331/331 más 34/34 tras el último ajuste CSS, TypeScript/build y bundle inicial
  280,5/322 KiB. Recorrido sintético 320/768/1440 sin overflow ni target en DOM;
  API vacía y cero canarios tras borrar. Solo quedaron eventos cerrados ligados
  a un recibo opaco; contenedor, imagen, datos y capturas temporales se eliminaron.

### PROD-186 — Bundle de evidencia Active verificable

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** equipos necesitaban conservar antes del borrado una
  evidencia reproducible y comprobable sin exportar el target ni resultados
  crudos.
- **Archivos o áreas implicadas:** proyección de postura, constructor/validador
  TAR, API, centro Active, estilos, documentación y pruebas.
- **Criterios de aceptación verificables:** seis entradas fijas, metadatos TAR
  canónicos, manifiesto versionado y checksums; periodos cerrados; límites de
  entradas/tamaño/historial; resultados allowlisted; otro owner denegado;
  manipulación rechazada; validador offline sin extracción; UI accesible y
  responsive.
- **Riesgo de no resolverla:** una exportación libre podía exfiltrar inventario
  o dar una falsa cadena de custodia sobre datos no reproducibles.
- **Estimación:** M
- **Dependencias:** `PROD-169` y `PROD-185`, completadas.
- **Evidencia de validación al completarla:** 2026-09-08: contrato
  `2026-09-08.1`, máximo 100 ejecuciones, 512 KiB/entrada y 4 MiB/TAR. Dos
  descargas y una tras reinicio fueron byte-idénticas (`d9d8cf…8af3d`); el
  validador de seis entradas pasó y el escaneo binario halló cero canarios de
  target, referencia, nota o raw result. Fixtures cubren checksum manipulado,
  truncado, identidades no allowlisted y aislamiento. Backend 1.208/1.208 bajo
  `--network none`, frontend 333/333+axe, build 280,7/322 KiB, Compose y
  diff-check. Revisión 320/768/1440 sin overflow; enlaces corregidos de 19 a
  44 px. Recursos sintéticos eliminados. El artefacto prueba integridad interna,
  no firma, límite explícito en documentación.

### PROD-145 — Cartera global por riesgo, cobertura y frescura

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** ofrece a seguridad y desarrollo una vista global de
  la organización para decidir qué proyecto revisar sin una puntuación opaca.
- **Archivos o áreas implicadas:** proyección y contrato de cartera, API y roles,
  triage bulk, frontend, contratos de proyectos/hallazgos/PVI y documentación.
- **Criterios de aceptación verificables:** señales cerradas de severidad, KEV,
  cambios comparables, cobertura/frescura, baseline, estado y acciones; filtros
  body-only, búsqueda, orden estable, cursor owner-scoped y deep link; estados
  carga/vacío/no-match/error, axe, responsive y escala sintética.
- **Riesgo de no resolverla:** agregación cruzada puede revelar otro tenant o
  declarar limpio un proyecto con cobertura perdida o evidencia caducada.
- **Estimación:** L
- **Dependencias:** `PROD-065`, `PROD-104` y parte de `PROD-108`, ya disponibles.
- **Evidencia de validación al completarla:** 2026-09-09: contrato
  `2026-09-09.1` y POST owner-scoped con prioridad explicable, KEV separado,
  cursor HMAC y caducidad recalculada. Pasaron 16 pruebas backend y 56 frontend
  con axe; TypeScript/build y bundle 287,3/322 KiB. Proyección de 2.000 proyectos:
  0,753 s y 84.328 KiB RSS. Revisión local desktop/móvil 375/375 sin overflow,
  filtro High y deep link correctos. Servicios cerrados y datos sintéticos
  enviados a papelera; sin red externa.

### PROD-146 — Centro de remediación transversal

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** agrupar evidencia actual de varios proyectos por una
  acción común, aplicar triage acotado y exportar un plan sin ejecutar gestores
  ni presentar una corrección como verificada antes de reanalizar.
- **Áreas:** `remediation_center.py`, lifecycle append-only, API/modelos,
  reporting JSON/CSV, panel frontend, contratos, documentación y pruebas.
- **Aceptación:** agrupación owner-scoped estable de hallazgos locales y públicos;
  instalada/afectada/corregida, alcance directa/transitiva/desconocida, conflictos,
  CVE/GHSA y KEV separados; selección exacta de hasta 25 ocurrencias con revisión
  de grupo y escritura atómica; resolución actual pasa a `awaiting_reanalysis` o
  `still_detected`; exportación consentida y acotada; carga/vacío/error/stale,
  teclado, axe y 320/768/1440.
- **Riesgo:** una agrupación o actualización incorrecta puede propagar triage entre
  proyectos, ocultar evidencia vigente o sugerir una compatibilidad inexistente.
- **Estimación:** L
- **Dependencias:** `PROD-046`, `PROD-048`, `PROD-066` y `PROD-145`, completadas.
- **Evidencia:** 2026-09-09: contrato owner-scoped con cursores HMAC canónicos y
  `409` ante cambio concurrente; planes por componente/advisory/versión común,
  conflictos sin objetivo automático, exposición `not_assessed` y comandos no
  ejecutables. El lote append-only pre-valida y revierte escrituras ante fallo;
  el informe limita 2.000 grupos/5.000 ocurrencias y omite rutas, contenido,
  comentarios e identidades. Pasaron 24 pruebas backend dirigidas, 57 frontend
  con axe, `compileall` y build (289,8/322 KiB). La revisión visual sintética a
  320/768/1440 verificó filtros, detalle, selección, persistencia tras reinicio y
  descargas JSON/CSV; corrigió el consentimiento responsive. Servicios, puertos y
  fixture fueron eliminados, sin Internet ni ejecución de gestores.

### PROD-147 — Tendencias reproducibles y vistas por perfil

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** ofrecer a desarrollo, seguridad y dirección una
  evolución común del riesgo sin mezclar ejecuciones incompatibles ni crear una
  puntuación o SLA opacos.
- **Áreas:** `project_risk_trends.py`, modelos/API, reporting JSON/CSV,
  `ProjectRiskTrendsPanel`, App/estilos, contratos y revisión visual.
- **Aceptación:** periodos cerrados 30/90/180 y buckets 7/30; cambios solo entre
  análisis consecutivos con perfil registrado y cobertura equivalente; PVI solo
  con snapshots `ready`; denominadores/exclusiones, cohortes de primera revisión
  y resolución verificada, ecosistema/fuente, tres perfiles sobre los mismos
  hechos, exportación consentida y estados accesibles/responsive.
- **Riesgo:** tendencias incomparables o sin denominador inducen prioridades y
  conclusiones ejecutivas falsas; una agregación cruzada filtra actividad.
- **Estimación:** L
- **Dependencias:** `PROD-105`, `PROD-145` y `PROD-146`, completadas.
- **Evidencia:** 2026-09-09: proyección owner-scoped limitada a 5.000 proyectos y
  10.000 análisis desde el índice; valida cada registro y cuenta aparte falta de
  predecesor/perfil, perfil cambiado, cobertura, PVI y datos inválidos. KEV no se
  mezcla con CVSS y `resolved` exige desaparición comparable. Pasaron 17 pruebas
  backend dirigidas, 60 frontend con axe, `compileall`, diff-check y build
  291,0/322 KiB. Revisión real sintética 320/768/1440 verificó perfiles,
  metodología, navegación y CSV con digest; corrigió ARIA, compatibilidad TS,
  cabecera móvil y overflow post-export. Puertos/servicios cerrados y fixture en
  papelera; ninguna consulta externa ni gestor ejecutado. `PROD-105` queda
  materializada; objetivos configurables siguen separados en `PROD-022`.

### PROD-213 — Canal de incorporación atestado

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** diferenciar archivo, Git/CLI, CI y SBOM mediante el
  punto de admisión, no por heurística sobre un commit.
- **Áreas:** snapshots/journal, endpoints, CLI, cartera, informes y backup.
- **Aceptación:** enum fijado por servidor, append-only, preservado en
  replay/recovery/restore; legacy `unknown_git_or_ci`; matriz de rutas y owners.
- **Riesgo:** trazabilidad falsa o canal manipulable.
- **Estimación:** M
- **Dependencias:** `PROD-134`, `PROD-145`.
- **Evidencia:** 2026-09-09: contratos de metadatos/admisión versionados; el
  servidor fija `archive_upload`, `git_cli`, `ci` o `sbom`, mientras los registros
  antiguos con commit se presentan conservadoramente como `unknown_git_or_ci`.
  Replay, recuperación, restore, cartera, historial, informe y retención preservan
  el dato sin permitir que el cliente lo suplante. Pasaron 15/15 pruebas backend
  dirigidas, 1.886/1.886 backend+tools, 34/34 CLI en grupos offline y 396/396
  frontend; también TypeScript, build (293,7/322 KiB), `compileall`, Compose y
  `git diff --check`. La revisión visual sintética en escritorio y 320 px mostró
  ambos canales sin overflow ni errores de consola; fixture enviado a papelera y
  servicios/puertos cerrados. No hubo red, proveedor real ni código de proyecto.

### PROD-214 — Índice duradero de cartera de proyectos

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** eliminar el límite operativo y el recorrido completo
  del listado heredado para organizaciones grandes.
- **Áreas:** índice privado, `ProjectStore`, API/App, backup/readiness y escala.
- **Aceptación:** ningún consumidor usa lista completa; página owner-scoped con
  validación autoritativa; fixture 20.000, corrupción/reinicio y presupuesto.
- **Riesgo:** IO/memoria no acotados o exposición al indexar nombres/señales.
- **Estimación:** L
- **Dependencias:** `PROD-145`, `PROD-208`.
- **Evidencia:** 2026-09-09: índice SQLite v2 privado, migrable y
  reconstruible; no conserva nombres, filenames, hallazgos ni texto. `POST
  /projects/search` entrega páginas de 50 (máximo 100), total exacto y cursor
  HMAC canónico ligado a owner y revisión autoritativa; cambios concurrentes,
  manipulación, alias Base64URL y corrupción fallan cerrados. Cada fila elegida
  se revalida contra su JSON/digest. `GET /projects` queda deprecado y acotado a
  100; App pagina, conserva filas y abre un deep link mediante consulta directa.
  Borrado/recovery retiran primero la referencia visible; backup valida esquema
  exacto. Los consumidores agregados cargan como máximo 5.001 registros y
  mantienen visible el límite 5.000 hasta `PROD-241`. Fixture 20.000/dos owners:
  18.000/2.000 aislados, 20 páginas warm, p95 <0,5 s y pico <32 MiB, sin glob.
  Pasaron 43/43 pruebas dirigidas, 1.889/1.889 backend+tools offline, 399/399
  frontend, TypeScript/build (295,1/322 KiB), `compileall`, Compose base/privado
  con valores sintéticos y `git diff --check`. Revisión local 50→51, deep link
  fuera de página y fragmento inválido; a 320 px el documento fue 305/305 y la
  tabla 237/672 dentro de scroll propio, sin errores de consola. Tabs, servicios,
  puertos, datos y capturas temporales quedaron eliminados; sin red externa.

### PROD-240 — Permisos y tipo seguro del lock de almacenamiento

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** el primer listado paginado tras restore reveló que
  `.locks` y `storage.lock` heredaban el `umask`; un directorio `0755` ampliaba
  metadatos visibles y una ruta enlazada podía desviar el lock.
- **Áreas:** `storage_lock`, backup/restore y regresiones backend.
- **Aceptación:** directorio `0700`, archivo regular único `0600`, apertura sin
  seguir symlink, rechazo de directorio enlazado y restore mantiene permisos.
- **Riesgo:** exposición local de metadatos, bloqueo fuera del volumen o
  sincronización falsa ante manipulación del host.
- **Estimación:** S
- **Dependencias:** hallazgo reproducido durante `PROD-214`.
- **Evidencia:** 2026-09-09: apertura con `O_NOFOLLOW` cuando está disponible,
  `fstat`, rechazo de hardlink y permisos forzados. Las pruebas de backup y lock
  verifican restauración, `0700`/`0600` y symlink; incluidas en las 41/41
  dirigidas de `PROD-214`, todas offline.

### PROD-241 — Proyección materializada de prioridad de cartera a gran escala

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** el listado operativo ya pagina 20.000 proyectos,
  pero prioridad/remediación/tendencias conservan por diseño un preflight máximo
  de 5.000 para no recalcular todos los hallazgos en una petición.
- **Áreas:** cartera, jobs/PVI/lifecycle, índice privado, backup/readiness y UI.
- **Aceptación:** señales cerradas materializadas sin nombres, rutas ni evidencia;
  orden/filtros equivalentes a la proyección actual, validación por digest,
  actualización/rebuild/reinicio y fixture de 20.000/dos owners con presupuesto.
- **Riesgo:** quitar el límite sin proyección produciría presión de CPU/IO; un
  agregado stale o cruzado falsearía prioridad y expondría existencia.
- **Estimación:** L
- **Dependencias:** `PROD-214` y proyecciones de jobs/lifecycle existentes.
- **Evidencia:** completada el 2026-09-10. Índice SQLite privado schema v2 con
  tokens HMAC exactos/de prefijo, hechos cerrados y digest de proyección; ninguna
  fila conserva nombres, rutas, componentes, evidencia o texto. SQL aplica
  filtros, orden, resumen y paginación; la página seleccionada se revalida contra
  la autoridad. Corrupción, topología de prefijos incompleta, reinicio, refresh a
  30 días, dos propietarios y equivalencia con `_matches`, `_sort_key` y
  `_portfolio_summary` quedan cubiertos. Fixture 20.000 (18.000/2.000): rebuild
  frío total 5,379 s, consulta caliente p95 0,264 s, pico incremental 271.699 B,
  240 lecturas autoritativas/10 páginas y base 116.727.808 B. Pasaron 13/13 de
  cartera, 13/13 backup/tendencias/remediación, 6/6 API/readiness/smoke, frontend
  419/419 tras repetir una prueba Active aislada inicialmente intermitente,
  build 302,5/322 KiB y revisión visual local desktop/móvil sin overflow ni
  errores de consola. La suite backend monolítica obtuvo 1.592/1.593 dos veces:
  solo el presupuesto temporal preexistente del plan de remediación de 20.000
  proyectos falló bajo carga acumulada (36,35 s y 7,56 s frente a 5 s), aunque
  aislado pasó en 2,59 s y su archivo 8/8; por ello ese gate no se declara verde
  y se separa en `PROD-247`. Temporales, puertos y contenedores visuales fueron
  eliminados; no se usó red pública.

### PROD-246 — Clave estable e invalidación segura del índice de cartera multiworker

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** el índice materializado deriva tokens con una clave
  de proceso; dos workers que compartan almacenamiento podrían reconstruir e
  invalidar mutuamente la búsqueda, produciendo resultados vacíos o thrashing.
- **Áreas:** configuración de secretos, `project_portfolio_priority_index.py`,
  arranque/readiness, despliegue, rotación y pruebas multiproceso.
- **Aceptación:** el despliegue single-worker soportado conserva una clave
  efímera y rebuild al reiniciar. Procesos adicionales que opten explícitamente
  por compartir la proyección deben usar una clave estable separada y validada;
  dos procesos leen los mismos tokens y una clave distinta falla antes de
  reconstruir. La clave no se persiste ni la exporta backup; pruebas
  multiproceso y de dos propietarios demuestran interoperabilidad y aislamiento.
- **Riesgo:** falsos vacíos y rebuilds repetidos al escalar horizontalmente; una
  clave reutilizada fuera de ámbito debilitaría la pseudonimización.
- **Estimación:** M
- **Dependencias:** `PROD-241`; requiere definir operación multiworker soportada.
- **Evidencia:** **2026-09-10:** configuración opcional canónica base64url de
  32 bytes con campo excluido de `repr`; la clave solo vive en memoria y el
  índice/backup conservan únicamente un marcador HMAC con separación de
  dominio. Dos procesos `spawn` con la misma clave leen la misma proyección;
  una clave rotada falla `portfolio_priority_index_key_mismatch` antes de
  mutar el SQLite. El fixture de 20.000 proyectos/dos propietarios conserva
  aislamiento. Pasaron 41/41 pruebas dirigidas de cartera+backup y la suite
  backend completa offline con exit 0; `compileall`, Compose local/privado,
  `git diff --check` y coherencia de backlogs también pasaron. La rotación está
  documentada como parada total y descarte exclusivo del índice derivado. No
  se declara soportada la cola multiworker: esta tarea resuelve únicamente la
  interoperabilidad segura de los tokens del índice.

### PROD-247 — Hacer reproducible el gate de rendimiento de planes de remediación

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** la suite backend monolítica supera de forma aislada
  el benchmark de 20.000 proyectos, pero bajo carga acumulada las 200 escrituras
  durables de progreso pueden exceder el presupuesto de 5 s.
- **Áreas:** `remediation_plan_jobs.py`, pruebas de cancelación/recuperación,
  benchmark y documentación operativa.
- **Aceptación:** desacoplar comprobación frecuente de cancelación y persistencia
  acotada de progreso sin relajar el umbral; conservar artefacto atómico,
  recuperación y progreso final exacto. Pruebas dirigidas y suite backend completa
  pasan con tiempos registrados.
- **Riesgo:** un gate dependiente de carga oculta regresiones; reducir checkpoints
  sin mantener cancelación durable podría prolongar trabajos no deseados.
- **Estimación:** S
- **Dependencias:** `PROD-216` y benchmark existente.
- **Evidencia:** completada el 2026-09-10. La cancelación se consulta después de
  cada página de 100 proyectos, pero el progreso solo se escribe durablemente
  cada 1.000 y al final; un trabajo de 20.000 pasa de 203 a 23 escrituras totales
  (create, claim, 20 checkpoints y complete). Una regresión cancela en 200,
  deliberadamente entre checkpoints, y confirma que no se publica artefacto.
  Pasaron 9/9 pruebas dirigidas; el benchmark aislado bajó a 0,48 s sin relajar
  el límite de 5 s ni el de 32 MiB, y la suite backend completa pasó 1.594/1.594
  offline. El caso ya no figura entre los diez más lentos de la ejecución.
  `compileall`, diff-check y `make check-backlogs` también pasaron. El warning de
  caché de pytest se debió al montaje de solo lectura usado para validar y no
  afectó pruebas ni repositorio.

### PROD-215 — Responsable estable de proyecto

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** separar el responsable accountable del proyecto de
  las asignaciones transitorias de hallazgos.
- **Áreas:** proyecto, equipo/roles, cartera, remediación, informes y auditoría.
- **Aceptación:** solo miembros activos del tenant, cambios trazables, baja
  fail-closed y presentación separada; matriz roles/owners y redacción.
- **Riesgo:** proyectos sin responsable o asignaciones cruzadas.
- **Estimación:** M
- **Dependencias:** `PROD-012`, `PROD-145`, `PROD-146`.
- **Evidencia:** 2026-09-09: el proyecto conserva revisiones monotónicas y
  `unassigned_attention`; solo admin/maintainer puede asignar un miembro activo
  del tenant con confirmación y CAS. El índice SQLite v3 guarda HMAC separado,
  no el ID; baja/reintento/reinicio/restore, dos owners, auditoría redactada,
  cartera, remediación e informes separan owner de assignee. La revisión real
  desechable encontró CORS sin `PUT`; se amplió únicamente el conjunto cerrado y
  la asignación persistió tras reinicio a 1440/768/320 px. Pasaron backend+tools
  1.891/1.891 offline, frontend 401/401, build TypeScript/Vite 295,7/322 KiB,
  `compileall`, Compose base/privado y diff-check. Fixture, contenedor, tab,
  viewport y puertos se limpiaron; ninguna red pública fue usada.

### PROD-216 — Diario recuperable para acciones masivas de remediación

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** garantizar que una caída de proceso durante un lote no
  deje decisiones parcialmente visibles ni una repetición ambigua.
- **Áreas:** lifecycle, diario de operaciones, recuperación/readiness, backup,
  auditoría y pruebas de interrupción.
- **Aceptación:** idempotency key y journal privado owner-scoped; prepare/commit
  durables, recuperación determinista y estado consultable sin texto sensible;
  kill/restart en cada frontera, dos owners y replay exacto.
- **Riesgo:** triage parcial o duplicado tras una interrupción del proceso.
- **Estimación:** M
- **Dependencias:** `PROD-146` y diseño de recuperación existente.
- **Evidencia:** 2026-09-09: contrato API `2026-09-09.2`, clave estable por
  reintento y binding opaco a organización/actor/payload. Staging, journal y
  recibo usan escritura+rename+`fsync`; el recibo es la frontera única de
  visibilidad. Startup recupera prepares incompletos y readiness falla cerrado
  ante diario pendiente/corrupto. Replay exacto, restore, interrupciones en cada
  frontera y dos organizaciones quedaron cubiertos. Pasaron 1.902/1.902 pruebas
  Python offline, 402 frontend, build, `compileall`, Compose y diff-check.

### PROD-217 — Vistas guardadas privadas del centro de remediación

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** permitir que cada perfil repita consultas operativas
  sin copiar filtros o metadatos a URLs, logs o integraciones externas.
- **Áreas:** preferencias owner/user-scoped, API, panel, auditoría y pruebas.
- **Aceptación:** filtros cerrados versionados, nombres seguros, roles, límites y
  borrado; ningún cursor, hallazgo, nombre de proyecto o búsqueda libre se guarda
  fuera del tenant; accesibilidad y responsive.
- **Riesgo:** filtros persistidos pueden convertirse en una nueva fuga de nombres
  o existencia de proyectos.
- **Estimación:** M
- **Dependencias:** `PROD-146` y preferencias privadas.
- **Evidencia:** 2026-09-09: store privado owner/tenant-scoped, contrato cerrado
  sin búsqueda/cursor/IDs, máximo 20 vistas por usuario, compartición restringida
  a maintainer/admin, vista por defecto, borrado y purga al dar de baja al
  usuario. API con CSRF/no-store y auditoría redactada; UI con estados y retry
  conserva filtros estables. Reinicio, backup/restore, corrupción, límites,
  roles, dos organizaciones y modo `0600` cubiertos. Pasaron 1.908/1.908 pruebas
  Python offline, 403/403 frontend, axe, TypeScript/Vite (296,3/322 KiB),
  `compileall`, Compose base/privado y `git diff --check`. Revisión visual real a
  1440/768/320 px corrigió permisos del JSON y overflow del checkbox; persistió
  tras recarga, sin consola ni servicios/temporales residuales.

### PROD-218 — Generación duradera de planes de remediación a escala

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** superar de forma explícita los límites síncronos de
  2.000 grupos/5.000 ocurrencias sin aumentar memoria o timeout de una petición.
- **Áreas:** jobs de reporting, índice de cartera, almacenamiento/retención,
  descarga autorizada, observabilidad y pruebas de escala.
- **Aceptación:** snapshot/cutoff coherente, paginación indexada, artefacto acotado
  y cifrable, progreso/cancelación/expiración, digest reproducible y owner
  isolation; fixture >=20.000 proyectos sin glob estable.
- **Riesgo:** exportaciones grandes pueden agotar recursos o mezclar instantáneas.
- **Estimación:** L
- **Dependencias:** `PROD-146` y `PROD-214`.
- **Evidencia:** 2026-09-09: job privado owner-scoped con cutoff único, revisión
  del índice de proyectos y snapshot de decisiones; paginación sin glob estable,
  idempotencia concurrente, máximo dos jobs en vuelo por organización,
  cancelación/reintento/recuperación y artefactos JSON/CSV coherentes de hasta
  16 MiB con digest, ficheros `0600`, directorios `0700`, `fsync`, TTL de siete
  días y limpieza. Backup/restore rechaza pendientes, huérfanos, corrupción y
  symlinks; retención `2026-09-10.2` declara 20 clases. El fixture de 20.000
  proyectos exigió 200 páginas, <5 s y <32 MiB; 16 altas concurrentes produjeron
  un solo job. El recorrido local sintético generó, persistió y descargó un plan
  1/1, sin red pública ni proyecto real; la revisión visual 1440/768/320 corrigió
  el overflow global móvil y terminó sin errores de consola. Pasaron las 1.918
  pruebas Python existentes en 68 archivos mediante grupos aislados, las 405/405
  pruebas frontend en 58 archivos, axe dirigido, build 298,0/322 KiB,
  `compileall`, Compose base/privado y `git diff --check`. Un primer intento
  monolítico corrigió una allowlist de rutas y agotó exactamente un tmpfs de
  512 MiB al 86%; la repetición por grupos frescos con 2 GiB no omitió pruebas.
  Contenedor, volumen, red y temporales dedicados fueron eliminados.

### PROD-219 — Índice materializado de tendencias históricas

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** mantener tendencias disponibles por encima del límite
  actual de 10.000 análisis sin cargar cada resultado en una petición.
- **Áreas:** índice privado de hechos, sincronización de jobs/PVI/lifecycle,
  rebuild/backup, API de tendencias y benchmarks.
- **Aceptación:** índice sin nombres/rutas/evidencia; hechos ligados a digest del
  registro autoritativo; rebuild/reinicio/corrupción, dos owners y fixture de
  100.000 análisis con presupuestos definidos y consultas proporcionales.
- **Riesgo:** el cálculo bajo demanda puede agotar IO/memoria; un agregado stale o
  cruzado presenta métricas falsas.
- **Estimación:** L
- **Dependencias:** `PROD-147` y `PROD-214`.
- **Evidencia:** 2026-09-10: contrato `2026-09-10.1` e índice SQLite privado
  schema v1, reconstruible y limitado a 250.000 análisis por organización y
  256 MiB. Materializa desde las autoridades de proyectos, jobs, inteligencia
  pública y lifecycle solo fechas, contadores cerrados, ecosistema/origen,
  referencias de proyecto con separación de dominio y digests de
  registro/perfil; no conserva nombres de proyecto o componente, rutas,
  hallazgos, texto, evidencia, recomendaciones, comentarios, actores ni cuerpos
  de proveedor. Una revisión de fuente por organización invalida y reconstruye;
  proceso nuevo y corrupción detectada reconstruyen desde autoridad. Las
  consultas agregan en SQL y revalidan una muestra determinista de como máximo
  ocho jobs. Dos owners alternados, cambios de PVI/lifecycle, backup/restore,
  readiness y corrupción quedaron cubiertos. El corpus determinista de 100.000
  análisis/dos owners exige rebuild <60 s, pico Python <64 MiB, consulta caliente
  <1 s y <=8 lecturas autoritativas. Se recogieron 68 archivos/1.922 pruebas
  Python completas por grupos frescos, 58 archivos/405 pruebas frontend,
  pruebas dirigidas posteriores al cierre exacto del schema, `compileall`, build
  Vite 298,0/322 KiB, Compose base/privado y `git diff --check`. La UI e informes
  consumen los mismos hechos y contrato; no se introdujo una superficie visual
  nueva. Todo se validó offline, sin proveedor ni proyecto real.

### PROD-242 — Refresco incremental y reconstrucción en segundo plano de tendencias

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** evitar que la primera consulta de una cartera grande
  espere una reconstrucción completa del índice derivado de tendencias.
- **Áreas:** `project_risk_trend_index.py`, hooks de escritura o scheduler,
  readiness/observabilidad, API/UI, backup/restore y pruebas de escala.
- **Aceptación:** una consulta no ejecuta sincrónicamente un rebuild de 250.000
  hechos; revisión dirty durable por owner, trabajo acotado/coalescido,
  recuperación tras reinicio y publicación atómica. Durante el trabajo la API
  declara `ready`, `rebuilding`, `stale` o `failed`; una proyección anterior se
  muestra explícitamente caducada/parcial, nunca actual. El índice incremental
  conserva la equivalencia con autoridad y no añade identidades privadas. Un
  corpus de 100.000/dos owners exige scheduling frío <250 ms y presupuesto de
  reconstrucción documentado, con fallos/carreras y estados UI deterministas.
- **Riesgo:** la reconstrucción fría puede agotar un worker o provocar timeout;
  una actualización incremental divergente presentaría métricas falsas.
- **Estimación:** L
- **Dependencias:** `PROD-219`; coordinar hechos compartidos con `PROD-241`.
- **Evidencia:** 2026-09-10: contrato de vista `2026-09-10.2` e índice SQLite
  privado schema v2. La petición solo registra/coalesce una revisión durable por
  owner y lee la última publicación; nunca recorre jobs ni reconstruye bajo la
  petición. Un worker single-process acotado a una ejecución y dos pasadas
  publica atómicamente, recupera `queued`/`rebuilding` tras reinicio y conserva
  estados separados `ready/rebuilding/stale/failed` y
  `current/stale/unavailable`. Primera carga sin hechos devuelve 202 y
  `Retry-After`, el cliente sondea con límite; refresh/retry es explícito y los
  informes rechazan proyección stale. Corrupción semántica descarta solo el
  owner afectado y backup/restore valida el diario. La suite completa detectó y
  corrigió la omisión de la ruta refresh en el contrato exacto y una validación
  redundante que hacía intermitente el presupuesto frío. El fixture de 100.000
  análisis/dos owners cumplió scheduling <250 ms sin leer jobs y reconstruyó en
  53,09 s; pasaron 10/10 tendencias+backup, 3/3 contrato/API y 1.599/1.599
  backend offline. Frontend pasó 59 archivos/420 pruebas, build TypeScript/Vite
  y 302,7/322 KiB; `compileall`, Compose base/privado y `git diff --check`
  quedaron verdes. Revisión visual local reproducible en 1280x720 y 390x844:
  current, vacío, failed/stale, export bloqueada y retry→ready, sin overflow ni
  errores de consola. El índice usa aún una revisión conservadora compartida de
  directorios: puede provocar rebuild redundante entre owners, nunca presentar
  hechos ajenos como actuales; la mejora fina queda en `PROD-248`. Sin
  proveedores, proyectos reales, push, PR ni despliegue.

### PROD-248 — Reloj de mutación owner-scoped para tendencias

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** sustituir la revisión conservadora compartida de
  directorios por una invalidación durable por organización, evitando que una
  mutación de otro tenant programe un rebuild costoso sin perder el fallback
  seguro de reconstrucción.
- **Áreas:** stores autoritativos de proyectos, jobs, inteligencia pública y
  lifecycle/remediación; lock de almacenamiento, índice/scheduler de tendencias,
  backup/restore, readiness, benchmarks y documentación.
- **Aceptación:** cada mutación que afecta tendencias incrementa bajo el lock
  correspondiente una revisión monotónica owner-scoped; una mutación extranjera
  no ensucia el owner observado. Migración, proceso nuevo, restore, carrera y
  caída entre autoridad/revisión no pueden omitir una invalidación: ausencia,
  corrupción o divergencia del diario cae al hash conservador y reconstruye.
  Dos organizaciones y 100.000 análisis prueban equivalencia contra autoridad,
  cero lecturas ajenas, ausencia de rebuild cruzado y sobrecoste p95 de escritura
  documentado sin datos privados en logs/índice.
- **Riesgo:** conservar el reloj global desperdicia CPU/IO en instalaciones
  multi-tenant; un reloj fino incompleto sería peor porque etiquetaría hechos
  stale como actuales.
- **Estimación:** L
- **Dependencias:** `PROD-242`; coordinar atomicidad con los stores autoritativos,
  el storage lock y la proyección de `PROD-241`.
- **Evidencia:** 2026-09-10: SQLite derivado schema v1 (`0600`, 16 MiB,
  10.000 owners) conserva solo claves de organización derivadas por SHA-256,
  generación monotónica, epoch y digest de metadatos de directorio. Jobs,
  proyectos, PVI OSV normalizada, decisiones/batches y el journal de borrado
  publican la mutación bajo el lock común; un writer legacy también queda
  aislado sin persistir su etiqueta. Ausencia, corrupción, restore, write
  omitido o crash usan revisión global y readiness false hasta rotar epoch;
  una avería del reloj nunca revierte la autoridad. Backup valida esquema y
  privacidad. Nueve regresiones dirigidas cubrieron writers, dos owners,
  marcador de borrado, corrupción, recuperación, fallo de reparación,
  privacidad y p95 de 100 escrituras <50 ms. El fixture 100.000/dos owners
  confirmó que una mutación extranjera conserva `ready` para el owner intacto,
  marca solo al extranjero `stale` y no lee jobs al programar (49,4 s total con
  rebuild completo bajo tracemalloc). Backend actual: 1.607 pruebas recolectadas,
  `test_backend.py` y el resto de la suite pasaron por separado offline; el
  único fallo intermedio descubrió etiquetas legacy y quedó corregido con 23
  regresiones verdes. Frontend 59/420, TypeScript/Vite y 302,7/322 KiB;
  Compose base/privado, `compileall` con caché temporal y `git diff --check`
  verdes. El primer `compileall` global no alcanzó el diff por `__pycache__` CLI
  preexistentes sin permiso y se repitió sin escribir en el checkout. Sin red
  de proveedores, proyectos externos, push, PR ni despliegue.

### PROD-249 — Integrar la suite CLI en la puerta Python reproducible

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** la puerta `make test-python` invocada por CI solo
  descubre backend/tools; una regresión de snapshot, policy o SARIF puede pasar
  aunque la evidencia manual de la CLI sea verde.
- **Áreas:** `Makefile`, dependencias de desarrollo Python, CLI, estrategia de
  pruebas y documentación de contribución.
- **Aceptación:** el entorno fijado declara las dependencias de prueba CLI;
  `make test-python` ejecuta de forma atribuible suite principal y `cli/tests` en
  Python 3.12, y una regresión CLI hace fallar el mismo target ya usado por CI.
  SARIF sigue validándose contra el esquema fijado y la ejecución ordinaria no
  necesita Internet.
- **Riesgo:** un pipeline aparentemente verde puede publicar una CLI incapaz de
  crear snapshots reproducibles o producir salidas CI válidas.
- **Estimación:** S
- **Dependencias:** `PROD-037`, `PROD-152` y `PROD-155`, completadas. No requiere
  modificar el workflow ni `SEC-012`.
- **Evidencia:** 2026-09-10: `test-python` ejecuta primero la suite raíz y después
  `PYTHONPATH=cli ... pytest cli/tests`; `test-cli` permite la repetición
  atribuible. `jsonschema==4.25.1` y `attrs`, `jsonschema-specifications`,
  `referencing` y `rpds-py` quedaron fijados en el lock de desarrollo; un
  `pip check` offline sobre esas distribuciones y el runtime fijado no encontró
  incompatibilidades. Una regresión estática verifica target, dependencias y
  documentación. Pasaron 65/65 pruebas CLI completas con Python 3.12, Git y
  dependencias montados read-only bajo `--network none`, y 476/476 pruebas de
  tools más el canario no-red backend. `make -n` demostró las dos invocaciones
  exactas; no se ejecutó `setup-python` porque el ciclo prohíbe red y el entorno
  preexistente no contenía las dependencias nuevas. No se tocó el workflow,
  `SEC-012`, proyectos externos, push, PR, tag ni despliegue.

### PROD-239 — Reconciliación verificable del backlog heredado

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** contrastar tareas heredadas con capacidades
  posteriores para eliminar estados contradictorios sin asumir equivalencia por
  nombre.
- **Áreas:** `TODO.md`, `TODO_PRODUCTO.md`, contratos, stores, API, CLI, UI,
  informes y pruebas de CI, auditoría, cartera, remediación y eliminación.
- **Aceptación:** cada tarea indicada por el objetivo queda completada con una
  implementación/evidencia concreta o reducida a su brecha exacta; ambos
  backlogs coinciden y ninguna capacidad ausente se presenta como terminada.
- **Riesgo:** priorizar duplicados consume capacidad; cerrar por similitud oculta
  deuda real de seguridad u operación.
- **Estimación:** S
- **Dependencias:** auditoría de criterios heredados y tareas posteriores.
- **Evidencia:** 2026-09-09: `PROD-019`, `034`, `067`–`070`, `108`, `112` y
  `120` quedaron enlazadas a las tareas/implementaciones que satisfacen todos
  sus criterios; `PROD-063` se redujo únicamente a exportación general de
  auditoría y `PROD-107` a lifecycle durable leído/no leído para avisos pasivos.
  No se confundió la exportación Active ni su action inbox con esos alcances.
  Pasaron 30/30 pruebas backend dirigidas y 29/29 CLI funcionales en Python
  3.12/Git, ambas en contenedores `--network none` y repositorio read-only. El
  primer runtime CLI carecía de `PYTHONPATH`, `jsonschema` y Git; se separó la
  validación, se montó Git local read-only y se repitió. La conformidad SARIF no
  se reejecutó porque ninguna imagen disponible contiene `jsonschema`; conserva
  evidencia previa explícita en `PROD-155`, sin afirmar una nueva pasada.

#### Matriz de reconciliación — 2026-09-09

| Tarea heredada | Resultado | Evidencia o brecha exacta |
| --- | --- | --- |
| `PROD-019` | Absorbida | `PROD-131`–`136`, `155`, `157`; webhook opcional sigue separado en `PROD-071`. |
| `PROD-034` | Absorbida | `PROD-033`, `050`, `051`, `053`, `065`, `096`, `099`, `104`. |
| `PROD-063` | Reducida | `PROD-013` cubre escritura/consulta/retención; falta exportación general confirmada y redactada. |
| `PROD-067`–`070` | Absorbidas | `PROD-133`–`136`, `155`, `157`; tokens, admisión, policy y salidas. |
| `PROD-107` | Reducida | Cartera/remediación muestran estado; falta bandeja pasiva durable con leído/no leído. |
| `PROD-108` | Absorbida | `PROD-145` y `147`. |
| `PROD-112` | Absorbida | `PROD-133`–`135` y `153`. |
| `PROD-120` | Absorbida | Cascada write-ahead recuperable de proyecto, API/UI y pruebas de dos tenants. |

### PROD-140 — Inventario y correlación segura de Go

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** ofrecer el recorrido `go.mod`/`go.sum` sin ejecutar
  Go ni confundir checksums o rutas de módulo con prueba de origen público.
- **Áreas:** runner pasivo, inventario/cobertura, PURL, egress OSV, correlación
  SemVer, modelos/API, remediación, UI, Compose y documentación.
- **Aceptación:** solo versiones exactas y mismo root; `replace` no correlaciona
  y su destino no persiste; hashes no persisten; Go sale únicamente tras
  atestación exacta del operador; payload `Go+name+version`; pseudo-versiones
  deterministas; estados locales/no correlacionables, informe y UI.
- **Riesgo:** una ruta Go privada o reemplazo podría salir a OSV; una semántica
  de versión incorrecta produciría falso positivo o falso negativo.
- **Estimación:** L
- **Dependencias:** `PROD-025`, `PROD-079` y `PROD-137`, completadas.
- **Evidencia:** 2026-09-09: parser lineal acotado de `go.mod`/`go.sum`, pareja
  same-root, PURL `pkg:golang`, allowlist exacta vacía por defecto y payload OSV
  mínimo. `replace`, hashes, URL/credencial y formas ambiguas tienen regresiones.
  Python 3.12 bajo Docker `--network none`: 284/284 módulos afectados y 2/2 API
  preflight; reporting/remediación/tendencias 17/17. Frontend 35/35 y build
  291,0/322 KiB; compileall, tres Compose y diff-check. Se corrigió el PURL Go
  sin versión y el texto de cobertura OSV. Estado: **adaptador validado solo con
  fixtures**, sin consulta real ni ejecución de Go.

### PROD-220 — Atestaciones públicas por organización

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** sustituir progresivamente allowlists globales por
  aprobaciones exactas, auditables y revocables por organización.
- **Áreas:** identidad/equipo, policy egress, store cifrable, API/roles, auditoría,
  UI, backup/retención y pruebas.
- **Aceptación:** admin/maintainer propone y admin aprueba nombre+ecosistema
  exactos con revisión/expiración; egress revalida tenant y versión de política;
  ningún nombre aparece en logs o exportación global; revocación es inmediata.
- **Riesgo:** una atestación global válida para un tenant puede habilitar la
  salida de un homónimo privado de otro tenant.
- **Estimación:** L
- **Dependencias:** `PROD-012`, `PROD-026` y verticales multi-ecosistema.
- **Evidencia:** 2026-09-09: contrato `2026-09-09.1` y esquema team identity v2.
  Un maintainer/admin propone una identidad exacta y solo un admin la aprueba;
  TTL 1–90 días, límite de 200 identidades retenidas, revisión monotónica,
  expiración y revocación inmediata. El overlay por organización solo puede
  estrechar la política del operador y se revalida justo antes de crear cada
  lote OSV; ausencia, cruce de tenant o revocación concurrente producen cero
  intentos de red y `organization_identity_not_attested`. API/CSRF/UI cubren
  roles, carga, vacío y error; la auditoría conserva solo ID opaco, ecosistema y
  revisión. Reinicio y backup/restore preservan las atestaciones. Validación
  offline: 152 pruebas dirigidas, 2 recorridos API, suite Python completa
  1.848/1.848, frontend 57 archivos/387 pruebas, axe dirigido, TypeScript/Vite,
  `compileall`, Compose base/privado y `git diff --check`. Sin proveedor real,
  push, PR ni despliegue; `SEC-012` permaneció intacta.

### PROD-221 — Grafo Go aportado por CI sin ejecutar el proyecto

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** distinguir transitivas reales de simples `indirect`
  mediante un artefacto precomputado, firmado/digestado y acotado.
- **Áreas:** CLI/CI, admisión de artefactos, inventario, comparación e informes.
- **Aceptación:** formato versionado con módulos exactos y aristas limitadas;
  ligado a commit/snapshot; sin rutas, repositorios ni sumas; ciclos/truncado y
  artefacto divergente quedan inconclusos; Inspectra nunca invoca `go mod graph`.
- **Riesgo:** usar `// indirect` como grafo completo falsea alcance y prioridad.
- **Estimación:** M
- **Dependencias:** `PROD-140` y contrato de artefactos CI.
- **Evidencia:** 2026-09-10: contrato cerrado `2026-09-10.1`, máximo 1 MiB,
  2.000 nodos y 4.000 aristas. CLI y backend exigen archivo regular de enlace
  único, JSON canónico, digest, commit y SHA-256 del snapshot exactos; la
  admisión owner/project/analysis-scoped es inmutable e imposible después de
  crear PVI. Solo un `go.mod`/`go.sum` del mismo root puede corroborar nodos y
  raíces; divergencia no añade identidades, truncado queda explícito y ciclos
  profundos se detectan iterativamente. El resultado retiene componentes
  corroborados y un recibo agregado, nunca JSON, IDs, raíces ni aristas. UI,
  comparación posterior, informe y documentación consumen esa proyección; la
  atestación pública sigue separada y Inspectra no ejecuta Go. Fixtures cubren
  digest/commit/source distintos, claves duplicadas, symlink/hardlink, grafo de
  1.200 nodos con ciclo, replay/conflicto, PVI existente y dos propietarios.
  Validación offline: CLI 38/38; backend 1.467/1.467; frontend 58 archivos y
  406/406, axe dirigido; TypeScript/Vite, bundle inicial 298,0/322 KiB,
  `compileall`, Compose base/privado y diff-check. Revisión visual local en
  escritorio y 390 px confirmó `Accepted`, binding/cobertura/ciclos, cero
  overflow y cero errores de consola. Fuente, grafo, datos y contenedor
  temporales eliminados; sin proveedor, proyecto real, push, PR ni despliegue.

### PROD-222 — Compatibilidad segura con escapes de módulos Go

- **Prioridad:** P3
- **Estado:** pendiente
- **Descripción y motivo:** evaluar rutas canónicas con mayúsculas codificadas
  (`!`) sin ampliar la gramática antes de demostrar demanda y semántica segura.
- **Áreas:** normalizador Go, PURL, atestaciones, fixtures y docs.
- **Aceptación:** contrato oficial verificado; equivalencia canónica única;
  colisiones/case-folding rechazadas y egress solo bajo atestación exacta.
- **Riesgo:** aceptar escapes por heurística correlaciona el módulo equivocado;
  rechazarlos limita cobertura de algunos proyectos.
- **Estimación:** S
- **Dependencias:** `PROD-140` y evidencia de demanda real.
- **Evidencia:** pendiente; no bloquea el subconjunto lowercase soportado.

### PROD-141 — Inventario y correlación segura de Rust/Cargo

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** vertical pasivo `Cargo.toml`/`Cargo.lock` para
  inventariar crates y consultar OSV solo con procedencia pública demostrable.
- **Áreas:** runner, inventario/PURL, egress/PVI/SemVer, modelos, UI, reporting,
  documentación y pruebas.
- **Aceptación:** solo lock v3/v4 y fuente literal oficial crates.io; Git, path,
  workspace, alias, registry alternativo y ambigüedad quedan locales; nunca se
  retienen locator, checksum ni credencial; payload solo crates.io/name/version.
- **Riesgo:** fuga de identidades privadas o falsa correlación por procedencia o
  mapeo de ecosistema incorrectos.
- **Estimación:** L
- **Dependencias:** `PROD-025`, `PROD-079` y `PROD-137`, completadas.
- **Evidencia:** 2026-09-09, Docker Python 3.12 sin red: 294/294 pruebas del
  núcleo y 53/53 de PVI/GHSA/reporting/consumidores; frontend 41/41 y build
  291,0/322 KiB; compileall/diff-check. Fixtures hostiles cubren v3/v4, v2,
  registry privado, alias/workspace/Git, checksum, payload OSV, affected/fixed
  y SemVer. Se cerró además el fallback GHSA a `pip`. Estado: adaptador solo
  validado con fixtures; no integración real OSV Cargo. No se ejecutó Cargo.

### PROD-223 — Grafo y features Cargo aportados por CI

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** aportar alcance, aristas, features y targets exactos
  sin ejecutar Cargo dentro de Inspectra.
- **Áreas:** CLI/CI, contrato de artefacto, inventario, PVI e informes.
- **Aceptación:** artefacto versionado, digestado y ligado al commit; límites,
  ciclos y truncado explícitos; sin rutas, registry, checksum ni metadatos libres.
- **Riesgo:** prioridad falsa por alcance inventado o fuga de topología.
- **Estimación:** M
- **Dependencias:** `PROD-141` y contrato de artefactos CI.
- **Evidencia:** 2026-09-10: contrato cerrado `2026-09-10.2`, lectura CLI de
  archivo regular no enlazado (1 MiB), binding exacto a commit/snapshot y
  límites de 2.000 nodos, 4.000 aristas, 32 targets opacos y 64 features por
  nodo. El backend exige un único `Cargo.toml`/`Cargo.lock` v3/v4 del mismo
  root, corrobora crate+versión oficial, roots y alcanzabilidad, y persiste solo
  scope y conteos más recibo; no conserva IDs, labels, roots ni aristas.
  Admisión owner/project/analysis-scoped, replay idempotente, conflicto y PVI
  posterior fallan cerrados; adjuntos Go/Cargo se preservan secuencialmente.
  API/UI/informe/documentación y handshake CLI quedaron alineados. Offline:
  1.476/1.476 backend con `tmpfs` 2 GiB, 42/42 CLI dentro de 66 pruebas
  dirigidas, 58 archivos/407 frontend con axe, build 298,0/322 KiB,
  compileall, Compose base/privado y diff-check. Un primer backend con 256 MiB
  falló por `sqlite3 database or disk is full`/`ENOSPC`; la repetición amplia
  no omitió pruebas. La revisión visual interactiva no se ejecutó porque esta
  sesión no expuso control de navegador; no se declara superada. Sin red,
  Cargo, proyecto externo, push, PR ni despliegue; bloqueos intactos.

### PROD-243 — Sobre común versionado para evidencia CI multi-ecosistema

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** extraer el binding, lectura segura, idempotencia y
  recibo compartidos solo cuando al menos tres grafos reales permitan demostrar
  qué es común, evitando que contratos copiados diverjan silenciosamente.
- **Áreas:** CLI, endpoints de admisión, storage, modelos, auditoría,
  documentación y fixtures hostiles de Go/Cargo/tercer ecosistema.
- **Aceptación:** un sobre versionado común exige archivo regular no enlazado,
  límites, digest, commit/source, owner/proyecto/análisis e inmutabilidad; cada
  ecosistema conserva su validador cerrado. Compatibilidad Go se prueba byte a
  byte; fallos cruzados, replay, carreras, PVI existente y dos owners fallan
  cerrados sin identidades en logs.
- **Riesgo:** duplicar el límite de confianza en cada vertical facilita que un
  ecosistema olvide una comprobación; abstraer antes de tener evidencia puede
  crear un contrato genérico permisivo.
- **Estimación:** M
- **Dependencias:** `PROD-221`, `PROD-223` y `PROD-226` completadas.
- **Evidencia:** 2026-09-10, sobre común `2026-09-10.1` publicado en el
  handshake CLI `2026-09-10.4`. La CLI comparte lectura de un único inode
  regular/no enlazado, cuota y JSON sin claves duplicadas; el backend comparte
  digest, decodificación y binding commit/snapshot. Los endpoints resuelven una
  frontera común de owner/proyecto/análisis terminal/PVI previo y storage
  aplica bajo un único lock aislamiento, replay e inmutabilidad. Go, Cargo y
  Composer conservan esquemas, productores, identidades, límites de colección
  y errores cerrados separados; los payloads no se reserializan y Go mantiene
  bytes/digest idénticos. Dos admisiones Composer concurrentes convergen en el
  mismo recibo; cruces, links, duplicados, digest/binding, dos owners y PVI
  fallan cerrados en regresiones existentes. Documentado en
  `docs/ci-graph-evidence.md`. Validación posterior al refactor: suite offline
  completa 1.993/1.993 Python y 58/58 dirigidas multi-ecosistema tras publicar
  el handshake; frontend ya validado 408/408 y build 298,0/322 KiB en el mismo
  ciclo; `compileall`, Compose base/privado y diff-check pasan. Sin red,
  gestores de paquetes del proyecto, push, PR ni despliegue.

### PROD-244 — Productores CI auditables para grafos pasivos

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** ofrecer transformadores de referencia que conviertan
  salidas ya generadas en CI en los contratos cerrados de Inspectra, para que
  cada equipo no tenga que implementar un productor incompatible o inseguro.
- **Áreas:** CLI, contratos de grafos Go/Cargo/tercer ecosistema, fixtures,
  documentación CI y supply chain del artefacto.
- **Aceptación:** comandos puros aceptan solo ficheros bounded ya producidos por
  el gestor fuera de Inspectra; no ejecutan gestores ni builds; descartan rutas,
  repositorios, checksums y metadata no admitida; generan salida canónica ligada
  a commit/snapshot y un recibo local. Fixtures hostiles, reproducibilidad,
  symlink/hardlink, dos roots y documentación de generación/verificación.
- **Riesgo:** delegar el contrato a scripts ad hoc puede filtrar topología o
  producir evidencia divergente difícil de adoptar y mantener.
- **Estimación:** M
- **Dependencias:** `PROD-221`, `PROD-223` y `PROD-226` completadas.
- **Evidencia:** 2026-09-10, `inspectra graph` transforma observaciones CI
  cerradas de Go, Cargo o Composer en sus contratos fuente-bound sin ejecutar
  comandos, gestores, builds, red ni leer el checkout. Entrada regular no
  enlazada ≤1 MiB, claves exactas y validación completa por ecosistema; descarta
  por rechazo toda metadata libre. Ordena únicamente colecciones admitidas,
  conserva errores por duplicado/identidad/referencia y crea salida nueva
  `0600` con `O_EXCL`, `fsync` y recibo sin rutas/identidades. Repeticiones en
  rutas distintas producen bytes/digest idénticos; dos roots, metadata hostil,
  symlink, hardlink y no-sobrescritura cubiertos. Documentación y ejemplo en
  CLI/runbook. Validación offline: CLI completa 52/52; suite previa del mismo
  árbol 1.993/1.993 más seis regresiones nuevas (1.999 recolectadas), frontend
  408/408 y build 298,0/322 KiB; compileall y diff-check pasan. La generación
  nativa del gestor permanece explícitamente fuera de Inspectra y en el CI
  autorizado.

### PROD-245 — Validador automático de coherencia entre backlogs

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** impedir que tablas resumen y fichas detalladas de
  `TODO.md` y `TODO_PRODUCTO.md` diverjan silenciosamente en ID, prioridad o
  estado, como ocurrió con tareas ya completadas y brechas aún pendientes.
- **Áreas:** helper bajo `tools/`, comprobaciones locales/CI, fixtures y ambos
  backlogs.
- **Aceptación:** analiza ambos documentos sin modificarlos; detecta IDs
  duplicados o ausentes, contradicciones de prioridad/estado y alteraciones de
  tareas protegidas bloqueadas; falla con diagnóstico accionable. Fixtures
  cubren documentos válidos y cada contradicción.
- **Riesgo:** un backlog contradictorio puede seleccionar trabajo equivocado,
  ocultar una brecha o declarar como validada una capacidad pendiente.
- **Estimación:** S
- **Dependencias:** `PROD-239` completada.
- **Evidencia:** 2026-09-10: `tools/backlog_consistency.py` analiza en solo
  lectura tablas resumen, fichas por encabezado y filas detalladas, compara
  todos los `PROD-XXX` entre documentos. En su cierre inicial protegía también
  `PROD-129`; la consolidación autorizada retiró esa tarea y el ciclo remoto
  autorizado retiró `PROD-130`. Mantiene bloqueadas `SEC-012` y `PROD-167`.
  La primera ejecución real
  encontró siete contradicciones: se respaldaron como completadas
  `PROD-063/124/243`, se mantuvieron pendientes `PROD-007/021/222` y se trasladó
  a `PROD-124` la evidencia de identidad que estaba erróneamente en `PROD-021`.
  `make check-backlogs` quedó integrado en `make validate`, CI, README y
  `AGENTS.md`; no modifica documentos y devuelve diagnósticos ordenados con
  líneas. Pasaron 10/10 fixtures del parser, 14/14 pruebas dirigidas del flujo
  de desarrollo y 474/474 pruebas de `tools` (7,20 s; 28.996 KiB RSS Docker),
  además de `compileall`, la puerta real y `git diff --check`, sin Internet. No
  se modificaron los hashes de acciones ni los bloqueos protegidos.

### PROD-224 — Evolución controlada de fuentes oficiales Cargo

- **Prioridad:** P3
- **Estado:** pendiente
- **Descripción y motivo:** admitir futuros identificadores oficiales solo con
  contrato versionado, nunca mediante URL configurable o coincidencia por prefijo.
- **Áreas:** parser, procedencia, contratos y documentación.
- **Aceptación:** cada literal nuevo tiene fuente oficial, bump y pruebas
  positiva/negativa; toda forma desconocida queda local.
- **Riesgo:** una heurística habilitaría fuga de paquetes privados.
- **Estimación:** S
- **Dependencias:** `PROD-141`.
- **Evidencia:** en progreso desde 2026-09-10: auditoría del parser
  `packages.lock.json`, del sobre común de evidencia CI y de los contratos Go,
  Cargo, Composer y Gradle antes de definir el subconjunto multi-target.

### PROD-225 — Mapeo GHSA explícito multi-ecosistema

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** corroborar Go/Cargo solo cuando exista una
  equivalencia documentada en el vocabulario oficial de GitHub.
- **Áreas:** normalizador GHSA, contratos, UI y fixtures.
- **Aceptación:** allowlist cerrada; homónimos entre ecosistemas nunca se cruzan;
  ausencia de mapa produce `not_correlated`, sin fallback.
- **Riesgo:** una corroboración falsa eleva confianza en evidencia equivocada.
- **Estimación:** M
- **Dependencias:** `PROD-141`; vocabulario oficial GHSA verificado.
- **Evidencia:** 2026-09-10, contrato normalizador `2026-09-10.2` con mapa
  cerrado `npm→npm`, `pypi→pip`, `go→go`, `cargo→rust`,
  `composer→composer`, `maven→maven` y `nuget→nuget`, respaldado por la
  documentación oficial REST/GraphQL de GitHub enlazada en
  `docs/public-vulnerability-intelligence.md`. Se exige identidad normalizada,
  versión afectada por un rango soportado y GHSA previamente originado en OSV;
  homónimo/ecosistema distinto, desconocido o rango incompatible queda
  `not_correlated` sin fallback. 18/18 regresiones dirigidas y 64/64 del
  circuito GHSA/PVI/reporting pasan offline; `compileall` y diff-check pasan.
  UI/informes ya consumen la corroboración normalizada sin cambio de contrato.
  Estado honesto: adaptador validado únicamente con fixtures; no hubo consulta
  GitHub real, token ni habilitación de egress.

### PROD-143 — Inventario y correlación segura de PHP/Composer

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** recorrido pasivo desde `composer.json` y
  `composer.lock` hasta inventario, OSV, resultados e informes.
- **Áreas:** runner, inventario/PURL, config/Compose/egress, PVI/SemVer,
  modelos, UI, documentación y tests.
- **Aceptación:** contrato JSON acotado; nombre `vendor/package` y versión exacta;
  root con `repositories` cerrado; atestación Packagist exacta; nunca retener
  source/dist/URL/reference/hash/alias/credencial ni ejecutar Composer.
- **Riesgo:** fuga de paquete privado homónimo o falsa correlación por metadata.
- **Estimación:** L
- **Dependencias:** `PROD-025`, `PROD-079`, `PROD-137`, completadas.
- **Evidencia:** 2026-09-09, Docker Python 3.12 sin red 332/332 pruebas amplias
  y 2/2 rutas API; frontend 43/43 y build 291,0/322 KiB; compileall, Compose y
  diff-check. Fixtures hostiles y OSV simulado cubren local/atestado/affected/
  fixed. Estado: adaptador únicamente validado con fixtures; no integración
  real OSV Composer. No se ejecutó Composer ni hubo Internet.

### PROD-226 — Grafo Composer aportado por CI

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** incorporar aristas exactas sin ejecutar el gestor.
- **Áreas:** CLI/CI, contrato de artefacto, inventario/PVI/reporting.
- **Aceptación:** ligado a commit/digest, acotado, sin metadata libre; ciclos,
  truncado y divergencia explícitos.
- **Riesgo:** alcance inventado o fuga de topología.
- **Estimación:** M
- **Dependencias:** `PROD-143` y contrato CI.
- **Evidencia:** 2026-09-10, vertical completo con contrato cerrado
  `2026-09-10.3`, archivo regular no enlazado de hasta 1 MiB, 2.000 nodos y
  4.000 aristas canónicas, binding commit/SHA-256 y admisión tenant-scoped
  inmutable antes de PVI. Un único root `composer.json`/`composer.lock`
  corrobora identidades y raíces; repositorios personalizados, identidades
  ajenas, nodos inalcanzables, truncación y ciclos quedan explícitos. CLI,
  capabilities, API, almacenamiento, inventario, UI accesible, informe y docs
  alineados; solo scope/status y recibo agregado persisten, nunca IDs, roots,
  aristas, repositorios, URLs, hashes o metadata libre. El grafo no atestigua
  Packagist. Validación offline: 1.993/1.993 pruebas Python (backend, tools y
  CLI), 408/408 frontend en 58 archivos, axe dirigido, build 298,0/322 KiB,
  `compileall`, Compose base/privado con configuración sintética y
  `git diff --check`. No se ejecutó Composer ni hubo red pública. El primer
  comando frontend dirigido duplicó por error `--run`; se corrigió el comando
  y no se atribuyó al código.

### PROD-227 — Versiones Composer avanzadas

- **Prioridad:** P3
- **Estado:** pendiente
- **Descripción y motivo:** ampliar aliases/branches/cuatro segmentos solo con
  semántica oficial y demanda demostrada.
- **Áreas:** parser, normalizador, matcher, UI y fixtures OSV.
- **Aceptación:** cero coerción heurística; formas ambiguas siguen locales.
- **Riesgo:** falso positivo o negativo por versión reinterpretada.
- **Estimación:** M
- **Dependencias:** `PROD-143`.
- **Evidencia:** pendiente.

### PROD-228 — Evolución versionada de composer.lock

- **Prioridad:** P3
- **Estado:** pendiente
- **Descripción y motivo:** gobernar cambios de estructura con corpus y bump.
- **Áreas:** parser, cobertura, contratos y docs.
- **Aceptación:** formatos desconocidos fallan cerrados y cada evolución tiene
  fixtures positivos/negativos sin campos sensibles.
- **Riesgo:** pérdida silenciosa de cobertura o retención de metadata.
- **Estimación:** S
- **Dependencias:** `PROD-143`.
- **Evidencia:** pendiente.

### PROD-142 — Inventario y correlación segura de Java/JVM

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** recorrido pasivo desde marcador Gradle y lockfile
  exacto hasta inventario, OSV simulado, resultados e informes.
- **Áreas:** runner, inventario/PURL, configuración/egress, PVI/matching,
  modelos, frontend, documentación y pruebas.
- **Aceptación:** nunca evaluar DSL ni ejecutar Gradle/Maven; aceptar solo
  `group:artifact:version` lowercase y SemVer estable del lock del mismo root;
  no retener configuración ni afirmar alcance u origen; atestación exacta antes
  del payload mínimo `Maven+name+version`.
- **Riesgo:** fuga de coordenadas privadas o falso hallazgo por origen, scope o
  orden de versión inferidos.
- **Estimación:** L
- **Dependencias:** `PROD-025`, `PROD-079` y `PROD-137`, completadas.
- **Evidencia:** 2026-09-09, contrato `2026-09-09.3`; Docker Python 3.12
  `--network none`: 346/346 pruebas backend amplias; frontend 45/45, build y
  bundle 291,0/322 KiB; `compileall`, Compose base/overlay y diff-check. La
  regresión UI conserva `scope unknown`. Fixtures cubren `.gradle`/`.kts`,
  ambigüedad, descarte de configuraciones, atestación, payload y affected/fixed.
  Adaptador validado solo con fixtures; no integración OSV real Maven.

### PROD-144 — Inventario y correlación segura de .NET/NuGet

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** permitir un flujo pasivo `packages.lock.json` v1
  hasta inventario e inteligencia, sin ejecutar restore ni inferir NuGet.org.
- **Áreas:** runner, inventario/PURL, egress/PVI/versiones, modelos, UI,
  informes, documentación y fixtures.
- **Aceptación:** solo lock v1 same-root con marcador de proyecto inequívoco;
  versión exacta soportada y targets reconciliados; conflictos/Project quedan
  locales; atestación pública exacta y payload mínimo; no se conservan TFM,
  hashes, rutas, repositorios ni credenciales.
- **Riesgo:** mezclar target frameworks, confundir proyecto local con paquete o
  inferir procedencia crea falsos hallazgos y fuga de identidad.
- **Estimación:** L
- **Dependencias:** `PROD-025`, `PROD-079` y `PROD-137`, completadas.
- **Evidencia:** 2026-09-09, contrato de inventario `2026-09-09.4`. El
  parser pasivo reconoce marcadores `*.csproj` sin leer/evaluar MSBuild y solo
  `packages.lock.json` v1 del mismo root; rechaza JSON con claves duplicadas,
  reconcilia targets sin conservar sus nombres y deja versiones/scope
  ambiguos o paquetes `Project` fuera de correlación. La atestación NuGet es
  exacta y el payload OSV simulado contiene únicamente `NuGet+name+version`.
  Docker Python 3.12 con `--network none`: backend completo 1.346/1.346,
  runner completo 451/451, frontend completo 381/381, build 291,0/322 KiB;
  además `compileall`, Compose base/overlay y `git diff --check`. Una primera
  pasada backend con tmpfs 256 MiB agotó `/tmp` (`Errno 28`) y no se contó; la
  repetición íntegra con 2 GiB pasó. Estado de fuente: adaptador validado solo
  con fixtures, no integración OSV real NuGet; no se ejecutó `dotnet` ni hubo
  Internet.

### PROD-233 — Cursores Active con representación Base64url canónica

- **Prioridad:** P1
- **Estado:** completada
- **Descripción y motivo:** rechazar aliases Base64url no canónicos de un
  cursor firmado; una firma válida no debe admitir varias cadenas externas.
- **Áreas:** `backend/app/active_job_index.py`,
  `backend/app/active_assets.py` y regresiones de paginación Active.
- **Aceptación:** el decoder admite solo el round-trip canónico sin padding;
  cursores válidos siguen paginando y cualquier mutación/alias devuelve el
  error cerrado existente sin revelar payload ni clave.
- **Riesgo:** aliases equivalentes complican auditoría, idempotencia y claves
  de caché, y hacían no determinista la detección de manipulación. No se
  confirmó bypass de tenant: el payload y HMAC decodificados eran idénticos.
- **Estimación:** S
- **Dependencias:** índices y paginación Active existentes.
- **Evidencia:** descubierto por la suite backend completa: el caso
  `test_active_execution_history_pages_and_resolves_an_old_baseline_owner_scoped`
  esperaba 400 y recibía 200 al mutar el último carácter. Ambos decoders ahora
  recodifican y comparan la forma canónica. Regresión dirigida 7/7 y backend
  completo 1.346/1.346 sin red.

### PROD-234 — Grafo NuGet multi-target aportado por CI

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** representar aristas y alcance por target sin que
  Inspectra ejecute restore/MSBuild ni retenga nombres privados de framework.
- **Áreas:** CLI/CI, contrato de artefacto, inventario, PVI e informes.
- **Aceptación:** artefacto versionado, digestado y ligado a commit; paquetes,
  aristas y grupos de target opacos/acotados; divergencia y truncado quedan
  inconclusos; no admite rutas, repositorios, hashes ni metadata libre.
- **Riesgo:** inferir un grafo desde el lockfile sesga la prioridad; aceptar
  salida libre puede filtrar topología.
- **Estimación:** M
- **Dependencias:** `PROD-144` y contrato de artefactos CI.
- **Evidencia:** **2026-09-10:** contrato cerrado `2026-09-10.5` y
  handshake CLI `2026-09-10.6`; artefacto regular limitado a 1 MiB, 2.000
  nodos, 4.000 aristas y 32 targets opacos consecutivos (`t0`–`t31`), ligado
  por digest al snapshot/commit. La admisión comprueba mismo root de
  `.csproj`/`packages.lock.json`, número de targets, identidades exactas,
  raíces, alcance por target, ciclos y truncación; divergencia no añade
  identidades. Solo persiste la proyección y un recibo agregado: nunca TFM,
  aristas, rutas, fuentes, hashes ni metadata libre, y no se infiere
  procedencia NuGet.org. CLI/productor, API owner-scoped, replay inmutable,
  bloqueo tras PVI, inventario, UI accesible e informes quedaron alineados.
  Fixtures hostiles, dos owners y el recorrido dirigido pasaron; validación
  completa sin red: backend 1.523/1.523, tools 464/464 y CLI 56/56; frontend
  58 archivos/410 pruebas, build y presupuesto inicial 298,0/322 KiB;
  `compileall`, Compose y `git diff --check` pasaron. No se ejecutó NuGet,
  MSBuild, proveedor externo ni proyecto real.

### PROD-235 — Semántica completa y segura de versiones NuGet

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** ampliar el subconjunto numérico actual solo con
  reglas oficiales verificadas de NuGetVersion y rangos OSV.
- **Áreas:** normalizador/matcher, PVI, UI y corpus de fixtures.
- **Aceptación:** orden/canonicalización compatibles con especificación; formas
  legacy o ambiguas quedan `unknown`; no se recortan qualifiers ni se inventa
  equivalencia.
- **Riesgo:** un orden incorrecto genera falsos positivos o negativos.
- **Estimación:** M
- **Dependencias:** `PROD-144` y corpus NuGet oficial revisado.
- **Evidencia:** **2026-09-10:** contrato NuGetVersion `2026-09-10.1` y PVI
  `2026-09-10.6`, contrastados con la referencia Microsoft y las
  implementaciones oficiales `NuGetVersion`/`VersionComparer`. Un normalizador
  puro limitado a 64 caracteres y enteros `System.Version` acepta 1–4
  segmentos, completa minor/patch, elimina ceros, omite revisión cero y build
  metadata, y canonicaliza prerelease case-insensitive con orden numérico. El
  runner normaliza antes de persistir; inventario, purl, egress OSV, caché,
  fingerprint, rangos/fixes, grafo backend y productor/validador CLI comparten
  esa identidad. Más segmentos, enteros fuera de rango, etiquetas vacías y
  rangos no soportados quedan `unknown`/rechazados. Se corrigieron durante la
  validación una variable de fingerprint fuera de ámbito y la exposición del
  valor no canónico en el estado de correlación, ambas con regresión. Pasaron
  232 pruebas backend dirigidas, 2 de parser, 6 de productor/CLI y 26 de UI;
  suites completas offline: backend 1.544/1.544, tools 464/464, CLI 56/56 y
  frontend 410/410; build/axe, bundle 298,0/322 KiB, `compileall`, Compose y
  diff-check. No se ejecutó .NET/NuGet ni se consultó un proveedor/proyecto.

### PROD-236 — Evolución versionada de `packages.lock.json`

- **Prioridad:** P3
- **Estado:** pendiente
- **Descripción y motivo:** gobernar futuros formatos del lock sin ampliar el
  parser de forma silenciosa.
- **Áreas:** runner, cobertura, contratos, fixtures y documentación.
- **Aceptación:** cada formato nuevo requiere fuente oficial, bump contractual
  y casos positivos/negativos; formatos y claves ambiguas fallan cerrados sin
  retener contenido.
- **Riesgo:** pérdida silenciosa de cobertura o nueva retención de metadata.
- **Estimación:** S
- **Dependencias:** `PROD-144`.
- **Evidencia:** pendiente.

### PROD-237 — Evaluador CVSS v4 validado con corpus oficial

- **Prioridad:** P3
- **Estado:** pendiente
- **Descripción y motivo:** permitir derivar una puntuación v4 solo cuando una
  implementación completa pueda demostrarse contra vectores oficiales; hoy se
  conserva únicamente la puntuación publicada por la fuente.
- **Áreas:** `backend/app/cvss.py`, normalizadores, UI/informes y fixtures.
- **Aceptación:** implementación versionada conforme a FIRST, corpus de
  referencia y fronteras de redondeo; igualdad con valores oficiales y fallback
  `unknown` ante toda forma no soportada, sin alterar scores de fuente.
- **Riesgo:** una aproximación v4 incorrecta cambia prioridad y decisiones de
  remediación.
- **Estimación:** M
- **Dependencias:** `PROD-097` y corpus oficial CVSS v4 revisado.
- **Evidencia:** pendiente; `PROD-097` falla cerrado y no aproxima v4.

### PROD-238 — Catálogo revisado de equivalencias CPE↔purl

- **Prioridad:** P2
- **Estado:** bloqueada
- **Descripción y motivo:** poblar progresivamente el registro seguro de
  `PROD-098` con equivalencias reales demostrables, sin inferencia por nombre
  ni uso de CPE como fuente primaria de aplicabilidad.
- **Áreas:** `cpe_purl_mappings.py`, manifiesto de gobernanza, fixtures,
  documentación, detalle/comparación e informes.
- **Aceptación:** cada entrada enlaza fuente primaria, fecha y revisión humana
  con purl, CPE y CVE exactos; dos revisores aprueban altas/retiradas; no se
  admite changelog aislado, wildcard, similitud, configuración runtime ni una
  relación sin CVE. Bump de política y fixtures positivos, homónimos y
  advisory/rango incompatible son obligatorios.
- **Riesgo:** una tabla con evidencia débil refuerza falsos positivos; mantenerla
  vacía solo limita corroboración secundaria y no bloquea OSV.
- **Estimación:** M
- **Dependencias:** `PROD-098`, acceso autorizado a evidencia primaria y dos
  revisores humanos.
- **Evidencia:** bloqueada 2026-09-10: el ciclo actual prohíbe red externa y no
  dispone de los dos revisores requeridos. El registro seguro permanece vacío;
  no se simuló evidencia, aprobación ni consulta real.

### PROD-229 — Grafo y scopes Gradle aportados por CI

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** obtener alcance real sin evaluar builds en Inspectra.
- **Áreas:** CLI/CI, contrato Gradle, inventario/PVI/reporting.
- **Aceptación:** artefacto versionado y ligado al commit, aristas/scopes
  allowlisted y acotados; cero DSL, rutas, repositorios o metadata libre.
- **Riesgo:** alcance inventado o fuga de topología.
- **Estimación:** M
- **Dependencias:** `PROD-142` y `PROD-243` completadas.
- **Evidencia:** 2026-09-10: contrato `2026-09-10.4`, sobre común y handshake
  `2026-09-10.5`; artefacto regular <=1 MiB, 2.000 nodos/4.000 aristas, binding
  commit/snapshot y scopes cerrados `compile/runtime/test`. Un único marker y
  `gradle.lockfile` del mismo root corroboran identidades y alcanzabilidad; la
  topología, IDs y configuración cruda no se persisten. API/CLI/productor puro,
  inventario, cobertura, UI accesible, informes y documentación quedan
  conectados; replay concurrente, cruce de owner, divergencia, claves libres,
  digest y esquemas cruzados fallan cerrados. Las relaciones se etiquetan
  `ci_reported` y nunca acreditan Maven Central. Offline: backend 1.496/1.496,
  tools 464/464, CLI 54/54, frontend 409/409 (58 archivos, axe dirigido), build
  298,0/322 KiB, `compileall`, Compose y diff-check. Sin ejecutar Gradle/Maven,
  consultar proveedores ni usar un proyecto real.

### PROD-230 — Versionado Maven no SemVer

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** cubrir qualifiers Maven solo con orden oficial.
- **Áreas:** normalizador/matcher, PVI/UI y fixtures.
- **Aceptación:** semántica verificada o estado desconocido; cero coerción de
  qualifiers/snapshots; conflictos visibles.
- **Riesgo:** falsos positivos o negativos por orden incorrecto.
- **Estimación:** M
- **Dependencias:** `PROD-142` y corpus Maven validado.
- **Evidencia:** 2026-09-10: matcher offline basado en la especificación y
  `ComparableVersion` oficiales de Apache Maven, limitado deliberadamente a
  componentes numéricos y qualifiers conocidos `alpha/beta/milestone/rc`,
  `snapshot`, release (`ga/final/release`) y `sp`. Conserva mayúsculas en la
  identidad enviada pero compara case-insensitive; release equivale a ausencia
  de qualifier y los componentes numéricos admiten longitud variable. Leading
  zero, qualifiers de proveedor, release numerado, range syntax y separadores
  cuyo árbol Maven sería ambiguo quedan no correlacionables/`unknown`, sin
  coerción. Parser Gradle, inventario/purl, grafo CI, OSV y explicación UI/docs
  usan el mismo subconjunto; fixture `1.0.Final` recorre lock→identidad atestada
  →OSV simulado→rango/fix `1.0-sp1`. Offline: 120 pruebas dirigidas backend,
  2 tools y 7 CLI; regresión completa backend 1.507/1.507, tools 464/464, CLI
  54/54 y frontend 409/409; build 298,0/322 KiB, compileall, Compose y
  diff-check. Sin Maven/Gradle, proveedor real ni proyecto externo.

### PROD-231 — Maven seguro desde SBOM

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** reutilizar evidencia CycloneDX/SPDX JVM exacta.
- **Áreas:** SBOM, PURL, inventario/PVI, UI y pruebas.
- **Aceptación:** purl Maven sin qualifiers/subpath, versión soportada,
  relaciones preservadas y atestación pública separada; metadata descartada.
- **Riesgo:** fuga de coordenada privada o alcance falso.
- **Estimación:** M
- **Dependencias:** `PROD-137`, `PROD-138`, `PROD-139`, `PROD-142` y
  `PROD-230`, completadas.
- **Evidencia:** 2026-09-10: contrato SBOM `2026-09-10.1` acepta solo
  CycloneDX/SPDX admitidos y `pkg:maven/group/artifact@version` exacta, con
  coordenadas lowercase y el subconjunto Maven seguro de `PROD-230`. Rechaza
  qualifier/subpath de purl, versión vendor, mayúsculas e identidad ambigua;
  URLs, refs, hashes y propiedades no sobreviven. El grafo SBOM conserva solo
  alcance demostrado o inconcluso. Importación, atestación pública del operador,
  aprobación tenant y egress siguen siendo puertas separadas; la última barrera
  recibe una marca interna no serializada y OSV ve exclusivamente
  ecosistema/nombre/versión. La suite completa descubrió y corrigió que el
  sanitizador reconstruía en vacío el nuevo contrato, dejando una regresión
  integración almacenamiento→API. Offline: 19 pruebas backend y 56 frontend
  dirigidas, 9 regresiones de integración/contrato, backend completo
  1.510/1.510 y frontend 409/409; build 298,0/322 KiB, axe incluido,
  `compileall`, Compose y diff-check. Sin Internet, gestor JVM, proyecto externo
  ni proveedor real.

### PROD-232 — Evolución versionada del contrato Gradle lock

- **Prioridad:** P3
- **Estado:** pendiente
- **Descripción y motivo:** gobernar cambios de sintaxis con corpus y bump.
- **Áreas:** parser, cobertura, contratos y docs.
- **Aceptación:** cada forma nueva tiene fuente oficial y regresiones; lo
  desconocido falla cerrado sin conservar contenido.
- **Riesgo:** pérdida silenciosa de cobertura o retención de configuración.
- **Estimación:** S
- **Dependencias:** `PROD-142`.
- **Evidencia:** pendiente.

### PROD-093 — Adaptador NVD/CVE sin inferencia de CPE

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** enriquecer un CVE ya correlacionado con evidencia
  oficial NVD acotada, sin usar CPE para atribuir vulnerabilidades a paquetes.
- **Áreas:** egress y normalización NVD, PVI/persistencia/API, modelos, panel,
  comparación, informes, fixtures y documentación operativa.
- **Aceptación:** NVD requiere habilitación independiente y CVE exacto; endpoint
  y parámetro son fijos; la respuesta repite el mismo CVE antes de cachearse.
  Se conservan únicamente estado, CVSS válido, CWE, fechas, digest, referencia
  NVD y conteo CPE rotulado no mapeado. Fallos y datos caducados degradan la
  fuente sin borrar evidencia anterior ni alterar OSV/KEV. UI e informes
  explican el límite; pruebas ordinarias permanecen sin Internet.
- **Riesgo:** correlacionar CPE por heurística o cachear otro CVE genera falsos
  hallazgos; retener descripciones/CPE/source accounts amplía datos sin valor.
- **Estimación:** M
- **Dependencias:** `PROD-027` y `PROD-088`, completadas. `PROD-098` consume
  posteriormente la evidencia CPE y no bloqueó este vertical.
- **Evidencia:** 2026-09-09, contratos PVI `2026-09-09.2` y NVD
  `2026-09-09.1`. Pruebas Docker Python 3.12 con `--network none`: backend
  completo 1.361/1.361, runner 451/451; frontend 56 archivos/381 pruebas y
  build 291,2/322 KiB. También pasaron `compileall`, Compose base y overlay
  privado/aceptación-egress, y `git diff --check`. Fixtures prueban CVE cruzado
  sin entrada en caché, respuesta ambigua, CVSS/CWE, CPE descartado, persistencia,
  owner scope, informe y panel. NVD sigue validado solo con fixtures y
  `MockTransport`: no se consultó el proveedor real.

### PROD-098 — Mapeo CPE↔purl solo corroborado

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** corroborar una relación de identidad CPE↔paquete
  solo mediante política revisada, sin atribución por nombre ni nuevos
  hallazgos.
- **Áreas:** registro CPE, normalización NVD, PVI/modelos, UI, comparación,
  informes, contratos, documentación y fixtures.
- **Aceptación:** una relación exige ecosistema+nombre, parte/vendor/product y
  CVE exactos; política inválida, duplicada, homónimos, otro CVE o escapes
  ambiguos fallan cerrados. CPE/UUID/rangos no se persisten y OSV conserva la
  autoridad sobre la afectación de versión.
- **Riesgo:** una inferencia CPE por similitud refuerza falsos positivos; retener
  metadatos CPE amplía la superficie de datos sin aportar aplicabilidad.
- **Estimación:** L
- **Dependencias:** `PROD-079`, `PROD-093` y `PROD-095`, completadas.
- **Evidencia:** 2026-09-09: política inmutable/acotada `2026-09-09.1`, vacía
  por defecto; contratos NVD `2026-09-09.2` y PVI `2026-09-09.5`. Fixtures
  cubren match exacto, homónimos, CVE/ecosistema/vendor distinto, escapes,
  duplicados, integración, informe y UI. Pasaron 67 pruebas backend dirigidas,
  suite Python offline 1.856/1.856, frontend 32/32 dirigido y 57 archivos/388
  completo, build 291,9/322 KiB, `compileall`, Compose y diff-check. No hubo
  Internet ni proveedor real; poblar entradas reales queda en `PROD-238`.

### PROD-109 — Matriz de permisos y pruebas de aislamiento

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** convertir los roles de equipo existentes en un
  contrato cerrado y demostrable para lectura, mutación de proyecto y
  administración del workspace.
- **Áreas:** identidad, middleware/helpers de autorización, API, UI existente,
  pruebas y `docs/team-permission-matrix.md`.
- **Aceptación:** `reader ⊂ maintainer ⊂ administrator`, valores desconocidos
  denegados, POST de lectura bajo allowlist exacta y CSRF, rutas administrativas
  revalidadas y stores owner-scoped. Pruebas de tres roles, cambio de
  rol/workspace y dos organizaciones sin confirmar recursos ajenos.
- **Riesgo:** escalada horizontal, mutación por reader o exportación cruzada.
- **Estimación:** L
- **Dependencias:** `PROD-012` y `PROD-013`, completadas.
- **Evidencia:** 2026-09-09: matriz runtime de tres capacidades, documentación
  por flujo y regresiones de maintainer/reader/admin, sesión/CSRF, triage,
  atestaciones y tenant cruzado. Pasaron 5/5 dirigidas y suite Python offline
  1.858/1.858; `compileall` y diff-check. La regresión frontend previa conserva
  388/388 y controles por rol. Sin Internet, SSO ni cambios en `SEC-012`.

### PROD-114 — Accesibilidad específica de inteligencia y triage

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** asegurar que una persona que usa teclado o lector
  de pantalla puede filtrar, comprender y decidir sobre evidencia de seguridad
  sin perder contexto ni depender del color.
- **Áreas:** `ProjectVulnerabilityIntelligencePanel.tsx`,
  `ProjectFindingsPanel.tsx`, `FindingLifecyclePanel.tsx`, estilos, pruebas axe
  y `docs/frontend-visual-review.md`.
- **Aceptación:** filtros agrupados semánticamente, conteos anunciados, listas y
  detalle identificables, foco visible/restaurado, jerarquía de encabezados
  válida y ausencia de desbordamiento a 320/768/1440 px. Los estados de egress
  y workflow conservan texto explícito además de color.
- **Riesgo:** pérdida de contexto o una decisión accidental en un flujo crítico;
  exclusión de usuarios de teclado/lector y contenido inutilizable en móvil.
- **Estimación:** M
- **Dependencias:** `PROD-077`, `PROD-103` y `PROD-113`, completadas.
- **Evidencia:** 2026-09-09: fieldsets/legends, regiones y listas etiquetadas,
  anuncio live del resultado y restauración de foco posterior al commit de
  React. Axe descubrió y corrigió un salto `h2`→`h4`; el navegador real reveló
  y corrigió pérdida de foco al desmontar el botón y anchos intrínsecos del
  detalle/remediación. El recorrido sintético local ejercitó estado de egress
  deshabilitado, filtros, expansión, excepción con fecha obligatoria y foco
  visible. Documentos/paneles midieron `305/305`, `753/753` y `1425/1425`
  client/scroll px a 320/768/1440, sin errores de consola ni proveedor externo.
  Pasaron 37/37 pruebas dirigidas, 58 archivos/392 pruebas frontend completas,
  axe, build y presupuesto 292,1/322 KiB. Pestaña, servicios, puertos,
  contenedores y raíz temporal quedaron eliminados; no se retuvo el proyecto
  sintético ni se modificaron los bloqueos protegidos.

### PROD-115 — Consola operativa de frescura y egress

- **Prioridad:** P2
- **Estado:** completada
- **Descripción y motivo:** dar a operación una vista agregada y segura del
  estado de proveedores y caché, sin revelar consultas ni proyectos.
- **Áreas:** caché/egress, modelos/API, auditoría, frontend y runbook.
- **Aceptación:** admin ve únicamente configuración, fresh/stale/invalid,
  tamaño, último refresh, truncado y snapshot offline; mantenimiento local
  exige CSRF y auditoría. Nunca aparecen claves, identidades, cuerpos, URLs ni
  datos de proyecto.
- **Riesgo:** una consola detallada se convierte en fuga; un control de red
  mutable o no auditado altera silenciosamente la cobertura.
- **Estimación:** M
- **Dependencias:** `PROD-053`, `PROD-060`, `PROD-089`, `PROD-100` y
  `PROD-109`, completadas.
- **Evidencia:** 2026-09-09: agregador backend acotado a 10.000 entradas por
  proveedor, GET admin/no-store sin parámetros y purga local de expirados o
  inválidos admin/CSRF con evento mínimo. El panel administrativo muestra solo
  estado agregado, distingue egress/snapshot/fresh/stale/invalid, incluye
  carga/error/reintento y exige confirmación separada antes de limpiar; una
  regresión axe llevó las tarjetas a lista HTML semántica. El runbook aclara que
  `configured` no prueba conectividad y que la consola nunca cambia egress en
  caliente. Pasaron 2/2 pruebas backend dirigidas, 7/7 pruebas frontend
  dirigidas, suite Python offline completa 1.860/1.860, 58 archivos/390 pruebas
  frontend, build y presupuesto 292,1/322 KiB, `compileall`, Compose base y
  privado y diff-check. Ninguna prueba usó Internet y no se tocaron los
  bloqueos protegidos.
