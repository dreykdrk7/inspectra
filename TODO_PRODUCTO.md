# Backlog de evolución de producto de Inspectra

Este documento convierte la arquitectura actual en verticales de producto que
pueden usarse, probarse y operar con seguridad. `TODO.md` sigue siendo la fuente
de verdad general: al cambiar una tarea `PROD-*`, se actualizan en el mismo
cambio su prioridad, estado, dependencias y evidencia aquí y allí. Si hubiese
una discrepancia, prevalece el estado registrado en `TODO.md` hasta corregir la
sincronización. `SEC-012` es una tarea interna fuera de este backlog: quedó
completada el 2026-09-10 tras autorización explícita y ejecución remota verde.

## Base observada y principios de alcance

Inspectra ya dispone de autenticación local/autohospedada, propiedad por
operador, CSRF en los flujos con cookie, subida validada y retenida de archivos,
trabajos pasivos con resultados redactados, informes por ejecución y una primera
entidad de proyecto. El único origen de proyecto actualmente admitido es una
instantánea ZIP/TAR subida por su propietario: no hay rutas del servidor,
clonado, URL ni credenciales de repositorio. La ejecución usa una cola local
durable con cancelación cooperativa, reintentos y recuperación explícita; no
promete una cola distribuida.

El roadmap preserva esos límites. La cola de proyectos es ahora durable dentro
del despliegue soportado de un único proceso: un trabajo nunca iniciado se
revalida y reencola tras reinicio; uno ya iniciado falla de forma explícita y
sin resultado parcial. No es una cola distribuida ni aislamiento multiempresa.
Cada incorporación de red, código, credencial
o multiusuario requiere antes aislamiento, permisos mínimos, límites y pruebas
de fallo. No se incorporarán pantallas que no cierren un flujo completo ni se
prometerán vulnerabilidades confirmadas cuando solo exista un indicador.

## Prioridad obligatoria tras `PROD-084`

La prioridad obligatoria que siguió a `PROD-084` quedó satisfecha por
`PROD-121`: el primer vertical de inteligencia pública tiene egress opt-in
seguro, OSV utilizable para identidades npm y PyPI con procedencia pública,
persistencia/frescura, resultado, comparación e informe. Por tanto,
`PROD-085` y `PROD-086` vuelven a su prioridad P2 normal, pero no deben
adelantarse a una tarea P1 viable de producto u operación. Las resoluciones
Poetry siguen deliberadamente locales: no bastan para enviar una identidad a un
proveedor. OSV y el catálogo CISA KEV se validaron posteriormente contra sus
servicios oficiales durante la aceptación expresamente autorizada de la fuente B;
GHSA continúa validado solo con fixtures y no se ha consultado con credenciales
reales. KEV se limita a enriquecer CVE ya correlacionados y nunca decide por sí
mismo que un paquete sea vulnerable.

## Referencias públicas de producto consultadas

- [GitHub Code Scanning: detalle, severidad y contexto de alertas](https://docs.github.com/en/enterprise-cloud%40latest/code-security/concepts/code-scanning/code-scanning-alerts)
  respalda que cada hallazgo debe conservar herramienta, ubicación, severidad y
  contexto, no solo un contador.
- [GitHub Code Scanning: resolver y documentar una alerta](https://docs.github.com/en/code-security/how-tos/manage-security-alerts/manage-code-scanning-alerts/resolve-alerts)
  informa el diseño de decisiones trazables con motivo y comentario, en vez de
  borrar hallazgos.
- [Snyk: ignores con motivo y caducidad](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/ignore-issues)
  justifica excepciones acotadas, revisables y visibles en ejecuciones futuras.
- [OSV API](https://google.github.io/osv.dev/api/) y su
  [guía rápida](https://google.github.io/osv.dev/quickstart/) documentan la
  consulta por paquete/ecosistema/versión y lote; se usarán solo tras diseñar
  caché, límites y evidencia reproducible.
- [NVD Vulnerability APIs](https://nvd.nist.gov/developers/vulnerabilities),
  [GitHub Global Security Advisories](https://docs.github.com/en/rest/security-advisories/global-advisories)
  y el [catálogo CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  confirman que CVE, rangos/fechas, CVSS y explotación conocida son señales
  distintas. Sus adaptadores conservarán la fuente y el estado de ausencia,
  sin inferir equivalencias de CPE ni explotación.

Estas fuentes inspiran expectativas verificables; no implican compatibilidad ni
integración con esos proveedores.

## Estado sincronizado

| ID | Prioridad | Estado en `TODO.md` | Vertical |
| --- | --- | --- | --- |
| PROD-001 | P0 | completada | Alta de proyecto con instantánea archivada |
| PROD-002 | P0 | completada | Ejecuciones reproducibles e historial básico |
| PROD-003 | P0 | completada | Contrato normalizado y redactado de hallazgos |
| PROD-004 | P0 | completada | Exploración de resultados de proyecto |
| PROD-005 | P1 | completada | Comparación entre ejecuciones |
| PROD-006 | P1 | completada | Informe de proyecto para equipos |
| PROD-007 | P2 | completada | Repositorios de solo lectura, tras modelo de amenaza |
| PROD-008 | P2 | completada | Límites, aislamiento y trazabilidad operativa |
| PROD-009 | P2 | completada | Perfiles pasivos por stack |
| PROD-010 | P1 | completada | Enriquecimiento reproducible de dependencias |
| PROD-011 | P1 | completada | Ciclo de vida y excepciones revisables |
| PROD-012 | P1 | completada | Organizaciones y roles mínimos |
| PROD-013 | P2 | completada | Auditoría de acciones de producto y configuración sensible |
| PROD-014 | P2 | completada | Reglas de secretos e indicadores de configuración en proyectos |
| PROD-015 | P1 | completada | Cola local durable, cancelación y recuperación explícita |
| PROD-016 | P2 | completada | Infraestructura, contenedores y configuración dentro del proyecto |
| PROD-017 | P1 | completada | Onboarding, navegación y accesibilidad del flujo de proyecto |
| PROD-018 | P2 | completada | SBOM y revisión de licencias declaradas |
| PROD-019 | P2 | completada | Integraciones de CI y salidas interoperables |
| PROD-020 | P2 | completada | Privacidad, residencia, retención y despliegue empresarial |
| PROD-021 | P3 | completada | Asignación, comentarios y colaboración contextual |
| PROD-022 | P3 | completada | Métricas de tendencia y objetivos de riesgo |
| PROD-023 | P1 | completada | Ubicaciones normalizadas seguras |
| PROD-024 | P1 | completada | Inventario seguro de componentes por ejecución |
| PROD-025 | P1 | completada | Fidelidad de versión y lockfiles soportados |
| PROD-026 | P1 | completada | Egress y privacidad de fuentes públicas |
| PROD-027 | P1 | completada | Contrato canónico y fixtures de advisories |
| PROD-028 | P1 | completada | Correlación OSV por versión exacta |
| PROD-029 | P1 | completada | CVSS, evidencia y remediación |
| PROD-030 | P1 | completada | UX de dependencias y cobertura |
| PROD-031 | P1 | completada | Señal CISA KEV independiente |
| PROD-032 | P1 | completada | Corroboración GHSA con evidencia versionada |
| PROD-033 | P1 | completada | Frescura, caché y recuperación |
| PROD-034 | P2 | completada | Línea base, comparación e informe |
| PROD-035 | P1 | completada | Cobertura visible de Módulo 2 |
| PROD-036 | P2 | completada | Retención/eliminación recuperable de proyecto y derivados |
| PROD-037 | P2 | completada | Modularidad de pruebas de producto |
| PROD-038 | P2 | completada | CI y puertas de riesgo |
| PROD-039 | P3 | completada | Identidad empresarial federada |
| PROD-040 | P2 | completada | Backup, verificación y restauración aislada |
| PROD-041 | P1 | completada | Nueva instantánea inmutable en el mismo proyecto |
| PROD-042 | P1 | completada | Estado y recuperación comprensibles por ejecución |
| PROD-043 | P1 | completada | Confirmación explícita de autorización de alcance |
| PROD-044 | P2 | completada | Prevuelo seguro de cobertura antes de analizar |
| PROD-045 | P2 | completada | Prueba de aceptación del recorrido de proyecto |
| PROD-046 | P2 | completada | Contexto de corrección enlazado al hallazgo |
| PROD-047 | P1 | completada | Emparejamiento manifiesto/lockfile |
| PROD-048 | P1 | completada | Alcance directo/transitivo/opcional |
| PROD-049 | P2 | completada | Aliases, workspaces y fuentes no registry |
| PROD-050 | P1 | completada | Estados de correlación verificables |
| PROD-051 | P1 | completada | Conflictos y retirada de advisories |
| PROD-052 | P2 | completada | Límites de respuesta de feeds |
| PROD-053 | P2 | completada | Frescura visible de inteligencia |
| PROD-054 | P2 | completada | Snapshots offline de advisories |
| PROD-055 | P2 | completada | Protección de namespaces privados |
| PROD-056 | P2 | completada | Gobernanza de fixtures de advisories |
| PROD-057 | P1 | completada | Perfil de ejecución inmutable |
| PROD-058 | P1 | completada | Admisión y cuota por propietario |
| PROD-059 | P1 | completada | Postura segura de despliegue |
| PROD-060 | P2 | completada | Salud y degradación operativa |
| PROD-061 | P2 | completada | Integridad de resultados retenidos |
| PROD-062 | P2 | completada | Retención por clase de derivado |
| PROD-063 | P2 | completada | Exportación general redactada de la bitácora protegida |
| PROD-064 | P2 | completada | Ensayo de recuperación |
| PROD-065 | P1 | completada | Línea base y regresión por proyecto |
| PROD-066 | P1 | completada | Triage local revisable; reconciliada con PROD-011 |
| PROD-067 | P2 | completada | Tokens de automatización mínimos |
| PROD-068 | P2 | completada | Contrato de integración seguro |
| PROD-069 | P2 | completada | Exportación SARIF trazable |
| PROD-070 | P2 | completada | Modo CI determinista |
| PROD-071 | P3 | completada | Eventos firmados a integraciones |
| PROD-072 | P3 | completada | Métricas de adopción privadas |
| PROD-073 | P1 | completada | Admisión idempotente y acotada de instantáneas |
| PROD-074 | P1 | completada | Matriz de seguridad para mutaciones de proyecto |
| PROD-075 | P2 | completada | Privacidad de metadatos de fuente e historial |
| PROD-076 | P1 | completada | Espacio de trabajo de proyecto y línea temporal |
| PROD-077 | P2 | completada | Revisión visual accesible del flujo de proyecto |
| PROD-078 | P1 | completada | Control verificable de cinco rondas de revisión |
| PROD-079 | P1 | completada | Identidad purl local de componentes exactos |
| PROD-080 | P1 | completada | Comparación de versiones por ecosistema y estado desconocido |
| PROD-081 | P1 | completada | Grafo npm bloqueado, acotado y sin URLs |
| PROD-082 | P2 | completada | Ingesta segura de `pnpm-lock.yaml` |
| PROD-083 | P2 | completada | Ingesta segura de `yarn.lock` |
| PROD-084 | P2 | completada | Ingesta segura de `poetry.lock` |
| PROD-085 | P2 | completada | Ingesta segura de `Pipfile.lock` |
| PROD-086 | P2 | completada | Evidencia de hashes en requisitos Python |
| PROD-087 | P2 | completada | Matriz de cobertura de gestores y lockfiles |
| PROD-088 | P1 | completada | Minimización verificable de egress de advisories |
| PROD-089 | P2 | completada | Transporte allowlist y fallos seguros de proveedores |
| PROD-090 | P1 | completada | Adaptador OSV por lote con fixture determinista |
| PROD-091 | P2 | completada | Paginación OSV y contabilidad reproducible |
| PROD-092 | P2 | completada | Adaptador GHSA con evidencia versionada (reconciliada con PROD-032) |
| PROD-093 | P2 | completada | Adaptador NVD/CVE sin inferencia de CPE |
| PROD-094 | P2 | completada | Resiliencia operativa y evolución del contrato CISA KEV |
| PROD-095 | P2 | completada | Evidencia de boletín oficial de proveedor |
| PROD-096 | P2 | completada | Reconciliación de fuentes a nivel de campo |
| PROD-097 | P2 | completada | Normalizador CVSS v3/v4 y ausencias |
| PROD-098 | P2 | completada | Mapeo CPE↔purl solo corroborado |
| PROD-099 | P2 | completada | Cadena de procedencia de snapshots de advisories |
| PROD-100 | P2 | completada | Caché obsoleta y degradación explicable |
| PROD-101 | P1 | completada | Motor local de correlación determinista |
| PROD-102 | P1 | completada | Huella estable de vulnerabilidad por componente |
| PROD-103 | P2 | completada | Excepciones temporales y revisión obligatoria |
| PROD-104 | P2 | completada | Línea base consciente de cobertura |
| PROD-105 | P2 | completada | Tendencias de riesgo reproducibles, materializadas por PROD-147 |
| PROD-106 | P2 | completada | Perfil de redacción para informes de equipo |
| PROD-107 | P2 | completada | Bandeja pasiva durable de acciones y avisos |
| PROD-108 | P2 | completada | Cartera de proyectos y priorización de equipo |
| PROD-109 | P2 | completada | Matriz de permisos y pruebas de aislamiento |
| PROD-110 | P2 | completada | Integridad encadenada de auditoría de acciones |
| PROD-111 | P2 | completada | Onboarding seguro con datos sintéticos |
| PROD-112 | P2 | completada | Puerta de alcance para automatización CI |
| PROD-113 | P1 | completada | Vista de resultados de vulnerabilidades profesional |
| PROD-114 | P2 | completada | Accesibilidad específica de inteligencia y triage |
| PROD-115 | P2 | completada | Consola operativa de frescura y egress |
| PROD-116 | P1 | completada | Candidatura de despliegue segura y reversible |
| PROD-117 | P1 | completada | Aceptación real de la fuente autorizada B con OSV/KEV oficiales y limpieza integral |
| PROD-118 | P1 | completada | Preservar intervalos OSV discontinuos |
| PROD-119 | P1 | completada | Preflight reproducible de versión Python para locks |
| PROD-120 | P2 | completada | Eliminación completa y verificable de proyecto |
| PROD-121 | P1 | completada | Procedencia pública mínima para OSV PyPI |
| PROD-122 | P1 | completada | Worker con montaje y cuota fuerte por ejecución |
| PROD-123 | P1 | completada | Estados terminales exactos en inventario, hallazgos e inteligencia |
| PROD-124 | P2 | completada | Retención y baja segura de invitaciones e identidades de equipo |
| PROD-125 | P0 | completada | Egress opt-in utilizable en la candidatura de aceptación |
| PROD-126 | P0 | completada | Eliminar desborde horizontal del recorrido de proyecto a 320 px |
| PROD-127 | P0 | completada | Compatibilidad estricta con respuestas resumidas de OSV |
| PROD-128 | P0 | completada | Presentación móvil e indicadores semánticos de inteligencia |
| PROD-129 | P1 | completada | Preparar un corte local coherente y revisable |
| PROD-130 | P1 | completada | Validar CI remoto y cerrar la puerta de release |
| PROD-131 | P1 | completada | CLI: snapshot Git seguro, preflight y dry-run |
| PROD-132 | P1 | completada | CLI: subida, seguimiento y resultado end-to-end |
| PROD-133 | P1 | completada | Tokens de automatización con alcance y revocación |
| PROD-134 | P1 | completada | Admisión CI idempotente ligada a proyecto y commit |
| PROD-135 | P1 | completada | Motor de políticas y baseline para pipelines |
| PROD-136 | P1 | completada | SARIF, JSON, Markdown y ejemplos de CI |
| PROD-137 | P1 | completada | Frontera inmutable de importación SBOM |
| PROD-138 | P1 | completada | Importación CycloneDX utilizable de extremo a extremo |
| PROD-139 | P1 | completada | Importación SPDX utilizable de extremo a extremo |
| PROD-140 | P2 | completada | Inventario y correlación segura de Go |
| PROD-141 | P2 | completada | Inventario y correlación segura de Rust/Cargo |
| PROD-142 | P2 | completada | Inventario y correlación segura de Java/JVM |
| PROD-143 | P2 | completada | Inventario y correlación segura de PHP/Composer |
| PROD-144 | P2 | completada | Inventario y correlación segura de .NET/NuGet |
| PROD-145 | P1 | completada | Cartera global por riesgo, cobertura y frescura |
| PROD-146 | P1 | completada | Centro de remediación y acciones comunes |
| PROD-147 | P2 | completada | Tendencias y vistas por perfil de equipo |
| PROD-148 | P1 | completada | Registro de activos y autorizaciones Active |
| PROD-149 | P1 | completada | Ejecuciones Active limitadas por activo autorizado |
| PROD-150 | P1 | completada | Historial, comparación y postura Active |
| PROD-151 | P2 | completada | Reauditoría de adopción semanal del Ciclo 6 |
| PROD-152 | P1 | completada | Distribución local verificable de Inspectra CLI |
| PROD-153 | P1 | completada | Asistente de incorporación CI por proyecto |
| PROD-154 | P1 | completada | Revisiones SBOM atómicas dentro del mismo proyecto |
| PROD-155 | P1 | completada | Conformidad SARIF 2.1 con esquema oficial fijado |
| PROD-156 | P1 | completada | Negociación de capacidades CLI/servidor antes de subir |
| PROD-157 | P1 | completada | Rotación y retención de credenciales de automatización |
| PROD-158 | P1 | completada | Certeza y cobertura del grafo SBOM |
| PROD-159 | P2 | completada | Cancelación remota opcional al interrumpir la CLI |
| PROD-160 | P2 | completada | Perfiles locales de CLI sin secretos |
| PROD-161 | P2 | completada | Matriz multiplataforma del CLI |
| PROD-162 | P2 | completada | Métricas privadas de adopción opt-in |
| PROD-163 | P2 | completada | Diagnóstico de clones superficiales y objetos ausentes |
| PROD-164 | P1 | completada | Preflight de SBOM antes de crear el proyecto |
| PROD-165 | P1 | completada | Entrada por intención y portada profesional |
| PROD-166 | P1 | completada | UX específica por tipo de fuente del proyecto |
| PROD-167 | P2 | bloqueada | Habilitar macOS y Windows con evidencia real |
| PROD-168 | P0 | completada | Restaurar contratos públicos y puertas operativas tras cambios del Ciclo 7 |
| PROD-169 | P1 | completada | Baseline, triage estructurado y exportación Active |
| PROD-170 | P1 | completada | Verificación opcional y acotada del control del activo |
| PROD-171 | P1 | completada | Centro de operaciones Active profesional v1 |
| PROD-172 | P2 | completada | Revisiones Active recurrentes autorizadas |
| PROD-173 | P1 | completada | Reauditoría de uso semanal empresarial de Active |
| PROD-174 | P0 | completada | Compatibilidad Active con administrador raíz de equipo |
| PROD-175 | P0 | completada | Aislar todas las ejecuciones Active registradas en el runner |
| PROD-176 | P1 | completada | Renovación reatestiguada de autorizaciones Active |
| PROD-177 | P1 | completada | Responsables Active validados contra miembros vigentes |
| PROD-178 | P1 | completada | Retención, exportación y borrado Active owner-scoped |
| PROD-179 | P1 | completada | Readiness efectivo del runner por capacidad |
| PROD-180 | P2 | completada | Aprobación opcional de cuatro ojos para cambios críticos Active |
| PROD-181 | P2 | completada | Alta masiva de activos con dry-run y revisión |
| PROD-182 | P2 | completada | Bandeja priorizada de acciones Active y SLA local |
| PROD-183 | P1 | completada | Cola durable, progreso y recuperación de ejecuciones Active |
| PROD-184 | P1 | completada | Cuotas y rate limits Active por organización |
| PROD-185 | P1 | completada | Snapshot inmutable de la revisión de autorización |
| PROD-186 | P2 | completada | Bundle de evidencia Active verificable |
| PROD-187 | P1 | completada | Aislar también el egress de verificación de control |
| PROD-188 | P1 | completada | Paginación y búsqueda Active a escala |
| PROD-189 | P2 | completada | Exportación de auditoría operativa Active |
| PROD-190 | P2 | completada | Ventanas, zonas horarias y backoff para recurrencia |
| PROD-191 | P1 | completada | Reconciliación de activos al salir un miembro |
| PROD-192 | P2 | completada | Validación UX/accesibilidad con cartera grande |
| PROD-193 | P2 | completada | Índice durable para carteras Active grandes |
| PROD-194 | P2 | completada | Retirada del listado Active no acotado |
| PROD-195 | P2 | completada | Unicidad y exclusión mutua en el alta individual Active |
| PROD-196 | P2 | completada | Resumen semanal Active acotado e indexado |
| PROD-197 | P1 | completada | Selección prioritaria completa para la bandeja Active |
| PROD-198 | P1 | completada | Admisión e idempotencia Active indexadas a escala |
| PROD-199 | P1 | completada | Historial de análisis paginado e indexado |
| PROD-200 | P1 | completada | Selección profunda de análisis y líneas base paginadas |
| PROD-201 | P1 | completada | Eliminar escaneos internos restantes del historial de jobs |
| PROD-202 | P1 | completada | Recuperación de jobs y fuentes vivas indexada |
| PROD-203 | P1 | completada | Borrado integral Active indexado por activo |
| PROD-204 | P1 | completada | Historial de verificaciones Active indexado por activo |
| PROD-205 | P1 | completada | Historial Active profundo y controles con cobertura exacta |
| PROD-206 | P1 | completada | Retención terminal Active indexada y reanudable por lotes |
| PROD-207 | P1 | completada | Marcación de referencias de fuente indexada y privada |
| PROD-208 | P1 | completada | Relaciones de baseline y fuente de proyectos indexadas |
| PROD-209 | P1 | completada | Retención de fuentes indexada y reanudable |
| PROD-210 | P1 | completada | Cola de recurrencia Active indexada y despacho acotado |
| PROD-211 | P1 | completada | Informe semanal reproducible de la cartera Active |
| PROD-212 | P2 | completada | Recibo privado y target-free de revisión semanal Active |
| PROD-213 | P2 | completada | Atestación inmutable del canal de incorporación de cada snapshot |
| PROD-214 | P2 | completada | Índice duradero y migración del listado heredado de proyectos |
| PROD-215 | P2 | completada | Responsabilidad estable de proyecto separada del triage de hallazgos |
| PROD-216 | P2 | completada | Diario recuperable para lotes de remediación |
| PROD-217 | P2 | completada | Vistas guardadas privadas de remediación |
| PROD-218 | P2 | completada | Planes de remediación duraderos a escala |
| PROD-219 | P2 | completada | Índice materializado privado de tendencias históricas |
| PROD-220 | P1 | completada | Atestaciones públicas tenant-scoped, auditables y revocables |
| PROD-221 | P2 | completada | Grafo Go precomputado y ligado al snapshot |
| PROD-222 | P3 | pendiente | Rutas Go canónicas con escapes de mayúsculas |
| PROD-223 | P2 | completada | Grafo y features Cargo aportados por CI |
| PROD-224 | P3 | pendiente | Evolución controlada de fuentes oficiales Cargo |
| PROD-225 | P2 | completada | Mapeo GHSA explícito para Go/Cargo y futuros ecosistemas |
| PROD-226 | P2 | completada | Grafo Composer aportado por CI sin ejecutar Composer |
| PROD-227 | P3 | pendiente | Versiones Composer avanzadas sin coerción insegura |
| PROD-228 | P3 | pendiente | Evolución versionada del contrato composer.lock |
| PROD-229 | P2 | completada | Grafo y scopes Gradle aportados por CI sin ejecutar builds |
| PROD-230 | P2 | completada | Comparación Maven compatible con esquemas no SemVer |
| PROD-231 | P2 | completada | Identidades Maven seguras desde SBOM admitidos |
| PROD-232 | P3 | pendiente | Evolución versionada del contrato gradle.lockfile |
| PROD-233 | P1 | completada | Cursores Active con Base64url canónico |
| PROD-234 | P2 | completada | Grafo NuGet multi-target aportado por CI |
| PROD-235 | P2 | completada | Semántica completa y segura de versiones NuGet |
| PROD-236 | P3 | pendiente | Evolución versionada de packages.lock.json |
| PROD-237 | P3 | completada | Evaluador CVSS v4 validado con corpus oficial |
| PROD-238 | P2 | bloqueada | Catálogo revisado de equivalencias CPE↔purl |
| PROD-239 | P2 | completada | Reconciliación verificable del backlog heredado |
| PROD-240 | P1 | completada | Permisos y tipo seguro del lock de almacenamiento |
| PROD-241 | P2 | completada | Proyección materializada de prioridad para carteras >5.000 |
| PROD-242 | P2 | completada | Refresco incremental y rebuild en segundo plano de tendencias |
| PROD-243 | P2 | completada | Sobre común versionado para evidencia CI multi-ecosistema |
| PROD-244 | P2 | completada | Productores CI auditables para grafos pasivos |
| PROD-245 | P2 | completada | Validador automático de coherencia entre backlogs |
| PROD-246 | P2 | completada | Clave estable e invalidación segura del índice de cartera multiworker |
| PROD-247 | P2 | completada | Gate reproducible de rendimiento para planes de remediación |
| PROD-248 | P2 | completada | Reloj de mutación owner-scoped para tendencias |
| PROD-249 | P2 | completada | Suite CLI dentro de la puerta Python reproducible |
| PROD-250 | P2 | completada | Gate reproducible de programación de tendencias a escala |
| PROD-251 | P2 | completada | Durabilidad eficiente y gate reproducible del reloj owner-scoped |
| PROD-252 | P3 | completada | Custodia y replay controlado del outbox de integraciones |
| PROD-253 | P2 | completada | Estabilizar la prueba asíncrona de paginación Active bajo carga |
| PROD-254 | P1 | completada | Estado canónico y verificable de aceptación de despliegue |
| PROD-255 | P2 | completada | Avisos verificables de dependencias runtime distribuidas |
| PROD-256 | P2 | pendiente | Ligar webhooks de integración a la resolución validada |
| PROD-257 | P2 | pendiente | Objetivos táctiles coherentes en los flujos principales |
| PROD-258 | P2 | completada | Política de reporte responsable de vulnerabilidades |
| PROD-259 | P2 | completada | Protección exigible de `main` y checks requeridos |

## Evaluación de las P3 multiecosistema — 2026-09-10

No se promueve ninguna tarea P3 en este corte. La búsqueda local no encontró un
proyecto autorizado o fixture contractual que necesite escapes Go (`PROD-222`)
ni aliases/branches Composer (`PROD-227`). `PROD-224`, `228`, `232` y `236`
requieren un cambio real de formato y corpus oficial revisado antes de ampliar
sus parsers. Aunque ya llegan vectores CVSS v4 publicados en fixtures, derivar su
puntuación (`PROD-237`) exige el corpus oficial FIRST y sus casos de redondeo;
conservar el score publicado y marcar la derivación como no disponible sigue
siendo el comportamiento seguro. La ausencia de red/evidencia primaria en este
ciclo impide satisfacer esos criterios sin especulación; las tareas permanecen
pendientes y los formatos desconocidos continúan fallando cerrados.

## Reconciliación del backlog heredado — PROD-239

- **Prioridad / estado / tamaño:** P2 / completada / S.
- **Necesidad y valor:** mantener un backlog fiable y evitar tanto rehacer
  verticales existentes como ocultar brechas bajo nombres parecidos.
- **Flujo y áreas:** criterios heredados → contratos/stores/API/CLI/UI/pruebas
  actuales → decisión absorbida o brecha reducida → sincronización de ambos
  backlogs.
- **Aceptación:** cada tarea solicitada queda ligada a evidencia concreta o a
  una brecha accionable; no hay estados contradictorios entre documentos.
- **Riesgos:** una absorción falsa oculta seguridad pendiente; un duplicado
  desperdicia capacidad y puede introducir dos fuentes de verdad.
- **Dependencias:** implementación posterior existente y sus pruebas.
- **Estrategia/evidencia:** grupos offline dirigidos, inspección de contratos y
  matriz siguiente; 30 backend y 29 CLI superadas, con la omisión SARIF
  declarada de forma explícita.

| Tarea | Estado reconciliado | Materialización o brecha demostrada |
| --- | --- | --- |
| `PROD-019` | completada | `PROD-131`–`136`, `155` y `157` cubren el primer adaptador CI; webhook permanece separado en `PROD-071`. |
| `PROD-034` | completada | Comparación/frescura/baseline/informe cubiertos por `PROD-033`, `050`, `051`, `053`, `065`, `096`, `099` y `104`. |
| `PROD-063` | pendiente reducida | `PROD-013` cubre store, redacción, consulta y retención; falta exportación general, pues la existente es solo Active. |
| `PROD-067`–`070` | completadas | `PROD-133`–`136`, `155` y `157` satisfacen tokens, contrato, SARIF y modo CI. |
| `PROD-107` | pendiente reducida | Cartera/remediación y action inbox Active no aportan lifecycle durable leído/no leído a proyectos pasivos. |
| `PROD-108` | completada | Cartera y tendencias owner/org-scoped en `PROD-145`/`147`. |
| `PROD-112` | completada | Puertas de scope, commit/digest, policy y asistente en `PROD-133`–`135`/`153`. |
| `PROD-120` | completada | Cascada write-ahead recuperable, preflight/API/UI y dos tenants en `project_deletion.py`. |

La reconciliación se ejecutó contra código y pruebas, no por coincidencia
nominal. Pasaron 30/30 pruebas backend dirigidas y 29/29 pruebas CLI funcionales
en contenedores Python 3.12 sin red y con el repositorio en solo lectura. La
imagen disponible carece de `jsonschema`, por lo que no se presenta una nueva
validación del esquema SARIF: se conserva la evidencia de `PROD-155`. Los
primeros intentos que no llegaron a ejecutar por entorno incompleto quedan
registrados en `TODO.md` y no cuentan como prueba superada.

## Cinco rondas de revisión

Este control no sustituye las fichas ni la evidencia de las tareas: acredita que
cada ronda se ejecutó sobre código, contratos y pruebas reales. La quinta ronda
no fue un cierre de producto ni de despliegue. `SEC-012` estaba bloqueada y no
se incluyó en aquel ciclo; quedó completada después, el 2026-09-10, con
autorización y evidencia CI remota independiente.

### Ronda 1 — flujo de proyecto y resultados

- **Alcance revisado:** incorporación por archivo autorizado, instantáneas,
  historial, ejecución, hallazgos, inventario, comparación, exportación y los
  componentes de proyecto de frontend.
- **Funcionalidades y riesgos detectados:** el flujo archivado es el único
  origen admisible y conserva propiedad; faltaban continuidad segura entre
  instantáneas, autorización explícita, cobertura visible y una vista que
  reuniese el contexto. Persistían riesgo de duplicación por reintento y de
  exposición de metadatos de archivo.
- **Tareas nuevas añadidas:** `PROD-041`…`PROD-046`, `PROD-073`…`PROD-077` y,
  en la comprobación actual, `PROD-109`, `PROD-110` y `PROD-111`.
- **Tareas implementadas:** `PROD-041`, `PROD-042`, `PROD-043`, `PROD-044`,
  `PROD-045`, `PROD-046`, `PROD-074`, `PROD-076` y `PROD-035`; sus pruebas y
  comandos figuran en sus evidencias.
- **Estado posterior (2026-09-06):** `PROD-073`, `PROD-075` y `PROD-077` están
  completadas con su evidencia individual; las tareas posteriores conservan el
  estado actual en la tabla sincronizada y sus fichas.

### Ronda 2 — Módulo 3 e inteligencia pública

- **Alcance revisado:** `component_inventory.py`, runner de archivos,
  contrato `2026-09-05.3`, `package.json`, `package-lock.json`, panel de
  inventario y documentación de fuentes OSV, GitHub, NVD y CISA.
- **Funcionalidades y riesgos detectados:** el inventario pasivo ya conserva
  identidades exactas aptas para correlación y el vertical OSV está disponible
  tras activación administrativa; sus snapshots ya conservan fuente, rango,
  CVE/GHSA, fecha, vector y CVSS v3 derivado. GHSA ya se corrobora por alias
  retenido y KEV por CVE exacto; siguen pendientes deduplicación multifuente,
  caducidad explícita y cobertura transitiva general. Consultar antes
  de aislar egress podría revelar nombres/versiones privados; inferir rangos
  provocaría falsos positivos o negativos.
- **Tareas nuevas añadidas:** `PROD-024`…`PROD-056`; esta reauditoría añade
  `PROD-079`…`PROD-094` para identidad, lockfiles, correlación y calidad de
  datos sin duplicar los contratos ya planificados.
- **Tareas implementadas:** `PROD-024`, `PROD-025`, `PROD-047`, `PROD-035`,
  `PROD-079`, `PROD-080`, `PROD-026`, `PROD-027`, `PROD-028`, `PROD-029`,
  `PROD-032`, `PROD-031` y `PROD-030`.
  La suite final usa exclusivamente fixtures y transportes simulados, sin
  contactar fuentes públicas.
- **Pendientes y razón de prioridad:** `PROD-033`, `PROD-050` y `PROD-051` ya
  completaron frescura/caducidad, estados verificables, conflictos y retirada
  bajo la misma frontera de egress. `PROD-048` cerró el alcance de dependencias,
  `PROD-017` el onboarding responsive y `PROD-030` la exploración segura de
  resultados. Quedan P2 de cobertura y operación que no deben fingir soporte
  para gestores, fuentes o perfiles todavía no implementados.
- **Actualización real 2026-09-06:** `PROD-117` consultó OSV y CISA KEV
  oficiales sobre el commit inmutable autorizado de la fuente B. Descubrió y cerró
  `PROD-127` al observar referencias resumidas de `querybatch`: lote, detalles
  y resultado quedaron reconciliados sin destinos dinámicos. OSV devolvió 33
  ocurrencias normalizadas (28 IDs únicos y 25 CVE); KEV evaluó únicamente CVE
  ya correlacionados y no creó vulnerabilidades. GHSA real permaneció prohibido.
  La reauditoría conserva `PROD-093`, `PROD-094` y `PROD-096`…`PROD-100` como
  ampliaciones P2: aportan nuevas fuentes/calidad, pero no invalidan el vertical
  OSV exacto ya utilizable y verificado.

### Ronda 3 — seguridad, operación y arquitectura

- **Alcance revisado:** configuración, autenticación, propiedad, CSRF,
  almacenamiento, recuperación tras reinicio, Compose, contenedores y pruebas
  de seguridad.
- **Funcionalidades y riesgos detectados:** hay defaults restrictivos, rutas
  owner-scoped, redacción y contenedores con capacidades eliminadas; la ejecución
  sigue local/en memoria y no ofrece cuota transaccional, recuperación durable,
  auditoría empresarial ni restauración ensayada. Una `422` podía reflejar
  entradas y se corrigió como `SEC-019`.
- **Tareas nuevas añadidas:** `PROD-057`…`PROD-064`; la reauditoría añade
  `PROD-095`…`PROD-101` para cadena de custodia, operación y configuración.
- **Tareas implementadas:** `SEC-019`, `PROD-074` y `PROD-059`; además la
  recuperación de trabajos y las defensas de Compose registradas en `TODO.md`
  fueron revisadas contra sus pruebas estáticas y de backend. `PROD-059` cierra
  la postura del perfil privado: sesión persistente SQLite bajo datos y permisos
  privados obligatorios antes de arrancar.
- **Pendientes y razón de prioridad:** `PROD-057` y `PROD-058` siguen siendo
  P1 porque perfil reproducible y admisión condicionan cualquier uso
  profesional, pero permanecen bloqueadas por `PROD-015`, `PROD-008` y
  `PROD-012`. `PROD-052` completó la validación previa a caché de feeds
  públicos. `PROD-049` cerró la clasificación y redacción de aliases,
  workspaces y locators no registry. `PROD-055` ya excluye nombres privados y
  exige procedencia npm pública verificable antes de egress. `PROD-101` ya
  separa y refuerza el motor local de correlación determinista. `PROD-118` ya
  conserva los intervalos OSV discontinuos y `PROD-102` estabiliza la identidad
  de hallazgos entre refrescos de evidencia. Esta revisión descubre `PROD-119`:
  el preflight local debe rechazar con claridad un Python incompatible antes de
  intentar resolver los lockfiles de Python 3.12.
- **Actualización ejecutada 2026-09-06:** `PROD-008` quedó completada tras
  implementar perfiles y límites, workspace opaco verificado, cancelación,
  linaje de reintento, recuperación de reinicio, causas terminales y límites
  Compose. La suite backend que antes parecía detenida se dividió y reprodujo:
  el primer corte fue un contrato obsoleto, no el sandbox; la pasada final fue
  997/997. Esta reauditación añadió `PROD-122` porque el montaje completo de
  `data/` en el runner sigue sin ser aislamiento fuerte por ejecución.
- **Actualización continuada 2026-09-06:** `PROD-015` y `PROD-058` ya están
  completadas: recuperación durable de trabajos de proyecto nunca iniciados,
  cierre explícito de ejecución interrumpida, apagado drenado y admisión
  atómica global/por propietario sin reservas huérfanas. La regresión más
  reciente pasó 1.011/1.011 backend, 412/412 runner/estáticas y 272/272
  frontend. Siguen P1 `PROD-122` para aislamiento fuerte del proceso/volumen y
  `PROD-073` para atomicidad integral snapshot+job ante un fallo entre stores;
  no se atribuyen esas garantías al control de cuota actual.
- **Actualización de aislamiento 2026-09-06:** `PROD-122` quedó completada. Se
  eliminó el montaje global del runner de archivos, se separó el runner con
  egress, se fijaron destinos internos sin proxies y cada fuente se procesa en
  un subproceso efímero serializado, con tmpfs y límites reproducibles. La
  regresión pasó 1.019 backend, 420 runner/guardas y 277 frontend; un smoke de
  imagen sin red confirmó fuente correcta, rol cerrado, ausencia de `/app/data`,
  tmpfs vacío y ningún hijo residual. `PROD-073` pasa a ser la P1 viable por
  atomicidad snapshot+job; `PROD-012` continúa impidiendo afirmar multiempresa.
- **Actualización de admisión 2026-09-06:** `PROD-073` quedó completada con
  clave opaca reutilizable, bitácora privada, recuperación antes del despacho y
  límite de historial sin purga. Sus pruebas y regresión constan en la ficha.
  `PROD-012` ya materializa organizaciones y roles, y `PROD-013` completa la
  bitácora mínima consultable; aún no se afirma multiempresa hasta completar
  retención por derivado, backup/restore y matriz integral de permisos.
- **Actualización de privacidad 2026-09-06:** `PROD-020` quedó completada con
  política visible por clase, purga administrativa limitada a la organización,
  limpieza separada de caché pública, borrado de snapshots junto al resultado y
  degradación observable por clase. La revisión detectó y corrigió un deadlock
  real del lock de almacenamiento. `PROD-036` completa ahora el borrado
  recuperable de proyecto y derivados, con scope previo, bloqueo de trabajo
  activo, journal reanudable y fuentes deliberadamente independientes. La
  revisión visual descubrió `PROD-123`: tres paneles describen erróneamente un
  análisis fallido como todavía activo. `PROD-040` y `PROD-062` están ahora
  completadas; `PROD-064` sigue priorizada para ensayar restore y `PROD-120`
  queda desbloqueada pero pendiente para la purga total de fuentes/copias. No se
  promete secure erase ni cifrado.

### Ronda 4 — colaboración, adopción e integración

- **Alcance revisado:** comparación, informe, contratos de hallazgos,
  navegación de proyecto, controles de autorización y vías de automatización.
- **Funcionalidades y riesgos detectados:** ya se puede corregir, subir otra
  instantánea y comparar, pero no existe línea base explícita, triage, roles,
  token de CI ni contrato de integración. Exponer integraciones sin alcance,
  rotación y auditoría elevaría el riesgo de datos y de automatización.
- **Tareas nuevas añadidas:** `PROD-065`…`PROD-072`; esta ronda ejecutada añade
  `PROD-102`…`PROD-108` para decisiones, colaboración y adopción de equipos.
- **Tareas implementadas:** `PROD-041`, `PROD-065`, `PROD-076`, `PROD-012` y
  `PROD-011`/`PROD-066` cierran el bucle local de comparación, línea base,
  roles y triage. `PROD-013` añade consulta administrativa de acciones; no se
  marca como implementado ningún token de CI, webhook o conector inexistente.
- **Pendientes y razón de prioridad:** `PROD-109` mantiene la matriz integral
  de permisos y `PROD-067`…`PROD-071` la automatización empresarial; continúan
  tras clasificación/retención y no deben adelantar la candidatura reversible.

### Ronda 5 — experiencia, entrega y preparación verificable

- **Alcance revisado:** App y paneles de proyecto, estados de carga/error/vacío,
  estilos responsive, guía visual, documentación de despliegue y comandos de
  validación reproducible.
- **Funcionalidades y riesgos detectados:** hay navegación, carga diferida,
  estados seguros, un workspace y presupuesto de bundle; falta una revisión
  visual profunda de todos los flujos, una guía de prueba real autorizada y una
  candidatura de despliegue con rollback. El tamaño de bundle llega ahora al
  límite de 322 KiB, por lo que cambios UI deben medirlo.
- **Tareas nuevas añadidas:** `PROD-073`…`PROD-077`; la revisión actual añade
  `PROD-109`…`PROD-117` para UX integral, aceptación y candidatura operativa.
- **Tareas implementadas:** `PROD-076`, `PROD-035` y `PROD-074`; se ejecutaron
  pruebas dirigidas, suites de backend/runner, build de frontend, Compose y
  comprobación de diff conforme a las evidencias existentes.
- **Pendientes y razón de prioridad:** `PROD-077` ya completó la revisión
  visual del recorrido de proyecto. `PROD-114` amplía accesibilidad de
  inteligencia/triage. `PROD-116` ya acredita una candidatura local con TLS,
  límites, smoke, recuperación y revisión visual. `PROD-117` queda completada
  con el GO acotado de fuente autorizada B. La consolidación de `PROD-129` fue autorizada
  después y quedó completada sobre `release-prep/inspectra-0.3-beta`;
  `PROD-130` exige además
  CI remoto y autorización explícita sobre `SEC-012`; no deben simularse como
  comprobaciones locales.
- **Registro previo de preparación, 2026-09-06:** la vista e informes de proyecto ya
  muestran contrato completo, inicio/fin, causa terminal y linaje de reintento;
  pasaron 271/271 pruebas frontend y build. Se creó
  `DEPLOYMENT_ACCEPTANCE.md` como borrador no ejecutado con configuración,
  salud, proyecto autorizado pendiente, privacidad, go/no-go y reversión. Esto
  no completaba entonces `PROD-116/117`; la actualización de candidatura que
  figura más abajo sustituye ese estado histórico.
- **Actualización ejecutada `PROD-113` (2026-09-06):** la inteligencia pública
  ofrece ahora estado operativo explícito, flujo OSV → corroboración GHSA →
  enriquecimiento KEV, prioridad por KEV/CVSS, cobertura progresiva, filtros
  restablecibles y detalle contraíble. La revisión visual real con API local y
  fixtures simulados pasó a 320/768/1440 px sin desbordamiento ni consola; se
  corrigió además una cuadrícula de hallazgos que ensanchaba 8 px el móvil. No
  cambia el estado de las fuentes: OSV, GHSA y CISA continúan validados solo con
  fixtures, no contra proveedores reales.
- **Actualización de aceptación fuente autorizada B (2026-09-06):** la revisión se repitió
  desde el objeto Git autorizado con egress inicialmente desactivado, tráfico
  capturado y activación explícita. OSV y CISA KEV oficiales quedaron validados;
  GHSA siguió prohibido. Se recorrieron onboarding, inventario/cobertura,
  resultados/filtros/detalle, triage, comparación, informes, persistencia,
  degradación y recuperación. La revisión a 320/768/1440 descubrió y cerró
  `PROD-128`; el navegador disponible no expuso consola, por lo que esta pasada
  no afirma una consola limpia. La limpieza integral terminó a cero. Se añaden
  `PROD-129` y `PROD-130` para el corte y la puerta remota posteriores, ambos
  bloqueados por autorizaciones que no forman parte de esta aceptación.
- **Actualización visual `PROD-020` (2026-09-06):** el panel de ciclo de datos
  muestra valores efectivos, responsabilidad de cifrado/backup, clases sin
  borrado integral y un flujo de purga con confirmación y resultado por clase.
  Se comprobó a 1440/768/390/320 px, sin desborde y con foco de 3 px. Esta
  revisión no cierra la fase profunda: siguen pendientes el borrado integral,
  restore/rollback, recorridos restantes y la prueba real autorizada.
- **Actualización de candidatura `PROD-116` (2026-09-06):** se construyeron
  cinco imágenes locales identificadas, se inició una pila privada aislada con
  TLS local, red y cuotas reproducibles, y el smoke sintético cubrió salud,
  autenticación/CSRF, análisis, privacidad, informe y cleanup sin proveedor.
  Se probó persistencia tras recreación, degradación de readiness al retirar un
  runner, auditorías de dependencias/secretos y la matriz visual 1440/768/320.
  El smoke descubrió y corrigió la cookie `SameSite=Lax`, la exposición de IDs
  de fuente en vistas de proyecto y la ausencia de cuota del proxy. La guía de
  `PROD-117` quedó preparada y posteriormente fue autorizada para `fuente autorizada A`.
  Su acta real posterior registra la ejecución y limpieza completas, pero no
  promueve la candidatura porque faltó una identidad exacta elegible para OSV.

### PROD-078 — Control verificable de cinco rondas de revisión

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo necesita saber qué se
  revisó de verdad, qué se implementó y por qué queda trabajo, en lugar de
  confundir una lista de ideas con una auditoría del producto.
- **Flujo completo afectado:** revisar arquitectura y verticales → contrastar
  evidencia de código/pruebas → registrar riesgos y tareas → sincronizar el
  backlog general → seleccionar la siguiente tarea viable.
- **Áreas o archivos implicados:** `TODO_PRODUCTO.md`, `TODO.md`, `AGENTS.md`,
  contratos de proyecto/Módulo 3, configuración, pruebas y documentación.
- **Criterios de aceptación verificables:** hay exactamente cinco rondas con
  alcance, funcionalidades/riesgos, tareas nuevas, tareas implementadas y
  pendientes justificados; los IDs/estados coinciden en ambos backlogs y las
  observaciones no afirman una capacidad ausente.
- **Riesgos de seguridad, privacidad y operación:** priorizar desde un estado
  ficticio oculta huecos de autorización, privacidad o reproducibilidad y
  desvía capacidad a pantallas aisladas.
- **Dependencias:** ninguna; no modifica `SEC-012`.
- **Tamaño:** S
- **Estrategia de pruebas:** revisión cruzada de IDs/estados, `rg` sobre
  implementaciones y ejecución de comprobaciones disponibles de documentación.
- **Evidencia de validación al completarse:** 2026-09-05: se releyeron
  `AGENTS.md`, ambos backlogs, contratos de proyecto, inventario,
  configuración/Compose, documentación y pruebas; se contrastaron las cinco
  rondas contra implementaciones y no se atribuyó egress, CVSS, KEV, cola
  durable, organizaciones ni triage a código inexistente. Se añadieron 39
  tareas `PROD-079`…`PROD-117` con flujo, aceptación, riesgos, dependencias,
  tamaño, estrategia y evidencia pendiente; la sincronización detectó 117 IDs
  en cada backlog. Las fuentes primarias OSV, GitHub, NVD y CISA quedaron
  enlazadas. `git diff --check` pasó. `SEC-012` no se modificó.

## Ciclos obligatorios de revisión de producto

### Ronda 1 — Producto y flujos de usuario (2026-09-05)

- **Alcance auditado:** alta mediante archivo, conservación de instantánea,
  ejecución inicial y repetición, lista de proyectos, estados de trabajo,
  hallazgos normalizados, inventario, comparación y exportación. Se revisaron
  `docs/product-projects.md`, contratos de `backend/app/models.py`, rutas de
  `backend/app/main.py`, persistencia y los paneles de proyecto de frontend.
- **Decisiones:** se conserva la incorporación exclusivamente por archivo
  validado y propiedad local; no se añaden rutas de host, repositorios ni
  credenciales. Una repetición sobre la misma instantánea ya es reproducible,
  pero no existe aún una progresión segura hacia una nueva instantánea del
  mismo proyecto, ni una confirmación técnica de que quien crea el proyecto
  está autorizado a analizarlo. La cancelación y reintentos durables siguen
  perteneciendo a `PROD-015`, no se duplican aquí.
- **Nuevas tareas:** `PROD-041` a `PROD-046`, detalladas al final del documento.
- **Criterio de priorización:** primero se corrigen ambigüedades de permiso y
  continuidad del flujo que pueden afectar a todos los proyectos; después la
  claridad de estados, cobertura y remediación; finalmente la automatización de
  aceptación. Cada tarea debe conservar aislamiento por propietario, no exponer
  archivo/ruta/credencial y tener prueba de API o de interfaz según corresponda.

## P0 — vertical activo

### PROD-004 — Explorador de hallazgos de proyecto

- **Prioridad:** P0
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un desarrollador necesita pasar de
  una instantánea analizada a una lista priorizada, filtrable y comprensible para
  decidir qué corregir sin abrir JSON ni recorrer informes dispersos.
- **Flujo completo afectado:** proyecto → elegir una ejecución propia completada
  → cargar hallazgos normalizados → resumen por riesgo → filtrar/buscar → abrir
  el detalle redactado y regresar conservando el contexto.
- **Áreas o archivos implicados:** `backend/app/main.py`, almacenamiento/modelos
  de ejecuciones, `frontend/src/App.tsx` o componentes extraídos, `api.ts`,
  `types.ts`, estilos, pruebas backend/frontend y guía de proyectos.
- **Criterios de aceptación verificables:** una API owner-scoped devuelve solo
  hallazgos normalizados de una ejecución de proyecto válida; la interfaz ofrece
  resumen de severidad/categoría, búsqueda, filtros combinables y detalle con
  regla, procedencia, evidencia, ubicación, recomendación y enlaces seguros.
  Incluye estados de carga, error, vacío, sin coincidencias y resultado
  truncado, URL profunda restaurable, foco y teclado; se prueba a 320, 768 y
  1440 px.
- **Riesgos de seguridad, privacidad y operativa:** una consulta sin comprobación
  de propietario expondría resultados; mostrar valores originales o URLs no
  confiables filtraría secretos o habilitaría enlaces peligrosos; un panel denso
  puede ocultar el riesgo real.
- **Dependencias:** PROD-001, PROD-002 y PROD-003 completadas.
- **Tamaño:** L
- **Evidencia de validación al completarse:** 2026-09-05: el endpoint
  owner-scoped de hallazgos exige que ejecución y proyecto coincidan y devuelve
  exclusivamente el contrato normalizado/redactado; sus pruebas cubren
  propietario cruzado, ID inválido, truncamiento y secreto redactado. La UI
  entrega selección de instantánea, resumen, búsqueda, filtros, detalle
  expandible, estados de decisión, referencias HTTPS verificadas y contexto
  restaurable por URL. Pasaron la suite Python completa, 31 archivos/216
  pruebas frontend y el build de producción. Compose respondió sano desde el
  host; la inspección con el navegador integrado quedó limitada por su bloqueo
  de loopback (`ERR_BLOCKED_BY_CLIENT`), no por el servicio.

## P1 — siguientes verticales de adopción

### PROD-005 — Comparación reproducible entre ejecuciones

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** equipos necesitan saber qué cambió
  entre dos ejecuciones del mismo proyecto para detectar regresiones y celebrar
  correcciones sin comparar informes manualmente.
- **Flujo completo afectado:** historial de proyecto → seleccionar dos
  ejecuciones compatibles → ver nuevo/resuelto/persistente y cambios de
  severidad → abrir evidencia de cada lado.
- **Áreas o archivos implicados:** contratos normalizados, API de proyectos,
  persistencia de ejecuciones, componentes de historial/comparación, informes y
  fixtures de dos instantáneas.
- **Criterios de aceptación verificables:** la comparación se limita al mismo
  proyecto y propietario, declara perfil/versión no comparable, usa IDs estables
  y no expone evidencia no retenida. Marca nuevos, resueltos y persistentes;
  pruebas cubren cambio de ruta, severidad, redacción, acceso cruzado y datos
  incompletos.
- **Riesgos de seguridad, privacidad y operativa:** comparar proyectos o
  propietarios distintos filtra datos; comparar reglas distintas como iguales
  genera falsas regresiones.
- **Dependencias:** PROD-002, PROD-003 y PROD-004 completadas.
- **Tamaño:** L
- **Evidencia de validación al completarse:** 2026-09-05: la ruta de
  comparación valida proyecto, propietario, dos IDs distintos y relación de
  ambas ejecuciones antes de leerlas; jamás entrega resultado bruto. Compara
  solo el mismo tipo/perfil completado, usando IDs estables de evidencia ya
  redactada, y devuelve nuevos/resueltos/persistentes con cambios de campos.
  La UI entrega selectores, métricas, grupos, limitaciones y acceso a ambos
  análisis. Las pruebas cubren aislamiento por propietario, ID malformado,
  perfil distinto, truncamiento, secreto redactado, cambio de severidad y ruta;
  pasaron la suite Python completa, 32 archivos/218 pruebas frontend, build y
  presupuesto de bundle.

### PROD-006 — Informe de proyecto técnico y ejecutivo

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** responsables y equipos requieren un
  artefacto compartible que explique riesgo, cobertura, límites y correcciones
  sin entregar datos brutos sensibles.
- **Flujo completo afectado:** ejecución o comparación → elegir exportación →
  generar resumen ejecutivo y detalle técnico → descargar bajo autorización.
- **Áreas o archivos implicados:** `backend/app/reporting.py`, rutas de
  exportación, redacción, UI de proyecto, nombres de archivo, pruebas de
  documentos y autorización.
- **Criterios de aceptación verificables:** Markdown y HTML/PDF describen
  instantánea, perfil, cobertura, totales, hallazgos redactados, recomendaciones
  y referencias; nunca incluyen raw JSON por defecto, secretos, rutas de host ni
  otro propietario. Las pruebas verifican contenido, error, retención y
  descarga autorizada.
- **Riesgos de seguridad, privacidad y operativa:** una exportación es una vía
  de exfiltración si evade la redacción o se nombra con datos de la fuente.
- **Dependencias:** PROD-003, PROD-004 y, para métricas de cambio, PROD-005.
- **Tamaño:** M
- **Evidencia de validación al completarse:** 2026-09-05: exportaciones de
  proyecto Markdown/HTML/PDF vuelven a validar proyecto, ejecución y
  propietario; solo se generan con una ejecución completada y contrato
  normalizado. Contienen resumen ejecutivo, severidades, snapshot/perfil,
  límites y hallazgos técnicos redactados, y usan nombres opacos sin fuente.
  La interfaz las ofrece desde el explorador. Pruebas cubren los formatos,
  autorización cruzada, pendiente, redacción, HTML escapado y retención de
  rutas; la suite Python completa, 32 archivos/219 pruebas frontend y build
  con presupuesto pasaron.

### PROD-023 — Contrato de ubicaciones seguras para resultados y exportaciones

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una persona que comparte un panel
  o informe necesita saber qué archivo relativo debe revisar, sin revelar una
  ruta de host, volumen de despliegue o dato heredado mal formado.
- **Flujo completo afectado:** analizador/adaptador → normalización → detalle de
  hallazgo → comparación → informe/exportación.
- **Áreas o archivos implicados:** normalizador, modelos y rutas de hallazgos,
  paneles de proyecto, comparación, informes, fixtures y documentación.
- **Criterios de aceptación verificables:** acepta únicamente rutas relativas
  normalizadas de proyecto; rechaza raíces Unix, Windows y UNC, traversal,
  controles y URL. El contrato expresa una ubicación retenida o suprimida sin
  filtrar el original; las pruebas cubren datos heredados, huellas estables y
  efectos en panel, comparación e informe.
- **Riesgos de seguridad, privacidad y operativa:** un analizador futuro o un
  registro histórico puede exponer topología interna o hacer que dos hallazgos
  se correlacionen de manera engañosa.
- **Dependencias:** PROD-003, PROD-004 y PROD-005 completadas.
- **Tamaño:** M
- **Evidencia de validación al completarse:** 2026-09-05: la versión
  `2026-09-05.1` restringe ubicaciones nuevas a rutas relativas portables y
  declara estado reportado, no reportado o retenido. El lector protege además
  contratos históricos antes de panel, comparación e informe. Las pruebas
  cubren rutas Unix/Windows/UNC, traversal, URL, controles, normalización,
  historial y presentación explícita sin filtrar la ruta original; pasaron
  suites completas, build y presupuesto.

### PROD-010 — Enriquecer dependencias exactas con advisories reproducibles

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo quiere distinguir una
  dependencia meramente no fijada de una versión concreta afectada por un
  advisory público, con datos que se puedan revisar posteriormente.
- **Flujo completo afectado:** manifiesto con versión exacta → resolución de
  ecosistema → consulta acotada/cacheada de advisories → hallazgo normalizado
  con OSV/CVE/GHSA y fecha de datos → detalle de corrección.
- **Áreas o archivos implicados:** parseres pasivos de dependencias,
  adaptador de advisory, caché/versionado de datos, configuración de salida de
  red, contrato de hallazgos, redacción, UI y fixtures offline.
- **Criterios de aceptación verificables:** la primera entrega soporta solo
  versiones y ecosistemas que el parser identifica sin ambigüedad; consulta en
  lote bajo allowlist, timeout, presupuesto y caché con `retrieved_at`/origen.
  Si no hay red o la respuesta es ambigua, informa cobertura degradada sin crear
  CVE. Las pruebas usan respuestas grabadas/sintéticas, cubren retirada,
  duplicado, timeout, credenciales ausentes y redacción.
- **Riesgos de seguridad, privacidad y operativa:** enviar nombres o versiones
  de paquetes revela composición del proyecto; datos cambiantes sin fecha rompen
  reproducibilidad; una respuesta externa no puede tratarse como explotación
  confirmada.
- **Dependencias:** PROD-003 completada; decidir egress seguro de PROD-008.
- **Tamaño:** L
- **Evidencia de validación al completarse:** 2026-09-05: el vertical se
  materializó sin ampliar su egress en `PROD-026`…`PROD-029`,
  `PROD-031`…`PROD-033`, `PROD-050` y `PROD-051`: OSV por identidad exacta,
  GHSA por alias retenido, KEV por CVE local, caché/versionado y degradación
  explícita, normalización de evidencia y UI/informes. Las suites usan fixtures
  y `MockTransport`; la regresión completa y Compose quedaron registradas en
  sus evidencias. Este cambio corrige el estado heredado frente a `TODO.md`.

### PROD-011 — Ciclo de vida de hallazgos y excepciones revisables

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** los equipos necesitan clasificar,
  asignar y justificar hallazgos sin borrarlos ni silenciarlos permanentemente.
- **Flujo completo afectado:** detalle → crear decisión (abierto, en revisión,
  aceptado, falso positivo, resuelto) → añadir motivo/comentario/fecha de
  revisión → reflejar estado en lista, comparación e informe.
- **Áreas o archivos implicados:** modelos de decisiones inmutables,
  autorización, API, detalle frontend, filtros, auditoría e informes.
- **Criterios de aceptación verificables:** toda excepción exige motivo,
  actor, marca temporal y caducidad opcional; una caducada vuelve a requerir
  revisión. La decisión se ata a proyecto/regla/huella y no altera resultado
  original. Se cubren transición inválida, autorización cruzada, reapertura,
  historial y contraste visual de estados.
- **Riesgos de seguridad, privacidad y operativa:** una exclusión global o sin
  caducidad puede ocultar riesgo; comentarios pueden contener secretos si no se
  aplican límites/redacción.
- **Dependencias:** PROD-004 completada y modelo de identidad de PROD-012.
- **Tamaño:** L
- **Evidencia de validación al completarse:** 2026-09-06: se añadió un
  historial append-only por organización/proyecto/huella/regla con estados
  `open`, `in_review`, `accepted`, `false_positive` y `resolved`, transición
  explícita, razón obligatoria, comentario limitado/redactado, actor, asignación
  a miembro activo y fecha futura opcional para excepciones. Una fecha vencida
  cambia el estado efectivo a revisión sin reescribir eventos; `needs_review`
  y `review_overdue` evitan confundir una revisión manual con una excepción
  caducada. El lector reconstruye y valida la cadena por enlaces, incluso si
  dos eventos tienen la misma hora, y rechaza nombre/ID, enlace, regla,
  asignación o zona horaria inconsistentes. Owner/maintainer pueden decidir y
  reader solo leer; el ID de análisis se resuelve dentro del proyecto y los
  IDs/regla/actor/organización se derivan en servidor. Lista, filtros, detalle,
  comparación y Markdown/HTML/PDF muestran el estado sin alterar el resultado;
  logs e informes excluyen el comentario libre. Se corrigieron durante la
  revisión visual un texto que confundía “en revisión” con fecha vencida y el
  evento de `datetime-local`, que antes podía perder la fecha al confirmar.
  Pasaron 1.050/1.050 pruebas backend en 23,92 s, 420/420 runner/guardas en
  6,49 s, 290/290 frontend en 20,98 s y el build TypeScript/Vite con bundle
  inicial 314,9/322 KiB; también `compileall`, Compose base/privado y
  `git diff --check`. La primera invocación frontend desde la raíz no ejecutó
  pruebas por ausencia de `package.json` y se repitió desde el directorio
  correcto; no se atribuyó al sandbox. El navegador local recorrió con datos
  sintéticos decisión, excepción con fecha, historial, filtro, comparación
  nuevo/resuelto/persistente e informe a 1440/768/390/320 px, sin desborde
  horizontal (1425/753/375/305 píxeles útiles) y con foco visible de 3 px. No
  hubo Internet, proveedor ni proyecto real.

### PROD-012 — Espacios de trabajo, organizaciones y roles mínimos

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una empresa necesita separar sus
  proyectos y permitir colaborar sin convertir al operador local actual en un
  superusuario implícito.
- **Flujo completo afectado:** administrador crea organización → invita usuario
  → asigna rol → crea/ve proyecto dentro del espacio → revoca acceso → consulta
  datos y exportaciones limitadas al espacio.
- **Áreas o archivos implicados:** modelo de identidad/propiedad, migración de
  almacén, middleware de autorización, UI de organización, configuración de
  autenticación, pruebas de aislamiento y documentación de despliegue.
- **Criterios de aceptación verificables:** se documentan roles iniciales
  (administrador, mantenedor, lector) y una matriz de permisos mínima. Todos los
  recursos de producto incluyen `organization_id`; no hay elevación por ID
  manipulable y la revocación invalida acceso posterior. Se cubren invitación,
  aislamiento entre organizaciones, CSRF/sesión y migración del modo local.
- **Riesgos de seguridad, privacidad y operativa:** un modelo multiempresa mal
  diseñado causa fuga transversal; migrar propietarios existentes sin estrategia
  puede dejar datos inaccesibles.
- **Dependencias:** revisar amenaza y compatibilidad de los modos de autenticación
  actuales; PROD-001 y PROD-002 completadas.
- **Tamaño:** L
- **Evidencia de validación al completarse:** 2026-09-06: se añadió el modo
  explícito `private_team_lightweight_users`, persistente en SQLite, con espacio
  bootstrap compatible con la frontera histórica `local-admin`, usuarios y
  membresías por organización, roles `administrator`/`maintainer`/`reader`,
  invitaciones caducables de un solo uso y cambio de espacio con rotación de
  sesión y CSRF. Los tokens de invitación se muestran una sola vez y solo se
  conserva un resumen SHA-256 con separación de dominio; contraseñas y cuentas
  desconocidas usan PBKDF2-HMAC-SHA256 con coste equivalente. La revocación o
  cambio de rol invalida sesiones y cada petición revalida la membresía. Los
  archivos, trabajos/listados y proyectos materializan `organization_id`
  junto a `owner_id` durante la compatibilidad, rechazan discrepancias y todas
  las rutas obtienen el espacio desde la sesión, nunca desde un ID de recurso
  manipulable. La suite cubre invitación/replay/caducidad, matriz de roles,
  CSRF, revocación, dos organizaciones, cambio de contexto, aislamiento de
  archivos y migración de sesiones SQLite v1. Pasaron 1.039/1.039 pruebas
  backend en 31,21 s, 420/420 de runners/guardas en 6,94 s y 286/286 frontend
  en 22,26 s; `compileall`, build TypeScript/Vite y presupuesto inicial
  314,6/322 KiB, Compose base/privado y `git diff --check` también pasaron.
  Una primera invocación backend desde `backend/` falló en siete guardas que
  leen rutas relativas a la raíz, y una primera validación privada omitió sus
  variables obligatorias; ambas se repitieron desde el contrato documentado y
  pasaron, sin atribuirlas al sandbox. La revisión visual local con datos
  sintéticos recorrió login, invitación, creación/cambio/regreso de espacio y
  estados vacíos a 1440/768/390/320 px: no hubo desborde horizontal ni avisos
  de consola y el foco de teclado conservó un contorno sólido de 3 px. El token
  y la base temporal se retiraron al terminar. No hubo Internet, proveedor,
  proyecto real, push ni PR. La bitácora empresarial, matriz exhaustiva,
  retención/borrado, recuperación/MFA/SSO y smoke multiempresa de contenedor
  permanecen correctamente separados en `PROD-013`, `PROD-109`, `PROD-062`,
  `PROD-120` y `PROD-039`; por ello este vertical está completo, pero no declara
  el modo de equipo candidato a despliegue empresarial.

### PROD-015 — Orquestación durable, límites y cancelación cooperativa

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** quienes envían varios proyectos
  necesitan una cola honesta, progreso recuperable, reintentos controlados y
  cancelación que no deje análisis ni datos ambiguos.
- **Flujo completo afectado:** encolar ejecución → reservar recursos → publicar
  fase/progreso → completar/fallar/reintentar/cancelar → limpiar espacio de
  trabajo → conservar una traza reproducible.
- **Áreas o archivos implicados:** modelo de trabajos, runner, almacenamiento,
  locks/cola, configuración de recursos, observabilidad, panel de seguimiento y
  pruebas de reinicio.
- **Criterios de aceptación verificables:** se elige una sola estrategia durable
  compatible con el despliegue actual; cada intento tiene ID, fase y causa
  pública. La cancelación es idempotente, solo del propietario autorizado y se
  confirma tras limpieza. Límites de concurrencia, tiempo, CPU/memoria/bytes y
  temporales fallan de forma recuperable; se prueban reinicio, doble solicitud,
  timeout, cancelación y agotamiento.
- **Riesgos de seguridad, privacidad y operativa:** una cola sin aislamiento
  agota host o mezcla resultados; cancelar sin confirmación puede dejar procesos
  activos o bytes de fuente.
- **Dependencias:** aislamiento de `PROD-008` completado; usa la trazabilidad
  estructurada local existente. `PROD-013` será necesario para una consola de
  auditoría empresarial, pero no bloquea la cola durable de un único proceso.
- **Tamaño:** L
- **Evidencia de validación al completarse:** 2026-09-06: la estrategia
  durable compatible con el despliegue actual conserva en disco trabajos de
  proyecto que no habían empezado. Al arrancar, revalida perfil exacto,
  propietario, proyecto, último job, snapshot retenido, linaje de reintento,
  tipo, tamaño y SHA-256 antes de reencolar; persiste contador/fecha de
  recuperación. Fuente alterada, eliminada o contrato cambiado termina
  `recovery_rejected` con mensaje cerrado; `running/cancelling` termina
  `application_restart`, nunca se finge reanudación. El apagado cancela y
  espera tareas registradas, limpia workspaces y usa `application_shutdown`.
  La UI y los informes muestran intento, contrato, tiempos, causa y
  recuperaciones sin rutas/contenido. Se probaron cola válida, integridad
  alterada, ejecución iniciada, apagado, doble solicitud, timeout,
  concurrencia, cancelación owner-scoped e idempotente y retry con nuevo ID.
  Backend pasó por grupos: 796/796 en 15,85 s y 211/211 en 0,74 s; la suite
  conjunta pasó 1.007/1.007 en 18,10 s, sin omitidas ni Internet. Runner y
  estáticas pasaron 412/412 en 5,48 s; frontend 38/38 archivos y 271/271
  pruebas en 20,07 s, build/presupuesto 311,6/322 KiB, `compileall`, Compose
  base/privado y `git diff --check`. La instalación del workspace no permite
  escribir `frontend/node_modules/.vite-temp`; por ello Vitest/Vite se ejecutó
  sobre la misma fuente sincronizada a un directorio temporal escribible. No
  se contactó proveedor ni se analizó proyecto real.

### PROD-017 — Onboarding, navegación y accesibilidad del flujo de proyecto

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una persona nueva debe entender qué
  puede analizar Inspectra, qué no ejecuta y cómo llegar de una fuente a una
  decisión en minutos, también con teclado o pantalla pequeña.
- **Flujo completo afectado:** primera visita → explicación de alcance → subir
  una instantánea → crear proyecto → seguir ejecución → explorar y exportar.
- **Áreas o archivos implicados:** arquitectura de información frontend,
  componentes de proyecto, textos, estilos, pruebas de accesibilidad y
  `docs/product-projects.md`.
- **Criterios de aceptación verificables:** cada estado muestra una siguiente
  acción clara; carga/error/vacío/no coincidencias están diferenciados; enlaces
  y títulos reflejan contexto; foco, etiquetas, contraste, regiones ARIA y
  responsive se verifican con pruebas y revisión a 320/768/1440 px. Ningún texto
  promete detectar explotación ni análisis de código ejecutado.
- **Riesgos de seguridad, privacidad y operativa:** un flujo ambiguo lleva a
  subir fuentes no autorizadas o interpretar indicadores como vulnerabilidades;
  una UI inaccesible excluye usuarios y ralentiza triage.
- **Dependencias:** PROD-004 completada para usar el explorador real.
- **Tamaño:** M
- **Evidencia de validación al completarse:** 2026-09-05: se añadió la guía
  `Analyze an authorized source snapshot` antes de las métricas, con CTA que
  selecciona Archive y lleva el foco al selector de archivo, pasos explícitos y
  límites de privacidad/ejecución. El flujo real con el fixture sintético
  `tests/fixtures/demo/passive-alpha/archives/demo-archive-app-config.zip`
  verificó carga → confirmación de autorización → creación/análisis → espacio de
  trabajo, hallazgos, inventario e inteligencia pública con egress desactivado;
  la consola no informó avisos ni errores. La revisión visual a 320/768/1440 px
  no mostró desbordamiento horizontal de página. Durante la revisión se
  corrigieron el selector nativo de archivos, los filtros compactos y la regla
  CSS que anulaba el atributo `hidden` de auditorías avanzadas. En una copia
  temporal pasaron `vitest --run` (36 archivos/243 pruebas), build TypeScript/
  Vite y presupuesto 316,4/322 KiB; `docker compose config -q`, la variante
  privada con fixtures y `git diff --check` pasaron.

## P2 — ampliaciones controladas y empresariales

### PROD-007 — Repositorios de solo lectura con diseño de amenaza previo

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** los equipos quieren analizar un
  repositorio autorizado sin descargar manualmente, manteniendo el mismo modelo
  de instantánea trazable.
- **Flujo completo afectado:** autorizar proveedor/repo → emitir credencial de
  mínimo privilegio → checkout aislado y sin hooks → crear archivo/snapshot
  inmutable → analizar → borrar workspace y revocar token.
- **Áreas o archivos implicados:** adaptador de proveedor, secret manager,
  política de URL/egress, sandbox de checkout, configuración, UI y runbook.
- **Criterios de aceptación verificables:** antes de código existe amenaza
  aprobada con proveedor inicial, allowlist, scopes, renovación/revocación,
  tamaño/tiempo/submódulos/hooks, auditoría y borrado. La implementación no
  acepta URL arbitraria, usa token efímero/cifrado externo y genera exactamente
  la instantánea que consumen los flujos de PROD-001/002. Fixtures cubren host,
  token, límite, limpieza y error de proveedor.
- **Riesgos de seguridad, privacidad y operativa:** SSRF, ejecución de hooks,
  fuga de token o checkout persistente de código de clientes.
- **Dependencias:** PROD-008, PROD-012 y decisión de amenaza explícita.
- **Tamaño:** L
- **Evidencia de validación al completarse:** 2026-09-11: el vertical adopta
  Git local, no un clone de proveedor. La CLI usa exclusivamente blobs del
  commit exacto, sin fetch/hooks/submódulos/symlinks/worktree; aplica límites y
  preflight Gitleaks, genera TAR reproducible privado y borra el temporal. El
  endpoint inicial es cerrado y no admite URL, host, path, token Git ni campos
  extra; persiste `git_cli`, commit, rama normalizada y digest. El bootstrap
  privado usa un grant de organización hash-only, 15 minutos, máximo tres
  activos, uso único y una sola ruta, consumido antes de retener bytes. La UI
  administrativa muestra el valor una vez, lo retira del DOM y entrega una
  orden sin secreto. Pasaron backend dirigido 5/5, CLI 66/66, frontend 423/423
  con axe, build 303,6/322 KiB, `compileall`, Compose local/privado, backlog y
  diff-check; revisión desktop/móvil sin overflow de página (1265/1265 y
  375/375). Backend recolectó 1.616 casos y las 1.615 pruebas restantes pasaron;
  el único benchmark de tendencias falla también aislado (0,302 s > 0,250 s),
  fuera del diff, y queda trazado en `PROD-250`. Sin red, proveedor remoto,
  proyecto externo, push, PR, tag ni despliegue.

### PROD-008 — Aislamiento y cuotas por ejecución

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** operadores necesitan saber que un
  archivo grande o malicioso no degrada otros análisis ni conserva bytes fuera de
  la retención esperada.
- **Flujo completo afectado:** recibir fuente → validar antes/durante análisis →
  crear workspace por ejecución → aplicar cuotas → limpiar siempre → registrar
  evento sin contenido sensible.
- **Áreas o archivos implicados:** configuración, runner, filesystem temporal,
  almacenamiento, logs/métricas, Compose/despliegue y pruebas de concurrencia.
- **Criterios de aceptación verificables:** límites configurables para archivo,
  expansión, entradas, bytes, tiempo, concurrencia y disco temporal; el
  workspace se identifica por ejecución/organización y se limpia en éxito,
  error, reinicio y cancelación. Los fallos son públicos y accionables, sin
  ruta de host ni secreto. Se prueban cuota, crash y aislamiento cruzado.
- **Riesgos de seguridad, privacidad y operativa:** DoS, contaminación entre
  proyectos, residuo de código y logs que exponen rutas.
- **Dependencias:** PROD-001 y PROD-002 completadas; coordina con PROD-015.
- **Tamaño:** L
- **Evidencia de validación al completarse:** 2026-09-06: el contrato
  `2026-09-06.1` captura carga, timeout, concurrencia, workspace, expansión,
  entradas, manifiestos y lockfiles sin configuración sensible. Cada fuente se
  copia a un workspace opaco, se verifica por tamaño/SHA-256 y se elimina en
  éxito, fallo, cancelación o reinicio; el runner rechaza límites distintos.
  Compose fija CPU, memoria, PID, filesystem de solo lectura y tmpfs para
  backend/runner. Estados `cancelling/cancelled`, causa terminal, tiempos y
  `retry_of_job_id` son owner/project-scoped y visibles en UI/informe con
  mensajes cerrados. Las rutas HTTP se registran por plantilla y los errores no
  conservan detalles de excepción. Pasaron 997/997 backend (15,7 s), 412/412
  runner/estáticas (5,8 s), 271/271 frontend (20,15 s), build/presupuesto
  311,6/322 KiB, `compileall`, Compose base/privado y `git diff --check`. La
  detención previa se aisló a una expectativa de contrato obsoleta; cinco
  regresiones deterministas posteriores se reprodujeron y corrigieron. Vite no
  pudo escribir en `node_modules/.vite-temp` del workspace (`EACCES`), por lo
  que se usó la misma fuente en el entorno temporal escribible. No hubo
  Internet ni proyecto real. El montaje completo de `data/` en solo lectura
  sigue siendo una frontera de proceso y queda en `PROD-122`.

### PROD-013 — Auditoría de acciones de producto y configuración sensible

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** administradores necesitan explicar
  quién accedió, exportó, cambió una decisión o configuró una integración sin
  registrar el contenido sensible.
- **Flujo completo afectado:** acción sensible → evento estructurado → consulta
  filtrada por organización → retención/expurgo → investigación autorizada.
- **Áreas o archivos implicados:** observabilidad existente, modelo de eventos,
  middleware, UI/endpoint de auditoría, configuración de retención y runbook.
- **Criterios de aceptación verificables:** registra actor, organización,
  recurso opaco, acción, resultado, correlación y hora; nunca tokens, evidencia,
  URL privada ni cuerpo. La lectura es role-gated, paginada y con retención
  documentada; pruebas verifican redacción, integridad de orden y acceso.
- **Riesgos de seguridad, privacidad y operativa:** sin trazabilidad no se puede
  investigar abuso; un log demasiado rico se transforma en fuga de datos.
- **Dependencias:** PROD-012 para roles/organizaciones; coordina con PROD-015.
- **Tamaño:** M
- **Evidencia de validación al completarse:** 2026-09-06: el contrato
  `2026-09-06.1` persiste eventos mínimos en archivos `0600`, separados por
  organización, con actor/rol, recurso opaco, resultado, correlación y UTC. Una
  allowlist elimina nombres, cuerpos, código, evidencia, rutas, URL, paquetes,
  hashes, cookies, tokens y credenciales; la retención de 90 días y el tope de
  50.000 son configurables y acotados. La lectura deriva la organización de la
  sesión, es paginada/filtrable y solo administrativa; registra también accesos
  denegados. Se cubren sesión, equipo, proyecto, análisis, inteligencia,
  baseline, triage, informes y borrado de fuente. El expurgo no sigue symlinks
  y una escritura fallida no rompe la acción primaria ni registra su contexto.
  Pasaron 1.058/1.058 pruebas backend (22,79 s; 86.824 KiB), 420/420
  runner/guardas (6,01 s; 67.920 KiB), 42 archivos/292 pruebas frontend
  (20,67 s; 581.580 KiB), build/presupuesto 315,4/322 KiB (7,92 s),
  `compileall`, Compose base/privado y diff. La primera suite backend aisló un
  `fsync` real dentro de un umbral no determinista de 10 ms en la prueba de
  timeout; se fijó el almacenamiento sano en ese caso y la regresión final
  pasó. Tres invocaciones frontend desde la raíz no llegaron a ejecutar por
  ausencia de `package.json`; se repitieron desde la copia escribible correcta.
  La revisión local sintética comprobó administración, filtro, vacío y foco de
  3 px a 1440/768/390/320, sin desborde (1425/753/375/305 px). No se afirmó
  consola limpia porque esa capacidad no estaba disponible. Sin Internet,
  proveedor, proyecto real, push ni PR.

### PROD-014 — Reglas de secretos e indicadores de configuración en proyectos

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un desarrollador quiere descubrir
  posibles secretos y configuraciones inseguras dentro de una instantánea, con
  evidencia suficiente para corregir sin que Inspectra persista la credencial.
- **Flujo completo afectado:** lectura pasiva acotada de archivo elegible →
  coincidencia de regla → redacción/huella → hallazgo con ruta/línea → detalle y
  remediación.
- **Áreas o archivos implicados:** lector seguro de archivos de archive, reglas
  versionadas, redactor, contrato de hallazgos, perfiles, UI y fixtures seguros.
- **Criterios de aceptación verificables:** analiza solo texto y rutas dentro de
  los límites de PROD-008; no extrae ni ejecuta. Cada regla declara precisión,
  severidad/confianza y redacción; la evidencia muestra contexto redactado y
  ruta/línea cuando se puede demostrar. Fixtures incluyen positivos sintéticos,
  falsos positivos esperables, binarios, límite, duplicado y ausencia de secreto
  en resultado/log/exportación.
- **Riesgos de seguridad, privacidad y operativa:** el detector puede almacenar
  o mostrar un secreto, generar ruido que erosiona confianza o consumir recursos
  sin límite.
- **Dependencias:** PROD-003, PROD-008 y perfil versionado de PROD-009.
- **Tamaño:** L
- **Evidencia de validación al completarse:** 2026-09-09: ruleset
  `2026-09-09.1` integra el detector pasivo existente de datos sensibles en el
  mismo worker aislado de `project_archive_basic`. Reabre únicamente el archivo
  temporal acotado, considera hasta 100 candidatos UTF-8, 512 KiB por archivo y
  2 MiB total; `.env` reales se registran sin leerse. El resultado conserva
  estado/cobertura agregados, hallazgos deduplicados, confianza, ruta relativa y
  línea, con valores/URLs/tokens/claves redactados; rutas hostiles se retienen
  como cobertura omitida. Se corrigió además la normalización transversal, que
  no reconocía `file_path` y perdía la localización segura en detalle,
  comparación e informes. En Docker Python 3.12, repositorio solo lectura y sin
  red, pasaron 64 pruebas backend de contrato/API/normalización, 17 del flujo de
  proyecto, 6 del detector (positivos, placeholders, claves, URLs, binarios,
  límites y rutas hostiles) y 6 de informes/exportación. Frontend 6/6, incluida
  localización/confianza y `axe` del preflight; TypeScript/build y bundle
  293,1/322 KiB; `compileall` y `git diff --check`. Las dos primeras pasadas
  detectaron expectativas obsoletas por la nueva familia de reglas y una
  aserción de texto no única; se corrigieron y repitieron. No hubo Internet,
  ejecución de proyecto ni proveedores.

### PROD-016 — Infraestructura, contenedores y configuración dentro del proyecto

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** equipos con IaC y contenedores
  quieren recibir señales de configuración relevantes desde el mismo proyecto,
  no lanzar revisiones manuales por cada archivo.
- **Flujo completo afectado:** detectar archivos soportados en instantánea →
  parsear pasivamente con límites → ejecutar reglas de configuración → normalizar
  y presentar cobertura/no soportado.
- **Áreas o archivos implicados:** catálogo de analizadores pasivos existentes,
  lector de archive, perfiles, runner, normalizador, resultado frontend y
  fixtures Docker/Compose/Kubernetes/Terraform.
- **Criterios de aceptación verificables:** cada formato se habilita por fases y
  reutiliza el analizador existente solo si no requiere ejecución, red ni rutas
  de host. El resultado identifica archivo, regla, cobertura y truncamiento;
  parseos fallidos no detienen el proyecto. Pruebas cubren entradas maliciosas,
  configuraciones sintéticas, mezclas de stack y redacción.
- **Riesgos de seguridad, privacidad y operativa:** tratar un archivo como
  confiable, ampliar parseres sin cuotas o no expresar cobertura parcial puede
  producir falsa seguridad.
- **Dependencias:** PROD-008, PROD-009 y PROD-003.
- **Tamaño:** L
- **Evidencia de validación al completarse:** 2026-09-09: ruleset
  `2026-09-09.2` integra como subrevisiones independientes los analizadores
  pasivos existentes de Dockerfile, Compose, Kubernetes y
  Terraform/OpenTofu/Terragrunt en `project_archive_basic`. Cada uno conserva
  estado completo/parcial, contadores primitivos, errores controlados y límites
  de 100 archivos, 512 KiB/archivo y 2 MiB total; los hallazgos llevan categoría
  normalizada y evidencia/ruta redactada. No se construyen imágenes, arrancan
  servicios, renderizan plantillas, consultan clústeres, resuelven módulos o
  ejecutan planes. Un error parcial no borra las demás revisiones y el límite
  global del worker sigue siendo autoritativo. La prueba integrada cubre los
  cuatro formatos y se suman regresiones de entradas maliciosas, límites y
  redacción. En contenedor Python 3.12 sin red y fuente solo lectura pasaron
  23/23 pruebas runner de los cuatro analizadores/vertical integrado y 11/11
  backend de perfil/preflight; frontend 6/6, build y bundle 293,1/322 KiB. La
  primera pasada descubrió que redactor no era idempotente (`[REDACTED]]`); se
  corrigió y todo el grupo se repitió. `compileall` y diff-check pasan. Sin
  proyecto real, Internet, proveedores ni ejecución de código analizado.

### PROD-018 — SBOM y revisión de licencias declaradas

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** compras, legal y seguridad necesitan
  inventario exportable de componentes declarados y señales de licencia sin
  confundirlo con una verificación legal completa.
- **Flujo completo afectado:** manifiesto soportado → inventario normalizado →
  SBOM exportable → política de licencia opcional → informe con límites.
- **Áreas o archivos implicados:** parseres de manifest, SBOM existente,
  normalización de paquetes, exportaciones, perfil/UI y documentación legal.
- **Criterios de aceptación verificables:** conserva origen/versión declarada y
  ecosistema; CycloneDX y SPDX no incluyen secretos ni paths de host. Las reglas
  de licencia distinguen desconocida, declarada y no permitida, sin dictamen
  jurídico. Pruebas validan esquema, duplicados, información incompleta y acceso
  de propietario.
- **Riesgos de seguridad, privacidad y operativa:** un SBOM incompleto tratado
  como inventario total o una licencia inferida como certeza legal daña decisiones.
- **Dependencias:** PROD-003, PROD-006 y soporte de ecosistema de PROD-009.
- **Tamaño:** M
- **Evidencia de validación al completarse:** completada 2026-09-09. El runner
  conserva únicamente declaraciones raíz de un catálogo SPDX cerrado en
  `package.json`/`pyproject.toml`; texto libre, credenciales o valores ambiguos
  quedan como `unknown_unrecognized_withheld`. El backend aplica una política
  opcional de hasta 64 identificadores exactos, capturada de forma inmutable en
  el perfil de ejecución, y distingue `declared`, `unknown` y `not_permitted`
  sin inferir licencias de dependencias ni emitir conclusiones jurídicas.
  CycloneDX/SPDX preservan la declaración raíz soportada, marcan licencias de
  dependencias como desconocidas, retienen procedencia/versión/ecosistema y
  deduplican solo declaraciones idénticas del mismo manifiesto. La UI muestra
  contrato, estado, expresión segura y límites. Pasaron 28 pruebas backend de
  perfiles/licencias/SBOM/acceso de propietario, 27 pruebas de runner de
  manifiestos/proyecto en contenedor sin red y raíz de solo lectura, y 7 pruebas
  frontend; `tsc`, build Vite, presupuesto inicial 293,1/322 KiB,
  `compileall`, `docker compose config -q` y `git diff --check`. Las primeras
  pasadas detectaron y corrigieron el catálogo tipado incompleto, la diferencia
  tupla/lista al verificar persistencia, la precedencia SPDX incompatible y
  `replaceAll` fuera del target TS. No se ejecutó código analizado ni hubo red.

### PROD-019 — Integraciones de CI y salidas interoperables

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo debe poder incorporar
  resultados de Inspectra en su proceso sin conceder acceso amplio ni descargar
  datos manualmente.
- **Flujo completo afectado:** CI prepara una instantánea → autenticación de
  alcance mínimo → subida/ejecución → espera o consulta limitada → salida
  versionada/SARIF o webhook firmado → revocación.
- **Áreas o archivos implicados:** API de automatización, tokens de servicio,
  límites, exportadores, firma de webhooks, documentación CI y pruebas de
  integración.
- **Criterios de aceptación verificables:** el primer adaptador usa token de
  proyecto/organización revocable con caducidad y scopes; no recibe secretos en
  argumentos/logs. Salida expresa versión, cobertura y enlaces no sensibles;
  reintentos/webhooks son idempotentes y firmados. Se prueban scope insuficiente,
  replay, timeout, token revocado y payload redactado.
- **Riesgos de seguridad, privacidad y operativa:** tokens CI sobredimensionados,
  webhooks falsificados y resultados que bloquean pipelines sin criterio claro.
- **Dependencias:** PROD-012, PROD-015 y PROD-006.
- **Tamaño:** L
- **Evidencia de validación al completarse:** reconciliada 2026-09-09 con
  `PROD-131`–`PROD-136`, `PROD-155` y `PROD-157`: snapshot Git por objetos,
  preflight obligatorio, cliente limitado, token hashed/project-scoped con
  caducidad/revocación/rate limit, admisión commit+digest idempotente, policy
  reproducible y JSON/Markdown/SARIF acotados. La entrega webhook no forma
  parte del primer adaptador y permanece separada en `PROD-071`. En esta
  reconciliación pasaron 29 pruebas CLI funcionales en Python 3.12/Git y 30
  pruebas backend dirigidas dentro de contenedores `--network none`; la
  conformidad SARIF oficial sigue respaldada por `PROD-155`.

### PROD-020 — Privacidad, residencia, retención y despliegue empresarial

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una empresa necesita configurar qué
  datos guarda Inspectra, cuánto tiempo y cómo opera el producto en un entorno
  propio de forma auditable.
- **Flujo completo afectado:** administrador define política → fuentes,
  resultados, exportaciones, caches y logs adoptan la política → expurgo seguro
  → evidencia operativa y recuperación.
- **Áreas o archivos implicados:** Settings, FileStore/JobStore, caches,
  despliegue privado, documentación, auditoría y pruebas de retención.
- **Criterios de aceptación verificables:** políticas separan fuente, resultado,
  exportación, cache de advisories y auditoría; valores seguros están documentados
  y el expurgo es verificable. Configuración muestra impacto sin revelar datos;
  backups/cifrado en reposo/gestión de claves se documentan según la plataforma
  elegida, sin afirmaciones que el stack no implemente. Se prueban expiración y
  recuperación de fallo.
- **Riesgos de seguridad, privacidad y operativa:** guardar código o resultados
  más tiempo del autorizado, borrar evidencia prematuramente o prometer cifrado
  inexistente.
- **Dependencias:** PROD-008, PROD-012 y PROD-013.
- **Tamaño:** L
- **Evidencia de validación al completarse:** 2026-09-06: el contrato
  `2026-09-06.1` separa fuente, resultado, snapshot normalizado, caché pública,
  exportación bajo demanda, metadato de proyecto, triage, workspace y actividad.
  `GET /privacy/retention` no expone hechos de almacenamiento; el panel muestra
  valores, límites de cifrado/backup y acceso por rol. La purga manual no acepta
  selectores, deriva la organización de sesión, protege trabajos activos,
  elimina snapshots antes del resultado y devuelve éxito parcial por clase sin
  mensajes de excepción. La caché compartida solo elimina documentos públicos
  con clave digest vencidos/inválidos; no selecciona snapshots de 32 caracteres.
  Un bloqueo real apareció al actualizar proyectos dentro del lock de storage:
  se reprodujo durante 69,51 s, se interrumpió y se corrigió ejecutando derivados
  fuera del lock con revalidación previa al borrado. Pasaron 1.063/1.063 backend
  (21,11 s, 86.072 KiB RSS), 420/420 runner/guardas (5,99 s, 67.492 KiB), 43
  archivos/295 frontend (20,30 s, 593.348 KiB), build y presupuesto 315,9/322
  KiB (7,57 s), `compileall`, Compose base/privado y diff. La primera regresión
  frontend falló en una expectativa obsoleta de cinco llamadas tras añadir el
  sexto endpoint inicial; se actualizó el mock y la repetición completa pasó.
  La revisión visual local sintética validó política, confirmación y resultado
  de purga a 1440/768/390/320 px sin desborde, foco sólido de 3 px y captura
  móvil. No se usaron Internet, proveedores ni proyectos reales. Continúan como
  límites explícitos la ausencia de scheduler, borrado integral de proyecto,
  cifrado aplicativo y control de backups externos.

## P3 — capacidad posterior, no bloqueante

### PROD-009 — Perfiles pasivos por stack y reglas de calidad técnica

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** cada equipo quiere una cobertura
  explícita y útil para su stack, sin un escaneo opaco o que ejecute su código.
- **Flujo completo afectado:** detectar stack → elegir/recomendar perfil →
  mostrar reglas y exclusiones → ejecutar pasivamente → registrar versión y
  cobertura.
- **Áreas o archivos implicados:** catálogo de reglas, detección de manifest,
  configuración de proyecto, runner, UI y fixtures por stack.
- **Criterios de aceptación verificables:** cada perfil declara versiones,
  reglas, límites y exclusiones; la opción segura por defecto no ejecuta código
  ni habilita red. El perfil queda persistido por ejecución y las pruebas cubren
  desconocido, incompatibilidad y compatibilidad con informe/comparación.
- **Riesgos de seguridad, privacidad y operativa:** cobertura ambigua, perfiles
  que habilitan análisis inesperado o comparaciones inválidas entre versiones.
- **Dependencias:** PROD-003 y PROD-008 completadas; desbloquea PROD-014 y PROD-016.
- **Tamaño:** M
- **Evidencia de validación al completarse:** 2026-09-09: el backend declara
  mediante el catálogo cerrado `2026-09-09.1` el perfil seguro
  `project_archive_basic`; no acepta perfiles aportados por cliente. El perfil
  conserva la selección manifiesto-driven de npm/PyPI/Go/Rust/PHP/JVM/.NET/multistack, seis
  familias de reglas, exclusiones explícitas, `network_access=disabled` y
  `passive_no_project_execution`. El preflight sin fuente expone también el
  contrato efectivo de límites; las ejecuciones conservan nombre, ruleset y
  límites inmutables, y la comparación exacta ya falla cerrada al divergir.
  Frontend explica perfil, versión, reglas y fuera de alcance antes de cargar.
  Pasaron 10 pruebas backend dirigidas dentro del runtime Python 3.12 sin red y
  con el repositorio de solo lectura (catálogo desconocido, persistencia,
  compatibilidad e API) y 17/17 del runner para detección/límites por stack. La
  auditoría cruzada corrigió un preflight obsoleto que omitía
  Cargo/Composer/Gradle/NuGet y clasificaba Yarn simultáneamente como resuelto y
  no resuelto. Pasaron 3/3 de la vista con `axe`, build y presupuesto inicial
  293,1/322 KiB, más `git diff --check`. No hubo ejecución de proyectos, red ni
  consultas a proveedores.

### PROD-021 — Asignación, comentarios y colaboración contextual

- **Prioridad:** P3
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** tras un triage consistente, los
  equipos pueden repartir correcciones y conservar contexto sin trasladar datos
  sensibles a herramientas no controladas.
- **Flujo completo afectado:** hallazgo abierto → asignar miembro → comentar con
  mención limitada → ver actividad → completar/reabrir decisión.
- **Áreas o archivos implicados:** identidad, ciclo de vida, modelo de comentarios,
  notificaciones internas, detalle de hallazgo y auditoría.
- **Criterios de aceptación verificables:** solo miembros del espacio pueden
  asignar/comentar; comentarios tienen límites, redacción y borrado/auditoría
  coherente. La UI no muestra PII innecesaria y pruebas cubren permiso, mención,
  paginación y contenido sensible.
- **Riesgos de seguridad, privacidad y operativa:** comentarios se convierten en
  canal de secretos/PII o facilitan acceso cruzado.
- **Dependencias:** PROD-011, PROD-012 y PROD-013.
- **Tamaño:** M
- **Evidencia de validación al completarse:** 2026-09-11: el contrato append-only
  `2026-09-11.1` conserva compatibilidad de lectura con el legado y añade hasta
  cinco menciones exactas, únicas y resueltas únicamente contra miembros activos
  del workspace; emails, usuarios desconocidos/inactivos y metadata discrepante
  fallan cerrados. El resultado de hallazgos embebe diez eventos y la ruta
  owner/project/finding-scoped pagina 1–25 con cursor revalidado, `no-store` y
  auditoría content-free; la UI carga más actividad sin perder lo ya mostrado y
  el selector accesible inserta solo miembros conocidos. Pruebas cubren secreto
  sintético redactado, cursor ajeno/desconocido, dos organizaciones, cinco
  menciones, fallo recuperable y `axe`: 3 backend dirigidas, 61 frontend
  dirigidas, frontend completo 424/424, CLI 66/66, TypeScript/Vite y bundle
  inicial 303,8/322 KiB. La suite backend ejecutó 1.617 casos: 1.616 pasaron y
  falló únicamente el gate preexistente de latencia del reloj owner-scoped
  (p95 63,1 ms frente a 50 ms), reproducido aislado 10/10 y registrado como
  `PROD-251`; no se presenta la puerta general como verde. Sin red, notificación
  externa, proyecto real ni cambio de CI.

### PROD-022 — Métricas de tendencia y objetivos de riesgo

- **Prioridad:** P3
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** dirección técnica necesita ver si el
  riesgo mejora o empeora sin usar los contadores como una promesa de seguridad.
- **Flujo completo afectado:** historial comparable → agregación por proyecto y
  periodo → panel de tendencia → exportación con cobertura y limitaciones.
- **Áreas o archivos implicados:** comparación, agregaciones owner/org scoped,
  dashboard, informes, performance y pruebas de datos.
- **Criterios de aceptación verificables:** muestra nuevos/resueltos/persistentes
  y distribución por severidad solo cuando perfiles/coverage son comparables;
  aclara huecos y no mezcla organizaciones. Consultas paginadas/coste acotado y
  pruebas cubren datos vacíos, series incompletas y autorización.
- **Riesgos de seguridad, privacidad y operativa:** métricas que mezclan fuentes
  o cobertura generan incentivos y decisiones erróneas; agregación cara degrada
  el producto.
- **Dependencias:** PROD-005, PROD-006 y PROD-012.
- **Tamaño:** M
- **Evidencia de validación al completarse:** reconciliada 2026-09-11. La
  auditoría trazó cada criterio a `PROD-105/147/219/242/248/250/251`: series de
  nuevos/resueltos/persistentes solo entre ejecuciones comparables; cambios de
  perfil/cobertura y PVI no disponible quedan excluidos; periodos 30/90/180 y
  buckets 7/30 son cerrados; los tres perfiles consumen el mismo hecho, declaran
  denominadores/limitaciones y permiten abrir proyecto; export JSON/CSV solo
  desde estado current y con confirmación. El índice owner-scoped limita 5.000
  proyectos/250.000 análisis, reconstruye fuera de la petición y conserva
  current/stale/unavailable sin mezclar organizaciones. Diez pruebas backend de
  tendencias cubren vacío, huecos, otro owner, alteración, reinicio, error,
  refresh y 100.000 análisis; cuatro frontend cubren perfiles, error, export,
  stale y `axe`. En el corte pasan backend 1.617/1.617, frontend 424/424, build y
  gates de rendimiento. «Objetivo» significa aquí dirección de reducción
  verificable y priorización actual; no se inventa score ni SLA configurable, y
  las duraciones siguen etiquetadas explícitamente como mediciones.

## Auditoría de producto y correspondencia de módulos — 2026-09-05

### Correspondencia explícita

El repositorio no tenía una nomenclatura previa y estable de “módulos de
producto”. Para no reescribir su historia se adopta esta correspondencia:

| Módulo | Alcance real | Estado actual |
| --- | --- | --- |
| **Módulo 1 — Base segura de auditoría** | autenticación local/autohospedada, propiedad por operador, carga validada, redacción, trabajos pasivos y límites | reforzado; sus tareas internas históricas siguen en `TODO.md` |
| **Módulo 2 — Proyectos y resultados** | archivo de proyecto → ejecución pasiva → hallazgos normalizados → exploración → comparación → informe | vertical base utilizable: `PROD-001` a `PROD-006`, `PROD-017` y `PROD-023` están completos; quedan la evolución de ejecución y colaboración |
| **Módulo 3 — Inteligencia de vulnerabilidades públicas** | inventario de componentes → correlación versionada de avisos públicos → priorización/triage → comparación e informe | OSV opt-in por versión exacta, GHSA por alias retenido, KEV por CVE exacto, CVSS v3 trazable, frescura recuperable, conflictos, cuatro resultados por componente y alcance directo/transitivo/opcional (`PROD-026`…`PROD-033`, `PROD-048`, `PROD-050`…`PROD-051`) están completos. `PROD-030` completa su exploración segura de extremo a extremo; siguen pendientes solo extensiones de cobertura y operación explícitamente delimitadas. |

### Hechos confirmados y límites de la auditoría

- El flujo de Módulo 2 conserva una instantánea SHA-256, aísla lecturas por
  propietario y entrega solo resultados normalizados y redactados. Las rutas,
  comparaciones e informes revalidan proyecto, ejecución y propietario.
- `project_archive_basic` analiza pasivamente `package.json`,
  `requirements.txt` y `pyproject.toml` dentro de ZIP/TAR; no ejecuta código ni
  instala paquetes y aplica límites. `PROD-024` añade inventario versionado,
  persistido y owner-scoped desde ese mismo parse; el SBOM CycloneDX/SPDX sigue
  siendo una exportación separada.
- El inventario conserva requisitos declarados y, para `package-lock.json` npm
  v2/v3 emparejado de forma segura, resoluciones exactas directas, transitivas y
  opcionales cuando el lockfile las declara. No existe aún cobertura general de
  otros ecosistemas/lockfiles; un rango sin resolución exacta no se convierte
  honestamente en un componente vulnerable.
- El contrato de inteligencia conserva fuente OSV, rango afectado/corregido,
  proveedor, consulta/caducidad, CVE/GHSA, vector y score CVSS v3 derivado;
  GHSA ya puede corroborar un alias retenido sin transmitir el componente; KEV
  usa solo CVE exactos retenidos y la deduplicación conserva conflictos o
  retirada sin fusionar evidencia. La consulta continúa deshabilitada por
  defecto y nunca es parte de la suite.
- La orquestación es local/en proceso: no hay cola durable ni cancelación
  cooperativa. `PROD-015` ya cubre esta deuda; el producto no debe simular
  progreso exacto o cancelación hasta implementarla.
- El frontend de resultados tiene selección de análisis, filtros, detalle,
  estados y exportación. `PROD-017`, `PROD-024`, `PROD-035` y `PROD-030` hacen
  visible el onboarding, la cobertura de componentes, la cobertura transversal
  de ejecución y la exploración segura de dependencias.
- La base sigue siendo de un propietario y no hay organizaciones/roles;
  `PROD-012` es prerrequisito de colaboración empresarial. Repositorios,
  credenciales y red quedan correctamente fuera del flujo actual (`PROD-007`).
- Validación puntual del 2026-09-05: `npm audit --package-lock-only --omit=dev`
  no informó vulnerabilidades de producción; `pip-audit` no informó vulnerabilidades
  conocidas para los lockfiles de backend ni tools. Es una fotografía, no una
  garantía ni una evaluación de los proyectos analizados.

### Fuentes de diseño del Módulo 3

- [OSV API](https://google.github.io/osv.dev/api/) admite consultas por paquete,
  ecosistema y versión, y consultas por lote. Sus datos deberán persistirse con
  hora, proveedor y respuesta normalizada, no tratarse como verdad eterna.
- La [API de advisories globales de GitHub](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28)
  expone ecosistema, paquete/rango vulnerable, primera versión corregida,
  identificadores y CVSS; documenta paginación y respuestas 429 que el adaptador
  debe manejar.
- La [base de advisories de GitHub](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/github-advisory-database?learn=security_advisories&learnProduct=code-security)
  documenta severidades CVSS y rangos/versiones corregidas. Una ficha de proveedor
  o NVD se conserva como fuente adicional, no se sustituye por un changelog.
- El [catálogo CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  es una señal de explotación conocida independiente de CVSS. No se debe inferir
  para un CVE sin coincidencia exacta.

## Módulo 3 y cierre profesional del Módulo 2

Estas tarjetas desglosaron el vertical `PROD-010`, ya completado, en entregas
verificables. La suite principal sigue siendo determinista: las respuestas de
red se ejercitan solo mediante adaptadores y fixtures grabados/revisados.

### PROD-024 — Inventario normalizado y versionado de componentes por ejecución

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un desarrollador necesita saber qué
  componentes declarados encontró Inspectra, en qué manifiesto y con qué grado
  de certeza antes de afirmar que una vulnerabilidad pública le afecta.
- **Flujo completo afectado:** archivo propio → análisis pasivo → extracción de
  componente seguro → persistencia junto a ejecución → consulta owner-scoped →
  resumen de cobertura en vista de proyecto.
- **Áreas o archivos implicados:** `backend/app/sbom.py` o contrato de inventario,
  almacenamiento/modelos/rutas de proyecto, componente frontend, tipos/API,
  pruebas y `docs/product-projects.md`.
- **Criterios de aceptación verificables:** cada ejecución compatible persiste
  versión de contrato y componentes deduplicados por manifiesto/grupo/nombre,
  con ecosistema, nombre normalizado, requisito declarado, tipo de fuente,
  versión exacta solo si se puede demostrar y ruta relativa segura; marca requisitos
  ambiguos, no-registry y cobertura truncada. Una API solo entrega inventario
  del proyecto/propietario actual y nunca bytes, rutas absolutas, URLs con
  credenciales ni secretos. La interfaz muestra total, cobertura y estados
  vacío/error/carga. Fixtures cubren npm, PyPI, duplicados, rutas inseguras,
  requisitos no exactos y acceso cruzado.
- **Riesgos de seguridad, privacidad y operación:** declarar resuelta una versión
  que solo fue declarada crea falsos positivos; requisito VCS/URL o ruta puede
  revelar infraestructura/credenciales; una API sin ownership expone composición.
- **Dependencias:** `PROD-001`, `PROD-002`, `PROD-003` y `PROD-023` completadas.
- **Tamaño:** M
- **Estrategia de pruebas:** unidades puras de extractor/política de rutas,
  integración de persistencia/API owner-scoped e interacción frontend con
  fixtures, carga/error/vacío y teclado; no requiere Internet.
- **Evidencia de validación al completarse:** 2026-09-05: cada resultado
  persistido `project_archive_basic` incorpora el contrato local
  `2026-09-05.1`, con componentes deduplicados por manifiesto/grupo/paquete y
  resumen de manifiestos parseados/omitidos, exactitud, no-correlacionables y
  truncamiento. Solo retiene identificadores de paquete válidos y requisitos de
  registry; no conserva especificadores VCS/URL/local ni rutas inseguras. Se
  añadió `GET /projects/{id}/components`, que revalida propietario y relación de
  ejecución y responde con 404 genérico para IDs ajenos. El panel de proyecto
  permite elegir instantánea, consultar cobertura, buscar y distingue declaración
  exacta, rango y fuente no correlacionable sin prometer advisories. Pasaron la
  suite Python completa (backend y runner), la suite frontend completa (33
  archivos, 221 pruebas), build con presupuesto inicial 319,7/320 KiB,
  `docker compose config --quiet` y `git diff --check`.

### PROD-025 — Distinguir versiones declaradas, resueltas y no correlacionables

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** los equipos necesitan evitar alertas
  engañosas cuando el manifiesto contiene rangos, alias, paquetes locales o una
  dependencia transitiva no resuelta.
- **Flujo completo afectado:** inventario declarado → detectar lockfile soportado
  sin ejecutar gestor → asociar origen/versión verificable → etiquetar elegibilidad
  de correlación → mostrar límite.
- **Áreas o archivos implicados:** runner, contrato de inventario, catálogo de
  manifiestos/lockfiles, SBOM, pruebas y documentación de cobertura.
- **Criterios de aceptación verificables:** el primer corte admite solo lockfiles
  con gramática/ecosistema explícitamente implementados; conserva `declared`,
  `resolved` o `not_correlatable` sin inventar transitivos y asocia cada resolución
  a manifiesto/lockfile relativo seguro. Truncamiento, alias, workspace, VCS,
  URL/local y parser desconocido quedan excluidos con razón visible.
- **Riesgos de seguridad, privacidad y operación:** un parser permisivo atribuye
  versión de otro paquete; abrir lockfiles sin límites agota recursos.
- **Dependencias:** `PROD-024`.
- **Tamaño:** L
- **Estrategia de pruebas:** fixtures mínimos por formato, límites de tamaño y
  pruebas de propiedad/normalización; sin instalar dependencias ni usar red.
- **Evidencia de validación al completarse:** 2026-09-05: el runner admite de
  forma pasiva solo `package-lock.json` npm v2/v3, con límites configurables de
  bytes, lockfiles y entradas. Para un `package.json` de la misma raíz y una
  dependencia registry directa conserva la versión exacta resuelta; no ejecuta
  npm, instala paquetes ni conserva URL de descarga, integridad, tokens o nodos
  transitivos. Los formatos no soportados, errores y límites se cuentan con un
  motivo seguro. El contrato `2026-09-05.2` y el panel distinguen declaración de
  resolución de lockfile y mantienen la advertencia de que no hay consulta de
  vulnerabilidades. Pasaron `backend/tests` y `tools/tests` completos,
  compilación Python, 33 suites/222 pruebas frontend, build con presupuesto
  320,0/320 KiB, `docker compose config --quiet` y `git diff --check`.

### PROD-026 — Límite de egress y privacidad para inteligencia pública

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un administrador debe decidir si la
  composición de paquetes puede salir del entorno sin enviar código, rutas o
  credenciales a terceros.
- **Flujo completo afectado:** configura proveedor permitido → ejecución decide
  local/cache/red → adaptador recibe solo ecosistema/nombre/versión elegible →
  registra cobertura y fallo seguro.
- **Áreas o archivos implicados:** configuración, red de contenedores, adaptadores
  HTTP, observabilidad/redacción, despliegue y pruebas de política.
- **Criterios de aceptación verificables:** red deshabilitada por defecto; cada
  fuente exige allowlist HTTPS, timeout, tamaño, presupuesto y configuración
  explícita. La petición excluye archivo, hash de proyecto, owner, ruta, requisito
  textual, token y cabecera ajena; logs guardan solo proveedor/estado/correlación
  segura. Error/429/caída devuelve cobertura degradada, no “sin vulnerabilidades”.
- **Riesgos de seguridad, privacidad y operación:** fuga de composición, SSRF,
  abuso de API o caída externa presentada como resultado limpio.
- **Dependencias:** `PROD-024`, revisión de egress y aislamiento de `PROD-008`.
- **Tamaño:** M
- **Estrategia de pruebas:** transporte falso que captura payload, allowlist,
  timeout/tamaño/429, redacción de logs y configuración por defecto; sin tráfico
  real en CI.
- **Evidencia de validación al completarse:** 2026-09-05: se añadió
  `backend/app/public_advisory_egress.py` con destinos HTTPS constantes para
  OSV, GHSA y CISA KEV; `trust_env=False`, sin redirecciones, timeout/bytes/
  concurrencia/reintentos con máximos de configuración y telemetría sin
  identidad ni datos de proyecto. El cache persistente usa una clave SHA-256 de
  la identidad mínima, TTL, límite de cuerpo y fallback señalado como
  `stale_cached`; no persiste el payload enviado, project ID, owner, ruta, hash
  de instantánea ni cabeceras. Egress permanece `false` por defecto en Settings
  y Compose. Nueve pruebas con `MockTransport` comprobaron modo deshabilitado,
  endpoint/payload fijos, rechazo de rango/namespace, respuesta grande,
  redirect, 429, retry, configuración, caché y degradación. La suite completa
  `backend/tests tools/tests` en Python 3.12, compilación, los dos perfiles
  Compose y `git diff --check` pasaron. La guía nueva
  `docs/public-vulnerability-intelligence.md` explica activación, amenazas,
  límites y el firewall FQDN externo necesario. Ninguna prueba final depende de
  Internet.

### PROD-027 — Contrato canónico de advisory y adaptadores deterministas

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo necesita resultados
  reproducibles aunque una fuente cambie, esté caída o discrepe de otra.
- **Flujo completo afectado:** componente elegible → adaptador/f fixture → registro
  canónico inmutable → caché versionada → correlación sin reinterpretar JSON externo.
- **Áreas o archivos implicados:** modelos/normalizadores de advisories, caché,
  adaptadores, fixtures y pruebas de contrato.
- **Criterios de aceptación verificables:** conserva OSV/GHSA/CVE cuando existe,
  URL HTTPS de fuente, paquete/ecosistema, rango afectado, versión corregida,
  fechas publicada/actualizada/consultada y retirada; campos desconocidos quedan
  ausentes. Rechaza ID/URL inválidos y deduplica por advisory canónico + paquete/
  intervalo sin fusionar evidencia incompatible. Un adaptador fixture intercambiable
  con red alimenta todos los tests principales.
- **Riesgos de seguridad, privacidad y operación:** mezclar fuentes o sobrescribir
  rangos cambia evidencia histórica; datos externos no validados permiten XSS/enlaces.
- **Dependencias:** `PROD-024`; para adaptadores de red, `PROD-026`.
- **Tamaño:** L
- **Estrategia de pruebas:** esquemas, deduplicación/idempotencia, advisory retirado,
  URL/HTML hostil y campos incompletos.
- **Evidencia de validación al completarse:** 2026-09-05:
  `backend/app/public_advisories.py` implementa el contrato
  `2026-09-05.1` y un normalizador OSV sin acceso de red. Conserva únicamente
  provider/ID, componente exacto, CVE/GHSA, referencias HTTPS sin credenciales,
  rangos, fixes, vector CVSS y fechas publicada/modificada/retirada. Cada fila
  se vincula posicionalmente al componente consultado y se descarta si el
  paquete no coincide; forma JSON inválida genera cobertura degradada. La
  deduplicación usa el digest de evidencia completo: elimina copias idénticas
  sin fusionar rangos discrepantes. Un fixture local y cuatro pruebas cubren
  normalización, retirada, desajuste, duplicación y entradas hostiles; junto a
  las nueve pruebas de egress dieron 13 casos sin Internet. `compileall` y
  `git diff --check` pasaron.

### PROD-028 — Correlación OSV por versión exacta y hallazgos de dependencia

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una persona quiere saber si una
  versión concreta verificada está afectada, con actualización/mitigación revisable.
- **Flujo completo afectado:** componente exacto → consulta OSV en lote permitida
  → validar paquete/versión/rango → finding normalizado → persistir evidencia/
  frescura → recomendación.
- **Áreas o archivos implicados:** OSV, comparador de versiones por ecosistema,
  normalizador, persistencia, resultados e informes.
- **Criterios de aceptación verificables:** consulta solo registry + versión exacta
  corroborada; conserva OSV, CVE/GHSA si existen, fuente, rango, primera versión
  corregida, fecha y confianza. Sin versión/respuesta/coincidencia clara no crea
  hallazgo de vulnerabilidad y muestra cobertura no correlacionada. Reintentos usan
  respuesta cacheada/fixture identificable.
- **Riesgos de seguridad, privacidad y operación:** semver/Python erróneo acusa
  inocentes; red reciente sin snapshot rompe reproducibilidad.
- **Dependencias:** `PROD-025`, `PROD-026`, `PROD-027`; evoluciona `PROD-010`.
- **Tamaño:** L
- **Estrategia de pruebas:** fixtures OSV de coincidencia/sin coincidencia/rango
  ambiguo/timeout/retirada y redacción; integración sin Internet.
- **Evidencia de validación al completarse:** 2026-09-05: se implementó el
  snapshot OSV separado y owner-scoped. Solo los componentes registry npm/PyPI
  exactos, correlacionables y con identidad pública segura entran al lote; la
  purl conservada se reconstruye desde esa identidad y nunca reutiliza
  metadatos almacenados de proyecto. El resultado del proveedor pasa el
  contrato `2026-09-05.1`, se vuelve a contrastar con el comparador local y
  solo entonces se conserva con rangos, fix, CVE/GHSA, fechas, vectores y
  referencias. Fallo, retirada, rango desconocido o incoherencia degradan o
  excluyen la cobertura en vez de crear un finding. API, informe y panel
  consumen el snapshot normalizado; la acción queda en la matriz CSRF/owner.
  Pasaron 17 pruebas backend dirigidas sin Internet, `backend/tests` y
  `tools/tests` completos en Python 3.12, `compileall`, ambos Compose, diff
  check, 36 suites/234 pruebas frontend y build 314,0/322 KiB. La revisión
  visual local con la instantánea sintética completada validó estados y
  responsive 1440/640 sin habilitar egress ni contactar OSV.

### PROD-029 — Evidencia, CVSS y prioridad de remediación

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** seguridad y desarrollo necesitan
  separar gravedad técnica de explotación conocida y saber qué versión actualizar.
- **Flujo completo afectado:** advisory canónico → coincidencia → finding enriquecido
  → lista/detalle/informe → priorización/filtro.
- **Áreas o archivos implicados:** modelo finding/advisory, normalizador, API,
  frontend, informes y compatibilidad.
- **Criterios de aceptación verificables:** conserva puntuación/vector CVSS tal
  como fuente; clasifica `none`, `low`, `medium`, `high`, `critical` sin inventar
  `none` si falta score. Muestra CVSS, fuente, afectado/corregido, fecha y acción;
  separa semántica y visualmente CISA KEV de CVSS. Mantiene compatibilidad y
  redacción de hallazgos pasivos antiguos.
- **Riesgos de seguridad, privacidad y operación:** convertir KEV en CVSS o
  inventar puntuaciones distorsiona prioridad; romper contrato bloquea informes.
- **Dependencias:** `PROD-027`, `PROD-028`, `PROD-004`, `PROD-006`.
- **Tamaño:** L
- **Estrategia de pruebas:** fixtures CVSS v3/v4, score ausente/0, vector inválido,
  compatibilidad, accesibilidad y HTML escapado.
- **Evidencia de validación al completarse:** 2026-09-05: se añadió un evaluador
  local estricto de vectores CVSS 3.0/3.1, que conserva el vector del proveedor
  y publica únicamente una puntuación base y banda claramente marcadas como
  derivadas. CVSS v4, vector malformado o ausencia quedan `unknown`, no `none`.
  El snapshot/API admite los campos nuevos con valores por defecto para leer
  resultados OSV heredados; la interfaz muestra prioridad, vector, origen,
  fechas, rangos, corrección y recomendación, y declara expresamente que KEV no
  está evaluado. Pasaron 16 pruebas backend dirigidas, la regresión completa de
  `backend/tests tools/tests` en Python 3.12, `compileall`, ambos Compose y
  `git diff --check`; en una copia temporal, 36 suites/234 pruebas frontend y
  build/presupuesto 314,0/322 KiB pasaron sin egress real.

### PROD-030 — Experiencia de inteligencia de dependencias y cobertura visible

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un desarrollador debe entender qué
  se analizó, qué quedó excluido y cómo filtrar dependencias sin confundir cobertura
  parcial con seguridad.
- **Flujo completo afectado:** abrir proyecto → inventario/cobertura → buscar paquete/
  CVE/GHSA → filtrar ecosistema/severidad/KEV/estado/fuente → detalle → informe.
- **Áreas o archivos implicados:** paneles, tipos/API, estilos, navegación profunda,
  accesibilidad, responsive, informes y tests frontend.
- **Criterios de aceptación verificables:** muestra carga/error/vacío, proveedor
  deshabilitado, dato obsoleto y cobertura parcial; filtros/búsqueda no exponen
  rutas/secretos. A 320/768/1440 px mantiene foco, teclado, etiquetas/contraste.
  Diferencia requisito declarado y versión resuelta; enlaces HTTPS verificados.
- **Riesgos de seguridad, privacidad y operación:** ocultar exclusiones o presentar
  “0” como limpio genera decisiones inseguras; listas densas reducen adopción.
- **Dependencias:** `PROD-024`, `PROD-029`, `PROD-017`.
- **Tamaño:** L
- **Estrategia de pruebas:** interacción/axe, filtros/estados y revisión visual
  con fixtures sintéticos según `docs/frontend-visual-review.md`.
- **Evidencia de validación al completarse:** 2026-09-05: el panel filtra y busca
  exclusivamente campos públicos ya normalizados de la instantánea retenida:
  advisory/CVE/GHSA, componente, versión, recomendación, banda CVSS, KEV,
  consenso de evidencia y alcance directo/transitivo/opcional. Conserva el
  recuento, el estado vacío de filtros, carga/error/vacío, egress desactivado y
  cobertura `stale`/`degraded`; no inicia consultas por filtrar ni muestra rutas,
  archivo, payload ni identidad enviada. Las referencias se revalidan en la UI:
  solo HTTPS sin credenciales, fragmento, `localhost` ni literal IP se abre con
  `noopener noreferrer`; lo demás queda retenido. Las fixtures cubren filtros
  combinados, dato obsoleto, referencia hostil y axe sin violaciones. La revisión
  local con egress desactivado comprobó acciones, mensaje y foco a 320/768/1440
  px; detectó y corrigió selectores y acciones largas que ensanchaban el móvil.
  Pasaron 36 suites/250 pruebas frontend, TypeScript/Vite y presupuesto
  316,4/322 KiB, ambos Compose con fixtures y `git diff --check`. No hubo egress
  ni consulta pública real.

### PROD-031 — CISA KEV como señal independiente y trazable

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** responsables de riesgo necesitan
  destacar advisories con explotación conocida sin afirmar explotación propia.
- **Flujo completo afectado:** advisory con CVE → feed KEV cacheado → coincidencia
  exacta → indicador/fecha/acción CISA → filtro, comparación e informe.
- **Áreas o archivos implicados:** adaptador/feed KEV, caché/provenance, normalización,
  UI, informe y fixtures.
- **Criterios de aceptación verificables:** marca KEV solo por CVE exacto en feed
  fechado; conserva fecha/acción. Sin CVE/feed/dato vigente muestra desconocido/
  no evaluado, no “no explotado”; nunca altera CVSS ni concluye explotación local.
- **Riesgos de seguridad, privacidad y operación:** feed obsoleto o coincidencia
  laxa sobreprioriza/oculta riesgo; descarga sin control abre egress.
- **Dependencias:** `PROD-026`, `PROD-027`, `PROD-029`.
- **Tamaño:** M
- **Estrategia de pruebas:** fixtures CISA fechados, CVE sin match, feed caído/
  caducado, deduplicación y render accesible.
- **Evidencia de validación al completarse:** se añadió una consulta separada
  del catálogo JSON CISA fijo y cacheado; no transmite ningún dato de proyecto
  ni siquiera un CVE. Solo después, localmente, compara un CVE exacto que ya
  está en OSV/GHSA. El contrato conserva únicamente estado, CVE, versión/fecha
  del catálogo, fechas/acción publicadas y enlace canónico; no CPE, proveedor,
  producto, descripción ni notas. Señales `known_exploited`, `not_listed`,
  `unavailable` y `not_evaluated` permanecen independientes de CVSS y explican
  que no son prueba de explotación ni ausencia de ella. Si no hay CVE, evita la
  descarga. El feed medía 1.696.769 bytes el 2026-09-05, por lo que el límite
  estrictamente acotado cambió a 2 MiB —también máximo— para hacerlo viable.
  Pasaron 12 pruebas backend dirigidas, regresión `backend/tests tools/tests`,
  `compileall`, ambos Compose con valores de fixture, `git diff --check`, 36
  suites/234 pruebas frontend y build 314,4/322 KiB; no hubo egress real en
  pruebas. Fuente: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

### PROD-032 — Corroboración GHSA con evidencia versionada

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** equipos necesitan una segunda fuente
  curada para corroborar identificadores GHSA, rangos, correcciones y CVSS cuando
  OSV sea incompleto o discrepe, sin compartir composición adicional.
- **Flujo completo afectado:** advisory OSV con GHSA → adaptador fijo de GitHub
  Global Security Advisories → respuesta versionada y trazada → corroboración o
  discrepancia visible → snapshot, informe y API sin alterar el hallazgo base.
- **Áreas o archivos implicados:** adaptador GHSA, egress fijo, contrato,
  caché/procedencia, modelos, UI, informe y fixtures.
- **Criterios de aceptación verificables:** GHSA usa solo su endpoint fijo
  aprobado y consulta por identificadores ya presentes en el snapshot OSV, sin
  enviar componentes/proyecto. Conserva por campo la fuente, fecha, rango,
  corrección y CVSS; no sustituye OSV ni inventa coincidencia. Maneja
  No pagina: una búsqueda de GHSA exacta usa `per_page=1` fijo y más de un
  resultado es una respuesta inválida; 429, retirada y respuesta incompleta
  degradan la cobertura.
  NVD y boletines de proveedor siguen en `PROD-093`/`PROD-095` y requieren una
  aprobación de egress separada; un changelog no es evidencia única.
- **Riesgos de seguridad, privacidad y operación:** una consulta por paquete o
  rangos fabricaría una fuga; mezclar identificadores/rangos atribuye CVE erróneo
  y una API limitada puede degradar la cobertura.
- **Dependencias:** `PROD-026`, `PROD-027`, `PROD-028`, `PROD-029` completadas.
- **Tamaño:** L
- **Estrategia de pruebas:** fixtures GHSA de coincidencia, conflicto, retirada,
  arreglo ausente, resultado múltiple rechazado y 429; nunca proveedor real en
  suite principal.
- **Evidencia de validación al completarse:** el adaptador usa exclusivamente
  un GHSA ya presente en OSV, endpoint/método/cabeceras/versión de API fijos y
  `per_page=1` interno; nunca remite identidad de componente ni datos de
  proyecto. Rechaza una respuesta ambigua, retirada o sin coincidencia local y
  conserva la corroboración como evidencia separada. Pasaron 16 pruebas backend
  dirigidas, regresión completa `backend/tests tools/tests` y `compileall`, ambos
  Compose y `git diff --check`; en copia temporal, 36 suites/234 pruebas
  frontend y build 314,2/322 KiB. Solo fixtures y `MockTransport`, sin egress
  real. Fuente: [GitHub Global Security Advisories](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28).

### PROD-033 — Frescura, caché y recuperación de fuentes públicas

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** operaciones necesita resultados
  reproducibles que indiquen actualidad y sobrevivan caídas/límites.
- **Flujo completo afectado:** caché → decidir refresco TTL/presupuesto → consultar
  o degradar → snapshot/provenance → estado/métricas seguras → reintento controlado.
- **Áreas o archivos implicados:** caché, configuración, observabilidad, UI de
  frescura, runbook y pruebas de reinicio.
- **Criterios de aceptación verificables:** cada resultado declara `as_of`, fuente,
  estado `fresh`/`stale`/`unavailable` y razón; TTL, tamaño, backoff, lote y
  retención son configurables. Una caída usa caché o cobertura degradada, nunca
  borra último resultado ni afirma cero; logs excluyen datos sensibles.
- **Riesgos de seguridad, privacidad y operación:** caché infinita normaliza datos
  obsoletos; reintentos sin tope causan bloqueo/DoS.
- **Dependencias:** `PROD-026`, `PROD-027`, `PROD-015`.
- **Tamaño:** L
- **Estrategia de pruebas:** reloj inyectable, caché fría/caliente/caducada,
  timeout/429, reinicio y concurrencia simulados.
- **Evidencia de validación al completarse:** 2026-09-05: cada fuente conserva
  estado, `as_of`, caducidad y razón limitada; el adaptador usa reloj inyectable,
  TTL y retención independiente (7 días por defecto, máximo 30, nunca menor que
  TTL). Al expirar la retención elimina la respuesta pública desechable y evita
  el fallback; antes de eso una caída muestra `stale`/`unavailable`, conserva
  los últimos hallazgos normalizados y marca el snapshot `degraded`. La UI y el
  informe presentan frescura/razón sin diagnóstico externo y lectores de
  snapshots antiguos migran esa razón en memoria. Pasaron 26 pruebas backend
  dirigidas, la regresión completa `backend/tests tools/tests`, `compileall`,
  Compose normal y privado con valores fixture, `git diff --check`, y 36 suites
  frontend/234 pruebas con build y presupuesto 314,4/322 KiB. Todo usa fixtures,
  `MockTransport` y reloj controlable: sin Internet.

### PROD-034 — Comparación, línea base e informe de vulnerabilidades públicas

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo necesita saber qué CVE/GHSA
  apareció, se resolvió o cambió por datos nuevos sin confundir feed y código.
- **Flujo completo afectado:** dos snapshots comparables → inventario/advisory →
  nuevo/resuelto/persistente/cambio de inteligencia → baseline/decisión → informe.
- **Áreas o archivos implicados:** comparación, contratos, informes, UI y `PROD-011`.
- **Criterios de aceptación verificables:** diferencia cambio de componente,
  advisory/frescura y cobertura no comparable; conserva advisory/snapshot de fuente.
  Informe incluye fecha/fuente/CVSS/KEV/acción sin rutas/secretos. Excepción sigue
  motivo/caducidad de `PROD-011` y no borra finding.
- **Riesgos de seguridad, privacidad y operación:** mezclar feeds/versiones fabrica
  regresiones; baseline global oculta riesgo entre proyectos.
- **Dependencias:** `PROD-005`, `PROD-006`, `PROD-011`, `PROD-029`, `PROD-031`.
- **Tamaño:** L
- **Estrategia de pruebas:** dos snapshots proyecto/feed, cambio rango, CVE resuelto,
  fuente obsoleta, aislamiento y exportación segura.
- **Evidencia de validación al completarse:** reconciliada 2026-09-09 con
  `PROD-033`, `PROD-050`, `PROD-051`, `PROD-053`, `PROD-065`, `PROD-096`,
  `PROD-099` y `PROD-104`. Comparación y baseline son owner-scoped, separan
  cambio de componente, evidencia pública, frescura y cobertura; una pérdida
  de cobertura queda `not_comparable`, nunca resuelta. Informes conservan
  CVE/GHSA, CVSS, KEV, fuentes/digest y lifecycle redactado. Las regresiones
  dirigidas de comparación pública, baseline e informe formaron parte de las
  30 pruebas backend sin red de `PROD-239`.

### PROD-035 — Cobertura y límites de ejecución visibles en el proyecto

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** antes de actuar, una persona necesita
  ver manifiestos/componentes analizados, exclusiones y siguiente acción segura.
- **Flujo completo afectado:** ejecución completa/parcial/fallida → cobertura segura
  → proyecto/explorador → informe → reintento o revisión manual.
- **Áreas o archivos implicados:** resumen runner, contratos proyecto, panel findings,
  reportes, estilos, observabilidad, documentación y tests.
- **Criterios de aceptación verificables:** expone conteos seguros de entradas,
  manifiestos soportados/parseados/omitidos, componentes elegibles/no elegibles,
  truncamiento y motivos agregados sin rutas inseguras. La UI explica cobertura,
  carga/error/vacío/parcial y acción. Pruebas cubren límite, parser, fuente vencida,
  acceso cruzado, lector pantalla y 320/768/1440 px.
- **Riesgos de seguridad, privacidad y operación:** “0 hallazgos” sin cobertura
  crea confianza indebida; ruta host/error bruto filtra datos.
- **Dependencias:** `PROD-004`, `PROD-006`, `PROD-023`; complementa `PROD-017`.
- **Tamaño:** M
- **Estrategia de pruebas:** contrato backend/fixtures parciales, frontend/axe y
  revisión visual documentada.
- **Evidencia de validación al completarse:** 2026-09-05: el contrato de
  hallazgos añade una cobertura agregada segura para análisis de proyecto y el
  panel distingue completo, parcial o desconocido con conteos de manifiestos y
  lockfiles, sin rutas ni resultados brutos. Los informes incluyen el mismo
  resumen. Pasaron pruebas dirigidas, backend/runner completo y `compileall`,
  Compose/diff check, y build frontend con presupuesto 322 KiB.

### PROD-036 — Eliminación y retención explícita de proyectos y derivados

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** el dueño necesita borrar un proyecto
  completo de forma comprensible, no deducirlo al borrar una subida.
- **Flujo completo afectado:** proyecto → alcance de borrado → confirmar → eliminar
  metadatos/inventarios/resultados/exportaciones → auditoría sin contenido.
- **Áreas o archivos implicados:** almacenamiento/modelos, autorización, rutas,
  UI, retención, audit log, documentación y tests.
- **Criterios de aceptación verificables:** owner/org-scoped, idempotente y declara
  qué conserva/elimina; no borra ajeno ni trabajo activo sin estado seguro. UI
  exige confirmación y refleja éxito/error. Tests: cruce, fuente vencida, jobs
  activos, reintento y ausencia de exportación/API.
- **Riesgos de seguridad, privacidad y operación:** retención involuntaria de
  composición/código o borrado de evidencia de otro usuario.
- **Dependencias:** `PROD-008`, `PROD-013`, `PROD-020`.
- **Tamaño:** M
- **Estrategia de pruebas:** integración de borrado/retención, autorización/UI y
  revisión runbook backup.
- **Evidencia de validación al completarse:** 2026-09-06: se añadió una vista
  previa owner/org-scoped y una cascada idempotente que elimina proyecto y
  baseline, trabajos terminales/resultados, snapshots de inteligencia, triage,
  admisiones y workspaces, pero conserva expresamente la subida fuente, caché
  pública, actividad mínima y copias externas. Un trabajo activo o admisión
  pendiente bloquea el inicio. Un journal `0600` sin contenido oculta el
  proyecto, cierra nuevas admisiones, se reanuda al arrancar y mantiene
  readiness no disponible hasta completar; logs/respuestas no incluyen ruta,
  nombre de fuente ni mensaje de excepción. Pasaron 6 pruebas backend dirigidas
  y 3 frontend; la regresión completa pasó 1.069 backend (38,72 s; 88.204 KiB
  RSS), 420 runner/guardas (6,23 s; 67.688 KiB RSS) y 44 archivos/298 frontend
  (20,70 s; 574.408 KiB RSS). El build pasó en 7,82 s con 317,0/322 KiB,
  además de `compileall`, Compose base/privado y diff. La revisión local real
  sobre el fixture sintético comprobó 1440/390 px, sin scroll horizontal, foco
  de 3 px y el estado de éxito. No hubo Internet, proveedor ni proyecto real;
  la consola del navegador no estaba disponible. `PROD-120` conserva la purga
  total de fuente/copias como trabajo bloqueado independiente.

### PROD-037 — Descomponer fixtures y pruebas de contratos de producto

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** el equipo necesita evolucionar
  inventario/advisories sin que una suite monolítica frene regresiones críticas.
- **Flujo completo afectado:** cambio contrato → fixture tipada → prueba unitaria/
  integración → suite local/CI → evidencia.
- **Áreas o archivos implicados:** `backend/tests/test_backend.py`, fixtures,
  runner, frontend, Makefile/CI y contribución.
- **Criterios de aceptación verificables:** tests de proyectos/inventario/advisories/
  autorización se extraen gradualmente sin reducir casos; guarda detecta secretos
  o llamadas de red en fixtures. Comandos documentados son deterministas y fallan
  de forma atribuible.
- **Riesgos de seguridad, privacidad y operación:** una suite difícil incentiva
  desactivar controles o deja rutas sensibles sin pruebas.
- **Dependencias:** ninguna; coordinar con `PROD-024` a `PROD-034`.
- **Tamaño:** M
- **Estrategia de pruebas:** suite antes/después, imports y guarda fixture/red;
  sin cambio de producción.
- **Evidencia de validación al completarse:** **2026-09-10:** reconciliación
  estructural sobre 62 módulos de dominio existentes: inventario/SBOM/PVI,
  OSV/GHSA/NVD/egress/fixtures, identidad/tokens/auditoría y numerosos stores ya
  viven fuera de `test_backend.py`; el monolito conserva 553 recorridos de
  integración heredados y las pruebas nuevas deben entrar en su dominio. Se añadió
  `docs/test-strategy.md` con grupos atribuibles y límites, y un canario que
  demuestra que el `conftest` global bloquea DNS, `connect` y `connect_ex` externos.
  La gobernanza de advisories exige manifiesto+digest y Gitleaks conserva sus
  exclusiones sintéticas puntuales: `make verify-secret-scanner` detectó el canario
  esperado. Pasaron 218/218 pruebas desacopladas de contratos/guardas y la suite
  backend inmediatamente anterior 1.612/1.612; el nuevo total colecciona 1.613
  pruebas. `compileall` y diff-check pasaron. El primer intento CLI usado para
  reconciliar `PROD-038` dejó evidencia separada de runtimes incompletos y no se
  contó como verde. No se modificó CI ni `SEC-012`.

### PROD-038 — Integración CI y puertas de riesgo de proyecto

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** equipos quieren ver regresiones antes
  de fusionar con mismo inventario/hallazgos sin enviar código no autorizado.
- **Flujo completo afectado:** CI crea snapshot autorizado → perfil explícito →
  JSON/SARIF/estado → baseline → política de fallo explicable.
- **Áreas o archivos implicados:** CLI/API, salida, política, CI docs, auditoría/tests.
- **Criterios de aceptación verificables:** no checkout ni tokens en logs; salida
  versionada distingue vulnerabilidad/cobertura/error. Gate falla solo reglas
  configuradas/evidencia reproducible, modo informativo y sin correlacionar no
  resueltos. Fixtures: token redactado, baseline ausente, timeout y salida válida.
- **Riesgos de seguridad, privacidad y operación:** gate opaco bloquea entregas o
  filtra secretos; no determinismo provoca alertas inestables.
- **Dependencias:** `PROD-019`, `PROD-024`, `PROD-034`, `PROD-012`.
- **Tamaño:** L
- **Estrategia de pruebas:** contratos CLI/API y pipeline fixture sin servicios externos.
- **Evidencia de validación al completarse:** **2026-09-10:** reconciliación
  criterio por criterio, no nominal. `PROD-131/132/163` aportan snapshot del commit
  sin checkout/fetch implícito y errores seguros; `PROD-133/153/157` aportan token
  one-shot por entorno, ámbitos mínimos, rotación/revocación y snippet sin secreto;
  `PROD-134/135/159` aportan admisión reproducible, espera, timeout y cancelación
  opt-in; `PROD-136/155` aportan política `observe|standard|strict`, códigos
  `0|8|9`, JSON y SARIF 2.1.0 versionados; `PROD-033/050/051/053/065/096/099/104`
  aportan baseline, comparación y cobertura. La política comprobada nunca convierte
  cobertura parcial, inteligencia stale ni baseline no comparable en `pass`.
  Pasaron 63/63 pruebas CLI de snapshot/CI/policy/config/grafos en Python 3.12 con
  Git montado read-only y red deshabilitada, 2/2 renderers contra el esquema SARIF
  fijado y 3/3 regresiones backend de token, atestación de canal y baseline; la
  suite backend completa de este ciclo pasó 1.612/1.612. Dos primeros runtimes
  fueron descartados de la evidencia: uno carecía de CLI/`jsonschema` y otro de
  Git (44 casos sí pasaron, 19 no pudieron arrancar Git); no se atribuyeron esos
  fallos al producto. No hubo CI remoto, proveedor, push, PR, tag ni despliegue.

### PROD-039 — Identidad empresarial federada y aprovisionamiento controlado

- **Prioridad:** P3
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** organizaciones con identidad central
  necesitan acceso/revocación consistente sin credenciales locales extra.
- **Flujo completo afectado:** proveedor → autenticación → grupo/rol mínimo →
  organización → revocación/auditoría.
- **Áreas o archivos implicados:** auth, sesiones, org, secret manager, UI admin,
  auditoría/runbooks.
- **Criterios de aceptación verificables:** solo tras `PROD-012`; valida issuer/
  audience/redirect/PKCE o equivalente, limita roles, rota secretos externos y
  revoca sesión. Tests: token inválido, grupo inesperado, tenant cruzado, fallo IdP.
- **Riesgos de seguridad, privacidad y operación:** federación mal configurada
  permite suplantación/elevación/fuga de atributos.
- **Dependencias:** `PROD-012`, `PROD-013`, `PROD-014`, revisión de amenaza.
- **Tamaño:** L
- **Estrategia de pruebas:** IdP simulado, middleware/session/autorización y docs;
  sin IdP real en suite principal.
- **Evidencia de validación al completarse:** **2026-09-11:** vertical OIDC
  privado opt-in y preaprovisionado para `reader`/`maintainer`, con administrador
  local de ruptura. Implementa Authorization Code + PKCE S256, `state` de un
  solo uso ligado al navegador, nonce, issuer/audience/azp/tenant/grupos, firma
  asimétrica RS256/ES256 y endpoints HTTPS de mismo origen fijados por operador.
  Token/JWKS usan `trust_env=false`, cero redirecciones, 5 s, 256 KiB,
  concurrencia cuatro y caché JWKS en memoria; tokens, claims, `sub` y secretos
  no se persisten. La ligadura almacena HMAC de `issuer + sub`, exige membresía
  y rol exactos, prohíbe federar administradores y su revocación invalida
  sesiones. API/CSRF/auditoría y UI administrativa cubren carga, vacío, error,
  acceso fijo y retorno fallido genérico. El contrato y runbooks quedaron en
  `docs/oidc-federation.md`, arquitectura, workspaces y backup/restore.
  Pruebas: backend completo 1.631/1.631 (384,59 s; 409.984 KiB RSS), frontend
  serial 427/427 (la primera ejecución paralela tuvo un único timeout de una
  prueba Active ajena, reproducida verde dos veces y luego en la suite serial),
  CLI 66/66 bajo Python 3.12.13, build 305,2/322 KiB, `compileall`, Compose
  base/privado, consistencia de release y auditorías de ambos locks Python sin
  vulnerabilidades conocidas. La primera pasada CLI bajo Python 3.13.15 dio
  65/66 porque `doctor` verifica el runtime 3.12 contractual; la repetición con
  3.12 pasó completa. Revisión visual reproducible en escritorio y 390×844
  confirmó login condicional, error redactado y panel admin responsive. Todo el
  IdP fue simulado con claves efímeras: **implementado y validado con fixtures,
  no validado contra proveedor real**; no se siguió el enlace IdP ni hubo
  egress, push, PR o despliegue.

### PROD-040 — Recuperación, backup y migración verificable

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una empresa necesita actualizar o
  recuperar sin perder trazabilidad ni restaurar datos sensibles de otro ámbito.
- **Flujo completo afectado:** backup seguro → restauración aislada → migrar esquema
  → verificar integridad/ownership → registrar resultado y limpiar temporal.
- **Áreas o archivos implicados:** almacenamiento/esquema, scripts, cifrado externo,
  runbooks y tests.
- **Criterios de aceptación verificables:** formato/versionado, checksum y restore
  probado con fixture; respeta owner/org y exclusiones de fuente/secretos. Fallos
  no dejan restauración parcial y docs declaran RPO/RTO solo si se han medido.
- **Riesgos de seguridad, privacidad y operación:** backup exfiltra datos; migración
  sin rollback pierde proyectos/evidencia.
- **Dependencias:** `PROD-008`, `PROD-012`, `PROD-020`, persistencia durable.
- **Tamaño:** L
- **Estrategia de pruebas:** backup/restore sintético, checksum corrupto, rollback/
  migración y autorización administrativa.
- **Evidencia de validación al completarse:** 2026-09-06: se añadió una CLI
  administrativa sin superficie HTTP para `create`/`verify`/`restore` bajo el
  contrato `2026-09-06.1`. La copia completa solo recorre `uploads`, `results`
  y el SQLite explícito bajo `runtime`; exige aplicación offline, comprensión
  del dato sensible y destino cifrado atestados. Rechaza trabajos activos,
  workspaces/journals/WAL, entradas temporales, symlink/hardlink, límites,
  registros inválidos, referencias rotas y cruces owner/org. El manifiesto no
  conserva paths del host ni nombres humanos, verifica conjunto exacto,
  tamaños, SHA-256, esquemas y semántica; no pretende autenticidad frente a
  quien pueda reescribirlo. Restore solo publica a un directorio nuevo tras
  staging, migra auth schema 1→2, acepta team schema 1, revoca sesiones,
  intentos e invitaciones y elimina el staging si falla. El runbook declara que
  fuentes/password hashes hacen sensible el bundle, que cifrado/KMS es externo
  y que RPO/RTO no se afirmarán hasta `PROD-064`. Pasaron 17 pruebas dirigidas
  (2,54 s; 62.164 KiB RSS), incluidos dos propietarios, fuente/resultados/PVI/
  triage/auditoría/identidad, corrupción, path hostil, estado no quiescente,
  esquema futuro y migración legado. La regresión backend pasó 1.087/1.087
  (23,97 s; 88.724 KiB RSS) y runner/guardas 420/420 (6,08 s; 67.760 KiB RSS),
  además de `compileall`, Compose base/privado y `git diff --check`, sin casos
  omitidos, Internet, proveedor, proyecto real ni despliegue. No se ejecutó aún
  el ensayo en volumen cifrado/host aislado, que permanece en `PROD-064`.

## Próximo corte de ejecución

`PROD-026`…`PROD-029`, `PROD-031`…`PROD-033` y `PROD-051` están completadas: OSV es
opt-in, GHSA solo corrobora identificadores retenidos, KEV solo CVE exactos y
las tres fuentes declaran frescura/recuperación bajo egress fijo y fixtures.
`PROD-051` también hace visible conflicto/retirada sin fusionar evidencia y
`PROD-050` clasifica cada componente sin crear negativos falsos y `PROD-048`
completa el alcance directo, transitivo y opcional. `PROD-017` cerró el
onboarding, foco y responsive del flujo de proyecto, y `PROD-030` cerró la
experiencia de inteligencia de dependencias. `PROD-059` completó la postura
segura de despliegue privado, `PROD-044` añadió un preflujo de cobertura,
`PROD-046` cerró el contexto de corrección y `PROD-045` añadió aceptación
reproducible. `PROD-052` completó la validación previa a caché de feeds,
`PROD-049` cerró aliases y locators no registry y `PROD-055` exige procedencia
pública verificable y excluye namespaces privados. `PROD-101` ya aporta el
motor local determinista y `PROD-118` preserva intervalos OSV discontinuos.
`PROD-102` ya separa identidad estable y evidencia mutable, y `PROD-119`
rechaza intérpretes incompatibles antes del bootstrap. `PROD-057` ya captura
el perfil de ejecución inmutable y redactado por análisis. `PROD-065`,
`PROD-113`, `PROD-122`, `PROD-073`, `PROD-060`, `PROD-012`, `PROD-013` y
`PROD-020`, `PROD-036`, `PROD-040`, `PROD-062`, `PROD-064`, `PROD-075` y
`PROD-123` están completadas. `PROD-116` también quedó completada tras el acta
local reproducible. `PROD-117` quedó **completada** tras dos fuentes autorizadas:
`fuente autorizada A` produjo un `NO-GO` honesto por carecer de versiones exactas y el
commit inmutable `[commit autorizado B redactado]` de fuente autorizada B cerró
el vertical con OSV y CISA KEV oficiales, GHSA prohibido, degradación,
persistencia, revisión visual y limpieza integral. `PROD-127` y `PROD-128`
cierran los dos defectos encontrados en esa aceptación. El próximo corte es
`PROD-129`, cuya consolidación local y versión `0.3.0-beta.1` se autorizaron y
completaron el 2026-09-10; `PROD-130` depende además de CI remoto y de `SEC-012`.
`PROD-054` y `PROD-061` permanecen como refuerzo P2. `SEC-012` no forma parte
de la secuencia autorizada y permanece bloqueada sin cambios.

### PROD-041 — Incorporar una nueva instantánea inmutable al mismo proyecto

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un desarrollador necesita asociar
  el archivo de una corrección o nueva versión al mismo proyecto para que el
  historial, la comparación y los informes representen la evolución real, sin
  reemplazar silenciosamente la fuente que produjo un análisis anterior.
- **Flujo completo afectado:** subir archivo autorizado → elegir proyecto propio
  → confirmar nueva instantánea → conservar hash y relación de cada ejecución
  → ejecutar análisis → comparar nuevo/resuelto/persistente entre snapshots.
- **Áreas o archivos implicados:** modelos y almacenamiento de proyecto/fuente,
  rutas owner-scoped, programador de auditorías, frontend de proyectos e
  historial, comparación, informes, guía y fixtures.
- **Criterios de aceptación verificables:** una nueva fuente solo puede unirse a
  un proyecto del mismo propietario tras validar archivo y confirmación; ningún
  resultado histórico cambia de hash, fuente ni perfil. La interfaz identifica
  qué ejecuciones pertenecen a cada snapshot y permite continuar al análisis;
  archivos eliminados mantienen la trazabilidad mínima sin impedir comparar
  resultados redactados. Pruebas cubren cruce de propietario, archivo no válido,
  doble envío, fuente expirada, historial e informe.
- **Riesgos de seguridad, privacidad y operación:** reemplazar una fuente en
  sitio rompe reproducibilidad; aceptar un archivo ajeno mezcla información;
  nombres o rutas de archivo en exceso filtran topología.
- **Dependencias:** `PROD-001`, `PROD-002`, `PROD-005`, `PROD-023` completadas;
  coordinar con límites de `PROD-008`.
- **Tamaño:** L
- **Estrategia de pruebas:** integración de API/almacenamiento con dos hashes y
  propietarios, comparación/regresión e interfaz de historial responsive.
- **Evidencia de validación al completarse:** 2026-09-05: `POST
  /projects/{id}/snapshots` exige `authorization_confirmed: true`, un archivo
  `archive` del mismo propietario y ausencia de una ejecución activa. Persiste
  una lista de metadatos de instantáneas inmutables (ID opaco, nombre de
  presentación, SHA-256 y marca de eliminación), mueve únicamente el puntero
  actual y encola una ejecución atribuida al nuevo hash. Rechaza el hash ya
  retenido con una acción segura para repetirlo. Al borrar una fuente anterior
  se marca solo esa instantánea; la historia y el resultado redactado siguen
  disponibles. La UI ofrece **Add snapshot**, excluye el hash ya retenido,
  confirma autorización, muestra estado vacío y etiqueta los selectores de
  hallazgos/inventario con el hash de la ejecución. Pasaron las pruebas de API
  para confirmación ausente, ejecución activa, duplicado, tipo no válido,
  cruce de propietario, dos hashes e historial/eliminación, y las de interfaz
  para formulario, solicitud y estado vacío. También pasaron `backend/tests`,
  `tools/tests`, compilación Python, 34 suites/225 pruebas frontend, build
  TypeScript/Vite, presupuesto inicial 321,0/322 KiB, `docker compose config
  --quiet` y `git diff --check`.

### PROD-042 — Estado, causa y recuperación útiles por ejecución

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** quien espera un análisis necesita
  saber qué está ocurriendo, qué parte puede recuperar y cuándo es seguro
  repetir, en lugar de recibir solo una etiqueta de estado o un error técnico.
- **Flujo completo afectado:** crear o repetir análisis → estado en cola/en curso
  → completado, fallo o reinicio → causa pública estable y siguiente acción →
  registro reproducible de intento.
- **Áreas o archivos implicados:** contratos de trabajos, clasificador de error,
  panel/lista de proyectos, observabilidad y documentación; se integra con la
  ejecución durable posterior de `PROD-015` sin simular cancelación.
- **Criterios de aceptación verificables:** cada estado terminal o recuperable
  tiene texto seguro, código estable, hora de actualización y acción permitida;
  no entrega traceback, ruta de host, nombre sensible ni secreto. Un análisis
  activo no ofrece una repetición engañosa; después de un error recuperable la
  acción explica el mismo snapshot que se volverá a usar. Pruebas cubren los
  estados, error redactado, foco/lector de pantalla y acceso propietario.
- **Riesgos de seguridad, privacidad y operación:** un error bruto filtra datos;
  una acción disponible en el momento equivocado duplica consumo o confunde el
  historial.
- **Dependencias:** `PROD-002` completada; ejecución durable de `PROD-015`
  amplía, pero no bloquea, la primera presentación.
- **Tamaño:** M
- **Estrategia de pruebas:** contratos de errores y estados sintéticos,
  integración owner-scoped, tests de componente y revisión a 320/768/1440 px.
- **Evidencia de validación al completarse:** 2026-09-05: cada elemento de
  historial/listado recibe `status_detail` con código, explicación y próxima
  acción seguros para cola, ejecución, completado, fallo y reinicio interrumpido.
  Los listados ya no devuelven el error retenido como resumen; las pruebas
  verifican ausencia de ruta y token aun con un error hostil, transición de
  reinicio y repetición solo terminal. Pasaron `backend/tests` y `tools/tests`
  completos, compilación Python, 33 suites/222 pruebas frontend, build con
  presupuesto 320,0/320 KiB, `docker compose config --quiet` y
  `git diff --check`.

### PROD-043 — Confirmación explícita de autorización y alcance de la fuente

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** desarrolladores y empresas deben
  confirmar que poseen o están autorizados para analizar la instantánea antes de
  que Inspectra la convierta en un proyecto, reduciendo uso accidental fuera de
  alcance sin bloquear el flujo de archivo ya soportado.
- **Flujo completo afectado:** archivo validado propio → leer límites del análisis
  pasivo → confirmar autorización → crear proyecto y encolar análisis → dejar
  constancia mínima sin almacenar una justificación sensible.
- **Áreas o archivos implicados:** `backend/app/models.py`, creación de proyecto
  en `backend/app/main.py`, contrato/API y formulario de archivo en frontend,
  pruebas backend/frontend y `docs/product-projects.md`.
- **Criterios de aceptación verificables:** la API rechaza una creación sin
  confirmación explícita o con campos extra; la interfaz presenta una casilla
  asociada a una explicación de alcance y mantiene desactivada la acción hasta
  marcarla. No persiste declaración libre, archivo, ruta ni datos personales
  adicionales; los flujos owner/CSRF existentes se conservan. Pruebas cubren
  rechazo, envío correcto, carga, error y accesibilidad de etiqueta/foco.
- **Riesgos de seguridad, privacidad y operación:** una afirmación implícita no
  evita errores de alcance; una nota libre crearía un canal de datos sensibles;
  romper el contrato bloquearía altas legítimas.
- **Dependencias:** `PROD-001` completada; ninguna infraestructura adicional.
- **Tamaño:** S
- **Estrategia de pruebas:** pruebas de validación FastAPI, contrato de cliente,
  interacción de formulario y regresión de creación owner-scoped.
- **Evidencia de validación al completarse:** 2026-09-05: `POST /projects`
  exige `authorization_confirmed: true` mediante un contrato que prohíbe campos
  extra; la confirmación no se persiste ni admite texto libre. La acción de
  proyecto queda desactivada hasta que la casilla etiquetada se marque y la API
  conserva los controles owner-scoped y CSRF. Las pruebas backend cubren valor
  ausente/falso, fuente no válida, propietario y campos adicionales; las de
  frontend cubren estado desactivado, foco/etiqueta, petición correcta y
  recorrido creado. Pasaron `backend/tests/test_backend.py` completa, las
  33 suites/221 pruebas frontend, build y presupuesto de 320,0/320 KiB; también
  pasó `git diff --check`.

### PROD-044 — Prevuelo seguro de cobertura antes de crear un proyecto

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** antes de invertir tiempo en una
  ejecución, la persona necesita saber de forma honesta qué formatos admite el
  perfil pasivo y qué no se analizará en esa entrega.
- **Flujo completo afectado:** seleccionar archivo → consultar límites y formatos
  públicos → crear proyecto autorizado → interpretar cobertura posterior sin
  confundir una validación de subida con un análisis de seguridad.
- **Áreas o archivos implicados:** catálogo de capacidades del runner, contrato
  público mínimo, interfaz de archivos/proyectos, documentación y fixtures.
- **Criterios de aceptación verificables:** la vista anuncia formatos de archivo,
  manifiestos detectables y límites configurados de forma agregada; no extrae ni
  sube contenido adicional y no promete hallazgos. Si la capacidad no puede
  determinarse, explica la incertidumbre y conserva la acción segura. Pruebas
  cubren configuración deshabilitada, texto accesible y ausencia de rutas/datos
  del archivo.
- **Riesgos de seguridad, privacidad y operación:** una previsión excesiva crea
  falsa seguridad; inspeccionar la fuente dos veces incrementa superficie y
  consumo.
- **Dependencias:** `PROD-035` para cobertura ejecutada; puede iniciar con el
  catálogo estático existente.
- **Tamaño:** M
- **Estrategia de pruebas:** contrato de capacidades y pruebas de interfaz con
  opciones soportadas/no soportadas.
- **Evidencia de validación al completarse:** 2026-09-05: `GET
  /project-analysis-preflight` publica solo un catálogo estático y el límite
  configurado de subida; rechaza cuerpo y parámetros, no abre archivos ni
  recibe su nombre, hash, ruta o contenido. La vista de archivo muestra
  formatos, manifiestos, resolución exacta limitada a `package-lock.json` npm
  v2/v3 y límites explícitos; ante error permite reintentar sin mostrar error
  bruto ni prometer cobertura. Pasaron 2 pruebas backend dirigidas, la suite
  backend/runner y `compileall` en Python 3.12, 37 suites/254 pruebas frontend,
  build con TypeScript y presupuesto (320,0/322 KiB), ambos `docker compose
  config -q` y `git diff --check`. La revisión local reproducible en
  320/768/1440 px no mostró desbordamiento horizontal; no se subió archivo ni
  se contactó una fuente externa.

### PROD-045 — Prueba de aceptación reproducible del recorrido de proyecto

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** mantenedores necesitan detectar una
  regresión que rompa la cadena completa antes de una entrega, no solo pruebas
  unitarias aisladas de API o interfaz.
- **Flujo completo afectado:** autenticarse según modo de prueba → subir fixture
  inocuo → confirmar alcance → crear proyecto → esperar resultado simulado →
  explorar inventario/hallazgos → comparar → exportar informe redactado.
- **Áreas o archivos implicados:** fixtures de proyecto, servidor de prueba,
  pruebas de integración/frontend, documentación de comando local y CI.
- **Criterios de aceptación verificables:** una prueba determinista, sin red ni
  código de terceros, comprueba contrato, autorización y ausencia de secreto en
  vistas/exportación; falla si cambia el orden o falta una transición esencial.
  Se ejecuta en tiempo acotado y documenta qué dobles usa.
- **Riesgos de seguridad, privacidad y operación:** una prueba end-to-end que
  use red o fuentes reales es inestable o filtra información; no probar el flujo
  permite entregar una interfaz conectada a contratos incompatibles.
- **Dependencias:** `PROD-043`, `PROD-004`, `PROD-005`, `PROD-006`, `PROD-024`
  completadas; coordinar con `PROD-037`.
- **Tamaño:** M
- **Estrategia de pruebas:** fixture de archivo sintético, adaptador de runner
  simulado y validación de exportación/redacción en CI.
- **Evidencia de validación al completarse:** 2026-09-05: una única prueba ASGI
  con ZIPs sintéticos y `NoopAuditService` recorre preflight, subida,
  confirmación ausente rechazada, creación autorizada, resultado fixture,
  hallazgos, inventario, informe Markdown, segunda instantánea y comparación.
  No ejecuta archivo, runner ni egress público; comprueba que secreto y ruta de
  host no llegan a respuestas, informe, historial o comparación. Pasaron la
  prueba dirigida, `compileall`, toda la suite `backend/tests tools/tests` en
  Python 3.12 y `git diff --check`. El comando de la aceptación quedó en
  `docs/product-projects.md`; la interfaz conserva sus pruebas con dobles de
  API, sin acoplar la suite ordinaria a red ni a un navegador externo.

### PROD-046 — Enlace de corrección desde resultado a contexto de trabajo

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un desarrollador necesita convertir
  una recomendación ya normalizada en una acción local verificable, sin que
  Inspectra invente cambios de código ni transmita contenido privado a terceros.
- **Flujo completo afectado:** abrir hallazgo → comprender evidencia y alcance →
  copiar recomendación segura/abrir referencia pública → corregir localmente →
  incorporar nueva instantánea y comparar.
- **Áreas o archivos implicados:** contrato normalizado, detalle frontend,
  documentación de remediación, comparación y tests de enlaces/copiar.
- **Criterios de aceptación verificables:** cada acción se muestra solo si hay
  recomendación o referencia HTTPS validada; copiar no incluye evidencia
  redactada inesperada ni rutas retenidas. La interfaz diferencia guía de
  corrección de veredicto de explotación y enlaza al ciclo de nueva instantánea
  cuando `PROD-041` exista. Pruebas cubren referencias inválidas, teclado,
  lectura y estado sin recomendación.
- **Riesgos de seguridad, privacidad y operación:** enlaces no controlados o
  texto de evidencia copiado pueden provocar phishing o exfiltración; sugerir
  una corrección como certeza genera decisiones erróneas.
- **Dependencias:** `PROD-004`, `PROD-023` completadas; `PROD-041` para cerrar
  la verificación dentro del producto.
- **Tamaño:** S
- **Estrategia de pruebas:** contrato de URL, componente de detalle y prueba de
  flujo con referencia permitida y ausente.
- **Evidencia de validación al completarse:** 2026-09-05: el componente
  reutilizable vuelve a validar referencias de contratos retenidos y solo abre
  NVD/CVE, GitHub Advisories u OWASP en sus formas HTTPS canónicas; la guía
  distingue expresamente corrección local de explotación o remediación
  confirmada. El portapapeles recibe únicamente `recommendation`, y la acción
  de nueva instantánea abre el formulario autorizado de `PROD-041` sin crear
  una ejecución. Pasaron 9 pruebas dirigidas de detalle/comparación/URL, 38
  suites/258 pruebas frontend, TypeScript/Vite y presupuesto 310,3/322 KiB,
  `git diff --check` y build local Docker. La revisión visual local verificó
  foco, controles, advertencia y estado vacío de nueva instantánea con el
  fixture pasivo; no hubo subida ni egress.

### Ronda 2 — Módulo 3: inteligencia de vulnerabilidades públicas (2026-09-05)

- **Alcance auditado:** contrato `component_inventory_contract_version`, parser
  de proyecto pasivo, `package.json`/requisitos/pyproject, señales de lockfiles
  del analizador Node separado y las tarjetas `PROD-025`…`PROD-034`. Se contrastó
  el diseño previsto con los contratos de [OSV](https://google.github.io/osv.dev/api/),
  la [API de advisories globales de GitHub](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28)
  y el [catálogo CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- **Decisiones:** el inventario actual es correcto al marcar solo declaraciones;
  no se inferirá una versión desde un rango ni se reutilizará la señal de
  lockfile de otro analizador como evidencia. `PROD-025` inicia el soporte
  pasivo de `package-lock.json` npm v2/v3 y debe conservar el tipo/origen de
  resolución. Ninguna consulta pública, CVSS, KEV o dato de proveedor se crea
  en esta ronda: primero se completan aislamiento de datos, contrato y pruebas
  offline de `PROD-026`…`PROD-029`.
- **Nuevas tareas:** `PROD-047` a `PROD-056`, detalladas inmediatamente después.
- **Criterio de priorización:** exactitud de identidad y versión antes que número
  de fuentes; trazabilidad y resultado “desconocido/no cubierto” antes que un
  falso negativo; mínima salida de datos y fixtures deterministas antes que red.

### PROD-047 — Emparejar manifiesto y lockfile por raíz de proyecto verificable

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo con monorepo necesita que
  una resolución se relacione con su `package.json` correcto, no con un lockfile
  de otro paquete o subárbol.
- **Flujo completo afectado:** archivo → detectar manifiesto/lockfile relativo →
  validar misma raíz y gestor → asociar componente → declarar emparejado, no
  emparejado o ambiguo → inventario y futura correlación.
- **Áreas o archivos implicados:** detector de rutas de archivo, parser npm,
  inventario, contrato de cobertura, documentación y fixtures de monorepo.
- **Criterios de aceptación verificables:** la relación usa solamente rutas
  relativas normalizadas y una política versionada de raíz; lockfiles múltiples,
  workspaces o gestores incompatibles quedan como ambiguos sin aportar una
  versión. La UI muestra el estado de relación sin URL, nombre de host o ruta
  retenida. Tests cubren raíz, subproyecto, traversal, lockfile duplicado y
  propietario cruzado.
- **Riesgos de seguridad, privacidad y operación:** una pareja equivocada acusa
  una versión ajena; exponer el árbol completo revela estructura interna.
- **Dependencias:** `PROD-025`, `PROD-023` completada.
- **Tamaño:** M
- **Estrategia de pruebas:** fixtures de ZIP/TAR con dos raíces y pruebas puras
  de normalización/asociación, sin ejecutar npm.
- **Evidencia de validación al completarse:** pendiente. Se corrigió una
  evidencia heredada que describía el emparejamiento de lockfile de `PROD-047`,
  no el onboarding de esta tarea.

### PROD-048 — Clasificar alcance directo, transitivo y opcional del grafo resuelto

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** seguridad necesita priorizar primero
  componentes directos que el equipo puede actualizar, sin esconder dependencias
  transitivas resueltas ni presentarlas como declaración propia.
- **Flujo completo afectado:** lockfile admitido → extraer nodos exactos →
  etiquetar alcance → correlación → filtros/informe y recomendación acorde.
- **Áreas o archivos implicados:** extractor de lockfile, contrato de componente,
  normalización de hallazgo, panel/informe y fixtures.
- **Criterios de aceptación verificables:** cada nodo tiene `direct`, `transitive`
  u `optional` solo cuando el formato lo prueba; los enlaces/alias y nodos sin
  versión quedan excluidos con motivo. Los filtros y exportación distinguen el
  alcance y no recomiendan actualizar un transitivo como si fuera directo.
- **Riesgos de seguridad, privacidad y operación:** priorización falsa hace que
  el equipo corrija el componente equivocado; una relación de grafo parcial se
  puede confundir con cobertura total.
- **Dependencias:** `PROD-025`, `PROD-047`, `PROD-029`.
- **Tamaño:** L
- **Estrategia de pruebas:** grafos npm sintéticos, ciclos, optional/peer,
  paquete repetido y render/informe sin red.
- **Evidencia de validación al completarse:** 2026-09-05: contrato
  `2026-09-05.6` y grafo npm v2/v3 acotado clasifican exclusivamente alcance
  probado `direct`, `transitive` u `optional`, incluidos grupos opcionales de
  manifiesto. La deduplicación retiene el alcance más accionable sin degradar un
  direct a transitivo; panel, filtro, informe y recomendaciones diferencian la
  cadena/resolución transitiva y la activación opcional. Pasaron 22 pruebas
  backend/runner dirigidas, 11 de frontend dirigidas, la regresión completa
  `backend/tests tools/tests`, `compileall`, ambos Compose con fixture, 36
  suites/237 pruebas frontend, build/presupuesto 314,4/322 KiB y `git diff
  --check`, sin Internet.

### PROD-049 — Política explícita para aliases, workspaces y fuentes no registry

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** quien analiza un monorepo debe saber
  por qué una dependencia local, alias o workspace no se correlaciona, sin que
  el producto oculte datos de topología o intente resolverlos contra un feed
  público.
- **Flujo completo afectado:** componente declarado/resuelto → clasificar fuente
  → excluir o conservar identidad registry → panel/cobertura → resultado de
  correlación seguro.
- **Áreas o archivos implicados:** parseres, `component_inventory.py`, contrato,
  frontend, docs y fixtures con enlaces locales/VCS/URL redactados.
- **Criterios de aceptación verificables:** aliases y workspaces no se convierten
  en nombre público salvo identidad comprobable; VCS/URL/local no conserva
  specifier ni credenciales y presenta `not_correlatable` con razón agregada.
  Tests cubren alias encadenado, URL con token, workspace y salida/exportación.
- **Riesgos de seguridad, privacidad y operación:** una conversión inventada
  causa CVE falsos; retener el specifier filtra hosts, rutas o tokens.
- **Dependencias:** `PROD-025`, `PROD-026`, `PROD-023` completada.
- **Tamaño:** M
- **Estrategia de pruebas:** fixtures mínimos hostiles y aserciones de ausencia
  de secretos en API, logs y UI.
- **Evidencia de validación al completarse:** 2026-09-05: el parser de
  `package-lock` distingue un alias por nombre declarado distinto de su ruta,
  y clasifica enlaces, VCS y URLs fuera de `registry.npmjs.org` como fuentes no
  registry aunque aporten una versión exacta. No se conserva su `resolved`,
  destino de alias, host, token o ruta; el inventario y la correlación los
  marcan localmente como `not_correlatable` sin construir una identidad OSV. El
  resultado de archivo y CycloneDX/SPDX retienen solo la categoría con
  referencia ocultada. La UI explica que esas fuentes no se consultan. Pasaron
  pruebas runner/backend/PVI/egress dirigidas, frontend completo en copia
  temporal offline, `compileall`, la suite completa `backend/tests tools/tests`,
  Compose, `git diff --check`, build de frontend 310,3/322 KiB y backend Docker
  con `/health` correcto; no hubo egress de advisories.

### PROD-050 — Resultado de correlación con cuatro estados verificables

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un usuario debe distinguir “afectado”
  de “no afectado por esta fuente”, “no correlacionable” y “consulta no
  disponible”, para no interpretar una ausencia de alerta como seguridad.
- **Flujo completo afectado:** componente elegible → adaptador/fixture → evaluar
  versión/rango → persistir resultado y fuente/frescura → inventario, hallazgo,
  informe y comparación.
- **Áreas o archivos implicados:** modelos de advisory, evaluador de versiones,
  persistencia, API/UI/reportes, comparación y fixtures.
- **Criterios de aceptación verificables:** los cuatro estados son mutuamente
  excluyentes y explican fuente/fecha/cobertura; solo “afectado” crea un
  hallazgo. Un rango ausente, respuesta inválida o fuente caída no deriva en
  “no afectado”. Pruebas cubren las transiciones, redacción, ID estable y
  comparación sin Internet.
- **Riesgos de seguridad, privacidad y operación:** un negativo injustificado
  oculta riesgo; mezclar estados cambia decisiones de remediación.
- **Dependencias:** `PROD-027`, `PROD-028`.
- **Tamaño:** M
- **Estrategia de pruebas:** tabla determinista de entradas/estados y fixtures
  de respuesta vacía, retirada, inválida y timeout.
- **Evidencia de validación al completarse:** 2026-09-05: el snapshot conserva
  una salida local por componente con cuatro estados excluyentes y razón
  limitada. Solo una coincidencia exacta/rango verificable crea `affected`; una
  respuesta OSV vacía y válida queda `not_affected`, mientras que rango ausente,
  retirada, JSON inválido o fallo de fuente queda `unavailable`. La UI muestra
  conteos y un detalle desplegable con su caveat; el informe exporta los totales
  sin egress. Pasaron 16 pruebas backend dirigidas, la regresión completa
  `backend/tests tools/tests`, `compileall`, ambos Compose, `git diff --check`,
  y 36 suites frontend/235 pruebas con build y presupuesto 314,4/322 KiB. Solo
  fixtures/`MockTransport`, sin Internet. La comparación histórica de estas
  salidas se realizará en `PROD-034`, que ya es la tarea específica del flujo.

### PROD-051 — Política de conflictos, retiro y precedencia de advisories

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** responsables de seguridad necesitan
  entender una discrepancia entre OSV, GHSA, CVE/NVD o un proveedor sin que
  Inspectra fusione rangos incompatibles ni oculte un advisory retirado.
- **Flujo completo afectado:** varias fuentes permitidas → validar registros →
  deduplicar sin pérdida → mostrar conflicto/retiro → seleccionar recomendación
  trazable para detalle e informe.
- **Áreas o archivos implicados:** contrato canónico, normalizador/deduplicador,
  UI de evidencia, exportador, documentación de política y fixtures.
- **Criterios de aceptación verificables:** se retienen fuente y fecha por cada
  afirmación; un conflicto crea estado visible, no una unión de rangos. Un
  advisory retirado conserva motivo/fuente cuando la fuente lo proporciona y no
  se presenta como hallazgo activo sin corroboración vigente. Tests cubren ID
  común, rangos distintos, URL hostil y retirada.
- **Riesgos de seguridad, privacidad y operación:** fusionar datos incompatibles
  inventa evidencia; ocultar una retirada mantiene alertas obsoletas.
- **Dependencias:** `PROD-027`, `PROD-029`, `PROD-032`.
- **Tamaño:** M
- **Estrategia de pruebas:** fixtures multi-fuente creados manualmente con
  procedencia, deduplicación y render/exportación.
- **Evidencia de validación al completarse:** 2026-09-05: OSV permanece como
  evidencia primaria y GHSA como corroboración separada. Se añadió consenso por
  hallazgo y conflictos de versión corregida/CVSS sin combinar rangos ni
  seleccionar una fuente; una retirada GHSA queda como evidencia histórica
  `secondary_withdrawn`, no corroboración activa. Un resultado válido que deja
  de corroborar elimina esa evidencia secundaria, mientras que un fallo de red
  conserva el último snapshot bajo la política `PROD-033`. Las referencias
  GitHub hostiles se descartan. Pasaron 9 pruebas backend dirigidas y la
  regresión completa `backend/tests tools/tests`, `compileall`, ambos Compose y
  `git diff --check`; frontend completo: 36 suites/235 pruebas y build/presupuesto
  314,4/322 KiB. Solo fixtures/`MockTransport`, sin Internet.

### PROD-052 — Validar y acotar respuestas de fuentes públicas

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** la operación debe resistir una
  respuesta malformada, enorme o inesperada de un proveedor sin bloquear una
  auditoría ni almacenar contenido no confiable.
- **Flujo completo afectado:** petición permitida → límite de descarga/tiempo →
  decodificación y validación de esquema → respuesta canónica o cobertura
  degradada → métrica/log seguro.
- **Áreas o archivos implicados:** cliente HTTP/adaptadores, configuración,
  modelos, observabilidad, fixtures y pruebas de límites.
- **Criterios de aceptación verificables:** aplica límite de bytes, tiempo,
  tipo de contenido y número de elementos antes de persistir; descarta HTML,
  campos no esperados y URLs no HTTPS. Los fallos tienen un código seguro y no
  incluyen cuerpo/proyecto/paquete en logs. Tests inyectan payload grande,
  JSON inválido, HTML, redirección y 429 sin red real.
- **Riesgos de seguridad, privacidad y operación:** el feed puede agotar memoria,
  contaminar resultados o servir contenido que acabe como XSS/enlace peligroso.
- **Dependencias:** `PROD-026`, `PROD-027`.
- **Tamaño:** M
- **Estrategia de pruebas:** transporte falso con límites de flujo y pruebas de
  modelo/observabilidad negativas.
- **Evidencia de validación al completarse:** 2026-09-05: el cliente fijo de
  egress exige `Content-Type` JSON antes de aceptar un `200`, valida JSON y una
  forma raíz mínima antes de escribir caché, y limita OSV a la cardinalidad del
  lote y 100 vulnerabilidades por componente, GHSA a un advisory y KEV a 5.000
  entradas. HTML, JSON roto, forma inesperada o colección excesiva se descartan
  sin cuerpo y con códigos controlados; el contrato de frescura los declara
  `invalid_source_data` sin diagnósticos externos. Se invalidó la caché anterior
  con esquema `2026-09-05.2`. Pasaron la suite dirigida de egress/OSV/GHSA/KEV,
  `compileall`, la suite completa `backend/tests tools/tests`, `docker compose
  config --quiet`, `git diff --check` y una reconstrucción de backend con
  `/health` correcto. Las nuevas fixtures usan `httpx.MockTransport`, sin red.

### PROD-053 — Frescura visible y decisión de actualización de inteligencia

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo necesita saber cuándo se
  consultó la información de vulnerabilidades y solicitar una actualización
  segura, sin perder el resultado reproducible original.
- **Flujo completo afectado:** análisis con snapshot de feeds → ver antigüedad →
  elegir refresco permitido → nueva ejecución/snapshot → comparación e informe.
- **Áreas o archivos implicados:** caché, modelos de ejecución, panel de
  componentes/hallazgos, informes, configuración y documentación.
- **Criterios de aceptación verificables:** cada resultado muestra fecha, fuente
  y estado actual/fresco/obsoleto/no disponible según política configurada; un
  refresco no sobrescribe evidencia previa y respeta el presupuesto/egress. Sin
  red explica cómo queda la cobertura. Tests cubren reloj fijo, caché vencida,
  refresco denegado y comparación.
- **Riesgos de seguridad, privacidad y operación:** datos antiguos se usan como
  actuales; sobreescribir impide auditar una decisión pasada o dispara tráfico.
- **Dependencias:** `PROD-033`, `PROD-050`, `PROD-029`.
- **Tamaño:** M
- **Estrategia de pruebas:** reloj/transportes falsos, snapshots cacheados y
  componentes de interfaz con estados de frescura.
- **Evidencia de validación al completarse:** 2026-09-05: cada actualización
  normalizada recibe un identificador opaco y una fecha de retención; la vista
  actual conserva el puntero compatible y cada revisión se guarda de forma
  inmutable, sin cuerpos crudos de proveedor, rutas, código, secretos ni
  identidad de propietario. Los snapshots heredados se migran una única vez al
  primer refresco, el historial expone como máximo 50 metadatos validados y un
  identificador malformado o fuera del análisis propio responde con un `404`
  genérico. El panel permite elegir la última actualización o una retenida,
  explica que la histórica es inmutable, deshabilita consultas públicas en ella
  y exporta Markdown ligado solo al ID opaco elegido; informe y API distinguen
  la revisión actual de la histórica. La retención física de revisiones queda
  explícitamente para `PROD-062`, sin prometer su borrado. Pasaron las pruebas
  dirigidas de historial, aislamiento, informe histórico y controles de
  egress; la suite completa `backend/tests tools/tests` (1.337 pruebas),
  `compileall`, las 38 suites/263 pruebas frontend, TypeScript/Vite y el
  presupuesto de 311,1/322 KiB, `docker compose config --quiet` y `git diff
  --check`. Los transportes de las pruebas son `MockTransport`: no se habilitó
  egress real ni se consultó un proveedor público.

### PROD-054 — Importación controlada de snapshots offline de advisories

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** entornos aislados necesitan
  inteligencia pública reproducible sin autorizar salida desde los análisis.
- **Flujo completo afectado:** administrador obtiene fuente autorizada fuera de
  banda → valida y carga snapshot → análisis consulta solo local → informa
  versión/frescura → expira o reemplaza de forma atómica.
- **Áreas o archivos implicados:** formato de snapshot, comando administrativo,
  validación/integridad, caché, controles de rol futuros, runbook y fixtures.
- **Criterios de aceptación verificables:** importador explícito valida esquema,
  tamaño, checksum/procedencia configurados y publica de forma atómica; nunca
  acepta URL arbitraria ni ejecuta contenido. Un análisis identifica snapshot
  usado o ausencia, y se puede revertir. Tests cubren archivo corrupto, esquema
  hostil, rollback, expiración y no-egress.
- **Riesgos de seguridad, privacidad y operación:** un feed local adulterado
  genera decisiones erróneas; importar sin cuota llena disco o ejecuta datos.
- **Dependencias:** `PROD-027`, `PROD-033`, `PROD-040`.
- **Tamaño:** L
- **Estrategia de pruebas:** fixtures checksum-bound/sintéticos y almacenamiento
  temporal, sin descargar feeds ni usar claves reales.
- **Evidencia de validación al completarse:** 2026-09-09: contrato estricto
  `2026-09-09.1`, importación local por SHA-256 exacto, límites 16 MiB/5.000
  entradas/100 identidades por lote/30 días y publicación/activación atómicas.
  Solo admite respuestas OSV, GHSA, NVD y CISA ya vinculadas a la consulta
  exacta; no acepta URL, host, descarga o ejecución. Las identidades se reducen
  a claves digest y scopes npm privados, JSON duplicado, respuesta parcial o
  cruzada, corrupción y expiración rechazan el bundle entero sin sustituir el
  activo. El flujo owner-scoped ejecuta OSV desde el snapshot con egress `false`,
  persiste el ID/frescura y la UI ofrece la acción local; los servicios GHSA,
  NVD y KEV también respetan la misma frontera offline. El runbook documenta
  formato, operación, rollback, amenazas y que SHA-256 no es firma ni validación
  real del proveedor. Docker Python 3.12 `--network none`: 8 pruebas dirigidas,
  backend completo 1.374/1.374 y runner 451/451; frontend 56 archivos/383
  pruebas, build 291,2/322 KiB; `compileall`, Compose base/privado/aceptación/
  aceptación-egress y diff-check pasaron. No hubo Internet, tokens ni proyecto
  real.

### PROD-055 — Clasificar espacios de nombres privados antes del egress

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una empresa debe impedir que nombres
  de paquetes propios o de un registry privado salgan por defecto a un servicio
  público, aunque la versión sea exacta.
- **Flujo completo afectado:** inventario → política de namespace/allowlist →
  elegible, local o excluido → adaptador → cobertura y auditoría segura.
- **Áreas o archivos implicados:** configuración, normalizador de componentes,
  política de egress, UI de cobertura, tests y guía de despliegue.
- **Criterios de aceptación verificables:** por defecto solo consulta nombres
  públicos inequívocos habilitados; scope/patrón privado configurado queda fuera
  con motivo sin almacenar registry/URL. La configuración se valida y no admite
  comodines que permitan eludir la política. Tests capturan payload y verifican
  scope privado, nombre público, configuración inválida y logs redactados.
- **Riesgos de seguridad, privacidad y operación:** revelar la composición o
  nombre interno de un producto puede ser información sensible comercial.
- **Dependencias:** `PROD-026`, `PROD-028`, `PROD-049`.
- **Tamaño:** M
- **Estrategia de pruebas:** política pura + transporte simulado y documentación
  de valores por defecto seguros.
- **Evidencia de validación al completarse:** 2026-09-05: se añadió
  `INSPECTRA_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES`, desactivada por defecto y
  validada al arranque. Acepta solo reglas locales `exact`, `prefix` y `scope`
  acotadas; rechaza comodines, URL, rutas, credenciales y entradas vacías sin
  incluir la regla en el error. El cliente aplica la política antes de crear un
  payload OSV y los resultados muestran únicamente `private_namespace`. Además,
  para no confundir una declaración con procedencia pública, Módulo 3 solo
  consulta actualmente npm exacto con pareja `package-lock` v2/v3 mismo-root y
  resolución HTTPS de `registry.npmjs.org`; una resolución ausente pasa a
  `unknown` y permanece local. Pruebas `MockTransport` capturaron que React
  público es el único payload mientras prefijos, exactos, PyPI configurado y
  scopes no salen ni aparecen en auditoría; cubrieron configuración inválida y
  ausencia de procedencia. Pasaron `compileall`, backend/runner completo,
  `docker compose config --quiet`, `git diff --check`, frontend offline
  (38 archivos/259 pruebas), build/presupuesto 310,3/322 KiB y reconstrucción
  Docker del backend con `/health` correcto; no hubo consultas a Internet.

### PROD-056 — Gobernanza de fixtures y atribución de datos de advisories

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** mantenedores deben poder reproducir
  pruebas sin convertir fixtures copiados en una fuente opaca, obsoleta o con
  restricciones de redistribución desconocidas.
- **Flujo completo afectado:** seleccionar ejemplo público mínimo → registrar
  fuente/fecha/licencia → reducir/redactar → fixture versionada → prueba de
  contrato y renovación documentada.
- **Áreas o archivos implicados:** árbol de fixtures, metadatos, guardas de
  prueba, documentación de contribución y CI.
- **Criterios de aceptación verificables:** cada fixture de advisory declara
  origen, fecha, propósito y transformación; no contiene respuesta completa
  innecesaria, token, proyecto ni dato personal. Una guarda rechaza fixture sin
  metadatos o red en la suite; el contrato cubre campos ausentes y retirada.
- **Riesgos de seguridad, privacidad y operación:** datos reales/copias grandes
  complican licencias, se pudren y hacen pruebas no deterministas.
- **Dependencias:** `PROD-027`, `PROD-037`.
- **Tamaño:** S
- **Estrategia de pruebas:** validación estática de metadatos y fixtures mínimos
  usados por adaptadores falsos.
- **Evidencia de validación al completarse:** 2026-09-09: manifiesto contractual
  `2026-09-09.1` para las tres fixtures actuales de OSV, GitHub y CISA KEV, con
  proveedor, esquema público HTTPS, fecha, propósito, transformación,
  procedencia/licencia sintética, SHA-256 y cuota. Una prueba descubre cada
  JSON bajo los directorios de proveedor y falla ante omisión, digest distinto,
  exceso o marcadores de credencial. `backend/tests/conftest.py` bloquea DNS y
  conexiones no loopback; la primera suite completa encontró tres pruebas web
  que resolvían dominios de ejemplo y se corrigieron con resolución inyectada.
  Pasaron 126 pruebas dirigidas de gobernanza/adaptadores y después backend
  completo 1.348/1.348 dentro de Docker `--network none`; `compileall` y
  `git diff --check` pasaron. Las fixtures son mínimas, escritas a mano y no
  representan vulnerabilidades reales ni copian respuestas de proveedor.

### Ronda 3 — Seguridad, arquitectura y operación empresarial (2026-09-05)

- **Alcance auditado:** modos de autenticación y perfil de despliegue,
  almacenes de archivos/trabajos/proyectos, ejecución en `BackgroundTasks`,
  límites de runner y archivo, eventos de auditoría, limpieza por retención,
  Docker/Compose, endpoint de salud y runbooks de arquitectura.
- **Decisiones:** la propiedad por operador y los controles CSRF existentes se
  preservan; no se presentará el proceso local ni la cola en memoria como
  recuperación durable o aislamiento multiempresa. La evolución empresarial se
  divide entre postura segura de arranque, datos reproducibles, admisión de
  recursos, integridad, observabilidad y recuperación, antes de organizaciones
  completas o proveedores de identidad.
- **Nuevas tareas:** `PROD-057` a `PROD-064`, detalladas a continuación.
- **Criterio de priorización:** denegar configuración insegura y evitar fuga o
  mezcla de datos antes que añadir capacidad; registrar metadatos mínimos antes
  que contenido; hacer visibles límites y degradación antes que prometer SLA.

### PROD-057 — Perfil de ejecución inmutable por análisis

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una empresa necesita reproducir el
  contexto técnico de un resultado, no solo su hash de archivo, al investigar
  por qué dos ejecuciones del mismo snapshot difieren.
- **Flujo completo afectado:** encolar → capturar contrato y versión de reglas
  junto con límites de admisión → ejecutar → consultar/comparar/exportar →
  retener perfil aun si la configuración cambia después.
- **Áreas o archivos implicados:** modelos de job, configuración,
  almacenamiento, comparación, informes, frontend y fixtures.
- **Criterios de aceptación verificables:** cada análisis registra un perfil
  opaco/versionado con límites y versiones no sensibles; no incluye ruta de
  host, variables, URL, token o secreto. Comparación/informe declaran diferencia
  de perfil y pruebas verifican configuración cambiante, registro legado y
  redacción.
- **Riesgos de seguridad, privacidad y operación:** sin contexto no se puede
  explicar una regresión; capturar configuración cruda filtra infraestructura.
- **Dependencias:** `PROD-002` completada, `PROD-015` para intentos durables.
- **Tamaño:** M
- **Estrategia de pruebas:** reloj/configuración fijados, serialización y
  comparación de perfiles, tests de no filtración.
- **Evidencia de validación al completarse:** `JobExecutionProfile` persiste
  contrato/reglas/perfil/límite de admisión/concurrencia al crear cualquier job,
  rechaza URLs/rutas como identificadores y `JobStore` conserva el valor original
  ante actualizaciones posteriores. La API marca como no comparable dos análisis
  con perfiles de ejecución distintos y limita de forma explícita los históricos
  sin perfil; los informes y el detalle de archivo muestran un resumen mínimo.
  Pasaron `python -m pytest backend/tests/test_execution_profile.py
  backend/tests/test_backend.py -q` con el entorno Python 3.12 validado,
  `python -m pytest tools/tests/test_developer_workflow_static.py -q` (4),
  `docker compose config --quiet`, `git diff --check`, la suite frontend
  (38 archivos/261 pruebas) y build (310,6 KiB/322 KiB). La revisión local del
  ZIP sintético documentado confirmó el perfil real a 980 y 640 px sin
  desbordamiento horizontal; egress público permaneció desactivado.

### PROD-058 — Admisión y cuota de recursos por propietario

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** varios operadores necesitan que un
  archivo grande o una ráfaga de un propietario no impida analizar a los demás
  ni supere el presupuesto del despliegue.
- **Flujo completo afectado:** solicitar análisis → evaluar cuota/concurrencia →
  encolar o rechazar con causa recuperable → liberar reserva en terminal/reinicio
  → observar capacidad sin exponer identidad.
- **Áreas o archivos implicados:** stores/cola, configuración, rutas de creación,
  observabilidad, UI de estado y documentación.
- **Criterios de aceptación verificables:** límites globales y por propietario
  configurables se aplican atómicamente; doble solicitud y reinicio no dejan
  reserva. La respuesta declara un código/acción segura, no número de usuarios
  ni datos ajenos. Tests cubren carrera, cuota, liberación, owner cruzado y
  configuración inválida.
- **Riesgos de seguridad, privacidad y operación:** agotamiento o hambre de
  recursos; exponer capacidad por usuario facilita inferencia o abuso.
- **Dependencias:** `PROD-008` y `PROD-015` completadas; el propietario local
  actual permite aplicar la cuota. `PROD-012` será obligatorio antes de
  presentarla como cuota multiusuario o por organización.
- **Tamaño:** L
- **Estrategia de pruebas:** store concurrente simulado, reinicio, límites y
  pruebas de UI/API de rechazo recuperable.
- **Evidencia de validación al completarse:** 2026-09-06: dos límites positivos
  y acotados (`INSPECTRA_AUDIT_MAX_INFLIGHT_JOBS=128` y
  `...PER_OWNER=32`) forman parte del perfil inmutable `2026-09-06.2`; el de
  propietario no puede superar al global. `JobStore` cuenta
  `queued/running/cancelling` bajo el mismo lock que persiste un trabajo, sin
  reserva separada: un terminal libera capacidad y recrear el store conserva
  la decisión. El rechazo `429`/`Retry-After: 5` tiene mensaje accionable fijo,
  evento mínimo y no revela conteos/actividad ajena. La creación inicial hace
  preflight antes de persistir el proyecto; el control atómico se repite al
  crear el job. Se probaron límite por propietario, otro propietario admitido,
  límite global, recreación/reinicio, liberación, dos hilos simultáneos,
  configuración inválida, proyecto sin registro parcial y alerta UI. Pasaron
  1.011/1.011 backend en 15,56 s, 412/412 runner/estáticas en 5,39 s,
  38 archivos/272 pruebas frontend en 19,33 s, build/presupuesto 311,6/322 KiB,
  `compileall`, Compose base/privado y `git diff --check`; sin Internet ni
  proyecto real. La atomicidad integral snapshot+job que quedaba separada se
  completó después en `PROD-073`; no se atribuye retrospectivamente a esta cuota.

### PROD-059 — Verificador de postura segura al iniciar despliegues no locales

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** quien autohospeda debe recibir un
  fallo explicable antes de exponer una instancia con autenticación, cookies,
  CORS o persistencia incompatibles con su perfil de despliegue.
- **Flujo completo afectado:** definir perfil/configuración → validar al iniciar
  → arrancar o denegar con diagnóstico de campo seguro → consultar guía de
  corrección → repetir validación en CI/Compose.
- **Áreas o archivos implicados:** `config.py`, Compose/deploy, health/readiness,
  docs de despliegue, pruebas y comandos de validación.
- **Criterios de aceptación verificables:** `trusted_local` queda explícito; un
  perfil no local exige auth configurada, sesión/cookie segura tras proxy TLS,
  origen CORS concreto y rutas persistentes con permisos definidos. No imprime
  valores secretos; pruebas cubren combinaciones válidas, fallidas y valores
  heredados. La comprobación no hace red externa.
- **Riesgos de seguridad, privacidad y operación:** una configuración de demo
  publicada permite acceso no autenticado, CSRF/CORS débil o pérdida de datos.
- **Dependencias:** `PROD-012` para equipo completo; puede avanzar con los modos
  actuales y documentación de `PROD-040`.
- **Tamaño:** M
- **Estrategia de pruebas:** matriz de configuración, Compose config y guía de
  recuperación; sin exponer secretos en snapshots de error.
- **Evidencia de validación al completarse:** `backend/app/config.py` mantiene
  `trusted_local` explícito y exige, para `private_tls_proxy`, el administrador
  autohospedado, cookie segura, CORS HTTPS concreto, retención positiva, estado
  `sqlite` y una base resuelta bajo `INSPECTRA_DATA_DIR`. `ensure_directories()`
  crea/valida los directorios persistentes gestionados a `0700` y rechaza
  permisos de grupo/mundo en el perfil privado. La documentación indica crear
  `data` a `0700` y no incluye valores secretos. Pasaron 9 pruebas dirigidas
  `private_tls_proxy_profile`, `compileall` y la suite backend/runner completa
  en un entorno temporal Python 3.12, los dos `docker compose config -q`,
  `docker compose up --build --no-deps backend` con `/health` 200, una carga
  aislada de la imagen con volumen temporal `0700` y `git diff --check`.

### PROD-060 — Señales de salud, preparación y degradación sin contenido sensible

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** operaciones necesitan distinguir un
  servicio vivo de uno que puede aceptar análisis, almacenar resultados y hablar
  con sus dependencias internas sin abrir una consola de datos.
- **Flujo completo afectado:** arranque → readiness → ejecutar/retener → fallo de
  dependencia → monitorizar/alertar → recuperar con evidencia segura.
- **Áreas o archivos implicados:** health, runner interno, stores, métricas/logs,
  Compose y runbook.
- **Criterios de aceptación verificables:** rutas separadas de vida/preparación
  declaran estado agregado de almacenamiento, runner, cola y limpieza; no
  incluyen host, ruta, configuración, owner ni error bruto. Timeouts/degradación
  tienen códigos y pruebas de fallo/recuperación.
- **Riesgos de seguridad, privacidad y operación:** una sonda demasiado rica
  filtra topología; una demasiado pobre oculta una instancia incapaz de servir.
- **Dependencias:** `PROD-015`, `PROD-058`.
- **Tamaño:** M
- **Estrategia de pruebas:** dependencias simuladas, timeout, respuesta mínima y
  prueba de Compose/readiness.
- **Evidencia de validación al completarse:** 2026-09-06: `/health` conserva
  liveness mínimo y el nuevo `/ready` verifica almacenamiento privado, ambos
  runners internos con destinos fijos, capacidad global de admisión y ausencia
  de admisiones/workspaces huérfanos. Usa timeout configurable acotado a 5 s,
  no hereda proxies, no sigue redirecciones y limita la respuesta a 4 KiB. API
  y logs solo declaran estados agregados, sin host, ruta, configuración,
  propietario, conteo ni error bruto. Pruebas cubren recuperación, timeout,
  storage no escribible, cola saturada, orphan, redirect, respuesta grande o
  incompatible, query/cuerpo hostil y limpieza de la sonda. Pasaron
  1.030/1.030 backend (15,42 s), 420/420 runner/guardas (6,08 s), `compileall`,
  Compose base/privado y diff, sin omisiones. Un smoke local aislado confirmó
  `ready` → runner caído/`not_ready` manteniendo `/health` → `ready` al
  recuperar; recursos temporales y logs se revisaron y limpiaron. El primer
  intento, con una única red Docker interna inaccesible desde el host, se
  descartó como evidencia y no se atribuyó al sandbox. No hubo Internet,
  proveedor ni proyecto real.

### PROD-061 — Integridad verificable de resultados retenidos

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** seguridad y auditoría necesitan
  detectar una modificación accidental o manual de resultados antes de confiar
  en un informe, comparación o excepción.
- **Flujo completo afectado:** normalizar/redactar resultado → calcular digest
  versionado → persistir → leer/exportar/comparar → verificar o señalar
  integridad desconocida en legado.
- **Áreas o archivos implicados:** almacenamiento de jobs/proyectos, modelos,
  exportadores, auditoría, migración y tests.
- **Criterios de aceptación verificables:** digest se calcula sobre representación
  canónica ya redactada y metadatos mínimos; una discrepancia bloquea exportación
  sensible y devuelve causa segura. Registros antiguos declaran estado de
  integridad desconocido, no válido. Tests cubren alteración, orden JSON,
  redacción y propietario.
- **Riesgos de seguridad, privacidad y operación:** evidencia alterada cambia
  decisiones; hashear entradas antes de redacción puede propagar secretos.
- **Dependencias:** `PROD-003`, `PROD-057`, estrategia de migración `PROD-040`.
- **Tamaño:** M
- **Estrategia de pruebas:** JSON canónico, mutación simulada, exportación y
  compatibilidad de resultado legado.
- **Evidencia de validación al completarse:** 2026-09-09: sello SHA-256
  versionado sobre el resultado ya redactado y sus metadatos de pertenencia y
  ejecución. La envolvente no se expone; API/UI/informe solo distinguen
  `valid` y `unknown`. Una alteración de resultado o propietario devuelve `409`
  genérico antes de validar el modelo y bloquea todo consumidor del store; el
  legado sin sello queda explícitamente desconocido. Pruebas cubren redacción,
  orden JSON, manipulación, legado y metadato inválido sin fuga de ruta. Pasaron
  44 pruebas dirigidas y 1.380/1.380 backend completas en Docker Python 3.12
  sin red, además de `compileall`, Compose base/privado/aceptación/egress y
  `git diff --check`. Frontend completo 56/383 y build 291,2/322 KiB ya habían
  pasado con la presentación del estado; runner 451/451 no cambió. Runbook:
  `docs/result-integrity.md`. No hubo Internet ni publicación.

### PROD-062 — Clasificación de datos y alcance de retención por derivado

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** administración necesita conocer y
  configurar cuánto conserva de fuente, resultado, inventario, informe, caché y
  evento, en lugar de inferirlo del borrado de una subida.
- **Flujo completo afectado:** crear dato → clasificar/sellar retención → mostrar
  alcance → expirar/borrar → auditar metadato mínimo → restaurar según política.
- **Áreas o archivos implicados:** settings/stores, informes/caché, UI de
  proyecto, auditoría y runbooks.
- **Criterios de aceptación verificables:** cada derivado tiene clase/retención
  documentada; limpieza es idempotente y no borra otro propietario. La interfaz
  separa fuente eliminada de resultado conservado y no promete borrado de una
  descarga externa. Tests cubren expiración, job activo, informes y aislamiento.
- **Riesgos de seguridad, privacidad y operación:** retención indefinida de
  composición o borrado prematuro de trazabilidad.
- **Dependencias:** `PROD-036`, `PROD-040`, `PROD-013`.
- **Tamaño:** L
- **Estrategia de pruebas:** reloj fijo, datos de cada clase, limpieza/reintento
  y documentación de recuperación.
- **Evidencia de validación al completarse:** 2026-09-06: el contrato
  `2026-09-06.2` clasifica exactamente 14 clases con almacenamiento,
  sensibilidad, relación de retención, disparadores, backup y restore. Distingue
  fuente/resultado/proyecto, inventario y snapshot embebidos, caché pública,
  exportación no persistida, workspaces/journals efímeros, auditoría,
  autenticación/identidad y backup externo. La API no expone rutas, nombres,
  paquetes ni conteos. La revisión corrigió una garantía falsa: el restore
  descarta sesiones/intentos/invitaciones, pero conserva usuarios y membresías.
  Pasaron 22 pruebas backend dirigidas tras esa corrección, 63 frontend
  dirigidas, 1.087/1.087 backend (23,34 s; 88.540 KiB RSS), 420/420
  runner/guardas (6,06 s; 68.008 KiB RSS) y 44 archivos/304 pruebas frontend
  (21,27 s; 579.760 KiB RSS), además de build/presupuesto 317,2/322 KiB
  (7,92 s), `compileall`, Compose base/privado y diff. La revisión local a
  1440×1000 y 390×844 confirmó 14 cards, agrupación, ausencia de desborde y foco
  de 3 px; no se ejecutó la purga. Un comando de sincronización no llegó a
  pruebas por ruta relativa errónea y un arranque visual no llegó a iniciar por
  omitir el paquete local del runner; ambos se repitieron correctamente y no se
  atribuyeron al sandbox. No hubo Internet, proveedor, proyecto real ni
  despliegue y no se afirma consola limpia. Se descubrió `PROD-124` para la
  purga/offboarding de identidad aún no implementada.

### PROD-063 — Exportación general redactada de la bitácora protegida

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** `PROD-013` ya implementó registro,
  retención y consulta protegida; queda permitir a un administrador exportar
  esa vista general mínima para investigación offline sin ampliar sus campos.
- **Flujo completo afectado:** filtro cerrado de actividad general → preflight
  con periodo/conteos → confirmación → JSON/CSV redactado → evento de exportación.
- **Áreas o archivos implicados:** `product_audit.py`, API/modelos,
  `ProductAuditPanel`, reporting, runbook y pruebas.
- **Criterios de aceptación verificables:** exportación org-scoped, paginada o
  acotada, ligada a periodo/filtro cerrado y digest; contiene solo los campos
  allowlist ya visibles. Excluye nombres, cuerpo, evidencia, rutas, targets,
  tokens y texto libre; exige administrador y confirmación. Fixtures cubren dos
  organizaciones, truncado, retención, corrupción y fallo de render.
- **Riesgos de seguridad, privacidad y operación:** sin bitácora no se investiga
  abuso; registrar demasiado se vuelve exfiltración persistente.
- **Dependencias:** `PROD-013`, `PROD-012`, `PROD-062`.
- **Tamaño:** S
- **Estrategia de pruebas:** eventos sintéticos, redacción negativa, autorización
  y retención; no usar logs de producción.
- **Evidencia de validación al completarse:** reconciliación inicial
  2026-09-09: `PROD-013` ya cubría store `0600`, redacción allowlist,
  orden/paginación, retención, capacidad, rol administrador, dos tenants y fallo
  de escritura; la exportación existente estaba limitada a Active. Cierre
  2026-09-10: contrato general `2026-09-10.1` con preflight de cinco minutos
  ligado por SHA-256 a periodo, filtro exacto y proyección; `POST` con
  confirmación y rechazo de snapshot vacío, cambiado o caducado; máximo 1.000
  eventos/1 MiB; pseudónimos estables por organización y omisión de organización,
  IDs originales, correlación, metadata, nombres, rutas, targets, fuente y
  evidencia. API/JSON/CSV, cabecera de digest, evento mínimo, UI accesible,
  estados vacío/error y documentación quedaron alineados. Pasaron 13 pruebas
  backend dirigidas y 24 frontend/CSS; backend completo 1.548/1.548 en
  contenedor de solo lectura y sin red, frontend 58 archivos/410 pruebas, build
  y presupuesto inicial 299,1/322 KiB, `compileall`, Compose y
  `git diff --check`. El primer intento backend con `/tmp` artificialmente
  limitado a 256 MiB falló primero en
  `test_terminal_retention_is_indexed_batched_retryable_and_race_safe` con
  `database or disk is full`; al repetir íntegramente con 2 GiB terminó sin
  fallos. No se usaron datos reales, proveedores ni egress.

### PROD-064 — Ensayo de recuperación de datos y configuración operativa

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo no puede afirmar que hay
  backup o despliegue recuperable hasta ejecutar una restauración controlada y
  medir el procedimiento sobre datos sintéticos.
- **Flujo completo afectado:** crear fixture → exportar backup/configuración →
  restaurar aislado → verificar ownership, hashes y retención → destruir
  entorno temporal → actualizar runbook.
- **Áreas o archivos implicados:** scripts de `PROD-040`, Compose/deploy,
  almacenamiento, runbook y CI manual controlada.
- **Criterios de aceptación verificables:** ensayo no usa archivos de usuario ni
  secretos, verifica fallo de checksum y rollback, y documenta duración medida
  como evidencia, no SLA. No genera acceso de red ni modifica instancia activa.
- **Riesgos de seguridad, privacidad y operación:** un backup no probado falla
  durante incidente; un ensayo sobre datos reales amplía exposición.
- **Dependencias:** `PROD-040`, `PROD-062`.
- **Tamaño:** M
- **Estrategia de pruebas:** contenedor/directorio temporal, fixture de dos
  propietarios, corrupción y limpieza comprobable.
- **Evidencia de validación al completarse:** 2026-09-06: se añadió
  `app.backup_cli drill`, un ensayo que no acepta directorios de datos ni
  archivos de usuario y crea una fixture fija de dos propietarios dentro de un
  workspace `0700` bajo un padre atestado como cifrado. El flujo crea/verifica
  el backup, corrompe una copia, exige `checksum_mismatch` sin publicar target,
  restaura la copia válida, valida fuente/proyecto/job por owner, bytes de
  fuente, triage, auditoría, snapshot de inteligencia, 14 clases de retención,
  egress deshabilitado y revocación de una sesión y una invitación. El origen
  permanece idéntico para rollback y el workspace se elimina antes de emitir
  JSON; la salida no contiene paths, nombres, IDs, hashes ni material de acceso.
  El ensayo manual produjo 13 archivos/132.546 bytes, cero registros perdidos,
  398,012 ms internos y 0,78 s de proceso; son observaciones, no RPO/RTO ni SLA.
  Pasaron 23 pruebas dirigidas, incluidas guardas que bloquean cualquier conexión
  de red, y la suite backend completa 1.093/1.093 en 25,01 s (87.512 KiB).
  También pasaron runner/guardas 420/420 en 6,12 s, frontend 44 archivos/306
  pruebas y build 317,4/322 KiB de la iteración previa, `compileall`, Compose
  base/privado y `git diff --check`. No se usó Internet, proveedor, dato real,
  instancia activa ni despliegue. En ese punto `PROD-116` quedó desbloqueada;
  su acta posterior ya validó arranque/TLS/readiness por separado y no lo
  infirió de este ensayo.

### Ronda 4 — Valor de producto, colaboración e integración (2026-09-05)

- **Alcance auditado:** comparación de ejecuciones, informes, contratos de
  hallazgos, historial de proyecto, acciones disponibles para archivo/proyecto y
  roadmap de organizaciones, decisiones, CI e integración. Se contrastó con las
  prácticas de detalle y resolución de alertas de
  [GitHub Code Scanning](https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning-alerts)
  y excepciones revisables de [Snyk](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/ignore-issues),
  sin adoptar sus productos ni enviarles datos.
- **Decisiones:** primero se completa el ciclo local “corregir → nueva
  instantánea → comparar” de `PROD-041`; líneas base, triage e integraciones
  solo pueden apoyarse en ejecuciones reproducibles y controles de identidad.
  No se crearán webhooks, tokens de CI ni conexiones de terceros antes de su
  permiso mínimo, rotación, redacción y trazabilidad.
- **Nuevas tareas:** `PROD-065` a `PROD-072`, detalladas a continuación.
- **Criterio de priorización:** el bucle de corrección local y la interpretación
  de regresiones preceden a automatización; los contratos interoperables y datos
  mínimos preceden a conectores; una excepción nunca oculta el hallazgo origen.

### PROD-065 — Línea base explícita y política de regresión por proyecto

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo necesita elegir qué
  ejecución representa su punto de partida y ver regresiones respecto a ella,
  sin tratar cualquier historial como una política de calidad implícita.
- **Flujo completo afectado:** seleccionar ejecución compatible → confirmar línea
  base → analizar nueva instantánea → comparar → clasificar regresión/cobertura
  degradada → mostrar en informe y futura automatización.
- **Áreas o archivos implicados:** modelos de proyecto/comparación, autorización,
  UI, informes, auditoría y fixtures.
- **Criterios de aceptación verificables:** una base pertenece al mismo proyecto,
  perfil y propietario; cambiarla deja evento/versionado sin alterar resultados.
  La comparación distingue nuevo/resuelto/persistente de no comparable y no
  permite ocultar truncamiento o cambio de cobertura. La política se borra al
  eliminar su análisis, pero no al eliminar solo los bytes fuente. Tests cubren
  base ajena, legado sin perfil, perfil distinto, fuente expirada y UI de
  confirmación/selección por defecto.
- **Riesgos de seguridad, privacidad y operación:** una base manipulable oculta
  regresiones; una base global mezcla proyectos o propietarios.
- **Dependencias:** `PROD-005`, `PROD-041`, `PROD-057`.
- **Tamaño:** M
- **Estrategia de pruebas:** dos snapshots/profile, owner cruzado, transiciones y
  reportes sin red.
- **Evidencia de validación al completarse:** 2026-09-05: `ProjectRecord`
  conserva `baseline_analysis_id`, versión monotónica y fecha. Las rutas
  owner-scoped `POST`/`DELETE /projects/{project_id}/baseline` solo aceptan una
  ejecución completada y perfilada del mismo proyecto; un legado o ID ajeno se
  rechaza sin revelar datos. Cambiar/retirar no altera resultados y deja evento
  mínimo; al borrar el job o purgarlo, el store limpia la política sin dejar
  referencia colgante. La comparación identifica `uses_saved_baseline`, conserva
  límites de perfil, truncamiento y fuente eliminada; el informe muestra solo
  estado/versión de la política. El panel guarda/limpia, elige la base retenida
  al cargar/refrescar y presenta carga, error y política obsoleta. Pasaron las
  suites completas backend/runner en Python 3.12, `compileall`, 38 archivos/262
  pruebas frontend, build (311,0/322 KiB), `docker compose config --quiet` y
  `git diff --check`. La revisión Compose con fixture sintético comprobó la
  política guardada, selección posterior y ausencia de desborde a 1265/640 px;
  detalle en `docs/frontend-visual-review.md`.

### PROD-066 — Triage de hallazgos con decisión local y fecha de revisión

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** incluso antes de equipos completos,
  un propietario necesita registrar por qué un indicador se está revisando,
  fue resuelto o necesita una excepción temporal, sin editar el resultado base.
- **Flujo completo afectado:** detalle → elegir estado → motivo acotado/fecha →
  lista/comparación/informe → revisión/caducidad → reapertura por nueva evidencia.
- **Áreas o archivos implicados:** evolución inicial de `PROD-011`, modelos de
  decisión, API owner-scoped, UI, auditoría y fixtures.
- **Criterios de aceptación verificables:** las decisiones son anexos inmutables
  al ID/huella del hallazgo, exigen motivo limitado y actor/hora; una excepción
  vencida se destaca y no elimina hallazgo. Tests cubren transición inválida,
  acceso cruzado, redacción y exportación.
- **Riesgos de seguridad, privacidad y operación:** silenciar indicadores sin
  caducidad crea puntos ciegos; comentarios abiertos pueden recibir secretos.
- **Dependencias:** `PROD-011`, `PROD-013`, `PROD-012` para colaboración total.
- **Tamaño:** L
- **Estrategia de pruebas:** modelo de estados, API/UI, reloj fijo, límites de
  comentario y comparación con decisión caducada.
- **Evidencia de validación al completarse:** 2026-09-06: reconciliada con el
  vertical completo de `PROD-011`. La decisión local owner-scoped, el reloj
  controlable, la caducidad/reapertura, la cadena append-only, la redacción,
  la comparación y la exportación ya están implementadas y validadas. La
  consulta empresarial y retención de la bitácora de acciones siguen en
  `PROD-013`; no se duplican dentro del triage.

### PROD-067 — Tokens de automatización con alcance y caducidad mínimos

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una integración autorizada necesita
  iniciar o leer un análisis sin reutilizar una sesión humana ni poder acceder a
  todos los proyectos.
- **Flujo completo afectado:** administrador crea token con proyecto/acciones y
  expiración → CI lo usa → API autoriza/deniega → revocar → auditar uso.
- **Áreas o archivos implicados:** auth, almacenamiento de secreto con hash,
  autorización, UI/admin, auditoría, docs y tests.
- **Criterios de aceptación verificables:** token se muestra una sola vez,
  almacenado solo como hash, tiene alcance de proyecto/acción/fecha y revocación
  inmediata. No aparece en URL/log/exportación ni cruza propietarios; tests
  cubren expirado, scope, revocación y rate limit.
- **Riesgos de seguridad, privacidad y operación:** un token amplio o persistente
  permite exfiltrar resultados o ejecutar trabajo no autorizado.
- **Dependencias:** `PROD-012`, `PROD-013`, `PROD-019`.
- **Tamaño:** L
- **Estrategia de pruebas:** hashes/fixtures, auth middleware, UI de una sola
  visualización y log redaction.
- **Evidencia de validación al completarse:** reconciliada 2026-09-09 con
  `PROD-133` y `PROD-157`: secreto visible una vez, hash con separación de
  dominio, organización/proyecto/scopes, TTL 5 minutos–90 días, 600 peticiones
  por hora, máximo dos activos durante rotación, revocación inmediata,
  retención y auditoría mínima. Las regresiones backend de token y aislamiento
  pasaron dentro del grupo 30/30 sin red.

### PROD-068 — Contrato de integración con salida mínima y versionada

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** equipos necesitan automatizar sin
  depender del HTML de la interfaz ni recibir datos de archivo, rutas privadas o
  evidencia sensible.
- **Flujo completo afectado:** análisis terminado → seleccionar esquema → emitir
  JSON/SARIF acotado → consumir en CI/gestor → validar versión y cobertura.
- **Áreas o archivos implicados:** normalizador, serializadores, API/CLI futura,
  documentación de esquema, fixtures y pruebas de compatibilidad.
- **Criterios de aceptación verificables:** cada salida tiene versión, origen,
  cobertura y límites; SARIF/JSON omite source bytes, tokens, rutas retenidas y
  referencias no HTTPS. Cambios incompatibles requieren versión nueva; fixtures
  validan esquema y consumidor simulado.
- **Riesgos de seguridad, privacidad y operación:** salida rica filtra proyecto;
  un contrato inestable rompe CI silenciosamente.
- **Dependencias:** `PROD-003`, `PROD-019`, `PROD-023`, `PROD-029`.
- **Tamaño:** M
- **Estrategia de pruebas:** snapshots de esquema, entradas hostiles y validación
  de consumidor sin red.
- **Evidencia de validación al completarse:** reconciliada 2026-09-09 con
  `PROD-134`–`PROD-136` y `PROD-155`: admisión ligada a commit/digest, policy y
  salida versionadas, límites explícitos y JSON/SARIF sin bytes, tokens ni rutas
  inseguras. El esquema SARIF 2.1.0 oficial está fijado y validado offline. En
  `PROD-239` pasaron 29 pruebas CLI funcionales y las pruebas backend de replay,
  scope y redacción incluidas en el grupo 30/30, sin red.

### PROD-069 — Exportación SARIF de indicadores normalizados con trazabilidad

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** desarrolladores quieren abrir los
  mismos resultados redactados en herramientas que entienden SARIF, sin afirmar
  que una heurística es una vulnerabilidad confirmada.
- **Flujo completo afectado:** ejecución compatible → validar hallazgo/lugar →
  mapear a SARIF → descargar autorizado → importar localmente y volver a detalle.
- **Áreas o archivos implicados:** normalización, reportes, rutas/exportación,
  pruebas de esquema y documentación.
- **Criterios de aceptación verificables:** rule ID, severidad/confianza,
  ubicación solo segura, recomendación y referencias permitidas se mapean con
  taxonomía que declara “review indicator”. Sin ubicación/contrato no exporta
  dato inventado; tests cubren redacción, owner, JSON válido y compatibilidad.
- **Riesgos de seguridad, privacidad y operación:** una ubicación insegura o
  nivel inflado contamina otra herramienta y filtra datos.
- **Dependencias:** `PROD-003`, `PROD-006`, `PROD-023`, `PROD-068`.
- **Tamaño:** M
- **Estrategia de pruebas:** fixtures de hallazgo con/sin ruta, validador SARIF y
  descarga owner-scoped.
- **Evidencia de validación al completarse:** reconciliada 2026-09-09 con
  `PROD-136` y `PROD-155`. El renderer limita 1.000 resultados, usa taxonomía de
  indicador de revisión, conserva rule/severidad/confianza/recomendación y solo
  emite ubicaciones relativas seguras; el esquema OASIS 2.1.0 fijado valida
  vacío, desconocido y límite. La suite funcional CLI pasó 29/29 en el runtime
  offline actual; la validación de esquema queda trazada por `PROD-155` porque
  la imagen local disponible no incluye `jsonschema`.

### PROD-070 — Modo CI determinista para instantáneas explícitamente autorizadas

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un repositorio propio necesita
  ejecutar un análisis acotado en pipeline sin checkout remoto de Inspectra ni
  configuración opaca de fallo.
- **Flujo completo afectado:** CI empaqueta archivo autorizado → token scoped →
  perfil/línea base → espera resultado → salida versionada/política → artefacto
  redactado y limpieza.
- **Áreas o archivos implicados:** CLI/API, tokens, límites, contratos,
  documentación de CI y fixtures de pipeline.
- **Criterios de aceptación verificables:** no imprime token ni archivo, requiere
  confirmación/alcance explícito y usa perfil/base identificados. Tiempo de espera,
  fallo de red y cobertura parcial tienen códigos claros; pruebas simulan CI sin
  proveedor real.
- **Riesgos de seguridad, privacidad y operación:** CI puede filtrar fuente o
  bloquear entregas por una política no reproducible.
- **Dependencias:** `PROD-019`, `PROD-067`, `PROD-065`, `PROD-068`.
- **Tamaño:** L
- **Estrategia de pruebas:** pipeline fixture, token falso, timeout, baseline y
  salida sin secretos.
- **Evidencia de validación al completarse:** reconciliada 2026-09-09 con
  `PROD-134`–`PROD-136`: snapshot commit-bound, token solo desde entorno,
  idempotencia/replay, baseline y perfiles `observe|standard|strict`, estados
  `pass|fail|inconclusive` y códigos estables para timeout/API/policy. Ningún
  comando imprime token o ejecuta el proyecto. Pasaron 29 pruebas CLI
  funcionales en Python 3.12/Git y contenedor sin red.

### PROD-071 — Entrega de eventos a integraciones con firma y reintento seguro

- **Prioridad:** P3
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo puede sincronizar eventos
  mínimos de análisis/estado sin otorgar acceso de lectura continuo al producto.
- **Flujo completo afectado:** configurar destino permitido → evento terminal →
  firmar payload mínimo → entregar/reintentar → registrar resultado → revocar.
- **Áreas o archivos implicados:** configuración segura, worker durable,
  criptografía/secrets, auditoría, UI/docs y pruebas de transporte.
- **Criterios de aceptación verificables:** destinos HTTPS allowlisted, secreto
  rotado y payload versionado sin evidencia/ruta/archivo; firma, timeout,
  reintento/idempotencia y desactivación se prueban con receptor falso. No se
  habilita mientras la cola no sea durable.
- **Riesgos de seguridad, privacidad y operación:** SSRF, fuga de hallazgos o
  reintentos que duplican tickets.
- **Dependencias:** `PROD-015`, `PROD-026`, `PROD-067`, `PROD-068`.
- **Tamaño:** L
- **Estrategia de pruebas:** receptor local falso, firma/caducidad, 429/timeout y
  ausencia de red externa.
- **Evidencia de validación al completarse:** **2026-09-11:** contrato
  `2026-09-11.1` y vertical opt-in para `analysis.terminal`. Un estado terminal
  de proyecto crea un único evento determinista con IDs opacos, UTC, estado y
  conteo agregado opcional; se excluyen organización, nombres, fuente, hashes,
  componentes, hallazgos, evidencia, errores, rutas, targets y credenciales.
  Outbox SQLite `0600`, lease de 30 s, recuperación tras reinicio, máximo cinco
  intentos y retención 30/90 días; HMAC-SHA256 sobre bytes exactos, key ID y
  receptor idempotente. La configuración todo-o-nada está apagada por defecto y
  solo admite una URL HTTPS:443 cuyo host coincide con la allowlist del operador.
  Transporte con resolución pública previa, `trust_env=false`, cero redirects,
  5 s/8 KiB y concurrencia dos (máximos 10 s/cuatro). `429`, `5xx`, timeout y red
  reintentan; `4xx`, redirect, respuesta excesiva o resolución privada agotan de
  forma controlada. Un endpoint/UI solo-admin muestra conteos tenant-scoped sin
  destino, payload ni IDs. Backend completo 1.649/1.649 (446,66 s; 405.876 KiB
  RSS) y 20/20 regresiones finales tras añadir purga; frontend serial 62
  archivos/429 pruebas (135,03 s), axe dirigido y build 305,3/322 KiB;
  `compileall`, Compose base/privado, release y diff-check verdes. La CLI vigente
  pasó 66/66 en Python 3.12.13. Revisión visual local escritorio/móvil confirmó
  apagado, copy de privacidad y jerarquía; runtime y servicios sintéticos fueron
  eliminados. Todo receptor fue `MockTransport`: **no existe validación contra
  un receptor real** ni hubo egress, push, PR o despliegue. Contrato operativo en
  `docs/signed-integration-events.md`; la custodia/replay después de restore se
  separa en `PROD-252`.

### PROD-252 — Custodia y replay controlado del outbox de integraciones

- **Prioridad:** P3
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** operación necesita decidir qué hacer
  con entregas agotadas y conservar una recuperación coherente sin duplicar
  tickets ni convertir el outbox en una exportación sensible.
- **Flujo completo afectado:** fila `dead` o backup → preflight agregado →
  corregir receptor/rotar clave → replay explícito idempotente → verificar recibo
  → purgar según custodia.
- **Áreas o archivos implicados:** `integration_events.py`, backup/restore,
  API/roles/CSRF, auditoría, panel administrativo y runbooks.
- **Criterios de aceptación verificables:** backup declara e implementa inclusión
  o exclusión segura del outbox; admin puede revisar y reintentar una selección
  acotada sin ver payload/destino/IDs sensibles, tras confirmación y con nuevo
  lease; receptor sigue deduplicando el event ID original. Retención/capacidad,
  dos organizaciones, carrera, reinicio, restore y clave rotada se prueban sin
  Internet.
- **Riesgos de seguridad, privacidad y operación:** replay masivo duplica efectos;
  copiar una cola con destino/clave o filas cruzadas filtra datos y restaurar sin
  política pierde notificaciones silenciosamente.
- **Dependencias:** `PROD-071` completada y `PROD-040`.
- **Tamaño:** M
- **Estrategia de pruebas:** SQLite/backup sintético, receptor simulado, CSRF,
  roles, replay concurrente, canarios sensibles y estados UI.
- **Evidencia de validación al completarse:** 2026-09-11: el outbox queda fuera
  del backup y su preflight rechaza filas `pending`, `delivering` o `dead`; un
  restore verificado empieza sin cola histórica. El replay solo-admin selecciona
  como máximo 100 agotados del tenant mediante digest opaco con TTL de cinco
  minutos, exige confirmación y CSRF, conserva el `event_id`, reinicia intentos
  atómicamente y no expone IDs, payload ni destino. Se verificaron dos owners,
  carrera/replay repetido, expiración, reinicio, retención y firma con una clave
  rotada usando solo SQLite y `MockTransport`. Pasaron 25 regresiones dirigidas;
  suite Python completa 2.136/2.136 (backend 1.655 + tools 481; 422,82 s,
  416.928 KiB RSS), CLI 66/66 en Python 3.12.13 y frontend 62 archivos/430
  pruebas (124,73 s), axe y build 305,7/322 KiB. También pasaron `compileall`,
  Compose base/privado, release, backlogs, diff-check, Gitleaks sobre el diff y
  su canario. El escaneo íntegro del árbol no se atribuye: halló 102 fixtures y
  no pudo leer `data/runtime`. La revisión visual nueva quedó no ejecutada porque
  el navegador integrado bloqueó ambos orígenes locales con
  `ERR_BLOCKED_BY_CLIENT`; permanece la revisión visual previa del estado
  deshabilitado y la regresión DOM/axe del replay. Servicios, pestaña y datos
  sintéticos se eliminaron (`TEMP_RESIDUALS=0`). No hubo Internet, receptor
  real, push, PR ni despliegue.

### PROD-253 — Estabilizar la prueba asíncrona de paginación Active bajo carga

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** la puerta frontend debe distinguir
  una regresión real de una carrera del test para que una candidatura no quede
  bloqueada o aprobada de forma aleatoria.
- **Flujo completo afectado:** cambiar filtros de activos → recibir la página
  correspondiente → paginar con su cursor firmado → conservar foco y filas.
- **Áreas o archivos implicados:** `ActiveOperationsCenter.test.tsx`, mocks de
  búsqueda paginada y, solo si la reproducción lo demuestra, el panel Active.
- **Criterios de aceptación verificables:** el test espera la respuesta del
  filtro exacto actual, no solo un botón habilitado por una respuesta anterior;
  20 repeticiones dirigidas y dos suites frontend completas pasan sin elevar
  timeouts ni ocultar una carrera real. La semántica de descarte stale, cursor,
  deduplicación y foco no cambia.
- **Riesgos de seguridad, privacidad y operativa:** una puerta flaky erosiona la
  confianza en CI; una corrección que desactive la protección stale podría
  mezclar resultados de filtros o scopes distintos.
- **Dependencias:** `PROD-171` completada; fallo observado durante la validación
  de `PROD-237`.
- **Tamaño:** S
- **Estrategia de pruebas:** reproducción bajo carga, repetición serial dirigida
  y suite completa; inspeccionar orden exacto de requests/responses simuladas.
- **Evidencia de validación al completarse:** 2026-09-11: se confirmó que el
  test esperaba un botón habilitado que podía pertenecer a la respuesta previa.
  El mock distingue ahora la página exacta (`has_more=false`) de la prefija y
  espera primero que el estado exacto quede aplicado; no se cambió producto ni
  timeout. Pasaron 20/20 repeticiones dirigidas y dos suites completas de 62
  archivos/430 pruebas (44,55 s y 45,03 s; picos 614.036 y 703.004 KiB). Se
  conservan las aserciones de cursor, deduplicación, filtros, foco, error
  recuperable, descarte stale y axe; diff-check/backlogs verdes.

### PROD-254 — Estado canónico y verificable de aceptación de despliegue

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** operación necesita distinguir la
  última aceptación real, la última revisión funcional con CI y el árbol de
  trabajo actual; el encabezado vigente presenta como actual el NO-GO histórico
  de la primera fuente y contradice el acta posterior.
- **Flujo completo afectado:** abrir guía canónica → identificar versión/revisión
  y alcance aceptado → decidir si el árbol concreto puede desplegarse → aplicar
  configuración, aceptación o reversión correcta.
- **Áreas o archivos implicados:** `DEPLOYMENT_ACCEPTANCE.md`, puerta
  `release_consistency.py`, sus pruebas y backlogs.
- **Criterios de aceptación verificables:** la cabecera separa explícitamente
  aceptación real de proyecto, revisión CI y cambios posteriores; conserva los
  NO-GO históricos fechados y no transfiere un GO a un árbol distinto. La guía
  deja de decir que `PROD-120` está pendiente, elimina duplicación y la puerta
  falla si desaparece el bloque canónico o vuelve el encabezado obsoleto.
- **Riesgos de seguridad, privacidad y operativa:** desplegar una revisión no
  aceptada, o bloquear una revisión aceptada por leer un estado histórico como
  actual; asumir que GO de OSV/KEV autoriza GHSA, NVD, publicación o estabilidad.
- **Dependencias:** actas `PROD-117`, `PROD-129/130` y estado Git local; no
  modifica ni reabre sus evidencias.
- **Tamaño:** S
- **Estrategia de pruebas:** fixtures positivos/negativos del validador de
  release, puerta real, diff-check y revisión textual de todos los GO/NO-GO.
- **Evidencia de validación al completarse:** 2026-09-11: la cabecera separa GO
  acotado de la segunda aceptación, CI verde/no publicada en `7f7614c…`, tip
  documental `e40b611…` y obligación de revalidar cualquier árbol posterior.
  Los NO-GO históricos permanecen fechados. Se corrigió la referencia obsoleta
  a `PROD-120` sin prometer secure erase. `make check-release` exige los tres
  marcadores y rechaza el encabezado legacy; dos regresiones nuevas, 28 pruebas
  dirigidas y tools completo 485/485 en 11,77 s pasaron, además de compileall,
  backlogs y diff-check. Sin modificar producto, aceptación histórica, CI,
  `SEC-012`, push, PR o despliegue.

### PROD-255 — Avisos verificables de dependencias runtime distribuidas

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** equipos que evalúan o redistribuyen
  Inspectra necesitan conocer las licencias de todos los paquetes runtime; la
  incorporación de `cvss` LGPL confirmó que no existe aviso ni gate de cobertura.
- **Flujo completo afectado:** actualizar lock de producción → revisar licencia
  y fuente → actualizar aviso → puerta de release detecta omisión/deriva.
- **Áreas o archivos implicados:** locks backend/frontend,
  `THIRD_PARTY_NOTICES.md`, herramientas/pruebas y documentación de release.
- **Criterios de aceptación verificables:** cada paquete Python runtime y cada
  paquete npm de producción aparece exactamente una vez con versión, expresión
  de licencia y enlace HTTPS; faltantes, extras, duplicados o versión divergente
  fallan. `cvss==3.6` se identifica como LGPL-3.0-or-later. Dev/test quedan fuera
  explícitamente y una licencia declarada no sustituye revisión jurídica.
- **Riesgos de seguridad, privacidad y operativa:** incumplimiento de licencias,
  adopción empresarial bloqueada o dependencia nueva distribuida sin revisión.
- **Dependencias:** locks reproducibles y `PROD-237` completada.
- **Tamaño:** S
- **Estrategia de pruebas:** fixtures de inventario válido, ausencia, versión,
  duplicado/extra/URL y ejecución contra locks reales, release y diff-check.
- **Evidencia de validación al completarse:** 2026-09-11: aviso humano enlazado
  desde README cubre exactamente 29 distribuciones Python y 6 paquetes npm de
  producción; `cvss==3.6` figura como LGPL-3.0-or-later y el límite jurídico se
  declara sin prometer cumplimiento automático. El validador deriva el conjunto
  de ambos locks y rechaza faltantes, extras/versiones obsoletas, duplicados,
  licencias no revisadas y fuentes no HTTPS; dev queda excluido por el lock. El
  vocabulario SPDX es cerrado y fuerza revisión ante una licencia nueva. Once
  pruebas dirigidas y tools 491/491 (7,17 s, 74.420 KiB) pasaron; también
  compileall, check real de avisos, release, backlogs, diff y Gitleaks
  diff/canario. Sin instalar/cambiar dependencias, red de producto, `SEC-012`,
  push, PR o despliegue.

### PROD-072 — Métricas de adopción locales y privadas

- **Prioridad:** P3
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** mantenedores necesitan saber si el
  producto ayuda a completar análisis y correcciones, sin telemetría de código,
  paquetes o usuarios enviada por defecto.
- **Flujo completo afectado:** acción de producto → métrica agregada local →
  panel/admin o exportación manual → decidir mejora → purgar según retención.
- **Áreas o archivos implicados:** observabilidad, almacenamiento, configuración,
  documentación de privacidad y pruebas.
- **Criterios de aceptación verificables:** solo conteos/agregados locales con
  opt-in explícito para exportación; no incluye identificador, nombre, hash,
  hallazgo, archivo ni URL. Retención y desactivación documentadas; tests
  inspeccionan payload y borrado.
- **Riesgos de seguridad, privacidad y operación:** telemetría invisible erosiona
  confianza; métricas sin contexto inducen decisiones erróneas.
- **Dependencias:** `PROD-013`, `PROD-062`.
- **Tamaño:** M
- **Estrategia de pruebas:** eventos agregados sintéticos, toggle, retención y
  aserciones de ausencia de identificadores.
- **Evidencia de validación al completarse:** reconciliada 2026-09-11 mediante
  `PROD-162`. `INSPECTRA_ADOPTION_METRICS_ENABLED` permanece `false` por defecto;
  el middleware solo acepta diez plantillas de ruta internas y persiste día,
  flujo/fase/resultado cerrados, bucket de duración y contador, nunca ruta real,
  query, payload, ID, nombre, componente, timestamp o duración exactos. SQLite
  `0600` está limitado a 8.192 filas/16 MiB y 90 días; purga, readiness y backup
  validan esquema/contenido y fallan cerrados. No existe endpoint ni transporte:
  la exportación JSON requiere confirmación en CLI local y declara sus límites.
  Cuatro pruebas específicas cubren off/toggle, agregación, payload canario,
  purga, manipulación, backup y export; la regresión middleware confirma que un
  payload secreto no llega al store. Formaron parte del backend 1.617/1.617 y
  Compose base/privado verdes de este corte. Sin duplicar store, red o telemetría.

### Ronda 5 — Revisión crítica de entrega, seguridad y experiencia (2026-09-05)

- **Alcance auditado:** se revisaron la implementación y contratos de la nueva
  instantánea, almacenamiento de proyecto y trabajos, borrado/retención,
  mensajes de estado, composición de la interfaz de proyectos, controles CSRF/
  propiedad y los límites pendientes de operación e inteligencia pública.
- **Hechos y decisiones:** `PROD-041` preserva hashes y rechaza fuente ajena,
  tipo no archivado, doble hash y ejecución activa. Aun así, una incorporación
  realiza persistencia de instantánea, creación de trabajo y asociación en pasos
  separados; no tiene clave de idempotencia ni límite por proyecto. La interfaz
  muestra tabla, hallazgos, inventario y comparación como paneles separados,
  sin un contexto único que explique historial, estado y siguiente acción.
  Se mantiene la consulta pública deshabilitada: `PROD-026` sigue siendo el
  límite obligatorio antes de cualquier egress de Módulo 3. No se adelantan
  organizaciones, repositorios ni ejecución durable.
- **Nuevas tareas:** `PROD-073`…`PROD-077`, detalladas a continuación. Se
  inicia `PROD-076` como la primera mejora de la fase profunda de UX: ofrece un
  vertical de proyecto completo sobre contratos ya existentes, sin reescribir la
  navegación ni añadir datos externos.
- **Seguridad inmediata vinculada:** durante esta revisión se confirmó que la
  respuesta estándar de validación podía reproducir valores de entrada en la
  interfaz. `SEC-019` se abrió como P0 en `TODO.md` para sustituirla por un
  contrato `422` genérico, con regresión negativa de secretos; su cierre y
  evidencia deben mantenerse sincronizados aquí antes de continuar con la
  matriz de mutaciones. **Completada:** el contrato genérico conserva el ID de
  petición y la prueba ASGI demuestra que un token inyectado no vuelve en la
  respuesta ni en el evento de auditoría; pasó la suite Python completa y
  `compileall`.
- **Criterio de priorización:** primero se cierran estados que pueden duplicar
  trabajo o debilitar autorización; después se hace comprensible el ciclo de
  corrección para un propietario; finalmente se refuerza accesibilidad y
  presentación con pruebas reproducibles. Cada tarea debe conservar resultados
  redactados, propiedad y límites de archivo.

### PROD-073 — Admisión idempotente y acotada de instantáneas

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo necesita que un reintento
  de red o dos clics no creen fuentes o ejecuciones ambiguas, y que un proyecto
  no acumule instantáneas sin un límite operativo explícito.
- **Flujo completo afectado:** confirmar fuente → reservar operación por clave
  idempotente → validar cuota/límite → persistir instantánea y trabajo como una
  unidad recuperable → devolver el mismo resultado o causa segura → auditar.
- **Áreas o archivos implicados:** `ProjectStore`/`JobStore`, rutas de proyectos,
  configuración de cuotas, UI de recuperación, observabilidad, migración y tests.
- **Criterios de aceptación verificables:** una misma clave/solicitud devuelve
  una operación previa compatible sin nueva instantánea; colisiones incompatibles
  fallan con código seguro. Hay límite configurable por proyecto y un estado de
  recuperación para una persistencia incompleta; nunca se borra historial para
  hacer sitio. Pruebas de concurrencia/fallo entre pasos prueban contador,
  hashes, owner y ausencia de duplicado.
- **Riesgos de seguridad, privacidad y operación:** duplicación consume recursos,
  rompe comparación y puede retener archivos de más; una compensación incorrecta
  borra trazabilidad.
- **Dependencias:** `PROD-008`, `PROD-015`; extiende `PROD-041` completada.
- **Tamaño:** L
- **Estrategia de pruebas:** reloj/almacén controlado, fallos inyectados entre
  persistencias, solicitudes paralelas y pruebas de UI de límite; sin red.
- **Evidencia de validación al completarse:** 2026-09-06: el cliente genera una
  clave aleatoria opaca de 128 bits al enviar la instantánea y conserva esa
  misma clave mientras un fallo sea reintentable. El backend persiste solo su
  digest SHA-256 en la bitácora privada versionada `2026-09-06.1`, junto con
  owner/proyecto/archivo/hash e IDs preasignados, nunca la clave, nombre, ruta o
  contenido. Proyecto, snapshot y job se coordinan bajo el lock de
  almacenamiento; una operación `pending` se completa con los mismos IDs al
  reintentar o antes de recuperar la cola tras reinicio. Una clave compatible
  converge sin duplicado, una vinculación distinta devuelve `409` y el límite
  `INSPECTRA_PROJECT_MAX_SOURCE_SNAPSHOTS` acepta 1–10000 (100 por defecto) sin
  borrar historia. Pruebas deterministas cubrieron dos hilos simultáneos,
  contador/hash/owner, no persistencia de clave/nombre/ruta, fallo inyectado
  entre proyecto y job, recuperación en lifespan y despacho, colisión, límite
  y reutilización de clave en UI. El grupo snapshot/seguridad pasó 18/18 y el
  grupo de recuperación 4/4; la suite backend completa pasó 1.023/1.023 en
  26,44 s. Runner/guardas pasó 420/420 en 6,17 s; frontend, 38 archivos y
  278/278 en 20,11 s; build/presupuesto, 311,8/322 KiB en 10,45 s. También
  pasaron `compileall`, Compose base/privado y `git diff --check`, sin Internet,
  proveedores ni proyecto real. Una primera orden frontend se lanzó desde la
  raíz y falló inmediatamente por no existir allí `package.json`; repetida en
  la copia frontend correcta terminó completa, sin pruebas omitidas.

### PROD-074 — Matriz de seguridad para mutaciones de proyecto

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** quien autohospeda necesita confiar
  en que toda mutación de proyecto conserva de forma uniforme sesión, CSRF,
  propiedad, validación estricta y respuesta segura al evolucionar la API.
- **Flujo completo afectado:** sesión o modo local → crear/repetir/añadir fuente/
  borrar → guardas comunes → resultado o rechazo → auditoría mínima.
- **Áreas o archivos implicados:** middleware/rutas de proyecto, modelos,
  pruebas de autenticación y CSRF, contrato OpenAPI y guía de despliegue.
- **Criterios de aceptación verificables:** una matriz automatizada cubre cada
  ruta mutante con anónimo, sesión sin CSRF, CSRF válido, propietario distinto,
  payload extra e identificador malformado; ninguna respuesta filtra archivo,
  ruta, token ni estado de otro propietario. Nuevas rutas mutantes deben quedar
  registradas por una guarda de contrato.
- **Riesgos de seguridad, privacidad y operación:** una ruta nueva puede eludir
  CSRF/ownership pese a que las rutas antiguas estén protegidas.
- **Dependencias:** `PROD-041`, `PROD-042`, `SEC-019` completada y autenticación actual;
  no requiere multiusuario de `PROD-012`.
- **Tamaño:** M
- **Estrategia de pruebas:** ASGI con sesión sintética, tabla parametrizada y
  aserciones negativas de contenido; sin credenciales reales.
- **Evidencia de validación al completarse:** 2026-09-05: se declaró un contrato
  de rutas para crear, repetir, añadir instantánea y borrar la fuente vinculada.
  La matriz ASGI cubre anónimo `401`, sesión sin CSRF `403`, propietario con CSRF,
  recurso de otro propietario `404`, ID malformado y campos extra sin eco de un
  secreto. La repetición declara un cuerpo vacío y rechaza cualquier campo en
  lugar de ignorarlo. Pasaron 7 pruebas dirigidas, suite completa backend/runner
  y `compileall`; frontend completo (35/229) y build/presupuesto 321,6/322 KiB.

### PROD-075 — Privacidad de metadatos de fuente e historial

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una empresa necesita retener hashes
  y estado para reproducibilidad sin que nombres sensibles de archivos se
  propaguen innecesariamente a listas, informes o futuras integraciones.
- **Flujo completo afectado:** carga → nombre de presentación → proyecto/
  instantánea → historial, exportación o integración → retención/eliminación.
- **Áreas o archivos implicados:** modelos de fuente/proyecto, serializadores,
  informes, frontend, política de retención y documentación de privacidad.
- **Criterios de aceptación verificables:** la política clasifica cada metadato
  y define dónde puede mostrarse; informe, integración y detalle técnico usan
  ID/hash opaco o un nombre seguro según configuración y no muestran por defecto
  un identificador largo que pueda correlacionar una fuente al compartir pantalla.
  Fixtures con nombres hostiles/prácticos prueban escape, redacción y que
  historial/comparación siguen siendo útiles.
- **Riesgos de seguridad, privacidad y operación:** nombres revelan cliente,
  rama o topología y se convierten en dato persistente o exportado.
- **Dependencias:** `PROD-036`, `PROD-062`; complementa `PROD-041`.
- **Tamaño:** M
- **Estrategia de pruebas:** contratos API/informe, render accesible y retención
  con archivos sintéticos; sin cambiar bytes de la fuente.
- **Evidencia de validación al completarse:** 2026-09-06: el contrato de
  retención `2026-09-06.3` clasifica exactamente nombre original, SHA-256 de
  contenido, ID interno y referencia segura. Modelos API específicos para
  proyecto, historial y detalle eliminan nombre/digest y derivan una referencia
  `snapshot-…` separada por dominio; informes y JSON técnico de proyecto tampoco
  publican `file_id`, `source_sha256`, `hashes` ni `original_filename`. La vista
  **Files** conserva la gestión owner-scoped de los metadatos originales y el
  almacenamiento interno conserva integridad/reproducibilidad. Nombres hostiles,
  historial, comparación, informe, retención y respuesta API quedaron cubiertos.
  La revisión visual a 1440 × 1000 y 390 × 844 confirmó referencia segura,
  ausencia de nombre/digest, foco 3 px + offset 2 px y documento sin desborde.
  Detectó además un blanco por estado de recarga en caliente con contrato antiguo:
  se corrigió con degradación cerrada y una regresión accesible. Pasaron 1.087
  pruebas backend (23,53 s), 420 runner/guardas (6,10 s), 44 archivos/306 pruebas
  frontend (22,24 s), build y presupuesto inicial 317,4/322 KiB (8,22 s),
  `compileall`, las dos configuraciones Compose y `git diff --check`. El primer
  Compose privado carecía de variables sintéticas obligatorias y se repitió con
  ellas; no se atribuyó al sandbox. Sin Internet, proveedor, despliegue ni
  proyecto real. Registro reproducible en `docs/frontend-visual-review.md`.
  El smoke TLS posterior de `PROD-116` descubrió una regresión residual:
  `file_id`/`source_file_id` seguían presentes en algunas proyecciones de
  proyecto y trabajo. Los modelos públicos se cerraron, **Files** usa una vista
  específica con ID owner-scoped y referencia segura, y pruebas negativas
  cubren ahora creación, lista, snapshot, reintento, detalle e informe. La
  candidatura volvió a validar privacidad y cleanup con esas proyecciones.

### PROD-076 — Espacio de trabajo de proyecto y línea temporal accionable

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un desarrollador necesita comprender
  en una misma vista qué instantánea está vigente, qué análisis se conservan,
  cuál requiere atención y qué hacer después, sin saltar entre una tabla y tres
  paneles desconectados.
- **Flujo completo afectado:** abrir proyecto propio → ver resumen de fuente y
  estado seguro → recorrer instantáneas/análisis por hash → abrir resultado o
  comparar → repetir/agregar fuente según acción disponible.
- **Áreas o archivos implicados:** paneles y navegación de proyectos, API de
  historial existente, tipos/estilos, pruebas de interfaz/teclado y guía.
- **Criterios de aceptación verificables:** existe una entrada clara **Open
  workspace** y un panel responsive con conteos, estado/acción segura, hash de
  fuente y línea temporal de análisis sin archivo, ruta, secreto ni error bruto.
  Tiene estados carga/error/vacío, foco semántico y enlaces para abrir una
  ejecución; una fuente eliminada se distingue de un resultado retenido.
- **Riesgos de seguridad, privacidad y operación:** una UX fragmentada oculta
  ejecuciones fallidas, induce repetición equivocada o divulga metadatos al
  intentar dar contexto.
- **Dependencias:** `PROD-041`, `PROD-042`, `PROD-023` completadas.
- **Tamaño:** M
- **Estrategia de pruebas:** componente con historial propio, estado pendiente/
  fallo/eliminado, acceso por teclado, error de API y verificación a 640/980/
  1440 px mediante fixture sin red.
- **Evidencia de validación al completarse:** 2026-09-05: se añadió una entrada
  **Open workspace** y un panel diferido que consulta exclusivamente el historial
  owner-scoped ya existente. Resume número de instantáneas/análisis, hash actual,
  estado seguro y línea temporal de hashes con marca de fuente eliminada; no
  vuelve a mostrar el nombre de archivo en las entradas históricas ni expone
  resultado bruto. Cada ejecución permite abrir su detalle. Se corrigió también
  un desborde real de tablet: la cuadrícula de contenido pasa a `minmax(0, 1fr)`
  a 980 px y una prueba estática evita su regresión. Las pruebas cubren carga,
  error, fuente eliminada, navegación, entrada desde tabla y axe sin violaciones
  para la vista. Pasaron 35 suites/229 pruebas frontend, build TypeScript/Vite y
  presupuesto inicial 321,6/322 KiB, `docker compose config --quiet` y `git
  diff --check`. La revisión local efímera con el archivo sintético
  `demo-archive-app-config.zip` verificó el flujo y el contenedor sin desborde a
  1440, 980 y 640 px; la tabla conservó su desplazamiento horizontal intencional.

### PROD-077 — Revisión visual accesible del recorrido de proyecto

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** usuarios de portátil y móvil deben
  poder completar creación, nueva instantánea y revisión sin tablas cortadas,
  foco perdido ni mensajes de estado poco perceptibles.
- **Flujo completo afectado:** archivo → confirmación → proyecto → espacio de
  trabajo → nueva instantánea → resultados/comparación/exportación.
- **Áreas o archivos implicados:** estilos, componentes de proyecto, fixture de
  revisión visual, pruebas axe/interacción y `docs/frontend-visual-review.md`.
- **Criterios de aceptación verificables:** la revisión fija 320, 768 y 1440 px;
  identifica orden de foco, contraste, regiones, tablas desplazables y mensajes
  de estado. Las correcciones tienen pruebas automatizadas donde sean estables y
  capturas/documentación que separen hecho de juicio visual.
- **Riesgos de seguridad, privacidad y operación:** una interfaz inaccesible o
  confusa lleva a ignorar límites de cobertura o iniciar el análisis incorrecto.
- **Dependencias:** `PROD-076`; coordinar con `UX-003` completada.
- **Tamaño:** M
- **Estrategia de pruebas:** Playwright o navegador local solo con fixtures,
  axe y pruebas de componentes; no usar archivos de usuario.
- **Evidencia de validación al completarse:** 2026-09-05: se revisaron el
  dashboard, espacio de trabajo y resultado seleccionado de
  `demo-archive-app-config.zip` a 1440/980/640 px, sin egress público y con
  zoom 100 %. El resultado recibe foco en `#results`, anuncia cambios y ordena
  exportaciones antes de Raw JSON; las tablas siguen su pista de desplazamiento
  y a 640 no hubo scroll horizontal de página. La revisión halló un solapamiento
  a 1440 px entre una etiqueta de límite larga y su valor: las etiquetas de
  metadatos ahora pueden encogerse/partirse y las pruebas de componente/estilos
  guardan la corrección. Tras reconstruir Compose no hubo solapamiento en la
  matriz. Pasaron 38 archivos/260 pruebas frontend, build/presupuesto
  310,6/322 KiB, 4 pruebas estáticas de workflow, Compose y diff. El registro
  reproducible y la decisión sobre IDs/hashes están en
  `docs/frontend-visual-review.md` y `PROD-075`, respectivamente.

## Expansión posterior a las cinco rondas (2026-09-05)

Las siguientes tareas descomponen fronteras ya identificadas en verticales
comprobables. No habilitan consultas, repositorios ni integraciones por el mero
hecho de existir: cada una declara sus dependencias. Para todas, **Estado** es
`pendiente` y la **Evidencia obligatoria** es `pendiente` hasta que se ejecuten
las pruebas indicadas y se sincronicen ambos backlogs.

| ID / prioridad / estado | Necesidad de usuario y flujo afectado | Áreas implicadas | Criterios de aceptación y estrategia de pruebas | Riesgos de seguridad, privacidad y operación | Dependencias | Tamaño | Evidencia obligatoria |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **PROD-079 — P1 — completada**<br>Identidad purl local de componentes exactos | Antes de preguntar a una fuente pública, el usuario necesita una identidad inequívoca del componente. Flujo: inventario exacto → purl local → elegibilidad visible → futura correlación. | `component_inventory.py`, modelos/tipos, contrato, panel, fixtures y guía M3. | Genera purl canónico solo para npm/PyPI registry con versión exacta; un alias, URL, rango o dato inseguro queda `not_correlatable`; ni URL privada ni ruta adicional se guarda. Pruebas puras de nombres con scope, mayúsculas PyPI, versión y redacción; contrato y UI. | Un purl mal construido consulta/atribuye otro paquete; guardar origen no registry puede filtrar topología. | PROD-024/025/047 completadas. | M | 2026-09-05: contrato `2026-09-05.4` incorpora `package_url` solo tras una versión npm/PyPI exacta de registro, incluida una resolución lockfile. Se reutilizó el codificador purl de SBOM y codifica versiones antes de serializarlas; rangos y VCS/URL no reciben purl. El panel lo muestra como identidad local no enlazada. Pasaron 18 pruebas backend dirigidas (inventario/SBOM), 4 pruebas frontend dirigidas, las 35 suites/230 pruebas frontend, build y presupuesto 322 KiB; Compose config y diff check pasaron. |
| **PROD-080 — P1 — completada**<br>Comparación de versiones por ecosistema y estado desconocido | El usuario necesita saber si Inspectra puede comparar una versión sin que una semántica npm se aplique erróneamente a Python. Flujo: versión exacta → comparador versionado → `matched`/`not_matched`/`unknown` → correlación. | Nuevo módulo de versiones, contrato M3, fixtures y documentación. | Soporta de forma aislada los formatos documentados de npm y PyPI; entradas no soportadas, pre-release ambiguo o rango inválido producen `unknown`, nunca una coincidencia. Matriz determinista de límites, epoch/local versions y errores. | Un comparador permisivo genera falsos negativos/positivos; una excepción sin control puede bloquear análisis. | PROD-079; coordina PROD-028. | M | 2026-09-05: `version_matching.py` no abre red y devuelve `matched`, `not_matched` o `unknown` con razón controlada. npm soporta únicamente comparadores conjuntivos de releases; PyPI usa `packaging` 26.3 fijado para un subconjunto PEP 440. Pre-releases, comodines, `^`/`~`, `||`, igualdad arbitraria y datos inválidos quedan unknown. Pasaron 13 pruebas dirigidas, `compileall`, instalación desde `backend/requirements.lock`, Compose config y diff check. |
| **PROD-081 — P1 — completada**<br>Grafo npm bloqueado, acotado y sin URLs | Un equipo necesita distinguir dependencias directas y transitivas de un lockfile ya emparejado. Flujo: `package-lock` fiable → nodos/aristas acotados → alcance visible → inventario futuro. | Runner npm, inventario, cobertura, modelos, UI, fixtures de monorepo. | Solo `package-lock` v2/v3 mismo-root y no workspace aporta nodos; límites de nodos/aristas truncan con estado explícito; no persiste `resolved`, integridad, URL ni contenido de paquete. Pruebas de ciclo, duplicado, raíz, truncamiento y redacción. | Un grafo de otro root o sin límite mezcla proyectos/consume memoria; `resolved` puede revelar registries internos. | PROD-025/047; desbloquea parte de PROD-048. | L | 2026-09-05: el runner genera un grafo npm v2/v3 de nodos con ID hash opaco y aristas runtime/opcionales, limitado por `INSPECTRA_PROJECT_ARCHIVE_MAX_LOCKFILE_PACKAGES` y el nuevo máximo de 4.000 aristas. Solo un lockfile ya emparejado añade nodos registry transitivos al inventario; workspaces/no registry se excluyen. Ni el grafo ni la API exponen path de paquete, `resolved`, integridad o URL. Se corrigió la extracción de nombre de nodos npm anidados. Panel, contrato `2026-09-05.5` y cobertura muestran alcance transitive/límite. Pasaron 9 pruebas backend/runner dirigidas, 5 frontend, build/presupuesto 322 KiB, Compose config y diff check. |
| **PROD-082 — P2 — completada**<br>Ingesta segura de `pnpm-lock.yaml` | Equipos pnpm necesitan cobertura honesta sin que YAML no confiable se ejecute. Flujo: detectar → parser seguro y acotado → identidad/versiones → motivo de exclusión. | Runner, parser seguro, inventario/cobertura, fixtures y docs. | No ejecuta pnpm ni evalúa YAML; acepta únicamente versión documentada y misma raíz; guarda nodos exactos mínimos o estado no soportado. Pruebas de anchors/alias, tamaño, traversal y lockfile corrupto. | Parser expansivo o YAML inseguro causa DoS/lecturas; inferir versiones de referencias es engañoso. | PROD-081, PROD-087. | L | 2026-09-06: el runner acepta exclusivamente el subconjunto de `pnpm-lock.yaml` v9 con `lockfileVersion: '9.0'`, importador raíz y versiones semver exactas directas. Antes de cargar YAML rechaza anchors, aliases, tags, claves duplicadas/no textuales y más de 20.000 tokens; no ejecuta pnpm ni conserva `specifier`, `resolution`, integridad, tarball o peer suffix. El inventario `2026-09-05.8` y la previsualización `2026-09-05.8` muestran la resolución local misma-raíz por separado, sin purl ni procedencia pública; PVI prueba que OSV no recibe ese componente. Pasaron pruebas dirigidas de runner/backend/PVI, suite completa `backend/tests tools/tests`, `compileall`, 38 archivos/266 pruebas frontend, build con 311,1/322 KiB, `docker compose config --quiet`, Compose reconstruido y `/health`. Sin consultas a proveedores. |
| **PROD-083 — P2 — completada**<br>Ingesta segura de `yarn.lock` | Equipos Yarn necesitan saber si sus versiones son verificables. Flujo: detectar lockfile → clasificar formato → extraer solo resolución exacta o explicar exclusión. | Runner, inventario, contrato de cobertura, UI y documentación. | Distingue Classic/Berry según gramática/versionado; no ejecuta Yarn ni conserva URLs; selectores múltiples/patch/protocol no soportado quedan no correlatables. Pruebas de comillas, scopes, integridad y límite. | Interpretar mal selector/alias acusa versión ajena; texto enorme degrada el análisis. | PROD-087; complementa PROD-049. | L | 2026-09-06: según la gramática oficial de Yarn Classic, el runner admite solo `# yarn lockfile v1`, con 20.000 líneas como máximo. Conserva nombre npm válido, versión semver exacta y un digest opaco del selector que debe coincidir con la declaración misma-raíz; descarta selector, `resolved`, integridad, URL, dependencias transitivas y aliases/protocolos. Berry (`__metadata:`), tabulaciones, líneas excesivas y gramática/versiones inválidas quedan `detected_not_parsed`, nunca limpias. Inventario/preflight `2026-09-06.1`, matriz y UI explican la resolución local sin purl ni egress; PVI prueba que OSV no recibe el componente. Pasaron pruebas dirigidas, suite completa `backend/tests tools/tests`, `compileall`, 38 archivos/267 pruebas frontend, build con 311,1/322 KiB, `docker compose config --quiet`, Compose reconstruido, backend `/health` y frontend HTTP local. Sin consultas a proveedores. |
| **PROD-084 — P2 — completada**<br>Ingesta segura de `poetry.lock` | Proyectos Poetry requieren una versión instalada diferenciada de la declaración. Flujo: pyproject → lock pareado → componente exacto local → cobertura honesta. | Runner Python, inventario, contrato/cobertura, panel, preflight, fixtures TOML y docs. | Acepta exclusivamente `[metadata].lock-version = "2.1"`, un `poetry.lock` y `pyproject.toml` del mismo root y nombre PyPI/versión exacta sin ambigüedad. Nunca ejecuta Poetry ni conserva `package.source`, URLs, referencias, archivos, hashes, grupos, marcadores, aristas o content hash. Las versiones duplicadas, ausentes, lockfiles incompatibles/malformados o entradas no correlacionables no resuelven un componente; no hay purl ni egress. | Un TOML ambiguo puede asociar una versión ajena; `source`/hashes pueden revelar registry, credenciales o topología privada. | PROD-079/080/087. | L | 2026-09-06: parser TOML limitado a 2.1, tope de paquetes y reducción a nombre PyPI normalizado + versión exacta local. Inventario/preflight/matriz `2026-09-06.2` y panel distinguen Poetry local-only; PVI prueba que OSV no recibe dicho componente. Pruebas dirigidas de parser, asociación misma-raíz, ambigüedad/no correlación, redacción, cobertura y PVI pasaron; `compileall`, frontend completo (38 archivos/268 pruebas) y build/presupuesto (311,1/322 KiB) pasaron. La suite Python global no se repitió en este sandbox porque una prueba heredada que abre un servidor TCP local recibe `PermissionError`; el flujo tocado usa fixtures/`MockTransport`, sin Internet. |
| **PROD-085 — P2 — completada**<br>Ingesta segura de `Pipfile.lock` | Equipos Pipenv necesitan trazabilidad de su resolución. Flujo: Pipfile → lock mismo root → versión/hash mínimo → cobertura. | Runner Python, inventario, fixtures JSON, UI y docs. | Versiona parser, extrae solo nombre/version exacta y grupos; no guarda hashes ni índices; lock de otro root o sin versión queda no correlatable. Pruebas de `default`/`develop`, JSON inválido y datos privados. | Exponer hash/índice revela infraestructura; confundir grupos altera priorización. | PROD-079/080/087. | M | **2026-09-09:** el runner acepta únicamente `_meta.pipfile-spec=6`, rechaza claves JSON duplicadas y limita todas las entradas, incluidas las descartadas. El parser de `Pipfile` conserva solo nombre normalizado, selector seguro, grupo y categoría de fuente; el lock conserva únicamente nombre, versión exacta y `packages`/`dev-packages`. Hashes, índices, fuentes, URLs, credenciales, markers y metadatos se descartan; entradas ambiguas/incorrectas quedan solo en contadores. El inventario `2026-09-09.5` exige un único par mismo-root, lo marca local-only, no crea purl y una regresión captura que OSV no recibe la identidad. Preflight, matriz y UI muestran formato 6, grupo y origen no verificado. Pasaron 50 pruebas runner amplias, 13 de matriz, 1 de no-egress, 2 de preflight y 24 frontend; build/bundle 293,1/322 KiB, `compileall`, Compose y diff-check, todo sin red. Las iteraciones corrigieron límites obsoletos del contrato preflight y una etiqueta UI que inicialmente mostraba `Registry`. |
| **PROD-086 — P2 — completada**<br>Evidencia de hashes en requisitos Python | Quien usa requisitos fijados necesita saber si la resolución es reproducible, sin publicar hashes. Flujo: requirements → detectar pin/hash → resumen de integridad → cobertura. | Parser de requisitos, modelo de cobertura, UI, docs y tests. | Publica solo estado `hashes_present`/`missing`/`not_applicable` y conteos para requisitos exactos; no serializa hashes, URL, ruta local, credenciales ni valores de opciones. Pruebas de continuaciones, múltiples hashes, hash malformado y entradas VCS/locales. | Hashes/URLs pueden dar pistas internas; asumir que un pin equivale a integridad es falso. | PROD-024, PROD-075. | M | **2026-09-09:** `requirements-lines-v2-hash-summary` une continuaciones sin evaluar includes/variables, reconoce solo SHA-256/384/512 de longitud exacta y publica únicamente conteos y estado agregado. Pins no exactos y fuentes URL/VCS/locales no reciben crédito; digest, option value y locator se eliminan antes de persistencia. Inventario/matriz `2026-09-09.6`, perfil pasivo `2026-09-09.6`, ruleset `2026-09-09.5` y preflight `2026-09-09.4` hacen visible el límite; UI e informe muestran evidencia agregada y explican que pin/hash declarado no prueba descarga o verificación. Regresiones cubren dos hashes continuados, hash malformado, pin sin hash, rango con hash, VCS/local/custom index y ausencia de fuga. Durante la suite se detectó y corrigió la caída del preflight ante contratos legados sin `analysis_profile`, y dos expectativas de versión obsoletas pasaron a constantes autoritativas. Pasaron 53 runner y 26 backend dirigidas; suites completas Python 1.883/1.883 con Docker Python 3.12 `--network none` y frontend 58 archivos/396 pruebas; build 293,1/322 KiB, `compileall`, Compose y diff-check. Los dos primeros intentos Python completos se detuvieron en esas expectativas obsoletas y se repitieron íntegros tras corregirlas; no hubo Internet ni ejecución de proyecto. |
| **PROD-087 — P2 — completada**<br>Matriz de cobertura de gestores y lockfiles | Un comprador necesita saber exactamente qué ecosistema/gestor tiene correlación fiable. Flujo: análisis → matriz de soporte → decisión de siguiente acción → informe. | Contrato de cobertura, frontend, informes, docs y fixtures. | Lista versión de parser, manifest/lockfile, directo/transitivo y razón de exclusión; no confunde `detected` con `parsed`. Pruebas de cada estado y snapshot de informe. | Una promesa genérica hace que se ignoren zonas sin cobertura. | PROD-035; coordina PROD-081…086. | M | 2026-09-05: contrato de inventario `2026-09-05.7` añade una matriz fija y versionada de npm/package-lock, pnpm, Yarn, requirements, pyproject, Poetry y Pipenv. Reduce los registros ya retenidos a estados agregados `parsed`, `detected_not_parsed` o `not_detected`, alcance directo/transitivo y una razón controlada; no serializa path, URL, integridad, contenido ni error de parser. El API recompone de forma segura la matriz de snapshots anteriores, el panel distingue detección de resolución y ofrece el siguiente paso, y el informe exporta la misma matriz. Pasaron 8 pruebas backend dirigidas, suite backend/runner, `compileall`, 38 archivos/265 pruebas frontend, TypeScript/Vite y presupuesto 311,1/322 KiB; Compose se reconstruyó y `/health` respondió. Sin Internet. |
| **PROD-088 — P1 — completada**<br>Minimización verificable de egress de advisories | El usuario debe poder activar inteligencia sin entregar código, rutas o datos de proyectos. Flujo: componente elegible → proyección mínima → allowlist → adaptador → evidencia de salida. | Configuración, nuevo límite de egress, observabilidad, tests, despliegue y privacidad. | Solo envía ecosistema, nombre canónico, versión y purl cuando sea necesario; rechaza namespaces privados/no elegibles antes de red y registra conteo/razón sin payload. Pruebas de inspección de requests y DNS/URL denegados. | Egress revela tecnología o se convierte en SSRF; un log puede reconstruir el proyecto. | PROD-026, PROD-055; revisión de PROD-008. | M | 2026-09-05, conciliada tras inspección: egress fijo y desactivado por defecto, únicamente con identidad npm mínima aprobada, exclusiones de namespace y procedencia de lockfile. `test_public_advisory_egress.py` captura el payload, deniega identificadores hostiles/privados y comprueba caché y logs sin identidad; documentación fija el runbook. Validado en la suite Python de 1337 pruebas sin red de proveedores. |
| **PROD-089 — P2 — completada**<br>Transporte allowlist y fallos seguros de proveedores | Operación necesita que caída, redirección o DNS de una fuente no altere resultados ni el perímetro. Flujo: request permitido → timeout/límite/redirección → resultado degradado → reintento controlado. | Cliente HTTP de advisories, config, telemetría mínima y tests. | Hosts y HTTPS se fijan por proveedor; no hay redirección a otro host, credenciales ni proxy implícito; timeout, bytes y presupuesto se prueban con servidor falso. | SSRF, DoS, coste y datos obsoletos aparentando certeza. | PROD-026/088, PROD-052. | M | 2026-09-05: además de `follow_redirects=False` y `trust_env=False`, el cliente valida antes de adquirir el transporte el método, HTTPS, host y ruta exactos para cada proveedor; rechaza puertos, userinfo, query y fragmentos. Una deriva interna se devuelve como fuente no disponible, con cero intentos y sin incluir el endpoint en telemetría. `MockTransport` cubrió HTTP, host ajeno, userinfo, query, fragmento e IP local; también 302, 400, 503, 504 y `ReadTimeout`, verificando reintentos solo en estados transitorios y cuerpos de error no expuestos. Pasaron 37 pruebas dirigidas, 1.358 casos backend/runner completos, `compileall`, `docker compose config --quiet` y controles de espacios en blanco; no hubo Internet. |
| **PROD-090 — P1 — completada**<br>Adaptador OSV por lote con fixture determinista | El usuario necesita correlación eficiente para identidades exactas. Flujo: purls elegibles → lote limitado → respuesta normalizada → detalle reproducible. | Adaptador OSV, contrato canonical, fixtures, configuración y tests. | Implementa interfaz sin red en la suite principal; respeta orden/respuesta parcial/paginación pendiente y nunca usa el endpoint experimental de inferencia. Solo se activa tras egress explícito. | Solicitudes sin identidad o demasiado grandes pierden trazabilidad/datos. | PROD-026/027/079/088. | L | 2026-09-05, conciliada tras inspección: `query_osv_batch` usa el endpoint fijo solo después de egress explícito y el normalizador enlaza resultado-posicional a identidad exacta. Fixtures cubren vacío, advisory válido, conteo parcial/forma inválida, respuesta hostil y caída; una respuesta incompleta degrada cobertura, no crea `not_affected`. La suite de 1337 pruebas ejercita este flujo sin Internet. |
| **PROD-091 — P2 — completada**<br>Paginación OSV y contabilidad reproducible | Un equipo no debe recibir un «sin vulnerabilidades» si la respuesta quedó paginada. Flujo: lote → token por componente → páginas acotadas → completo/parcial → informe. | Adaptador OSV, modelos de frescura, cache y tests. | Guarda únicamente token efímero durante ejecución, límite de páginas y estado degradado `pagination_incomplete`; no mezcla respuestas entre componentes. Fixtures simulan token por una sola consulta. | Truncamiento silencioso produce falso negativo; tokens retenidos indebidamente complican privacidad. | PROD-090, PROD-052/053. | M | 2026-09-05: se verificó la semántica de `querybatch` en la documentación oficial OSV: el token se devuelve por resultado y la petición siguiente solo incluye las identidades marcadas. El cliente reconstituye el orden original, conserva los tokens exclusivamente en memoria y guarda/cacha solo el JSON agregado sin token más `pages`. El límite fijo es 4 páginas y 4.000 advisories por identidad; token/formato inválido, caída de continuación, exceso de presupuesto o límite agotado devuelven `pagination_incomplete`, sin cuerpo ni negativos. API, panel e informe muestran el número seguro de páginas. `MockTransport` cubrió continuidad selectiva, caché sin token, límite, fallo posterior e input hostil; la integración confirma correlación tras segunda página sin rutas/tokens. Pasaron pruebas backend/runner completas (1.362), `compileall`, 38 archivos/264 pruebas frontend, TypeScript/Vite y presupuesto 311,1/322 KiB; Compose se reconstruyó, `/health` respondió y no hubo Internet. |
| **PROD-092 — P2 — completada**<br>Adaptador GHSA con evidencia versionada | El usuario necesita rangos vulnerables y versión corregida desde una fuente pública secundaria, no solo un texto. Flujo: ID GHSA/CVE → adaptador → campos normalizados → referencia visible. | Adaptador GitHub, normalizador, fixtures y docs. | Conserva GHSA, CVE, rango, primera versión corregida, fechas, URL y retirada si existen; no necesita token para recursos públicos ni registra cabeceras. Pruebas de campo ausente/conflicto/retirada. | Confundir una advisory no revisada o retirada con confirmación; token accidental en logs. | PROD-027/088; `PROD-096` consume esta evidencia, no la bloquea. | M | Reconciliada el 2026-09-05 tras auditar implementación y contrato de `PROD-032`: `github_advisories.py`, el endpoint fijo de egress, la ruta de corroboración, modelos, UI e informe ya conservan únicamente un GHSA existente en OSV, campos versionados, retirada y conflicto sin sustituir la evidencia base. Las fixtures y `MockTransport` cubren ausencia, conflicto, retirada, respuesta múltiple y redacción sin Internet. No se añadió un segundo adaptador ni se cambió el comportamiento. |
| **PROD-093 — P2 — completada**<br>Adaptador NVD/CVE sin inferencia de CPE | Empresas requieren trazabilidad CVE/NVD sin correlacionar CPE con paquetes por intuición. Flujo: CVE corroborado → NVD → CVSS/CWE/referencia → detalle, comparación e informe. | Adaptador/egress NVD, modelos, persistencia, API, panel, informes, fixtures y documentación. | Solo enriquece un CVE ya enlazado; conserva métricas/versiones tal como NVD las publica y etiqueta CPE como no mapeado. Rechaza CVE cruzado antes de caché, respuesta ambigua/bomba, CVSS ausente o inválido y esquema cambiante. NVD tiene habilitación independiente y no altera el hallazgo OSV, CVSS principal ni KEV. | Mapeo automático CPE↔paquete causa hallazgos falsos; respuestas cruzadas en caché, tasas o cambios de esquema rompen trazabilidad. | PROD-027/088 completadas; `PROD-098` consume la evidencia CPE posterior y no bloquea este enriquecimiento exacto. | M | **2026-09-09:** contrato PVI `2026-09-09.2` y NVD `2026-09-09.1`. Endpoint fijo `services.nvd.nist.gov/rest/json/cves/2.0`, parámetro único `cveId`, HTTPS/sin redirect/límites/caché y segundo interruptor default-off. Solo se persisten CVE, estado, CVSS válido, CWE, fechas, digest, referencia canónica y conteo CPE `present_unmapped`; se descartan descripciones, criterios/UUID CPE y cuentas. API owner-scoped, snapshot histórico, UI y Markdown muestran la evidencia sin afirmar aplicabilidad. Docker Python 3.12 `--network none`: backend completo 1.361/1.361 y runner 451/451; frontend 56 archivos/381 pruebas, build 291,2/322 KiB; `compileall`, Compose base/privado/aceptación-egress y diff-check. NVD permanece **adaptador validado solo con fixtures/MockTransport**, no integración real; no hubo Internet. |
| **PROD-094 — P2 — completada**<br>Resiliencia operativa y evolución del contrato CISA KEV | Tras el vertical `PROD-031`, operación necesita detectar cambios de esquema/catálogo y conservar una señal explicable a través de reinicios. Flujo: feed fijo → validar versión/esquema/tamaño → caché caducada o error → señal conservada/degradada → UI e informe. | Normalizador KEV, caché/frescura, modelos, panel/informe, fixtures y runbook. | No amplía fuentes ni correlación: sigue siendo CVE exacto. Detecta campos/fecha de catálogo incompatibles, feed que supera el tope y cambio de esquema; conserva la última señal normalizada con estado de frescura explícito o `unavailable`, nunca «no explotada». Pruebas de timestamp, feed obsoleto, reinicio y esquema nuevo. | Mezclar KEV y severidad altera decisiones; un cambio de feed o caché silencioso produce prioridad obsoleta. | PROD-031/033/099 completadas. | M | **2026-09-09:** contrato `2026-09-09.2`, raíz y filas con claves exactas, `count`/versión/límites/fecha validados antes de caché; fecha futura se rechaza y catálogo >7 días queda `provider_catalog_stale`. Caída preserva solo la última señal exacta normalizada con fuente degradada, sin crear hallazgos ni alterar CVSS; la caché validada sobrevive a reinicio dentro de retención. Pasaron 138 pruebas dirigidas, suite Python completa al 100 % (1.841 casos recopilados), 56 archivos/384 pruebas frontend, build 291,2/322 KiB, compileall, Compose base/privado y diff-check, todo sin Internet. |
| **PROD-095 — P2 — completada**<br>Evidencia de boletín oficial de proveedor | El usuario necesita una recomendación de actualización respaldada por el fabricante cuando exista. Flujo: advisory → boletín validado → versión corregida/mitigación → detalle. | Registro de fuentes, normalizador, docs y fixtures. | Una referencia de proveedor exige dominio/política allowlist y relación declarada con el advisory; changelog sin aviso no confirma vulnerabilidad. Pruebas de dominio falso, enlace ausente y mitigación sin versión. | Phishing o dato comercial se presenta como evidencia; fijar una versión no corroborada rompe producción. | PROD-027/088, complementa PROD-032. | M | 2026-09-05: `vendor_bulletins.py` implementa una política interna, no configurable y versionada. En esta primera entrega solo `npm:react` y `npm:lodash` pueden promover una referencia a las rutas GitHub de security advisories de sus proyectos; exige HTTPS, host/ruta exactos, sin puerto/credenciales/query/fragmento y un GHSA ya retenido como alias. No abre la URL ni amplía egress, no infiere dominio por nombre y rechaza host parecido, releases/changelog, GHSA diferente y paquete no revisado. Snapshot, API, panel e informe separan el enlace como evidencia de apoyo sin alterar rango, CVSS, versión corregida ni recomendación. Pasaron 4 pruebas nuevas de política, correlación e informe, 1.366 casos backend/runner, `compileall`, 38 archivos/264 pruebas frontend, TypeScript/Vite y presupuesto 311,1/322 KiB; sin Internet. |
| **PROD-096 — P2 — completada**<br>Reconciliación de fuentes a nivel de campo | El usuario necesita entender qué fuente aportó cada dato y cuándo hay conflicto. Flujo: OSV/GHSA/NVD/proveedor → campos → precedencia declarada → hallazgo. | Modelo canonical, normalizador, UI detalle, fixtures e informe. | Cada campo conserva fuente/fecha/estado; conflictos de rango, severidad o fix se muestran como `conflicting`, no se escogen silenciosamente. Pruebas de cuatro fuentes y retirada. | Precedencia implícita oculta contradicciones; mezclar fechas reduce trazabilidad. | PROD-027, PROD-092/093/095; complementa PROD-051. | L | **2026-09-09:** contrato PVI `2026-09-09.3`; matriz cerrada para identidad, rangos, fixes, CVSS, fechas, referencias, CWE, CPE, KEV, boletín y recomendación. Cada fuente conserva ID/fecha/estado/digest sin fusionar valores: OSV es primario; GHSA se marca supporting/conflicting/withdrawn; NVD puede contradecir CVSS pero CPE siempre queda unmapped; KEV no establece aplicabilidad y boletín es solo apoyo. UI e informe muestran la traza, y snapshots heredados la derivan en memoria. Regresiones de fix incompatible, retirada, CVSS NVD distinto, CPE/KEV y reporte; 49 dirigidas, backend 1.375/1.375 sin red, frontend 383/383, build 291,2/322 KiB, compileall, Compose y diff-check. Runner 451/451 no cambió. Sin Internet ni nueva validación real. |
| **PROD-097 — P2 — completada**<br>Normalizador CVSS v3/v4 y ausencias | Un usuario necesita severidad comparable sin perder puntuación/vector ni inventar CVSS. Flujo: fuente → métrica → banda → detalle/informe. | Modelo M3, normalizador, frontend, informes y tests. | Conserva versión, score y vector válidos; banda es none/low/medium/high/critical o `unknown`; v3 y v4 no se mezclan y ausencia sigue visible. Pruebas de límites, vector inválido y fuentes sin CVSS. | Convertir texto a CVSS o redondear indebidamente altera SLA/priorización. | PROD-029 completada; `PROD-096` consume este contrato y no lo bloquea. | M | **2026-09-09:** contrato OSV/GHSA `2026-09-09.1`; valida campos base y vocabulario opcional de 3.0/3.1/4.0, conserva `cvss_version` y rechaza duplicados, mezcla de generación, métricas desconocidas y scores no finitos/fuera de rango. Deriva solo base v3; v4 sin score queda `unknown` y con score válido conserva `source_provided`. Pasaron 61 pruebas dirigidas, backend completo 1.356/1.356 bajo bloqueo externo y Docker sin red, frontend 381/381, TypeScript/build y 291,0/322 KiB, `compileall` y diff-check. |
| **PROD-098 — P2 — completada**<br>Mapeo CPE↔purl solo corroborado | El analista necesita que un CVE de producto no se asigne automáticamente a un paquete homónimo. Flujo: hallazgo OSV exacto + CVE → evidencia NVD CPE en memoria → política revisada CVE-bound → estado de identidad. | `cpe_purl_mappings.py`, normalizador NVD, PVI/persistencia/modelos, UI de hallazgo/comparación, informe, contratos, docs y fixtures. | Sin entrada exacta el estado permanece `present_unmapped`; una equivalencia liga ecosistema+nombre, parte/vendor/product y CVE exactos, es versionada/revisable y nunca deriva por nombre. El CPE bruto, UUID, rango y metadata no se persisten; la señal no crea hallazgo ni sustituye la afectación OSV. Homónimos, CVE distinto, escapes, duplicados y política ambigua fallan cerrados. | Falsos positivos masivos y decisiones de actualización erróneas; retener CPE completo amplía datos sin necesidad. | PROD-079/093/095 completadas. | L | **2026-09-09:** registro inmutable/acotado (256) y política `2026-09-09.1`, vacía por defecto hasta revisar evidencia primaria. Contratos NVD `2026-09-09.2` y PVI `2026-09-09.5`; persisten solo estado, conteos, IDs de mapeo y versión. Fixtures sintéticas demuestran match exacto, homónimo/CVE/ecosistema/vendor distinto, escape, duplicado, integración, procedencia, informe y UI. Pasaron 67 pruebas backend dirigidas, suite Python offline 1.856/1.856, frontend dirigido 32/32 y completo 57 archivos/388 pruebas, TypeScript/Vite y bundle 291,9/322 KiB, `compileall`, Compose base/privado y diff-check. Sin Internet ni proveedor real; el catálogo real queda separado en PROD-238. |
| **PROD-099 — P2 — completada**<br>Cadena de procedencia de snapshots de advisories | Operación necesita reproducir qué datos públicos sustentaron un análisis. Flujo: descarga/importación → checksum/fecha/fuente → snapshot inmutable → correlación → retención. | Almacén de advisories, config, informes, runbook y tests. | Cada snapshot tiene ID, checksum, fuente, recuperación y caducidad; resultado apunta al snapshot y no conserva respuesta cruda innecesaria. Imports corruptos/repetidos se rechazan. | Sin procedencia no se puede explicar un cambio; retener respuestas completas incrementa exposición/licencia. | PROD-033/054/061 completadas. | L | **2026-09-09:** contrato PVI `2026-09-09.4`; fuente/tiempos/conteo/digest de conjunto y snapshot offline quedan vinculados sin duplicar cuerpos ni consultas. Sello canónico por revisión verificado al leer; alteración falla cerrada y legado queda `unknown`. UI/informe exponen la traza acotada; reimport offline repetido se rechaza y rollback sigue separado. 51 pruebas dirigidas, backend 1.383/1.383, frontend 383/383, build 291,2/322 KiB, compileall, cuatro variantes Compose y diff-check, todo sin red. |
| **PROD-100 — P2 — completada**<br>Caché obsoleta y degradación explicable | Un usuario necesita distinguir «sin datos» de «datos de hace N días». Flujo: consulta/cache → evaluar TTL → estado actual/obsoleto/fallido → panel/informe. | Caché M3, modelos, UI, observabilidad y tests. | Nunca trata cache expirada como consulta actual; expone fecha/estado sin URL/payload y permite política fail-open/fail-closed documentada. Pruebas con reloj fijo y proveedor caído. | Inteligencia vieja o caída aparece como veredicto actual; reintentos en cascada agotan recursos. | PROD-033/053/099 completadas. | M | **2026-09-09:** política híbrida explícita: stale solo con respuesta validada dentro de retención; sin ella, `unavailable`. Circuito independiente por proveedor tras tres timeouts/429/caídas, cooldown 30 s, cero socket mientras está abierto y recuperación con respuesta válida. UI/informe muestran `provider_circuit_open`, frescura y digest sin identidad/URL/error bruto. Pruebas dirigidas de reloj/caída/circuito y recuperación; backend 1.385/1.385 offline, frontend dirigido 24/24, build 291,2/322 KiB, compileall, cuatro Compose y diff-check. |
| **PROD-101 — P1 — completada**<br>Motor local de correlación determinista | El usuario necesita el mismo resultado para el mismo componente y snapshot, aun offline. Flujo: purl+versión exacta → advisories normalizados fixture → evaluar rango → estado y razón → hallazgo. | `vulnerability_correlation.py`, PVI, fixtures, pruebas y guía M3. | No hace red ni compara identidades/rangos no soportados; entrega resultado por componente/advisory con razón, versión afectada/fix o `unknown`. Fixtures cubren afectado, corregido, fuera de rango y datos insuficientes. | Lógica no determinista o demasiado optimista genera falsos negativos y comparaciones incoherentes. | PROD-027/079/080; prepara PROD-028/050. | L | 2026-09-05: se extrajo un motor puro que decide `affected`/`not_affected`/`unknown` por advisory y componente sin socket, archivo ni egress. El flujo OSV lo usa para crear hallazgos y conserva `unavailable` cuando una respuesta devuelta no puede verificarse localmente. Un rango OSV `introduced=0` sin límite se reconoce como todas las versiones afectadas. Pasaron pruebas puras de afectado, corrección, rango no soportado, retirada, identidad distinta y ausencia de socket; integración OSV, suite `backend/tests tools/tests`, `compileall`, Compose, diff y backend Docker `/health`, sin Internet. |
| **PROD-102 — P1 — completada**<br>Huella estable de vulnerabilidad por componente | Triage y comparación necesitan que un mismo advisory no cambie de identidad por orden/fuente. Flujo: resultado correlado → huella versionada → agrupar en ejecución → comparar/triaje. | Normalizador de hallazgos, comparación, modelos, informes y tests. | Huella incluye purl/version/advisory/regla versionados, no ruta privada; cambios de evidencia no duplican un hallazgo y cambios de componente sí. Pruebas de orden, fuentes múltiples y dos snapshots. | Deduplicar en exceso oculta componente afectado; huella con rutas filtra topología. | PROD-003, PROD-101; prepara PROD-065/066. | M | 2026-09-05: `vulnerability_fingerprint.py` crea la huella `pvf_…` desde proveedor, advisory canónico, PURL reconstruido, versión exacta y versiones de contrato/regla, separada del `evidence_digest`. El snapshot y API exponen `fingerprint_version`; snapshots antiguos siguen legibles como `legacy_evidence_digest`. Informes muestran ambos identificador y esquema, sin rutas. Pasaron 32 pruebas dirigidas de OSV/correlación/huella, la suite completa `backend/tests tools/tests`, `compileall`, Compose, `git diff --check`, build Docker backend y frontend temporal (38 archivos/259 pruebas y build 310,3/322 KiB). Las pruebas no consultaron proveedores públicos. |
| **PROD-103 — P2 — completada**<br>Excepciones temporales y revisión obligatoria | Equipos necesitan aceptar riesgo temporal sin borrar el hallazgo. Flujo: detalle o centro de remediación → motivo/fecha → excepción visible → caducidad/reapertura → cartera/comparación/informe. | `finding_lifecycle.py`, rutas de decisiones/lotes, modelos existentes, `FindingLifecyclePanel`, `RemediationCenterPanel`, cartera, docs y tests. | Solo actor autorizado crea excepción, motivo limitado/redactado y fecha UTC futura obligatoria, como máximo a 366 días; al caducar reaparece, no altera resultado base y queda auditado. Registros legados sin fecha fallan a revisión sin reescribir historial. | Excepción eterna es ocultación; texto libre puede contener secretos. | PROD-066 y PROD-109 completadas; desbloquea PROD-114. | M | **2026-09-09:** `accepted`/`false_positive` rechazan fecha nula, ingenua, vencida o superior a 366 días tanto en acción individual como atómica. UI de detalle y lote exige fecha con límites y ayuda; el legado sin fecha deriva `in_review`, `review_overdue=true` y la cartera lo cuenta vencido. Motivos/comentarios mantienen redacción, owner scope y append-only; comparación/informe leen el estado derivado. Pasaron 19/19 pruebas backend y 9/9 frontend dirigidas, suite Python offline 1.861/1.861, 58 archivos/392 pruebas frontend, axe, build 292,1/322 KiB, `compileall`, Compose base/privado y diff-check. Sin Internet ni cambios en bloqueos. |
| **PROD-104 — P2 — completada**<br>Línea base consciente de cobertura | Un responsable necesita que una mejora aparente no oculte menos análisis. Flujo: elegir base → nueva ejecución → comparar hallazgos y cobertura → decisión explicada. | Comparación, cobertura, UI, informes y fixtures. | Clasifica `not_comparable` por cambio de perfil/cobertura/truncamiento; no llama «resuelto» a lo que dejó de analizarse. Pruebas de manifest/lockfile omitido y fuente eliminada. | Métricas engañosas incentivan degradar cobertura. | PROD-035/057/065. | M | 2026-09-05: el contrato devuelve dos resúmenes agregados de cobertura y una comparación `equivalent`/`changed`/`unknown`. Para análisis archive-backed, un resumen ausente o un cambio de límite, entradas, manifiestos, lockfiles o dependencias detiene la clasificación antes de construir nuevos/resueltos/persistentes. La UI identifica los campos y muestra dos tarjetas responsive; la retención de bytes se distingue de la cobertura capturada y no invalida por sí sola resultados redactados. Pasaron 3 pruebas backend dirigidas, 1.348 casos backend/runner completos, `compileall`, 38 archivos/264 pruebas frontend, build/presupuesto 311,1/322 KiB, `docker compose config --quiet`, `git diff --check`, Compose reconstruido y `/health`. La revisión local a 1265/640 px no tuvo desborde ni errores de consola; solo usó el fixture sintético y ningún proveedor público. |
| **PROD-105 — P2 — completada**<br>Tendencias de riesgo reproducibles | Dirección necesita evolución, no solo una foto actual. Flujo: ejecuciones comparables → serie agregada → nuevos/resueltos/persistentes → filtro temporal/informe. | Modelos agregados, comparación, dashboard, informes y pruebas; materializada por PROD-147. | Solo incluye ejecuciones comparables, declara denominador/cobertura y permite volver a evidencia; no crea telemetría externa. Pruebas de orden temporal, huecos y cambio de perfil. | Gráficas sin contexto inducen decisiones; agregados entre propietarios revelan actividad. | PROD-065/104/145/146 y organización actual. | L | **2026-09-09:** `PROD-147` implementó una proyección owner-scoped con comparabilidad estricta, periodos/buckets cerrados, denominadores, exclusiones y exportación; evidencia completa en su ficha. |
| **PROD-106 — P2 — completada**<br>Perfil de redacción para informes de equipo | Un equipo necesita compartir un informe sin incluir nombres de archivo, rutas o evidencia sensible por defecto. Flujo: elegir perfil → comprender contenido → exportar → registrar política. | Reporting, modelos/API, autorización/CSRF, auditoría, UI, docs, smoke y tests. | Perfil mínimo es default; detalle técnico exige confirmación/permiso y omite secretos/rutas retenidas. Pruebas negativas de JSON/PDF/SARIF y de enlace público. | Una exportación es vía común de fuga de datos; redacción excesiva inutiliza correcciones. | PROD-006/075/109/069 completadas. | M | **2026-09-10:** `GET` solo entrega un agregado mínimo sin proyecto/miembro, IDs, rutas, evidencia, componente/advisory, decisión libre o digest, con filename genérico. El detalle técnico usa un `POST` separado con `profile=technical`, confirmación literal, CSRF y maintainer/admin; bearer requiere `report:read`. Sigue redactando secretos/rutas inseguras/fuente y ambos perfiles son `private,no-store`. La UI explica el límite, reinicia confirmación al cambiar análisis y reader solo obtiene mínimo. Un query no eleva perfil; JSON, SARIF y enlace público permanecen ausentes. Auditoría conserva solo formato/perfil y referencias opacas existentes. Pasaron 15 pruebas dirigidas de auth/report, 17 de auditoría/smoke, backend completo 1.563/1.563 y frontend 58 archivos/412 pruebas; axe, TypeScript/Vite, bundle 300,0/322 KiB, `compileall`, Compose base/privado y diff-check. La primera pasada global detectó la ruta nueva ausente del inventario cerrado de mutaciones; se añadió al contrato y a la parametrización auth/CSRF antes de repetir en verde. Sin Internet, push, PR ni cambio de bloqueos. |
| **PROD-107 — P2 — completada**<br>Bandeja pasiva durable de acciones y avisos | Un usuario necesita conservar qué proyecto pasivo requiere revisión sin enviar datos a terceros. Flujo: transición de análisis/riesgo/caducidad → evento deduplicado → bandeja owner-scoped → abrir resultado → marcar leído. | `project_action_inbox.py`, cartera, API/auth/auditoría, backup/borrado/retención, `ProjectActionInboxPanel`, docs y tests. | Persiste solo evento cerrado de cambio, riesgo o caducidad, sin evidencia/texto libre; deduplica, admite leído y reconstrucción, y no confunde la action inbox Active con proyectos pasivos. Dos organizaciones, orden, interrupción y límites. | Una bandeja efímera pierde trabajo; mezclar Active y pasivo o guardar evidencia filtra alcance y genera fatiga. | PROD-042/065/066/145/146 completadas; no requiere webhooks. | M | **2026-09-10:** cartera autoritativa → máximo 2.000 acciones cerradas/100 lectores → orden no leído/prioridad → deep link → marca SHA-256 por usuario; una ejecución nueva vuelve a avisar y una señal resuelta desaparece. Reader puede leer/marcar con CSRF; rebuild queda en maintainer/admin y reinicia leído. Store `0600` atómico sin nombre/evidencia/ruta/fuente/secreto; corrupción falla `503`, backup valida tenant/proyecto y borrado recuperable purga. Retención `2026-09-10.4` añade la clase 22. Pasaron backend completo 1.573/1.573, frontend 59 archivos/415 pruebas, axe, build 300,9/322 KiB, `compileall`, Compose base/privado y diff-check. Recorrido local sintético en navegador: 2→1→2 no leídos, navegación exacta, 1280×720/390×844, 375/375 px sin overflow, consola vacía; store sin canarios y entorno totalmente eliminado. Sin Internet. |
| **PROD-108 — P2 — completada**<br>Cartera de proyectos y priorización de equipo | Un responsable necesita priorizar varios proyectos sin abrirlos uno a uno. Flujo: cartera autorizada → agregados → filtro → entrar a proyecto → evidencia. | `project_portfolio.py`, `ProjectPortfolioPanel`, tendencias, API/informes y tests; materializada por PROD-145/147. | Muestra solo proyectos permitidos y agregados de cobertura/riesgo, sin rutas/archivos; en modo local conserva ámbito personal. Pruebas de 0/1/muchos, dos tenants, escala, filtros, paginación y responsive. | Agregar datos entre equipos vulnera aislamiento y puede ocultar denominadores. | PROD-012/065/104; materializada por PROD-145 y PROD-147. | L | **Reconciliada 2026-09-09:** PROD-145 aporta cartera owner/org-scoped con prioridad explicable, cobertura/frescura, cursor firmado, filtros/deep links y prueba de 2.000 proyectos; PROD-147 añade tendencias comparables y perfiles. Las regresiones de cartera formaron parte del grupo backend 30/30 sin red. |
| **PROD-109 — P2 — completada**<br>Matriz de permisos y pruebas de aislamiento | Empresas necesitan demostrar que cada rol ve/edita solo lo permitido. Flujo: organización → rol → proyecto/hallazgo/exportación → denegar o auditar. | `team_identity.py`, middleware/helpers de autorización, rutas, UI existente, pruebas y `docs/team-permission-matrix.md`. | Matriz cerrada `reader ⊂ maintainer ⊂ administrator`, deny-by-default; reader solo usa GET y cinco POST exactos de consulta con CSRF. Rutas administrativas revalidan capacidad, stores aíslan por organización y cambio de rol/workspace invalida sesión/CSRF. Pruebas cubren lectura/mutación/administración, dos tenants y recursos cruzados sin revelar existencia. | Escalada horizontal, mutación de reader o exportación de otro equipo. | PROD-012/013 completadas; desbloquea PROD-103/110/115 y prepara PROD-039/067. | L | **2026-09-09:** capacidades runtime `workspace_read`, `project_mutate`, `workspace_admin`; rol/capacidad desconocidos se deniegan. Allowlist reader de POST se prueba por igualdad exacta y sin paths parametrizados. Casos API prueban maintainer sin invitaciones/auditoría, reader sin mutación, cambio de rol con sesión invalidada, dos organizaciones, triage/assignee y atestaciones. 5/5 dirigidas y suite Python offline 1.858/1.858; `compileall` y diff-check. La UI existente oculta controles por rol y su regresión completa previa pasó 388/388. Contrato operativo en `docs/team-permission-matrix.md`; no SSO, red ni proveedor real. |
| **PROD-110 — P2 — completada**<br>Integridad encadenada de auditoría de acciones | Un administrador necesita detectar alteración de operaciones sensibles. Flujo: acción → evento mínimo → hash encadenado → consulta autorizada → verificación. | Auditoría, almacenamiento, runbook y tests. | Cada evento enlaza al anterior por ámbito, no incluye secreto/contenido; verificador detecta corte, orden roto o manipulación y no impide operación primaria si la bitácora falla de forma segura. | Auditoría manipulable o con secretos no sirve para incidentes. | PROD-063/061, PROD-109. | L | **2026-09-10:** contrato de integridad `2026-09-10.1`, ledger privado por organización y generaciones encadenadas. Cada evento conserva digest exacto, secuencia y digest previo; lectura/exportación/backup fallan cerrados ante cambio, corte, inserción, reordenación o estado inconsistente. Retención avanza un ancla antes de purgar y la anonimización Active rota una generación ligada al head anterior. `GET /audit/integrity` es solo administrador y la UI distingue válido, vacío, bootstrap legado, almacenamiento inválido y recuperación. Limitación documentada: SHA-256 local sin clave no resiste a quien reescriba eventos, ledger y head completos. Pasaron 45 pruebas backend dirigidas; suite backend completa 1.555/1.555 sin red; frontend completo 410/410 y build 299,1/322 KiB; `compileall`, Compose y diff-check. El primer pase frontend tuvo una intermitencia de temporización ajena en paginación Active: pasó aislada y en la repetición completa. El primer backend con `/tmp` artificial de 256 MiB agotó disco; con el límite operativo de 2 GiB pasó completo. |
| **PROD-111 — P2 — completada**<br>Onboarding seguro con datos sintéticos | Un desarrollador nuevo necesita probar el flujo sin subir código sensible por error. Flujo: bienvenida → límites claros → fixture local → análisis → borrar datos de demostración. | Frontend, fixture sintético, docs, tests y guía de privacidad. | La muestra es sintética y etiquetada, no se activa sola ni simula CVE real; explica archivo admitido, cobertura y cómo eliminarlo. Pruebas de navegación/foco y ausencia de secretos. | Demo realista con datos reales o promesas de cobertura crea riesgo/confusión. | PROD-017/043/076. | M | 2026-09-05: el aviso visible usa la muestra como elección manual de `tests/fixtures/demo/passive-alpha/`, sin lectura/carga automática ni promesa de CVE/explotación. Mantiene redacción y explica borrar archivo/trabajos, declarando que el historial conserva metadatos por política. `docs/product-projects.md` añade el recorrido, ZIP sugerido, resultado esperado y límite de purga; `PROD-120` cubre la eliminación total futura. `App.test.tsx` verifica copy, foco y límites; pasaron 38 archivos/259 pruebas frontend, build y presupuesto 310,6/322 KiB, sin red de proveedores. |
| **PROD-112 — P2 — completada**<br>Puerta de alcance para automatización CI | Equipos quieren automatizar sin permitir a un token ejecutar sobre cualquier fuente. Flujo: CI autorizado → fuente/snapshot explícita → perfil permitido → resultado versionado/local. | Tokens, admisión CI, policy, CLI, auditoría y tests; materializada por PROD-133–135/153. | Exige organización/proyecto/commit/digest/perfil explícitos y confirmación no interactiva; deniega URL/target/ruta host y Active. Pruebas de replay, token caducado/revocado, digest conflictivo y cruce de proyecto. | CI se vuelve vector de análisis no autorizado o exfiltración. | PROD-133–135 y PROD-153. | L | **Reconciliada 2026-09-09:** bearer project-scoped con scopes cerrados, snapshot commit-bound e idempotente, policy reproducible y asistente que nunca incrusta el secreto. Pasaron las regresiones correspondientes dentro de 29 pruebas CLI y 30 backend sin red. |
| **PROD-113 — P1 — completada**<br>Vista de resultados de vulnerabilidades profesional | El analista necesita pasar de resumen a evidencia/recomendación sin leer JSON. Flujo: ejecución → resumen por severidad/KEV/frescura → filtros → detalle → siguiente acción. | Panel de hallazgos, tipos, estilos, informe, axe y pruebas. | Incluye carga/error/vacío/no-cubierto, búsqueda/filtros combinables, severidad separada de KEV, fuente/frescura y recomendación sin enlaces inseguros. Pruebas de teclado, móvil y datos incompletos. | UI que sobrerrepresenta confianza o mezcla KEV/CVSS provoca mala priorización. | PROD-029/030/050 completadas; PROD-094/097 amplían fuentes/CVSS pero no bloquean la presentación honesta de ausencias. | L | 2026-09-06: el panel muestra `disabled`/en curso/actualizado/parcial/caducado, política de egress y snapshot retenido; separa los tres pasos y explica que KEV nunca crea el hallazgo. Ordena primero explotación conocida y después CVSS/alcance, resume cinco señales, mantiene la cobertura detallada contraída, ofrece filtros combinables/restablecibles y abre solo la primera evidencia prioritaria. Los enlaces siguen limitados a HTTPS públicos seguros. Fixtures cubren `not_requested`, `disabled`, no correlacionable, `ready`, `degraded`, `stale`, carga y error; axe no halló violaciones automatizadas. La revisión visual con aplicación/API locales y snapshot creado por adaptadores simulados pasó a 320/768/1440 px, foco visible, `scrollWidth == clientWidth` y consola vacía; encontró y corrigió un desborde previo de 8 px en listas de hallazgos. Pasaron 38 archivos/277 pruebas frontend (18,89 s), TypeScript/Vite y presupuesto 311,6/322 KiB (7,51 s), sin Internet. |
| **PROD-114 — P2 — completada**<br>Accesibilidad específica de inteligencia y triage | Lectores de pantalla y teclado necesitan comparar riesgo, estado y excepción con la misma claridad. Flujo: inteligencia/filtros → detalle → triage → confirmación/errores. | `ProjectVulnerabilityIntelligencePanel`, `ProjectFindingsPanel`, `FindingLifecyclePanel`, estilos, tests axe y guía visual. | Etiquetas, foco, anuncio de filtros/resultados, contraste y responsive cumplen la matriz definida; no usa color como única señal. Pruebas axe y navegación de extremo a extremo con fixture. | Un flujo inaccesible excluye al analista o hace que omita una advertencia crítica. | PROD-077/103/113 completadas. | M | **2026-09-09:** filtros como `fieldset`/`legend`, conteos live separados de controles, listas/detalle etiquetados, foco visible y restaurado después del render y jerarquía `h2`→`h3`. Axe descubrió el salto anterior a `h4`; el navegador real descubrió pérdida de foco al desmontar el botón y desbordamientos intrínsecos, todos corregidos con regresión. El flujo sintético local ejercitó egress deshabilitado, filtrado, detalle y excepción acotada; a 320/768/1440 px el documento quedó `305/305`, `753/753` y `1425/1425`, consola vacía. Pasaron 37/37 dirigidas, 58 archivos/392 frontend, axe y build 292,1/322 KiB. Servicios, puertos, contenedores y datos temporales eliminados; sin Internet ni cambios en bloqueos. |
| **PROD-115 — P2 — completada**<br>Consola operativa de frescura y egress | Operación necesita comprobar proveedor, cache y degradación sin ver consultas ni proyectos. Flujo: admin autorizado → salud agregada → revisar cobertura → limpiar expirados/invalidos tras confirmación → evento auditado. | `public_advisory_egress.py`, modelos/API, `PublicAdvisoryOperationsPanel`, equipo, estilos, auditoría y `docs/public-vulnerability-intelligence.md`. | Expone solo egress/snapshot, configuración, fresh/stale/invalid, bytes, última actualización y truncado para cuatro proveedores fijos; no acepta selectores ni lista componentes/URLs/payloads. Lectura es admin/no-store y limpieza local exige CSRF, confirmación y audit trail mínimo. | Panel operativo puede convertirse en fuga o control inseguro de red. | PROD-053/060/089/100/109 completadas. | M | **2026-09-09:** resumen acotado a 10.000 entradas por proveedor y purga restringida a ficheros digest de la caché, nunca snapshots/hallazgos ni red. Panel accesible con carga, error, reintento, estados semánticos y confirmación; el runbook separa configuración de conectividad real. Pasaron 2/2 pruebas backend y 7/7 frontend dirigidas, suite Python offline 1.860/1.860, 58 archivos/390 pruebas frontend, axe, build 292,1/322 KiB, `compileall`, Compose base/privado y diff-check. Sin Internet ni cambios en bloqueos. |
| **PROD-116 — P1 — completada**<br>Candidatura de despliegue segura y reversible | Un operador necesita una versión candidata demostrable antes de confiar datos de proyecto. Flujo: configuración privada → migración/arranque → smoke → aceptación → rollback probado. | Compose privado, imágenes, configuración, migraciones, CI, runbooks y docs. | Define versión, hashes de imagen, secretos externos, backups, smoke, criterios de go/no-go y rollback sin borrar proyectos; se ejecuta en entorno aislado documentado. | Despliegue sin reversión o controles puede perder datos/exponer servicio. | PROD-059/060/064/075 y validaciones existentes. | L | 2026-09-06: `DEPLOYMENT_ACCEPTANCE.md` contiene el acta local, IDs/tamaños de cinco imágenes, configuración y go/no-go. Una pila Compose con nombre único publicó solo TLS/HTTP en loopback; el smoke TLS sintético verificó readiness, cabeceras, auth/CSRF, cookie Strict, análisis, 14 clases, informe, privacidad y cleanup en 1.117,271 ms, sin proveedor. La recreación preservó sesión/datos y recuperó readiness en 12.953,615 ms; retirar `audit-tools` produjo `/ready` 503 seguro y recuperó en 1.328,546 ms. Los cinco servicios tienen CPU/memoria/PID, raíz/capacidades restringidas según rol; cargas/workspaces terminaron a cero. Pasaron 1.096 backend, 423 runner/guardas, 306 frontend, build 317,4/322 KiB, `compileall`, tres Compose, cinco `pip-audit`, `npm audit`, Gitleaks historia/árbol y diff, sin omisiones. La revisión 1440/768/320 no tuvo desborde ni errores. El rollback de datos está cubierto por el drill sintético de PROD-064 y la recreación del montaje; una reversión entre versiones exige conservar el artefacto previo por digest cuando se autorice promoverlo. No hubo push, PR, proveedor, despliegue externo ni proyecto real. |
| **PROD-117 — P1 — completada**<br>Aceptación real con una fuente autorizada exacta | Un desarrollador necesita comprobar que Inspectra procesa un proyecto propio sin leer el worktree, filtrar identidad privada ni dejar residuos. Flujo: commit autorizado → snapshot reproducible → preflight local → análisis sin egress → overlay opt-in → OSV/KEV → resultados/comparación/triage/informes → reinicio/degradación/recuperación → limpieza. | README, `docs/product-projects.md`, `DEPLOYMENT_ACCEPTANCE.md`, política de egress, inventario, PVI, informes, frontend y pruebas. | La instantánea procede solo del objeto Git autorizado; Gitleaks completo y canario pasan antes de red; solo npm/PyPI exacto y público puede salir. El tráfico real se limita a OSV y, tras CVE exacto, CISA KEV; GHSA sigue prohibido. Se verifican persistencia, estados honestos, UI responsive, aislamiento y ausencia final de recursos. | Leer el worktree o enviar scopes/locators privados expondría datos; declarar ausencia durante fallo produciría falsos negativos; una limpieza parcial retendría código o credenciales. | `PROD-043`, `PROD-075`, `PROD-116`, `SEC-020`, `PROD-125`…`PROD-128` completadas. | M | 2026-09-06 — `fuente autorizada A` conservó su **NO-GO** honesto por no tener versiones exactas. La segunda fuente completó la tarea con **GO acotado**: commit fuente autorizada B `[commit autorizado B redactado]`, 1.417 archivos/12.871.680 bytes, SHA-256 canónico `[SHA-256 de snapshot B redactado]`, `package-lock.json` v3 y Gitleaks 0/canario detectado. El inventario obtuvo 590 componentes; consultó solo 369 npm exactos/no scopeados y retuvo 212 scopeados más 9 no exactos. OSV oficial devolvió 33 ocurrencias (28 IDs/25 CVE), 33 fixes y 0 indisponibles; CISA KEV evaluó solo esos CVE (30 no listados, 3 sin CVE no evaluados, 0 explotados); GHSA real no se consultó. Captura sin destinos inesperados, caché, comparación 0/0/33, triage, informes, reinicio, degradación sin falso limpio, recuperación y UI 320/768/1440 pasaron. También 1.523 backend, 307 frontend, build 317,4/322 KiB, cuatro Compose, `compileall`, diff y Gitleaks. La limpieza dejó a cero proyectos, archivos, snapshots, workspaces, contenedores, volúmenes, redes, imágenes y temporales. El worktree ajeno cambió concurrentemente, pero nunca fue fuente ni destino; la instantánea quedó ligada al objeto Git. Acta completa en `DEPLOYMENT_ACCEPTANCE.md`. |
| **PROD-118 — P1 — completada**<br>Preservar intervalos OSV discontinuos | Un analista necesita que una vulnerabilidad con varios periodos afectados no pierda un intervalo al normalizarse. Flujo: respuesta OSV → eventos ordenados → intervalos normalizados acotados → motor local → hallazgo/cobertura. | `public_advisories.py`, contrato de snapshots, motor local, fixtures, pruebas y guía M3. | Conserva cada intervalo válido hasta un máximo explícito, sin fusionar periodos separados; si no se puede representar, declara `unknown` y nunca `not_affected`. Fixtures cubren `introduced/fixed/reintroduced/fixed`, límites, orden hostil y migración de snapshot. | Colapsar eventos puede producir un falso negativo para una versión reintroducida o una explicación de corrección equivocada. | PROD-027/101; coordina PROD-099. | M | 2026-09-05: el normalizador versión `2026-09-05.2` descompone eventos OSV ordenados en intervalos separados, con tope de 25 intervalos y 50 eventos por rango. No conserva un prefijo como si fuera completo: orden inválido, evento malformado o exceso queda `affected_ranges_complete=false`; el motor devuelve `unknown` y el flujo OSV se degrada, sin hallazgo ni negativo. Pasaron fixtures de reintroducción, límites, orden hostil e integración de estado degradado; suite backend/runner, `compileall`, Compose, diff y Docker `/health`, sin Internet. |
| **PROD-119 — P1 — completada**<br>Preflight reproducible de versión Python para locks | Quien instala o valida Inspectra necesita saber antes de descargar dependencias si el intérprete satisface el lock, y CI/local deben seguir el mismo contrato. Flujo: `make` → detectar intérprete → comprobar versión soportada → crear entorno → instalar lock → pruebas/auditoría. | `Makefile`, CI, README/despliegue y pruebas de scripts. | El bootstrap exige Python 3.12 de forma explícita y falla antes de `venv`/`pip` con instrucción accionable si recibe otra versión; `make test-python`, auditoría y CI usan esa misma comprobación. Una instalación fría con Python 3.12 resuelve los lockfiles, mientras Python 3.10 se rechaza sin intentar una resolución parcial. | Un entorno local parece preparado pero falla al resolver, produciendo builds no reproducibles y una falsa señal de calidad. | Ninguna; coordina validaciones de `PROD-116`. | S | 2026-09-05: `check-python-version` se ejecuta antes de `setup-python`, exige 3.12 y explica cómo seleccionar el binario correcto. La prueba estática verifica el preflight y README; `make check-python-version` con Python 3.10.12 falla con código 2 antes de crear venv/pip, y con Python 3.12.14 pasa. Un venv temporal nuevo creado por `make setup-python` resolvió los locks; `make test-python` en él pasó 1337 pruebas. También pasaron `compileall`, Compose y `git diff --check`. |
| **PROD-120 — P2 — completada**<br>Eliminación completa y verificable de proyecto | Un equipo necesita retirar proyecto y derivados con un alcance comprensible sin afectar otro propietario. Flujo: preflight → confirmación → marcador durable → cascada/recovery → ausencia verificable. | `project_deletion.py`, stores/API, `ProjectDeletionPanel`, retención, auditoría, runbook y tests. | Solo organización autorizada; scope declara delete/retain/not-stored; idempotente, recuperable y bloquea admisión mientras existe marcador. Elimina metadatos, jobs/resultados, snapshots PVI, triage, admisiones y workspaces; conserva explícitamente uploads, cache pública compartida y auditoría por sus políticas independientes. | Cascada cruzada o parcial puede borrar datos ajenos o dejar derivados inesperados. | PROD-062 completada. | M | **Reconciliada 2026-09-09:** implementación existente usa write-ahead `2026-09-06.1`, readiness fail-closed y recuperación tras interrupción. Pruebas cubren dos owners, repetición, trabajo activo, caída en cada frontera, API/exportación y ausencia de derivados; 5 tests de servicio más la ruta ASGI pasaron dentro del grupo backend 30/30 sin red. No promete borrado forense ni elimina uploads compartidos fuera de su lifecycle. |
| **PROD-121 — P1 — completada**<br>Procedencia pública mínima para OSV PyPI | Un equipo Python necesita recibir advisories OSV para un paquete PyPI exacto solo cuando Inspectra pueda demostrar que esa identidad es pública sin enviar datos del proyecto. Flujo: declaración PyPI + resolución compatible → prueba de procedencia pública mínima → filtro de privacidad → OSV opt-in → snapshot/resultado/comparación/informe. | Inventario Python, política de egress, PVI/OSV, modelos, UI, informes, docs y fixtures. | Define una señal versionada de procedencia PyPI pública que no conserve ni exponga URL/índice/credencial; Poetry 2.1 local-only no es suficiente por sí mismo. Reutiliza los límites opt-in, allowlist, caché, caducidad y redacción de `PROD-026`; solo remite `pypi`, nombre normalizado y versión exacta bajo `PRIVATE_PACKAGE_RULES`. Pruebas con fixtures cubren identidad pública aceptada, paquete privado/local/ambigua rechazado, payload mínimo, respuesta OSV, estados disabled/empty/unavailable/stale, comparación e informe sin Internet. | Enviar un nombre de paquete interno a OSV es fuga de metadatos; asumir PyPI por un lockfile puede producir SSRF lógico/falsos positivos. | PROD-026/027/028/033/079/084; libera la restricción temporal de parsers, pero no adelanta `PROD-085/086` sobre trabajo de producto/operación prioritario. | L | 2026-09-06: `INSPECTRA_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES` es una atestación local, vacía por defecto, de hasta 100 nombres PyPI exactos normalizados; rechaza URL, ruta, comodín y credencial, no se persiste ni se registra. Solo un pin directo `==` de `pyproject.toml` que coincide con la versión exacta y no está bloqueado por `PRIVATE_PACKAGE_RULES` puede salir a OSV. Poetry 2.1 sigue local-only. El snapshot `2026-09-06.1` conserva procedencia `operator_attested_public_pypi`, no rutas/índices, y la UI distingue identidad no atestada. La comparación de ejecuciones usa snapshots OSV frescos/ready y huellas actuales; ante ausencia, degradación o caducidad no declara resoluciones. GHSA recibe únicamente el alias ya retenido y CISA KEV solo el catálogo fijo, cruzado por CVE exacto. Pasaron 23 pruebas backend dirigidas/`compileall`, 38 suites/270 pruebas frontend y build con 311,1/322 KiB, `docker compose config --quiet` y `git diff --check`, todo sin Internet. La validación transversal posterior ejecutó 997/997 pruebas backend y corrigió expectativas obsoletas sin relajar la atestación PyPI. Ninguna validación contactó proveedores reales. |

### PROD-122 — Worker con montaje y cuota fuerte por ejecución

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo que evalúa código no
  confiable necesita que un fallo o compromiso del runner de una ejecución no
  permita leer fuentes o artefactos de otra, incluso en el mismo host.
- **Flujo completo afectado:** reservar intento durable → crear fuente mínima
  de solo lectura → iniciar worker aislado con CPU/memoria/PID/disco/tiempo →
  producir resultado acotado → desmontar y limpiar → registrar causa.
- **Áreas o archivos implicados:** orquestador/runner, Compose o runtime de
  workers, almacenamiento, leases, configuración, observabilidad y runbook.
- **Criterios de aceptación verificables:** el worker recibe únicamente la
  fuente verificada del job en staging `0400` y un resultado acotado, no monta
  `data/`; las cuotas
  se aplican por ejecución y quedan atestadas en el intento. El cleanup es
  idempotente tras éxito, cancelación, timeout, kill y reinicio. Una prueba con
  dos propietarios demuestra que ningún worker enumera o lee el otro workspace
  y que no queda montaje, proceso ni byte temporal.
- **Riesgos de seguridad, privacidad y operativa:** el montaje read-only actual
  reduce escritura pero no lectura transversal si el runner es comprometido;
  workers dinámicos mal gestionados pueden dejar procesos o volúmenes.
- **Dependencias:** `PROD-008` y `PROD-015` completadas;
  `PROD-012` antes de declarar uso multiempresa.
- **Tamaño:** L
- **Estrategia de pruebas:** runtime falso determinista para leases/cleanup,
  prueba de permisos con dos workspaces, límites/kill/reinicio y smoke aislado
  sin proyecto real ni red de proveedores.
- **Evidencia de validación al completarse:** 2026-09-06: `audit-tools` quedó
  sin `data/` y sin egress; `network-tools`, sin volumen, concentra web/DNS y
  rechaza archivos. El backend transmite solo una fuente con tamaño/SHA-256 e
  identidad mínima, a destinos fijos y sin proxy de entorno. Cada análisis usa
  un subproceso efímero, serialización a uno, entorno allowlist, fuente `0400`,
  directorio `0700`, tmpfs 64 MiB, límites de CPU/memoria/PID/disco/pared y
  resultado, kill de grupo y limpieza idempotente. Perfil `2026-09-06.3` y
  resultado atestan contrato `2026-09-06.1`; timeout y recursos tienen causas
  distintas, y el 422 saneado no refleja la fuente. Pasaron 1.019/1.019 backend
  (16,90 s), 420/420 runner/guardas (6,09 s), 277/277 frontend (19,15 s), build
  311,6/322 KiB (7,29 s), Compose, compileall, diff e imágenes. Smoke sin red:
  digest correcto, red 404, `/app/data` ausente, tmpfs vacío y solo Uvicorn.
  Sin Internet, proveedor ni proyecto real; `PROD-012` sigue siendo requisito
  previo para una afirmación multiempresa.

### PROD-123 — Estados terminales exactos en inventario, hallazgos e inteligencia

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** quien investiga un análisis fallido
  o cancelado necesita saber que terminó y qué acción segura puede tomar; decir
  que sigue en cola o ejecución induce espera infinita y oculta el fallo real.
- **Flujo completo afectado:** ejecución terminal sin resultado utilizable →
  workspace del proyecto → inventario/hallazgos/inteligencia → explicación y
  acción para reintentar o elegir otra ejecución.
- **Áreas o archivos implicados:** contratos y constructores de respuestas de
  proyecto, `ProjectComponentInventoryPanel`, `ProjectFindingsPanel`,
  `ProjectVulnerabilityIntelligencePanel`, tipos, documentación y pruebas.
- **Criterios de aceptación verificables:** los tres paneles distinguen
  `queued`/`running`/`cancelling`, `failed`, `cancelled` y ejecución completada
  sin contrato/resultados; nunca rotulan un estado terminal como activo. El
  mensaje usa vocabulario cerrado, no muestra error bruto/ruta/contenido y
  ofrece seleccionar otra ejecución o reintentar cuando sea viable. Los
  contratos heredados degradan a un estado honesto. Pruebas backend/frontend y
  axe cubren cada estado; la revisión visual reproduce fallo y cancelación en
  escritorio/móvil sin proyecto real.
- **Riesgos de seguridad, privacidad y operación:** un mensaje inexacto retrasa
  respuesta, dispara reintentos innecesarios y puede tentar a exponer el error
  interno para diagnosticar; estados divergentes entre paneles erosionan la
  confianza del producto.
- **Dependencias:** `PROD-015`, `PROD-030`, `PROD-035` y `PROD-042` completadas.
- **Tamaño:** S
- **Estrategia de pruebas:** fixtures deterministas para estados del job y
  contrato ausente, pruebas parametrizadas de API/componentes, axe y navegador
  local con fuente sintética; sin runner/proveedor externo.
- **Evidencia de validación al completarse:** 2026-09-06: los tres contratos
  separan `analysis_pending`, `analysis_failed` y `analysis_cancelled`; las
  respuestas conservan solo el contexto seguro del job y una prueba ASGI
  comprueba que un marcador de secreto/ruta del error no se serializa. Un
  componente compartido presenta orientación coherente y deshabilita egress de
  inteligencia para estados terminales sin inventario. Pasaron la prueba
  backend dirigida, 36 pruebas de paneles con axe, 1.070 backend (21,69 s;
  87.372 KiB RSS), 420 runner/guardas (6,22 s; 67.628 KiB RSS) y 44
  archivos/304 frontend (21,10 s; 574.244 KiB RSS); build 317,2/322 KiB en
  8,03 s, además de `compileall`, Compose y diff. La revisión local sintética
  comprobó fallo real `runner_unavailable` y presentación cancelada a 1440/390
  px, sin desborde y con foco de 3 px. La cancelación visual se preparó con el
  mismo store probado porque el runner ausente fallaba antes de la petición; no
  se presenta como prueba de esa carrera. No hubo proveedor, Internet ni
  proyecto real; la consola no estaba disponible. Dos comandos frontend
  iniciales no ejecutaron pruebas por ruta y `--run` duplicado, y se repitieron
  correctamente sin atribuirlo al sandbox.

### PROD-124 — Retención y baja segura de invitaciones e identidades de equipo

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una organización necesita retirar
  accesos y datos de identidad obsoletos sin conservar indefinidamente hashes de
  invitación ni perder la trazabilidad mínima necesaria para investigar una
  acción administrativa.
- **Flujo completo afectado:** invitación creada → usada/revocada/caducada →
  purga acotada del hash; miembro desactivado o eliminado → revocación de
  sesiones → reasignación/retención mínima de actividad → verificación por el
  administrador.
- **Áreas o archivos implicados:** estado SQLite de autenticación, membresías e
  invitaciones, política de retención, rutas y UI de equipo, auditoría de
  producto, backup/restore, documentación y pruebas.
- **Criterios de aceptación verificables:** las invitaciones usadas, revocadas o
  caducadas se purgan con una ventana documentada y nunca exponen ni registran
  token o hash; la baja de usuario/membresía revoca sus sesiones y no cruza
  organizaciones ni permite eliminar al último administrador. Los registros de
  proyecto y actividad conservados no quedan inaccesibles o falsamente
  atribuidos; `GET /privacy/retention` describe la política efectiva y el
  restore sigue revocando acceso.
- **Riesgos de seguridad, privacidad y operación:** material de invitación
  retenido amplía el impacto de una copia de la base; una baja incompleta deja
  acceso activo, mientras una purga agresiva puede romper ownership o auditoría.
- **Dependencias:** `PROD-012`, `PROD-013` y `PROD-062`; coordina con
  `PROD-109` antes de afirmar preparación multiempresa.
- **Tamaño:** M
- **Estrategia de pruebas:** reloj fijo, dos organizaciones, invitaciones en
  cada estado, replay negativo, revocación de sesiones, protección del último
  administrador, reinicio y restauración aislada con datos sintéticos.
- **Evidencia de validación al completarse:** **2026-09-10:** ventana
  configurable 1–365 días (30 por defecto), purga terminal owner-scoped manual
  y de arranque, y restore que elimina invitaciones sin devolver su material.
  La baja revoca solo las sesiones del espacio afectado, conserva acceso
  legítimo a otros espacios y pseudonimiza/desactiva una cuenta sin membresías
  sin romper referencias históricas. Contratos `2026-09-10.3` (21 clases) y
  `2026-09-10.1`; UI y runbooks alineados. Pasaron 24 pruebas de identidad,
  retención, restore y smoke, 5 de API/config/lifespan, 9 frontend y una
  regresión Active; backend completo 1.561/1.561, frontend 410/410, build
  299,1/322 KiB, `compileall`, Compose base/privado y diff-check. La primera
  suite backend reveló una expectativa antigua del invalidator global; la
  regresión exige scope organizativo y la repetición completa terminó verde.
  Sin Internet ni promesa de borrado físico forense.

### PROD-125 — Egress opt-in utilizable en la candidatura de aceptación

- **Prioridad:** P0
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un operador autorizado necesita validar proveedores públicos desde la candidatura endurecida sin convertir la configuración segura por defecto en una red abierta ni improvisar cambios no reproducibles.
- **Flujo completo afectado:** candidatura aislada con egress deshabilitado → autorización y preflight local → aplicación deliberada de un overlay adicional → OSV/KEV desde el backend → retirada del overlay y limpieza.
- **Áreas o archivos implicados:** Compose de aceptación, red del backend, variables de inteligencia pública, pruebas de configuración y guía de aceptación/despliegue.
- **Criterios de aceptación verificables:** sin el overlay, las redes siguen internas y `INSPECTRA_PUBLIC_ADVISORY_EGRESS_ENABLED=false`; con el overlay y una variable explícita, únicamente el backend recibe una red externa dedicada y la configuración efectiva habilita el cliente. Ningún runner, frontend o proxy comparte esa red. La guía enumera los proveedores autorizados, recuerda que las rutas de aplicación siguen siendo la frontera allowlisted y exige recreación para deshabilitar/retirar la red.
- **Riesgos de seguridad, privacidad y operación:** conectar la red equivocada concede salida a código que procesa archivos; habilitarla implícitamente permite fugas; documentar como aislamiento una topología distinta impide una auditoría fiable.
- **Dependencias:** `PROD-026`, `PROD-116` y autorización expresa de proveedor en `PROD-117`.
- **Tamaño:** S
- **Estrategia de pruebas:** validación de las dos composiciones, inspección JSON de variables/redes por servicio, prueba estática de defaults y smoke de conectividad controlada sin analizar fuente real hasta superar el preflight.
- **Evidencia de validación al completarse:** 2026-09-06: se añadió un cuarto overlay que no participa en la candidatura ordinaria, requiere activación explícita y crea una red externa dedicada usada únicamente por backend. La composición sin overlay mantiene egress `false` y todas sus redes internas; la composición autorizada mostró egress `true`, backend unido a `inspectra_public_advisory_egress` y ningún runner/frontend/proxy en esa red. Las dos variantes se inspeccionaron desde su JSON renderizado, y pasaron 18 pruebas estáticas y la comprobación de diff. Documentación de inteligencia y aceptación exige preflight previo, autorización por fuente, retirada/recreación posterior y no confunde disponibilidad de red con permiso para consultar. No hubo tráfico externo en esta implementación.

### PROD-126 — Eliminar el desborde horizontal del recorrido de proyecto a 320 px

- **Prioridad:** P0
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** una persona que revisa riesgos desde móvil o una ventana estrecha necesita leer estados y accionar filtros sin desplazar toda la aplicación lateralmente.
- **Flujo completo afectado:** abrir dashboard → workspace de proyecto → inteligencia/inventario/comparación → hallazgos e informes → navegación móvil.
- **Áreas o archivos implicados:** `frontend/src/styles.css`, componentes del workspace, pruebas frontend y guía/evidencia visual.
- **Criterios de aceptación verificables:** a 320, 768 y 1440 px `documentElement.scrollWidth <= innerWidth` en el recorrido real; el panel de inteligencia y las tarjetas se adaptan, mientras tablas y grupos deliberadamente anchos desplazan solo dentro de su región con etiqueta accesible. El foco de teclado sigue visible y no se usa `overflow-x:hidden` global para ocultar contenido.
- **Riesgos de seguridad, privacidad y operación:** ocultar el problema globalmente puede volver inaccesible evidencia o controles; dejarlo rompe responsive y aumenta errores de triage.
- **Dependencias:** `PROD-113`, `PROD-123` y datos de aceptación de `PROD-117`.
- **Tamaño:** S
- **Estrategia de pruebas:** localizar el elemento por sus métricas de caja, prueba CSS/componente dirigida y navegador con el mismo dataset a 320/768/1440 px; revisar consola y foco.
- **Evidencia de validación al completarse:** 2026-09-06: la inspección de cajas del recorrido real identificó como causa el grid de título/ID de `.project-finding-toggle`, cuyo identificador largo medía 302 px dentro de una tarjeta de 237 px. El cambio permite encoger y envolver solo ese contenido; no oculta el overflow global. Pasaron 14/14 pruebas CSS en una imagen limpia sin red, TypeScript/build Vite y el presupuesto inicial de 317,4/322 KiB. Tras reconstruir la imagen, el workspace completo obtuvo `scrollWidth=clientWidth` a 320 (305 px útiles), 768 (753) y 1440 (1425); los ocho encabezados muestreados no desbordaron, las tablas conservaron scroll local, el foco mantuvo un contorno sólido de 3 px y la consola quedó sin errores ni avisos.

### PROD-127 — Compatibilidad estricta con respuestas resumidas de OSV

- **Prioridad:** P0
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un equipo necesita que la
  integración oficial produzca los mismos resultados completos que los
  fixtures y que una variación válida de la respuesta no se transforme en un
  falso limpio.
- **Flujo completo afectado:** componentes npm exactos → `querybatch` OSV →
  referencias resumidas → detalle oficial fijo → normalización/persistencia →
  resultados, comparación e informe.
- **Áreas o archivos implicados:** `backend/app/public_advisory_egress.py`,
  pruebas del transporte, contrato y guía de inteligencia pública.
- **Criterios de aceptación verificables:** se acepta `vulns` ausente o lista
  válida; solo IDs con formato acotado se hidratan desde la ruta HTTPS OSV
  compilada en código, sin redirecciones ni destino aportado por la respuesta.
  Hay tope, deduplicación, fallo seguro y reconciliación entre lote, detalles y
  snapshot normalizado.
- **Riesgos de seguridad, privacidad y operación:** seguir URLs externas
  permitiría SSRF; hidratar sin límite agotaría recursos; ignorar el formato
  resumido ocultaría vulnerabilidades reales.
- **Dependencias:** `PROD-026`, `PROD-090` y validación real de `PROD-117`.
- **Tamaño:** S
- **Estrategia de pruebas:** transportes simulados para vacío/resumen/ID
  inválido/duplicado/exceso y una aceptación autorizada que compare los tres
  conjuntos de IDs sin conservar el cuerpo externo completo.
- **Evidencia de validación al completarse:** 2026-09-06: se validan y
  deduplican hasta 250 IDs, y cada detalle procede exclusivamente de
  `api.osv.dev/v1/vulns/{id}` bajo los límites existentes. Las regresiones
  deterministas pasaron en 1.523/1.523 pruebas backend. La fuente oficial
  produjo 28 IDs de lote, 28 detalles y 28 IDs normalizados, sin ausencias ni
  extras; la captura solo mostró `api.osv.dev`.

### PROD-128 — Presentación móvil e indicadores semánticos de inteligencia

- **Prioridad:** P0
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** quien hace triage desde móvil o
  comparte un informe necesita leer toda la evidencia y comprender qué cuenta
  cada indicador sin confundir advisories únicos con ocurrencias por componente.
- **Flujo completo afectado:** workspace → resumen/filtros → detalle →
  comparación → informes, en escritorio, tablet y móvil.
- **Áreas o archivos implicados:** `frontend/src/styles.css`, panel de
  inteligencia, comparación, informes backend, pruebas y guía visual.
- **Criterios de aceptación verificables:** la página no desborda a
  320/768/1440; informes y texto técnico encogen/parten sin ocultar evidencia y
  las tablas conservan scroll local. Los contadores denominan “hallazgos
  verificados” a ocurrencias componente/advisory. Carga, vacío, error, filtro y
  detalle permanecen navegables y con foco visible.
- **Riesgos de seguridad, privacidad y operación:** contenido inaccesible puede
  ocultar la corrección; una etiqueta estadística imprecisa induce decisiones
  equivocadas y reduce confianza.
- **Dependencias:** `PROD-113`, `PROD-126` y datos de `PROD-117`.
- **Tamaño:** S
- **Estrategia de pruebas:** regresión CSS/componente, build/presupuesto y
  revisión visual reproducible sobre el dataset real ya redactado a tres
  viewports; sin retener capturas con datos sensibles.
- **Evidencia de validación al completarse:** 2026-09-06: las 307 pruebas
  frontend y el build 317,4/322 KiB pasaron. La revisión en navegador integrado
  obtuvo ancho documento/contenido 305/305, 753/753 y 1425/1425; el informe
  midió 239 px dentro de 305 px a móvil, las tablas conservaron overflow local
  y el foco siguió visible. No se afirmó estado de consola porque esa superficie
  no estuvo disponible en esta pasada.

### PROD-129 — Preparar un corte local coherente y revisable

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** un evaluador necesita asociar la
  candidatura aceptada a una versión y conjunto de cambios inequívocos antes de
  instalarla o compararla, sin que eso implique declarar una versión estable.
- **Flujo completo afectado:** revisar árbol → decidir versión → alinear
  documentación/metadatos → construir y validar candidato local → registrar
  digest/commit para la futura CI.
- **Áreas o archivos implicados:** Git de Inspectra, versión backend/frontend,
  README, arquitectura, seguridad, despliegue y notas del corte.
- **Criterios de aceptación verificables:** se clasifica cada cambio actual y no
  quedan residuos/secretos; una única versión coherente aparece en artefactos y
  documentación; el commit local candidato reproduce las puertas de aceptación
  y queda identificado sin tag, push ni publicación.
- **Riesgos de seguridad, privacidad y operación:** mezclar trabajo no revisado
  o versiones divergentes impide reproducir el GO y puede publicar datos o
  promesas incorrectas.
- **Dependencias:** `PROD-117`, `PROD-127` y `PROD-128` completadas. La
  consolidación local y `0.3.0-beta.1` fueron autorizadas el 2026-09-10;
  `PROD-130`, CI remoto y toda publicación permanecen bloqueados/fuera de alcance.
- **Tamaño:** L
- **Estrategia de pruebas:** inventario de diff/archivos, escaneo de secretos,
  comparación de metadatos, suites/build/Compose/auditorías y reconstrucción
  por digest desde el commit local propuesto.
- **Evidencia de validación al completarse:** 2026-09-10: rama local creada
  desde `8e72f1e…` sin alterar el árbol inicial (`db9de357…`). El inventario
  clasifica 357 rutas, 351 incluidas y seis excluidas como entorno/runtime, sin
  submódulos, modos ni ambigüedades. La serie local separa núcleo, frontend,
  CLI, documentación/release y fingerprints sintéticos; el tip que contiene
  esta evidencia identifica la candidatura sin tag ni referencia remota.
  Gitleaks dejó limpio el historial y el canario funcionó; las 53 señales del
  árbol candidato se verificaron como sintéticas en 25 archivos controlados.
  La matriz del tip pasó 1.613 backend, 481 tools, 65 CLI y 420 frontend,
  `compileall`, TypeScript/build, presupuesto 302,7/322 KiB, seis Compose,
  `pip check`, guardas y diff-check. Las cinco auditorías Python quedaron
  limpias. `CVE-2026-84373 / GHSA-82fw-gwwq-j7x9` se corrigió actualizando
  Vitest/`@vitest/mocker` a 4.1.11; instalación limpia Node 22 y auditoría npm
  quedaron a cero. Dos builds dieron los mismos SHA-256: wheel `fd3012ef…`,
  sdist `b35c7287…`, SBOM `666a5b90…` y checksums `aef8d96d…`; el wheel se
  instaló offline fuera del repo. El smoke TLS sintético pasó en 1.296,506 ms
  con auth, análisis, privacidad, egress apagado, informes y cleanup; ningún
  proveedor fue contactado. La degradación mantuvo health 200/readiness 503 y
  recuperó 200. Quedaron cero recursos/temporales. El `ENOSPC` inicial se
  atribuyó al `/tmp` de 512 MiB y la suite pasó con 2 GiB; dos smokes que no
  iniciaron flujo por cliente sin `httpx` y CA `0600` se diagnosticaron antes de
  repetir la aceptación válida completa. No hubo push, PR, tag, release,
  publicación ni despliegue.

### PROD-130 — Validar CI remoto y cerrar la puerta de release

- **Prioridad:** P1
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** empresas y mantenedores necesitan
  evidencia independiente de que el commit candidato supera las mismas puertas
  en CI y de que su cadena de acciones no depende de referencias mutables.
- **Flujo completo afectado:** commit candidato → CI remoto con permisos mínimos
  → pruebas/build/auditorías → evidencia enlazada → decisión de promover o
  rechazar.
- **Áreas o archivos implicados:** `.github/workflows/ci.yml`, `SEC-012`,
  política de permisos/secretos, checklist y documentación de release.
- **Criterios de aceptación verificables:** con autorización explícita,
  `SEC-012` ancla cada acción a un SHA verificado; CI remoto ejecuta todas las
  puertas sobre el commit exacto, sin credenciales de proveedor innecesarias,
  y un fallo bloquea promoción. La evidencia identifica ejecución, commit y
  resultado sin exponer secretos.
- **Riesgos de seguridad, privacidad y operación:** acciones mutables comprometen
  la cadena de suministro; CI parcial o sobre otro commit da una confianza falsa.
- **Dependencias:** `PROD-129` y `SEC-012`; requiere autorización expresa para
  modificar `SEC-012` y para todo push/PR. Ambas autorizaciones fueron
  concedidas el 2026-09-10 para este ciclo remoto limitado.
- **Tamaño:** M
- **Estrategia de pruebas:** revisión de permisos y SHAs, validadores estáticos,
  ejecución remota sobre el commit candidato y comparación con la matriz local;
  ninguna consulta real a proveedores forma parte de la suite ordinaria.
- **Evidencia de validación al completarse:** 2026-09-10: con autorización
  explícita se reescribió exclusivamente la serie local inédita, sin bypass ni
  force-push. La rama remota y el PR borrador #1 se publicaron inicialmente
  sobre `3d912d2e8196c5185b8e378fd3e04ca692b99a01`. El primer CI remoto dejó verdes
  Compose, Gitleaks (historial y canario) y Python; frontend instaló sin
  vulnerabilidades y ejecutó las 420 pruebas, pero cuatro esperas asíncronas de
  `App.test.tsx` fallaron bajo carga antes de permitir build/audit. El caso se
  reprodujo con Node 22/Vitest 4.1.11 y cuatro CPU (419/420): el DOM ya mostraba
  la sesión autenticada, pero una transición secundaria superó el segundo
  implícito. Cuatro aserciones de transición usan ahora un presupuesto local de
  5 s, sin relajar el resto de la suite; dos repeticiones completas pasaron
  420/420. El segundo CI confirmó que la aserción ya no expiraba, pero el límite
  total predeterminado de Vitest (5 s) competía con esa espera y detuvo el test
  de enlace restaurado. Los cuatro tests afectados tienen ahora 10 s totales y
  mantienen 5 s para la transición; la repetición completa volvió a pasar
  420/420, build 302,7/322 KiB y `npm audit` cero vulnerabilidades. La ejecución
  real [34520803043](https://github.com/dreykdrk7/inspectra/actions/runs/34520803043)
  terminó verde sobre `ef046a1fe2d8468aed6bfa83315ab7ae687bf922`:
  Python 2.094/2.094 + CLI 65/65 y cinco auditorías sin vulnerabilidades
  conocidas; frontend 59/59 archivos y 420/420, build y auditoría; Compose base
  y privado; Gitleaks 363 commits sin fugas y canario activo. Los cuatro jobs y
  todos sus pasos terminaron, se publicaron cero artefactos y los logs no
  incluyeron nombres de las fuentes privadas de aceptación ni rutas locales.
  Tras los commits correctivos ordinarios, la rama remota coincidía con el tip
  validado y el PR #1 permanecía abierto y draft. No
  hubo merge, tag, release, publicación ni despliegue. `SEC-012` quedó completada
  con esta evidencia; la advertencia no bloqueante de runtime Node de las
  acciones se conserva como `SEC-021` en el backlog general. Un tip documental
  posterior reveló que el benchmark de 100.000 análisis medía conjuntamente el
  rebuild y el sobrecoste de `tracemalloc`: dos pasadas remotas marcaron
  63,83/63,94 s frente al límite de 60 s, mientras la repetición aislada local
  dio 52,28 s. La regresión separa ahora la guarda de memoria `<64 MiB` de una
  segunda medición de rebuild sin instrumentación que conserva `<60 s`; la
  prueba completa dirigida pasó offline/read-only sin relajar ninguno de los
  dos límites. El siguiente CI ejecutó 419/420 pruebas frontend y mostró el
  flujo restaurado desde URL, pero su informe terminó de cargar después de los
  5 s específicos. Solo ese caso usa ahora 10 s de espera/15 s totales; los
  demás presupuestos y el timeout global siguen intactos. En Node 22/Vitest
  4.1.11 y cuatro CPU pasaron 59/59 archivos, 420/420 pruebas, build y bundle
  302,7/322 KiB. La ejecución remota del tip funcional
  [34524924443](https://github.com/dreykdrk7/inspectra/actions/runs/34524924443)
  validó conjuntamente el tip `7f7614cc2c2024aaa90506841bf05b576c4bdb38`:
  Python 2.094/2.094 y CLI 65/65 con cinco auditorías sin vulnerabilidades
  conocidas; frontend 59/59 y 420/420, build y auditoría npm; Compose; e
  historial Gitleaks de 366 commits más canario. Los cuatro jobs terminaron
  verdes, sin pasos esenciales omitidos ni artefactos publicados.
  La consolidación funcional posterior se publicó como fast-forward normal,
  sin bypass ni force-push, y la ejecución remota
  [34599394973](https://github.com/dreykdrk7/inspectra/actions/runs/34599394973)
  validó `b768fc3efc85ce7174029c8719d1f228f2f0cbca`: Python 2.151/2.151 y CLI
  66/66, cinco auditorías Python sin vulnerabilidades conocidas; frontend
  62/62 archivos y 430/430 pruebas, build 305,7/322 KiB y auditoría npm sin
  vulnerabilidades; Compose base/privado; e historial Gitleaks más canario.
  Los cuatro jobs y todos sus pasos terminaron verdes en 5 min 59 s de
  ejecución total, con cero artefactos publicados. El PR #1 permaneció abierto
  y draft; no hubo merge, tag, release, publicación de paquetes/imágenes ni
  despliegue.

## Ciclo 6 — Expansión funcional para desarrolladores y empresas

Este ciclo prioriza capacidades utilizables. En su apertura, `SEC-012` y
`PROD-130` permanecían bloqueadas y `PROD-129` acababa de completarse tras su
autorización local. La autorización extraordinaria posterior permitió sanear y
publicar la serie inédita sin bypass ni force-push; `SEC-012` y `PROD-130`
quedaron completadas el 2026-09-10 con PR borrador y CI remota verde. Las tareas
que materializan trabajo ya previsto indican
la ficha anterior que deben reconciliar al completarse; no crean un segundo
estado funcional para la misma capacidad.

| ID / prioridad / estado | Necesidad, valor y flujo completo | Áreas implicadas | Criterios de aceptación y estrategia de pruebas | Riesgos de seguridad, privacidad y operación | Dependencias | Tamaño | Evidencia obligatoria |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **PROD-131 — P1 — completada**<br>CLI: snapshot Git seguro, preflight y dry-run | Un desarrollador necesita convertir un commit autorizado en una fuente reproducible sin ZIP manual ni lectura del worktree. Flujo: `inspectra scan <ruta>` → resolver repo/commit → objetos Git → exclusiones → Gitleaks+canario → metadatos/dry-run → confirmación. | Nuevo paquete CLI, Git, empaquetado, documentación y fixtures. | Solo blobs rastreados del commit; excluye `.git`, `.env*`, credenciales y artefactos; rechaza symlink/submódulo/ruta hostil/límites. Muestra commit, árbol, archivos, bytes y SHA-256. `--dry-run`, JSON, ayuda y códigos fiables. Pruebas con repos sintéticos y Gitleaks simulado/real cuando esté disponible; nunca ejecuta el proyecto. | Leer el checkout filtraría cambios; un escáner opcional permitiría secretos; TAR no determinista rompería reproducibilidad. | PROD-043, PROD-073 y flujo archive-backed. | L | 2026-09-07: paquete instalable Python 3.12 y comando `inspectra scan`; deriva blobs con `ls-tree`/`cat-file`, normaliza TAR, excluye clases sensibles/generadas, bloquea rutas/objetos/límites inseguros y ejecuta Gitleaks obligatorio con canario. Repositorios sintéticos probaron que cambios locales/no rastreados no entran y dos pasadas producen bytes/digest idénticos. La suite CLI pasó 8/8 bajo Python 3.12+Git; instalación/help y el canario con la imagen Gitleaks fijada pasaron. Dos primeros entornos no ejecutaron todos los casos por ausencia de Git/privilegios apt y se repitieron correctamente; no se atribuyeron al sandbox. |
| **PROD-132 — P1 — completada**<br>CLI: subida, seguimiento y resultado end-to-end | El usuario necesita que el mismo comando suba el snapshot al servidor, cree el proyecto, espere con límite y entregue resumen/enlace. | Cliente HTTP CLI, API existente, estados y docs. | HTTPS o HTTP loopback; sin rutas del host en payload/log; subida multipart genérica, creación, polling, timeout y resumen local/PVI honesto. Salida humana/JSON y códigos para completo/fallido/timeout/API. E2E con servidor sintético y smoke ASGI/Compose sin Internet. | URL insegura, credencial en argumentos, carga parcial o timeout presentado como éxito. | PROD-131. | M | 2026-09-07: el cliente stdlib valida HTTPS/HTTP-loopback, limita respuestas/tiempos, transmite `snapshot.tar` genérico y no refleja errores internos. Crea proyecto, espera estados cerrados, conserva enlace al timeout/fallo y obtiene resumen/cobertura/PVI sin activar egress. El E2E HTTP sintético forma y abre el TAR recibido y prueba ausencia de worktree/ruta. Un segundo E2E levantó backend+runner reales en red interna, usó Gitleaks 8.30.1 real, completó análisis con PVI `disabled` y eliminó fuente/proyecto; quedaron 0 contenedores, redes y temporales. Suite CLI 8/8 e instalación/help pasaron. |
| **PROD-133 — P1 — completada**<br>Tokens de automatización | Un equipo necesita credenciales no interactivas mínimas, caducables y revocables. Flujo: admin crea → muestra una vez → pipeline usa → API valida scope/organización → revoca/caduca → auditoría. | Auth SQLite, modelos/rutas, auditoría, UI administrativa y CLI; implementa PROD-067. | Hash en reposo, secreto una sola vez, scopes de proyecto/acción, expiración obligatoria, rotación/revocación inmediata, rate limits y deny-by-default. Matriz de dos organizaciones, replay/revocación/reinicio y logs redactados. | Robo de token, escalada horizontal o token perpetuo. | PROD-012 y PROD-013. | L | 2026-09-07: SQLite conserva solo hash separado por dominio y metadatos mínimos; token ligado a organización/proyecto, TTL 5 min–90 días, 600 peticiones/hora, revocación inmediata y política cerrada de rutas/scopes. API administrativa exige sesión+CSRF, muestra el secreto una sola vez y audita creación/revocación. Panel accesible permite crear/copiar/revocar. Backend dirigido: 3/3; frontend: 1/1; `tsc`, Vite y presupuesto 318.1/322 KiB pasan en copias efímeras. El primer intento frontend no ejecutó pruebas por permisos de `.vite-temp`; las repeticiones aisladas sí. Documentado en `docs/automation-credentials.md`. |
| **PROD-134 — P1 — completada**<br>Admisión CI idempotente ligada a commit | El pipeline necesita subir una sola instantánea por proyecto/commit y reusar de forma segura el resultado. Flujo: token → proyecto explícito → snapshot+commit+rama informativa → clave idempotente → análisis → estado. | Contrato API/almacenamiento/CLI; materializa PROD-068 y extiende PROD-073. | Commit SHA completo, digest de fuente y proyecto forman la identidad; rama se normaliza y no autoriza nada; replay concurrente no duplica; discrepancia falla 409. Pruebas de carreras, dos organizaciones y payload hostil. | Confundir rama con identidad, duplicar análisis o cruzar proyecto. | PROD-132 y PROD-133. | L | 2026-09-07: nuevo `POST /projects/{id}/ci/snapshots` multipart verifica digest, deriva identidad de organización+proyecto+commit+contenido y conserva commit/rama en snapshot privado. Reintentos reutilizan job incluso al atribuir el snapshot inicial, borran uploads duplicados y un commit con bytes distintos falla 409; ruta bearer ligada al proyecto. CLI añade `--project-id`/`--branch` y token solo desde entorno. Backend snapshot/token 7/7 y CLI 9/9 pasaron antes del siguiente vertical; regresión dedicada cubre replay, conflicto y cero huérfanos. |
| **PROD-135 — P1 — completada**<br>Políticas y baseline para pipelines | El equipo necesita una puerta determinista que bloquee por crítico/alto nuevo, KEV, pérdida de cobertura o análisis incompleto sin castigar deuda inicial. | Motor de políticas, comparación, CLI/API y contratos; materializa PROD-070/112. | Política versionada con criterios cerrados, baseline explícita, resultado pass/fail/inconclusive y códigos estables; cobertura/proveedor parcial nunca es “sin vulnerabilidades”. Fixtures cubren cada regla, datos obsoletos y baseline incompatible. | Falso verde por cobertura menor o política ambigua; bloqueo sorpresivo por deuda histórica. | PROD-104 y PROD-134. | L | 2026-09-07: motor puro `observe|standard|strict` consume hallazgos, cobertura, PVI, KEV y comparación contra baseline guardada. Fallo confirmado prevalece; sin fallo, cobertura parcial/truncada, PVI no actual o baseline no comparable produce `inconclusive`. Salida versionada y códigos 8/9; baseline ausente no convierte toda la deuda en nueva. Suite CLI completa 12/12 con fixtures deterministas. |
| **PROD-136 — P1 — completada**<br>Salidas CI interoperables | El pipeline necesita SARIF, JSON y Markdown acotados, más ejemplos copiables sin activar CI remoto de Inspectra. | Reporting/CLI, docs y fixtures; materializa PROD-069. | SARIF 2.1 válido con rutas seguras, JSON versionado, Markdown accionable y artefactos sin secretos; ejemplos GitHub/generic usan token secreto y commit exacto. Validación por esquema/fixtures, no publicación. | Informes pueden filtrar rutas o representar indicadores como confirmaciones. | PROD-135. | M | 2026-09-07: CLI genera JSON contractual, Markdown acotado y SARIF 2.1 con niveles normalizados y solo ubicaciones relativas seguras; límites de 200/1.000 resultados y escritura exclusiva. `docs/ci-integration.md` incluye GitHub Actions y pipeline genérico sin activar CI remoto. Suite CLI 13/13. |
| **PROD-137 — P1 — completada**<br>Frontera inmutable de importación SBOM | Un equipo necesita aportar inventario ya generado sin que Inspectra ejecute builds. Flujo: subir CycloneDX/SPDX → detectar formato/versión → límites/redacción → snapshot → proyecto/análisis. | Upload, modelos, almacenamiento, parser boundary, UI/CLI y docs. | Solo JSON de versiones admitidas, límite de bytes/componentes/relaciones, sin externalRefs sensibles, rutas o hashes privados; conserva digest/formato y estados inválido/parcial. Fixtures hostiles y aislamiento owner. | SBOM puede contener URLs internas, paths, autores o millones de nodos. | PROD-003 y PROD-024. | L | 2026-09-07: endpoint multipart con autorización explícita lee bajo límite, normaliza en memoria y persiste solo proyección mínima; documento/nombre de archivo, hashes, URLs, rutas y metadatos libres se descartan. Máximo 2.000 componentes y 10.000 relaciones con truncado declarado; perfil `sbom_import` evita comparaciones incompatibles. Backend dirigido 4/4. |
| **PROD-138 — P1 — completada**<br>Vertical CycloneDX | Quien ya produce CycloneDX necesita inventario, correlación y resultados comparables. | Parser CycloneDX, purl, PVI, comparación, informes y UI. | Admite CycloneDX JSON definido; exactos públicos generan purl/elegibilidad, privados/rangos/ambiguos quedan locales; OSV usa payload mínimo. E2E fixture con hallazgo/no correlacionable, comparación e informe. | Confiar ciegamente en purl o refs privadas filtra metadatos/falsos positivos. | PROD-027, PROD-079 y PROD-137. | L | 2026-09-07: CycloneDX JSON 1.4–1.6 conserva únicamente purl exacta npm/PyPI; qualifiers, subpaths, versiones ausentes y ecosistemas no soportados quedan rechazados. La relación raíz determina directa/transitiva sin conservar refs. UI ofrece importación, estados de error y atestación separada de identidad pública; inventario/PVI/reporting reutilizan los contratos existentes. Repetición offline del snapshot y comparación compatible pasaron con fixtures hostiles y E2E API. |
| **PROD-139 — P1 — completada**<br>Vertical SPDX | Equipos con SPDX necesitan el mismo recorrido sin perder trazabilidad del formato. | Parser SPDX JSON, paquetes/relaciones, PVI, comparación, informes y UI. | Versiones admitidas y package relationships acotadas; identidad exacta demostrable, purl solo válida, no downloadLocation privada. E2E equivalente a CycloneDX y estados parciales. | Identidades `NOASSERTION`, relaciones cíclicas o URLs privadas no deben salir. | PROD-027, PROD-079 y PROD-137. | L | 2026-09-07: SPDX JSON 2.2/2.3 extrae solo externalRefs purl exactas; ignora `downloadLocation`, nombres, checksums y demás campos. `DESCRIBES`/`DEPENDS_ON` determina alcance directo de forma acotada y el resto queda transitivo. Sin atestación pública, todas las identidades permanecen locales/no correlacionables. E2E API verifica importación, inventario, repetición, comparación y descarte de campos privados; fixtures cubren versión no soportada. |
| **PROD-140 — P2 — completada**<br>Go | Desarrolladores Go necesitan analizar módulos exactos y vulnerabilidades públicas sin ejecutar Go ni exponer módulos privados. Flujo: archive → `go.mod`/`go.sum` same-root → inventario/cobertura → atestación exacta → OSV → hallazgo/comparación/remediación/informe. | Runner pasivo, inventario, PURL, policy/config/Compose, PVI/correlación SemVer, modelos, UI, contratos y tests. | Formato lineal acotado; versiones exactas incluidas pseudo-versiones; `replace` queda no correlacionable y su destino se descarta; hashes nunca persisten. `go.sum` no prueba publicidad: solo módulo exacto atestado por operador sale como `Go+name+version`; sin atestación queda local. UI explica cobertura, fixed version y procedencia; reporting y consumidores aceptan Go. | Un módulo privado/homónimo podría salir; `replace` o comparación SemVer incorrectos causan fuga, falso positivo o falso negativo. La allowlist global aún requiere evolución tenant-scoped (`PROD-220`). | PROD-025, PROD-079 y PROD-137. | L | **2026-09-09:** Python 3.12 en Docker `--network none`: 284/284 pruebas de runner/inventario/egress/PVI/versiones y 2/2 preflight API; reporting/remediación/tendencias 17/17. Frontend Go/inventario/PVI 35/35, TypeScript/build 291,0/322 KiB; `compileall`, Compose base/privado/egress y diff-check. Regresiones prueban destino `replace`, hashes, URL/credencial, identidad no atestada, payload mínimo, afectada/fixed y pseudo-versión. Se corrigió PURL Go sin versión y copy OSV incompleto. **Estado de fuente: adaptador validado únicamente con fixtures; no integración real con OSV para Go.** No se ejecutó Go ni hubo red en pruebas. |
| **PROD-141 — P2 — completada**<br>Rust/Cargo | Equipos Rust necesitan resolver `Cargo.lock` con procedencia segura. Flujo: archive → `Cargo.toml`/`Cargo.lock` same-root → inventario/cobertura → prueba crates.io → OSV → resultado/comparación/remediación/informe. | Runner pasivo, inventario/PURL, egress/PVI/SemVer, modelos, UI, reporting, contratos y pruebas. | Solo Cargo.lock v3/v4; crates exactos con uno de los dos literales oficiales fijos de crates.io. Git/path/workspace/alias/registry alternativo/versión ambigua quedan locales; `source`, checksum, aristas y locator se descartan. Payload OSV solo `crates.io+name+version`; transitivas acotadas con relación no reportada. | `source` puede contener URL privada o credencial; mapear un ecosistema GHSA por defecto puede crear falsa corroboración. No se afirma origen público desde Cargo.toml. | PROD-025, PROD-079 y PROD-137 completadas. | L | **2026-09-09:** parser e inventario same-root, PURL `pkg:cargo`, OSV `crates.io`, correlación SemVer, estados UI y consumidores de comparación/remediación/reporting implementados. Un hallazgo de revisión corrigió el fallback GHSA que trataba Go/Cargo como `pip`; ahora ecosistemas sin mapeo explícito quedan no corroborados. Docker Python 3.12 `--network none`: 294/294 runner/inventario/egress/PVI/versiones y 53/53 en revisión PVI/GHSA/reporting/remediación/tendencias/cartera; frontend 41/41 con axe existente, TypeScript/build y presupuesto 291,0/322 KiB; `compileall` y diff-check. Fixtures cubren v3/v4, v2 rechazado, crates.io sparse/Git, alias/workspace, registry privado con credencial, checksum, ambigüedad, payload mínimo, affected/fixed/CVSS y filtro Cargo. **Estado de fuente: adaptador validado únicamente con fixtures; no integración real OSV Cargo.** No se ejecutó Cargo ni hubo Internet. |
| **PROD-142 — P2 — completada**<br>Java/JVM | Equipos Java necesitan inventariar resoluciones Gradle exactas y llegar a hallazgos OSV accionables sin ejecutar builds. Flujo: archive → marcador `build.gradle[.kts]` + `gradle.lockfile` same-root → inventario/cobertura → atestación Maven exacta → OSV → hallazgo/comparación/remediación/informe. | Runner pasivo, inventario/PURL, config/Compose/egress, PVI/matching, modelos, UI, docs y pruebas. | Gradle DSL es solo marcador; lock acepta únicamente coordenadas lowercase `group:artifact:version` y SemVer estable. No retiene configuraciones ni infiere alcance/origen; atestación exacta obligatoria y payload `Maven+name+version`. Nunca ejecuta Gradle/Maven. | Repositorios privados, DSL dinámico y esquemas Maven no SemVer pueden causar fuga o correlación errónea si se infieren; por eso fallan cerrados. | PROD-025, PROD-079 y PROD-137 completadas. | L | **2026-09-09:** contrato `2026-09-09.3`; Docker Python 3.12 `--network none`: 346/346 pruebas amplias de runner/inventario/egress/PVI/matching/GHSA/reporting/remediación/tendencias/cartera. Frontend 45/45, TypeScript/build y bundle 291,0/322 KiB; compileall, Compose base/overlay y diff-check. Fixtures cubren `.gradle`/`.kts`, coordenadas válidas/ambiguas, configuración descartada, atestación, payload mínimo y affected/fixed. Se corrigió una expectativa UI para conservar `scope unknown`. **Estado de fuente: adaptador validado únicamente con fixtures; no integración real OSV Maven.** |
| **PROD-143 — P2 — completada**<br>PHP/Composer | Equipos PHP necesitan inventario exacto y vulnerabilidades accionables sin ejecutar Composer. Flujo: archive → `composer.json`/lock same-root → resolución local/cobertura → atestación exacta → OSV → hallazgo/comparación/remediación/informe. | Runner pasivo, inventario/PURL, config/Compose/egress, PVI/SemVer, modelos, UI, docs y tests. | Contrato estructural `composer-lock-json-v1`; solo lowercase `vendor/package` y SemVer exacta. `repositories` cierra el root; `source`, `dist`, referencias, hashes, aliases y metadatos se descartan. Lock no prueba Packagist: atestación exacta obligatoria y payload mínimo `Packagist+name+version`. | URL/credencial en metadatos o paquete privado homónimo; aliases/dev/rangos mal interpretados; relación transitive no reportada. Atestación global migra a PROD-220. | PROD-025, PROD-079 y PROD-137 completadas. | L | **2026-09-09:** vertical completo con estado local/no atestado y finding/fixed UI. Docker Python 3.12 `--network none`: 332/332 runner/inventario/egress/PVI/version/GHSA/reporting/remediación/tendencias/cartera y 2/2 rutas API; frontend 43/43, build y 291,0/322 KiB; `compileall`, Compose base/overlay y diff-check. Fixtures prueban repositorio personalizado, dist/source con credencial, hashes/references/aliases, dev/transitive, JSON inválido, atestación exacta/rechazos, payload mínimo, affected/fixed y SemVer. Contrato inventario subido a `2026-09-09.2`. **Estado de fuente: adaptador validado únicamente con fixtures; no integración real OSV Composer.** No se ejecutó Composer ni hubo Internet. |
| **PROD-144 — P2 — completada**<br>.NET/NuGet | Equipos .NET necesitan importar activos resueltos sin ejecutar restore. | Parser `packages.lock.json`, inventario/PVI/UI/report y configuración de egress. | Solo v1 same-root, marcador `*.csproj` inequívoco y versiones exactas del subconjunto soportado; claves duplicadas, targets/versiones ambiguos y `Project` fallan cerrados. Atestación pública exacta y fixtures multi-target/ambigüedad; nunca ejecutar .NET. | Resolver rangos, mezclar targets o inferir NuGet.org produce falsos hallazgos o fuga de identidad privada. | PROD-025, PROD-079 y PROD-137. | L | **2026-09-09:** contrato `2026-09-09.4`; descarta TFM, hashes, rutas, rangos, repositorios y credenciales, reconcilia scopes y genera payload mínimo `NuGet+name+version` solo tras allowlist exacta. Backend 1.346/1.346, runner 451/451 y frontend 381/381 sin red; build 291,0/322 KiB, `compileall`, Compose y diff-check. La primera pasada con tmpfs 256 MiB agotó `/tmp` y se repitió íntegra con 2 GiB. Adaptador validado solo con fixtures; no integración OSV real NuGet. |
| **PROD-145 — P1 — completada**<br>Cartera global | Seguridad necesita ordenar proyectos autorizados por riesgo, frescura y cobertura. Flujo: abrir cartera owner-scoped → buscar/filtrar → entender señales y límites → paginar una instantánea coherente → abrir el proyecto por enlace profundo. | `project_portfolio.py`, modelos/ruta, lifecycle bulk, cliente/tipos, `ProjectPortfolioPanel`, App, estilos, contratos de proyectos/hallazgos/PVI y revisión visual; materializa la parte global de PROD-108. | Organización actual; prioridad cerrada sin score; severidades y KEV separados; nuevos/persistentes/resueltos solo con evidencia comparable; cobertura y frescura con denominadores; baseline, estado operativo, acciones y responsabilidad derivada; búsqueda prefijo/exacta, filtros cerrados en body, orden estable y cursor HMAC owner/filtros/snapshot. Vacío/no-match/error/paginación que preserva filas, axe, 320/desktop y prueba sintética 2.000. | La proyección cruzada puede revelar existencia/riesgo entre tenants o declarar mejora con cobertura perdida. El límite 5.000 y `GET /projects` sin paginar quedan visibles en PROD-214; canales commit históricos no se adivinan y pasan a PROD-213. | PROD-065 y PROD-104 completadas; PROD-108 sigue pendiente para tendencias más amplias. | L | **2026-09-09:** contrato `2026-09-09.1`, endpoint POST owner-scoped con CSRF de reader, 14 señales visibles y `409` ante cambio concurrente. Expiración PVI se recalcula; decisiones se leen una vez por organización; corrupción/límites fallan cerrados. Backend dirigido 16/16; frontend 56/56 con axe; TypeScript, Vite y bundle 287,3/322 KiB. Proyección 2.000: 0,753 s y 84.328 KiB RSS (no SLA). Revisión local sintética desktop/móvil: documento 375/375, panel 343 px, filtros y deep link correctos; pestaña/servicios cerrados y fixture enviado a papelera. Sin red externa. |
| **PROD-146 — P1 — completada**<br>Centro de remediación | Desarrolladores necesitan agrupar hallazgos por acción común y ver directa/transitiva, instalada, corregida, conflicto y responsable. | Motor local, lifecycle, API/UI/report. | Planes verificables sin aplicar parches; comandos son orientación marcada; agrupación estable, asignación/excepción/revisión y evidencia fuente. Fixtures con conflictos/transitivas. | Comando sugerido inseguro o agrupación incorrecta puede romper proyecto. | PROD-046, PROD-048, PROD-066 y PROD-145. | L | **2026-09-09:** proyección owner-scoped sobre evidencia actual, agrupación local y pública, revisión estable de grupo y lote append-only de hasta 25 decisiones. Versiones/rangos/correcciones, alcance, conflictos, KEV y cobertura se mantienen explícitos; `resolved` exige un análisis comparable posterior y mientras tanto conserva la evidencia como `awaiting_reanalysis`/`still_detected`. API reader-safe para búsqueda/informe y mutación con CSRF/roles; JSON/CSV consentidos, acotados y sin rutas, contenido, comentarios ni actor. Pasaron 24 pruebas backend, 57 frontend con axe, `compileall` y build 289,8/322 KiB. Revisión sintética 320/768/1440, persistencia tras reinicio y descargas verificadas; temporales y servicios eliminados, sin Internet. |
| **PROD-147 — P2 — completada**<br>Tendencias y vistas por perfil | Desarrollador, seguridad y dirección necesitan distinta densidad sobre datos comparables. | `project_risk_trends.py`, modelos/API, reporting JSON/CSV, panel/App/estilos, contratos y revisión visual; implementa PROD-105. | Periodos 30/90/180 y buckets 7/30; solo transiciones consecutivas con perfil registrado, cobertura equivalente y evidencia válida; PVI comparable exige dos snapshots `ready`. Denominadores/exclusiones, cohortes, ecosistema/fuente y tres perfiles consumen los mismos hechos. Exportación confirmada, axe y 320/768/1440. | Métricas ejecutivas engañosas, fuga cross-tenant o `resolved` falso por pérdida de cobertura. | PROD-145 y PROD-146 completadas. | L | **2026-09-09:** límite 5.000 proyectos/10.000 análisis sobre índice owner-scoped, validación autoritativa y exclusiones cerradas. KEV separado de CVSS; tiempo a resolución solo tras desaparición comparable y las duraciones no son SLA. Backend dirigido 17/17, frontend 60/60 con axe, `compileall`, diff-check y build 291,0/322 KiB. Revisión sintética ejerció tres perfiles, metodología, navegación y CSV a 320/768/1440; corrigió ARIA, target TS, cabecera móvil y digest desbordado. Servicios y fixture eliminados, sin red. |
| **PROD-148 — P1 — completada**<br>Registro de activos autorizados | Un equipo necesita demostrar qué dominio/host/IP puede analizarse, por qué y hasta cuándo. | Modelos/store/API/UI/auditoría Active. | Activo owner/org-scoped con tipo, valor redactable, alcance, método/evidencia mínima, capacidades/puertos/protocolos, expiración y revocación; no expande objetivos. Fixtures con dos organizaciones. | Un registro débil convierte Active en escáner no autorizado o retiene evidencia sensible. | PROD-012, PROD-013 y controles Active existentes. | L | **2026-09-09:** contrato/store/API/UI completos con canonicalización, historial append-only, expiración materializada, revocación y búsqueda; lectores read-only y automatización denegada. Se rechazaron wildcard/CIDR/userinfo/path/query/notas sensibles antes de persistir. Backend dirigido 25/25 con dos organizaciones; frontend App+componente 65/65 y axe; `tsc` correcto. Documentado en `docs/active-operations.md`, sin tráfico externo. |
| **PROD-149 — P1 — completada**<br>Active limitado por activo | El operador necesita iniciar Nmap/DNS OSINT/HTTP solo dentro del activo vigente. | Rutas Active, policy, jobs, UI/report. | Cada ejecución referencia activo vigente y capacidad exacta; revocación bloquea nuevas, objetivo derivado debe ser idéntico/no ampliado, defaults off. E2E solo local sintético con adaptadores falsos. | Carrera de revocación o expansión automática viola autorización. | PROD-148. | L | **2026-09-09:** admisión única sin target/perfil controlable, doble revalidación, selección TLS dentro del allowlist, persistencia asset-bound y cancelación Nmap por revocación. Rutas libres live retiradas por defecto y formularios eliminados de App. Backend Active pasó al 100 % en 9,55 s y el vertical 7/7; frontend App+centro 56/56 y `tsc`. El aparente bloqueo inicial fue un fixture que dejaba un runner lento global; se aisló y corrigió, no se atribuyó al sandbox. |
| **PROD-150 — P1 — completada**<br>Historial y postura de activos | El propietario necesita ver ejecuciones comparables y cambios observados sin confundirlos con vulnerabilidades resueltas. | Historial/comparación, UI y API Active. | Timeline de autorización/análisis; compara solo misma capacidad/contrato; puertos nuevos/persistentes/desaparecidos, cambios DNS y cabeceras como observaciones; cobertura, truncado y error visibles. | Historial puede exponer activo o presentar observación como prueba. | PROD-149. | M | **2026-09-09:** postura owner/org-scoped agrupa únicamente ejecuciones terminales de la misma capacidad y contrato, permite baseline explícita o dos últimas comparables y normaliza señales acotadas de puertos TCP, DNS, cabeceras HTTP y TLS. Expone cobertura, errores, truncado e incompatibilidad; la UI presenta historial y diferencias como observaciones, nunca como vulnerabilidades resueltas. Pasaron 439/439 pruebas backend Active seleccionadas, 5/5 del centro frontend y `tsc --noEmit`. |
| **PROD-151 — P2 — completada**<br>Reauditoría de adopción semanal | Tras tres verticales, producto necesita medir las fricciones restantes para uso recurrente. | Flujos, telemetría privada, docs y backlogs. | Ejecuta recorridos sintéticos de instalación→scan→CI→SBOM, registra tiempos/errores sin datos y añade tareas no duplicadas con criterios. | Declarar adopción por cobertura de pruebas sin observar el recorrido real. | Tres primeros verticales del Ciclo 6 completados. | M | 2026-09-06: se recorrieron instalación/ayuda/scan sintético, credencial+admisión CI concurrente+policy+salidas, e importación/repetición/comparación SBOM. Backend y tools pasaron al 100 %, CLI 13/13, frontend 309/309 y build 318,7/322 KiB. Revisión visual 1265×710/390×844 corrigió un solapamiento y confirmó ausencia de overflow móvil. Hallazgos y tiempos redactados en `docs/adoption-review-cycle-6.md`; se añadieron PROD-152–166. |
| **PROD-152 — P1 — completada**<br>Distribución local verificable del CLI | Un desarrollador necesita instalar una versión fija sin clonar todo el monorepo. Flujo: artefacto local aprobado → verificar digest/procedencia → instalar en Python 3.12 limpio → `inspectra doctor`/`scan`. | `cli/pyproject.toml`, build, versión, SBOM de distribución, docs y pruebas de instalación. | Wheel y sdist reproducibles dentro de tolerancias documentadas, checksums, una sola fuente de versión y smoke offline desde ambos artefactos; incluye Gitleaks/Git como requisitos externos comprobables. No publica nada. | Artefacto no trazable o versión divergente impide adopción y facilita sustitución de dependencias. | PROD-131/132. | M | 2026-09-08: `inspectra_cli.__version__` gobierna metadata, `--version`, User-Agent y SARIF; `inspectra doctor` valida Python 3.12, Git, Gitleaks, política empaquetada y canario sin leer proyecto ni usar red. La receta final construyó dos copias aisladas de solo lectura y exigió igualdad byte a byte: wheel `c269cb60f144f843ef9c0b7936c33fd7fde5986d1f5cd9210a05857f627a7b0e`, sdist `17d496f21a40824762fb7dadb19ce83f3415fa6a5696c34964a23627f2b364eb` y SBOM `0a04dc27d39d082ff767a4c4ac3b905f7502035820488705751145dec56726ae`. `SHA256SUMS` pasó; wheel y sdist se instalaron sin repositorio/dependencias runtime y ejecutaron version/help con política incluida. El E2E artefacto→doctor→preflight→upload→resultado se conserva en `docs/adoption-review-cycle-7.md`; 34/34 pruebas CLI y compileall pasaron. No se publicó ningún artefacto. |
| **PROD-153 — P1 — completada**<br>Asistente CI por proyecto | Un equipo necesita pasar del proyecto al primer pipeline sin copiar datos a ciegas. Flujo: abrir proyecto → elegir proveedor genérico/GitHub → política/baseline → crear token → copiar variables y snippet sin secreto embebido → probar lectura mínima. | Frontend proyecto, API de tokens/capabilities, docs y fixtures. | Genera snippet con URL/ID no secretos y referencia a `INSPECTRA_TOKEN`; nunca renderiza el token después del paso único; explica 0/8/9, baseline y cobertura. Estado vacío/error/éxito, teclado y móvil. | Copiar un secreto al YAML/log o sugerir permisos amplios expone proyectos; una policy opaca crea falsos verdes. | PROD-133–136. | M | 2026-09-08: el workspace incorpora un asistente administrativo GitHub/genérico con policy, estado de baseline, TTL, secreto de una sola fase y snippet que solo referencia `INSPECTRA_TOKEN`. La URL insertada admite HTTPS o HTTP-loopback sin credenciales/query/fragmento/controles y el ID se valida antes de generar shell/YAML. `GET /automation/tokens/{id}` comprueba metadatos owner-scoped, revocación, caducidad, proyecto y ámbitos sin recibir el secreto ni ejecutar CI. Pasaron 8/8 pruebas frontend (DOM, inyección, portapapeles, axe y panel integrado), `tsc`, build Vite (326.597/329.728 bytes) y la regresión backend ASGI de creación→probe→uso→revocación. Los cachés `node_modules/.vite-temp` y `dist` preexistentes eran root-only; la validación se repitió con config loader y outDir efímero, sin atribuirlo al sandbox. Documentado en `docs/ci-integration.md`; no hubo CI remoto, push ni PR. |
| **PROD-154 — P1 — completada**<br>Revisiones SBOM atómicas | Equipos que publican SBOM periódicamente necesitan mantener historial en el mismo proyecto. Flujo: proyecto SBOM → selección/atestación → digest/idempotencia → snapshot inmutable → resultado → comparación. | Store/admisión, ruta multipart owner-scoped y bearer `project:scan`, modelos, UI del workspace, comparación, documentación y cleanup. | Solo un proyecto SBOM admite otra revisión del mismo formato; clave+digest evitan duplicados y replay ambiguo; fallo no mueve puntero, contador ni historial y elimina fuente/job; la clave solo persiste como SHA-256 interno. | Mezclar archive/SBOM o perder atomicidad falsea tendencias y retiene datos. | PROD-137–139 completadas. | L | **Evidencia 2026-09-08:** backend 3/3 con carrera/replay/conflicto, formato incompatible, fallo entre fases, dos owners, inventario, comparación y ausencia de campos privados; frontend 67/67 con App/axe/errores/lector; `tsc` correcto; build 327.294/329.728 bytes; `docs/sbom-import.md`. |
| **PROD-155 — P1 — completada**<br>Conformidad SARIF oficial | Integradores necesitan que el artefacto sea aceptado por consumidores SARIF reales. Flujo: resultado → render acotado → validar contra esquema fijado → entregar. | `integration_output.py`, fixture del esquema oficial, tests y docs. | Todos los fixtures validan SARIF 2.1.0 contra una copia oficial con origen/licencia/hash documentados; paths inseguros siguen omitidos y límites preservados. | Un JSON parecido a SARIF puede ser rechazado silenciosamente o perder ubicaciones. | PROD-136. | S | 2026-09-08: se fijó sin modificar el esquema oficial OASIS SARIF 2.1.0 Plus Errata 01 (112.768 bytes, SHA-256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`) con fuente, copyright y términos documentados. El renderer usa su URI normativa y sustituyó el objeto policy no conforme por propiedades primitivas/array acotadas. JSON Schema Draft 4 valida offline casos vacío, ubicación segura/omitida, severidad desconocida, razones incompletas y corte exacto de 1.000 resultados. Pasaron 2/2 pruebas dirigidas y 34/34 de la suite CLI en CPython 3.12/Git; no hubo red durante pytest. |
| **PROD-156 — P1 — completada**<br>Negociación CLI/servidor | El usuario necesita detectar incompatibilidad antes de escanear y subir. Flujo: CLI → capabilities/version pública mínima → comprobar contratos/formatos → continuar o fallar con acción concreta. | Backend capabilities, cliente CLI, contratos y docs. | Handshake sin datos de proyecto declara versiones compatibles de snapshot/CI/policy; incompatibilidad bloquea antes de Gitleaks/upload y distingue servidor antiguo/no disponible. | Subir primero y descubrir después un contrato incompatible desperdicia datos/tiempo y puede dejar huérfanos. | PROD-132/134. | M | 2026-09-08: `GET /client-capabilities` es público, estático, source-free, de esquema cerrado y rechaza query/body sin reflejarlos. La CLI omite incluso el bearer en esa llamada y exige protocolo más contratos Git snapshot, admisión CI, policy y resultado; ausente/404, malformado, incompatible o indisponible falla con causa segura. El handshake ocurre antes de construir snapshot o llamar Gitleaks y `--dry-run` conserva cero red. Pasaron 21/21 pruebas CLI, prueba ASGI backend dirigida, compileall y diff-check; una regresión demuestra cero preflight/upload ante rechazo. |
| **PROD-157 — P1 — completada**<br>Ciclo de credenciales de automatización | Seguridad necesita rotar sin corte y eliminar metadatos caducados de acuerdo con retención. Flujo: crear reemplazo → verificar uso → revocar anterior → purgar registro tras plazo. | SQLite tokens, API/UI, auditoría, retención y docs. | Rotación guiada mantiene como máximo dos activas durante ventana acotada; revocación inmediata; purge owner-scoped de caducadas/revocadas sin borrar auditoría mínima requerida; `last_used_at` no es dato de actividad fina. | Rotación manual causa caídas; retención indefinida revela nombres y patrones operativos. | PROD-133 y política de retención. | M | 2026-09-08: SQLite aplica bajo `BEGIN IMMEDIATE` un máximo de dos activas por organización+proyecto incluso con tres creaciones concurrentes; una tercera devuelve 409 y no consume material secreto. Reinicio conserva el límite, revocación es inmediata, el reemplazo puede descartarse antes de revocar y `last_used_at` se actualiza en bloques horarios. La limpieza elimina solo metadatos revocados/caducados de la organización activa tras 30 días configurables (1–365) y no toca la auditoría independiente; el contrato de 15 clases es `2026-09-08.1`. La UI explica el orden, impide la tercera, diferencia expirado/revocado y elimina el secreto del DOM. Pasaron 16/16 pruebas backend dirigidas, 9/9 frontend, `tsc`, build 326.597/329.728 bytes, compileall, `docker compose config` y diff-check. |
| **PROD-158 — P1 — completada**<br>Certeza del grafo SBOM | El desarrollador necesita distinguir una dependencia transitiva demostrada de una clasificación conservadora por falta de grafo. | Normalizador SBOM, modelos de componente/hallazgo/correlación, cobertura, UI, comparación, informe y recomendación. | Cada componente incluye `relationship_status=reported|not_reported|truncated`; alcance directo/transitivo exige camino válido; ausencia y truncado se muestran como desconocido/inconcluso y no alimentan prioridad ni recomendación como certeza. | Etiquetar desconocido como transitivo puede priorizar mal o ocultar pérdida de cobertura. | PROD-138/139 completadas. | M | **Evidencia 2026-09-08:** recorrido acotado con ciclos/distancia mínima y deduplicación; fixtures de raíz/relación ausente y truncado; backend dirigido 57/57 para SBOM, policy, comparación e informe; frontend 35/35 para inventario, inteligencia y comparación; `tsc` correcto; contrato/documentación `2026-09-08.1` en `docs/sbom-import.md`. |
| **PROD-159 — P2 — completada**<br>Cancelación opcional desde CLI | Quien interrumpe un pipeline necesita decidir si el análisis remoto continúa. Flujo: señal/timeout → mostrar job → `--cancel-on-interrupt` → cancelación idempotente → estado terminal. | CLI cliente/comandos, scope bearer, backend cancel y docs. | Por defecto conserva el trabajo; flag explícito solicita una vez cancelación del job propio y reporta si no pudo confirmar; nunca cancela replay ajeno ya existente. | Cancelar implícitamente rompe reintentos compartidos; no ofrecer opción consume cuota. | PROD-008/132/134. | S | **2026-09-10:** flag opt-in para timeout/`Ctrl-C`, una única petición exacta, replay siempre omitido y estados cerrados con enlace. 401/409 preservan códigos 6/130 y no exponen respuesta. CLI 65/65 offline, backend bearer/cancel 2/2, `compileall` y diff-check; documentación CLI/CI actualizada. La suite se repitió con Git y dependencias lock locales tras identificar un primer runtime incompleto, sin Internet. |
| **PROD-160 — P2 — completada**<br>Perfiles locales del CLI | Un usuario recurrente necesita guardar URL, proyecto y policy sin repetir flags, manteniendo el token fuera del archivo. | CLI config, permisos, precedencia, docs y tests. | Archivo opcional con esquema cerrado, sin campo de token, rechaza symlink/permisos inseguros y respeta flags>env>perfil; `inspectra config show` redacta valores sensibles. | Config arbitraria o token persistido filtra credenciales y hace ejecuciones no reproducibles. | PROD-131–135. | M | 2026-09-08: perfiles JSON versionados, cerrados, ≤64 KiB y ≤32 entradas se leen solo de forma explícita; se rechazan symlink, no-regulares, duplicados, permisos POSIX distintos de 0600, URL/ID/policy/límites inválidos y toda clave sensible. `INSPECTRA_TOKEN` nunca es campo ni valor de salida. `config show` presenta valores no sensibles y procedencia `flag > environment > profile > default`; rutas convencionales de Linux/macOS/Windows están calculadas pero no implican soporte validado. Pasaron 30/30 pruebas CLI, incluidas precedencia, permisos, homes sintéticos y canario de token; compileall y diff-check pasaron. |
| **PROD-161 — P2 — completada**<br>Matriz multiplataforma CLI | Equipos mixtos necesitan saber dónde funciona el snapshot reproducible. | Git subprocess, TAR, paths, packaging, docs y CI local simulada. | Declara Linux/macOS/Windows soportado o no; mismas fixtures producen lista/digest contractual cuando Git lo permite; mensajes cubren path Unicode, CRLF y shell. | Suposiciones POSIX pueden incluir archivos distintos o impedir adopción. | PROD-152. | M | 2026-09-08: la matriz canónica declara soporte demostrado solo para Linux x86_64/CPython 3.12 y marca macOS, Windows nativo y WSL2 como no validados, sin inferir soporte del wheel universal. Una regresión Git real conserva bytes CRLF y nombres UTF-8/espacios y produce TAR idéntico; la documentación explica invocación sin shell, orden y límites. Pasaron 31/31 pruebas CLI en Debian/Python 3.12 con Git 2.47.3 y diff-check. Se registró `PROD-167`, bloqueada por runners reales y la autorización CI ligada a `SEC-012`/`PROD-130`; no se simuló ningún SO. |
| **PROD-162 — P2 — completada**<br>Métricas privadas de adopción | Operación necesita detectar fricción sin observar nombres, paths, componentes ni repositorios. | Observabilidad, configuración opt-in, docs y tests. | Solo contadores/duración por fase y códigos cerrados; cardinalidad acotada, off por defecto, sin ID persistente de usuario/proyecto; exportación local inspeccionable. | Telemetría de seguridad puede reconstruir actividad o activos. | Observabilidad existente. | M | **2026-09-10:** contrato `2026-09-10.1`, apagado por defecto, instrumenta únicamente diez rutas allowlist con día UTC, flujo/fase/resultado y seis cubos de duración. SQLite privado 0600, 8.192 filas/16 MiB y retención de 90 días; no guarda timestamps/duraciones exactos, IDs, paths, query, payload, componentes ni contenido. Exportación exclusiva por CLI local sin transporte externo; readiness, backup/restore y política de retención `2026-09-10.7` (25 clases) validan el esquema y fallan cerrado ante manipulación. La suite descubrió y corrigió la omisión inicial de los literales de la nueva clase. Pasaron 19/19 pruebas dirigidas, 2/2 middleware/retención, backend completo 1.612/1.612 offline por grupos (97,81 s + 226,11 s), frontend 420/420 y build 302,7/322 KiB, `compileall`, Compose base/privado, coherencia de backlogs y diff-check. Sin red, proyectos externos, push, PR, tag ni despliegue. |
| **PROD-163 — P2 — completada**<br>Clones superficiales y objetos ausentes | En CI, el commit pedido puede no existir localmente y el usuario necesita una acción segura. | `git_snapshot.py`, CLI errores/docs y fixtures Git. | Detecta objeto ausente/shallow sin intentar `fetch`; mensaje indica cómo aportar el commit sin URL/token; distingue revisión inválida de objeto prometido no disponible. | Fetch automático ampliaría red/credenciales; error genérico alarga diagnóstico. | PROD-131/132. | S | 2026-09-08: la frontera Git detecta shallow y repositorios promisor, diferencia revisión inexistente de árbol/blob incompleto o corrupto y nunca expone stderr, ruta, remote u object ID. Todas las invocaciones establecen `GIT_NO_LAZY_FETCH=1`; ninguna ejecuta `fetch`. Fixtures reales cubren clon `--depth 1` con commit histórico ausente, SHA desconocida y objeto loose retirado, además de espiar comandos y entorno. Pasaron 33/33 pruebas CLI, compileall y diff-check; documentación indica materializar el commit autorizado fuera de Inspectra y reintentar sin entregar URL/token. |
| **PROD-164 — P1 — completada**<br>Preflight SBOM visible | Antes de crear un proyecto, el usuario necesita conocer formato, retenidos, rechazados, truncado y elegibilidad. Flujo: seleccionar → preflight privado sin persistencia/egress → revisar agregados → atestiguar → importar mismos bytes. | Store efímero acotado, API multipart, normalizador, modelos, UI y documentación. | El preflight no persiste el original ni identidades, devuelve solo formato/versión/contadores y caduca en 300 s; token owner-scoped de un uso vincula digest; cambio de archivo invalida UI y backend; máximo 256 admisiones. | Atestiguar a ciegas identidades públicas causa fuga lógica; mantener preflight retiene SBOM. | PROD-137–139 completadas. | M | **Evidencia 2026-09-08:** backend 35/35 con digest distinto, single-use, owner, expiración/límite y cero stores tras preflight; frontend 62/62 con App/axe/parcial; `tsc` correcto; build 327.509/329.728 bytes; límites fail-closed multiworker en `docs/sbom-import.md`. |
| **PROD-165 — P1 — completada**<br>Portada por intención | Nuevos y recurrentes necesitan elegir “repositorio local”, “CI” o “SBOM” sin recorrer una consola extensa. | Arquitectura de información, navegación, App, estados y visual review. | Entrada con tres acciones principales y proyectos recientes; auditorías especializadas quedan en disclosure; deep links y foco preservados; 320/768/1440 sin overflow y sin degradar estados críticos. | Densidad actual ocultaba el camino feliz y aumentaba errores de autorización. | PROD-111 y verticales 1–3 completadas. | L | **Evidencia 2026-09-08:** portada con Archivo/CI/SBOM, recientes, administración colapsada y auditorías especializadas separadas; Archivo y SBOM requieren una acción y trasladan foco, CI explica el bloqueo o abre workspace+`ci-setup` manteniendo deep link. Revisión real 1440/768/320: cero overflow, CTA 44 px y consola limpia; 70/70 pruebas dirigidas con axe/teclado. Suite frontend 48 archivos/322 pruebas; `tsc`; build 328.334/329.728 bytes tras separar la guía en un chunk diferido. Registro en `docs/frontend-visual-review.md`. |
| **PROD-166 — P1 — completada**<br>UX por tipo de fuente | Un proyecto SBOM no debe ofrecer acciones de archivo y viceversa. | `ProjectView`, listado, workspace/timeline, CI, formularios, findings, comparación y docs. | Fuente expone tipo seguro `archive|sbom` sin nombre privado; Run conserva perfil; Add y remediación ofrecen solo archivo o revisión SBOM compatible; selector archive falla cerrado ante SBOM. | Acción incompatible produce 409 confuso o mezcla de coberturas. | PROD-137–139 y PROD-154 completadas. | M | **Evidencia 2026-09-08:** backend 6/6 con respuesta archive/SBOM; frontend 80/80 con App/workspace/form/findings/comparison; `tsc` correcto; ningún CTA CI/ZIP en workspace SBOM; contrato en `docs/product-projects.md`. |
| **PROD-167 — P2 — bloqueada**<br>Habilitar macOS y Windows con evidencia real | Equipos mixtos necesitan ampliar el soporte sin asumir que un wheel puro garantiza snapshots iguales. Flujo: artefacto único verificado → instalar en runners reales → doctor → repos fixture → dry-run → comparar lista/digest/errores. | Matriz CI autorizada, scripts multiplataforma, docs y soporte operativo. | macOS y Windows solo pasan a soportados si runners reales prueban Python/Git/Gitleaks, ACL/permisos, Unicode/CRLF/path largo, señales y digest contractual; fallos generan límites explícitos. | Anunciar soporte por simulación puede variar el contenido subido o fallar el control de secretos. | PROD-161; bloqueada por PROD-130/SEC-012 y disponibilidad/autorización de runners reales. | M | Matriz remota sobre commit exacto y artefacto con hash; hoy no ejecutada ni simulada. |
| **PROD-168 — P0 — completada**<br>Restaurar contratos públicos y puertas operativas tras cambios del Ciclo 7 | Usuarios y operación necesitan que un metadato interno nuevo no rompa todas las lecturas de trabajos y que smoke/recuperación validen el contrato de retención vigente. Flujo: revisión SBOM → detalle de job → smoke/backup/restore → política de 15 clases. | `models.py`, `retention.py`, `deployment_smoke.py`, `recovery_drill.py` y regresiones backend. | `sbom_revision_key_sha256` queda solo en almacenamiento y nunca entra en API; detalle de cualquier job valida; smoke y drill consumen la versión `2026-09-08.1` y el contador central de 15 clases; expectativas de certeza SBOM incluyen los campos contractuales. Suite backend completa obligatoria. | Una proyección rota inutiliza resultados; una puerta obsoleta genera NO-GO falso o deja de vigilar una clase sensible. | Descubierta al validar PROD-154/157/158/165; ninguna dependencia externa. | S | **Evidencia 2026-09-08:** la primera suite completa llegó al 100 % y listó 74 fallos encadenados por la proyección extra y dos checks de 14 clases; tras la corrección dirigida pasaron 11/11, una segunda pasada aisló una expectativa antigua del grafo y la tercera pasó 1.117/1.117. La respuesta de job de una revisión SBOM prueba ausencia del hash; smoke y recovery verifican 15 clases y el resumen tipado del drill declara la versión vigente. |
| **PROD-169 — P1 — completada**<br>Baseline, triage y exportación Active | Operaciones necesita fijar una referencia, registrar una decisión cerrada y compartir evidencia acotada. Flujo: activo → historial comparable → baseline → triage → informe Markdown. | Store/API Active, postura, frontend, reporting y auditoría. | Baseline solo acepta ejecución terminal del activo y contrato/capacidad comparable; triage usa estados cerrados sin notas libres; exportación owner-scoped incluye cobertura y límites, nunca salida cruda. Regresiones de otro owner, incompatibilidad y redacción. | Un baseline ajeno o un informe crudo filtra activos y convierte observaciones en conclusiones. | PROD-150. | M | **2026-09-09:** baseline compatible, triage cerrado e informe Markdown owner-scoped implementados y auditados. Backend Active 439/439; centro frontend 5/5; TypeScript correcto; sin red. |
| **PROD-170 — P1 — completada**<br>Verificación opcional del control del activo | Un equipo necesita elevar confianza operativa mediante un reto acotado sin confundir control técnico con autorización legal. Flujo: activo autorizado → operador habilita función → reto manual/DNS TXT/HTTP well-known/privado gestionado → comprobación → expiración o revocación. | Configuración, store/API Active, adaptadores DNS/HTTP, frontend, auditoría y docs. | Deshabilitada por defecto; reto de un solo uso y TTL corto, solo digest persistido; DNS/HTTP usan nombre/ruta fija, sin redirecciones ni expansión; respuesta cruda no se conserva. Caduca/revoca, nunca amplía capacidades y toda prueba ordinaria usa mocks/local. | Verificación remota mal limitada habilita SSRF, fuga de tokens o falsa prueba de autorización. | PROD-148. | L | **2026-09-09:** contrato/store/API/UI para atestación manual, TXT fijo, HTTP well-known público y adaptador privado gestionado. Challenge de 15 min, 5/hora, digest SHA-256, vigencia ≤90 días/autorización, revocación y aislamiento. HTTP conecta a la IP global prevalidada y no vuelve a resolver ni sigue redirects; 3 s/512 bytes. Pasaron 18/18 pruebas backend específicas, 539/539 de configuración/Active/auditoría, 6/6 frontend, TypeScript y axe. Revisión 320/768/1440 sin overflow, controles ≥44 px y consola limpia, solo con activo sintético local. |
| **PROD-171 — P1 — completada**<br>Centro de operaciones Active v1 | Operadores necesitan una única superficie para activos, autorizaciones, ejecuciones, cambios y acciones pendientes. Flujo: abrir centro → filtrar → registrar/verificar → ejecutar → seguir → comparar/triage/exportar/revocar. | API agregada/configuración segura, `ActiveOperationsCenter`, navegación, estilos y docs. | Resumen owner/org-scoped de activos activos/por caducar/revocados y jobs en curso/fallidos; filtros útiles; estados carga/vacío/parcial/error; configuración Active visible sin secretos; teclado, axe y 320/768/1440; ninguna acción acepta target libre. | Una consola fragmentada oculta caducidades/fallos y facilita ejecutar con contexto incorrecto. | PROD-148, PROD-149, PROD-150 y PROD-170. | L | **2026-09-09:** read model cerrado de conteos/acciones/configuración, límite 500 activos/2.000 jobs y degradación independiente; filtros y detalle a ancho completo. Backend 20/20, frontend 8/8, axe y TypeScript. Revisión sintética sin red a 320/768/1440: cero overflow, tarjeta/grid 241/673/1326 px y controles >=44 px. Docs en `active-operations.md` y `frontend-visual-review.md`. |
| **PROD-172 — P2 — completada**<br>Revisiones Active recurrentes autorizadas | Equipos necesitan observar cambios periódicos sin reautorizar manualmente cada lanzamiento ni ejecutar tras caducidad. Flujo: activo verificado → política acotada → próxima ejecución visible → revalidación → ejecución → historial → pausa/reanudación/borrado. | `active_recurrence.py`, scheduler/cola durable, revisión/verificación Active, borrado/backup, API, `ActiveRecurrencePanel`, auditoría y runbooks. | Opt-in default-off; 7/14/30 días y jitter estable 1–900 s; máximo 500 políticas/organización y 16 vencidas/tick, además de cuotas de jobs; cada ocurrencia revalida activo, revisión exacta, última verificación vigente, capability gate y runner; renovar/revocar suspende; idempotencia evita duplicar una ocurrencia; no acepta ni duplica target. CRUD owner-scoped y UI accesible con estados carga/vacío/error/configuración. | Un programador sin revalidación puede escanear tras retirar consentimiento, crear tormentas o filtrar alcance. | PROD-170, PROD-171 y límites operativos Active. | L | **Evidencia 2026-09-08:** contrato persistido `2026-09-08.1`, scheduler default-off y flujo API/UI completo. Una revisión visual detectó que la UI ofrecía una combinación ya programada; se bloqueó explícitamente y quedó cubierta. Backend 1.226/1.226 y tools 439/439 en Docker `--network none`; frontend 343/343, build y bundle inicial 283,0/322 KiB; compileall, Compose base/privado/Active standalone y diff-check. Recorrido local sintético creó, persistió tras reinicio, pausó y reanudó sin ejecutar capacidad: 320/768/1440 sin overflow (305/305, 753/753, 1425/1425), controles 44 px y consola limpia. Contenedores, imágenes, volumen, pestaña y datos sintéticos eliminados. |
| **PROD-173 — P1 — completada**<br>Reauditoría de uso semanal empresarial de Active | Producto necesita descubrir la fricción real restante antes de ofrecer recurrencia. Flujo sintético: alta → control opcional → ejecución → seguimiento → comparación → decisión → informe → revocación. | Recorridos, telemetría privada local, documentación, pruebas visuales y backlogs. | Ejecuta al menos dos ciclos sintéticos y roles admin/maintainer/reader, registra tiempos/errores con códigos cerrados y añade tareas no duplicadas sobre permisos, evidencia, límites, UX y operación. No declara adopción por cobertura de tests. | Sin reauditoría, el centro puede ser técnicamente correcto pero inviable en operación diaria. | PROD-171, PROD-174 y PROD-175 completadas. | M | **2026-09-09:** dos ciclos y tres roles recorrieron alta, control, runner, postura, baseline, triage, informe y revocación; la repetición dirigida pasó sin red. La revisión encontró/cerró PROD-174/175 y añadió PROD-176–192 pendientes. Matriz en `docs/active-weekly-adoption-review.md`. Validación final: frontend 320/320, TypeScript/build, compileall, auditorías Python/npm sin hallazgos, Compose default/private/Active, Gitleaks y diff-check. |
| **PROD-174 — P0 — completada**<br>Compatibilidad Active con administrador raíz de equipo | Una organización recién creada debe poder iniciar Active con su administrador bootstrap. Flujo: login de equipo → alta → verificación → ejecución/gestión compartida. | Contratos/store de activos y verificaciones, identidad de equipo y pruebas de roles. | `team-admin` se acepta solo como actor/responsable/owner, nunca como ID de organización; admin puede completar Active, IDs arbitrarios siguen rechazados y secretos de sesión/reto no persisten. Repetir ciclo admin/maintainer/reader. | El modo empresarial anunciado no puede crear activos; ampliar indiscriminadamente el patrón permitiría namespaces de almacenamiento no válidos. | Identidad de equipo ya implementada; descubierta por PROD-173. | S | **2026-09-09:** espacios actor/organización separados; recorrido admin/maintainer/reader con alta, verificación, dos ciclos, baseline/triage/report, revocación y denegaciones pasó en 0,79 s. Regresión adicional rechaza IDs arbitrarios y persistencia no contiene passwords/challenge. |
| **PROD-175 — P0 — completada**<br>Aislar todas las ejecuciones Active registradas en el runner | Un operador necesita garantías de que DNS, CT, HTTP y TLS no abren sockets desde el backend privilegiado. Flujo: activo autorizado → admisión/revalidación → contrato fijo interno → runner aislado → resultado acotado → persistencia redactada → revocación/cancelación. | `backend/app/main.py`, cliente interno del runner, `tools/active_runner`, imagen `active-tools`, Compose, pruebas y documentación operativa. | Las cuatro capacidades cruzan exclusivamente rutas y perfiles internos fijos; backend no tiene fallback de red; doble opt-in backend/runner; destino interno privado sin userinfo/path y sin redirects; timeout ≤8 s, respuesta ≤256 KiB, concurrencia ≤4; revocación cancela la petición y deja estado terminal; resultados no contienen target, comandos, salida cruda ni secretos. Imagen/Compose y fixtures prueban éxito, flags off, errores, exceso de tamaño y cancelación sin Internet. | Red desde backend amplía el impacto de SSRF/errores de autorización; una revocación que no corta tráfico mantiene actividad fuera del consentimiento vigente. | Runner Nmap y registro Active existentes; descubierta por PROD-173. | M | **2026-09-09:** límite cerrado con cuatro rutas/perfiles fijos, doble gate, cliente interno sin redirects (8 s, 256 KiB, concurrencia 4), rechazo de target/salida cruda y cancelación terminal al revocar. La imagen importó el ASGI app y enumeró rutas bajo read-only/`--network none`; SHA local `7f1d04b…e288b56`. Pasaron 29 pruebas dirigidas, 427/427 tools, 1.150/1.150 backend, ambos `docker compose config` y diff-check, con red de tests deshabilitada/simulada. Documentado en README, arquitectura y `active-operations.md`. |
| **PROD-176 — P1 — completada**<br>Renovación reatestiguada de autorización | El propietario necesita renovar un activo antes de caducar sin borrar su historia. Flujo: aviso → revisar alcance actual → nueva atestación/referencia/fecha → confirmar → nueva revisión append-only. | Contrato/store/API/UI Active, auditoría y docs. | Una renovación crea revisión nueva, no resucita revocados, no amplía capacidad/puerto sin confirmación específica y limita vigencia a 366 días; carrera e idempotencia fallan cerrado. Pruebas con reloj falso, dos organizaciones, expirado/revocado y CSRF. | Editar fechas en sitio destruye trazabilidad o reactiva permiso retirado. | PROD-148, PROD-170 y PROD-185 completada. | M | **2026-09-08:** API/store/UI/informe/auditoría completan renovación append-only con CAS de revisión, idempotencia concurrente y confirmación separada. La revisión inmutable conserva `scope_expanded`; caducados requieren reatestiguación y revocados quedan bloqueados. Backend dirigido 39/39 y completo 1.590/1.590 sin red; frontend 322/322, TypeScript y build 285.825 bytes/322 KiB. Recorrido localhost y revisión 320/1440 confirmaron estados, historial y ausencia de overflow; recursos sintéticos eliminados. |
| **PROD-177 — P1 — completada**<br>Responsables miembros vigentes | El administrador debe asignar un activo solo a miembros reales de su organización. Flujo: alta/renovación → seleccionar miembros activos → backend verifica membresía/rol → guardar IDs opacos. | Directorio de equipo, contratos Active, formulario y tests. | Rechaza IDs bien formados pero ajenos/inactivos; bootstrap se admite según contrato; lector puede ser responsable sin obtener escritura; respuesta no enumera otra organización. Fixtures con dos organizaciones y miembro revocado. | Un responsable fantasma o externo falsea ownership operativo y puede filtrar identidad. | PROD-148 y directorio de equipo. | S | **2026-09-08:** alta/renovación validan miembros activos owner-scoped; admin, maintainer y reader son asignables sin cambiar permisos, y local acepta solo su operador. Revocado/ajeno/inexistente devuelve el mismo `422` sin eco. UI accesible conserva asignación al fallar directorio y omite identidades de historial/informes. Backend dirigido 43/43 y completo 1.593/1.593; frontend 323/323, TypeScript, build 285.917 bytes/322 KiB y recorrido real team-mode 320/1440 sin overflow ni DOM ajeno. Recursos sintéticos eliminados. |
| **PROD-178 — P1 — completada**<br>Retención y borrado Active | Privacidad necesita eliminar activos, verificaciones y resultados según política sin romper auditoría mínima. Flujo: preflight → ver dependencias → exportar si procede → confirmar → borrar/anonimizar → verificar. | Retención, stores Active/jobs, API/UI, backup/restore y docs. | Política declara cada clase; owner-scoped, idempotente y reiniciable; no borra job en curso; elimina targets/challenge digests/resultados y conserva solo auditoría cerrada permitida. Pruebas de fallo entre fases, backup y otro owner. | Retención indefinida revela infraestructura; borrado parcial deja huérfanos o tendencias engañosas. | PROD-148, retención y borrado de proyecto existentes. | L | **2026-09-08:** preflight y DELETE owner-scoped, confirmación exacta, journal write-ahead reiniciable y cierre de admisión/mutaciones completados. Trabajo vivo y retos pendientes bloquean; la cascada borra verificaciones, jobs/resultados, revisiones y agregado, anonimiza auditoría a un recibo opaco y verifica cero huérfanos. El contrato de retención `2026-09-10.1` declara 19 clases; backup bloquea journals y restore valida referencias Active. Pasaron backend completo 1.206/1.206 y tools 439/439 en Docker `--network none`, frontend completo 331/331 más 34/34 tras la corrección responsive, TypeScript/build y bundle inicial 280,5/322 KiB. Recorrido local sintético a 320/768/1440 sin overflow ni target en DOM; API vacía y cero canarios en almacenamiento tras borrar. Solo quedó auditoría cerrada; recursos temporales eliminados. |
| **PROD-179 — P1 — completada**<br>Readiness efectivo por capacidad | Operación necesita distinguir “flag backend activo” de “runner sano y gate runner activo”. Flujo: abrir centro → consultar estado targetless → ver disabled/ready/degraded/unavailable → acción segura. | Health interno, `active-tools`, read model, UI, observabilidad y runbook. | Estado cerrado por capacidad combina ambos gates sin URL/host; health ≤4 KiB/2 s, sin target ni red de análisis; fallo degrada solo el resumen. Mock de timeout/malformed/desalineado y revisión visual. | Un botón aparentemente habilitado puede fallar en producción o revelar topología. | PROD-171 y PROD-175. | M | **2026-09-08:** backend y runner combinan los dos gates de las cinco capacidades en `disabled/ready/degraded/unavailable`; el health targetless exige identidad/forma exactas, no sigue redirects, limita 2 s/4 KiB y no refleja topología. La UI explica cada estado y bloquea ejecución salvo `ready`; alta y mutaciones refrescan el resumen (la revisión visual descubrió y cerró el contador obsoleto). Fixtures cubren timeout, conexión, JSON/tamaño, redirect, servicio/capacidad faltante o desalineada y target inyectado. Runner real `--network none`: off 657 B, on 687 B, cinco gates coherentes y 0 peticiones/ejecuciones. Recorrido local sintético: `degraded → ready → unavailable → ready`, activo siempre legible, cero canarios en logs y cero topología en DOM; 320/768/1440 sin overflow (305/305, 753/753, 1425/1425) y axe dirigido. Validación final: backend+tools 1.609/1.609 sin red, frontend 326/326, TypeScript/build y bundle inicial 279,7/322 KiB, Compose base/privado/Active y `git diff --check`. Cuatro ficheros sintéticos, contenedores, red y datos visuales eliminados; no se ejecutó ninguna capacidad ni objetivo externo. |
| **PROD-180 — P2 — completada**<br>Cuatro ojos opcional | Empresas reguladas necesitan separar solicitud y aprobación de alta, ampliación, renovación o revocación. Flujo: maintainer solicita → admin distinto revisa diff → aprueba/rechaza → evento inmutable. | Roles, Active store/API/UI, auditoría y configuración default-off. | Política opcional; solicitante no autoaprueba; diff cerrado sin secretos; expiración y revocación de emergencia siguen reglas explícitas. Pruebas de misma persona, carreras y dos organizaciones. | Aprobación nominal sin separación real da falsa garantía; bloquear revocación urgente prolonga riesgo. | PROD-176, auditoría y roles. | M | **2026-09-10:** default-off y solo equipo privado; alta/ampliación/renovación/revocación ordinaria quedan ligadas a digest exacto, admin distinto, solicitante original, TTL 24 h y consumo único. `security_hold` ofrece revocación urgente administrativa auditada; lotes se bloquean. Estados terminales borran target/payload, expiran a 90 días y reader no enumera. Backup/restore, retención y borrado cubren el store `0600`. Se corrigieron CORS y refresco terminal descubiertos visualmente. Offline: 2.044/2.044 Python (`496,07 s`, 30.264 KiB), 416/416 frontend, build 301,8/322 KiB, compileall, Compose y diff-check. Recorrido local 320/768/1440, consola/overflow limpios, reinicio persistente y canarios ausentes; recursos eliminados. Sin capacidad, egress, proveedor, proyecto real, push, PR ni despliegue. |
| **PROD-181 — P2 — completada**<br>Alta masiva con dry-run | Equipos grandes necesitan registrar decenas de activos exactos sin formularios repetidos. Flujo: cargar CSV/JSON acotado → parseo local → preflight agregado → corregir → confirmar lote → resultados por fila. | Ingesta Active, validadores, API/UI, cuotas y docs. | Máximo fijo, esquema cerrado, cero wildcard/CIDR/URLs con path, transacción idempotente y sin altas parciales silenciosas; no persiste original. Fixtures hostiles/duplicados/otro owner. | La importación puede ampliar alcance masivamente o retener inventario sensible. | PROD-148, PROD-177 y PROD-184. | M | **2026-09-08:** JSON/CSV cerrado, 50 filas/128 KiB, preflight en memoria de 5 min ligado a actor+organización+bytes y resultado explícito por fila. Solo un dry-run totalmente listo permite la confirmación global. Commit bajo lock con journal sin target, rollback/recovery, IDs deterministas y replay exacto; el original, filename, token y clave nunca son durables. Backup/restore valida recibos y el borrado de cualquier miembro los invalida. Visual local real: tres `.test`, preflight/commit/replay, 320/768/1440 sin overflow, controles ≥44 px, consola limpia; el driver no soportó `DataTransfer`, por lo que upload real fue API local y tabla/axe se validó con componente determinista. Pasaron 91 dirigidas, backend 1.221/1.221 y tools 439/439 sin red, frontend 341/341, TypeScript/build 281,9/322 KiB, tres Compose, compileall y diff-check. Todo recurso sintético se eliminó. |
| **PROD-182 — P2 — completada**<br>Bandeja de acciones y SLA local | Un operador semanal necesita ordenar caducidades, fallos, cambios y verificaciones sin inspeccionar cada tarjeta. Flujo: abrir bandeja → filtrar prioridad/edad → resolver mediante acción permitida → ver estado actualizado. | Resumen Active, frontend, triage y preferencias locales. | Prioridad deriva de códigos cerrados y fechas, explica por qué, no inventa SLA ni vulnerabilidad; deep link con foco; estado vacío/parcial. Tests de orden estable y zona horaria. | Un contador sin cola accionable oculta trabajo; prioridad opaca induce decisiones incorrectas. | PROD-171, PROD-176 y PROD-183 completadas. | M | **2026-09-08:** contrato `2026-09-09.2`, cola owner-scoped/target-free de 100 acciones, orden estable, fuente parcial y estado actual por capacidad. Triage cerrado y éxito posterior limpian acciones sin borrar historia. UI con prioridad/edad desde `generated_at`, preferencias locales, vacío/parcial/error, deep link/foco y activo fijado fuera del filtro. Pasaron 14 dirigidas backend, backend 1.233/1.233 y tools 439/439 sin red; frontend 21 dirigidas y 347/347 completas con axe, build 283,0/322 KiB, compileall, tres Compose y diff-check. Flujo real sintético 320/768/1.280 sin overflow, controles 44 px, hash/foco/filtro persistentes; summary/logs sin target, cero capacidad/egress y limpieza total de recursos dedicados. Invocaciones auxiliares que no llegaron a tests/build no se cuentan como éxitos. |
| **PROD-183 — P1 — completada**<br>Cola durable y progreso Active | Usuario necesita lanzar, abandonar la página, volver, cancelar y entender interrupciones. Flujo: admisión → job queued → worker toma → running → terminal; cancel/restart/retry idempotente. | Job store, scheduler/worker, runner Active, API/UI, readiness y recovery. | Job se crea antes del runner; transiciones cerradas y monotónicas; cancelación corta runner; reinicio recupera o falla con código seguro; retry crea intento enlazado sin duplicar tráfico. Pruebas con runner lento/crash y reloj falso. | La petición síncrona pierde estado, impide cancelación UX y puede duplicar escaneos tras timeout. | PROD-008, PROD-149 y PROD-175. | L | **2026-09-08:** job previo al tráfico, claim CAS, progreso cerrado, cancelación persistida/cross-worker, recuperación solo de queued revalidado y retry enlazado/idempotente completados. API/list/detail/report no exponen clave ni digest; runners no reciben metadatos adicionales. 42/42 Active, backend 1.185/1.185 y tools 429/429 sin red; frontend 327/327+axe, TypeScript/build 280,2/322 KiB; Compose y diff-check. Recorrido local con cuatro estados a 320/768/1440 sin overflow; recursos sintéticos eliminados. |
| **PROD-184 — P1 — completada**<br>Cuotas Active por organización | Operación necesita evitar que un equipo agote runner y red. Flujo: admitir → comprobar cupo global/org/activo/capacidad → ejecutar o 429 con retry seguro → liberar. | Admisión, almacenamiento coordinado, configuración, centro y métricas. | Límites conservadores documentados; conteo atómico multiworker; no usa target como etiqueta; revocación/cancelación libera cupo; rechazo no crea tráfico. Tests de carrera y reinicio. | Semáforo por proceso no impide abuso ni garantiza reparto justo. | PROD-149, PROD-171 y PROD-183 completada. | M | **2026-09-08:** límites configurables y fail-closed 16 global/4 organización/2 activo/4 capacidad se aplican en el mismo lock que replay/admisión. Carrera con ocho instancias de store admitió exactamente una; nuevo store tras reinicio respetó `queued/running/cancelling`. `429` uniforme con `Retry-After: 5`, cero counts/target/revisión y cero llamada al runner; fallo/cancelación/revocación terminal liberan, mientras un runner revocado conserva cupo hasta parar. Resumen/UI solo publican `ready|saturated`, mantienen historial usable y bloquean trabajo nuevo. Validación: Active 55/55, backend 1.191/1.191 y tools 429/429 sin red; frontend 328/328+axe, TypeScript/build 280,2/322 KiB, Compose y diff-check. Sin capacidad ni objetivo externo. |
| **PROD-185 — P1 — completada**<br>Revisión de autorización inmutable | Auditoría necesita demostrar el alcance exacto vigente cuando se ejecutó cada job. Flujo: registrar/renovar → generar revisión → ejecutar con ID+digest contractual → comparar/reportar. | Modelo/store Active, jobs, postura, reporting y migración compatible. | Revisión contiene solo campos estructurados no sensibles; digest/ID inmutables en job; revalidación compara misma revisión; históricos legacy son `unknown`, no se inventan. Pruebas de renovación concurrente y manipulación. | Referenciar solo el activo mutable impide reproducir por qué se admitió una ejecución. | PROD-148 y PROD-149. | M | **2026-09-08:** alta y job conservan revisión ID/secuencia/digest; el store detecta manipulación y preserva evidencia frente a updates, la segunda lectura compara la misma revisión y legacy queda `unknown`/bloqueado. UI, postura, auditoría e informe trazan la revisión sin exportar target. Backend completo 1.155/1.155 y dirigido final 31/31; frontend 321/321, build y bundle 278,9/322 KiB; revisión 1440/320 sin overflow global y limpieza verificada. Todo sin red. |
| **PROD-186 — P2 — completada**<br>Bundle de evidencia Active | Equipos necesitan archivar un paquete verificable sin raw output ni target. Flujo: seleccionar activo/periodo → generar manifiesto+informes → checksum → descargar → validar offline. | Reporting, exportaciones, autorización y docs. | ZIP/TAR determinista con manifiesto versionado, hashes, revisiones de autorización y resultados redactados; tamaño/entradas limitados; sin comandos, target, notas ni retos. Validador offline con fixtures. | Un paquete no acotado exfiltra inventario o crea falsa cadena de custodia. | PROD-169 y PROD-185. | M | **2026-09-08:** TAR canónico de seis entradas, contrato `2026-09-08.1`, periodos cerrados, máximo 100 ejecuciones, entradas ≤512 KiB y archivo ≤4 MiB. Proyecta solo señales normalizadas allowlisted; manifiesto y `SHA256SUMS` son reproducibles y el validador no extrae. Dos descargas y otra tras reinicio tuvieron SHA-256 idéntico `d9d8cf…8af3d`; canarios de target/referencia/nota/raw result dieron cero. Manipulación, >100 registros, identidad externa y otro owner tienen regresión. Backend 1.208/1.208 con `--network none`, frontend 333/333+axe, build 280,7/322 KiB, Compose y diff-check. Visual 320/768/1440 sin overflow; se corrigieron enlaces de 19 a 44 px. Contenedor, datos, TAR y capturas sintéticas eliminados. No es una firma y la documentación lo declara. |
| **PROD-187 — P1 — completada**<br>Egress de verificación en runner | Seguridad necesita que DNS TXT y HTTP well-known tampoco abran red desde backend. Flujo: reto válido → contrato fijo mínimo → `active-tools` → observación booleana → digest/estado. | Verificación Active, cliente/runner, Compose, cancelación y docs. | Backend sin transportes live; rutas internas fijas, mismo doble gate, pinning/3 s/512 B/no redirects; revocar cancela; token no aparece en logs/respuesta del runner y se destruye en memoria. Pruebas simuladas. | El backend privilegiado conserva superficie SSRF/egress aunque la ejecución principal esté aislada. | PROD-170 y PROD-175. | L | **2026-09-08:** backend conserva solo manual/managed y delega DNS/HTTP a una ruta fija del runner con contrato cerrado. Doble gate visible, `trust_env=False`, sin redirects/fallback, destino derivado, pinning global, 3 s/512 B/8 TXT y respuesta booleana sin eco. Revocación local o persistida cancela una consulta lenta y descarta su resultado; canarios no persisten. Validación: 70 dirigidas, backend 1.197/1.197, tools 439/439 sin red, frontend 328/328+axe, build 280,2/322 KiB y Compose. Imagen `9dbe4b8…f1d3e9` verificó gate off/on y health con cero tráfico bajo `--network none`; luego eliminada. Sin target externo. |
| **PROD-188 — P1 — completada**<br>Paginación Active a escala | Un equipo con miles de activos necesita buscar sin cargar/renderizar toda la cartera. Flujo: filtros server-side → cursor opaco → página → detalle → retorno preservando contexto. | Store/API Active, summary, frontend y pruebas de rendimiento. | Cursor owner-bound y firmado/validado, orden estable, page size limitada, búsqueda exacta/prefijo acotada; no revela total ajeno; UI conserva filtro/foco. Fixtures >2.000 y dos owners. | Listas completas consumen memoria, congelan UI y amplifican enumeración. | PROD-171 y almacenamiento Active. | L | **2026-09-08:** `POST /active/assets/search` entrega 24 registros por defecto/máximo 100 con filtros server-side de estado, capacidad, recencia y prefijo/exacto. El cuerpo JSON cerrado evita que el target entre en URL/access logs y aplica CSRF en sesión privada. Cursor HMAC process-local ligado a propietario, filtros, cutoff y clave estable falla genérico al manipular/cambiar owner/filtro; inserciones nuevas no duplican páginas. UI 24→48→55 preserva filtros, registros y foco, y degrada sin vaciar. Fixture 2.005+segundo owner: 3,16 s, <128 MiB, respuesta <1 MiB. Visual 320/768/1440: 305/305, 753/753, 1425/1425, controles 44 px, consola limpia; se corrigieron foco y fuga en query log. Backend 1.214/1.214 y tools 439/439 sin red; frontend 337/337+axe, build 281,5/322 KiB, Compose base/privado/Active, compileall y diff-check. Runtime, 55 activos, pestañas y puertos sintéticos eliminados. |
| **PROD-189 — P2 — completada**<br>Exportación de auditoría operativa | Auditor y operador necesitan explicar quién autorizó, ejecutó, decidió y revocó sin acceder al almacenamiento. Flujo: periodo/activo → preflight → exportar eventos cerrados → verificar. | Product audit, Active events, permisos, reporting y retención. | Export owner-scoped, límites/periodo máximo, actor opaco/rol/acción/resultado/revisión; excluye target, referencia, notas, IP de cliente y evidencia cruda. Tests de redacción y truncado. | Auditoría inaccesible obliga a leer disco; exportación excesiva filtra comportamiento. | PROD-169, PROD-185 y auditoría existente. | M | **2026-09-08:** preflight y JSON/CSV admin-only aceptan periodos 7/30/90/365, filtro opcional owner-scoped, máximo 1.000 eventos/1 MiB y truncado explícito. La proyección seudonimiza evento/actor/recurso y conserva solo rol/acción/resultado/revisión válida; omite target, referencia, notas, IP, correlación, metadata y evidencia. Regresiones cubren dos organizaciones, periodos/formato inválidos, >1.000 registros, recurso desconocido, ausencia de resultados y acceso reader. Una instancia privada sintética produjo JSON 991 B y CSV 840 B con un evento y cero de seis canarios; 320/768/1440 quedó contenido y todos los controles a 44 px tras corregir 19/19/36 px. También se habilitó el panel al administrador único autenticado. Validación: backend 1.211/1.211 y tools 439/439 en Docker `--network none`; frontend 335/335+axe, TypeScript/build 281,1/322 KiB; Compose base, privado y Active standalone, y diff-check. Consola limpia; cookies, exports, datos, contenedor, puertos y capturas sintéticas eliminados. |
| **PROD-190 — P2 — completada**<br>Ventanas y backoff de recurrencia | Operación necesita programar sin tormentas ni ejecución fuera de ventanas autorizadas. Flujo: zona horaria IANA → ventana → próxima ejecución → fallo/backoff → pausa/reanudación. | Scheduler, contrato Active recurrente, UI y observabilidad. | DST explícito; ventana semanal cerrada; backoff persistido/acotado; conserva el jitter ya implementado y no hace catch-up; siguiente hora visible y siempre dentro de autorización. Reloj falso cubre año/DST/reinicio/doble instancia. | Un scheduler ingenuo duplica tráfico o ejecuta fuera de horario/acuerdo. | PROD-172, PROD-176, PROD-183 y PROD-184 completadas. | M | **2026-09-08:** contrato `2026-09-08.2` valida IANA+días+hora+duración, no cruza medianoche y define DST; conserva identidad de ocurrencia legacy. Backoff persistido 5 min→6 h + jitter, CAS, no-catch-up y expiración fail-closed; legacy sin expiración queda suspendido. UI muestra ventana, autorización, siguiente instante/retry y estados de pausa/suspensión; telemetría es target-free. Pasaron 1.230 backend y 439 tools sin red, 344 frontend más 21 dirigidas tras dos correcciones, axe, build 283,0/322 KiB, compileall, tres Compose y diff-check. Recorrido local crear/pausar/restart/reanudar: una política, cero jobs, registro 1.168 B sin target; consola limpia, viewport real sin overflow y controles 44 px. Overrides móviles no cambiaron el viewport y no se presentan como pase. Recursos y token sintéticos eliminados/verificados. |
| **PROD-191 — P1 — completada**<br>Salida de miembros y reasignación | Al revocar un usuario, administración necesita saber qué activos quedan sin responsable. Flujo: desactivar miembro → revisar impacto agregado → invalidar sesiones → revocar y reconciliar → reasignar o dejar `unassigned` → auditar. | Identidad SQLite, sesiones, Active store/API/UI, auditoría y docs. | Sesiones se invalidan antes de revocar; validación/asignación y baja usan un orden transaccional común; historial genérico no incluye ID, username ni target; reasignación exige miembro vigente, confirmación y CAS sin alterar revisión de autorización; fallo revierte membresía y permite retry seguro. | Un exmiembro puede seguir operando, una carrera reintroducirlo o activos críticos quedar con ownership engañoso. | PROD-177 y ciclo de miembros. | M | **2026-09-08:** preflight 1/1/0, baja, `Unassigned`, reasignación y carreras implementados. Backend específico 7/7, Active/identidad/auditoría 47/47 y completo backend+tools 1.597/1.597 sin red; frontend 325/325, TypeScript y build 286.371 B. La revisión visual inicial encontró una tarjeta obsoleta; se añadió refresh de contexto y regresión y se repitió desde cero a 320/768/1440 sin overflow. Instancia/datos sintéticos eliminados. La invocación CLI incompatible quedó registrada como no ejecutada, no como éxito. |
| **PROD-192 — P2 — completada**<br>UX con cartera grande | Usuarios deben conservar comprensión y accesibilidad con volumen, textos largos y todos los estados operativos. Flujo: centro → filtrar/paginar → abrir detalle → ejecutar/triage/reportar desde móvil/teclado. | Frontend Active, fixtures visuales, CSS y documentación QA. | Revisión reproducible 320/768/1440 con ≥2.000 registros simulados, locales largas, disabled/ready/degraded/error/partial; WCAG AA, foco y sin layout shift/overflow. | Una UI validada solo con una tarjeta no demuestra uso empresarial. | PROD-171 y PROD-188 completada. | M | **2026-09-08:** fixture determinista y runtime local con 2.005 activos. Ventana DOM 24→48→72→96, después exige filtro; búsqueda exacta recupera el 2.005. Se corrigió carrera de respuestas obsoletas, render ilimitado y toggle ambiguo (`Close details`+`aria-controls`); `aria-busy`, resumen parcial y foco de continuación/error quedan explícitos. Estados locales: 5 disabled, 1 unavailable, 1 degraded y 1 ready mediante health contract targetless; error de página conserva 24. Matriz 320/768/1440: client/scroll 305/305, 753/753, 1425/1425; sección 273/705/1.377; controles ≥44 px y geometría móvil estable 273/241/241/305 antes/después. Test escala+axe 1,59 s aislado/3,66 s en suite, límite 5 s. Dirigidas 37/37, frontend completo 339/339, build 281,5/322 KiB y consola limpia. Pestañas, puertos, contenedores, red y datos sintéticos eliminados; no hubo capacidad ni egress externo. |
| **PROD-193 — P2 — completada**<br>Índice durable para carteras Active grandes | Operación empresarial necesita que la latencia de la página no crezca linealmente por abrir y validar todos los JSON del propietario. Flujo: arrancar/migrar → validar índice owner-scoped → buscar/continuar → reparar o fallar cerrado → backup/restore. | `active_assets` store, índice SQLite o equivalente ya operativo, migración, backup/restore, readiness y pruebas de escala. | El listado no recorre ni parsea la cartera completa; índice y agregado fuente permanecen consistentes bajo alta/renovación/revocación/borrado/carrera/reinicio; corrupción no mezcla owners ni omite silenciosamente y tiene reparación documentada. Presupuesto verificable a 10.000 registros (p95 local objetivo <500 ms por página después de warm-up) con memoria acotada. | El contrato HTTP está acotado pero el coste O(N) actual causa latencia/CPU/IO y amplificación DoS con carteras mayores; un índice divergente falsearía autorizaciones. | PROD-188 completada; `PROD-196` usa esta base para eliminar el escaneo restante del resumen semanal. | L | **Evidencia 2026-09-08:** SQLite derivado `0600`, ≤256 MiB, reconstruible desde los JSON fuente y sincronizado bajo el lock común en todas las mutaciones. Query owner-scoped selecciona como máximo 101 IDs/JSON para una página de 100 y verifica digest/orden; filtros y cursor siguen parametrizados. Repara versión, DB, proceso/reinicio y temporales, mientras JSON inválido/permisos inseguros fallan cerrado y `/ready` lo incorpora. Backup valida correspondencia exacta y restore reconstruye. Fixture 10.005/dos owners con p95 exigido <500 ms y memoria <128 MiB. Una primera validación final quedó en colección (0 casos) por `SyntaxError` localizado y se repitió tras corregirlo; una pasada verde de ~215 s reveló reconstrucción eager y, tras hacerla lazy detrás de readiness/primera operación, la final completó backend 1.240/1.240 en ~50 s. Tools 439/439, frontend 348/348, build 282,8/322 KiB, compile/Compose/diff-check, sin Internet. |
| **PROD-194 — P2 — completada**<br>Retirada del listado Active no acotado | Clientes e integraciones deben usar un único contrato que no cargue toda la cartera ni coloque búsquedas sensibles en query strings. Flujo: inventariar consumidores → anunciar deprecación → migrar → limitar/retirar `GET /active/assets` → observar errores seguros. | API Active, clientes internos/externos documentados, OpenAPI, runbook, pruebas y telemetría sin target. | Ningún consumidor propio usa la ruta heredada; la compatibilidad tiene fecha/versión y límite seguro o devuelve retirada explícita; no admite búsqueda de target en URL; documentación ofrece migración a POST paginado y pruebas verifican respuesta acotada, roles y no fuga en logs. | El endpoint legado mantiene carga O(N), facilita respuestas enormes y puede registrar la identidad buscada en proxies/access logs. | PROD-188; coordinar compatibilidad antes de una ruptura de API. | S | **2026-09-08:** cero consumidores frontend; helper retirado y tests migrados al POST con cuerpo. GET autenticado devuelve tombstone `410` target-free con deprecación/OpenAPI, sunset, sucesor y no-store; no evalúa ni refleja query. Pasaron 4 dirigidas, backend 1.233/1.233, frontend 347/347, build 282,8/322 KiB y tools 439/439 sin red. Uvicorn real mostró solo las rutas fijas para alta, búsqueda exacta por cuerpo y tombstone, sin el canario; instancia y datos eliminados. La guía incluye migración/CSRF y el límite de logging en proxies previos. |
| **PROD-195 — P2 — completada**<br>Unicidad y exclusión mutua en el alta individual Active | Operación necesita una única identidad operativa por organización incluso si el alta individual coincide con un borrado en curso. Flujo: registrar o borrar → detectar identidad existente/oculta → rechazar duplicado o completar borrado → reintentar explícitamente. | Store/API de alta individual, journals de borrado, preflight, auditoría y migración de duplicados existentes. | Define si `(asset_type, canonical_value)` es clave única; detecta duplicados heredados sin eliminarlos; alta individual y masiva usan la misma admisión atómica e incluyen activos ocultos por borrado; errores no revelan otro owner/target. Carreras alta-alta y alta-borrado quedan cubiertas. | Duplicados pueden dividir baseline, autorización, triage y recurrencia; una alta concurrente podría reintroducir alcance que el usuario está eliminando. | PROD-178 y PROD-181 completadas; `PROD-193` absorberá el coste de indexar la identidad sin alterar esta semántica. | M | **Evidencia 2026-09-08:** unicidad `(organization_id, asset_type, canonical_value)` bajo el lock común para alta individual/lote y exclusión por journal de borrado owner-scoped. Las carreras alta-alta admiten exactamente una; alta-borrado queda bloqueada hasta recuperación. Duplicados heredados se conservan y solo producen contadores agregados target-free y un aviso accesible, nunca fusión/borrado automático. Pasaron 23 dirigidas, borrado 8/8, store 64/64, backend 1.237/1.237, tools 439/439, frontend 348/348, build 282,8/322 KiB, `compileall`, Compose y diff-check, sin red. |
| **PROD-196 — P2 — completada**<br>Resumen semanal Active acotado e indexado | Un operador con miles de activos necesita abrir la bandeja semanal sin que el backend materialice toda la cartera y todo el historial antes de aplicar límites. Flujo: abrir centro → cargar métricas/bandeja → entender cobertura parcial → navegar a la acción owner-scoped. | Índices privados de activos/jobs/verificaciones, stores, `active_operations`, endpoint summary, readiness, backup, UI y documentación. | Los conteos de activos son exactos y se calculan desde una proyección validada; como máximo 500 activos, 2.000 jobs y una última verificación por activo se materializan; el steady state no recorre todos los JSON. Orden/acciones son deterministas y target-free; fuente inválida falla cerrado y límites se declaran parciales. Fixture 10.000 activos/20.000 jobs exige p95 local <1 s y memoria acotada después de warm-up. | Un endpoint supuestamente acotado que primero lee todo amplifica IO/CPU y puede ocultar acciones si una proyección diverge. | PROD-182 y PROD-193 completadas; abre PROD-197 para corregir la selección solo por recencia. | L | **Evidencia 2026-09-08:** SQLite derivados `0600`, ≤256 MiB y JSON autoritativo proporcionan totales exactos de activos/jobs y ventanas 500/2.000/500 con validación owner/relación/digest. Sync/rebuild cubre mutación, borrado, otro proceso, corrupción y reinicio; fuente insegura falla cerrada. Readiness y backup/restore validan las tres proyecciones. Fixtures 10.005 activos, 20.000 jobs y 10.000 verificaciones de dos owners imponen p95 warm <1 s, pico <128 MiB y límites de lectura. UI distingue total exacto de detalle parcial. Pasaron backend 1.247/1.247 (69,91 s), tools 439/439, frontend 348/348+axe, build 282,8/322 KiB, compileall, tres Compose y diff-check sin red. El primer Compose acceptance no llegó a validación por una variable obligatoria ausente y se repitió correctamente. |
| **PROD-197 — P1 — completada**<br>Selección prioritaria completa para la bandeja Active | Una cartera mayor de 500 activos necesita que las autorizaciones vencidas y fallos de mayor urgencia no desaparezcan porque sus activos sean antiguos. Flujo: abrir resumen → proyectar señales operativas owner-scoped → seleccionar por urgencia → revisar cobertura/truncado → navegar a resolver. | Consultas de candidatos en índices Active/job/verificación, agregador, contrato API/UI, docs y escala. | Selecciona `immediate/high/scheduled/review` antes de recencia sin superar 500/2.000/500; señal antigua aparece, éxito nuevo limpia fallo, sobrecarga/owners son deterministas; cobertura parcial no inventa SLA/vulnerabilidad y solo muestra acciones admitibles. | Una bandeja rápida podía omitir la acción más urgente o enlazar una operación bloqueada. | PROD-196 completada; abre PROD-198 por el escaneo de admisión posterior. | L | **Evidencia 2026-09-08:** summary `2026-09-09.4`, `priority_then_recency`, supresión de retry/reverificación sin autorización vigente/capacidad actual y fixtures >500/dos owners. Recorrido local 503 activos mostró expiración y fallo de 20 días; 320/768/1440 sin overflow (305/305, 753/753, 1425/1425), controles ≥44 px y consola limpia. Backend 1.251/1.251 (64,31 s), frontend 348/348+axe, build 282,8/322 KiB, tools 439/439, tres Compose y diff-check sin red; fixture/servicios eliminados. |
| **PROD-198 — P1 — completada**<br>Admisión e idempotencia Active indexadas a escala | Al resolver una acción, un equipo con historial largo necesita admitir o repetir trabajo sin que cada clic abra todos los jobs. Flujo: ejecutar/reintentar → resolver replay owner-scoped → comprobar cupos global/organización/activo/capacidad → persistir atómicamente o devolver estado recuperable. | `ActiveJobIndex`, `JobStore`, admisión/retry Active, readiness, backup/restore, observabilidad y pruebas de carrera/escala. | En steady state el lookup de idempotencia carga como máximo el JSON coincidente y valida digest/owner/contrato; cupos globales de todo trabajo y cupos Active usan conteos indexados exactos bajo el mismo lock que el alta. No hay escaneo O(N) del histórico; corrupción/fuente insegura falla cerrada o se reconstruye. El índice no añade target, resultados crudos ni clave sin hash. Fixture 20k exige p95 <250 ms para replay/cupo warm y lecturas acotadas; carreras mantienen límites y mensajes sin actividad ajena. | La bandeja puede ser rápida pero su acción bloquea CPU/IO linealmente, facilitando amplificación DoS y timeouts que incentivan reintentos duplicados. | PROD-184 y PROD-196 completadas. | M | **Evidencia 2026-09-08:** esquema v3 proyecta todos los jobs con estado cerrado y solo, para Active, activo opaco y hash SHA-256 de idempotencia. Cuotas generales/Active son agregados exactos bajo el lock; replay owner-scoped carga un único JSON y valida digest. Fixture 20.000/dos owners: cupos sin lecturas, replay una lectura, p95 warm <250 ms y columnas sin target/autorización/raw. Pasaron 92/92 dirigidas y backend 1.252/1.252, `compileall` y diff-check, sin red. Frontend/tools permanecen sin cambios y con la evidencia verde de PROD-197. |
| **PROD-199 — P1 — completada**<br>Historial de análisis paginado e indexado | Una persona que abre Inspectra con años de actividad necesita ver trabajo reciente y continuar bajo demanda sin descargar ni parsear todo el historial. Flujo: portada/proyecto → página reciente owner-scoped → filtros cerrados → continuar → abrir detalle → volver conservando contexto. | Proyección privada de jobs, `JobStore`, `/jobs`, listados de proyecto, cliente API, `App`, estados accesibles, contratos, backup/readiness y pruebas de escala. | El API devuelve páginas acotadas con orden estable y cursor opaco ligado a propietario/filtros/cutoff; ninguna búsqueda sensible entra en URL o logs. En steady state carga como máximo la página solicitada y verifica owner/digest. Portada y proyecto muestran carga/vacío/error/continuación sin perder registros ni foco. Fixture 20.000/dos owners exige p95 warm <500 ms, memoria/respuesta acotadas, sin duplicados por inserción concurrente; endpoint legado se migra con contrato explícito. | El arranque anterior abría y devolvía todos los jobs, amplificando IO/memoria y pudiendo congelar la UI aunque la bandeja Active fuese rápida. Un cursor no ligado podría enumerar actividad ajena. | PROD-196 y PROD-198 completadas; abre PROD-200 para los consumidores especializados. | L | **Evidencia 2026-09-08:** esquema v4 añade solo proyecto opaco; POST general/proyecto con cursor HMAC ligado a owner/filtros/corte, exact total, orden estable y páginas 50/máximo 100. GET heredados quedan acotados/deprecados. Fixture 20.000 verifica p95 <500 ms, lecturas acotadas, aislamiento y manipulación. UI 50→51 conserva filas/foco y declara loaded/total; revisión 320/768/1440 sin overflow, controles ≥44 px y consola limpia tras corregir targets de 36 px. Pasaron 26 dirigidas, seguridad 10/10, backend 1.254/1.254, frontend 350/350+axe, build 284,8/322 KiB, compileall y diff-check sin red; servicios/fixture eliminados. |
| **PROD-200 — P1 — completada**<br>Selección profunda de análisis y líneas base paginadas | Un analista necesita abrir hallazgos, inventario, inteligencia y comparaciones de cualquier snapshot retenido, incluida una línea base anterior a los 50 análisis recientes, sin que la UI la declare ausente ni descargue todo el historial. Flujo: abrir área especializada → ver página reciente y cobertura → continuar bajo demanda → resolver selección/línea base por ID owner-scoped → conservar selección al refrescar → abrir resultado. | `ProjectComparisonPanel`, `ProjectFindingsPanel`, `ProjectComponentInventoryPanel`, `ProjectVulnerabilityIntelligencePanel`, cliente API y contratos owner/project-scoped. | Los cuatro consumidores dejan de depender del wrapper de primera página; ofrecen continuación acotada con total exacto y estados carga/error/fin, deduplican y conservan selección. La línea base guardada fuera de la página se resuelve directamente solo si pertenece al proyecto/owner; otra organización, proyecto o ID inválido responde como no encontrado. Ningún cursor ni entrada libre/sensible entra en URL o access log; los identificadores opacos siguen los contratos de recurso existentes. Fixtures ≥105 análisis prueban página profunda, línea base antigua, cursor y fallo de continuación sin perder opciones; axe y móvil validan los selectores. | Una baseline retenida podía parecer borrada, comparaciones elegir referencias equivocadas y analistas revisar resultados recientes creyendo que cubrían todo el historial. Cargar todas las páginas automáticamente reintroduciría el coste que PROD-199 eliminó. | PROD-199 completada; abre PROD-201 al revelar escaneos internos no visibles. | M | **Evidencia 2026-09-08:** cuatro consumidores paginados; resumen directo owner/project-scoped sin result; fixtures 52/105 con baseline 1, página 51+, deduplicación, error/retry y ausencia de egress automático. Pasaron 45 dirigidas frontend, API/auth dirigidas, backend 1.254/1.254, frontend 354/354+axe, build 285,0/322 KiB, compileall y diff-check. Recorrido local 50/51→52/52; se corrigió overflow interno de 11 px a 320. Matriz final 305/305, 753/753, 1425/1425, paneles contenidos, controles 44 px y consola limpia. Primer fixture fuera de retención descartado; final y servicios eliminados sin red. |
| **PROD-201 — P1 — completada**<br>Eliminar escaneos internos restantes del historial de jobs | Operación necesita que abrir detalle, comprobar readiness o admitir trabajo siga siendo predecible aunque existan años de jobs; paginar la UI no basta si helpers internos aún parsean todo el directorio. Flujo: readiness/admisión → proyecto/activo owner-scoped → resolver último o en curso → cargar solo candidatos acotados → devolver estado exacto o fallo cerrado. | `ActiveJobIndex`, `JobStore.has_active_project_job`, `has_global_admission_capacity`, `active_jobs_for_asset`, defaults de findings/inventory/intelligence, backup/readiness y pruebas de escala. | Existencia global/proyecto y último completado se resuelven por conteo/selección indexados; detalle de activo carga como máximo 500 JSON y valida owner/activo/digest. En steady state ninguna ruta indicada recorre `jobs_dir`; corrupción o divergencia falla cerrada/reconstruye según contrato. El esquema solo añade campos cerrados u opacos, nunca target, resultado, fuente, autorización ni clave cruda. Fixture 20.000/dos owners espía glob/lecturas, exige resultados exactos y presupuesto p95 documentado. | Un GET o readiness aparentemente inocuo puede amplificar CPU/IO O(N), bloquear el lock global y degradar ejecución/cancelación; un filtro incorrecto puede mezclar actividad entre organizaciones. | PROD-198, PROD-199 y PROD-200 completadas. | L | **Evidencia 2026-09-08:** esquema v4 sin nuevos datos sensibles; conteos/readiness cero lecturas JSON, último completado una y detalle Active máximo 500 con owner/relación/digest. Fixture 20.000/dos owners impone p95 warm <250 ms y resultados exactos. La validación descubrió y corrigió un deadlock por lock anidado (primera suite detenida tras 264) y un fixture legacy sin resincronización (segunda 1.253/1.254); la tercera pasó 1.254/1.254, además de dirigidas, `compileall` y diff-check sin red. Frontend sin cambios conserva 354/354+axe y build 285,0/322 KiB. |
| **PROD-202 — P1 — completada**<br>Recuperación de jobs y fuentes vivas indexada | Tras un reinicio, operación necesita revalidar o cerrar solamente el trabajo interrumpido sin que los años de historial retrasen readiness ni limpieza. Flujo: arrancar → obtener candidatos queued/running/cancelling → validar JSON y contrato → preservar/reencolar o cerrar → conservar únicamente fuentes todavía referenciadas. | `ActiveJobIndex`, `JobStore.recover_interrupted_jobs`, `list_queued_project_jobs`, `list_queued_active_jobs`, `active_file_ids`, startup dispatch, retención y pruebas de escala. | El índice devuelve IDs/digests mínimos de todos los candidatos in-flight y sus `file_id` opacos, con orden determinista; cada candidato consumido se carga y valida una vez. El steady state de recuperación no recorre jobs terminales; no proyecta rutas, targets, resultados ni autorización. Reinicio con 20.000 jobs, dos owners y candidatos mixtos preserva/cierra exactamente los debidos, mantiene cupos y exige p95 warm <500 ms; corrupción/divergencia falla cerrada sin borrar fuentes. | Un reinicio puede quedar bloqueado por IO lineal, retrasar la recuperación o eliminar una fuente aún viva; confiar solo en el índice podría reencolar trabajo manipulado. | PROD-201 completada. | M | **Evidencia 2026-09-08:** esquema v5 selecciona y valida únicamente candidatos in-flight; fuentes vivas se derivan de esos JSON. Marcador de directorio persistido permite adopción en reinicio solo con SQLite `0600`, esquema/integridad/estado coincidentes; si no, reconstruye o falla cerrado. Fixture 20.000/dos owners reinicia el store, prohíbe glob, carga 4 candidatos por operación y exige p95 <500 ms. Pasaron 6 de índice, 32 de backup/retención/startup, 9 de lifecycle y backend 1.254/1.254; helper posterior cubierto por carrera, `compileall` y diff-check, sin red. |
| **PROD-203 — P1 — completada**<br>Borrado integral Active indexado por activo | Una organización con años de ejecuciones necesita previsualizar y borrar un activo completo sin recorrer el historial global ni arriesgar residuos o cruces de tenant. Flujo: preview owner-scoped → enumerar todas las ejecuciones del activo → bloquear si hay trabajo vivo → journal → borrar agregado → verificar ausencia → recibo redactado. | `ActiveJobIndex`, `JobStore`, `ActiveAssetDeletionService`, backup/readiness, auditoría y pruebas de escala/recuperación. | Una consulta exhaustiva parametrizada por owner+asset devuelve todos los IDs/digests en orden estable y valida cada JSON, sin el límite de 500 de UI. Preview y comprobación de huérfanos no hacen `glob` global; otro owner/activo nunca entra. Fixture 20.000 global/1.001 del activo demuestra lecturas proporcionales al agregado, p95 warm <500 ms antes de borrar, bloqueo de in-flight, recuperación de journal y cero residuos. El índice no incorpora target, notas, evidencia ni autorización. | El escaneo O(N) bloquea el lock y facilita DoS; truncar a 500 dejaría resultados privados; un filtro owner incorrecto borraría datos ajenos. | PROD-178, PROD-193 y PROD-202 completadas. | M | **Evidencia 2026-09-08:** consulta exhaustiva por activo con owner/digest, sin reutilizar el límite UI; fixture 20.000/1.000 prohíbe glob y exige p95 <500 ms. Colisión cross-owner falla antes del journal. Recuperación por fases y cero residuos permanecen cubiertos. Pasaron 15/15 dirigidas y backend 1.255/1.255, `compileall` y diff-check, sin red. |
| **PROD-204 — P1 — completada**<br>Historial de verificaciones Active indexado por activo | Operación necesita comprobar, renovar y borrar controles de un activo sin abrir todas las verificaciones de la organización, incluso tras reiniciar. Flujo: abrir/crear challenge → recuperar historial del activo → aplicar rate limit/supersession → preflight/borrado → verificar ausencia. | `ActiveVerificationIndex`, `ActiveAssetVerificationStore`, borrado Active, readiness/backup y pruebas de escala. | Consulta exhaustiva owner+asset devuelve IDs/digests en orden estable y valida cada JSON; latest conserva su ventana. Un proceso nuevo adopta el SQLite durable solo si permisos, esquema, integridad y marcador fuente coinciden; mismatch reconstruye y corrupción falla cerrada. Fixture 10.000 verificaciones/dos owners y 101 del activo prohíbe escaneo de la organización, exige lecturas proporcionales y p95 warm <500 ms; rate limit, supersession, borrado y restore conservan semántica. | El escaneo owner-wide al crear un challenge amplifica coste y puede bloquear el lock; una proyección stale podría saltarse rate limit o dejar desafíos privados. | PROD-170, PROD-193 y PROD-203 completadas. | M | **Evidencia 2026-09-08:** índice v3 owner/activo exhaustivo y digest-validado para rate-limit, supersession y borrado; marcador fuente permite adopción segura tras reinicio. Fixture 10.000/dos owners prohíbe glob, carga 101 registros y exige p95 <500 ms. Pasaron 33/33 dirigidas y backend 1.255/1.255, `compileall` y diff-check, sin red. |
| **PROD-205 — P1 — completada**<br>Historial Active profundo y controles con cobertura exacta | Un operador necesita revisar cualquier ejecución retenida, conservar una baseline antigua, exportar evidencia honesta y revocar todo trabajo vivo sin que una ventana visual de 500 altere la semántica. Flujo: activo → página reciente → continuar → abrir ejecución/baseline → postura/comparación → exportar → revocar/cancelar exhaustivamente. | `ActiveJobIndex`, `JobStore`, rutas Active, postura/baseline/report/evidence bundle, frontend Active, contratos y pruebas de escala/axe. | API paginada de ejecuciones con 50 por defecto/100 máximo, total exacto y cursor HMAC ligado a owner+activo+corte; selección directa devuelve resumen solo si pertenece al owner/activo. UI conserva filas/foco y muestra loading/vacío/error/fin. Baseline antigua se resuelve directamente; postura/report/evidence declaran universo y truncado exactos. Revocación selecciona todos los in-flight del activo por índice, nunca la página visible. Fixtures 20.000/1.001, inserción concurrente, cursor manipulado, dos owners, baseline >500, export 100 y axe/matriz móvil. | Una ventana presentada como total produce comparaciones falsas; una revocación parcial deja egress autorizado en ejecución; paginar con query sensible o cursor transferible facilita fuga/enumeración. | PROD-178, PROD-186, PROD-199 y PROD-204 completadas. | L | **2026-09-08:** cursor HMAC con corte inmutable y total exacto; selección directa mínima; postura/baseline profunda; informe, bundle y revocación exhaustivos. Fixtures 20.000/1.001, 505 terminales y 501 vivos. Backend 1.257/1.257, frontend 355/355+axe, CSS 19/19, build 285,2/322 KiB, `compileall` y diff-check sin red. Revisión local 50→52 y vacío a 320/768/1440, foco estable, controles 44 px, consola limpia y cero overflow final. Se corrigieron foco final, total concurrente y overflow móvil; temporales eliminados. |
| **PROD-206 — P1 — completada**<br>Retención terminal Active indexada y reanudable por lotes | Un operador necesita que el arranque y la limpieza semanal mantengan latencia y memoria predecibles aunque exista un historial grande. Flujo: arranque o mantenimiento → seleccionar lote vencido → validar registro autoritativo → ejecutar callbacks/borrado → reanudar o reintentar hasta terminar. | `ActiveJobIndex`, `JobStore.purge_expired_terminal`, arranque/retención, callbacks de limpieza, documentación y pruebas de escala. | La consulta indexada selecciona solo `completed/failed/cancelled` con `updated_at` anterior al corte, propietario opcional, orden estable y lote fijo. Cada JSON se valida por estado, fecha, owner y digest antes del callback/borrado; un registro vivo, reciente o modificado concurrentemente nunca se elimina. El fallo de callback conserva el candidato para retry; cada borrado sincroniza índice y marcador. Fixture 20.000/dos owners prohíbe `glob` en estado estable, mide lecturas proporcionales, reinicia el store y cubre inserción/cambio concurrente. | El escaneo y parseo global bajo lock puede bloquear arranque, admisión y cancelación; una selección stale puede borrar evidencia reciente o perder limpieza pendiente. | PROD-198, PROD-202 y PROD-205 completadas. | L | **2026-09-08:** schema v6 con índices parciales global/owner, lote 100 y máximo 500; validación owner/estado/fecha/digest antes de callback y digest idéntico antes de borrar. Callback fallido reintentable; carrera a `running`, vivo antiguo, inserción nueva y vencido extranjero preservados. Fixture reiniciado 20.000/dos owners, 137 elegibles, lotes 100+37, sin glob, p95 <500 ms y pico <32 MiB. Índice+retención 11/11, backend 1.258/1.258, `compileall` y diff-check sin red; frontend conserva 355/355+axe y build 285,2/322 KiB. |
| **PROD-207 — P1 — completada**<br>Marcación de referencias de fuente indexada y privada | Una fuente que expira o se elimina debe marcar solo los análisis que realmente la referencian, sin bloquear el trabajo Active al recorrer todo el historial ni copiar IDs privados al índice. Flujo: expiración/eliminación autorizada → resolver jobs relacionados → validar owner y referencia → marcar `source_file_deleted_at` → reanudar/reintentar. | `ActiveJobIndex`, `JobStore.mark_file_deleted/mark_files_deleted`, retención/Files, borrado de fuente, documentación y pruebas de escala. | El índice almacena solo un digest con separación de dominio de la referencia de fuente, nunca `file_id` en claro. La consulta acepta un conjunto acotado, owner opcional solo en mantenimiento interno, devuelve lotes estables y valida JSON por owner, referencia y digest. La marcación vuelve a validar antes de guardar, no toca otros owners ni jobs ya marcados, y una carrera de cambio de referencia/estado falla cerrada. Fixture 20.000/dos owners prohíbe glob, demuestra lecturas proporcionales, reinicio, lote/reintento y ausencia de IDs crudos en SQLite. | El escaneo global bajo lock puede bloquear admisión/cancelación; una relación stale puede marcar el análisis equivocado o filtrar la existencia de una fuente entre organizaciones. | PROD-202 y PROD-206 completadas. | L | **2026-09-08:** schema v7 con digest SHA-256 separado por dominio, bit `source_deleted`, máximo 500 referencias y lote 100. Fixture reiniciado 20.000/dos owners marcó 137 como 100+37, dos lecturas/candidato, sin glob, sin IDs crudos en SQLite y sin tocar el owner ajeno. Interrupción 1/3 reanudó exactamente 2. Dirigidas 35/35, backend 1.258/1.258, `compileall` y diff-check sin red; frontend conserva 355/355+axe y build 285,2/322 KiB. |
| **PROD-208 — P1 — completada**<br>Relaciones de baseline y fuente de proyectos indexadas | Retención y borrado deben limpiar baselines y snapshots relacionados sin recorrer todos los proyectos por cada resultado o fuente, manteniendo aislamiento y privacidad. Flujo: resultado/fuente vencido → resolver proyectos relacionados → validar owner/relación/digest → limpiar baseline o marcar snapshot → reanudar tras interrupción. | Nuevo índice privado de relaciones de `ProjectStore`, guardado/borrado/restore de proyectos, retención y pruebas de escala. | El índice durable proyecta project ID, owner, digest de registro y digests separados por dominio de baseline/fuentes; nunca nombres, SHA de contenido ni IDs de fuente/análisis crudos. Consultas acotadas y owner-scoped devuelven lotes estables; cada JSON se valida antes de mutar. `clear_baselines_for_analysis_ids` y `mark_source_file_deleted` no hacen glob en estado estable, son idempotentes/reanudables y preservan otro owner. Fixture multi-owner a escala cubre reinicio, corrupción/mismatch, interrupción y ausencia de referencias crudas. | Escanear proyectos N veces amplifica retención bajo el lock; una proyección stale puede limpiar políticas o snapshots ajenos. | PROD-193, PROD-206 y PROD-207 completadas. | L | **2026-09-08:** schema v1 con relaciones digestadas, marcador de directorio y adopción segura; lotes 100 owner-scoped y JSON autoritativo bajo lock. Fixture 5.000/dos owners procesó 137 como 100+37, sin glob ni referencias/nombres crudos, p95 <500 ms, pico <32 MiB y reanudación 1+2. Backup rechazó columnas job y relación project manipuladas. Dirigidas 29/29; backend 1.259/1.259 con marcador/exit 0, `compileall` y diff-check sin red. |
| **PROD-209 — P1 — completada**<br>Retención de fuentes indexada y reanudable | Operación necesita que el arranque y la limpieza semanal identifiquen fuentes vencidas sin recorrer todas las subidas ni retener una lista ilimitada en memoria. Flujo: owner/corte → excluir fuentes de jobs vivos → seleccionar lote → marcar derivados → revalidar metadato/bytes → borrar → reanudar. | Nuevo índice privado de `FileStore`, `purge_expired`, retención startup/manual, backup/restore, docs y pruebas de escala. | El índice proyecta únicamente file ID opaco, owner, fecha, nombre almacenado cerrado y digest de metadato necesarios para borrar; nunca nombre original, SHA de contenido o bytes. Consulta owner/cutoff en lotes de 100, excluye referencias vivas acotadas, valida JSON y path seguro antes/después del callback. Fallo conserva fuente; carrera/protección reciente evita borrado. Fixture multi-owner ≥10.000 prohíbe glob estable, mide p95/memoria, reinicio, interrupción y ausencia de metadatos sensibles en SQLite. | El escaneo O(N) retrasa readiness y mantiene el lock; una selección stale puede borrar una fuente viva o ajena, y acumular candidatos permite presión de memoria. | PROD-206, PROD-207 y PROD-208 completadas. | L | **Evidencia 2026-09-08:** SQLite schema v1 sincronizado en save/delete y validado por backup. Fixture reiniciado de 10.000/dos owners, 137 vencidas, conservó una protección estática, otra dinámica y la extranjera; eliminó 135 con lotes 100+36 sin glob. Protección final, callbacks, revalidación y borrado ocurren bajo un lock compartido con helpers lock-owned; fallo conserva la fuente. p95 <500 ms, pico <32 MiB y canarios de nombre/SHA ausentes. Pasaron 32/32 dirigidas, backend 1.260/1.260 con exit 0, compileall y diff-check, sin Internet. |
| **PROD-210 — P1 — completada**<br>Cola de recurrencia Active indexada y despacho acotado | Un operador necesita que cada tick semanal encuentre a tiempo las políticas vencidas y que borrar un activo no dependa del tamaño total de la organización. Flujo: tick → seleccionar hasta 16 candidatos globales → validar política/ventana → reclamar/admitir → registrar resultado; activo → listar/contar/borrar su agregado exacto. | `ActiveRecurrenceStore`, nuevo índice privado durable, loop de recurrencia, borrado Active, readiness, backup/restore, documentación y pruebas de escala. | El índice solo proyecta organization/asset/schedule IDs opacos, status cerrado, `next_run_at`, `next_retry_at` y digest del registro; excluye target, referencias/digests de autorización, verification ID, actor, token y contenido. La consulta global devuelve como máximo 16 candidatos elegibles en orden estable y cada JSON se valida por owner, estado, fechas, ventana y digest antes del dispatch. List/count/delete por owner+asset son exactos sin escaneo de organización. Create, pause, resume, suspend, failure, dispatch y delete sincronizan índice/marcador; adopción, corrupción y backup fallan cerrados o reconstruyen solo desde JSON. Fixture ≥10.000/two owners prohíbe scans estables, cubre reinicio, CAS/doble tick, ventana, interrupción, p95 <500 ms y memoria <32 MiB. | El tick O(N) mantiene el lock y puede perder una ventana autorizada o retrasar cancelación; una proyección divergente podría duplicar despachos, omitir trabajo o cruzar propietarios. Riesgo de privacidad si el índice copiara material de autorización o targets. | PROD-172, PROD-190, PROD-198 y PROD-209 completadas. | L | **Evidencia 2026-09-09:** schema v1 exacto, digest-validado y sincronizado en todas las mutaciones. Fixture reiniciado de 10.000 políticas/20 owners, 16 due y agregado 101; prohíbe recorrido de organización, exige p95 <500 ms/pico <32 MiB, conserva aislamiento y borra exactamente el agregado. Canarios de autorización/verificación ausentes. Barrera de dos ticks: un job idempotente y una transición CAS. Backup detecta manipulación y reconstruye desde JSON. Dirigidas 38/38, backend 1.262/1.262 exit 0, compileall y diff-check sin Internet. |
| **PROD-211 — P1 — completada**<br>Informe semanal reproducible de la cartera Active | Operadores y responsables de seguridad necesitan preparar una revisión semanal sin abrir activo por activo ni confundir una ventana parcial con la postura completa. Flujo: abrir centro → elegir periodo cerrado 7/30 días → revisar preflight/sensibilidad/cobertura → generar → descargar Markdown o JSON → verificar hechos en el activo enlazado. | Nuevo read model/reporting Active owner-scoped, API, `ActiveOperationsCenter`, cliente/tipos frontend, documentación y pruebas visuales/E2E sintéticas. | Una misma instantánea/cutoff produce Markdown y JSON coherentes con contrato/version/digest; resume totales, acciones priorizadas, autorizaciones vencidas/próximas, últimas ejecuciones fallidas/degradadas, cambios comparables materiales y recurrencias pausadas/suspendidas/con reintento. Incluye denominadores, ventanas y truncado explícitos; máximo 500 activos/2.000 jobs/100 acciones y tamaño ≤1 MiB. Preflight confirma que el informe contiene targets autorizados; nunca incluye notas, authorization reference/digest, challenge/token, actor/usuario, rutas, raw output o respuesta de runner. Owner isolation y roles; estados loading/vacío/parcial/error, descarga accesible y 320/768/1440. Fixtures de dos organizaciones, cartera >500, cambio concurrente y formatos coherentes; suite sin red. | Sin un corte compartible, la revisión semanal es manual e inconsistente. Un informe cruzado o excesivo puede filtrar superficie; ocultar truncado puede producir falsas conclusiones; dos formatos divergentes rompen auditoría. | PROD-182, PROD-189, PROD-205 y PROD-210 completadas. | L | **Evidencia 2026-09-09:** contrato `2026-09-09.1`, preflight target-free y exportación confirmada Markdown/JSON con el mismo digest, corte y límites 500 activos/2.000 jobs/100 acciones/100 recurrencias/1 MiB. Solo maintainer/admin exporta; reader obtiene preflight sin capacidad de descarga. Se excluyen notas, referencias/digests de autorización, retos, identidades, rutas, resultados crudos y respuestas de runner; auditoría conserva únicamente formato y periodo. La revisión reproducible a 320/768/1440 corrigió exposición CORS del digest, wrap del consentimiento y errores de red; quedó sin overflow, con controles ≥44 px, consola limpia y estados ready/parcial/vacío/error. Pasaron 1.704/1.704 pruebas backend (253,98 s; 224.120 KiB), 361/361 frontend con axe, build 286,2/322 KiB, dirigidas 14/14, `compileall`, Compose y diff-check, todo sin Internet. Fixture y servicios locales eliminados; puertos cerrados. |
| **PROD-212 — P2 — completada**<br>Recibo privado y target-free de revisión semanal Active | Un equipo que usa el informe semanal necesita dejar constancia de que una instantánea concreta se revisó y si requiere seguimiento, sin conservar otra copia de targets ni convertir la revisión en un SLA. Flujo: preflight/export autorizado → confirmar revisión del digest vigente → elegir resultado cerrado `reviewed`/`follow_up_required` → consultar historial acotado → verificar acciones en el activo. | Nuevo store privado de recibos owner-scoped, API/roles/CSRF, panel semanal, auditoría, retención/backup y documentación. | El recibo liga organización, contrato, periodo, cutoff y un HMAC separado por dominio del digest, nunca el digest crudo, target, notas, comentarios libres, actor visible, resultado de runner ni contenido del informe. Solo maintainer/admin puede crear; reader ve una historia acotada sin identidades. No resuelve, descarta ni re-prioriza acciones automáticamente. Máximo 52 recibos retenidos por organización, mutación idempotente y estado concurrente obsoleto rechazado. Pruebas deterministas cubren dos organizaciones, roles, replay/carrera, retención/restore, canarios, loading/vacío/error, axe y 320/768/1440. | Un simple evento de descarga no demuestra revisión; guardar el informe o su digest crudo como comprobante duplicaría superficie sensible, y un estado que cierre acciones daría una falsa señal de remediación. | PROD-211 completada y política de retención/auditoría existentes. | M | **2026-09-10:** contrato `2026-09-10.1`, store privado owner-scoped, HMAC separado por dominio y revisión CAS. Mantiene 52 recibos/400 días y excluye digest crudo, target, notas, actor, resultados y contenido del informe; solo maintainer/admin crea y reader consulta/verifica sin mutar lifecycle. Retención, backup/restore y auditoría mínima están integrados y fallan cerrados ante clave, permisos, symlink, integridad o storage inválidos. Pruebas deterministas cubren dos organizaciones, roles, replay/carrera, estado stale, retención y canarios. El recorrido local sintético creó dos recibos, verificó tras reinicio y revisó loading/vacío/error a 320/768/1440; corrigió la cuadrícula móvil, sin overflow ni consola. Se detectó y corrigió un deadlock por lock anidado mediante reentrada acotada al mismo hilo/path, y se mantuvieron exhaustivas la allowlist reader y las clases de retención. Validación offline: 256/256 Active dirigidas, 868/868 `test_backend.py`, colección integral backend+tools de 2.051 pruebas con salida 0 (316,32 s; 30.208 KiB RSS Docker), 419/419 frontend+axe, build 302,5/322 KiB, `compileall`, tres Compose y diff-check. Temporales eliminados; sin red, proyecto real, push, PR ni despliegue. |
| **PROD-213 — P2 — completada**<br>Canal de incorporación atestado | Operación necesita distinguir archivo manual, Git/CLI, CI y SBOM sin inferirlo de un commit. Flujo: admisión por ruta servidor-conocida → persistir canal inmutable → cartera/historial/informe → migración conservadora de registros antiguos. | `ProjectSourceSnapshot`, journals de admisión, rutas archive/CI/SBOM, CLI/API, cartera, reporting, backup y docs. | El servidor fija un enum de canal según el endpoint y credencial efectiva; ninguna entrada libre puede fingir CI. Cada snapshot nuevo lo conserva append-only y lo expone sin nombre/ruta. Registros anteriores quedan `unknown_git_or_ci`, nunca se reetiquetan por heurística. Replay, recuperación y restore preservan el canal. Matriz de rutas, dos owners y registros legacy. | Un canal manipulable falsea trazabilidad; una migración inferida atribuye evidencia al pipeline incorrecto. | PROD-134 y PROD-145 completadas. | M | **2026-09-09:** contratos de metadatos/admisión versionados; rutas servidor-conocidas fijan `archive_upload`, `git_cli`, `ci` o `sbom`; legacy con commit queda `unknown_git_or_ci`. Replay, recovery, restore, cartera, historial, reporting y retención lo preservan sin datos libres. Backend dirigido 15/15 y suite backend+tools 1.886/1.886; CLI 34/34 por grupos offline; frontend 396/396, TypeScript/build 293,7/322 KiB, `compileall`, Compose y diff-check. Revisión visual sintética escritorio/320 sin overflow ni consola; temporales y servicios eliminados. Sin red ni proyectos reales. |
| **PROD-214 — P2 — completada**<br>Índice duradero de cartera de proyectos | Organizaciones por encima del límite actual necesitan abrir y paginar proyectos sin que App ni `GET /projects` recorran todos los JSON. Flujo: save/delete/restore → índice privado → página owner-scoped → consumidores heredados migrados → reconstrucción segura. | `ProjectReferenceIndex`, `ProjectStore`, API, App/onboarding, backup/readiness y pruebas de escala. | Índice no conserva nombres privados, filenames, hallazgos ni texto; la página revalida cada JSON por owner/digest. `POST /projects/search` usa total exacto, 50 por defecto/100 máximo y cursor HMAC canónico ligado a owner+revisión; `GET /projects` queda acotado/deprecado. App conserva páginas y resuelve deep links directamente. Fixture 20.000/dos owners, corrupción/reinicio/cambio concurrente y presupuesto. Los agregados permanecen limitados a 5.000 hasta una proyección separada. | El listado heredado duplicaba IO y una proyección sensible ampliaría exposición; retirar el límite de agregados sin materialización agotaría CPU/IO. | PROD-145 y PROD-208 completadas; PROD-241 conserva la brecha de prioridad >5.000. | L | **2026-09-09:** índice SQLite v2 reconstruible, eliminación visible antes del journal y backup con esquema exacto. Fixture 18.000/2.000: 20 páginas warm sin glob, p95 <0,5 s y pico <32 MiB; corrupción, alias Base64URL, cursor alterado/stale y owner cruzado fallan cerrados. Backend dirigido 43/43 y completo 1.889/1.889 offline; frontend 399/399, TypeScript/build 295,1/322 KiB; `compileall`, Compose y diff-check. Revisión visual local 50→51, deep link fuera de página, fragmento inválido local, móvil sin overflow global y consola limpia. Temporales/servicios eliminados; sin red. |
| **PROD-215 — P2 — completada**<br>Responsable estable de proyecto | Equipos necesitan un accountable owner aunque no haya hallazgos asignados, sin confundirlo con responsables de remediaciones concretas. Flujo: admin/maintainer asigna miembro activo → cartera/centro/informe → baja del miembro → reasignación explícita. | Proyecto/identidad de equipo, API/roles/CSRF, auditoría, cartera, remediación, informes y UI. | Asignación append-only o versionada, solo miembro activo de la organización; reader no muta. La baja produce `unassigned_attention`, no reasignación silenciosa. Cartera muestra responsable de proyecto y responsables de hallazgos por separado. Dos owners, baja/reinicio/restore, axe y redacción de logs. | La derivación actual desde hallazgos deja proyectos sin dueño visible y una asignación cruzada filtra identidad o responsabilidad. | PROD-012, PROD-145 y contrato de PROD-146. | M | **2026-09-09:** revisiones monotónicas/CAS, miembro activo tenant-scoped, roles/CSRF y estado de atención tras baja. Índice v3 conserva solo HMAC separado; auditoría no guarda identidad. Cartera, remediación, informes y UI distinguen owner/assignee; reinicio y backup/restore cubiertos. La revisión visual encontró y corrigió CORS cerrado sin `PUT`; desktop/móvil y persistencia real pasaron. Backend+tools 1.891/1.891 offline, frontend 401/401, axe, TypeScript/Vite 295,7/322 KiB, compileall, Compose y diff-check; temporales eliminados y sin red pública. |
| **PROD-216 — P2 — completada**<br>Diario recuperable de lotes de remediación | Un equipo necesita saber que una acción sobre varios proyectos es toda-o-nada incluso si el proceso cae. Flujo: preflight exacto → prepare durable → decisiones append-only → commit → consulta/replay/recuperación. | Lifecycle, journal privado, readiness/recovery, backup, auditoría y pruebas de interrupción. | Idempotency key ligada a owner/grupo/revisión/selección; journal sin comentarios ni nombres; prepare/commit y recuperación determinista; un replay devuelve el resultado original y nunca duplica. Kill/restart simulado en cada frontera, dos owners, corrupción y restore. | La reversión en proceso actual no cubre una muerte abrupta entre renames; puede dejar triage parcial o repetido. | PROD-146 y patrón de recuperación existente. | M | **2026-09-09:** contrato API `2026-09-09.2`, clave estable por reintento y binding opaco a organización/actor/payload. Staging, journal y recibo usan escritura+rename+`fsync` de archivo/directorio; el recibo es la frontera única de visibilidad. Startup recupera prepare incompleto y readiness falla cerrado ante diario pendiente/corrupto. Replay exacto devuelve las decisiones originales sin duplicar ni repetir auditoría; otro payload/tenant falla. Journals/recibos excluyen motivo, comentario y username. Backup rechaza operaciones pendientes, valida digest/owner/conjunto de recibos comprometidos y restore preserva replay. Interrupciones simuladas en staged/prepared/cada rename/commit/cleanup, corrupción y dos organizaciones pasaron; suite Python offline 1.902/1.902, frontend 58 archivos/402 pruebas, build 295,7/322 KiB, compileall, Compose base/privado y diff-check. La revisión detectó y corrigió que el helper previo hacía rename sin durabilidad `fsync`. Sin red, push, PR ni despliegue; bloqueos intactos. |
| **PROD-217 — P2 — completada**<br>Vistas guardadas privadas de remediación | Desarrollador y seguridad necesitan volver a su cola habitual sin reconstruir filtros. Flujo: configurar filtros cerrados → nombrar/guardar → abrir por defecto → compartir solo dentro del tenant si el rol lo permite → borrar. | Store de preferencias, API/roles/CSRF, panel y auditoría. | Contrato versionado, máximo 20 vistas/usuario y nombre normalizado; no persiste cursores ni términos libres que contengan rutas, nombres de proyecto o identificadores de hallazgo. Privada por defecto; compartir exige maintainer/admin. Estados loading/vacío/error, teclado, axe y móvil. | Persistir consultas o compartirlas incorrectamente filtra la existencia y taxonomía de proyectos. | PROD-146 y modelo de identidad del equipo. | M | **2026-09-09:** store privado owner/tenant-scoped, contrato cerrado sin búsqueda/cursor/IDs, máximo 20 vistas por usuario, compartición solo maintainer/admin, default, borrado y purga por baja. API CSRF/no-store y auditoría redactada; UI con estados, retry y filtros estables. Reinicio, backup/restore, corrupción, límites, roles, dos organizaciones y modo `0600` cubiertos. Pasaron 1.908/1.908 Python offline, 403/403 frontend, axe, TypeScript/Vite 296,3/322 KiB, `compileall`, Compose y diff-check. Revisión visual real 1440/768/320 corrigió permisos y overflow; persistió tras recarga sin consola ni residuos. |
| **PROD-218 — P2 — completada**<br>Planes de remediación duraderos a escala | Carteras por encima del límite síncrono necesitan un informe coherente sin mantener la petición abierta. Flujo: preflight → job owner-scoped con cutoff → progreso/cancelación → artefacto digestado → descarga/expiración/limpieza. | Orquestación, índice de proyectos, reporting, retención, UI y observabilidad. | Límite explícito y paginación por índice; una misma instantánea genera JSON/CSV coherentes y declara truncado. Artefacto ≤ tamaño fijado, sin rutas/comentarios/actores, descarga autorizada, TTL y limpieza. Fixture ≥20.000, reinicio/cancelación/carrera, memoria/latencia y dos owners. | Exportar todo sin índice puede agotar recursos; reconsultar durante el render mezcla estados y produce un plan no auditable. | PROD-146 y PROD-214. | L | **2026-09-09:** job privado owner-scoped con cutoff/revisión coherentes, paginación indexada, idempotencia concurrente, dos jobs en vuelo por organización y cancelación/reintento/recuperación. Artefactos JSON/CSV ≤16 MiB, digestados, `0600` bajo directorios `0700`, con `fsync`, TTL siete días y limpieza; backup/restore, retención `2026-09-10.2`, corrupción, symlink y dos owners fallan cerrados. Fixture 20.000: 200 páginas, <5 s, <32 MiB; 16 creaciones concurrentes dieron un job. Recorrido local sintético y revisión 1440/768/320 completaron creación, progreso, persistencia y descarga sin red ni proyecto real; corrigió overflow móvil y terminó sin consola. Validación: 1.918 pruebas Python/68 archivos por grupos frescos con 2 GiB, 405/405 frontend/58 archivos, axe, build 298,0/322 KiB, compileall, Compose y diff-check. El intento monolítico previo agotó exactamente 512 MiB al 86% y reveló una allowlist de rutas desactualizada, corregida antes de repetir sin omisiones. Recursos efímeros eliminados. |
| **PROD-219 — P2 — completada**<br>Índice materializado de tendencias | Carteras con más de 10.000 análisis retenidos necesitan series sin cargar resultados completos en cada petición. Flujo: revisión de jobs/PVI/lifecycle → hechos privados → consulta temporal owner-scoped → muestra autoritativa → rebuild seguro. | `project_risk_trend_index.py`, tendencias, modelos/API, backup/readiness, UI e informes. | Schema v1 cerrado; máximo 250.000 análisis/owner y 256 MiB; no conserva nombres, rutas, texto, componente, evidencia, recomendaciones, comentarios, actores ni cuerpos externos. Consulta SQL y muestra determinista de hasta ocho jobs; proceso nuevo, revisión fuente, corrupción y restore reconstruyen desde autoridad. Dos owners y corpus 100.000 con presupuestos verificables. | Un agregado stale o cross-tenant falsea métricas; recalcular todo bajo demanda agota IO/memoria. | PROD-147 y PROD-214. | L | **2026-09-10:** contrato `2026-09-10.1`; hechos mínimos digestados, rebuild por revisión y validación estricta de backup/readiness. Corpus 100.000/dos owners: rebuild <60 s, pico Python <64 MiB, consulta caliente <1 s y <=8 lecturas autoritativas. Cambios PVI/lifecycle, owners alternados y corrupción cubiertos. Suite completa: 68 archivos/1.922 pruebas Python por grupos, 58/405 frontend, regresiones finales de schema, `compileall`, build 298,0/322 KiB, Compose base/privado y diff-check. UI/report consumen el mismo contrato; sin nueva superficie visual, red, proveedor ni proyecto real. |
| **PROD-220 — P1 — completada**<br>Atestaciones públicas por organización | Empresas multi-tenant necesitan aprobar identidades públicas sin que una allowlist global habilite un homónimo privado de otra organización. Flujo: proponer identidad exacta → revisión admin → aprobar con caducidad → consultar → revocar/revalidar. | Team identity, policy egress, store cifrable, API/roles/CSRF, auditoría, UI, backup/retención y docs. | Ecosistema+nombre exactos, máximo/TTL y revisión versionada; maintainer propone y admin aprueba; revalidación tenant-scoped antes de cada lote; revocación inmediata; ninguna identidad en logs/export global. Dos tenants, carrera, expiración, restart/restore y canarios. | Una atestación global puede exponer nombre/version de un paquete privado homónimo; un flujo libre puede convertirse en selector SSRF o inventario de terceros. | PROD-012, PROD-026 y verticales multi-ecosistema. | L | **2026-09-09:** contrato `2026-09-09.1` y esquema team identity v2. Un maintainer/admin propone ecosistema+nombre canónico; solo admin aprueba; 1–90 días, 200 identidades retenidas por tenant, revisiones monotónicas, expiración y revocación inmediata. El overlay tenant solo estrecha la política de operador y se relee justo antes de cada lote OSV; falta, cruce o revocación abre cero sockets y queda `organization_identity_not_attested`. API/CSRF/UI responsive cubren carga, vacío, error y roles; auditoría guarda solo ID opaco/ecosistema/revisión, con `private,no-store`. Reinicio y backup/restore conservan el registro. Validación offline: 152 pruebas dirigidas de store/egress/PVI/backup, 2 recorridos API, suite Python completa 1.848/1.848, 57 archivos/387 pruebas frontend, axe dirigido, TypeScript/Vite y bundle 291,9/322 KiB, compileall, Compose base/privado y diff-check. Sin proveedor real, push, PR ni despliegue; SEC-012 intacta. |
| **PROD-221 — P2 — completada**<br>Grafo Go aportado por CI | Equipos Go necesitan alcance transitivo reproducible sin que Inspectra ejecute el gestor. Flujo: CI autorizado genera artefacto → CLI lo liga a commit/snapshot → ingestión acotada → grafo/cobertura → comparación/informe. | CLI/CI, contrato de artefacto, inventario, PVI, comparación, UI/report. | Formato versionado con módulos exactos y aristas limitadas; digest y commit obligatorios; sin rutas/repositorios/checksums; ciclos y truncado explícitos; divergencia queda inconclusa. Inspectra nunca ejecuta `go mod graph`. Fixtures de ciclo, bomba, commit distinto y dos owners. | Tratar `// indirect` como grafo completo falsea dependencia directa/transitiva y prioridad; un artefacto libre puede filtrar topología. | PROD-140 y contrato de artefactos CI. | M | **2026-09-10:** contrato `2026-09-10.1`, 1 MiB/2.000 nodos/4.000 aristas; binding exacto, archivo regular no enlazado, admisión owner-scoped inmutable y bloqueo tras PVI. Solo un root `go.mod`/`go.sum` corrobora identidades/raíces/alcanzabilidad; divergencia no añade identidades, truncado y ciclos son explícitos. Se persiste proyección+recibo, nunca JSON/IDs/aristas; UI/informe/comparación posterior y docs alineados, sin ejecutar Go ni otorgar procedencia pública. Hostiles: binding, duplicados, enlaces, 1.200 nodos, replay/conflicto/PVI y dos owners. Offline: CLI 38/38, backend 1.467/1.467, frontend 406/406+axe, build 298,0/322 KiB, compileall, Compose y diff-check. Visual desktop/390 px sin overflow ni consola; temporales eliminados. Sin red externa, proyecto real, push, PR ni despliegue. |
| **PROD-222 — P3 — pendiente**<br>Escapes canónicos de módulos Go | Algunos módulos con mayúsculas usan escapes `!`; el subconjunto lowercase actual debe ampliarse solo con semántica oficial y sin colisiones. Flujo: importar path escapado → canonicalizar → atestar exactamente → PURL/OSV. | Normalizador Go, PURL, policy y fixtures. | Contrato oficial verificado, forma canónica única y round-trip; case-folding/escapes ambiguos se rechazan; atestación exacta sigue obligatoria y ninguna ruta local pasa. | Una heurística puede correlacionar otro módulo; no soportarlo reduce cobertura pero falla cerrado. | PROD-140 y demanda real confirmada. | S | Pendiente; no bloquea módulos lowercase. |
| **PROD-223 — P2 — completada**<br>Grafo y features Cargo aportados por CI | Equipos Rust necesitan distinguir alcance real, features y dependencias por target sin que Inspectra ejecute Cargo. Flujo: CI autorizado produce artefacto versionado → liga commit/snapshot → valida → inventario/cobertura/PVI/informe. | CLI/CI, contrato de artefacto Cargo, inventario, PVI y reporting. | Artefacto exacto, digestado y ligado a commit; aristas/features/targets acotados, sin paths, registries, checksums ni metadatos de build. Ciclos/truncado/divergencia quedan inconclusos. Fixtures hostiles y dos owners, sin ejecutar Cargo en Inspectra. | Tratar todo Cargo.lock como transitive sin grafo reduce priorización; aceptar metadatos libres filtra topología o falsea alcance. | PROD-141 y contrato de artefactos CI. | M | **2026-09-10:** contrato `2026-09-10.2`, archivo regular no enlazado, 1 MiB/2.000 nodos/4.000 aristas/32 targets/64 features y binding exacto. Un único par Cargo v3/v4 corrobora crates, roots y alcance; solo scope y conteos sobreviven, nunca IDs, labels o aristas. Admisión tenant-scoped inmutable, replay/conflicto/PVI y coexistencia Go cubiertos; API/UI/informe/docs/handshake alineados. Offline: backend 1.476/1.476 con 2 GiB tras documentar ENOSPC exacto a 256 MiB; CLI 42/42, frontend 407/407+axe, build 298,0/322 KiB, compileall, Compose y diff-check. Sin red ni Cargo. Revisión visual interactiva no disponible y no declarada superada. |
| **PROD-224 — P3 — pendiente**<br>Evolución controlada de fuentes oficiales Cargo | El formato o los identificadores oficiales de crates.io pueden evolucionar sin que una actualización amplíe egress silenciosamente. Flujo: cambio de contrato verificado → fixture/revisión → nueva versión de parser → despliegue explícito. | Runner, política de procedencia, contratos y documentación. | Ninguna URL configurable; cada nuevo literal requiere fuente oficial, test positivo/negativo y bump de contrato. Formas desconocidas siguen locales. | Aceptar prefijos o hosts por heurística habilitaría fuga de nombres privados. | PROD-141. | S | Pendiente; no bloquea los literales actuales. |
| **PROD-225 — P2 — completada**<br>Mapeo GHSA explícito para Go/Cargo y futuros ecosistemas | Seguridad necesita corroboración secundaria solo cuando GitHub publica un ecosistema inequívocamente equivalente. Flujo: hallazgo OSV con GHSA → mapa oficial versionado → coincidencia exacta package/version → evidencia o no correlación. | `github_advisories.py`, contratos, UI, informes, docs y fixtures. | Allowlist cerrada respaldada por documentación GitHub; jamás fallback a `pip`/npm. Homónimos, ecosistemas/rangos incompatibles y ausencia de mapa quedan `not_correlated`. | Un fallback incorrecto puede reforzar un falso positivo o esconder conflicto de fuentes. | PROD-141 y contrato GHSA oficial. | M | **2026-09-10:** normalizador `2026-09-10.2`; mapas explícitos npm/pip/go/rust/composer/maven/nuget conforme a docs REST/GraphQL oficiales. Exige GHSA de OSV, identidad exacta y rango afectado. 18/18 dirigidas y 64/64 GHSA/PVI/reporting offline, compileall/diff-check. Adaptador solo validado con fixtures: sin consulta GitHub real, token o egress. |
| **PROD-226 — P2 — completada**<br>Grafo Composer aportado por CI | Equipos PHP necesitan alcance transitive real sin que Inspectra ejecute Composer. Flujo: CI autorizado exporta artefacto cerrado → liga commit/snapshot → valida aristas → inventario/PVI/informe. | CLI/CI, contrato de artefacto, inventario y reporting. | Artefacto versionado/digestado, límites de nodos/aristas y commit; sin repositorios, URLs, hashes, scripts ni metadata. Ciclo/truncado/divergencia quedan inconclusos. | Inventar aristas desde el lockfile sesga prioridad; metadata libre filtra topología. | PROD-143 y contrato CI. | M | **2026-09-10:** contrato `2026-09-10.3`, binding exacto, 1 MiB/2.000 nodos/4.000 aristas, archivo regular no enlazado y admisión tenant-scoped inmutable. Un único root Composer corrobora identidades/raíces; divergencia y truncación fallan cerradas. Persisten solo scope/status y recibo agregado, nunca topología o metadata libre; no se atestigua Packagist. CLI/API/inventario/UI/informes/docs completos. Offline: 1.993/1.993 Python, 408/408 frontend/58 archivos, axe, build 298,0/322 KiB, compileall, Compose y diff-check. Sin ejecutar Composer ni usar Internet. |
| **PROD-227 — P3 — pendiente**<br>Versiones Composer avanzadas | Proyectos que usan aliases, branches o versión normalizada de cuatro segmentos necesitan cobertura sin coerción equivocada. | Parser/normalizador Composer, matching OSV y UI. | Cada forma se admite solo con semántica oficial verificada y fixtures OSV; identidad/rango ambiguos permanecen no correlacionables. | Coerción de `dev-main`, alias o cuarta parte puede producir falsos positivos/negativos. | PROD-143 y evidencia de demanda. | M | Pendiente; subconjunto estable `X.Y.Z[-pre][+build]` falla cerrado. |
| **PROD-228 — P3 — pendiente**<br>Evolución del contrato composer.lock | Operación necesita detectar cambios estructurales de Composer sin aceptar campos desconocidos silenciosamente. | Parser, matriz de cobertura, docs y fixtures. | Contrato versionado con corpus oficial; cambios de shape requieren bump y regresiones; formatos desconocidos se rechazan sin datos sensibles. | Un parser estructural demasiado permisivo puede perder paquetes o retener metadata. | PROD-143. | S | Pendiente. |
| **PROD-229 — P2 — completada**<br>Grafo y scopes Gradle aportados por CI | Equipos JVM necesitan distinguir dependencias directas, transitivas y configuraciones relevantes sin que Inspectra evalúe el build. Flujo: CI autorizado exporta artefacto cerrado → liga commit/snapshot → valida → inventario/cobertura/PVI/informe. | CLI/CI, contrato de artefacto Gradle, inventario, PVI, comparación y reporting. | Artefacto versionado, digestado y ligado al commit; coordenadas/aristas/scopes bajo allowlist y límites; sin repositorio, path, DSL, credencial ni metadata libre. Ciclos, truncado y divergencia quedan inconclusos. | Tratar el lock como grafo completo sesga la prioridad; aceptar salida libre del build filtra topología. | PROD-142 y PROD-243. | M | **2026-09-10:** contrato `2026-09-10.4`, sobre/handshake `.5`, 1 MiB/2.000 nodos/4.000 aristas y scopes cerrados. Binding, mismo root, lock, identidad y alcanzabilidad fallan cerrados; se retiene proyección y recibo agregado, nunca topología/configuración. Relaciones `ci_reported`, no procedencia Maven Central. API/CLI/productor/inventario/UI/informes/docs completos; replay concurrente y aislamiento cubiertos. Offline: backend 1.496/1.496, tools 464/464, CLI 54/54, frontend 409/409+axe, build 298,0/322 KiB, compileall, Compose y diff-check; sin ejecutar Gradle/Maven ni usar red/proyecto real. |
| **PROD-230 — P2 — completada**<br>Versionado Maven no SemVer | Proyectos JVM usan qualifiers y esquemas Maven que el subconjunto SemVer seguro actual excluye. Flujo: importar versión → clasificar esquema → correlacionar rango OSV solo si la semántica es inequívoca → explicar cobertura. | Normalizador/matcher Maven, PVI, UI y corpus de fixtures. | Implementa semántica verificada de `ComparableVersion` o mantiene cada forma fuera de correlación; no recorta qualifiers ni coacciona versiones. Conflictos de fuente producen estado desconocido. | Ordenar incorrectamente `Final`, `RELEASE`, snapshots o segmentos variables causa falsos positivos/negativos. | PROD-142 y corpus Maven validado. | M | **2026-09-10:** subconjunto oficial revisado: numérico variable, qualifiers conocidos, aliases release y `sp`, comparación case-insensitive sin cambiar la identidad. Leading zero, vendor, ranges, release numerado y separadores ambiguos quedan `unknown`/locales. Parser Gradle, purl, grafo, PVI/OSV simulado y UI/docs alineados; fixture `1.0.Final` termina con fix `1.0-sp1`. Offline: backend 1.507/1.507, tools 464/464, CLI 54/54, frontend 409/409, build 298,0/322 KiB, compileall, Compose y diff-check. Fuentes: POM order y ComparableVersion oficiales Apache; sin ejecutar gestores ni usar red de proveedores. |
| **PROD-231 — P2 — completada**<br>Maven seguro desde SBOM | Equipos que generan CycloneDX/SPDX JVM necesitan reutilizar esa evidencia sin POM/Gradle. Flujo: importar SBOM admitido → validar purl Maven exacta → atestación tenant/operator → PVI/comparación/informe. | Parsers SBOM, purl, inventario, policy, UI y fixtures. | Solo `pkg:maven/group/artifact@version` sin qualifiers/subpath y con versión soportada; relaciones mantienen su evidencia SBOM; atestación pública sigue separada. URLs, refs y propiedades quedan descartadas. | Confiar en cualquier purl o metadata externa puede sacar coordenadas privadas o inventar alcance. | PROD-137, PROD-138, PROD-139, PROD-142 y PROD-230. | M | **2026-09-10:** contrato SBOM `2026-09-10.1`; Maven exacto/lowercase y subconjunto de versión seguro, relaciones demostradas y descarte de URL/ref/hash/metadata. Import, atestación operator, aprobación tenant y egress son puertas distintas; la marca SBOM interna nunca se serializa y la petición OSV contiene solo identidad mínima. Se corrigió una regresión hallada por la suite completa que vaciaba el inventario al persistir el nuevo contrato. Offline: dirigidas 19 backend/56 frontend y 9 integración; backend 1.510/1.510, frontend 409/409+axe, build 298,0/322 KiB, compileall, Compose y diff-check. Sin proveedor real, gestor ni proyecto externo. |
| **PROD-232 — P3 — pendiente**<br>Evolución del contrato Gradle lock | Operación necesita detectar cambios de sintaxis sin ampliar el parser silenciosamente. Flujo: corpus oficial → revisión → bump de contrato → despliegue. | Runner, cobertura, contratos y documentación. | Cada forma nueva requiere fuente oficial, fixture positivo/negativo y bump; líneas desconocidas, dinámicas o con coordenadas ambiguas fallan cerradas sin retener su contenido. | Un parser permisivo puede omitir componentes o conservar configuración sensible. | PROD-142. | S | Pendiente. |
| **PROD-233 — P1 — completada**<br>Cursores Active con Base64url canónico | Operación necesita que un cursor firmado tenga una sola representación externa verificable. Flujo: página Active → cursor firmado → petición siguiente → validación canónica/HMAC → página o error cerrado. | `active_job_index.py`, `active_assets.py` y regresiones Active. | Exige al decodificar el mismo valor que produce el encoder sin padding; cursor válido pagina y alias o mutación devuelve el error público existente. Pruebas dirigidas y suite completa. | Aliases equivalentes dificultan auditoría, idempotencia y cacheado; no se confirmó bypass de tenant porque bytes y HMAC eran idénticos. | Índices/paginación Active existentes. | S | **2026-09-09:** la suite completa reprodujo un alias no canónico aceptado (esperaba 400, recibió 200). Se añadió round-trip canónico a ambos decoders; 7/7 dirigidas y 1.346/1.346 backend pasaron sin red. |
| **PROD-234 — P2 — completada**<br>Grafo NuGet multi-target aportado por CI | Equipos .NET necesitan alcance y aristas verificables sin ejecutar restore/MSBuild en Inspectra. Flujo: CI autorizado → artefacto ligado a commit → validación acotada → inventario/PVI/informe. | CLI/CI, contrato de artefacto, inventario, PVI y reporting. | Artefacto versionado/digestado, paquetes/aristas y grupos de target opacos y acotados; sin TFM privados, rutas, repositorios, hashes ni metadata libre. Divergencia/truncado quedan inconclusos. Fixtures hostiles y dos owners. | Inferir un grafo del lock sesga prioridad; aceptar salida libre filtra topología. | PROD-144 y contrato de artefactos CI. | M | **2026-09-10:** contrato cerrado `2026-09-10.5` y handshake CLI `2026-09-10.6`; 1 MiB/2.000 nodos/4.000 aristas/32 targets opacos consecutivos. Digest y commit/snapshot, mismo root, target count, identidad, raíces y alcance por target fallan cerrados; ciclos/truncación son explícitos. Solo se retienen proyección y recibo agregado, nunca TFM, topología, rutas, fuentes, hashes o metadata libre; tampoco se atribuye NuGet.org. CLI/productor/API/inventario/PVI/UI/informes/docs completos, con replay, bloqueo tras PVI, hostiles y dos owners. Offline: backend 1.523/1.523, tools 464/464, CLI 56/56, frontend 410/410+axe, build 298,0/322 KiB, compileall, Compose y diff-check. Sin ejecutar NuGet/MSBuild, usar red/proveedor o analizar proyecto real. |
| **PROD-235 — P2 — completada**<br>Semántica completa y segura de versiones NuGet | Proyectos con formas NuGet fuera del subconjunto numérico actual necesitan cobertura sin coerción incorrecta. Flujo: versión exacta → canonicalización oficial → matching OSV → estado o inconcluso. | Normalizador/matcher, PVI, UI y corpus de fixtures. | Orden y equivalencias siguen la especificación NuGetVersion verificada; legacy/ambigua queda `unknown`, nunca se recorta qualifier ni se inventa equivalencia. Pruebas de precedencia y límites. | Comparación incorrecta genera falsos positivos o negativos. | PROD-144 y corpus oficial revisado. | M | **2026-09-10:** contrato NuGetVersion `2026-09-10.1` y PVI `2026-09-10.6`, basados en la referencia Microsoft y código oficial `NuGetVersion`/`VersionComparer`. Normalización pura 1–4 segmentos/64 caracteres/enteros .NET; completa minor/patch, elimina ceros, omite revisión cero/build metadata y canonicaliza prerelease case-insensitive con orden numérico. Runner, inventario, purl, egress/caché/fingerprint OSV, rangos/fixes, grafo y productor/validador CLI usan una identidad; sintaxis/enteros ambiguos quedan `unknown` o se rechazan. La validación descubrió y corrigió el fingerprint fuera de ámbito y un valor no canónico en estado PVI. Offline: 232 backend dirigidas, 2 parser, 6 CLI/productor, 26 UI; suites backend 1.544/1.544, tools 464/464, CLI 56/56, frontend 410/410+axe, build 298,0/322 KiB, compileall, Compose y diff-check. Sin .NET/NuGet, proveedor ni proyecto real. |
| **PROD-236 — P3 — pendiente**<br>Evolución versionada de packages.lock.json | Operación necesita detectar nuevas versiones/estructuras sin ampliar aceptación silenciosamente. Flujo: fuente oficial → corpus → revisión → bump contractual → despliegue. | Runner, cobertura, contratos, fixtures y docs. | Cada formato nuevo requiere fuente oficial, casos positivos/negativos y bump; versión, shape o claves duplicadas no soportadas fallan cerradas sin retener contenido. | Aceptación permisiva puede perder paquetes o conservar metadata sensible. | PROD-144. | S | Pendiente; v1 y rechazo de JSON ambiguo están cubiertos. |
| **PROD-237 — P3 — completada**<br>Evaluador CVSS v4 validado con corpus oficial | Seguridad necesita derivar v4 solo si el cálculo puede demostrarse, no aproximarse. Flujo: vector validado → evaluación oficial → banda/origen → detalle/informe. | `cvss.py`, normalizadores, UI/report y fixtures. | Algoritmo completo versionado, corpus FIRST y fronteras de redondeo; igualdad con resultados oficiales, score publicado intacto y `unknown` ante forma no soportada. | Una puntuación v4 aproximada altera prioridad y remediación. | PROD-097 y corpus oficial CVSS v4 revisado. | M | **2026-09-11:** `cvss==3.6` fijado y adaptado al redondeo final FIRST. Validador offline ligado al commit `fe21348d…7b` y cuatro SHA-256: 270 MacroVectors, 419.904 Base/Threat y 41.270 referencias soportadas coinciden; 25.028 vectores negativos quedan `unknown`, 33 marcadores inválidos y cero discrepancias. Score publicado permanece autoritativo; orden/forma inválida falla cerrado; KEV no cambia. 29 pruebas dirigidas, Python 3.12 completo 2.143/2.143, CLI 66/66, frontend 430/430 al repetir, build 305,7/322 KiB, auditorías, compileall, Compose y Gitleaks diff/canario verdes. El primer frontend completo tuvo una carrera no atribuida y queda en PROD-253. Sin proveedor/proyecto real, push, PR o despliegue. |
| **PROD-238 — P2 — bloqueada**<br>Catálogo revisado de equivalencias CPE↔purl | Analistas necesitan aprovechar relaciones reales sin convertir el registro seguro vacío en una heurística. Flujo: evidencia primaria de proveedor/NVD/advisory → revisión de equivalencia y CVE → entrada de código → fixture negativa/positiva → mapeo visible y auditable. | Registro `cpe_purl_mappings.py`, manifiesto de gobernanza, fixtures, documentación y revisión de UI/informes. | Cada entrada documenta fuente primaria enlazada, fecha, revisor, componente purl exacto, CPE exacto y CVE acotados; dos revisores aprueban el cambio. No se aceptan changelog aislado, nombre similar, wildcard, entrada runtime ni equivalencia global sin CVE. Renovación/retirada sube versión y conserva fixture histórica; pruebas demuestran homónimos y rangos/advisories incompatibles. | Una tabla poblada sin evidencia puede reforzar falsos positivos a escala; no poblarla limita solo esta corroboración secundaria y mantiene OSV operativo. | PROD-098; requiere acceso a evidencia primaria y dos revisores humanos. | M | **Bloqueada 2026-09-10:** el ciclo prohíbe red externa y no hay dos revisores autorizados disponibles. El registro seguro vacío conserva OSV operativo y evita equivalencias heurísticas; no se simuló aprobación ni evidencia. |
| **PROD-240 — P1 — completada**<br>Lock de almacenamiento endurecido | Operación necesita que el primer acceso posterior a restore no amplíe permisos ni permita redirigir la exclusión mutua. Flujo: crear/restaurar datos → abrir listado paginado → adquirir lock local → validar tipo/permisos → operar. | `storage_lock`, backup/restore y pruebas backend. | `.locks` queda `0700`; `storage.lock` es regular, enlace único y `0600`; la apertura no sigue symlink y rechaza un directorio enlazado. Restore y primer acceso conservan el árbol privado. | El `umask` observado creó `.locks` `0755`; un path manipulable podría exponer metadatos o hacer creer a procesos que comparten un lock cuando no es así. | Hallazgo confirmado durante PROD-214. | S | **2026-09-09:** `O_NOFOLLOW` cuando existe, `fstat`, `nlink=1`, `fchmod` y directorio validado/forzado. Regresiones de modos, symlink y restore incluidas en la validación dirigida offline de PROD-214. |
| **PROD-241 — P2 — completada**<br>Prioridad de cartera materializada por encima de 5.000 | Empresas con carteras grandes necesitan ordenar riesgo global sin recalcular todos los hallazgos bajo una petición ni rebajar el límite a ciegas. Flujo: cambio job/PVI/triage → hecho privado → página priorizada → filtros/resumen coherentes → rebuild. | Cartera, índices job/PVI/lifecycle, backup/readiness, API/UI y pruebas de escala. | Proyección sin nombres, rutas, componentes, evidencia ni texto; señales cerradas equivalentes byte-semánticamente a PROD-145, ligadas a digests autoritativos. Paginación coherente, rebuild/reinicio/corrupción y fixture de 20.000/dos owners con p95/memoria definidos. | Una consulta O(N) agota CPU/IO; un índice stale o cross-tenant falsea prioridad y puede revelar existencia/riesgo. | PROD-214 y proyecciones job/lifecycle existentes; coordinar con PROD-219. | L | **2026-09-10:** SQLite privado schema v2, HMAC exacto/de prefijo, digest y revalidación autoritativa. Equivalencia de filtros/orden/resumen, corrupción/topología/reinicio/refresh y dos owners cubiertos. Fixture 20.000: cold 5,379 s, warm p95 0,264 s, pico 271.699 B, 240 lecturas/10 páginas. Dirigidas 32/32, API/smoke 6/6, frontend 419/419 y build 302,5/322 KiB; revisión visual desktop/móvil limpia. Backend monolítico quedó 1.592/1.593 por el benchmark preexistente de remediación (aislado verde), registrado como `PROD-247`; no se falsea el gate. Sin red y con limpieza completa. |
| **PROD-242 — P2 — completada**<br>Refresco incremental de tendencias | Una cartera grande no debe bloquear su primera consulta mientras se recompone todo el índice. Flujo: mutación autoritativa → revisión dirty owner-scoped → job acotado/coalescido → publicación atómica → estado UI y recuperación. | Índice de tendencias, hooks/scheduler, readiness/observabilidad, API/UI, backup y benchmarks. | Ninguna consulta hace un rebuild síncrono de 250.000 hechos. Estado durable por owner y respuestas `ready/rebuilding/stale/failed`; la proyección vieja jamás se etiqueta como actual. Reinicio, carrera, fallo y equivalencia contra autoridad; sin identidades privadas. Fixture 100.000/dos owners con scheduling frío <250 ms y presupuesto de rebuild documentado. | El rebuild frío puede agotar workers; una actualización incremental divergente falsea el riesgo. | PROD-219; coordinar PROD-241. | L | **2026-09-10:** contrato `2026-09-10.2` y schema v2 con diario owner-scoped. La petición coalesce y lee la publicación existente; worker único/dos pasadas publica atómicamente y recupera trabajo tras reinicio. API/UI distinguen estado operativo de frescura, primera carga 202, polling acotado, error/retry y export solo current. Corrupción elimina solo el owner afectado; backup/restore valida el diario. Se corrigieron el contrato de rutas y una revalidación redundante hallados por la suite. Fixture 100.000/dos owners: scheduling <250 ms, cero lecturas de jobs y rebuild 53,09 s. Offline: 10/10 tendencias+backup, 3/3 contrato/API, backend 1.599/1.599, frontend 59/420, build 302,7/322 KiB, compileall, Compose y diff-check. Visual 1280x720/390x844 cubrió current, vacío, failed/stale, export bloqueada y retry→ready, sin overflow/consola. La revisión global conservadora puede causar rebuild cruzado redundante y queda acotada en `PROD-248`; no causa mezcla de datos. Sin red de proveedores, proyecto real, push, PR ni despliegue. |
| **PROD-243 — P2 — completada**<br>Sobre común versionado para evidencia CI | Equipos y operación necesitan que todos los grafos apliquen el mismo binding y aislamiento sin diseñar un sobre genérico antes de conocer las diferencias reales. Flujo: CI → preflight local → admisión owner-scoped → validación de ecosistema → recibo/proyección. | CLI, endpoints, storage, modelos, auditoría, docs y fixtures multi-ecosistema. | Tras al menos tres verticales, factoriza archivo regular no enlazado, límites, digest, commit/source, owner/proyecto/análisis, replay/inmutabilidad y bloqueo tras PVI; validadores de ecosistema siguen cerrados. Go conserva compatibilidad byte-semántica. Carreras, cruces, contratos y dos owners fallan sin identidades en logs. | Copia divergente omite controles; abstracción prematura vuelve permisivo el límite de confianza. | PROD-221, PROD-223 y PROD-226 completadas. | M | **2026-09-10:** sobre `2026-09-10.1` y handshake `2026-09-10.4`; lectura segura/JSON/digest/binding, frontera owner-proyecto-análisis-PVI y replay/inmutabilidad bajo lock compartidos. Los tres esquemas siguen cerrados y el payload Go conserva bytes/digest. Carrera Composer idempotente y fixtures hostiles/aislamiento cubiertos. Offline: 1.993/1.993 Python, 58/58 regresiones finales, 408/408 frontend, build 298,0/322 KiB, compileall, Compose y diff-check. Documentado en `docs/ci-graph-evidence.md`; sin red ni gestores. |
| **PROD-244 — P2 — completada**<br>Productores CI auditables para grafos pasivos | Equipos necesitan generar contratos correctos sin mantener scripts ad hoc que puedan filtrar metadata. Flujo: gestor ejecutado por CI autorizado → salida bounded → transformador puro → contrato ligado → preflight/upload. | CLI, contratos Go/Cargo/tercer grafo, fixtures y docs CI. | No ejecuta gestor/build; lee solo artefacto regular bounded ya generado; descarta paths/repos/checksums/metadata; salida canónica ligada a commit/snapshot y un recibo local. Reproducibilidad, hostiles, dos roots y enlaces cubiertos. | Un productor ad hoc puede filtrar topología o falsear evidencia, reduciendo adopción y auditabilidad. | PROD-221, PROD-223 y PROD-226 completadas. | M | **2026-09-10:** `inspectra graph` genera Go/Cargo/Composer desde una observación cerrada sin procesos, red ni checkout; archivo regular ≤1 MiB, validación de esquema, binding, salida `0600`/`O_EXCL`/`fsync` y recibo redactado. Reproducibilidad byte a byte, dos roots, metadata libre, symlink/hardlink y no-sobrescritura cubiertos. CLI 52/52 offline; 1.999 pruebas totales recolectadas, suite previa 1.993/1.993, frontend 408/408, build 298,0/322 KiB, compileall/diff-check. La producción nativa sigue siendo responsabilidad explícita del CI autorizado. |
| **PROD-245 — P2 — completada**<br>Validador automático de coherencia entre backlogs | Producto y agentes necesitan una fuente de verdad consistente para elegir trabajo y no confundir evidencia histórica con estado actual. Flujo: ejecutar check local/CI → parsear resúmenes y fichas → comparar IDs/prioridad/estado → informar contradicciones sin editar. | Helper bajo `tools/`, fixtures, CI/documentación y ambos backlogs. | Detecta IDs duplicados o ausentes, prioridad/estado contradictorios y cambios en las tareas que sigan protegidas y bloqueadas. Salida accionable, determinista y sin modificar documentos; fixtures válidos y conflictivos. | Una contradicción puede ocultar trabajo pendiente o declarar cierre falso. | PROD-239 completada. | S | **2026-09-10:** helper stdlib read-only para resumen/fichas/filas detalladas y diagnósticos deterministas con línea. En su cierre inicial protegía `SEC-012`, `PROD-129`, `PROD-130` y `PROD-167`; las autorizaciones posteriores retiraron `PROD-129` y `PROD-130`, conservando `SEC-012` y `PROD-167`. El primer run real halló siete contradicciones; evidencia confirmó como completadas `PROD-063/124/243`, mantuvo pendientes `PROD-007/021/222` y movió la evidencia de identidad mal ubicada desde `PROD-021` a `PROD-124`. Integrado como `make check-backlogs` en validación local, CI, README y ciclo de `AGENTS.md`. Pasaron los fixtures, pruebas dirigidas, `compileall`, puerta real y diff-check, sin red ni mutación de documentos por el helper. |
| **PROD-246 — P2 — completada**<br>Clave estable e invalidación segura multiworker | Operación necesita compartir la cartera entre procesos auxiliares sin que claves HMAC distintas causen falsos vacíos o rebuilds alternos. Flujo: arranque → clave estable opcional → lectura → rotación explícita; el despliegue soportado continúa single-worker. | Configuración de secretos, índice de cartera, backup/despliegue y pruebas multiproceso. | Single-worker conserva clave efímera/rebuild; procesos que opten por compartir la proyección usan la misma clave canónica. Dos procesos leen los mismos tokens; una clave distinta falla antes de reconstruir; la clave no se persiste/exporta y dos owners permanecen aislados. | Thrashing o resultados vacíos en procesos auxiliares; reutilización indebida de clave debilita pseudonimización. | PROD-241; el despliegue soportado continúa siendo single-worker. | M | **2026-09-10:** secreto opcional canónico de 32 bytes excluido de `repr`, almacenamiento y backup; solo persiste un marcador HMAC separado por dominio. Dos procesos `spawn` leen una proyección común y una rotación discrepante falla antes de mutarla; el fixture de 20.000 proyectos/dos owners conserva aislamiento. Pasaron 41/41 pruebas cartera+backup y la suite backend completa offline con exit 0; `compileall`, Compose local/privado, diff-check y backlogs verdes. Rotación offline documentada; no se promete coordinación de cola multiworker. |
| **PROD-247 — P2 — completada**<br>Gate reproducible de rendimiento de remediación | Operación necesita que el presupuesto de 20.000 proyectos sea estable también dentro de la suite completa. Flujo: páginas → cancelación frecuente → checkpoint durable acotado → artefacto atómico/recuperación. | Jobs de plan de remediación, benchmark, tests y docs. | Menos escrituras durables sin relajar 5 s; cancelación, recuperación, progreso final y artefacto siguen correctos; dirigida y suite backend completa verdes con tiempo. | Un gate intermitente oculta regresiones; checkpoints excesivamente espaciados degradan cancelación. | PROD-216. | S | **2026-09-10:** cancelación por página de 100 y escritura cada 1.000/final; 20.000 proyectos requieren 23 escrituras totales en vez de 203. Regresión de cancelación entre checkpoints, 9/9 dirigidas, benchmark aislado 0,48 s con umbrales originales y backend completo 1.594/1.594 offline. `compileall`, diff-check y coherencia de backlogs verdes. |
| **PROD-248 — P2 — completada**<br>Reloj owner-scoped de mutaciones de tendencias | Empresas multi-tenant necesitan evitar rebuilds de tendencias provocados por cambios de otra organización sin arriesgar hechos stale. Flujo: mutación autoritativa → revisión monotónica del owner → refresh solo del owner afectado → fallback conservador. | Stores de proyectos/jobs/PVI/lifecycle/remediación, storage lock, índice/scheduler, backup/readiness, benchmarks y docs. | Cada mutación relevante incrementa una revisión owner-scoped atómica; un cambio extranjero no ensucia al owner consultado. Migración, restore, carrera y crash no pierden invalidaciones: diario ausente/corrupto/divergente cae al hash conservador. Dos owners/100.000 análisis demuestran equivalencia, cero lecturas cruzadas, ausencia de rebuild ajeno y coste p95 documentado; sin datos privados en índice/logs. | El estado actual gasta CPU/IO de forma conservadora; una invalidación fina incompleta podría etiquetar evidencia stale como actual. | PROD-242; coordinar stores, storage lock y PROD-241. | L | **2026-09-10:** clock SQLite v1 privado/derivado con owner key SHA-256, generación, epoch y digest content-free; cubre jobs/proyectos/PVI/lifecycle/batches/borrado bajo lock. Fallo o divergencia activa fallback global/readiness false y nunca revierte autoridad. Nueve regresiones dirigidas, fixture 100.000/dos owners sin dirty/read ajeno, backend actual 1.607 offline por grupos, frontend 420/420, build 302,7/322 KiB, Compose, compileall y diff-check verdes. Etiquetas legacy y reparación concurrente quedaron corregidas durante la suite; docs/backup alineados. Sin red/proyecto externo/push/PR/despliegue. |
| **PROD-249 — P2 — completada**<br>Suite CLI dentro de la puerta Python reproducible | Equipos necesitan que el mismo target local/CI falle ante una regresión de snapshot, policy o SARIF, no depender de una pasada manual separada. Flujo: preparar Python 3.12 desde locks → backend/tools → CLI → resultado único atribuible. | `Makefile`, `backend/requirements-dev.*`, CLI, documentación y pruebas. | El lock fija dependencias de test CLI; `make test-python` ejecuta suite raíz y `cli/tests` con import correcto; SARIF valida el esquema oficial fijado; cero red ordinaria y sin cambiar workflow/SEC-012. | CI puede quedar verde con una CLI rota o con un test que solo pasa gracias a una dependencia local no declarada. | PROD-037, PROD-152 y PROD-155. | S | **2026-09-10:** `test-python` incorpora `cli/tests` y existe repetición atribuible `test-cli`; `jsonschema==4.25.1` y cuatro transitivas quedan fijadas. Regresión estática cubre target/lock/docs. Offline y read-only: CLI 65/65, tools+canario no-red 476/476 y `pip check` sin requisitos rotos; `make -n` muestra ambas fases. No se ejecutó bootstrap con red. Workflow y bloqueos protegidos permanecen intactos. |
| **PROD-250 — P2 — completada**<br>Gate reproducible de programación de tendencias a escala | Operación necesita que la puerta de 100.000 análisis detecte regresiones reales sin depender de variación accidental de I/O. Flujo: mutación owner-scoped → scheduling acotado → publicación incremental → medición atribuible cold/warm. | Scheduler/índice de tendencias, storage lock/SQLite, benchmark, instrumentación y documentación. | Perfila lock, revisión owner-scoped, SQLite y `fsync`; conserva cero lecturas de jobs y semántica stale/ready; separa presupuesto algorítmico de variación de I/O sin elevar el límite sin evidencia; repeticiones aisladas y suite completa quedan verdes con presupuesto documentado. | Una puerta intermitente oculta regresiones o induce a perder invalidaciones mediante una optimización no demostrada. | PROD-242 y PROD-248; perfil reproducible de plataforma. | M | **2026-09-11:** 106/124 ms del perfil previo eran inicialización de esquema (97 ms `executescript`), no el scheduling ni los 100.000 análisis; commit/`fsync` siguieron activos. El fixture usa ahora el mismo startup `recover_pending_refreshes()` y después mide first-owner y warm con pared `<250 ms`, CPU `<100 ms` y cero reads. Diez repeticiones: 12,9–24,9 ms first-owner, 2,2–3,1 ms warm y 2,8–3,1 ms CPU. Benchmark completo 75,42 s con guards de rebuild `<60 s` y memoria `<64 MiB`; backend 1.616/1.616 en 481,59 s. Solo prueba/docs, sin relajar límites ni tocar producto, red, CI o bloqueos. |

### PROD-251 — Durabilidad eficiente y gate reproducible del reloj owner-scoped

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** las mutaciones autoritativas deben
  invalidar tendencias con durabilidad suficiente y coste predecible; una puerta
  roja de forma sostenida impide certificar cualquier candidatura local.
- **Flujo completo afectado:** mutación bajo lock → digest de directorios →
  transacción owner-scoped → crash/reinicio → lectura exacta o fallback global.
- **Áreas o archivos implicados:** `backend/app/risk_trend_source_clock.py`,
  pruebas de reloj/tendencias y documentación de arquitectura/operación.
- **Criterios de aceptación verificables:** conserva transacción atómica,
  permisos `0600`, claves de owner opacas, detección de mutación fuera de banda y
  fallback conservador; una transacción perdida nunca puede presentar una
  revisión stale como actual. El gate de 100 mutaciones pasa repetidamente con
  p95 menor de 50 ms sin elevar el límite, y la suite backend completa queda
  verde.
- **Riesgos de seguridad, privacidad y operativa:** reducir durabilidad sin
  demostrar recuperación puede ocultar hechos stale; mantener dos `fsync` por
  mutación deriva en latencia alta y una puerta permanentemente roja.
- **Dependencias:** `PROD-248` completada; fallo reproducido al validar
  `PROD-021`.
- **Tamaño:** S
- **Estrategia de pruebas:** perfil de commit/SQLite, regresiones de transacción
  perdida/corrupción/out-of-band/dos owners, diez repeticiones del gate y suite
  backend completa offline.
- **Evidencia de validación al completarse:** 2026-09-11: la suite inicial falló
  con p95 63,1 ms y diez repeticiones aisladas fallaron entre 52,8 y 68,0 ms;
  `cProfile` atribuyó 2,738/2,789 s a 101 commits SQLite. Solo el diario derivado
  adopta `DELETE`+`synchronous=NORMAL`, conservando transacción y detección por
  digest independiente; autoridad JSON y demás stores no cambian. La regresión
  verifica journal/sync, `0600`, redacción, pérdida out-of-band, corrupción,
  rotación y aislamiento. Diez repeticiones posteriores pasaron sin elevar el
  límite; medición adicional: p95 37,073 ms, media 16,516 ms y máximo 55,915 ms.
  Reloj+tendencias dirigidas y backend completo 1.617/1.617 pasaron offline;
  frontend 424/424, CLI 66/66, build 303,8/322 KiB, compileall, Compose
  base/privado, release, backlogs y diff-check verdes. Documentada la garantía y
  el trade-off según SQLite oficial; sin proyecto real, push, PR o despliegue.
### PROD-256 — Ligar webhooks de integración a la resolución validada

- **Prioridad:** P2
- **Estado:** pendiente
- **Necesidad de usuario y valor aportado:** los operadores necesitan entregar eventos mínimos a un receptor HTTPS configurado sin que un cambio DNS entre validación y conexión permita alcanzar redes privadas.
- **Flujo completo afectado:** configuración fija del operador → política SSRF → conexión ligada a IP aprobada con SNI/Host originales → entrega firmada → reintento y auditoría mínima.
- **Áreas o archivos implicados:** `backend/app/integration_events.py`, configuración, transporte, pruebas y documentación operativa.
- **Criterios de aceptación verificables:** no existe una segunda resolución; cada socket conecta solo a una IP global aprobada; HTTPS conserva certificado y SNI; redirecciones/proxy ambiental siguen deshabilitados. DNS mixto, rebinding, IPv4/IPv6, error TLS, reintento e idempotencia fallan sin payload ni destino en logs.
- **Riesgos de seguridad, privacidad y operativa:** SSRF por rebinding o pinning que desactive TLS; la mitigación actual es mantener webhooks apagados y usar DNS confiable.
- **Dependencias:** PROD-071 completada; requiere transporte acotado compatible con TLS.
- **Tamaño:** M
- **Estrategia de pruebas:** transporte simulado sin Internet, servidor TLS local y regresiones de ausencia de segunda resolución.
- **Evidencia de validación al completarse:** pendiente.

### PROD-257 — Objetivos táctiles coherentes en los flujos principales

- **Prioridad:** P2
- **Estado:** pendiente
- **Necesidad de usuario y valor aportado:** personas en móvil o con movilidad fina limitada necesitan accionar formularios y navegación sin controles de 16–40 px difíciles de pulsar.
- **Flujo completo afectado:** onboarding → proyecto → inventario/inteligencia → triage, comparación e informes, incluidos diálogos y acciones destructivas.
- **Áreas o archivos implicados:** estilos/componentes frontend, pruebas de accesibilidad y `docs/frontend-visual-review.md`.
- **Criterios de aceptación verificables:** acciones principales, inputs, selects, checkboxes y enlaces operativos ofrecen área mínima 44×44 CSS px o separación equivalente documentada; 320/390/768/1440 y 200 % conservan reflow, foco y flujo sin overflow global.
- **Riesgos de seguridad, privacidad y operativa:** acciones erróneas o inaccesibles; un cambio global sin revisión puede degradar densidad y tablas.
- **Dependencias:** PROD-114 y PROD-165 completadas.
- **Tamaño:** M
- **Estrategia de pruebas:** medición DOM, axe, teclado y navegador real en cuatro viewports y zoom 200 %.
- **Evidencia de validación al completarse:** pendiente.

### PROD-258 — Política de reporte responsable de vulnerabilidades

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** investigadores y clientes necesitan un canal privado y expectativas claras para comunicar fallos sin exponerlos en un issue público.
- **Flujo completo afectado:** descubrir vulnerabilidad → consultar versiones soportadas → contacto privado → acuse/triage → divulgación coordinada.
- **Áreas o archivos implicados:** `SECURITY.md`, README y configuración de seguridad del repositorio.
- **Criterios de aceptación verificables:** política visible desde GitHub y README, versiones beta soportadas, canal privado real verificado, datos que no deben publicarse, tiempos realistas y límites de la candidatura; sin dirección ficticia ni promesa inoperable.
- **Riesgos de seguridad, privacidad y operativa:** divulgación pública accidental, pérdida de reportes o compromiso de plazos inexistentes.
- **Dependencias:** el mantenedor debe proporcionar o habilitar un canal privado verificable.
- **Tamaño:** S
- **Estrategia de pruebas:** revisión de enlaces y contacto por dos mantenedores, render GitHub y gate documental sin secretos.
- **Evidencia de validación al completarse:** 2026-09-11: Private Vulnerability Reporting quedó habilitado y la lectura posterior devolvió `enabled=true`; el endpoint autenticado de advisories fue accesible y el formulario oficial respondió HTTP 200, sin crear un advisory. `SECURITY.md` documenta soporte beta, alcance, límites, investigación responsable, datos mínimos y el único canal privado real; README lo enlaza. Sin email, PGP, SLA, recompensa ni *safe harbor* inventados.

### PROD-259 — Protección exigible de `main` y checks requeridos

- **Prioridad:** P2
- **Estado:** completada
- **Necesidad de usuario y valor aportado:** adoptantes necesitan que el proceso remoto impida integrar código que no haya pasado las puertas revisadas.
- **Flujo completo afectado:** push/PR → revisión → cuatro jobs CI → conversaciones resueltas → integración autorizada.
- **Áreas o archivos implicados:** branch protection/rulesets de GitHub, documentación de mantenimiento y evidencia remota.
- **Criterios de aceptación verificables:** `main` exige PR, cuatro checks CI y conversaciones resueltas; bypass ordinario deshabilitado o acotado a emergencia auditada. Una PR sintética demuestra que fallo, job ausente y push directo quedan bloqueados.
- **Riesgos de seguridad, privacidad y operativa:** integración o push directo sin escaneo, pruebas o auditorías pese a que el workflow exista.
- **Dependencias:** PROD-130 y SEC-012 completadas; bloqueada hasta autorización explícita para mutar configuración remota.
- **Tamaño:** S
- **Estrategia de pruebas:** lectura antes/después de rulesets/protection y PR sintética sin merge.
- **Evidencia de validación al completarse:** 2026-09-11: tras confirmar `404 Branch not protected` y rulesets vacíos, la autorización explícita desbloqueó la tarea. La protección efectiva de `main` exige PR, rama actualizada, conversaciones resueltas y los cuatro checks reales de GitHub Actions; se aplica a administradores, exige cero aprobaciones porque solo existe un colaborador elegible, no añade bypass y bloquea force-push/eliminación. Secret Scanning y Push Protection siguen habilitados. La API confirmó todos los valores; la transición pending/verde del PR y el HEAD final se registran en el cierre para evitar un commit circular.
