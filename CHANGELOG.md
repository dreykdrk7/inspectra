# Changelog

Este proyecto sigue [Semantic Versioning](https://semver.org/). Una prerelease
no se considera una versión estable ni amplía por sí sola el soporte declarado.

## 0.3.0-beta.1 — GitHub Prerelease

### Añadido

- Flujo completo de proyecto con snapshots inmutables, cola durable, inventario,
  cobertura, hallazgos, comparación e informes.
- Inteligencia pública opt-in: OSV con caché/frescura/degradación, correlación de
  CVE/GHSA y enriquecimiento CISA KEV exclusivamente por CVE exacto previo.
- Inventario acotado de lockfiles npm, PyPI, Go, Cargo, Composer, Gradle y NuGet,
  además de importación SBOM y grafos cerrados aportados por CI.
- CLI reproducible para snapshot Git, preflight de secretos, análisis, políticas,
  SARIF y artefactos de grafos.
- Triage append-only, líneas base, cartera, tendencias, centro de remediación,
  asignación, informes técnicos/ejecutivos y auditoría de acciones.
- Espacios privados con roles, invitaciones y credenciales de automatización
  acotadas.
- Active experimental: registro de activos autorizados, controles de propiedad,
  aprobación opcional, recurrencia, cuotas, evidencia e informes operativos.
- Contratos de retención, integridad, backup/restore, readiness y smoke local.

### Seguridad

- Egress deshabilitado por defecto, destinos oficiales fijos, HTTPS sin
  redirecciones y límites de tiempo, tamaño, concurrencia, reintentos y caché.
- Aislamiento owner/organización/proyecto/ejecución, runners endurecidos y
  evidencia/logs redactados.
- Gitleaks con reglas completas, canario bloqueante y fixtures sintéticos
  gobernados.
- Vitest y `@vitest/mocker` actualizados a 4.1.11 para corregir
  [CVE-2026-84373 / GHSA-82fw-gwwq-j7x9](https://github.com/advisories/GHSA-82fw-gwwq-j7x9);
  la instalación limpia con Node 22 y la auditoría npm no conservan avisos.
- Imágenes base y acciones CI declaradas por digest/SHA; la rama protegida exige
  los cuatro jobs CI y la cadena de prerelease construye artefactos temporales
  con permisos de solo lectura antes de cualquier publicación.

### Cambiado

- Versión de producto unificada en `0.3.0-beta.1` mediante `VERSION` y una guarda
  reproducible que comprueba API, contrato cliente, frontend, CLI y documentos.
- README convertido en presentación canónica del producto; el diario técnico se
  conserva en documentación secundaria y backlogs.

### Límites conocidos

- Prerelease beta, no estable y sin despliegue de producción.
- OSV npm y CISA KEV tienen aceptación real acotada; GHSA, NVD, OSV PyPI y otros
  ecosistemas no deben presentarse como integraciones reales sin una aceptación
  separada.
- Arquitectura soportada single-host/single-worker; sin alta disponibilidad ni
  cifrado de backups gestionado por la aplicación.
- Active y espacios de equipo continúan experimentales y apagados por defecto.

## 0.1.0-alpha.1

Primera alpha pasiva histórica. Sus notas y decisiones se conservan bajo
`docs/releases/` y `docs/future/`; no describen el alcance actual.
