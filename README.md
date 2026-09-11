# Inspectra

Inspectra es una plataforma local-first y self-hosted para analizar seguridad,
calidad técnica y riesgo de proyectos propios o expresamente autorizados. Une
inventario de dependencias, reglas pasivas, inteligencia pública de
vulnerabilidades, triage, comparación, informes, automatización y una superficie
Active acotada en una sola experiencia.

> **Estado actual:** `0.3.0-beta.1` es una beta validada para distribución como
> GitHub Prerelease, no una versión estable ni un despliegue de producción. La
> aceptación controlada validó OSV y CISA KEV con
> identidades npm públicas exactas; GitHub Security Advisories y NVD continúan
> validados solo con fixtures. El egress y todas las capacidades Active están
> deshabilitados por defecto.

## Qué aporta

- Incorporación reproducible mediante archivo autorizado, snapshot Git desde la
  CLI, CI o SBOM CycloneDX/SPDX.
- Alta inicial Git sin clone remoto: snapshot exacto local, Gitleaks obligatorio
  y grant privado de un uso; véase [`docs/repository-ingestion.md`](docs/repository-ingestion.md).
- Análisis pasivo sin ejecutar código, instaladores ni gestores del proyecto.
- Inventario y cobertura explícita de manifests/lockfiles npm, PyPI, Go, Cargo,
  Composer, Gradle y NuGet dentro de contratos cerrados y versionados.
- Hallazgos normalizados con severidad, confianza, evidencia redactada,
  recomendación, referencias y estado de ciclo de vida.
- Inteligencia pública opt-in con OSV; CISA KEV enriquece únicamente CVE ya
  correlacionados y nunca decide por sí solo que una versión es vulnerable.
- Comparación entre ejecuciones, tendencias, cartera, centro de remediación,
  informes Markdown/HTML/PDF y salidas JSON/SARIF para CI.
- Equipos privados, permisos, credenciales de automatización, auditoría de
  acciones, retención, backup/restore y readiness operativo.
- Active para activos autorizados, con registro, revisión, límites y ejecución
  aislada; sigue siendo experimental y fail-closed.

## Estado por capacidad

| Capacidad | Estado en `0.3.0-beta.1` | Límite principal |
| --- | --- | --- |
| Proyectos y análisis pasivo | Beta candidata | Solo fuentes autorizadas; nunca ejecuta el proyecto |
| Inventario y SBOM | Beta candidata | Formatos/versiones enumerados; lo ambiguo queda no correlacionable |
| OSV npm | Validación real acotada | Egress explícito; identidad pública exacta |
| OSV PyPI y otros ecosistemas | Implementado/fixtures | Requiere atestación y aceptación real separada |
| CISA KEV | Validación real acotada | Solo enriquecimiento por CVE exacto ya correlacionado |
| GHSA y NVD | Fixtures únicamente | Deshabilitados; sin credenciales GitHub ni consulta real acreditada |
| Triage, comparación e informes | Beta candidata | Evidencia sensible redactada; export técnico requiere confirmación |
| CLI y CI | Beta candidata validada | Python 3.12; CI remota verde sobre el commit candidato, sin publicar artefactos |
| Equipos privados | Experimental | No es SaaS multi-tenant ni alta disponibilidad |
| Active | Experimental/deshabilitado | Solo activos propios/autorizados y controles opt-in independientes |

La matriz ampliada y las diferencias entre estable, experimental y deshabilitado
están en [docs/feature-matrix.md](docs/feature-matrix.md).

## Primer análisis local

Requisitos: Docker Engine con Compose y Git. El modo siguiente es únicamente
para una estación local confiable; publica frontend y API solo en loopback.

```bash
git clone <copia-autorizada-de-inspectra>
cd inspectra
docker compose config --quiet
docker compose up --build
```

Abra `http://localhost:5173`, seleccione **Archive**, cargue un ZIP/TAR de un
proyecto autorizado y elija **Create project & analyze**. La vista de proyecto
muestra progreso, inventario, cobertura, hallazgos, comparación e informes. La
aplicación no acepta rutas del servidor ni clona URLs aportadas por el usuario.

Para detener la instancia:

```bash
docker compose down
```

Los datos permanecen en `data/`; no los incluya en Git. Para una prueba privada
con TLS, autenticación persistente, backup y reversión, siga
[DEPLOYMENT_ACCEPTANCE.md](DEPLOYMENT_ACCEPTANCE.md) y
[docs/backup-restore.md](docs/backup-restore.md). El ejemplo privado no equivale
a una autorización de despliegue público. El hash PBKDF2 debe permanecer en un
archivo de entorno privado y entre comillas simples para que Compose no
interprete sus `$`:

```dotenv
INSPECTRA_ADMIN_PASSWORD_HASH='pbkdf2_sha256$<iterations>$<salt>$<digest>'
```

An unquoted verifier is a deployment error: cualquier aviso de interpolación en
`docker compose config` es `NO-GO` y no debe resolverse debilitando la
autenticación.

## CLI reproducible

La CLI crea una instantánea desde objetos Git inmutables, no desde el worktree.
Excluye clases sensibles/generadas, exige Gitleaks con canario y permite revisar
commit, árbol, cantidad, tamaño y SHA-256 antes de subir nada.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install ./cli
.venv/bin/inspectra doctor
.venv/bin/inspectra scan /ruta/al/repositorio --dry-run
```

La subida y automatización requieren un servidor autorizado y credenciales con
alcance mínimo. Consulte [cli/README.md](cli/README.md) y
[docs/ci-integration.md](docs/ci-integration.md).

## Inteligencia pública sin fuga de proyecto

El egress ordinario está apagado. Al habilitarlo deliberadamente, el cliente usa
hosts y rutas compilados en código, HTTPS sin redirecciones, tiempos/tamaños/
concurrencia/reintentos limitados y caché con caducidad. Solo puede enviar:

```text
ecosistema + nombre público normalizado + versión exacta
```

Nunca envía nombre de proyecto, ruta, código, archivo, hash privado, secreto,
usuario ni dominio. Un fallo del proveedor produce estado degradado o dato
caducado, no un falso «sin vulnerabilidades». Vea
[docs/public-vulnerability-intelligence.md](docs/public-vulnerability-intelligence.md)
y [docs/offline-advisory-snapshots.md](docs/offline-advisory-snapshots.md).

## Active: autorización antes que alcance

Active registra activos, revisiones de autorización, responsables, aprobación
opcional por cuatro ojos, cuotas y evidencia redactada. La ejecución ocurre en
un servicio aislado y solo al activar controles independientes. No admite flags
libres, rangos amplios, CIDR, comodines, NSE/scripts, explotación, fuerza bruta,
credenciales ni escaneo público arbitrario.

El recorrido operativo y todos sus límites están en
[docs/active-operations.md](docs/active-operations.md). Mantenga Active apagado
si no existe una autorización verificable sobre el activo.

## Arquitectura y límites de confianza

- **Frontend React/Vite:** onboarding, proyectos, resultados, remediación,
  equipos y operaciones.
- **API FastAPI:** autenticación/autorización, contratos, cola durable,
  persistencia y orquestación.
- **`audit-tools`:** análisis de archivos en tmpfs, sin montaje de datos ni
  egress.
- **`network-tools`:** comprobaciones pasivas de red dentro de límites propios.
- **`active-tools`:** capacidades Active opcionales, internas y deshabilitadas.
- **Almacenamiento local:** datos privados owner/org-scoped, locks endurecidos,
  integridad de resultados y operaciones offline de backup/restore.

La arquitectura soportada es single-host/single-worker. No promete alta
disponibilidad, coordinación distribuida, borrado físico forense ni cifrado de
backup dentro de la aplicación. Use almacenamiento cifrado y un perímetro de red
real. Detalles: [docs/architecture.md](docs/architecture.md),
[docs/security-scope.md](docs/security-scope.md) y
[docs/data-retention.md](docs/data-retention.md).

## Desarrollo y validación

Se requiere Python 3.12 y Node.js 22. Las suites ordinarias no necesitan
Internet; proveedores externos se sustituyen por fixtures/adaptadores simulados.

```bash
make check-backlogs
make check-release
make check-python-version PYTHON=/ruta/a/python3.12
make test-python PYTHON=/ruta/a/python3.12
make test-cli PYTHON=/ruta/a/python3.12
make test-frontend
make build-frontend
make validate-compose
make validate-compose-private
make verify-secret-scanner
```

`make validate` agrupa las puertas locales principales; para una candidatura se
añaden los perfiles Compose, reproducibilidad de artefactos y smoke descritos en
las notas del corte.

Las auditorías de dependencias sí consultan sus índices públicos:

```bash
make audit-python PYTHON=/ruta/a/python3.12
make audit-frontend
```

La estrategia, separación de suites y canario de no-red están documentados en
[docs/test-strategy.md](docs/test-strategy.md). `TODO.md` es la fuente de verdad
operativa y `TODO_PRODUCTO.md` mantiene el roadmap funcional sincronizado.

## Documentación

- [Arquitectura](docs/architecture.md)
- [Alcance y amenazas](docs/security-scope.md)
- [Política y reporte privado de seguridad](SECURITY.md)
- [Proyectos y fuentes](docs/product-projects.md)
- [Contrato de hallazgos](docs/product-findings-contract.md)
- [Inteligencia pública](docs/public-vulnerability-intelligence.md)
- [SBOM](docs/sbom-import.md)
- [Operación Active](docs/active-operations.md)
- [Equipos y permisos](docs/team-permission-matrix.md)
- [Federación OIDC privada](docs/oidc-federation.md)
- [Eventos firmados para integraciones](docs/signed-integration-events.md)
- [Backup y restore](docs/backup-restore.md)
- [Aceptación de despliegue](DEPLOYMENT_ACCEPTANCE.md)
- [Notas de la candidatura](docs/releases/0.3.0-beta.1-local.md)
- [Avisos de dependencias runtime](THIRD_PARTY_NOTICES.md)

El historial técnico detallado se conserva en `docs/future/`, `docs/audits/`,
las actas de aceptación y los backlogs; el README describe únicamente el
producto actual.

## Uso responsable y licencia

Use Inspectra solo sobre proyectos y activos propios o con autorización expresa.
Los resultados son señales de revisión y no sustituyen verificación humana,
pruebas especializadas ni gestión de riesgo organizativa.

Los defectos de seguridad del propio Inspectra deben comunicarse mediante la
[política de seguridad y su canal privado](SECURITY.md), no como un issue
público inicial.

Inspectra se distribuye bajo la licencia [MIT](LICENSE). Sus dependencias de
producción conservan licencias propias; el inventario fijado y sus fuentes se
publican en [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
