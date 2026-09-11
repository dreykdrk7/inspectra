# Matriz de funcionalidades de Inspectra 0.3.0-beta.1

Esta matriz describe la candidatura `0.3.0-beta.1`, validada técnicamente en un
PR borrador pero todavía sin tag, release ni publicación. Los estados se
refieren a evidencia disponible, no a una promesa comercial.

| Área | Estado | Evidencia disponible | Límite operativo |
| --- | --- | --- | --- |
| Archivo autorizado → proyecto → análisis | Beta candidata | Suites, smoke TLS y aceptación real | No ejecuta contenido ni acepta ruta del servidor |
| Snapshot Git con CLI | Beta candidata | Repositorios sintéticos, Gitleaks y reproducción byte a byte | Solo objetos rastreados del commit; no worktree |
| CI con credencial acotada | Beta candidata validada | Contratos, E2E local y CI remota verde sobre el commit candidato | PR borrador; no implica merge, tag, release ni despliegue |
| SBOM CycloneDX/SPDX | Beta candidata | Fixtures hostiles, aislamiento y UI | Solo versiones/formas cerradas; metadata libre descartada |
| Reglas pasivas de configuración | Beta candidata | Backend/runner/frontend y fixtures | Señales para revisión; no prueba de explotabilidad |
| Inventario npm/PyPI/Go/Cargo/Composer/Gradle/NuGet | Beta candidata | Parsers acotados y cobertura explícita | Formatos no soportados quedan no correlacionables |
| OSV para npm público exacto | Validación real acotada | Aceptación de la fuente autorizada B, caída/recuperación y caché | Egress explícito; solo identidad mínima |
| OSV para PyPI/Go/Cargo/Composer/Maven/NuGet | Implementado con fixtures | Suite determinista y política de procedencia | Falta aceptación real específica; atestaciones adicionales |
| CISA KEV | Validación real acotada | Catálogo oficial durante aceptación | Enriquecimiento por CVE exacto; nunca crea vulnerabilidad |
| GitHub Security Advisories | Adaptador con fixtures | Normalización/correlación simulada | Egress real y token GitHub no autorizados |
| NVD | Adaptador con fixtures | CVE exacto y transporte simulado | Apagado aparte; no correlaciona CPE con paquetes |
| Boletines oficiales de proveedor | Preventivo/curado | Contrato y fixtures | Sin catálogo general automático ni inferencia por changelog |
| Triage, excepciones y baseline | Beta candidata | Persistencia, permisos, comparación e informes | Excepciones requieren revisión futura; evidencia inmutable |
| Cartera, tendencias y remediación | Beta candidata | Escala sintética, índices privados y UI | Single-worker; límites por contrato visibles |
| Informes Markdown/HTML/PDF y JSON/SARIF | Beta candidata | Pruebas de redacción y artefactos locales | Export técnico requiere confirmación/permiso |
| Equipos privados | Experimental | Matriz de roles, revocación y dos owners sintéticos | No es SaaS ni aislamiento de infraestructura por cliente |
| Active: registro/operación | Experimental | Flujos semanales sintéticos, auditoría e informes | Requiere activos propios/autorizados; apagado por defecto |
| Active: ejecución | Experimental | Runners aislados y capacidades cerradas | Sin flags libres, explotación ni objetivos públicos arbitrarios |
| Backup/restore e integridad | Beta candidata | Drill, corrupción, revocación y restore a ruta nueva | El operador aporta almacenamiento cifrado y copias externas |
| Despliegue privado TLS | Candidatura controlada | Compose, smoke, acta local y CI remota verde | Sin declaración estable; single-host |
| macOS/Windows | Bloqueado | Ninguna aceptación real | Linux es la única plataforma acreditada |

## Convenciones

- **Beta candidata:** vertical utilizable y probado localmente, todavía sin
  publicación ni garantía estable.
- **Validación real acotada:** se contactó el proveedor oficial bajo una
  autorización y dataset concretos; no generaliza a otros ecosistemas.
- **Adaptador con fixtures:** implementación probada sin Internet. No equivale a
  integración real.
- **Experimental:** exige opt-in y puede cambiar de contrato; no debe habilitarse
  por defecto.
- **Bloqueado:** falta evidencia o autorización externa; no se simula como verde.
