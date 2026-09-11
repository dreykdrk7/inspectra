# Política de seguridad de Inspectra

## Versiones soportadas

Inspectra todavía no tiene una versión estable publicada. `0.3.0-beta.1` es
una candidatura de prerelease y puede cambiar antes de su publicación.

| Versión | Estado de soporte |
| --- | --- |
| `0.3.0-beta.1` | Candidata; se revisan reportes reproducibles sobre el código publicado en este repositorio |
| Ramas o versiones anteriores | Sin compromiso de mantenimiento |

Esta tabla se actualizará cuando exista una release publicada. No implica
mantenimiento indefinido, un SLA ni garantía de corrección.

## Reportar una vulnerabilidad de forma privada

Use exclusivamente el formulario de
[reporte privado de vulnerabilidades de GitHub](https://github.com/dreykdrk7/inspectra/security/advisories/new).
No publique inicialmente vulnerabilidades de Inspectra como issues, discussions
o pull requests públicos.

Incluya solo lo necesario para comprender y reproducir el problema:

- componente o flujo afectado;
- versión o commit observado;
- pasos mínimos de reproducción y condiciones necesarias;
- impacto observado y evidencia mínima redactada;
- mitigación conocida, si existe.

No envíe credenciales reales, secretos, datos personales innecesarios, dumps
completos, información de terceros sin autorización ni resultados obtenidos
atacando sistemas ajenos. Si una prueba revela datos sensibles, deténgala y
describa el resultado de forma redactada.

Los reportes se revisarán de buena fe según gravedad, reproducibilidad y
capacidad disponible. Cuando sea razonable se coordinará la divulgación con la
persona informante, sin prometer plazos rígidos, recompensas o una fecha de
resolución.

## Investigación responsable

- Pruebe únicamente en entornos propios o con autorización expresa.
- Deténgase al demostrar el impacto mínimo necesario.
- No degrade servicios, mantenga persistencia, exfiltre datos ni acceda a
  cuentas de terceros.
- No realice pruebas Active contra activos sin autorización verificable.
- No use un reporte para ampliar el acceso o recopilar información ajena al
  defecto.

Estas expectativas operativas no constituyen una promesa legal de *safe harbor*.

## Alcance

Se pueden reportar defectos de seguridad del propio proyecto en:

- backend y API;
- frontend;
- CLI e integración CI mantenidas aquí;
- importación de archivos, repositorios autorizados y SBOM;
- inventario e inteligencia pública de vulnerabilidades;
- capacidades Active experimentales;
- imágenes, Compose, workflows y configuraciones mantenidas por Inspectra.

Las vulnerabilidades encontradas por Inspectra en un proyecto analizado
pertenecen a los mantenedores de ese proyecto. No deben reportarse aquí salvo
que demuestren un fallo de Inspectra, por ejemplo exposición de datos,
aislamiento roto, ejecución inesperada o un control de seguridad eludido.

## Limitaciones actuales

- El producto está en beta y no existe una versión estable.
- El soporte acreditado es Linux, single-host y single-worker.
- Active es experimental, está deshabilitado por defecto y requiere autorización
  sobre cada activo.
- La cobertura depende de formatos, reglas, fuentes disponibles y versiones
  correlacionables; no se garantiza detección completa.
- «Sin hallazgos conocidos» no significa que un proyecto sea seguro.

Consulte también el [alcance y modelo de amenazas](docs/security-scope.md) y la
[matriz funcional](docs/feature-matrix.md).
