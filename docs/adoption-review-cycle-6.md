# Reauditoría de adopción semanal — Ciclo 6

Fecha: 2026-09-06. Alcance: los tres verticales nuevos del Ciclo 6, ejecutados
con datos sintéticos y sin egress: CLI Git, integración CI/CD e importación
SBOM. Esta revisión no autoriza publicación, CI remoto ni despliegue.

## Recorridos ejercitados

| Recorrido | Evidencia observada | Resultado |
| --- | --- | --- |
| Instalación y CLI | Instalación desde `cli/` en Python 3.12 limpio, `inspectra --help` y 13 pruebas con repositorios Git sintéticos; la suite tardó 1,30 s tras instalar dependencias del entorno. | Utilizable, pero todavía sin artefacto de distribución verificable ni matriz multiplataforma. |
| Snapshot y análisis | Preflight Gitleaks obligatorio con canario, TAR determinista desde objetos Git, subida HTTP local, espera acotada y enlace a resultado. El E2E real previo del mismo ciclo terminó y limpió recursos. | Flujo completo; los clones superficiales y la compatibilidad cliente/servidor necesitan mejor diagnóstico preventivo. |
| CI/CD | Token de un solo uso ligado a proyecto, admisión por commit+digest, dos solicitudes concurrentes y conflicto de bytes distintos. JSON, Markdown y SARIF se generaron con códigos `pass`/`fail`/`inconclusive`. | Flujo completo; la configuración sigue siendo manual y SARIF aún carece de validación contra un esquema oficial fijado. |
| SBOM | CycloneDX 1.4–1.6 y SPDX 2.2/2.3, descarte de campos privados, 2.000 componentes/10.000 relaciones, atestación pública independiente, repetición del mismo snapshot y comparación 0/0/0. | Flujo completo inicial; falta importar revisiones SBOM al mismo proyecto y declarar la certeza de relaciones cuando el grafo no la demuestra. |
| UI responsive | Revisión en navegador contra frontend actual y backend local: escritorio 1265×710 y móvil 390×844; DOM semántico y ausencia de desborde horizontal (`scrollWidth` 375 con viewport 390). | Se detectó y corrigió el solapamiento de consentimientos del formulario SBOM; queda deuda de arquitectura de información en la portada. |

## Regresión transversal

- Backend: suite completa ejecutada al 100 %. La primera pasada encontró dos
  regresiones (orden de fallo cerrado SQLite y contrato de rutas); ambas se
  corrigieron. Al añadir la repetición SBOM, otra pasada detectó un cambio
  incompatible en el mensaje de fuente archive eliminada; se restauró el copy
  anterior y se añadió uno específico para SBOM. La pasada final, incluido el
  E2E SPDX nuevo, terminó al 100 %.
- Herramientas auxiliares: suite completa ejecutada al 100 %.
- Frontend: primera pasada, 307/309; la nueva entrada de archivo SBOM hacía que
  dos pruebas eligieran el control incorrecto. Tras usar el nombre accesible,
  309/309 y build Vite/TypeScript correctos; bundle inicial 318,7/322 KiB.
- CLI: 13/13 e instalación/ayuda en Python 3.12 limpio.

## Fricciones priorizadas

1. Un desarrollador no dispone todavía de wheel/sdist verificables ni de una
   comprobación previa de compatibilidad con el contrato del servidor.
2. Configurar CI exige trasladar manualmente URL, ID, token, flags y política;
   falta un asistente por proyecto que genere ejemplos sin incrustar secretos.
3. Un proyecto SBOM puede repetir y comparar su snapshot actual, pero no
   incorporar todavía una revisión SBOM posterior de manera atómica.
4. La UI muestra alcance directo/transitivo, pero no distingue “demostrado por
   grafo” de “tratado conservadoramente como transitivo”.
5. La portada mezcla onboarding, ciclo de datos, SBOM, métricas y auditorías;
   para adopción recurrente necesita una entrada por intención sin ocultar los
   estados críticos.
6. El ciclo de credenciales carece de rotación solapada guiada y purga acotada
   de registros revocados/caducados.
7. SARIF tiene estructura y límites probados, pero no validación determinista
   contra una copia fijada del esquema oficial.

Las tareas `PROD-152`–`PROD-166` convierten estas observaciones en trabajo
verificable. No duplican los ecosistemas `PROD-140`–`PROD-144`, la cartera
`PROD-145` ni Active `PROD-148`–`PROD-150`.
