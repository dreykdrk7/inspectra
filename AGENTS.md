# Instrucciones operativas para agentes de Inspectra

`TODO.md` es la fuente de verdad del trabajo pendiente y realizado. El objetivo es mejorar Inspectra de forma continua en seguridad, fiabilidad, mantenibilidad y experiencia de usuario, con cambios proporcionales y verificables.

## Ciclo obligatorio

1. Lee `TODO.md` y selecciona **una única** tarea pendiente: prioriza P0, después impacto, riesgo y dependencias desbloqueadas. Márcala como `en progreso` antes de editar código.
2. Lee los archivos, pruebas, configuración y documentación afectados. Comprueba también cambios no relacionados en el árbol de trabajo y no los sobrescribas.
3. Implementa un cambio pequeño, coherente y mantenible que satisfaga los criterios de aceptación. No hagas refactors cosméticos ni amplíes el cambio sin una justificación concreta.
4. Añade o actualiza pruebas, validaciones y documentación cuando correspondan. Toda corrección de seguridad o regresión debe tener una comprobación que reduzca la posibilidad de reintroducirla.
5. Ejecuta las comprobaciones disponibles y pertinentes (por ejemplo, pruebas dirigidas, lint, build, `docker compose config`, auditorías). Corrige los fallos provocados por el cambio. Si una comprobación no se puede ejecutar, registra el motivo exacto y el comando necesario para desbloquearla.
6. Actualiza el bloque de la tarea en `TODO.md`: cambia el estado a `completada`, añade evidencia breve de validación y revisa/desbloquea las tareas dependientes. No marques una tarea completa solo porque se editó código.
   Si la tarea aparece también en `TODO_PRODUCTO.md`, sincroniza ambos documentos y ejecuta `make check-backlogs` antes de continuar.
7. Si el análisis o la implementación revela una vulnerabilidad, deuda, riesgo, hueco de pruebas o problema de UX relevante, añade una tarea nueva con ID único, prioridad, contexto, áreas, criterios de aceptación, riesgo, tamaño y dependencias. Cuando una vulnerabilidad externa sea aplicable, enlaza su fuente oficial o fiable y anota versión/rango afectado.
8. Continúa con la siguiente tarea prioritaria desbloqueada mientras el encargo activo lo permita.

## Criterios de calidad y seguridad

- Da preferencia a vulnerabilidades, exposición de servicios, autenticación/autorización, sesiones, validación de entrada, protección de datos, secretos, logs y manejo de errores.
- Antes de actualizar una dependencia, verifica el aviso en fuentes públicas primarias (advisories de GitHub, proveedor, CVE/NVD u OWASP) y prueba la versión resultante.
- Trata toda entrada, URL, cabecera y dato externo como no confiable. No registres secretos ni datos personales innecesarios.
- Mantén los valores por defecto seguros y documenta con claridad cualquier modo local o de desarrollo que reduzca controles.
- En frontend, prioriza flujos claros, estados de carga/error/vacío/éxito, formularios comprensibles, teclado, foco visible, contraste, semántica, responsive y mensajes accionables.
- No reescribas una capa completa cuando una mejora incremental verificable resuelva el problema. Divide los trabajos grandes en tareas dependientes.

## Forma de actualizar `TODO.md`

Cada tarea debe conservar: ID único, prioridad, estado, descripción y motivo, áreas afectadas, criterios de aceptación verificables, riesgo, estimación, dependencias y evidencia de validación al completarse. Registra hechos observados, comandos y resultados; separa hipótesis de evidencia confirmada.

Si una tarea está bloqueada por una decisión, credencial, infraestructura o dependencia externa, márcala `bloqueada`, explica el bloqueo y continúa con otra tarea que no dependa de ella. No borres tareas completadas: su evidencia aporta trazabilidad.

## Límites operativos

- Respeta los cambios preexistentes de otras personas o agentes y no uses comandos destructivos para limpiar el árbol.
- No introduzcas secretos reales, datos de producción ni desactives controles para conseguir que una prueba pase.
- Mantén documentación de usuario y despliegue alineada con el comportamiento implementado.
