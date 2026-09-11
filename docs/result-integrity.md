# Integridad de resultados retenidos

Inspectra sella cada resultado nuevo después de aplicar redacción y
normalización. El contrato `2026-09-09.1` calcula SHA-256 sobre JSON canónico y
los metadatos mínimos que explican el resultado: trabajo, propietario/
organización, proyecto, tipo/perfil de análisis y perfil inmutable de ejecución.
El digest no incluye bytes de fuente ni secretos sin redactar y no se expone en
la API o la interfaz.

Al leer un trabajo sellado, el almacenamiento vuelve a calcular el digest antes
de construir el modelo. Una modificación del resultado, propietario, proyecto
o contrato produce `409 Stored result integrity check failed.`. Al quedar
bloqueada la lectura, también quedan bloqueados informes, comparaciones y otras
vistas que consumen ese trabajo. El error no incluye ruta, ID, contenido ni
valor discrepante.

Los resultados anteriores a este contrato carecen de sello y siguen legibles
con `result_integrity_status=unknown`; nunca se presentan como verificados. Los
resultados nuevos con sello válido muestran `valid` en API, `verified` en el
workspace y `valid` en los informes.

## Límites

- Es un control de integridad local, no una firma ni una prueba de autoría. Un
  administrador con escritura completa sobre datos y código puede recalcular
  un SHA-256; la detección resistente a ese atacante requiere una clave o
  registro externo gestionado y queda fuera de este contrato.
- El formato JSON físico puede reordenarse o cambiar de espacios sin invalidar
  el sello; el contenido semántico no puede cambiar.
- Eliminar el sobre de un registro lo convierte en legado `unknown`, no en
  válido. Operación debe investigar cualquier regresión inesperada de `valid` a
  `unknown` y restaurar desde una copia verificada si procede.
- La restauración conserva y vuelve a verificar los ficheros; no debe generar
  sellos nuevos para ocultar una discrepancia.

Las regresiones ordinarias se ejecutan sin red y cubren redacción previa al
hash, orden JSON, modificación de resultado/propietario, error genérico y
compatibilidad explícita del legado.
