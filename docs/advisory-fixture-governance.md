# Gobernanza de fixtures de inteligencia pública

Las pruebas ordinarias de Inspectra no consultan OSV, GitHub, NVD, CISA ni ningún
otro host externo. `backend/tests/conftest.py` bloquea resolución y conexiones
no loopback; la validación completa se ejecuta además en contenedor con
`--network none`. Los adaptadores usan fixtures y transportes simulados.

El inventario canónico está en
`backend/tests/fixtures/advisory-fixtures-manifest.json`. Toda fixture JSON bajo
`fixtures/osv`, `fixtures/github` o `fixtures/cisa` debe tener exactamente una
entrada con:

- proveedor y enlace HTTPS a su esquema o contrato público;
- fecha de revisión, propósito y transformación aplicada;
- estado de licencia/procedencia;
- SHA-256 y tamaño máximo.

Las cuatro fixtures actuales son sintéticas y escritas a mano a partir del shape
público. No copian respuestas reales ni representan vulnerabilidades reales;
por ello su estado es `synthetic_no_provider_content_copied`. Los identificadores,
fechas, relaciones, puntuaciones y textos son datos de prueba. Un URL inseguro
en la fixture OSV es entrada negativa deliberada y debe ser descartado.

## Añadir o renovar una fixture

1. Usa el ejemplo mínimo capaz de cubrir el contrato y sus campos ausentes o
   retirados. No copies una respuesta completa.
2. Elimina tokens, cabeceras, datos personales, nombres/rutas de proyectos,
   cuerpos innecesarios y cualquier contenido no redistribuible.
3. Prefiere datos sintéticos. Si una futura fixture deriva de contenido real,
   registra la fuente, fecha, licencia aplicable y transformación de forma
   precisa; no la etiquetes como sintética.
4. Calcula el SHA-256 del fichero reducido, fija un límite de tamaño cercano y
   actualiza el manifiesto en el mismo cambio.
5. Ejecuta
   `pytest backend/tests/test_advisory_fixture_governance.py` y las pruebas del
   adaptador dentro del entorno Python 3.12 sin red.

La guarda falla si aparece una fixture sin metadatos, si cambia su digest, si
supera su cuota o si contiene marcadores comunes de credenciales. Un cambio de
schema del proveedor requiere actualizar primero el adaptador y sus casos
negativos; el manifiesto no convierte un changelog ni una fixture en evidencia
de vulnerabilidad.
