# Estrategia de pruebas por dominio

La suite Python mantiene contratos pequeños por dominio y conserva
`backend/tests/test_backend.py` como conjunto de integración heredado. Una prueba
nueva debe ir en el módulo de su capacidad; no se debe ampliar el archivo
monolítico salvo que el recorrido dependa realmente de varios dominios y no exista
todavía una fixture compartida segura.

## Grupos reproducibles

Tras preparar el entorno fijado con `make setup-python`, estos grupos permiten
atribuir un fallo sin omitir la puerta completa:

```bash
PYTHONPATH=backend:tools .venv/bin/python -m pytest \
  backend/tests/test_component_coverage.py \
  backend/tests/test_sbom_import.py \
  backend/tests/test_project_vulnerability_intelligence.py

PYTHONPATH=backend:tools .venv/bin/python -m pytest \
  backend/tests/test_advisory_fixture_governance.py \
  backend/tests/test_public_advisories.py \
  backend/tests/test_public_advisory_egress.py \
  backend/tests/test_github_advisories.py \
  backend/tests/test_nvd_advisories.py

PYTHONPATH=backend:tools .venv/bin/python -m pytest \
  backend/tests/test_team_identity.py \
  backend/tests/test_automation_tokens.py \
  backend/tests/test_product_audit.py

PYTHONPATH=backend:tools .venv/bin/python -m pytest \
  backend/tests/test_backend.py
```

Ningún grupo sustituye a `make test-python`. El resultado final exige la suite
completa —que también ejecuta `cli/tests`— y debe registrar expresamente los
grupos no ejecutados. `make test-cli` permite repetir solo la CLI con las mismas
dependencias fijadas.

## Guardas de fixtures y red

`backend/tests/conftest.py` bloquea por defecto resolución DNS y conexiones a
direcciones no loopback. `backend/tests/test_test_safety_contract.py` es el
canario que demuestra esa frontera. Los servidores loopback, transportes ASGI y
adaptadores simulados siguen permitidos.

Las fixtures públicas de advisories están inventariadas por digest y contrato en
`backend/tests/fixtures/advisory-fixtures-manifest.json`; la prueba de gobernanza
falla ante altas o cambios no declarados. Las fixtures que simulan datos
sensibles son sintéticas y de rutas explícitas. La puerta Gitleaks del repositorio
y `make verify-secret-scanner` deben detectar un secreto nuevo y demostrar con un
canario que las reglas completas siguen activas. Nunca se debe añadir una
exclusión amplia para hacer pasar una fixture.

Si una prueba necesita Internet, no pertenece a la suite ordinaria: debe usar un
adaptador inyectado o una fixture local. Las validaciones reales autorizadas se
documentan aparte y no se presentan como pruebas deterministas.
