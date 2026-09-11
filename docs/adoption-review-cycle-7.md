# Revisión de adopción — Ciclo 7

Estado: cuatro verticales de adopción completados y validados localmente. Esto
no declara release, despliegue ni soporte no validado. `SEC-012`, `PROD-129` y
`PROD-130` permanecen bloqueadas.

## Vertical 1 — Distribución y operación del CLI

- Distribución: wheel y sdist se construyen dos veces desde copias temporales
  de solo lectura con tooling fijado. Ambos deben coincidir byte a byte tras
  normalizar únicamente reloj/propietario/modo del contenedor sdist. Se entrega
  SBOM CycloneDX y `SHA256SUMS`; no se publica ni firma.
- Diagnóstico: `inspectra doctor` comprueba Python 3.12, Git, Gitleaks, política
  empaquetada y canario. En el E2E real del artefacto informó `ready` con Git
  2.47.3 y Gitleaks 8.30.1.
- Compatibilidad: un handshake público, estático y sin bearer ocurre antes de
  Git/Gitleaks/upload y exige los cuatro contratos declarados.
- Configuración: el perfil local es de esquema cerrado, modo 0600, sin secretos
  y con precedencia `flag > entorno > perfil > default`.
- Git: no hay fetch; el lazy-fetch queda deshabilitado. Shallow, promisor,
  revisión ausente y corrupción tienen fallos cerrados diferenciados.
- Plataformas: solo Linux x86_64/CPython 3.12 tiene evidencia. macOS, Windows y
  WSL2 no están validados ni se anuncian como soportados.

### E2E reproducible desde artefacto

Se construyó e instaló el wheel en un Python 3.12 limpio, sin importar el
monorepo. Sobre un repositorio Git sintético de tres archivos y un
`package-lock.json` v3 válido se recorrió:

1. `config show` → `valid`;
2. `doctor` → `ready`;
3. dry-run con Gitleaks/canario real → digest
   `eb83213131f7ad0619d4db39efa1fb59a827902566800c5e3aad74c3a49715d8`;
4. handshake contra backend actual → upload → runner aislado → resultado
   `completed`, con el mismo digest y un hallazgo local;
5. policy `observe` → código 9/inconclusa por
   `local_coverage_incomplete`, que es el resultado contractual correcto para
   un fixture mínimo que no cubre todos los analizadores; PVI quedó
   `not_requested` y no hubo egress.

Una primera repetición había usado por error un lockfile de fixture con JSON
escapado inválido. Se identificó exactamente mediante el estado de cobertura,
se eliminaron sus siete registros y se repitió desde cero; no se contabiliza
como éxito. En la repetición válida se revisaron logs contra paths temporales y
canarios sensibles, se eliminaron siete registros, tres contenedores, la red y
todo el directorio temporal. La verificación final encontró cero recursos E2E.

Pruebas acumuladas del vertical: 33/33 CLI en Debian/CPython 3.12 + Git real,
endpoint ASGI dirigido, `compileall`, `diff-check`, builds reproducibles,
instalación wheel/sdist y E2E local desde wheel.

## Vertical 2 — experiencia CI profesional

El workspace de archivo ofrece un asistente GitHub/genérico que crea una
credencial ligada al proyecto, muestra el secreto una sola vez y genera un
snippet sin material sensible. La API permite comprobar metadatos/scopes sin
recibir el secreto; rotación, máximo de dos activas, revocación, caducidad y
purga owner-scoped están probadas. SARIF 2.1.0 valida offline contra el esquema
OASIS fijado, y políticas/baseline explican códigos 0/8/9 sin falsos verdes. No
se ejecutó CI remoto.

## Vertical 3 — ciclo de vida SBOM

CycloneDX/SPDX se preflightan sin persistir documento o identidades y sin
egress; un token owner-scoped, digest-bound, single-use y de 300 s enlaza la
atestación con los mismos bytes. Las revisiones compatibles avanzan el mismo
proyecto de forma atómica e idempotente, conservan historial/comparación y
limpian fuentes/jobs ante fallo. El grafo diferencia relaciones reportadas,
ausentes o truncadas y la interfaz ofrece acciones distintas para archivo y
SBOM.

## Vertical 4 — portada por intención

La entrada principal prioriza Archivo, CI y SBOM, muestra hasta tres proyectos
recientes y relega administración y auditorías especializadas a disclosures.
Archivo/SBOM se alcanzan con una acción; CI explica el prerrequisito o abre el
workspace con foco y deep link. La revisión reproducible en 1440, 768 y 320 px
midió cero overflow, CTA de 44 px y consola limpia. Detalle y capturas locales
ignoradas en `docs/frontend-visual-review.md`.

## Validación acumulada del Ciclo 7

- Backend: 1.117/1.117; la validación detectó y corrigió una proyección pública
  que incluía el campo interno de idempotencia SBOM y dos puertas operativas
  ancladas al antiguo total de clases de retención.
- Runner y guardas: 424/424. CLI: 34/34. Frontend: 48 archivos/322
  pruebas, incluidas axe, primera visita, recurrente, foco y teclado.
- TypeScript/build: bundle inicial 328.334/329.728 bytes; la guía de entrada se
  carga en un chunk separado en vez de elevar el presupuesto.
- Dependencias: cinco locks Python y el lock npm sin vulnerabilidades conocidas
  en las auditorías ejecutadas. Compose base, privado, aceptación y egress
  renderizados; canario Gitleaks detectado; `compileall` y `git diff --check`
  correctos.
- Artefactos CLI finales: wheel
  `c269cb60f144f843ef9c0b7936c33fd7fde5986d1f5cd9210a05857f627a7b0e`,
  sdist `17d496f21a40824762fb7dadb19ce83f3415fa6a5696c34964a23627f2b364eb`
  y SBOM `0a04dc27d39d082ff767a4c4ac3b905f7502035820488705751145dec56726ae`.
  Se verificó `SHA256SUMS` y la instalación aislada de ambos formatos.
