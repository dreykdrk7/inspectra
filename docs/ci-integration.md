# Integración CI/CD

Los tres contratos de grafo comparten el límite de admisión documentado en
[Sobre de seguridad para grafos aportados por CI](ci-graph-evidence.md). Sus
esquemas de ecosistema permanecen deliberadamente separados y cerrados.

Inspectra analiza el objeto Git exacto del pipeline mediante la CLI. El job no
ejecuta código del proyecto ni gestores de paquetes: deriva una instantánea de
blobs rastreados, aplica exclusiones, exige Gitleaks y envía el mínimo contrato
al proyecto ya autorizado.

## Preparación

1. Crea el proyecto desde una sesión administrativa.
2. Crea una credencial ligada a ese proyecto con ámbitos `project:scan`,
   `project:read` y `report:read`, y una caducidad corta.
3. Guarda el valor mostrado una sola vez como `INSPECTRA_TOKEN` en el almacén
   secreto del sistema CI. Guarda la URL HTTPS y el ID no secreto como variables.
4. Instala una versión fijada de `inspectra-cli` y Gitleaks 8.x desde canales
   aprobados por tu organización; no uses `latest`.

La vista del proyecto ofrece **Connect this project to CI** a administradores.
El asistente crea una credencial ligada al proyecto, la muestra en una fase
única y la elimina del DOM antes de presentar el snippet. El snippet nunca
contiene el secreto: solo referencia `INSPECTRA_TOKEN`. La comprobación final
consulta metadatos retenidos (proyecto, caducidad, revocación y ámbitos) y no
recibe el valor del token ni ejecuta un pipeline. Lectores y mantenedores ven
el requisito administrativo, pero no pueden crear o revelar credenciales.

El canal de admisión no forma parte del formulario ni de la CLI. El backend
atesta `ci` únicamente cuando la petición de commit está autenticada con una
credencial de automatización efectiva y ligada al proyecto. La misma ruta bajo
una sesión interactiva queda `git_cli`; un campo adicional enviado por el
cliente no puede fingir ninguno de los dos estados. Replay y recuperación
conservan la primera atestación. Los snapshots con commit creados antes del
contrato `2026-09-09.1` permanecen `unknown_git_or_ci`.

La URL insertada se obtiene de la configuración del operador y se acepta solo
como HTTPS, o HTTP en loopback para desarrollo. No se admiten credenciales,
query, fragmento, controles o espacios en esa URL; el ID de proyecto debe ser
el identificador interno esperado. Si el operador configuró un valor inseguro,
el asistente se niega a generar el snippet.

## GitHub Actions (ejemplo, no activado por el repositorio)

```yaml
permissions:
  contents: read
jobs:
  inspectra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<commit-fijado>
        with:
          fetch-depth: 1
          persist-credentials: false
      - name: Inspectra policy gate
        env:
          INSPECTRA_API_URL: ${{ vars.INSPECTRA_API_URL }}
          INSPECTRA_TOKEN: ${{ secrets.INSPECTRA_TOKEN }}
        run: |
          inspectra scan . --commit "$GITHUB_SHA" \
            --project-id "${{ vars.INSPECTRA_PROJECT_ID }}" \
            --branch "$GITHUB_REF_NAME" --policy standard \
            --yes --confirm-authorized --format sarif \
            --output inspectra.sarif
```

El ejemplo no concede `security-events: write` ni sube el SARIF: cada operador
debe revisar su política de retención y decidir el destino. Nunca imprimas el
entorno, habilites trazas de shell o pases el token como argumento.

## Pipeline genérico

```bash
set +x
test -n "$INSPECTRA_TOKEN"
inspectra scan . --commit "$CI_COMMIT_SHA" \
  --project-id "$INSPECTRA_PROJECT_ID" --policy standard \
  --yes --confirm-authorized --format json --output inspectra-result.json
result=$?
case "$result" in
  0) echo "Inspectra policy passed" ;;
  8) echo "Inspectra policy failed" ;;
  9) echo "Inspectra result is inconclusive" ;;
  *) echo "Inspectra execution failed ($result)" ;;
esac
exit "$result"
```

El pipeline conserva el análisis remoto si la espera vence o el proceso recibe
`Ctrl-C`, y los códigos 6/130 incluyen el enlace para seguirlo. Cuando liberar
esa cuota sea preferible, añade `--cancel-on-interrupt`: la CLI hará una única
petición de cancelación owner/project/analysis-scoped y declarará
`confirmed_cancelling`, `confirmed_cancelled` o `not_confirmed`. Nunca cancela
un análisis devuelto como replay idempotente (`skipped_replayed`), ya que otra
ejecución podría estar esperando el mismo trabajo. Un 401/409 durante esa
petición no reemplaza el código original ni imprime el cuerpo del servidor.

JSON y SARIF están versionados; Markdown está orientado a revisión humana. El
SARIF declara la URI oficial OASIS 2.1.0 Plus Errata 01 y la suite lo valida
offline contra una copia exacta fijada por SHA-256; su procedencia y términos
están en `cli/tests/fixtures/SARIF_SCHEMA_NOTICE.md`. Las
rutas solo se incluyen si el backend las marcó como relativas seguras. Una
ruta absoluta, traversal o ubicación retenida se omite. Todos los formatos
conservan `fail` frente a evidencia confirmada y `inconclusive` frente a una
cobertura insuficiente; ninguno representa “sin hallazgos” como “seguro”.

## Evidencia opcional de relaciones Go

Un pipeline autorizado puede aportar un grafo Go ya calculado por su propio
entorno con `--go-graph /ruta/efimera/go-graph.json`. Inspectra **no** invoca
`go`, `go mod graph`, scripts ni gestores del proyecto. El pipeline debe crear
el artefacto antes de llamar a la CLI y es responsable de que su origen sea el
mismo commit autorizado. La CLI construye primero el snapshot Git, comprueba el
preflight de secretos y admite el grafo únicamente si declara exactamente ese
commit y el SHA-256 de ese snapshot. El grafo se adjunta cuando el análisis
termina y antes de iniciar inteligencia pública.

El contrato inicial es `2026-09-10.1` y acepta exclusivamente este objeto JSON:

```json
{
  "contract_version": "2026-09-10.1",
  "ecosystem": "go",
  "producer": "go-mod-graph",
  "source_commit_sha": "<sha Git hexadecimal exacto>",
  "source_sha256": "<sha256 del TAR reproducible de Inspectra>",
  "complete": true,
  "truncation_reason": null,
  "nodes": [{"id": "n0001", "name": "example.org/module", "version": "v1.2.3"}],
  "roots": ["n0001"],
  "edges": []
}
```

Las colecciones deben estar ordenadas canónicamente, sin claves duplicadas, y
los IDs solo existen dentro del artefacto. El límite es 1 MiB, 2.000 nodos y
4.000 aristas. Un productor que alcance un límite usa `complete: false` y uno
de `node_limit`, `edge_limit` o `producer_limit`; Inspectra muestra entonces
alcance truncado. La versión inicial requiere exactamente un `go.mod` y un
`go.sum` soportados bajo la misma raíz. Los nodos deben coincidir con identidades
exactas ya presentes en `go.sum`, las raíces con los `require` directos y todos
los nodos deben ser alcanzables. Cualquier divergencia queda inconclusa y no
amplía el inventario.

No incluyas rutas, URLs de repositorio o proxy, checksums Go, ramas, código,
tokens, variables, nombres del proyecto ni metadatos libres. La CLI rechaza
symlinks, hardlinks, tamaño excesivo y binding distinto. El backend no conserva
el JSON, IDs ni aristas: persiste solo los componentes ya corroborados por
`go.sum` y un recibo agregado con contrato, binding, digest, conteos, truncado y
ciclos. El digest del artefacto sirve para idempotencia y auditoría, no demuestra
la procedencia pública de un módulo. El egress posterior sigue exigiendo la
política de operador y la atestación exacta de organización.

## Evidencia opcional de relaciones y features Cargo

Un pipeline Rust autorizado puede aportar con `--cargo-graph` una proyección
generada previamente por su entorno de CI. Inspectra no ejecuta Cargo. La opción
requiere `--project-id`, contrato `2026-09-10.2`, el mismo commit y SHA-256 del
snapshot reproducible, y debe adjuntarse antes de solicitar inteligencia
pública. El servidor exige un único par `Cargo.toml`/`Cargo.lock` v3/v4 del
mismo root y corrobora cada identidad exacta contra una entrada de crates.io.

El JSON cerrado declara `producer: cargo-metadata-graph`,
`target_coverage: all_locked_targets`, `complete`, `truncation_reason`, una
lista canónica de hasta 32 target IDs opacos, hasta 2.000 nodos, 4.000 aristas
y 64 features por nodo. No admite rutas, URLs, registries, checksums, comandos
ni metadatos libres.

Inspectra conserva únicamente alcance corroborado, número de features y número
de targets por componente, más un recibo agregado con digest, commit, contrato,
conteos, ciclos y estado. Nombres de features, IDs de targets/nodos, raíces y
aristas no se persisten ni aparecen en API, UI o informes. Evidencia truncada o
divergente es inconclusa y nunca sustituye la procedencia pública del lockfile.

## Evidencia opcional de relaciones Composer

Para Composer, CI puede generar fuera de Inspectra una proyección cerrada del
grafo ya resuelto y adjuntarla mediante `--composer-graph`. El contrato
`2026-09-10.3` solo admite identidades exactas, roots y aristas canónicas, queda
ligado al commit/snapshot y tiene límites 1 MiB/2.000 nodos/4.000 aristas. La
presencia de repositorios personalizados o cualquier divergencia con el
`composer.json`/`composer.lock` retenido invalida la proyección. El recibo no
prueba procedencia Packagist y debe adjuntarse antes de solicitar inteligencia
pública. Inspectra no ejecuta Composer ni scripts/plugins del proyecto.

## Evidencia opcional de relaciones Gradle

Un CI autorizado puede aportar coordenadas Maven, aristas y scopes cerrados
`compile`, `runtime` o `test`, y transformarlos con `inspectra graph
--ecosystem gradle`. El artefacto se liga al mismo commit y SHA-256 del snapshot
y se adjunta con `inspectra scan --project-id … --gradle-graph …`. Inspectra no
ejecuta Gradle/Maven, no interpreta el DSL y no retiene la topología. El estado
indica si la evidencia CI es completa, truncada o divergente; nunca acredita
que las coordenadas procedan de Maven Central.

## Evidencia opcional de relaciones NuGet

Un CI autorizado puede transformar una observación previamente saneada con
`inspectra graph --ecosystem nuget` y adjuntarla mediante `inspectra scan
--project-id … --nuget-graph …`. El contrato `2026-09-10.5` admite solo
identidades NuGet exactas, IDs de target opacos, raíces y aristas canónicas; se
liga al mismo commit y SHA-256 del snapshot. Inspectra comprueba que los targets
y paquetes concuerdan con un único `packages.lock.json` v1 y verifica la
alcanzabilidad por target. No ejecuta restore/MSBuild, no conserva TFM ni
topología y no considera esta evidencia una atestación de NuGet.org.
El productor puro canonicaliza cada versión bajo el contrato NuGetVersion
`2026-09-10.1` y elimina metadata de build; el receptor rechaza versiones no
canónicas para impedir identidades equivalentes duplicadas.

## Verificación y rotación

“Verify setup” confirma únicamente que la credencial sigue vigente, pertenece
al proyecto visible y conserva los tres ámbitos mínimos. No demuestra que el
runner remoto tenga el secreto ni que el pipeline haya ejecutado Inspectra.
Antes de revocar una credencial anterior, crea la sustituta, guárdala en el
almacén del proveedor y ejecuta un pipeline autorizado. La rotación sin corte y
la purga automática de metadatos siguen registradas en `PROD-157`.
