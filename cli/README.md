# Inspectra CLI

`inspectra scan` convierte un commit Git autorizado en una instantánea privada
y reproducible, ejecuta Gitleaks con sus reglas completas y, tras confirmación,
la envía a una instancia de Inspectra. El servidor nunca recibe una ruta local
ni accede al filesystem del desarrollador.

## Instalación local

Requiere Python 3.12, Git y Gitleaks 8.x disponibles en `PATH`:

```bash
python3.12 -m pip install inspectra_cli-0.3.0b1-py3-none-any.whl
python3.12 -m pip check
inspectra --help
inspectra doctor
```

Use únicamente un artefacto entregado por el operador junto con `SHA256SUMS` y,
desde el directorio que contiene ambos, verifique primero
`sha256sum --check SHA256SUMS`. El repositorio incluye una
receta local que construye wheel y sdist dos veces con fecha/orden fijados,
exige igualdad byte a byte, genera un SBOM CycloneDX mínimo y escribe checksums:

```bash
python3.12 -m venv /ruta/temporal/build-env
/ruta/temporal/build-env/bin/pip install -r cli/requirements-build.lock
/ruta/temporal/build-env/bin/python cli/scripts/build_release.py --output /ruta/temporal/dist
```

No se publica ni se firma nada. La procedencia verificable termina en el árbol
local revisado y en los hashes entregados por un canal autorizado. El wheel no
tiene dependencias Python de runtime; instalar el sdist offline requiere que el
entorno de build ya contenga las versiones fijadas en `requirements-build.lock`.
`SOURCE_DATE_EPOCH=315532800` es parte de la receta reproducible.

La CLI no instala ni ejecuta herramientas del repositorio analizado. Gitleaks
es una dependencia operativa deliberada y su comprobación no puede omitirse.
`inspectra doctor` comprueba Python 3.12, Git, Gitleaks, la política empaquetada
y el canario del detector sin leer un repositorio ni contactar al servidor.
La candidatura está validada únicamente en Linux x86_64; consulte la
[`matriz de plataformas`](../docs/cli-platforms.md) antes de usar macOS,
Windows nativo o WSL2.

Antes de leer Git o ejecutar Gitleaks para una subida, la CLI consulta
`GET /client-capabilities`. Ese handshake público no lleva token, nombre de
proyecto, ruta ni metadatos del repositorio y exige coincidencia explícita de
los contratos de snapshot Git, admisión CI, policy y salida. Un servidor
antiguo, no disponible, malformado o incompatible bloquea antes del preflight y
de la subida con una acción concreta. `--dry-run` sigue siendo completamente
local y no consulta al servidor.

Un pipeline que ya haya calculado relaciones Go en su entorno autorizado puede
añadir `--go-graph /ruta/efimera/go-graph.json` junto con `--project-id`. La
opción no ejecuta Go: valida un JSON cerrado `2026-09-10.1`, regular y no
enlazado, de hasta 1 MiB, ligado al commit y al SHA-256 del snapshot que acaba
de construir. El servidor lo adjunta tras completar el análisis y no conserva
sus IDs ni aristas. Consulta el contrato y sus límites en
[`docs/ci-integration.md`](../docs/ci-integration.md#evidencia-opcional-de-relaciones-go).

## Perfiles locales sin secretos

Un perfil evita repetir configuración no sensible. Solo se lee si se indica
`--profile`, `--config` o `INSPECTRA_PROFILE`; el archivo debe ser JSON UTF-8,
regular, no symlink, menor de 64 KiB y, en POSIX, modo `0600`:

```json
{
  "contract_version": "2026-09-08.1",
  "profiles": {
    "equipo": {
      "api_url": "https://inspectra.example.test",
      "web_url": "https://inspectra.example.test",
      "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "policy": "standard",
      "timeout": 180,
      "http_timeout": 15
    }
  }
}
```

Valide la resolución con
`inspectra config show --profile equipo --config /ruta/config.json --json`.
Los campos son cerrados y cualquier clave de token, secreto, contraseña,
credencial, autorización o cookie se rechaza. `INSPECTRA_TOKEN` permanece
exclusivamente en el entorno/almacén de secretos y `config show` comunica solo
si está presente. La precedencia verificable es flag, variable de entorno,
perfil y valor por defecto. Las variables admitidas son `INSPECTRA_API_URL`,
`INSPECTRA_WEB_URL`, `INSPECTRA_PROJECT_ID`, `INSPECTRA_POLICY`,
`INSPECTRA_TIMEOUT` e `INSPECTRA_HTTP_TIMEOUT`.

## Preflight sin subida

```bash
inspectra scan /ruta/al/repositorio --commit HEAD --dry-run
inspectra scan /ruta/al/repositorio --commit <sha> --dry-run --json
```

La instantánea se deriva con `git ls-tree` y `git cat-file`, no desde el
checkout. Solo incorpora blobs regulares rastreados del commit. Excluye `.env*`,
archivos de credenciales/claves, metadatos Git y directorios/artefactos generados
conocidos; symlinks y submódulos no se empaquetan. Un nombre no UTF-8 o ruta
ambigua, un límite superado, un fallo de Gitleaks o un canario no detectado
bloquean la operación.

La CLI nunca ejecuta `git fetch`, no usa el remote ni recibe una URL/token Git.
En clones superficiales, un commit ausente se diagnostica como tal y debe
materializarse fuera de Inspectra antes de reintentar. En clones parciales se
desactiva también el lazy-fetch de objetos prometidos. Una revisión local
desconocida y un blob/árbol ausente o corrupto producen errores distintos sin
mostrar ruta, hash de objeto, remote ni stderr de Git.

El preflight muestra commit, árbol, entradas rastreadas, archivos incluidos y
excluidos, bytes de fuente, tamaño del TAR y SHA-256. El TAR usa orden por bytes
del nombre, tiempo cero, propietario vacío y modos normalizados para que dos
ejecuciones sobre el mismo commit produzcan el mismo digest.

## Crear y analizar

```bash
export INSPECTRA_API_URL=http://127.0.0.1:8000
export INSPECTRA_WEB_URL=http://127.0.0.1:5173
inspectra scan /ruta/al/repositorio
```

Después del preflight se debe escribir la confirmación exacta mostrada. Para un
entorno no interactivo, `--yes` solo funciona junto a
`--confirm-authorized`. `--json` exige esa combinación durante una subida para
mantener stdout como un único documento JSON. HTTP sin TLS se acepta solo en
loopback; otros servidores requieren HTTPS. No coloque credenciales en la URL.

La CLI sube `snapshot.tar` como nombre genérico, crea el proyecto, espera el
trabajo hasta `--timeout` y devuelve un enlace `#project=…&job=…`, el resumen de
hallazgos, cobertura y el estado honesto de inteligencia pública. No activa
egress ni proveedores por sí misma.

Un timeout o `Ctrl-C` conserva el trabajo remoto por defecto y devuelve su enlace
de seguimiento. `--cancel-on-interrupt` solicita una sola cancelación del análisis
recién admitido; si el servidor no la confirma, la CLI lo declara y deja que el
operador compruebe el enlace. La opción nunca cancela una admisión CI marcada
`ci_replayed: true`, porque podría pertenecer a otro reintento idempotente.

## Uso en CI sobre un proyecto existente

El administrador crea una credencial con `project:scan`, `project:read` y
`report:read`, ligada al proyecto de destino. El pipeline la guarda en su
almacén de secretos y ejecuta:

```bash
export INSPECTRA_TOKEN='valor-del-almacen-secreto'
inspectra scan . --commit "$CI_COMMIT_SHA" \
  --project-id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --branch feature/example --yes --confirm-authorized --json
```

`--project-id` cambia a la admisión CI atómica: envía el TAR junto con commit
completo y digest local, y el servidor verifica el digest antes de admitirlo.
La identidad idempotente combina organización, proyecto, commit y digest. Un
reintento del mismo contenido devuelve el mismo análisis (`ci_replayed: true`)
y elimina la subida duplicada; el mismo commit con contenido distinto falla
con conflicto. La rama es metadato informativo validado y nunca concede acceso.
La credencial solo se lee desde `INSPECTRA_TOKEN`, no existe flag para pasarla
como argumento. Rote o revoque el secreto tras exposición o al retirar el job.

La puerta se selecciona con `--policy observe|standard|strict`:

- `observe` no falla por severidad, pero devuelve resultado inconcluso si el
  análisis local está incompleto o truncado.
- `standard` exige inteligencia pública actual, falla ante críticos, KEV o
  hallazgos nuevos altos/críticos respecto de la baseline guardada.
- `strict` aplica el mismo contrato desde severidad alta actual y media nueva.

La baseline se configura explícitamente en el proyecto. Si existe, la CLI usa
la comparación compatible del servidor; si no existe, informa `absent` y no
trata toda la deuda inicial como regresión. Un hallazgo confirmado que viola la
política produce `fail` incluso si otras fuentes están incompletas. En ausencia
de un fallo confirmado, cobertura parcial, resultados truncados, inteligencia
caducada/degradada o baseline no comparable producen `inconclusive`, nunca
`pass`.

## Códigos de salida

| Código | Significado |
| ---: | --- |
| `0` | Dry-run o análisis completado. |
| `2` | Ruta, commit, límites o confirmación inválidos. |
| `3` | Gitleaks falló, el canario no respondió o se detectó un secreto. |
| `4` | Error de transporte o contrato de API. |
| `5` | El análisis terminó fallido o cancelado. |
| `6` | Expiró la espera; el enlace identifica el trabajo que puede continuar. |
| `7` | Error local inesperado, sin detalles sensibles. |
| `8` | La política CI falló por evidencia confirmada. |
| `9` | La política CI es inconclusa por cobertura, frescura o comparación insuficiente. |
| `130` | Interrupción local por teclado. |

Los archivos temporales se crean con permisos privados y se eliminan al salir,
incluidos errores y cancelación. La eliminación lógica no promete borrado
forense en SSD o almacenamiento copy-on-write.

## Grafo Cargo aportado por CI

`--cargo-graph /ruta/efimera/cargo-graph.json` requiere `--project-id` y aplica
el contrato cerrado `2026-09-10.2`. El archivo debe ser regular, no enlazado y
de hasta 1 MiB. La CLI valida commit, snapshot, límites y orden antes de subirlo;
el backend corrobora las identidades contra un único `Cargo.toml`/`Cargo.lock`.
Solo conserva conteos de features/targets y alcance, nunca IDs, nombres de
features, targets o aristas. Véase
[`docs/ci-integration.md`](../docs/ci-integration.md#evidencia-opcional-de-relaciones-y-features-cargo).

## Grafo Composer aportado por CI

`--composer-graph /ruta/efimera/composer-graph.json` acepta únicamente el
contrato cerrado `2026-09-10.3`, ligado al commit y SHA-256 de la instantánea.
El archivo debe ser regular, no enlazado, de hasta 1 MiB y contener como máximo
2.000 nodos y 4.000 aristas canónicas. Solo transporta nombre/versión exacta y
relaciones; no admite repositorios, URLs, rutas, hashes de distribución,
credenciales ni metadata libre. Requiere `--project-id` salvo en `--dry-run`.

## Grafo Gradle aportado por CI

`--gradle-graph /ruta/efimera/gradle-graph.json` aplica el contrato cerrado
`2026-09-10.4`: coordenadas Maven exactas, aristas y scopes `compile`, `runtime`
o `test`, ligados al commit y snapshot. Requiere `--project-id` salvo en
`--dry-run`. No admite rutas, repositorios, URLs, hashes, credenciales ni
metadata libre y no acredita procedencia Maven Central.

## Grafo NuGet multi-target aportado por CI

`--nuget-graph /ruta/efimera/nuget-graph.json` aplica el contrato cerrado
`2026-09-10.5`: paquetes exactos, raíces y aristas asociados únicamente a
ordinales de target opacos y consecutivos `t0`…`t31`. Se liga al commit y snapshot y requiere
`--project-id` salvo en `--dry-run`. No admite TFM, rutas, repositorios, URLs,
hashes, credenciales ni metadata libre; tampoco ejecuta restore/MSBuild ni
acredita procedencia NuGet.org.
El productor convierte versiones admisibles a la identidad canónica
NuGetVersion `2026-09-10.1` (segmentos ausentes/ceros/revisión y metadata de
build) y el upload rechaza cualquier forma no canónica o fuera de rango.

## Preparar artefactos cerrados en CI

`inspectra graph` no ejecuta gestores, comandos ni builds y no lee el checkout.
Recibe un único JSON regular ya generado y saneado por el CI autorizado, añade
el binding exacto y escribe un artefacto nuevo privado sin sobrescribir:

```bash
inspectra graph --ecosystem go --input go-observation.json \
  --output inspectra-go-graph.json --commit "$CI_COMMIT_SHA" \
  --source-sha256 "$INSPECTRA_SNAPSHOT_SHA256" --json
```

Los ecosistemas admitidos son `go`, `cargo`, `composer`, `gradle` y `nuget`. La observación usa
solo `complete`, `truncation_reason`, `nodes`, `roots` y `edges`; Cargo añade
`target_coverage` y `targets`; Gradle añade `scope_coverage` y scopes cerrados
en nodos/aristas. NuGet añade `target_coverage`, targets opacos y asignaciones
cerradas en nodos, raíces y aristas. Cualquier
ruta, repositorio, URL, checksum, comando o clave libre provoca rechazo. El
productor ordena canónicamente, pero no corrige duplicados, identidades,
versiones o referencias inválidas. La salida debe validarse después mediante
el `--*-graph` correspondiente durante `inspectra scan`.
