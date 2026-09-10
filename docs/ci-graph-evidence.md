# Sobre de seguridad para grafos aportados por CI

El sobre común versionado `2026-09-10.1` permite que Inspectra admita grafos
de relaciones calculados por un CI autorizado sin
ejecutar gestores de paquetes ni código del proyecto. Go (`2026-09-10.1`),
Cargo (`2026-09-10.2`), Composer (`2026-09-10.3`), Gradle
(`2026-09-10.4`) y NuGet (`2026-09-10.5`) comparten únicamente el
siguiente límite de transporte y admisión:

- archivo JSON regular, con un único enlace, sin seguir symlinks y de hasta
  1 MiB, leído una vez desde el mismo inode;
- JSON UTF-8 sin claves duplicadas, SHA-256 aportado fuera de banda y binding
  exacto al commit Git y al digest de la instantánea reproducible;
- destino fijado por organización, proyecto y análisis completado; un replay
  con el mismo digest es idempotente y un artefacto diferente entra en
  conflicto;
- admisión antes de inteligencia pública; una consulta ya materializada
  bloquea cambios tardíos de topología;
- persistencia limitada a campos de relación corroborados y un recibo
  agregado. El JSON, IDs de nodo, raíces y aristas no se conservan.

El sobre no es un esquema genérico. Cada ecosistema conserva una lista cerrada
de claves, productor, identidad, versión, dimensiones, límites y razones de
truncación. Cambiar `ecosystem`, reutilizar un artefacto entre contratos o
añadir metadata produce rechazo. La evidencia tampoco concede procedencia de
registro público ni habilita egress: las atestaciones de identidad siguen un
flujo separado, tenant-scoped y revocable.

## Validación operativa

Los fixtures ordinarios son offline y cubren claves duplicadas, symlink,
hardlink, digest/commit/snapshot distintos, referencias desconocidas, orden no
canónico, truncación, replay, conflicto, PVI previo y aislamiento de owner. La
compatibilidad Go se conserva porque el payload no se reserializa: el digest y
los bytes enviados son exactamente los leídos tras el preflight.

## Productor local de referencia

`inspectra graph --ecosystem go|cargo|composer|gradle|nuget` liga una observación CI ya
saneada al commit y digest del snapshot. Es una transformación pura: no invoca
subprocesos, no abre red y no consulta el checkout. Rechaza metadata libre y
entradas enlazadas o sobredimensionadas, ordena colecciones permitidas, vuelve
a ejecutar el validador cerrado del ecosistema y crea la salida con `0600` y
exclusión mutua (`O_EXCL`). Nunca sobrescribe una salida existente. La etapa que
ejecuta el gestor pertenece al pipeline autorizado y debe producir solo el
subconjunto documentado; Inspectra no automatiza ni oculta esa frontera.

La observación Gradle añade `scope_coverage`; nodos y aristas usan solo
`compile`, `runtime` y `test`. Las coordenadas Maven deben ser exactas y estar
en el lock admitido. No se aceptan configuraciones libres, repositorios, URLs,
rutas, hashes, credenciales, variantes ni DSL. Inspectra persiste únicamente
scope directo/transitivo, número de scopes por componente y un recibo agregado.
Esto acredita relaciones reportadas por CI, no procedencia Maven Central.

La observación NuGet usa como targets únicamente ordinales opacos consecutivos
`t0`…`t31`. Nodos, raíces y aristas declaran el subconjunto ordenado de
targets en que existen; el contrato exige al menos una raíz por target y limita
la evidencia a 32 targets, 2.000 nodos y 4.000 aristas. El backend contrasta el
número de targets y cada identidad exacta contra un único par `.csproj` y
`packages.lock.json` v1 del mismo root, y verifica alcanzabilidad por target.
Solo persiste alcance, número de variantes por componente y recibo agregado:
TFM, IDs, raíces, aristas y topología no sobreviven. No ejecuta restore/MSBuild
ni acredita NuGet.org.
Sus versiones se reducen a la identidad NuGetVersion `2026-09-10.1` antes de
crear el artefacto: uno a cuatro segmentos, ceros/revisión/build metadata
normalizados y prerelease case-insensitive. El servidor exige exactamente esa
forma canónica; una forma inválida o fuera del límite no se adjunta.
