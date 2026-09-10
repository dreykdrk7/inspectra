# Importación segura de SBOM

Inspectra puede crear un proyecto utilizable sin disponer del repositorio a
partir de CycloneDX JSON 1.4, 1.5 o 1.6 y SPDX JSON 2.2 o 2.3. La importación es
offline: no ejecuta el documento, no invoca gestores de paquetes y no realiza
egress.

## Preflight obligatorio

La incorporación comienza con `POST /projects/import/sbom/preflight`. El backend
valida el JSON íntegramente en memoria, sin egress, y devuelve solo formato,
versión y contadores agregados de componentes retenibles, rechazados y límites
alcanzados. No devuelve nombres, purl, rutas, URLs, hashes del contenido ni
metadatos libres; tampoco crea archivos, proyectos o análisis.

El servidor mantiene durante cinco minutos una vinculación efímera y acotada
entre el owner, un token aleatorio y el SHA-256 de los bytes. Solo conserva el
hash del token y el digest en memoria, con un máximo global de 256 admisiones;
al alcanzar el límite expulsa la más próxima a expirar. El token es de un solo
uso y `POST /projects/import/sbom` exige que owner y bytes coincidan exactamente.
Un cambio, expiración, reinicio o balanceo hacia otro proceso obliga a repetir el
preflight. Esta última propiedad es intencionadamente fail-closed; despliegues
con varios workers deben mantener ambas peticiones en el mismo proceso hasta que
exista un store efímero compartido.

La UI solo habilita autorización y atestación después de presentar estos
contadores. Cambiar el archivo invalida inmediatamente la revisión anterior.

## Datos retenidos

El documento original se procesa en memoria bajo el límite global de subida y
no se conserva. La fuente inmutable del proyecto es una proyección JSON
normalizada que contiene únicamente el formato/contrato, contadores y las
identidades exactas npm/PyPI/Maven derivadas de `purl`. El contrato de esta
proyección es `2026-09-10.1`; revisiones anteriores siguen siendo legibles, pero
solo una revisión importada con este contrato demuestra la admisión Maven aquí
descrita.

Se descartan nombres del documento, seriales, namespaces, autores, proveedores,
hashes, licencias libres, rutas, URLs, VCS, `downloadLocation`, referencias y
propiedades. Los purl con qualifier/subpath, sin versión, de ecosistemas no
soportados o ambiguos solo incrementan el contador rechazado.

La relación directa/transitiva solo se afirma cuando existe un camino verificable
desde el componente raíz de CycloneDX o desde `DESCRIBES`/`DEPENDS_ON` de SPDX.
El recorrido acotado admite ciclos y elige la distancia demostrada más corta; un
duplicado conserva la evidencia más fuerte sin multiplicar el componente. Cada
componente declara `relationship_status`: `reported`, `not_reported` o
`truncated`. Sin camino, el alcance se muestra como desconocido y no se usa para
recomendar que se edite una dependencia directa. Se procesan como máximo 10.000
relaciones; si se supera el límite, el alcance de todos los componentes se vuelve
inconcluso aunque su versión exacta pueda seguir siendo correlacionable. Los
identificadores internos usados para calcular el grafo tampoco se conservan.

## Correlación pública

La autorización para importar no autoriza egress. Una segunda casilla permite
al operador atestiguar que las identidades npm/PyPI/Maven retenidas son públicas. Sin
ella quedan no correlacionables. Con ella, la procedencia se etiqueta
`operator_attested_public_sbom`; la política global de namespaces privados y el
egress desactivado por defecto siguen aplicándose. En despliegues multi-tenant,
la aprobación exacta de la organización es una segunda condición independiente.
OSV recibe, cuando se activa por separado, solo ecosistema, nombre y versión
normalizados; la marca de atestación es interna y no forma parte de la petición.

Maven admite únicamente `pkg:maven/group/artifact@version`, sin qualifiers de
purl ni subpath. `group` y `artifact` deben ser lowercase y la versión debe
pertenecer al subconjunto ComparableVersion documentado. Propiedades, URLs,
repositorios, hashes, nombres libres y refs internos se descartan. La relación
directa/transitiva se conserva solo cuando el grafo CycloneDX/SPDX la demuestra;
si falta o está truncado permanece inconclusa. En una organización, la
atestación exacta tenant-scoped sigue siendo obligatoria además de la casilla
del importador y puede revocarse antes de cada lote.

El resultado aparece inmediatamente como análisis completado y funciona con
inventario, hallazgos públicos, baseline e informes existentes. `Run again`
reprocesa la proyección normalizada ya retenida, sin volver a abrir el SBOM
original ni ejecutar un runner.

## Revisiones inmutables

Un administrador o mantenedor puede añadir una revisión desde el workspace del
proyecto SBOM. La revisión debe conservar el formato original (CycloneDX o SPDX),
pero puede usar otra versión incluida en los rangos soportados. No se permite
mezclar una fuente archive con una SBOM ni CycloneDX con SPDX dentro del mismo
historial. La API equivalente es
`POST /projects/{project_id}/sbom-revisions`; acepta credenciales de automatización
limitadas al proyecto con `project:scan`.

Cada petición incorpora una clave de idempotencia opaca. La misma clave y el
mismo contenido normalizado devuelven el análisis ya retenido; una clave
reutilizada con contenido diferente y un digest ya retenido bajo otra petición
se rechazan con `409`. La clave se conserva únicamente como SHA-256 interno y no
se expone en vistas, informes ni integraciones. El archivo original, su nombre y
los campos privados siguen sin persistirse.

El puntero de fuente, el contador y el historial solo avanzan después de crear
un resultado completado válido. Un fallo antes de esa fase elimina el job y la
proyección recién creados. Las revisiones del mismo perfil pueden compararse
cuando la cobertura registrada es equivalente; si cambia o queda truncada, la
comparación se presenta como no comparable para no clasificar ausencias como
resoluciones. Una versión fuera de la lista se rechaza en vez de interpretarse
parcialmente.

La importación no habilita egress. La atestación de identidades públicas se
solicita de nuevo para cada revisión y la política global del proveedor continúa
desactivada por defecto.
