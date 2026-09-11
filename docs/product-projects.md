# Project sources and immutable snapshots

Este es el flujo principal de la candidatura `0.3.0-beta.1`, técnicamente
validada en un PR borrador pero todavía sin tag, release ni publicación: fuente
autorizada → snapshot inmutable → ejecución limitada → inventario/cobertura →
hallazgos → comparación e informe. Ningún canal ejecuta el proyecto ni acepta
una ruta del servidor o URL de repositorio aportada por el usuario.

## Cartera global y priorización explicable

`POST /projects/portfolio/search` construye la vista global de la organización
activa sin aceptar propietario, URL ni identificadores de proyecto en la
consulta. El cuerpo usa filtros cerrados (`priority`, `severity`, `source_type`,
`operational_state`, `coverage`, `public_intelligence`, `baseline` y
`responsibility`), búsqueda exacta o por prefijo y una página de 1–100
proyectos. Los cursores están firmados, ligados al propietario, filtros y
contenido observado; cambiar la cartera durante la paginación produce `409` y
obliga a empezar una instantánea coherente. Ni los filtros ni el cursor se
incluyen en la URL.

La prioridad no es una puntuación. El contrato `2026-09-10.2` ordena señales
visibles: KEV, severidades, fallo de la última ejecución, pérdida de cobertura,
hallazgos nuevos, datos públicos caducados/degradados, revisiones de excepción,
triage pendiente, ausencia de baseline o de ejecución reciente. KEV se cuenta
aparte de CVSS. Una reducción de cobertura o dos ejecuciones incompatibles
invalidan la lectura de mejora y nunca generan un total de «resueltos» fiable.
Los contadores de cobertura muestran sus denominadores de manifiestos y
lockfiles; un estado parcial, desconocido o caducado sigue visible como límite.

La responsabilidad actual se deriva únicamente de asignaciones de hallazgos
locales abiertos y se revalida contra los miembros activos. No equivale todavía
a un responsable estable del proyecto ni cubre el triage de vulnerabilidades
públicas; esas capacidades se mantienen como tareas explícitas del centro de
remediación. Cada snapshot nuevo conserva un canal cerrado fijado por el
servidor: `archive_upload`, `git_cli`, `ci` o `sbom`. La ruta no acepta este
valor desde el cliente. Una credencial de automatización vigente atesta `ci`;
la ruta inicial cerrada, autenticada mediante sesión o grant de un uso, atesta
`git_cli`; los endpoints de archivo y SBOM fijan sus valores respectivos. La
ingesta Git se construye localmente y nunca acepta URL o credenciales de
repositorio; su decisión de amenaza se documenta en
[`repository-ingestion.md`](repository-ingestion.md). En registros históricos con
commit que preceden a este contrato no es posible distinguir de forma fiable
Git/CLI de CI: la cartera conserva `unknown_git_or_ci`, explica la ambigüedad y
nunca adivina ni migra el canal por heurística.

La cartera admite como máximo 20.000 proyectos por organización y 10.000
hallazgos por análisis. Una proyección SQLite privada y reconstruible conserva
solo IDs opacos, digests autoritativos, contadores y estados cerrados. No guarda
nombres, rutas, componentes, evidencia ni texto libre: la búsqueda exacta o por
prefijo usa tokens HMAC separados por organización y el orden alfabético usa un
ordinal, ambos con clave efímera de proceso. Cada tarjeta devuelta se vuelve a
construir desde los registros autoritativos y se compara por digest antes de
responder. Filtros, orden, resumen y página se resuelven en SQLite; una revisión
de fuente, un límite temporal, reinicio o inconsistencia fuerzan reconstrucción,
y una corrupción semántica no puede producir silenciosamente una tarjeta limpia.

El índice está limitado a 256 MiB y la primera petición tras un reinicio realiza
una reconstrucción síncrona; es un acelerador, no fuente de verdad ni mecanismo
de autorización. Superar 20.000 proyectos falla de forma controlada. Remediación
y tendencias conservan su límite independiente de 5.000 proyectos hasta que sus
propias proyecciones cubran ese volumen; elevar la cartera no amplía esos dos
agregados. Los presupuestos de la prueba sintética de 20.000 proyectos y dos
organizaciones son reconstrucción <60 s, p95 caliente <1 s y memoria Python
incremental <64 MiB. Son guardas de regresión locales, no un SLA de producción.

## Bandeja pasiva durable de acciones

`GET /projects/actions` reconcilia la cartera autoritativa de la organización
activa y devuelve recordatorios cerrados de riesgo, cobertura, frescura,
ejecución y triage. Esta bandeja es exclusivamente **pasiva** y no es la action
inbox de Active operations. Ordena primero los avisos no leídos y después la
prioridad explicable; `unread_only=true` limita la vista sin borrar estado.
Cada tarjeta abre el proyecto actual y ofrece una acción independiente para
marcar el aviso como leído mediante `PUT /projects/actions/{id}/read`.

El store `2026-09-10.1` conserva por organización un máximo de 2.000 eventos:
ID opaco, proyecto/análisis opacos, motivo/prioridad/destino cerrados, fecha y
marcas de lectura derivadas por SHA-256 para un máximo de 100 lectores. Nunca
persiste nombres, rutas, evidencia, componentes, advisories, texto libre,
fuente o secretos. El nombre de proyecto mostrado se une desde la cartera solo
al responder. Un análisis distinto genera un evento distinto; si la señal
desaparece, la reconciliación elimina el aviso. Borrar un proyecto elimina sus
avisos y marcas de lectura dentro de la cascada recuperable.

Un reader puede consultar y marcar sus propios avisos como leídos con CSRF,
pero solo maintainer/administrator puede ejecutar la reconstrucción explícita
`POST /projects/actions/rebuild` con `rebuild_confirmed=true`. La
reconstrucción recupera señales desde la cartera y reinicia las marcas de
lectura; se usa únicamente ante corrupción o recuperación operativa. Un store
inválido falla cerrado con `503`, sin exponer su contenido. Las respuestas usan
`private, no-store`; llegar al límite devuelve `source_complete=false` y la UI
no presenta el subconjunto como completo.

## Listado operativo paginado

`POST /projects/search` es el contrato `2026-09-09.1` para descubrir proyectos
de la organización activa. Acepta únicamente `page_size` (1–100) y un cursor en
el cuerpo, devuelve total exacto y una página ordenada por actualización. El
cursor está autenticado, ligado al propietario y a la revisión del directorio;
una escritura concurrente lo invalida con `400` para evitar mezclar páginas. No
se coloca en URL ni access logs. `GET /projects` queda deprecado y limitado a
los 100 primeros registros, con `X-Inspectra-Total-Count` y
`X-Inspectra-Truncated`; no debe usarse para enumeración completa.

El índice SQLite privado es reconstruible y conserva solo IDs opacos,
propietario, tiempo, digests de integridad y las relaciones ya digestadas de
baseline/fuente. No incluye nombre de proyecto, filename, hallazgos, código o
evidencia. Cada fila seleccionada se contrasta con el JSON autoritativo y el
owner antes de responder. La interfaz carga 50 proyectos y continúa bajo
demanda; los enlaces profundos resuelven un proyecto directamente y no fuerzan
la descarga de páginas intermedias. Los cursores expiran al reiniciar el backend.

Inspectra now has an initial product workflow for analyzing a source snapshot as a project. It is deliberately archive-backed: an operator uploads a ZIP, TAR, TAR.GZ, or TGZ that passes the existing content validation, then selects **Create project & analyze** from that archive.

The action creates a project record and immediately queues one `project_archive_basic` review. Internally, the project retains the source filename, SHA-256 snapshot, creation time, owner, and linked first job for integrity and recovery. Product-facing responses do not publish the source name or digest: a short `snapshot-…` reference derived from the internal source ID identifies the same input without being a content hash. Original upload metadata remains available only in the owner-scoped **Files** flow.

Project, snapshot and project-analysis responses also omit the internal source
file ID. The owner-scoped **Files** response carries both its actionable file ID
and the derived `snapshot-…` reference, allowing the UI to exclude an already
retained upload without leaking that ID into project history or exports.

## Supported flow

1. Upload an archive you own or are authorized to assess.
2. Read the passive-analysis boundary and explicitly confirm that you own or
   are authorized to analyze that archive as a project.
3. Select **Create project & analyze** in that archive's actions.
4. Inspectra records the immutable SHA-256 of that upload, creates the project, and queues the passive project-archive analysis.
5. Follow its safe source reference and state in **Projects**, or open the linked job to view the redacted result and existing exports.

### Guided project entry

The dashboard begins the project path with **Analyze an authorized source
snapshot**. Select **Prepare a project archive** to switch the upload control to
the Archive type and focus the file picker. After the upload, use the archive's
**Create project & analyze** action and its authorization confirmation. The
guide distinguishes this path from individual file and target-based reviews: it
does not execute project code, install dependencies, clone repositories, or
send source contents to a public vulnerability provider. Only an explicit
vulnerability-intelligence action on an eligible retained project can use the
separately configured public egress policy.

After a project execution is terminal, **Run again** queues a new `project_archive_basic` job against the same retained source snapshot. Every such job records the project ID, source SHA-256, and analysis profile so the result remains attributable to the exact input. Its repeat endpoint accepts no request fields: an unexpected body is rejected with the same generic validation response used elsewhere, rather than being silently ignored. Inspectra refuses a duplicate while another analysis of the same project is queued or running.

### Probar sin código propio con una muestra sintética

Para conocer el recorrido sin arriesgar una fuente real, use de forma opcional
un archivo de `tests/fixtures/demo/passive-alpha/archives/`, empezando por
`demo-archive-app-config.zip`. Es material sintético del checkout local: la
interfaz no lo busca, lee ni carga automáticamente. Seleccione manualmente
**Archive**, elija ese ZIP y siga la misma confirmación de autorización que se
exige para una fuente propia.

El resultado esperado son indicadores pasivos y, en las muestras de redacción,
`[REDACTED]`. No es una demostración de CVE, explotación, credenciales válidas
ni seguridad del archivo. Al terminar, use **Delete** en la fila de **Files**
para borrar los bytes cargados y borre los trabajos de demostración que no
necesite. Desde el workspace también puede revisar y confirmar **Delete project
data** para eliminar el proyecto y todos sus derivados. Esa cascada conserva
deliberadamente la subida original, que mantiene un ciclo de vida independiente
en **Files**; `PROD-120` sigue cubriendo una futura purga integral de fuente y
verificación operativa de copias externas antes de prometer borrado total.

### Preview coverage before uploading

When **Archive** is selected, the dashboard loads `GET
/project-analysis-preflight`. It is a source-free capability catalog, not an
archive inspection: it accepts neither query fields nor a request body, and it
does not receive a filename, local path, hash, project ID, source byte or
credential. The catalog reports the configured upload limit, accepted archive
types, currently parsed manifests (`package.json`, `requirements.txt`,
`pyproject.toml` and `Pipfile`), and the deliberately narrow exact-resolution support for a
same-root npm v2/v3 `package-lock.json`, pnpm v9, Yarn Classic v1 `yarn.lock`
and Poetry `poetry.lock` format 2.1 or Pipenv `Pipfile.lock` format 6. The latter
four are explicitly local-only
and cannot enable public-advisory traffic. It also names currently detected but
not resolution-capable lockfiles so a developer is not promised unsupported
coverage.

The preview never executes, extracts, hashes, installs, uploads, or sends a
selected archive to a public service. Defensive runner limits still apply, but
the preview cannot determine whether a particular archive will hit one; the
retained analysis is the only source of actual coverage. If the catalog cannot
be loaded, the interface keeps the safe archive-upload action available and
states that actual limits and coverage will be reported after analysis. This
degradation is not a clean or unsupported-project verdict.

To review a correction or a new version under the same project, choose **Add
snapshot** in the project row. Select a different archive that belongs to the
same operator, confirm authorization again, and Inspectra appends immutable
metadata for that source before queuing its analysis. It does not replace the
source attribution of earlier executions. The findings and component-inventory
analysis selectors identify each execution by its derived safe source reference, and the
comparison panel can then compare completed snapshots. A duplicate archive hash
is not added again; use **Run again** to repeat its existing snapshot instead.

The browser creates one opaque 128-bit idempotency key when the operator submits
a new snapshot and reuses it after an uncertain request failure. The backend
stores only its SHA-256 digest in a private recovery journal. Project metadata,
the immutable snapshot and the queued job use identifiers fixed by that journal:
two concurrent copies of the same request return the same operation, and a
restart completes a write interrupted between project and job persistence
before dispatching it. Reusing the key with a different source is rejected.
The journal contains no source filename, path, code or raw key.

El journal `2026-09-09.1` conserva también el canal cerrado antes de escribir el
snapshot. Replay, recuperación tras reinicio y backup/restore preservan el
primer valor retenido: volver a enviar la misma operación por otra clase de
credencial no reetiqueta el origen. Los journals `2026-09-06.1` siguen siendo
recuperables y sus snapshots con commit se presentan como
`unknown_git_or_ci`. La UI muestra el canal en el historial, la cartera y los
informes sin exponer filename, ruta, digest ni credenciales.

`INSPECTRA_PROJECT_MAX_SOURCE_SNAPSHOTS` bounds total immutable snapshots per
project to 100 by default (allowed range 1–10000). Reaching the limit returns a
controlled error and never evicts history; preserve that project and create a
new one for later snapshots. This is a storage/admission boundary, not a tenant
quota or billing control.

### Verificar una corrección local

En el detalle de un hallazgo y en su comparación, Inspectra presenta una guía
de corrección solo cuando el resultado retiene una recomendación o una
referencia pública canónica validada. **Copy recommendation** copia únicamente
esa recomendación, no la evidencia redactada ni la ubicación del hallazgo. Las
referencias se vuelven a validar en el navegador contra las formas HTTPS de
NVD/CVE, GitHub Advisories u OWASP antes de convertirse en enlaces; una
referencia heredada o malformada no crea una acción externa.

La guía es una ayuda para revisar el cambio local: no demuestra explotación ni
que una modificación resuelva el hallazgo. Tras corregir un proyecto autorizado,
el control **Review a new snapshot** lleva a **Add project snapshot**. Elija un
archivo distinto que esté autorizado, confirme el alcance y espere a que termine
la nueva ejecución; después compare ambas instantáneas. Inspectra no edita
código, no abre archivos locales desde ese control y no envía datos adicionales
a un tercero.

The project API is owner-scoped. In local and single-admin modes that boundary
is the current operator. In `private_team_lightweight_users` it is the active
organization carried by the server-side session: files, jobs and projects
materialize the same `organization_id`, and a mismatch with the historical
`owner_id` fails closed. A project can only be created from an archive in the
active boundary, and project list/detail endpoints do not disclose another
workspace's projects or linked jobs. Switching workspace revalidates membership
and rotates session/CSRF before any new list is loaded. This applies equally to
adding a snapshot. Cookie-authenticated deployments require the existing CSRF
header for every change.

Project creation and new snapshots require the boolean
`authorization_confirmed: true` in the request. This is intentionally a
short-lived confirmation, not a free-text attestation: Inspectra stores no
additional justification, source path, code or personal data for it. A missing
or false value is rejected before a project, snapshot or job is created.

The create, repeat, add-snapshot and source-delete mutations are covered by a
backend route contract and ASGI matrix. In cookie-authenticated deployments,
each requires a valid session and CSRF token before it reaches storage; a source
or project owned by another operator returns a generic not-found response.
Malformed IDs and unexpected request fields are rejected without echoing their
values, including in the validation response.

## Deterministic project acceptance check

The focused acceptance scenario is part of the ordinary backend suite and uses
only in-process ASGI, synthetic ZIP bytes and a no-op analysis adapter:

```bash
python -m pytest backend/tests/test_backend.py -k project_workflow_acceptance -q
```

It checks the source-free preflight, archive upload, rejected missing scope
confirmation, authorized project creation, queued-to-completed fixture result,
normalized findings, inventory, redacted Markdown report, authorized second
snapshot and comparison. It does not execute archive code, wait for an external
worker, contact advisory providers or use production data. The separate frontend
suite verifies the controls and rendered states against API doubles; this test
protects the server-side workflow and data boundaries deterministically.

## Project workspace

Select **Open workspace** from a project row to keep the current source state,
safe next action and retained execution timeline together. The workspace shows
only the count of snapshots, derived `snapshot-…` references, status details and retention
markers already available to that owner. It does not fetch source bytes or
repeat source filenames in historical entries. A removed source is distinct from
its retained redacted result, so a completed report can still be opened while
the interface accurately says that the original archive is gone.

## Explicit boundaries

This first vertical does **not** accept a server filesystem path, repository URL, Git credential, SSH key, token, or arbitrary checkout. Those inputs would require a separate isolation, credential, host-allowlist, resource-limit, and cleanup design before they are safe to support.

The workflow also does not execute project code. It reuses the existing bounded passive project-archive analyzer and its redaction policy. Results remain review indicators with their reported coverage and limits, not an assertion that a project is secure, vulnerable, or exploitable.

La ejecución de proyectos dispone de cancelación cooperativa local. El estado
solo pasa a `cancelled` después de detener la tarea y limpiar su workspace; el
resultado parcial no se conserva. Esta garantía corresponde al despliegue
actual de un único proceso backend y no equivale a cancelar un worker remoto o
distribuido.

Project and job histories expose a stable, safe status detail for queued,
running, completed, generic failure and restart-interrupted work. It contains a
short next action such as waiting, viewing retained results or reviewing before
retrying; it never repeats a traceback, host path, command output or source
content in a list summary. A retry remains available only after a terminal state
and uses the recorded source snapshot when that source is retained.

## Execution profile and reproducibility

Before an archive is selected, `GET /project-analysis-preflight` publishes the
closed, source-free profile catalog. The current safe default is
`project_archive_basic`: supported manifests select only backend-owned rule
packs for npm, PyPI, Go, Rust, PHP, JVM, .NET, or a mixed repository. The declaration includes its
profile/ruleset versions, rule families, applicable stacks, explicit exclusions
and effective execution ceilings. The endpoint accepts neither selectors nor a
body and does not inspect a source. An unknown profile cannot be requested or
silently substituted.

This profile covers bounded archive safety, manifest parse integrity,
dependency repeatability/source boundaries, package-execution indicators,
multi-ecosystem coverage and a bounded sensitive-data review. The latter reads
only supported UTF-8 configuration candidates, never reads real `.env` files,
and retains redacted evidence plus a safe project-relative file/line when one
can be demonstrated. Its status and examined/skipped/truncated counts are part
of the result; an omitted or partial candidate is never treated as clean.

The profile does not execute code, scripts, hooks, installers,
tests or package managers and does not enable network access. Framework,
infrastructure, container, CI/CD, database, proxy and sensitive-data deep
configuration reviews remain separate until a later versioned profile integrates them. The UI
therefore presents this single honest safe default and its exclusions rather
than implying that every detected stack receives a deep review.

The same profile now includes the existing bounded Dockerfile/Compose,
Kubernetes and Terraform/OpenTofu/Terragrunt rule sets. Each review has its own
file, per-file and total-byte ceilings and reports `completed` or `partial`
independently; a malformed format does not erase the other project results.
Inspectra does not build images, start services, render Helm/Kustomize, contact
a cluster, resolve Terraform modules/providers, read state, or create a plan.
Only aggregate coverage and redacted normalized findings are retained.

Every newly admitted job retains an immutable, versioned **execution profile**.
It records only the non-sensitive contract name, ruleset version, upload limit
and backend audit-concurrency limit that applied when the job was accepted. The
profile is visible to the project owner in the job detail and project reports so
two retained results can be interpreted in their original context even after a
later configuration rollout.

This is deliberately not a process-configuration dump. Since contract
`2026-09-06.3`, file jobs also retain the fixed worker contract version,
transport, lifecycle, concurrency and resource ceilings; the successful result
must attest the same non-sensitive values. The profile never stores host paths,
environment variable names or values, provider
URLs, request headers, credentials, tokens, source contents, source filenames,
or analyzer output. La cola local de proyectos conserva en disco los trabajos que todavía
no habían empezado y los revalida al arrancar, pero no aporta alta disponibilidad,
coordinación multiproceso ni procedencia binaria del runner.

Comparing two current profiles requires the exact same retained profile. A
profile mismatch, or a mix of a profiled record and a legacy record, is marked
**not comparable** rather than silently presenting a regression. Two legacy
records may still use the former comparison contract, but Inspectra displays a
limitation that their effective admission/scheduling limits were not recorded.
Legacy metadata is not retrofilled, and later job updates cannot replace the
profile captured at admission.

## Saved regression baseline

After two compatible project analyses complete, an owner can choose **Save
selected baseline** in the comparison panel. This creates an explicit,
owner-scoped regression policy for that project; it is not inferred from the
oldest result. The selected analysis must belong to the same project and
operator, be completed, and retain an execution profile. A legacy analysis
without that profile must be run again from a retained source before it can be
selected.

The policy has a monotonically increasing version. Changing or clearing it
never rewrites a retained result or its normalized findings; the action is
recorded in the local audit log with opaque identifiers only. Future visits and
history refreshes choose the retained saved baseline by default, while a user
can still make an ad-hoc comparison deliberately. The comparison marks when it
used the saved policy and continues to show all coverage, truncation,
source-retention and profile limitations.

If job deletion or retention removes the saved analysis, Inspectra clears the
policy and records that safe lifecycle event instead of leaving a dangling
reference. Deleting the source bytes alone does not clear it: comparison may
still use the retained redacted results and explicitly says that source coverage
is no longer retained. Project reports disclose only whether a baseline policy
is configured and its version; they do not add a separate baseline analysis ID.

## Retention and deletion

The source upload remains governed by the configured upload retention policy.
Deleting the current source or expiring it marks the current project source and
its linked job source as removed; deleting an earlier source marks only that
retained snapshot. In both cases the redacted job record remains available until
job retention deletes it, so historical comparison and reporting do not claim
the bytes still exist. The project never stores the source bytes, a host path, a
repository address, or a credential.

### Borrado seguro del proyecto y sus derivados

En **Delete project data**, el operador solicita primero `GET
/projects/{project_id}/deletion`. La vista enumera sin nombres de archivo ni
rutas qué se eliminará: metadatos y baseline del proyecto, trabajos terminales
y sus resultados, snapshots normalizados de inteligencia pública, decisiones de
triage, journals de admisión y cualquier workspace opaco restante. Los informes
no son artefactos persistidos; al desaparecer el job dejan de estar disponibles
por API. Antes de ejecutar, la interfaz exige una confirmación explícita.

La cascada no borra subidas. Un mismo archivo puede tener usos independientes y
el proyecto no es autoridad suficiente para inferir que sus bytes pueden
eliminarse. La interfaz declara que las fuentes siguen en **Files** hasta una
eliminación expresa o su vencimiento configurado. También permanecen la caché
pública compartida —sin identidad de proyecto y con TTL propio— y el registro
mínimo de la acción hasta su retención administrativa. Las copias descargadas y
los backups siguen bajo control del operador.

`DELETE /projects/{project_id}` requiere `{"deletion_confirmed": true}`, sesión
y CSRF cuando correspondan. Reader es solo lectura; administrator y maintainer
pueden operar dentro de la organización activa. Un proyecto ajeno y uno ausente
producen el mismo estado idempotente sin borrar datos externos. Si existe un job
`queued`, `running` o `cancelling`, o una admisión pendiente, la preparación se
rechaza: hay que cancelar y esperar un estado terminal.

Antes del primer borrado se escribe bajo el lock de almacenamiento un journal
efímero que contiene solo organización, ID de proyecto, IDs opacos de trabajos,
conteos y versión de contrato. Esa marca oculta el proyecto y hace que nuevas
ejecuciones/snapshots fallen cerradas. Cada derivado se borra antes que el
metadato autoritativo; una interrupción conserva el journal y el siguiente
intento o arranque reanuda la misma operación. Readiness permanece no disponible
mientras quede un journal. Al completar, se elimina el journal y se registra
solo acción, contrato, conteos y IDs opacos; ningún error público o log incluye
la ruta, el contenido o el nombre de una fuente.

## Normalized findings

Project executions retain the source result from each analyzer and, when it
contains compatible findings, add a safe common view for product features.
See the [normalized finding contract](product-findings-contract.md) for its
fields, confidence limits, and public-reference policy.

An imported CycloneDX 1.4–1.6 or SPDX 2.2–2.3 project can retain only exact,
canonical npm, PyPI and supported Maven purls under SBOM import contract
`2026-09-10.1`. Maven is restricted to lowercase `group:artifact` coordinates
and the documented safe ComparableVersion subset; purl qualifiers, subpaths,
URLs, hashes, refs and free metadata are discarded. Import authorization,
operator public-identity attestation, tenant approval and provider egress are
separate gates. The last egress boundary receives only the normalized
ecosystem/name/version tuple and never serializes the internal attestation.

When an operator selects a non-completed attempt, findings, component inventory
and public intelligence use the same closed availability states. `queued`,
`running` and `cancelling` map to `analysis_pending`; `failed` maps to
`analysis_failed`; and `cancelled` maps to `analysis_cancelled`. The last two
are terminal and never instruct the user to keep waiting. Their UI guidance is
to choose a completed snapshot or use the project-history retry action; the
derived responses include the safe job status context but never the stored raw
runner error, source path or source content. A completed historical result that
predates a derived contract remains separately labelled as lacking normalized
findings or component inventory.

## Component inventory

Completed `project_archive_basic` executions now persist a safe component
inventory alongside the redacted result. The **Component inventory** panel lets
the project owner select a retained analysis and review the parsed npm/PyPI
dependency declarations, their dependency group, safe relative manifest path,
and coverage limits.

This is a declared-manifest inventory with two narrow passive resolution paths.
When a `package.json` and a single parsed `package-lock.json` npm v2/v3 share
the same normalized archive root, Inspectra can retain an exact lockfile version
for a matching direct registry dependency. A `pnpm-lock.yaml` is also parsed
only for pnpm lockfile version `9.0`, in the same root, and only yields exact
direct local versions. Its registry origin is deliberately **unverified**: it
never creates a purl, transitive node or public-advisory identity. Each npm
component can instead be paired with a Yarn Classic `yarn.lock` v1 only through
an opaque identifier derived from the same declared selector; Yarn Berry is
detected but not parsed. Yarn Classic is also local-only: its `resolved`,
integrity and selector text never become a purl, graph or public-advisory
identity. Poetry is parsed only when `[metadata].lock-version` is exactly
`"2.1"`, from one same-root `pyproject.toml`; it retains only a normalized PyPI
name and an exact resolved version for a matching direct registry declaration.
It deliberately discards `package.source`, URLs, references, package files,
hashes, dependency edges, groups, markers and content hashes. Duplicate package
versions or missing entries do not resolve a component. Poetry data is therefore
local-only: it creates neither purl, transitive node nor public-advisory
identity. `Pipfile.lock` is parsed only when `_meta.pipfile-spec` is exactly 6
and a single `Pipfile` shares its normalized archive root. It preserves only
normalized PyPI name, exact version and `packages`/`dev-packages` group;
hashes, indexes, sources, URLs, credentials, markers and arbitrary metadata are
discarded. Ambiguous-source and invalid entries are counted without retaining
their identity, and every accepted Pipenv resolution remains local-only with
no purl or advisory egress. Each compatible component declares whether that root relation was
**matched**, has **no matching** supported lockfile, or is **ambiguous**.
Workspaces, duplicated lockfiles and mixed compatible package-manager lockfiles
are ambiguous and never supply a lockfile version. Inspectra never runs npm,
pnpm, Yarn, Poetry nor downloads packages. It includes bounded direct,
transitive and proven optional npm lockfile nodes, while preserving their scope
instead of presenting every resolved package as a direct declaration. Version
ranges without that supported pairing, aliases, workspaces, local paths, VCS
and URL sources remain visible only as non-correlatable source categories; their
specifier is intentionally not retained because it can contain private topology
or credentials. Unsupported, invalid or over-limit lockfiles remain excluded
with coverage counts. Inspectra can run an explicitly enabled,
bounded OSV check only for an exact unscoped npm identity whose same-root
`package-lock.json` v2/v3 records an explicit HTTPS resolution from
`registry.npmjs.org` and which does not match a local private-package rule. A
manifest pin, missing resolution, private scope, alias, custom-registry URL or
configured internal prefix is not public provenance and is never sent. An exact
direct PyPI pin from `pyproject.toml` is separately eligible only when its
normalized name appears in the local operator attestation
`INSPECTRA_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES` and does not match a private
rule; this is not inferred from Poetry or any index URL, and the setting accepts
no URL, path, wildcard or credential. It can then
query an exact Go module only when one supported same-root `go.mod`/`go.sum`
pair agrees on the version and the normalized module path appears in
`INSPECTRA_PUBLIC_ADVISORY_PUBLIC_GO_MODULES`. Go checksums and `replace`
targets are discarded; an unattested, replaced, malformed or unmatched module
remains a local coverage outcome and never becomes an OSV payload. An optional
CI-produced Go graph contract `2026-09-10.1` can refine direct/transitive scope
only after its commit and reproducible source digest match the retained
snapshot. It is capped at 1 MiB, 2,000 nodes and 4,000 edges and must agree with
one same-root `go.mod`/`go.sum`; divergent evidence stays inconclusive. The raw
nodes, IDs and edges are not retained. A graph proves relationship evidence,
not public registry origin, and therefore never bypasses operator or tenant
attestation. Inspectra does not execute Go. It can then
query an exact Rust crate when a supported same-root `Cargo.toml`/`Cargo.lock`
v3 or v4 pair resolves it and the lock entry uses one of Inspectra's fixed
official crates.io source literals. The parser discards source locators,
checksums and dependency edges; Git, path, workspace, alias, alternate registry
and ambiguous versions remain local-only. Cargo is never executed. It can then
accept an optional CI graph contract `2026-09-10.2` bound to the exact commit
and reproducible snapshot. The graph refines direct/transitive scope and
provides only per-component feature/target counts after every node is
corroborated by the official-registry lock inventory. It is capped at 1 MiB,
2,000 nodes, 4,000 edges, 32 opaque targets and 64 features per node. Raw IDs,
feature names, target labels, roots and edges are request-local and never
persisted. Truncation, cycles and divergence remain visible and inconclusive;
the graph never grants public provenance. Cargo is never executed. It can then
query a Composer package only when a same-root `composer.json` and supported
`composer.lock` structural contract agree on an exact normalized SemVer and an
operator explicitly attests the lowercase `vendor/package` as public
Packagist. Any custom `repositories` declaration fails the root closed. The
parser discards `source`, `dist`, references, hashes, aliases and metadata;
Inspectra never runs Composer. It can then query Maven only from exact
lowercase `group:artifact:version` entries in a same-root `gradle.lockfile`
paired with a `build.gradle` or `build.gradle.kts` marker. Inspectra never
evaluates that DSL, never runs Gradle/Maven and never infers public origin from
the lockfile. Egress requires an exact operator attestation in
`INSPECTRA_PUBLIC_ADVISORY_PUBLIC_MAVEN_PACKAGES`; dependency scope stays
unknown because configuration names and graph edges are deliberately not
retained. It can then query NuGet only from one same-root `*.csproj` marker and
`packages.lock.json` v1. The marker is never parsed as MSBuild; target framework
names, requested ranges, hashes, edges and metadata are discarded. A package
must resolve to one supported exact version across every observed target and
must not be a `Project` entry. Public NuGet.org origin is never inferred:
`INSPECTRA_PUBLIC_ADVISORY_PUBLIC_NUGET_PACKAGES` must attest the normalized
lowercase name before the fixed OSV boundary receives `NuGet+name+version`.
The version is first reduced to the bounded NuGetVersion `2026-09-10.1`
identity: one to four numeric segments become canonical three/four-part form,
zero revision and build metadata are omitted, and prerelease comparison is
case-insensitive. Unsupported syntax stays local and inconclusive. This follows
Microsoft's [NuGet version reference](https://learn.microsoft.com/en-us/nuget/concepts/package-versioning)
and the official [`NuGetVersion`](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Versioning/NuGetVersion.cs)
and [`VersionComparer`](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Versioning/VersionComparer.cs)
implementations without loading .NET code.
It can then
corroborate an existing normalized GHSA alias without sending the component or
project to GitHub, and correlate exact CVE aliases against the approved CISA
KEV catalog. It does not query package registries or vendor advisories. An
independently disabled NVD step may send only an exact CVE already retained
from OSV/GHSA; it stores bounded CVSS/CWE/date evidence while leaving CPE
explicitly unmapped, so NVD never establishes package applicability. Unqueried
sources remain coverage limitations rather than an absence of vulnerability.

The `2026-09-10.1` inventory contract records parsed/supported/skipped manifest
counts, parsed/skipped lockfiles, root-pairing counts, truncation and a canonical
Package URL (purl) only for an exact npm/PyPI/Go/Cargo/Composer/Maven/NuGet identity permitted by the local
inventory contract; a Go purl is not public-origin evidence by itself. For one
matched npm v2/v3 lockfile it also exposes bounded direct, transitive and proven
optional registry nodes with opaque graph IDs internally; it retains no lockfile package path,
download URL or integrity value. Reaching a node or edge limit makes transitive
coverage partial. Parsed pnpm v9 and Yarn Classic v1 lockfiles contribute only
a count of local-only direct resolutions, with no purl and no public
provenance. A purl is
local correlation metadata, not an advisory lookup or vulnerability verdict;
ranges and non-registry sources do not receive one. A
zero-component result or partial coverage is not a claim that the source has no
vulnerable dependencies.

### Matrix of package-manager coverage

The component view and project report also expose a small, versioned coverage
matrix. It lists the currently supported npm, Python, Go, Cargo, Composer and Gradle workflows, their
manifest/lockfile pair, parser label, direct/transitive capability and two
separate observations: **manifest** and **lockfile**. `parsed` means that the
retained analysis parsed that kind of file; `detected_not_parsed` means a known
file was seen but was not used to derive versions; `not_detected` is not a
claim that the package manager is absent from the source.

The initial matrix states that `package-lock.json` v2/v3 can provide exact
same-root npm versions and bounded registry transitive nodes. `pnpm-lock.yaml`
v9 can provide exact same-root **local-only direct** npm versions: it has no
transitive graph and never establishes public-registry provenance. Yarn Classic
`yarn.lock` v1 can provide an exact same-root **local-only direct** version only
when its opaque selector matches the declaration; Yarn Berry remains detected
but not parsed. It has no transitive graph and never establishes
public-registry provenance. `poetry.lock` 2.1 puede aportar una resolución
directa local cuando coincide sin ambigüedad con el `pyproject.toml` del mismo
root, pero no demuestra procedencia pública ni habilita egress. `Pipfile.lock`
6 aporta de forma análoga versiones directas agrupadas cuando coincide con un
único `Pipfile` del mismo root; descarta fuente e integridad y nunca habilita
egress. `requirements.txt` y `pyproject.toml` siguen siendo vistas de
declaración salvo los emparejamientos estrechos descritos arriba. El parser
`requirements-lines-v2-hash-summary` añade únicamente evidencia agregada para
pins exactos: estado `hashes_present`, `missing` o `not_applicable`, cantidad de
pins con/sin hash y cantidad de opciones hash admitidas. Los digest, valores de
opciones y referencias URL/VCS/locales se descartan; la presencia declarada de
un hash no demuestra que Inspectra haya descargado o verificado el artefacto. The
matrix exposes controlled reasons such as `ambiguous_root_pair`,
`graph_truncated` or `unsupported_lockfile_parser` instead of a path, registry
URL, integrity hash, package content or parser exception. It is an honest
coverage aid, not a recommendation to enable egress or a vulnerability verdict.

The Gradle row is intentionally narrower than a build-resolution claim:
`build.gradle` and `build.gradle.kts` are passive markers, while a same-root
`gradle.lockfile` contributes exact Maven coordinates with relationship scope
reported as unknown. Unsupported syntax, mixed-case coordinates, dynamic
versions, unknown qualifiers and unmatched roots stay excluded. The reviewed
version subset follows Maven ComparableVersion for numeric components and the
known `alpha`, `beta`, `milestone`, `rc`, `snapshot`, release and `sp`
qualifiers; leading-zero, vendor and range-like forms are not coerced. Public
Maven origin is never inferred and requires a separate exact operator
attestation.

An authorized CI may attach contract `2026-09-10.4` for a single same-root
Gradle build/lock pair. It binds commit and snapshot digest, allows only exact
locked coordinates plus `compile`, `runtime` and `test` scopes, and never
executes the build. The UI and reports label these relationships as CI-reported;
raw nodes, edges and build metadata are not retained. Divergent or truncated
evidence remains inconclusive and does not satisfy public-origin attestation.

The NuGet row likewise reports only passive `packages.lock.json` v1 evidence.
It preserves a direct/transitive label only when every target agrees, withholds
target framework names, and makes version conflicts, local `Project` entries,
unsupported versions and multiple same-root projects non-correlatable. Neither
the project marker nor lockfile proves NuGet.org; exact operator attestation is
mandatory before egress.

Authorized CI may attach NuGet graph contract `2026-09-10.5` before public
intelligence is requested. The artifact is bound to the same commit and
snapshot, covers at most 32 opaque target IDs, and is checked against one
same-root `.csproj`/lock pair. Reachability is verified independently for every
target. Inspectra persists only direct/transitive scope, per-component target
count and an aggregate receipt; framework names, target/node IDs, roots and
edges are withheld. Truncated or divergent evidence remains inconclusive, and
the receipt never proves NuGet.org origin.

### Límite seguro de `pnpm-lock.yaml`

El soporte pnpm implementa únicamente el subconjunto documentado de
[`pnpm-lock.yaml` v9](https://github.com/pnpm/spec/blob/master/lockfile/9.0.md):
`lockfileVersion: '9.0'`, el importador raíz `.` y sus grupos de dependencias
directas. Inspectra rechaza aliases, anchors, tags YAML, claves duplicadas o no
textuales, YAML inválido, otra versión de lockfile y más de 20.000 tokens YAML.
También se aplican los límites generales de bytes y entradas del archivo
autorizado. Solo conserva nombre npm válido y versión semver exacta; descarta
specifier, `resolution`, integridad, tarball, peer suffix y todo registro
transitivo. No ejecuta pnpm ni usa un parser del gestor de paquetes. Un rechazo
se comunica como cobertura defensiva/entrada no válida, nunca como una versión
limpia o una ausencia de vulnerabilidades.

### Límite seguro de `yarn.lock`

El soporte Yarn se limita a la gramática textual documentada de
[Yarn Classic v1](https://classic.yarnpkg.com/en/docs/yarn-lock/), identificada
por `# yarn lockfile v1`. No invoca Yarn ni evalúa YAML. El lector tiene un
límite de 20.000 líneas, rechaza tabulaciones, líneas excesivas o gramática
incompleta y conserva solo nombre npm válido, versión semver exacta y un
identificador opaco del selector. No guarda selector, `resolved`, integridad,
dependencias transitivas, URL, credenciales ni hashes. Una cabecera
`__metadata:` se identifica como Yarn Berry y queda `detected_not_parsed`, no
como Classic v1. Los selectores `npm:`, `patch:`, URL, VCS o locales se ignoran
en vez de inferir una identidad de paquete. Ninguna resolución Yarn se envía a
OSV, GHSA o CISA KEV.

For npm lockfiles, an exact `version` is not enough to prove public-registry
provenance. A linked package, package name that differs from its lockfile path
(alias), VCS locator, local reference or URL outside the fixed public npm
registry category is kept only as `workspace`, `alias`, `vcs`, `local` or `url`.
Its resolved locator, alias target, credentials, host and path are not retained
in the project inventory, public-intelligence snapshot or SBOM export. The UI
shows the category and explains that it is not queried; it does not synthesize a
registry identity from that data.
Inventory APIs are project- and owner-scoped and never return source bytes, raw
results, host paths, lockfile download URLs, integrity strings or original
non-registry requirements.

### Límite de salida para inteligencia pública

La preparación para correlación pública incorpora una política de egress
desactivada por defecto. Sus endpoints son constantes internas HTTPS y no
acepta URL, host, ruta, proxy, credencial o cabecera configurable. Solo podrá
enviar una identidad mínima `ecosistema/nombre-versión` ya normalizada para un
componente elegible; no transmite la instantánea, hash, propietario, rutas,
lockfile, requisito original ni código. El adaptador OSV y la corroboración
GHSA ya funcionan sobre esa frontera. Consulte [la guía de inteligencia pública](public-vulnerability-intelligence.md)
para límites, amenazas cubiertas, configuración segura y la restricción actual
de namespaces npm.

En el espacio de trabajo, la inteligencia pública ya retenida se puede buscar
por advisory, alias, componente, versión o recomendación y filtrar por CVSS,
señal KEV, consenso de evidencia y alcance de la dependencia. Los filtros nunca
solicitan ni revelan el archivo, rutas o la identidad enviada a un proveedor.
La tarjeta mantiene separadas la prioridad CVSS, la señal KEV y la evidencia
OSV/GHSA; sus referencias se abren solo como HTTPS público validado. Estados
`disabled`, `not_requested`, `degraded` y `stale` deben tratarse como cobertura
limitada, no como un resultado limpio.

### Ejecución acotada, cancelación y reintento

Cada análisis de proyecto nuevo conserva un perfil inmutable y no sensible con
la versión de contrato y reglas, tamaño admitido, timeout, concurrencia, cuota
global y por propietario de trabajos en curso, cuota del workspace, expansión,
entradas, manifiestos y lockfiles. La admisión cuenta atómicamente los estados
`queued`, `running` y `cancelling` persistidos; cuando se alcanza un límite
devuelve un `429` recuperable sin revelar conteos ni actividad ajena. Los
estados terminales liberan capacidad sin reservas separadas que puedan quedar
huérfanas tras reinicio. Antes de llamar al
runner, el backend crea una copia en un directorio cuyo único nombre es el ID
opaco de la ejecución, comprueba tamaño y SHA-256 y la deja en modo solo
lectura. Después verifica otra vez los bytes y envía exclusivamente esa fuente,
su tamaño, SHA-256, identidad de archivo y límites seguros; no envía propietario,
proyecto, ruta ni nombre almacenado. `audit-tools` no monta `data/` y no tiene
red de egress. Serializa las fuentes y crea un subproceso efímero en tmpfs con
límites de CPU, memoria, pared, archivos, tamaño, procesos y resultado. El
runner rechaza una petición si sus límites no coinciden con el contrato enviado
por el backend. La vista y el informe muestran el perfil,
inicio, fin, causa terminal y, si existe, el intento anterior.

Un propietario puede cancelar una ejecución `queued` o `running`. La petición
es idempotente: pasa por `cancelling`, interrumpe cooperativamente el trabajo
local, elimina el workspace y solo entonces queda `cancelled`. Reintentar crea
un ID nuevo y enlaza `retry_of_job_id`; nunca reabre ni sobrescribe la evidencia
del intento anterior. Tras reiniciar el backend, un trabajo de proyecto que
seguía realmente `queued` se revalida contra propietario, proyecto, snapshot,
bytes/hash y perfil de ejecución. Si todo coincide, se vuelve a encolar y
aumenta su contador de recuperación; si no, termina
`failed`/`recovery_rejected` sin revelar una causa interna sensible. Un trabajo
que ya estaba `running` o `cancelling` nunca se simula como reanudado: termina
`failed`/`application_restart` y pierde cualquier resultado parcial. En un
apagado ordenado, las tareas locales se cancelan y se esperan antes de registrar
`application_shutdown` y limpiar workspaces. El timeout o la cancelación del
runner mata el grupo de procesos y su limpieza `finally` elimina el tmpfs.

Los contenedores base añaden límites de CPU, memoria y procesos y filesystem
raíz de solo lectura. `network-tools` está separado y es el único runner pasivo
con egress; rechaza archivos y no monta datos. La cola durable sigue siendo
local a un único proceso y el subproceso de fuente no obtiene un cgroup o VM
propios. Por tanto, esta frontera elimina la lectura transversal del volumen y
acota cada intento, pero no debe presentarse como multiempresa fuerte antes de
`PROD-012` ni como resistencia a un escape del runtime/kernel.

### Preparación local de versiones para inteligencia pública

Antes de activar una fuente externa, Inspectra dispone de un comparador local y
determinista para identidades exactas. Para npm acepta únicamente versiones de
release `major.minor.patch` (la metadata `+build` no altera su orden) y conjuntos
conjuntivos de comparadores `=`, `<`, `<=`, `>`, `>=`; los rangos con `^`, `~`,
comodines, disyunciones, rangos de guion o pre-releases quedan como
**unknown/not comparable**. La gramática completa de npm es más amplia, como
documenta [npm semver](https://docs.npmjs.com/cli/v6/using-npm/semver/), por lo
que Inspectra no la coacciona en esta fase.

Para PyPI usa el parser PEP 440 de
[PyPA Packaging](https://packaging.pypa.io/en/latest/specifiers.html) para un
subconjunto explícito de `==`, `!=`, `<`, `<=`, `>`, `>=` y `~=`. Versiones con
epoch o segmento local se comparan de forma determinista; pre-releases,
comodines, igualdad arbitraria y sintaxis inválida siguen siendo **unknown**.
Ese estado nunca se traduce a «sin vulnerabilidades» y no abre red.

## Explore findings

From **Projects**, select **Findings** for a project to open its latest
completed analysis with normalized findings. The explorer lets you choose any
retained project execution, search by rule, file, evidence, or recommendation,
and combine severity and category filters. It shows a per-severity summary,
coverage warning when the analyzer reports a truncated result, and an
expandable detail with the safe location, remediation guidance, and approved
public references.

The explorer only receives the normalized, redacted representation; it does
not fetch an archive, raw analyzer result, secret, host path, or another
operator's execution. If a project has no completed analysis, is still
running, or has no compatible findings, it explains that state and offers the
appropriate next step. The selected project is reflected in the browser URL
fragment so returning to the Projects view restores the same context; access
control is always enforced again by the API.

## Compare retained executions

Once a project has two completed executions, the **Analysis comparison** panel
selects a baseline and a later comparison snapshot from that project's retained
history. When configured, its saved regression baseline is selected by default;
otherwise the comparison is explicitly ad hoc. It reports **new**, **resolved**,
and **persistent** normalized indicators and makes a severity change visible
without treating it as an exploitation verdict. You can open either selected
full analysis when more analyzer-specific context is needed.

Inspectra refuses a comparison across projects or operators. It also does not
compare executions with different analyzer types or profiles, missing
normalized views, unfinished work, or a missing/changed recorded coverage
summary. For archive analyses, the comparison checks aggregate counts of
entries, manifests, lockfiles and dependencies together with the recorded
limit-reached state. If any of those change, it displays both safe coverage
summaries and does not label a finding **new** or **resolved**: the absence may
only reflect reduced or different analysis coverage.

The later deletion of archive bytes is deliberately not treated as a change to
what the already retained analysis covered. It remains a visible limitation
and is shown independently in both coverage cards, while comparison continues
from the redacted retained results. No archive paths, names, bytes, provider
data or secrets are included in this coverage decision.

Public dependency intelligence retains a separate, versioned finding identity
for each verified advisory/component/version. It is deliberately independent
from mutable source evidence, so a provider refresh that adds a reference or
changes a timestamp does not manufacture a new finding. The current general
comparison panel still compares normalized passive-analysis findings; future
public-advisory history will use this stable identity rather than an evidence
digest.

Each public-advisory update is also retained as a separate immutable refresh:
the latest view is convenient for day-to-day review, but it never rewrites the
prior normalized evidence. The intelligence panel shows its recorded time,
provider freshness and finding count in a bounded history selector. Viewing an
older refresh makes that context explicit, disables new provider checks until
the user returns to latest, and offers a Markdown export scoped to that retained
refresh. The history stores no source archive metadata or provider payload; its
retention class remains part of the derivative-data policy.

## Export a project report

When the selected execution has compatible normalized findings, the findings
explorer offers two deliberately separate profiles in Markdown, HTML and PDF:

- **Minimal** is the default `GET` export. It contains aggregate risk, workflow,
  coverage and public-intelligence state, but omits project/member names,
  source and analysis identifiers, filenames, paths, evidence, component and
  advisory identities, free-text decisions, credentials, secrets and source
  digests. Its generic filename contains no project identifier.
- **Technical** is available only through a CSRF-protected `POST` containing
  `profile=technical` and the literal confirmation
  `technical_detail_confirmed=true`. In team mode the caller must be a
  maintainer or administrator; a project-bound automation credential needs
  `report:read`. It adds actionable normalized detail, while still omitting
  source bytes, source filenames/content digests, unsafe paths and secrets.

Supplying `profile=technical` as a query parameter does not change a default
download: the `GET` route remains minimal. JSON, SARIF and public-link project
reports are not exposed by this contract; CI SARIF is a separate bounded
integration documented in `docs/ci-integration.md`.

Both export routes validate the project, analysis, and current owner. The
technical profile uses the safe source reference for attribution and export
filenames use opaque project and analysis IDs. Either profile can be created
after the source archive expires because it reads the retained redacted result,
but marks that limitation clearly. A report is a review aid, not a statement
that a vulnerability is exploitable or a remediation is complete. Audit events
record only the format and selected profile alongside existing opaque resource
references; exports are generated in the response and are not retained by the
server.

## Source-specific project actions

Project responses expose the safe discriminator `source_type=archive|sbom`.
It is derived from the retained server-side source contract and does not expose
or trust a user filename in the public view. The frontend uses it to keep
workflows apart: archive projects offer retained ZIP/TAR snapshots and the
project CI wizard; SBOM projects offer only compatible normalized SBOM
revisions. `Run again` selects the retained analysis profile on the backend in
both cases. Older clients can temporarily infer an SBOM from
`analysis_profile=sbom_import`, but new integrations should use `source_type`.

## Cross-project remediation center

`POST /remediation/search` builds an owner-scoped projection from the latest
completed analysis of each project. It groups public findings by ecosystem,
component, canonical CVE/GHSA and one conflict-free fixed target; local findings
are grouped by rule and recommendation. The request accepts only closed filters
in the body, returns at most 100 groups per signed page and rejects a changed
projection with `409`. It never opens source files, executes a package manager,
contacts a provider or treats passive evidence as proof of exposure.

Every group exposes its exact observed versions, affected ranges, candidate
fixed versions, direct/transitive/optional/unknown scopes, current projects,
workflow state, source conflicts and visible priority reasons. CISA KEV remains
an independent exploitation signal and is never used to establish that the
package/version is affected. A conflicting source suppresses the automatic
fixed target. Lost or incomparable coverage suppresses `new`/`resolved`
inferences rather than making a project appear improved.

The correction workflow is append-only. `POST /remediation/actions` accepts one
explicitly confirmed group, its current revision and at most 25 exact
project/analysis/finding selections. The backend resolves every selection again
under the current owner, validates the lifecycle transition and persists the
whole batch or rolls back all new records. It supports both normalized local
SHA-256 IDs and the versioned `pvf_<sha256>` public-finding identity. A `resolved`
decision means **correction awaiting proof** while that finding is still present;
only a later comparable analysis where it is absent verifies resolution.

The UI can export a bounded JSON or CSV plan after explicit acknowledgement
that project names and security metadata are sensitive. Reports include at most
2,000 groups and 5,000 occurrence rows, disclose truncation, use the same owner
and filter boundary, and return a SHA-256 response digest. They exclude source
paths/content, decision comments and actor identifiers. A downloaded report is
an operator-managed sensitive copy and is not persisted by Inspectra.

## Organization risk trends and team profiles

`POST /projects/trends` contract `2026-09-10.2` reads a bounded organization
view from at most 5,000 projects and 250,000 retained completed project
analyses. Its nested fact contract remains `2026-09-10.1`. Historical series
use the private rebuildable `project_risk_trend_index.sqlite3` (schema v2)
instead of loading every result into an HTTP request. A cold or stale HTTP read
records one durable organization-scoped request and returns immediately; it
does not rebuild the projection synchronously. One bounded background worker
claims queued owners, reconstructs a complete tenant partition from job,
project, normalized public-intelligence and lifecycle authority, and publishes
it in one SQLite transaction. Duplicate reads coalesce. A mutation observed
during work queues at most one immediate second pass; continued churn remains
queued rather than monopolizing the worker.

The scheduling performance gate mirrors that lifecycle: startup first creates
and validates the empty trend database through `recover_pending_refreshes`,
then the request-path measurement schedules two previously unseen owners. Both
cold-owner and already-queued passes must remain below 250 ms, use less than
100 ms of process CPU and perform zero authoritative job reads. One-time SQLite
DDL and its mandatory `fsync` remain part of startup/readiness validation, but
not of the HTTP scheduling budget; the separate 60-second rebuild and 64 MiB
memory guards continue to cover the 100,000-analysis materialization.

The response declares operational state (`ready`, `rebuilding`, `stale` or
`failed`) separately from fact state (`current`, `stale` or `unavailable`). A
previous snapshot may remain visible during rebuild, but is explicitly labelled
stale/partial and cannot be exported. With no prior snapshot, the API returns
`202`, no fabricated zero-risk facts and a fixed one-second polling hint. A
controlled failure retains the last valid snapshot and a closed reason code;
`POST /projects/trends/refresh` explicitly retries it. The frontend polls for at
most 60 bounded attempts, then leaves the durable work queued and asks the user
to refresh later.

Interrupted `rebuilding` claims become `queued` at startup and are processed
sequentially. The refresh journal contains only the opaque organization
identifier, opaque source revisions, closed state/reason, timestamps and
counters. A second rebuildable SQLite clock stores only a SHA-256-derived owner
key, monotonic generation, random epoch and digest of content-free directory
metadata. It stores no tenant label, project/component name, path, evidence,
provider response or free-text error. Covered writes to project, job,
normalized PVI, lifecycle/remediation and project-deletion authority update the
clock under the common storage lock, so another organization's mutation does
not dirty this one.

If the clock is absent, corrupt, restored, manually bypassed or interrupted
between authority and clock publication, attribution is deliberately discarded:
reads use one global fallback revision, readiness fails and startup recovery
rotates the epoch, causing lazy rebuilds for every owner. The clock remains a
derived accelerator and cannot make a successful authoritative write fail.
This is a process-local scheduler backed by a durable claim, not a distributed
multiworker queue.

The projection retains opaque job IDs only for sample validation, domain-
separated project references, timestamps, record/profile digests, closed source
and ecosystem dimensions, transition counters, duration samples and exception
review dates. It never retains project or component names, filenames, paths,
source/content hashes, finding IDs or text, evidence, recommendations, comments,
actors or provider payloads. It is capped at 250,000 facts per organization and
256 MiB. Corruption, unsafe permissions/symlinks, schema drift or a concurrent
source change fails closed or queues reconstruction; authoritative JSON remains
the source of truth. Backup/restore validates the private SQLite topology and a
restored process requeues interrupted work before treating it as current. Every
available read revalidates a deterministic bounded sample against authoritative
job digests and accepts a result only while the index file remains stable.

The request accepts only 30, 90 or 180 day periods and 7 or 30 day buckets; no
project identity, cursor or arbitrary query is placed in the URL.

A local change is counted only between consecutive retained analyses with the
same recorded analysis and execution profile, valid normalized findings and
equivalent coverage. Public-vulnerability changes additionally require valid
`ready` snapshots on both sides. Missing predecessors, profiles, changed
coverage, invalid evidence and unavailable public snapshots remain explicit
exclusion counts. A missing or incompatible transition can therefore never be
shown as an improvement. KEV remains a current exploitation signal separate
from CVSS and does not establish package affectedness.

Developer, security and executive tabs render the same response rather than
recalculating independent metrics. The response declares its period,
denominators, exclusions and limitations; time-to-review and time-to-verified-
resolution use only findings first observed in retained evidence during the
selected period. These duration distributions are measurements, not an SLA,
and resolution requires disappearance from a later comparable analysis.

The trend report is available as JSON or bucket-oriented CSV only when the
projection is current. Export requires
explicit confirmation because the priority-project section includes project
names. The response is `no-store`, carries a SHA-256 digest and excludes source
filenames, paths, content, comments, actor identities, credentials and provider
payloads. Inspectra does not persist the downloaded copy.

## Finding collaboration and activity

Finding workflow decisions use the append-only `2026-09-11.1` contract while
remaining able to read legacy `2026-09-06.1` records. A decision may assign one
currently active workspace member and include one redacted comment. Within that
comment, up to five exact lowercase `@username` values may be mentioned; each
must be followed by whitespace or end-of-text and resolve to an active member
of the current workspace. Email addresses are not mentions, unknown or inactive
accounts fail closed, and no mention triggers email, webhook or other external
notification.

The findings response embeds only the ten newest decision events and declares
the exact retained total. Older context is loaded through the owner-scoped
`GET /projects/{project_id}/findings/{finding_id}/activity` endpoint, at most 25
records per page. Its opaque decision-ID cursor must belong to the same validated
organization, project and finding; otherwise the client restarts from page one.
Responses are `private, no-store`, reads create a content-free product-audit
event, and the UI preserves already loaded context if a later page fails.

Comments remain bounded to 1,000 characters and pass through the existing
secret redactor before storage. Activity contains only workflow context already
available within the project boundary; it never includes analyzer source bytes,
paths or raw evidence. Project deletion removes the same validated decision
chain, including comments and mentions, and no separate collaboration database
or orphan notification record is created. This is contextual collaboration
attached to explicit decisions, not a general chat system.

## Stable project responsibility

A project may retain one accountable workspace member independently of any
assignee on an individual finding. `PUT /projects/{project_id}/responsibility`
requires an authenticated administrator or maintainer, CSRF, explicit
confirmation and the project's current `updated_at`; a concurrent project
change returns a conflict and leaves the prior assignment unchanged. The
backend accepts only a currently active member of the same workspace. Readers
can inspect the assignment but cannot mutate it, and automation credentials
cannot use this route.

Responsibility changes are monotonic revisions in the authoritative project
record. The public project view exposes only current state, current opaque
member ID, revision and time; portfolio, remediation and reports resolve an
active username only inside the current workspace. Audit events keep resource,
change/count and revision metadata but not the responsible member ID or
username. The private project index keeps only a domain-separated keyed digest
of the member reference, so a copied index cannot enumerate raw account IDs.

Before member revocation, the administrative preflight reports aggregate
project and Active-asset impact without targets, project names or usernames.
Revocation invalidates sessions and clears each current project assignment
under the membership serialization boundary. Affected projects become
`unassigned_attention`; Inspectra does not choose a replacement silently.
Repeating reconciliation is idempotent. The portfolio, remediation center and
project report label project responsibility separately from finding assignees.

This is accountability metadata, not authorization: assignment grants no
additional access, does not prove that findings were reviewed, and does not
change triage or remediation state. History is bounded to 100 revisions per
project; reaching that defensive limit fails closed pending operator review.

## Declared license inventory and SBOM boundary

Project-archive analysis inventories only root-project license declarations
that match Inspectra's closed, normalized SPDX identifier catalog. Unsupported,
free-form or potentially sensitive text is recorded only as
`unknown_unrecognized_withheld`. An optional operator-owned exact deny list is
captured in the immutable execution profile and can emit a review signal when
the complete normalized expression matches; this is not a legal compatibility
or obligations engine.

CycloneDX and SPDX exports preserve that supported root declaration and mark
every dependency license as unknown (`NOASSERTION` for SPDX). Exact duplicate
dependency declarations from the same manifest are collapsed, while distinct
versions, sources and manifests remain separate. No registry, package manager,
provider or network access is used by this review or export path.

Composer relationship evidence follows the same fail-closed model through the
closed `2026-09-10.3` CI artifact. It is accepted only for one source root whose
manifest roots and locked identities agree exactly. Cycles are handled
iteratively; truncated, unreachable, custom-repository or divergent graphs stay
inconclusive. Only per-component scope/status and an aggregate digest-bound
receipt survive. This evidence never attests public registry provenance.
