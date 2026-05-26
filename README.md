# Inspectra

Inspectra is a lightweight, open source MVP for defensive and educational local security audits. The current phase focuses on passive PDF, image, dependency manifest, and archive inspection inside Docker containers so audit tools do not need to be installed on the host system.

This project is intentionally small: a FastAPI backend, a containerized tool runner, local job/result storage, and clear boundaries for authorized use.

## What This MVP Does

- Uploads local PDF files through a REST API.
- Uploads local JPEG, PNG, and WebP images through a REST API.
- Uploads local dependency manifests: `package.json`, `requirements.txt`, and `pyproject.toml`.
- Uploads local ZIP, TAR, TAR.GZ, and TGZ archives through a REST API.
- Lists registered local files without exposing host paths.
- Stores uploaded files under `data/uploads`.
- Starts basic PDF, image, manifest, and archive audit jobs.
- Starts project-archive manifest analysis jobs for archives that contain supported dependency manifests.
- Runs passive tools inside the `audit-tools` container.
- Calculates file hashes inside the tool container.
- Stores job state and results under `data/results/jobs`.
- Lists audit jobs with a compact summary.
- Exports job reports as Markdown, HTML, XML, and PDF.
- Exports offline SBOMs as CycloneDX JSON and SPDX JSON from completed manifest and project-archive manifest jobs.
- Deletes uploaded source files while keeping historical job results.
- Provides a minimal React UI for uploads, audits, filters, jobs, readable PDF/image/manifest/archive/project-archive reports, exports, and raw JSON results.
- Exposes OpenAPI docs at `http://localhost:8000/docs`.

## What This MVP Does Not Do

- It does not run exploits.
- It does not scan external networks.
- It does not brute-force, fuzz, or automate aggressive checks.
- It does not install audit tools on the host.
- It does not install dependencies from uploaded manifests.
- It does not execute package scripts or project code.
- It does not extract archives broadly to the filesystem.
- It does not execute, install, or resolve anything found inside archives.
- It does not parse unsupported internal manifest formats beyond filename detection.
- It does not call external services to generate reports.
- It does not call external services to generate SBOMs.
- It does not query external CVE or vulnerability databases yet.
- It does not resolve transitive dependencies or infer installed package versions.
- It does not process targets unless you upload them intentionally.

## Requirements

- Docker
- Docker Compose v2

## Run Locally

```bash
mkdir -p data/uploads data/results
docker compose up --build
```

The backend will be available at:

```text
http://localhost:8000
```

The frontend will be available at:

```text
http://localhost:5173
```

Healthcheck:

```bash
curl http://localhost:8000/health
```

## Configuration

The Docker Compose defaults are intentionally conservative:

| Variable | Service | Default | Purpose |
| --- | --- | --- | --- |
| `INSPECTRA_CORS_ORIGINS` | backend | `http://localhost:5173` | Comma-separated browser origins allowed in development. |
| `INSPECTRA_DATA_DIR` | backend, audit-tools | `/app/data` | Local data mount used for uploads and results. |
| `INSPECTRA_MAX_UPLOAD_BYTES` | backend | `20971520` | Maximum accepted upload size. Default is 20 MB. |
| `INSPECTRA_TOOL_RUNNER_URL` | backend | `http://audit-tools:8081` | Internal URL for the tool runner. |
| `INSPECTRA_TOOL_TIMEOUT_SECONDS` | audit-tools | `10` | Timeout applied to each external tool command. |
| `INSPECTRA_ARCHIVE_MAX_ENTRIES` | audit-tools | `5000` | Maximum archive entries inspected before truncating the result. |
| `INSPECTRA_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES` | audit-tools | `209715200` | Informational archive-size threshold, defaulting to 200 MB. |
| `INSPECTRA_ARCHIVE_MAX_ENTRY_NAME_LENGTH` | audit-tools | `512` | Entry-name length threshold for review findings. |
| `INSPECTRA_ARCHIVE_MAX_LISTED_ENTRIES` | audit-tools | `200` | Maximum archive entries and detected manifests listed in the result. |
| `INSPECTRA_ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES` | audit-tools | `8388608` | Maximum standard ZIP central directory size accepted before detailed ZIP metadata parsing. |
| `INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFESTS` | audit-tools | `25` | Maximum supported manifests parsed from one archive. |
| `INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFEST_BYTES` | audit-tools | `1048576` | Maximum bytes read per supported manifest inside an archive. |
| `INSPECTRA_PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES` | audit-tools | `5242880` | Maximum total supported-manifest bytes read per project archive analysis. |
| `INSPECTRA_PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES` | audit-tools | `5000` | Maximum archive entries scanned while looking for internal manifests. |
| `VITE_API_BASE_URL` | frontend | `http://localhost:8000` | Browser-facing backend URL used by the React app. |

## Use the Web UI

Open:

```text
http://localhost:5173
```

From the UI you can check backend health, upload PDFs, images, manifests, or archives, list uploaded files, launch matching audits, delete uploaded files, list recent jobs, and inspect job results.

For archive files, the file list shows two actions: `Analyze archive` for container structure and extraction-risk indicators, and `Analyze project manifests` for bounded parsing of supported dependency manifests inside the archive.

The dashboard includes client-side counters, file filters by kind, job filters by status and audit type, quick search fields, manual refresh, and gentle auto-refresh while jobs are queued or running.

From the upload panel, choose `PDF`, `Image`, `Manifest`, or `Archive`. Image uploads currently accept JPEG, PNG, and WebP. Manifest uploads currently accept `package.json`, `requirements.txt`, and `pyproject.toml`. Archive uploads currently accept `.zip`, `.tar`, `.tar.gz`, and `.tgz`. Inspectra does not render image previews or extract archives broadly in this phase.

Completed PDF, image, manifest, archive, and project-archive jobs show readable reports with:

- General job summary.
- Hashes.
- File identification.
- Metadata from passive tools.
- PDF `qpdf --check` validation when relevant.
- Image privacy indicators such as GPS, creator, serial number, device, and software metadata presence.
- Manifest project metadata, dependencies by group, scripts, and informational supply-chain indicators.
- Archive structure metrics, detected manifest filenames, entries sample, path traversal indicators, sensitive-name indicators, nested archives, and size/compression indicators.
- Project-archive supported manifests, unsupported manifest filenames, parsed dependencies, scripts, parser findings, limits, truncation, and controlled errors.
- Tool errors and timeouts.
- Optional raw JSON for debugging.

The job detail panel also offers export buttons for Markdown, HTML, XML, and PDF. Completed `manifest_basic` and `project_archive_basic` jobs also show SBOM export buttons for CycloneDX JSON and SPDX JSON. Exports are generated by the backend from the stored job JSON and downloaded from Inspectra.

## Upload a PDF

```bash
curl -sS -F "file=@/path/to/file.pdf;type=application/pdf" \
  http://localhost:8000/files/pdf
```

The response includes an `id`. Use it to launch the audit.

## Upload an Image

```bash
curl -sS -F "file=@/path/to/image.png;type=image/png" \
  http://localhost:8000/files/image
```

JPEG, PNG, and WebP are accepted. Inspectra validates image content using magic bytes, not only file extension or `Content-Type`.

## Upload a Manifest

```bash
curl -sS -F "file=@/path/to/package.json;type=application/json" \
  http://localhost:8000/files/manifest
```

Accepted names are `package.json`, `requirements.txt`, and `pyproject.toml`. Inspectra validates the filename and basic text/JSON/TOML structure, applies the same upload size limit, and stores the file as `kind: "manifest"`.

## Upload an Archive

```bash
curl -sS -F "file=@/path/to/project.zip;type=application/zip" \
  http://localhost:8000/files/archive
```

Accepted archive names are `.zip`, `.tar`, `.tar.gz`, and `.tgz`. Inspectra validates filename and initial content signatures before storing the file as `kind: "archive"`. Stronger format validation happens inside the `audit-tools` runner using Python standard library parsers.

## List Uploaded Files

```bash
curl -sS http://localhost:8000/files
```

The response contains registered metadata such as `id`, original filename, size, hash, and creation time. It does not expose absolute host paths.

## Launch a PDF Audit

```bash
curl -sS -X POST http://localhost:8000/audits/pdf/<file_id>
```

The response includes a job `id`.

## Launch an Image Audit

```bash
curl -sS -X POST http://localhost:8000/audits/image/<file_id>
```

The image audit runs passive identification, metadata extraction, hashing, and privacy indicator checks inside `audit-tools`.

## Launch a Manifest Audit

```bash
curl -sS -X POST http://localhost:8000/audits/manifest/<file_id>
```

The manifest audit parses local text only. It does not run npm, pip, Poetry, pnpm, yarn, project scripts, or dependency installation. It does not query external CVE databases in this phase.

## Launch an Archive Audit

```bash
curl -sS -X POST http://localhost:8000/audits/archive/<file_id>
```

The archive audit inspects container metadata passively with Python standard library parsers. It does not extract the full archive to the filesystem, follow symlinks, execute files, install dependencies, resolve internal manifests, or call the internet.

For ZIP files, Inspectra first reads the standard end-of-central-directory metadata to estimate declared entry count and central directory size before opening the archive with Python `zipfile`. If the declared entry count or central directory size exceeds configured limits, the result is marked truncated and detailed entry parsing is skipped. ZIP64 or inconclusive metadata is handled conservatively in this MVP. Upload size remains the primary guardrail for unusual ZIP metadata layouts.

## Launch a Project Archive Manifest Audit

```bash
curl -sS -X POST http://localhost:8000/audits/project-archive/<file_id>
```

The source file must be `kind: "archive"`. This audit opens the archive with Python standard library parsers, locates supported internal manifests, and reads only bounded manifest bytes in memory. It currently parses `package.json`, `requirements.txt`, and `pyproject.toml`; it detects but does not parse lockfiles and other ecosystem files such as `go.mod`, `Cargo.toml`, `pom.xml`, `composer.json`, and Docker Compose files.

It does not extract the project, execute files or scripts, follow symlinks, install dependencies, invoke package managers, resolve transitive dependencies, query CVEs, or call the internet.

## Read Job Results

```bash
curl -sS http://localhost:8000/jobs/<job_id>
```

Jobs start as `queued`, move to `running`, and then become `completed` or `failed`. Results are also stored locally in `data/results/jobs/<job_id>.json`.

Inspectra stores MVP state as local JSON. Writes use atomic temp-file replacement plus a storage lock file under `data/.locks/storage.lock` for write and read-modify-write operations. The lock is held only during quick local persistence steps, not while external analysis runs. This reduces local races but is still not a substitute for SQLite or another database in multi-user/high-volume deployments.

## Export Job Reports

Every existing job can be exported, including jobs that are still queued, running, or failed. The report clearly includes the job state.

```bash
curl -sS -OJ http://localhost:8000/jobs/<job_id>/export/markdown
curl -sS -OJ http://localhost:8000/jobs/<job_id>/export/html
curl -sS -OJ http://localhost:8000/jobs/<job_id>/export/xml
curl -sS -OJ http://localhost:8000/jobs/<job_id>/export/pdf
```

Supported formats:

| Format | Content-Type | Notes |
| --- | --- | --- |
| Markdown | `text/markdown; charset=utf-8` | Plain readable report. Dynamic values are rendered as code spans or code blocks to avoid misleading Markdown links, images, HTML, headings, or table structure. |
| HTML | `text/html; charset=utf-8` | Static, self-contained HTML with inline CSS and no JavaScript. |
| XML | `application/xml; charset=utf-8` | Inspectra-specific XML rooted at `inspectraAuditReport`. |
| PDF | `application/pdf` | Generated locally by Inspectra without external services or browser automation. |

## Export SBOMs

SBOM export is available for completed dependency jobs:

- `manifest_basic`
- `project_archive_basic`

The SBOM is generated offline from declared dependencies already present in the stored job JSON. Inspectra does not call package registries, resolve transitive dependencies, install packages, execute package managers, query CVEs, or infer licenses.

Inspectra generates package URLs (`purl`) only for dependencies that look like registry packages with a clear npm or PyPI identity. URL, VCS, `file:`, local path, workspace, alias, and editable dependencies are preserved as declared requirements and marked with Inspectra properties/comments explaining why `purl` was omitted.

```bash
curl -sS -OJ http://localhost:8000/jobs/<job_id>/sbom/cyclonedx-json
curl -sS -OJ http://localhost:8000/jobs/<job_id>/sbom/spdx-json
```

Supported SBOM formats:

| Format | Content-Type | Notes |
| --- | --- | --- |
| CycloneDX JSON | `application/vnd.cyclonedx+json; charset=utf-8` | Basic CycloneDX document with declared library components and Inspectra properties. |
| SPDX JSON | `application/spdx+json; charset=utf-8` | Basic SPDX 2.3 document using `NOASSERTION` where Inspectra does not know supplier, license, or download location. |

## List Jobs

```bash
curl -sS http://localhost:8000/jobs
```

Jobs are returned with the most recently created first. Completed jobs include a compact summary with analyzer name, hash, validation state, warnings, timed-out tools, manifest dependency/finding counts, archive entry/finding counts, or project-archive dependency/finding counts when present.

## Delete an Uploaded File

```bash
curl -sS -X DELETE http://localhost:8000/files/<file_id>
```

This deletes the uploaded file and its metadata. Existing job results are kept. Associated jobs are marked with `source_file_deleted_at` so historical results remain readable while making it clear that the original source file is no longer available.

## Development

To run backend and tool-runner tests without installing dependencies globally:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
pytest
```

To build the frontend locally without installing anything globally:

```bash
cd frontend
npm install
npm run build
```

To run frontend unit tests:

```bash
cd frontend
npm run test -- --run
```

Validate Compose configuration:

```bash
docker compose config
```

## Documentation

- [Architecture](docs/architecture.md)
- [Security Scope](docs/security-scope.md)

## License

MIT. See [LICENSE](LICENSE).
