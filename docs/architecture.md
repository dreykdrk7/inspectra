# Inspectra Architecture

## Goal

Inspectra starts as a small defensive audit API for authorized local files. The MVP keeps the backend simple and delegates passive analysis to a dedicated Docker container where external tools or local parsers run away from the host.

## Components

### Backend

- Location: `backend/app`
- Runtime: FastAPI on Python 3.12
- Public port: `8000`
- Responsibilities:
  - Healthcheck endpoint.
  - PDF, image, and dependency manifest upload endpoints.
  - File listing and deletion endpoints.
  - Basic file metadata registry.
  - Job creation, listing, and status management.
  - Job report export in Markdown, HTML, XML, and PDF.
  - Calling the internal tool runner.
  - Persisting results under `data/results/jobs`.

The backend does not install or execute audit binaries directly.

### Frontend

- Location: `frontend`
- Runtime: Vite dev server with React and TypeScript
- Public port: `5173`
- Responsibilities:
  - Display backend health.
  - Upload PDFs, images, and dependency manifests.
  - List and delete uploaded files.
  - Launch PDF, image, and manifest audits.
  - List recent jobs.
  - Fetch jobs and render readable PDF, image, and manifest reports.
  - Provide export links for Markdown, HTML, XML, and PDF job reports.
  - Keep raw job JSON available for debugging.

The frontend is a development service in Docker Compose. Browser requests go to the backend through `VITE_API_BASE_URL`, defaulting to `http://localhost:8000`.

Report presentation is normalized client-side in `frontend/src/pdfReport.ts`, `frontend/src/imageReport.ts`, and `frontend/src/manifestReport.ts`. Dashboard filters and counters live in `frontend/src/dashboardFilters.ts`. This keeps the backend contract stable while making audit result JSON and UI state easier to test.

### Reporting

- Location: `backend/app/reporting.py`
- Responsibilities:
  - Normalize stored `JobRecord` JSON into report sections.
  - Render Markdown, static HTML, Inspectra-specific XML, and a simple PDF.
  - Escape dynamic content for HTML and XML.
  - Include job state, hashes, summaries, type-specific sections, errors, and timeouts when present.

PDF output is generated with a small local Python writer to avoid adding browser automation, LaTeX, external services, or heavyweight dependencies in this MVP.

### Audit Tools Container

- Location: `tools/runner`
- Runtime: FastAPI on Python 3.12
- Internal port: `8081`
- Installed tools:
  - `pdfinfo` from `poppler-utils`
  - `exiftool`
  - `qpdf`
  - `file`

The tool runner is reachable only on the internal Compose network. It receives a relative path for an uploaded file, validates that the path stays inside `data/`, runs passive tools without a shell when tools are needed, and returns structured JSON to the backend.

Each external command has an `INSPECTRA_TOOL_TIMEOUT_SECONDS` timeout, defaulting to 10 seconds. A timed-out tool is recorded in that tool's output and in the result summary instead of failing the entire job by itself.

Manifest analysis uses Python parsing inside the tool runner instead of package managers. It reads `package.json`, `requirements.txt`, or `pyproject.toml` as local text and never runs npm, pip, Poetry, pnpm, yarn, project scripts, dependency installation, or network lookups.

### Local Data

- Uploaded files: `data/uploads`
- Job/result JSON: `data/results/jobs`

The `data/` directory is bind-mounted into containers. Uploads and results are ignored by Git except for `.gitkeep` placeholders.

## Request Flow

1. A user uploads a PDF to `POST /files/pdf`, an image to `POST /files/image`, or a manifest to `POST /files/manifest`.
2. The backend validates file magic bytes or manifest name/content, stores it in `data/uploads`, and records metadata.
3. A user starts analysis with `POST /audits/pdf/{file_id}`, `POST /audits/image/{file_id}`, or `POST /audits/manifest/{file_id}`.
4. The backend creates a queued job and schedules background execution.
5. The backend calls `audit-tools` over the internal Compose network.
6. The tool runner performs passive analysis inside its container. For `manifest_basic`, it parses local text and returns normalized dependencies and informational findings.
7. The backend stores the final job state and result JSON.
8. A user reads the job with `GET /jobs/{job_id}` from the API or the UI.
9. A user exports a report with `GET /jobs/{job_id}/export/{format}`. The backend renders the report from the stored job JSON.

## API Surface

- `GET /health`: backend healthcheck.
- `POST /files/pdf`: upload and register a PDF.
- `POST /files/image`: upload and register a JPEG, PNG, or WebP image.
- `POST /files/manifest`: upload and register `package.json`, `requirements.txt`, or `pyproject.toml`.
- `GET /files`: list registered files.
- `GET /files/{file_id}`: read one file record.
- `DELETE /files/{file_id}`: delete an uploaded source file and its metadata.
- `POST /audits/pdf/{file_id}`: start a basic passive PDF audit.
- `POST /audits/image/{file_id}`: start a basic passive image audit.
- `POST /audits/manifest/{file_id}`: start a basic passive dependency manifest audit.
- `GET /jobs`: list jobs, newest first, with summaries when available.
- `GET /jobs/{job_id}`: read one full job record.
- `GET /jobs/{job_id}/export/markdown`: export a Markdown report.
- `GET /jobs/{job_id}/export/html`: export a static HTML report.
- `GET /jobs/{job_id}/export/xml`: export an Inspectra XML report.
- `GET /jobs/{job_id}/export/pdf`: export a simple PDF report.

Deleting a file does not remove historical job results. Associated jobs are marked with `source_file_deleted_at`.

The browser UI consumes these same endpoints. The backend enables CORS only for configured origins through `INSPECTRA_CORS_ORIGINS`, defaulting to the local Vite origin.

## Isolation Choices

- Audit binaries are installed only in the `audit-tools` image.
- The Docker socket is not mounted into the backend.
- The tool runner uses an internal Compose network.
- The tool runner mount of `data/` is read-only.
- Containers drop Linux capabilities and set `no-new-privileges`.
- Containers use read-only root filesystems with `/tmp` as tmpfs.
- File and job identifiers are constrained to generated UUID hex values before filesystem paths are built.
- File records include `kind` so audit endpoints can reject mismatched file types. Older records without `kind` are treated as PDFs by default.
- Upload size is limited by `INSPECTRA_MAX_UPLOAD_BYTES`, defaulting to 20 MB.
- Development CORS is explicit and defaults to `http://localhost:5173`, not a wildcard.

These are sensible MVP guardrails, not a substitute for a hardened sandbox.

## Extensibility

Future audit types should follow the same pattern:

1. Add a narrow backend endpoint and job type.
2. Add a tool-runner endpoint for the passive analysis.
3. Keep command execution inside the tool container.
4. Persist results as JSON in `data/results/jobs`.
5. Document the new tool scope in `docs/security-scope.md`.

Possible next modules:

- Local archive inspection.
- Optional offline SBOM export from parsed manifests.
- Job history filters and result-specific views in the frontend.
