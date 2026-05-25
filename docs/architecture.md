# Inspectra Architecture

## Goal

Inspectra starts as a small defensive audit API for authorized local files. The MVP keeps the backend simple and delegates external security tools to a dedicated Docker container.

## Components

### Backend

- Location: `backend/app`
- Runtime: FastAPI on Python 3.12
- Public port: `8000`
- Responsibilities:
  - Healthcheck endpoint.
  - PDF and image upload endpoints.
  - File listing and deletion endpoints.
  - Basic file metadata registry.
  - Job creation, listing, and status management.
  - Calling the internal tool runner.
  - Persisting results under `data/results/jobs`.

The backend does not install or execute audit binaries directly.

### Frontend

- Location: `frontend`
- Runtime: Vite dev server with React and TypeScript
- Public port: `5173`
- Responsibilities:
  - Display backend health.
  - Upload PDFs and images.
  - List and delete uploaded files.
  - Launch PDF and image audits.
  - List recent jobs.
  - Fetch jobs and render readable PDF and image reports.
  - Keep raw job JSON available for debugging.

The frontend is a development service in Docker Compose. Browser requests go to the backend through `VITE_API_BASE_URL`, defaulting to `http://localhost:8000`.

Report presentation is normalized client-side in `frontend/src/pdfReport.ts` and `frontend/src/imageReport.ts`. This keeps the backend contract stable while making audit result JSON easier to read.

### Audit Tools Container

- Location: `tools/runner`
- Runtime: FastAPI on Python 3.12
- Internal port: `8081`
- Installed tools:
  - `pdfinfo` from `poppler-utils`
  - `exiftool`
  - `qpdf`
  - `file`

The tool runner is reachable only on the internal Compose network. It receives a relative path for an uploaded file, validates that the path stays inside `data/`, runs passive tools without a shell, and returns structured JSON to the backend.

Each external command has an `INSPECTRA_TOOL_TIMEOUT_SECONDS` timeout, defaulting to 10 seconds. A timed-out tool is recorded in that tool's output and in the result summary instead of failing the entire job by itself.

### Local Data

- Uploaded files: `data/uploads`
- Job/result JSON: `data/results/jobs`

The `data/` directory is bind-mounted into containers. Uploads and results are ignored by Git except for `.gitkeep` placeholders.

## Request Flow

1. A user uploads a PDF to `POST /files/pdf` or an image to `POST /files/image`.
2. The backend validates file magic bytes, stores it in `data/uploads`, and records metadata.
3. A user starts analysis with `POST /audits/pdf/{file_id}` or `POST /audits/image/{file_id}`.
4. The backend creates a queued job and schedules background execution.
5. The backend calls `audit-tools` over the internal Compose network.
6. The tool runner performs passive analysis inside its container.
7. The backend stores the final job state and result JSON.
8. A user reads the job with `GET /jobs/{job_id}` from the API or the UI.

## API Surface

- `GET /health`: backend healthcheck.
- `POST /files/pdf`: upload and register a PDF.
- `POST /files/image`: upload and register a JPEG, PNG, or WebP image.
- `GET /files`: list registered files.
- `GET /files/{file_id}`: read one file record.
- `DELETE /files/{file_id}`: delete an uploaded source file and its metadata.
- `POST /audits/pdf/{file_id}`: start a basic passive PDF audit.
- `POST /audits/image/{file_id}`: start a basic passive image audit.
- `GET /jobs`: list jobs, newest first, with summaries when available.
- `GET /jobs/{job_id}`: read one full job record.

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

- Passive image metadata checks.
- Local archive inspection.
- SBOM or dependency manifest review.
- Job history filters and result-specific views in the frontend.
