# Inspectra

Inspectra is a lightweight, open source MVP for defensive and educational local security audits. The first phase focuses on passive PDF analysis inside Docker containers so audit tools do not need to be installed on the host system.

This project is intentionally small: a FastAPI backend, a containerized tool runner, local job/result storage, and clear boundaries for authorized use.

## What This MVP Does

- Uploads local PDF files through a REST API.
- Lists registered PDF uploads without exposing host paths.
- Stores uploaded files under `data/uploads`.
- Starts a basic PDF audit job.
- Runs `pdfinfo`, `exiftool`, `qpdf`, and `file` inside the `audit-tools` container.
- Calculates file hashes inside the tool container.
- Stores job state and results under `data/results/jobs`.
- Lists audit jobs with a compact summary.
- Deletes uploaded source files while keeping historical job results.
- Provides a minimal React UI for uploads, audits, jobs, and results.
- Exposes OpenAPI docs at `http://localhost:8000/docs`.

## What This MVP Does Not Do

- It does not run exploits.
- It does not scan external networks.
- It does not brute-force, fuzz, or automate aggressive checks.
- It does not install audit tools on the host.
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
| `VITE_API_BASE_URL` | frontend | `http://localhost:8000` | Browser-facing backend URL used by the React app. |

## Use the Web UI

Open:

```text
http://localhost:5173
```

From the UI you can check backend health, upload PDFs, list uploaded PDFs, launch PDF audits, delete uploaded PDFs, list recent jobs, and inspect full job JSON.

## Upload a PDF

```bash
curl -sS -F "file=@/path/to/file.pdf;type=application/pdf" \
  http://localhost:8000/files/pdf
```

The response includes an `id`. Use it to launch the audit.

## List Uploaded PDFs

```bash
curl -sS http://localhost:8000/files
```

The response contains registered metadata such as `id`, original filename, size, hash, and creation time. It does not expose absolute host paths.

## Launch a PDF Audit

```bash
curl -sS -X POST http://localhost:8000/audits/pdf/<file_id>
```

The response includes a job `id`.

## Read Job Results

```bash
curl -sS http://localhost:8000/jobs/<job_id>
```

Jobs start as `queued`, move to `running`, and then become `completed` or `failed`. Results are also stored locally in `data/results/jobs/<job_id>.json`.

## List Jobs

```bash
curl -sS http://localhost:8000/jobs
```

Jobs are returned with the most recently created first. Completed jobs include a compact summary with analyzer name, hash, validation state, warnings, and timed-out tools when present.

## Delete an Uploaded PDF

```bash
curl -sS -X DELETE http://localhost:8000/files/<file_id>
```

This deletes the uploaded PDF and its file metadata. Existing job results are kept. Associated jobs are marked with `source_file_deleted_at` so historical results remain readable while making it clear that the original source file is no longer available.

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

Validate Compose configuration:

```bash
docker compose config
```

## Documentation

- [Architecture](docs/architecture.md)
- [Security Scope](docs/security-scope.md)

## License

MIT. See [LICENSE](LICENSE).
