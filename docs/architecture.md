# Inspectra Architecture

## Goal

Inspectra starts as a small defensive audit API for authorized local files and controlled baseline web checks. The MVP keeps the backend simple and delegates passive analysis to a dedicated Docker container where external tools, local parsers, or bounded HTTP clients run away from the host.

## Components

### Backend

- Location: `backend/app`
- Runtime: FastAPI on Python 3.12
- Public port: `8000`
- Responsibilities:
  - Healthcheck endpoint.
  - PDF, image, dependency manifest, and archive upload endpoints.
  - Authorized single-URL web audit endpoint.
  - File listing and deletion endpoints.
  - Basic file metadata registry.
  - Job creation, listing, and status management.
  - Job report export in Markdown, HTML, XML, and PDF.
  - Offline SBOM export in CycloneDX JSON and SPDX JSON for completed manifest jobs.
  - Calling the internal tool runner.
  - Persisting results under `data/results/jobs`.

The backend does not install or execute audit binaries directly.

### Frontend

- Location: `frontend`
- Runtime: Vite dev server with React and TypeScript
- Public port: `5173`
- Responsibilities:
  - Display backend health.
  - Upload PDFs, images, dependency manifests, and archives.
  - List and delete uploaded files.
  - Launch PDF, image, manifest, archive, project-archive manifest, and web baseline audits.
  - List recent jobs.
  - Fetch jobs and render readable PDF, image, manifest, archive, project-archive, and web reports.
  - Provide export links for Markdown, HTML, XML, and PDF job reports.
  - Provide SBOM export links for completed manifest and project-archive manifest jobs.
  - Keep raw job JSON available for debugging.

The frontend is a development service in Docker Compose. Browser requests go to the backend through `VITE_API_BASE_URL`, defaulting to `http://localhost:8000`.

Report presentation is normalized client-side in `frontend/src/pdfReport.ts`, `frontend/src/imageReport.ts`, `frontend/src/manifestReport.ts`, `frontend/src/archiveReport.ts`, `frontend/src/projectArchiveReport.ts`, and `frontend/src/webReport.ts`. Dashboard filters and counters live in `frontend/src/dashboardFilters.ts`. This keeps the backend contract stable while making audit result JSON and UI state easier to test.

### Reporting

- Location: `backend/app/reporting.py`
- Responsibilities:
  - Normalize stored `JobRecord` JSON into report sections.
  - Render Markdown, static HTML, Inspectra-specific XML, and a simple PDF.
  - Render untrusted dynamic Markdown values as code spans or fenced code blocks.
  - Escape dynamic content for HTML and XML.
  - Include job state, hashes, summaries, type-specific sections, errors, and timeouts when present.

Markdown output keeps report structure static and treats filenames, metadata, dependency declarations, archive paths, tool output, findings, and errors as text/code so external Markdown renderers do not turn them into links, images, inline HTML, headings, or table structure. PDF output is generated with a small local Python writer to avoid adding browser automation, LaTeX, external services, or heavyweight dependencies in this MVP.

### SBOM

- Location: `backend/app/sbom.py`
- Responsibilities:
  - Validate that SBOM export is only used with completed `manifest_basic` and `project_archive_basic` jobs.
  - Normalize declared dependencies from stored job JSON into a small component model.
  - Preserve declared requirement ranges and source manifest paths.
  - Classify dependency sources as registry, URL, VCS, local, editable, workspace, alias, or unknown.
  - Generate CycloneDX JSON and SPDX JSON without package-manager execution, dependency resolution, registry access, CVE lookup, or license inference.

SBOM output intentionally reflects only dependencies declared in analyzed manifests. It does not claim installed versions unless the manifest declares an exact pin Inspectra can identify locally. Package URLs are generated only for dependencies that can be represented conservatively as npm or PyPI registry packages. URL, VCS, local path, editable, workspace, and alias dependencies keep the original declaration and include an Inspectra omission reason instead of an inferred `purl`.

### Audit Tools Container

- Location: `tools/runner`
- Runtime: FastAPI on Python 3.12
- Internal port: `8081`
- Installed tools:
  - `pdfinfo` from `poppler-utils`
  - `exiftool`
  - `qpdf`
  - `file`

The tool runner is reachable by the backend on the internal Compose network. For `web_basic` and `domain_basic`, the runner is also attached to a separate egress-capable network so it can make explicitly authorized HTTP/HTTPS requests and bounded DNS queries. It does not publish a public port. For uploaded-file audits it receives a relative path, validates that the path stays inside `data/`, runs passive tools without a shell when tools are needed, and returns structured JSON to the backend.

Each external command has an `INSPECTRA_TOOL_TIMEOUT_SECONDS` timeout, defaulting to 10 seconds. A timed-out tool is recorded in that tool's output and in the result summary instead of failing the entire job by itself.

Manifest analysis uses Python parsing inside the tool runner instead of package managers. It reads `package.json`, `requirements.txt`, or `pyproject.toml` as local text and never runs npm, pip, Poetry, pnpm, yarn, project scripts, dependency installation, or network lookups.

Archive analysis uses Python standard library parsers (`zipfile` and `tarfile`) inside the tool runner. It reads archive metadata, estimates sizes, records entries up to configured limits, detects manifest filenames and extraction-risk indicators, and does not extract archives broadly to the filesystem, follow symlinks, execute content, install dependencies, resolve internal manifests, or call the internet.

For ZIP files, the runner performs a small standard EOCD preflight before opening the archive with `zipfile`. The preflight checks declared entry count and central directory size so entry-heavy ZIPs can be truncated before Python materializes detailed ZIP metadata. ZIP64 sentinel values, multi-disk metadata, or inconclusive EOCD parsing are treated conservatively and produce truncated findings instead of detailed parsing in this MVP. TAR analysis continues to iterate members from `tarfile` and stops at the configured entry limit.

Project archive analysis also uses Python standard library archive readers, but it only reads bounded content for supported dependency manifests inside an archive. It currently parses internal `package.json`, `requirements.txt`, and `pyproject.toml` files by reusing the local manifest parsers. It detects other manifest filenames for reporting, but does not parse unsupported ecosystems, extract the whole project, follow symlinks, execute files, invoke package managers, resolve dependencies, or call the internet.

Web baseline analysis uses Python standard library HTTP/TLS primitives. It accepts only absolute `http` and `https` URLs, rejects embedded URL credentials, requires authorization confirmation at the backend, follows a bounded number of redirects, validates every redirect target, limits bytes read per response, and checks the final origin's `robots.txt` and common `security.txt` locations. Anti-SSRF validation resolves hostnames before connecting and blocks localhost, private ranges, link-local addresses, multicast/reserved addresses, and cloud metadata targets by default. `INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS=true` permits private/loopback targets for labs, while metadata, link-local, multicast, and reserved targets remain blocked. `INSPECTRA_WEB_ALLOWED_PORTS` limits explicit and implicit target ports, defaulting to `80,443`; Inspectra never probes alternate ports. DNS is validated before each request and redirect, but DNS rebinding or resolver time-of-check/time-of-use races are still better controlled with network-level egress policy. The runner does not execute JavaScript, render HTML, crawl links, fuzz, brute-force, scan ports, query CVEs, or call third-party APIs.

Web results redact cookie values and sensitive response headers before they are stored. Cookie metadata such as name, Secure, HttpOnly, SameSite, Domain, Path, Max-Age, Expires, and value length can be retained for reporting without keeping session tokens. The backend passes the full submitted URL to the web runner only in memory for the authorized request, while job records store a display URL with common sensitive query parameters redacted. The runner applies the same query redaction to target URLs, redirects, findings, errors, and resource URLs before returning JSON. Reporting applies redaction again for compatibility with older jobs that may contain raw URLs.

Domain baseline analysis uses a small standard-library DNS client in the tool runner. It accepts a domain name, rejects URLs, IP literals, userinfo, paths, query strings, localhost-style names, and reserved/internal suffixes, then queries only bounded record types for the authorized domain, `_dmarc.<domain>`, and `www.<domain>`. It parses SPF, DMARC, CAA, MX, NS, SOA, and generic TXT records into informational findings. It does not brute-force subdomains, use wordlists, attempt AXFR, perform reverse DNS sweeps, crawl sites, scan ports, query CVEs, or call external reputation APIs. `INSPECTRA_DOMAIN_DNS_TIMEOUT_SECONDS` controls each UDP DNS query/resolver attempt. The backend computes the HTTP timeout for the runner call from the maximum bounded domain query set, the runner's maximum nameserver attempts, and a fixed margin, so normal bounded DNS timeouts are returned as structured result errors instead of premature backend failures. The current DNS client is UDP-only and best-effort: it uses configured IPv4 resolvers from `/etc/resolv.conf`, reports truncated responses, and does not perform TCP fallback.

### Local Data

- Uploaded files: `data/uploads`
- Job/result JSON: `data/results/jobs`
- Storage lock file: `data/.locks/storage.lock`

The `data/` directory is bind-mounted into containers. Uploads and results are ignored by Git except for `.gitkeep` placeholders. JSON persistence uses atomic temp-file replacement and an exclusive file lock for write and read-modify-write operations such as job updates and source-file deletion marking. The backend keeps the lock scoped to local disk operations only; background audit services do not hold it while calling the `audit-tools` runner. This is sufficient for the local MVP, while SQLite remains the preferred future step before multi-user or high-volume use.

## Request Flow

1. A user uploads a PDF to `POST /files/pdf`, an image to `POST /files/image`, a manifest to `POST /files/manifest`, or an archive to `POST /files/archive`. For web checks, the user submits a URL to `POST /audits/web/basic` with authorization confirmation. For domain checks, the user submits a domain to `POST /audits/domain/basic` with authorization confirmation.
2. The backend validates file magic bytes, manifest name/content, or archive name/signature, stores it in `data/uploads`, and records metadata.
3. A user starts file analysis with `POST /audits/pdf/{file_id}`, `POST /audits/image/{file_id}`, `POST /audits/manifest/{file_id}`, `POST /audits/archive/{file_id}`, or `POST /audits/project-archive/{file_id}`. Web and domain jobs are already created by `POST /audits/web/basic` or `POST /audits/domain/basic` and store `target_url` or `target_domain` instead of `file_id`.
4. The backend creates a queued job and schedules background execution.
5. The backend calls `audit-tools` over the internal Compose network.
6. The tool runner performs passive analysis inside its container. For `manifest_basic`, it parses local text and returns normalized dependencies and informational findings. For `archive_basic`, it inspects archive metadata and returns structure, size, manifest-presence, extraction-risk, and informational findings without broad extraction. For `project_archive_basic`, it scans archive metadata, reads only bounded supported manifest files in memory, and returns internal dependency summaries plus informational findings. For `web_basic`, it makes bounded HTTP/HTTPS requests to the authorized URL and same-origin `robots.txt`/`security.txt` paths, returning headers, cookies, TLS summary, redirects, and configuration findings. For `domain_basic`, it makes bounded DNS queries for the authorized domain and returns DNS, email-security, `www`, findings, and errors.
7. The backend stores the final job state and result JSON.
8. A user reads the job with `GET /jobs/{job_id}` from the API or the UI.
9. A user exports a report with `GET /jobs/{job_id}/export/{format}`. The backend renders the report from the stored job JSON.
10. For completed manifest jobs, a user exports an SBOM with `GET /jobs/{job_id}/sbom/{format}`. The backend generates the SBOM from stored declared dependencies only.

## API Surface

- `GET /health`: backend healthcheck.
- `POST /files/pdf`: upload and register a PDF.
- `POST /files/image`: upload and register a JPEG, PNG, or WebP image.
- `POST /files/manifest`: upload and register `package.json`, `requirements.txt`, or `pyproject.toml`.
- `POST /files/archive`: upload and register a ZIP, TAR, TAR.GZ, or TGZ archive.
- `GET /files`: list registered files.
- `GET /files/{file_id}`: read one file record.
- `DELETE /files/{file_id}`: delete an uploaded source file and its metadata.
- `POST /audits/pdf/{file_id}`: start a basic passive PDF audit.
- `POST /audits/image/{file_id}`: start a basic passive image audit.
- `POST /audits/manifest/{file_id}`: start a basic passive dependency manifest audit.
- `POST /audits/archive/{file_id}`: start a basic passive archive inspection.
- `POST /audits/project-archive/{file_id}`: start passive manifest analysis inside an archive.
- `POST /audits/web/basic`: start a controlled baseline web configuration audit for one authorized URL.
- `POST /audits/domain/basic`: start a controlled passive DNS baseline audit for one authorized domain.
- `GET /jobs`: list jobs, newest first, with summaries when available.
- `GET /jobs/{job_id}`: read one full job record.
- `GET /jobs/{job_id}/export/markdown`: export a Markdown report.
- `GET /jobs/{job_id}/export/html`: export a static HTML report.
- `GET /jobs/{job_id}/export/xml`: export an Inspectra XML report.
- `GET /jobs/{job_id}/export/pdf`: export a simple PDF report.
- `GET /jobs/{job_id}/sbom/cyclonedx-json`: export a CycloneDX JSON SBOM for a completed manifest dependency job.
- `GET /jobs/{job_id}/sbom/spdx-json`: export an SPDX JSON SBOM for a completed manifest dependency job.

Deleting a file does not remove historical job results. Associated jobs are marked with `source_file_deleted_at`.

The browser UI consumes these same endpoints. The backend enables CORS only for configured origins through `INSPECTRA_CORS_ORIGINS`, defaulting to the local Vite origin.

## Isolation Choices

- Audit binaries are installed only in the `audit-tools` image.
- The Docker socket is not mounted into the backend.
- The backend reaches the tool runner on an internal Compose network; the tool runner also has outbound network access for the bounded `web_basic` audit.
- The tool runner mount of `data/` is read-only.
- Containers drop Linux capabilities and set `no-new-privileges`.
- Containers use read-only root filesystems with `/tmp` as tmpfs.
- File and job identifiers are constrained to generated UUID hex values before filesystem paths are built.
- File records include `kind` so audit endpoints can reject mismatched file types. Older records without `kind` are treated as PDFs by default.
- Upload size is limited by `INSPECTRA_MAX_UPLOAD_BYTES`, defaulting to 20 MB.
- Archive inspection is bounded by `INSPECTRA_ARCHIVE_MAX_ENTRIES`, `INSPECTRA_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES`, `INSPECTRA_ARCHIVE_MAX_ENTRY_NAME_LENGTH`, `INSPECTRA_ARCHIVE_MAX_LISTED_ENTRIES`, and `INSPECTRA_ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES`.
- Project archive manifest parsing is bounded by `INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFESTS`, `INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFEST_BYTES`, `INSPECTRA_PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES`, and `INSPECTRA_PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES`.
- Web auditing is bounded by `INSPECTRA_WEB_TIMEOUT_SECONDS`, `INSPECTRA_WEB_MAX_RESPONSE_BYTES`, `INSPECTRA_WEB_MAX_REDIRECTS`, and `INSPECTRA_WEB_ALLOWED_PORTS`. Private targets require `INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS=true`; metadata/link-local/multicast/reserved targets remain blocked.
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

- Optional deeper project-in-archive workflows that explicitly extract into a constrained temporary workspace.
- SPDX tag-value SBOM export if a text format becomes useful.
- Optional richer manifest ecosystem support while keeping parsing offline.
- Job history filters and result-specific views in the frontend.
