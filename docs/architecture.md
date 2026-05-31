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
  - Authorized domain and explicit subdomain-inventory audit endpoints.
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
  - Launch PDF, image, manifest, archive, project-archive manifest, Django config, Docker config, secrets review, Node package config, CI/CD config, web baseline, domain baseline, and controlled subdomain inventory audits.
  - List recent jobs.
  - Fetch jobs and render readable PDF, image, manifest, archive, project-archive, Django config, Docker config, secrets review, Node package config, CI/CD config, web, domain, and subdomain inventory reports.
  - Provide export links for Markdown, HTML, XML, and PDF job reports.
  - Provide SBOM export links for completed manifest and project-archive manifest jobs.
  - Keep raw job JSON available for debugging.

The frontend is a development service in Docker Compose. Browser requests go to the backend through `VITE_API_BASE_URL`, defaulting to `http://localhost:8000`.

Report presentation is normalized client-side in `frontend/src/pdfReport.ts`, `frontend/src/imageReport.ts`, `frontend/src/manifestReport.ts`, `frontend/src/archiveReport.ts`, `frontend/src/projectArchiveReport.ts`, `frontend/src/djangoConfigReport.ts`, `frontend/src/dockerConfigReport.ts`, `frontend/src/secretsReviewReport.ts`, `frontend/src/nodePackageConfigReport.ts`, `frontend/src/ciCdConfigReport.ts`, `frontend/src/webReport.ts`, `frontend/src/domainReport.ts`, and `frontend/src/subdomainReport.ts`. Dashboard filters and counters live in `frontend/src/dashboardFilters.ts`. This keeps the backend contract stable while making audit result JSON and UI state easier to test.

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

The tool runner is reachable by the backend on the internal Compose network. For `web_basic`, `domain_basic`, and `subdomain_inventory_basic`, the runner is also attached to a separate egress-capable network so it can make explicitly authorized HTTP/HTTPS requests and bounded DNS queries. It does not publish a public port. For uploaded-file audits it receives a relative path, validates that the path stays inside `data/`, runs passive tools without a shell when tools are needed, and returns structured JSON to the backend.

Each external command has an `INSPECTRA_TOOL_TIMEOUT_SECONDS` timeout, defaulting to 10 seconds. A timed-out tool is recorded in that tool's output and in the result summary instead of failing the entire job by itself.

Manifest analysis uses Python parsing inside the tool runner instead of package managers. It reads `package.json`, `requirements.txt`, or `pyproject.toml` as local text and never runs npm, pip, Poetry, pnpm, yarn, project scripts, dependency installation, or network lookups.

Archive analysis uses Python standard library parsers (`zipfile` and `tarfile`) inside the tool runner. It reads archive metadata, estimates sizes, records entries up to configured limits, detects manifest filenames and extraction-risk indicators, and does not extract archives broadly to the filesystem, follow symlinks, execute content, install dependencies, resolve internal manifests, or call the internet.

For ZIP files, the runner performs a small standard EOCD preflight before opening the archive with `zipfile`. The preflight checks declared entry count and central directory size so entry-heavy ZIPs can be truncated before Python materializes detailed ZIP metadata. ZIP64 sentinel values, multi-disk metadata, or inconclusive EOCD parsing are treated conservatively and produce truncated findings instead of detailed parsing in this MVP. TAR analysis continues to iterate members from `tarfile` and stops at the configured entry limit.

Project archive analysis also uses Python standard library archive readers, but it only reads bounded content for supported dependency manifests inside an archive. It currently parses internal `package.json`, `requirements.txt`, and `pyproject.toml` files by reusing the local manifest parsers. It detects other manifest filenames for reporting, but does not parse unsupported ecosystems, extract the whole project, follow symlinks, execute files, invoke package managers, resolve dependencies, or call the internet.

Django config analysis is another archive-based passive workflow. The backend accepts only `kind: "archive"` source files and creates `django_config_basic` jobs. The runner reuses the archive safety model, detects Django-related config, deployment, dependency, and environment-template paths, and reads only bounded UTF-8 text into memory. It does not extract the project broadly, follow symlinks or hardlinks, import Python modules, execute Django code, run `manage.py`, install dependencies, connect to databases, query CVEs, or call the internet. Real `.env` and `.env.*` entries are recorded as sensitive files present and are not read, while explicit template/sample names such as `.env.example`, `.env.template`, and `.env.sample` may be read within limits. Evidence for secret-like settings is redacted before storage, and reporting/UI apply an additional best-effort Django redaction pass for compatibility with legacy or malformed job payloads. The runner strips full-line comments before stronger settings heuristics, lowers severity for obvious development/test/local/example paths, and groups repeated missing-setting indicators across settings files.

Docker config analysis is an archive-based passive workflow. The backend accepts only `kind: "archive"` source files and creates `docker_config_basic` jobs. The runner reuses the archive safety model, detects Dockerfile, Docker Compose, and `.dockerignore` candidate paths, and reads only bounded UTF-8 text into memory. It does not execute Docker, invoke `docker compose`, build images, start containers, inspect the Docker socket, download images, resolve tags, scan ports, query CVEs, extract the project broadly, follow symlinks or hardlinks, execute scripts, or call the internet. Findings are heuristic review indicators for Dockerfile and Compose text such as root users, missing `USER`, mutable image tags, privileged services, host networking, Docker socket mounts, published database/cache ports, and sensitive-looking environment names. Evidence is redacted before storage, and reporting applies an additional best-effort secret redaction pass for compatibility with legacy or malformed job payloads.

Secrets review analysis is an archive-based passive workflow. The backend accepts only `kind: "archive"` source files and creates `secrets_review_basic` jobs. The runner reuses the archive safety model, records real `.env`, `.env.*`, and `.envrc` files as sensitive files present without reading their content, and reads only bounded UTF-8 text from candidate environment templates, app config, CI/CD config, Docker/Compose, Kubernetes, and Terraform-style files. It does not validate credentials, query providers, scan Git history, run external scanners, execute code, install dependencies, extract the project broadly, follow symlinks or hardlinks, query CVEs, or call the internet. Findings are heuristic review indicators for secret-like assignments, credential-bearing URLs, private key blocks, JWT-like values, CI/Docker/Kubernetes/Terraform inline secret patterns, and sensitive files present. Evidence is generated redaction-first without prefixes, suffixes, or fingerprints, and reporting applies an additional best-effort redaction pass for compatibility with legacy or malformed job payloads.

Node package config analysis is an archive-based passive workflow. The backend accepts only `kind: "archive"` source files and creates `node_package_config_basic` jobs. The runner reuses the archive safety model, records real `.env`, `.env.*`, and `.envrc` files as sensitive files present without reading their content, and reads only bounded UTF-8 text from package manifests, lockfiles, package-manager config, workspace config, JS/TS tool config, and CI/publishing hint files. It does not execute npm, pnpm, yarn, bun, npx, lifecycle scripts, JavaScript, TypeScript, or config files; install dependencies; resolve transitive dependencies; download packages; query registries; run `npm audit`; query CVEs/advisories; extract the project broadly; follow symlinks or hardlinks; or call the internet. Findings are heuristic review indicators for scripts, dependency declarations, package metadata, npm config, lockfile consistency, and simple framework/config hints. Secret-like `.npmrc` values, credential-bearing URLs, sensitive query parameters, and script assignment fragments are redacted before storage, and reporting applies an additional best-effort redaction pass for compatibility with legacy or malformed job payloads.

CI/CD config analysis is an archive-based passive workflow. The backend accepts only `kind: "archive"` source files and creates `ci_cd_config_basic` jobs. The runner reuses the archive safety model, records real `.env`, `.env.*`, and `.envrc` files as sensitive files present without reading their content, and reads only bounded UTF-8 text from CI/CD candidates such as GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines, CircleCI, Jenkins/generic pipeline files, release helpers, and workflow action descriptors. It does not execute workflows, emulate runners, evaluate dynamic expressions, call provider APIs, validate tokens, execute scripts, install dependencies, resolve remote actions/reusable workflows, download actions/images, query CVEs/advisories, extract the project broadly, follow symlinks or hardlinks, or call the internet. Findings are heuristic review indicators for triggers, permissions, action/image pinning, CI secret/env handling, remote-script patterns, publish/deploy signals, self-hosted runners, artifact/cache usage, and service-container hints. Secret-like CI values, credential-bearing URLs, sensitive query parameters, provider-token-like strings, and private key blocks are redacted before storage, and reporting applies an additional best-effort redaction pass for compatibility with legacy or malformed job payloads.

Kubernetes config analysis is an archive-based passive workflow. The backend accepts only `kind: "archive"` source files and creates `k8s_config_basic` jobs. The runner reuses the archive safety model, records real `.env`, `.env.*`, and `.envrc` files as sensitive files present without reading their content, and reads only bounded UTF-8 text from Kubernetes manifest, Helm context, and Kustomize context candidates. It does not run `kubectl`, access clusters, validate against an API server, apply manifests, render Helm templates, build Kustomize overlays, resolve remote bases/charts/includes, download images, query registries, query CVEs/advisories, extract the project broadly, follow symlinks or hardlinks, execute scripts, or call the internet. Findings are heuristic review indicators for Secret data/stringData, ConfigMap/env secret-like values, pod/container security settings, image tags/digests, resources/probes, service/ingress exposure, RBAC wildcard rules, namespace defaults, and Helm/Kustomize files detected but not rendered or built. Secret-like Kubernetes values, credential-bearing URLs, sensitive query parameters, and private key blocks are redacted before storage, and reporting applies an additional best-effort redaction pass for compatibility with legacy or malformed job payloads.

Terraform config analysis is an archive-based passive workflow. The backend accepts only `kind: "archive"` source files and creates `terraform_config_basic` jobs. The runner reuses the archive safety model, detects Terraform/OpenTofu-compatible files, tfvars, Terragrunt files, lockfiles, and Terraform state files, and reads only bounded UTF-8 text from reviewable config candidates. Terraform state files are recorded as sensitive files present and are not read. It does not execute Terraform, OpenTofu, or Terragrunt; run init/validate/plan/apply/destroy; download providers or modules; resolve remote module sources; evaluate expressions or variables; access remote state; call cloud or Kubernetes APIs; query registries; query CVEs/advisories; extract the project broadly; follow symlinks or hardlinks; or call the internet. Findings are heuristic review indicators for secret-like Terraform values, state-file presence, provider/backend/module hygiene, AWS network/IAM/storage signals, and parser uncertainty. Secret-like Terraform values, credential-bearing URLs, private key blocks, state-content-like fields, errors, and exports are redacted before storage and again in reporting for compatibility with legacy or malformed job payloads.

Web baseline analysis uses Python standard library HTTP/TLS primitives. It accepts only absolute `http` and `https` URLs, rejects embedded URL credentials, requires authorization confirmation at the backend, follows a bounded number of redirects, validates every redirect target, limits bytes read per response, and checks the final origin's `robots.txt` and common `security.txt` locations. Anti-SSRF validation resolves hostnames before connecting and blocks localhost, private ranges, link-local addresses, multicast/reserved addresses, and cloud metadata targets by default. `INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS=true` permits private/loopback targets for labs, while metadata, link-local, multicast, and reserved targets remain blocked. `INSPECTRA_WEB_ALLOWED_PORTS` limits explicit and implicit target ports, defaulting to `80,443`; Inspectra never probes alternate ports. DNS is validated before each request and redirect, but DNS rebinding or resolver time-of-check/time-of-use races are still better controlled with network-level egress policy. The runner does not execute JavaScript, render HTML, crawl links, fuzz, brute-force, scan ports, query CVEs, or call third-party APIs.

Web results redact cookie values and sensitive response headers before they are stored. Cookie metadata such as name, Secure, HttpOnly, SameSite, Domain, Path, Max-Age, Expires, and value length can be retained for reporting without keeping session tokens. The backend passes the full submitted URL to the web runner only in memory for the authorized request, while job records store a display URL with common sensitive query parameters redacted. The runner applies the same query redaction to target URLs, redirects, findings, errors, and resource URLs before returning JSON. Reporting applies redaction again for compatibility with older jobs that may contain raw URLs.

Domain baseline analysis uses a small standard-library DNS client in the tool runner. It accepts a domain name, rejects URLs, IP literals, userinfo, paths, query strings, localhost-style names, and reserved/internal suffixes, then queries only bounded record types for the authorized domain, `_dmarc.<domain>`, and `www.<domain>` unless the target already starts with `www.`. It parses SPF, DMARC, CAA, MX, NS, SOA, and generic TXT records into informational findings. It does not brute-force subdomains, use wordlists, attempt AXFR, perform reverse DNS sweeps, crawl sites, scan ports, query CVEs, or call external reputation APIs. `INSPECTRA_DOMAIN_DNS_TIMEOUT_SECONDS` controls each UDP DNS query/resolver attempt. The backend computes the HTTP timeout for the runner call from the maximum bounded domain query set, the runner's maximum nameserver attempts, and a fixed margin, so normal bounded DNS timeouts are returned as structured result errors instead of premature backend failures. The current DNS client is UDP-only and best-effort: it uses configured IPv4 resolvers from `/etc/resolv.conf`, reports truncated responses, and does not perform TCP fallback.

Subdomain inventory analysis reuses the same DNS client but only for candidates explicitly supplied by the user. The backend validates the root domain with the `domain_basic` policy, applies 253-character root/candidate string limits, accepts relative labels or FQDNs inside that root, and rejects URLs, paths, query strings, userinfo, IP literals, wildcards, trailing-dot candidates, root self-references, and out-of-root names before creating a `subdomain_inventory_basic` job. The public API is fail-fast: one invalid candidate rejects the whole request and the runner is not called. The runner defensively normalizes and deduplicates candidates again, resolves only `A`, `AAAA`, and `CNAME`, detects private or reserved IP responses as informational inventory signals, identifies external CNAMEs, and optionally performs up to `INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS` random wildcard-DNS probes. It does not generate candidate permutations, use wordlists, query Certificate Transparency, call external APIs, attempt AXFR, crawl, scan ports, use Nmap, or brute-force subdomains. `INSPECTRA_SUBDOMAIN_MAX_CANDIDATES` bounds explicit candidate count. `INSPECTRA_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS` caps the full runner analysis; the backend HTTP timeout is the deadline plus one in-flight DNS query budget and a fixed margin, so slow DNS returns partial/truncated results instead of very long jobs.

### Local Data

- Uploaded files: `data/uploads`
- Job/result JSON: `data/results/jobs`
- Storage lock file: `data/.locks/storage.lock`

The `data/` directory is bind-mounted into containers. Uploads and results are ignored by Git except for `.gitkeep` placeholders. JSON persistence uses atomic temp-file replacement and an exclusive file lock for write and read-modify-write operations such as job updates and source-file deletion marking. The backend keeps the lock scoped to local disk operations only; background audit services do not hold it while calling the `audit-tools` runner. This is sufficient for the local MVP, while SQLite remains the preferred future step before multi-user or high-volume use.

## Request Flow

1. A user uploads a PDF to `POST /files/pdf`, an image to `POST /files/image`, a manifest to `POST /files/manifest`, or an archive to `POST /files/archive`. For web checks, the user submits a URL to `POST /audits/web/basic` with authorization confirmation. For domain checks, the user submits a domain to `POST /audits/domain/basic` with authorization confirmation. For subdomain inventory, the user submits a root domain plus explicit candidates to `POST /audits/subdomains/basic` with authorization confirmation.
2. The backend validates file magic bytes, manifest name/content, or archive name/signature, stores it in `data/uploads`, and records metadata.
3. A user starts file analysis with `POST /audits/pdf/{file_id}`, `POST /audits/image/{file_id}`, `POST /audits/manifest/{file_id}`, `POST /audits/archive/{file_id}`, `POST /audits/project-archive/{file_id}`, `POST /audits/django-config/{file_id}`, `POST /audits/docker-config/{file_id}`, `POST /audits/secrets-review/{file_id}`, `POST /audits/node-package-config/{file_id}`, `POST /audits/ci-cd-config/{file_id}`, `POST /audits/k8s-config/{file_id}`, or `POST /audits/terraform-config/{file_id}`. Web, domain, and subdomain inventory jobs are already created by `POST /audits/web/basic`, `POST /audits/domain/basic`, or `POST /audits/subdomains/basic` and store `target_url` or `target_domain` instead of `file_id`.
4. The backend creates a queued job and schedules background execution.
5. The backend calls `audit-tools` over the internal Compose network.
6. The tool runner performs passive analysis inside its container. For `manifest_basic`, it parses local text and returns normalized dependencies and informational findings. For `archive_basic`, it inspects archive metadata and returns structure, size, manifest-presence, extraction-risk, and informational findings without broad extraction. For `project_archive_basic`, it scans archive metadata, reads only bounded supported manifest files in memory, and returns internal dependency summaries plus informational findings. For `django_config_basic`, it reads only bounded Django-related config/deployment text from archives, redacts secret-like evidence, and returns heuristic configuration findings. For `docker_config_basic`, it reads only bounded Dockerfile/Compose text from archives, redacts secret-like evidence, and returns heuristic Docker configuration findings. For `secrets_review_basic`, it records real env files without reading them, reads only bounded candidate text, redacts evidence before storage, and returns heuristic secret-exposure indicators. For `node_package_config_basic`, it records real env files without reading them, reads only bounded Node package/config text, redacts package-manager credentials before storage, and returns heuristic package configuration indicators. For `ci_cd_config_basic`, it records real env files without reading them, reads only bounded CI/CD config text, redacts CI secret-like evidence before storage, and returns heuristic workflow configuration indicators. For `k8s_config_basic`, it records real env files without reading them, reads only bounded Kubernetes manifest/Helm/Kustomize context text, redacts Kubernetes secret-like evidence before storage, and returns heuristic manifest configuration indicators. For `terraform_config_basic`, it detects Terraform state files without reading them, reads only bounded Terraform/OpenTofu/Terragrunt config text, redacts IaC secret-like evidence before storage, and returns heuristic infrastructure configuration indicators. For `web_basic`, it makes bounded HTTP/HTTPS requests to the authorized URL and same-origin `robots.txt`/`security.txt` paths, returning headers, cookies, TLS summary, redirects, and configuration findings. For `domain_basic`, it makes bounded DNS queries for the authorized domain and returns DNS, email-security, `www`, findings, and errors. For `subdomain_inventory_basic`, it resolves only explicit candidates and bounded wildcard probes, returning candidate status, DNS answers, heuristic findings, and errors.
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
- `POST /audits/django-config/{file_id}`: start passive Django configuration analysis inside an archive.
- `POST /audits/docker-config/{file_id}`: start passive Docker/Compose configuration analysis inside an archive.
- `POST /audits/secrets-review/{file_id}`: start passive redaction-first secrets exposure review inside an archive.
- `POST /audits/node-package-config/{file_id}`: start passive Node package/configuration analysis inside an archive.
- `POST /audits/ci-cd-config/{file_id}`: start passive CI/CD workflow/configuration analysis inside an archive.
- `POST /audits/k8s-config/{file_id}`: start passive Kubernetes manifest/configuration analysis inside an archive.
- `POST /audits/terraform-config/{file_id}`: start passive Terraform/OpenTofu/Terragrunt configuration analysis inside an archive.
- `POST /audits/web/basic`: start a controlled baseline web configuration audit for one authorized URL.
- `POST /audits/domain/basic`: start a controlled passive DNS baseline audit for one authorized domain.
- `POST /audits/subdomains/basic`: start a controlled passive inventory for explicit authorized subdomain candidates.
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
- The backend reaches the tool runner on an internal Compose network; the tool runner also has outbound network access for the bounded `web_basic`, `domain_basic`, and `subdomain_inventory_basic` audits.
- The tool runner mount of `data/` is read-only.
- Containers drop Linux capabilities and set `no-new-privileges`.
- Containers use read-only root filesystems with `/tmp` as tmpfs.
- File and job identifiers are constrained to generated UUID hex values before filesystem paths are built.
- File records include `kind` so audit endpoints can reject mismatched file types. Older records without `kind` are treated as PDFs by default.
- Upload size is limited by `INSPECTRA_MAX_UPLOAD_BYTES`, defaulting to 20 MB.
- Archive inspection is bounded by `INSPECTRA_ARCHIVE_MAX_ENTRIES`, `INSPECTRA_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES`, `INSPECTRA_ARCHIVE_MAX_ENTRY_NAME_LENGTH`, `INSPECTRA_ARCHIVE_MAX_LISTED_ENTRIES`, and `INSPECTRA_ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES`.
- Project archive manifest parsing is bounded by `INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFESTS`, `INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFEST_BYTES`, `INSPECTRA_PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES`, and `INSPECTRA_PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES`.
- Django config archive analysis is bounded by `INSPECTRA_DJANGO_CONFIG_MAX_FILES`, `INSPECTRA_DJANGO_CONFIG_MAX_FILE_BYTES`, `INSPECTRA_DJANGO_CONFIG_MAX_TOTAL_BYTES`, archive entry limits, and ZIP central directory metadata limits.
- Docker config archive analysis is bounded by `INSPECTRA_DOCKER_CONFIG_MAX_FILES`, `INSPECTRA_DOCKER_CONFIG_MAX_FILE_BYTES`, `INSPECTRA_DOCKER_CONFIG_MAX_TOTAL_BYTES`, archive entry limits, and ZIP central directory metadata limits.
- Secrets review archive analysis is bounded by `INSPECTRA_SECRETS_REVIEW_MAX_FILES`, `INSPECTRA_SECRETS_REVIEW_MAX_FILE_BYTES`, `INSPECTRA_SECRETS_REVIEW_MAX_TOTAL_BYTES`, archive entry limits, and ZIP central directory metadata limits.
- Node package config archive analysis is bounded by `INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILES`, `INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILE_BYTES`, `INSPECTRA_NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES`, archive entry limits, and ZIP central directory metadata limits.
- CI/CD config archive analysis is bounded by `INSPECTRA_CI_CD_CONFIG_MAX_FILES`, `INSPECTRA_CI_CD_CONFIG_MAX_FILE_BYTES`, `INSPECTRA_CI_CD_CONFIG_MAX_TOTAL_BYTES`, archive entry limits, and ZIP central directory metadata limits.
- Kubernetes config archive analysis is bounded by `INSPECTRA_K8S_CONFIG_MAX_FILES`, `INSPECTRA_K8S_CONFIG_MAX_FILE_BYTES`, `INSPECTRA_K8S_CONFIG_MAX_TOTAL_BYTES`, archive entry limits, and ZIP central directory metadata limits.
- Terraform config archive analysis is bounded by `INSPECTRA_TERRAFORM_CONFIG_MAX_FILES`, `INSPECTRA_TERRAFORM_CONFIG_MAX_FILE_BYTES`, `INSPECTRA_TERRAFORM_CONFIG_MAX_TOTAL_BYTES`, archive entry limits, and ZIP central directory metadata limits.
- Web auditing is bounded by `INSPECTRA_WEB_TIMEOUT_SECONDS`, `INSPECTRA_WEB_MAX_RESPONSE_BYTES`, `INSPECTRA_WEB_MAX_REDIRECTS`, and `INSPECTRA_WEB_ALLOWED_PORTS`. Private targets require `INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS=true`; metadata/link-local/multicast/reserved targets remain blocked.
- Subdomain inventory is bounded by `INSPECTRA_SUBDOMAIN_MAX_CANDIDATES`, `INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS`, `INSPECTRA_DOMAIN_DNS_TIMEOUT_SECONDS`, and the global deadline `INSPECTRA_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS`.
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
