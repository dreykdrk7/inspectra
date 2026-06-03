# Inspectra Security Scope

## Intended Use

Inspectra is for defensive, educational, and authorized security audits. The MVP is limited to files that the user intentionally uploads plus controlled single-target web and domain baseline checks, starting with PDF/image metadata checks, dependency manifest review, passive archive inspection, bounded manifest analysis inside archives, passive Docker/Django/Node package configuration review, passive CI/CD configuration review, passive Kubernetes/Terraform/Nginx/Compose/Database/SQL DB/Redis configuration review, redaction-first secrets review, passive HTTP/HTTPS configuration review, and bounded DNS baseline review.

Use Inspectra only on files, domains, systems, or services that you own or are explicitly authorized to assess.

## Current MVP Scope

Allowed in this phase:

- Uploading local PDF files.
- Uploading local JPEG, PNG, and WebP images.
- Uploading local dependency manifests named `package.json`, `requirements.txt`, or `pyproject.toml`.
- Uploading local archives with `.zip`, `.tar`, `.tar.gz`, or `.tgz` names.
- Extracting PDF metadata.
- Extracting image metadata.
- Parsing dependency manifests as local text.
- Inspecting archive metadata with Python standard library parsers.
- Reading bounded supported manifest files from archives in memory.
- Reading bounded Django-related configuration/deployment text from archives in memory for `django_config_basic`.
- Reading bounded Dockerfile/Compose text from archives in memory for `docker_config_basic`.
- Reading bounded candidate text from archives in memory for redaction-first `secrets_review_basic`, while detecting real `.env`, `.env.*`, and `.envrc` files without reading their content.
- Reading bounded Node package/config text from archives in memory for `node_package_config_basic`, while detecting real `.env`, `.env.*`, and `.envrc` files without reading their content.
- Reading bounded CI/CD workflow/config text from archives in memory for `ci_cd_config_basic`, while detecting real `.env`, `.env.*`, and `.envrc` files without reading their content.
- Reading bounded Kubernetes manifest/config text from archives in memory for `k8s_config_basic`, while detecting real `.env`, `.env.*`, and `.envrc` files without reading their content.
- Reading bounded Terraform/OpenTofu/Terragrunt config text from archives in memory for `terraform_config_basic`, while detecting Terraform state files as sensitive files present without reading their content.
- Reading bounded Nginx/reverse-proxy config text from archives in memory for `nginx_config_basic`, while detecting `include` directives without resolving them.
- Reading bounded Docker Compose config text from archives in memory for `compose_config_basic`, while detecting real `.env`, `.env.*`, and `.envrc` files plus `env_file` and `secrets.file` references without reading referenced content.
- Reading bounded PostgreSQL/MySQL/MariaDB config text from archives in memory for `database_config_basic`, while detecting real `.env`, `.env.*`, `.envrc`, hidden client credential files, dumps, backups, and include directives without reading sensitive file contents or resolving includes.
- Reading bounded PostgreSQL/MySQL/MariaDB config text from archives in memory for `sql_database_config_basic`, while detecting real `.env`, `.env.*`, `.envrc`, hidden client credential files, dumps, backups, data/WAL/binlog/InnoDB files, key/certificate-like files, and include directives without reading sensitive file contents or resolving includes.
- Reading bounded Redis/Sentinel config text from archives in memory for `redis_config_basic`, while detecting real `.env`, `.env.*`, `.envrc`, ACL, RDB, AOF, appendonly, dump, backup, and include directives without reading sensitive file contents or resolving includes.
- Extracting declared dependencies, scripts, engines, and basic project metadata from supported manifests.
- Recording informational dependency indicators such as lifecycle scripts, unpinned requirements, broad ranges, and URL/VCS/local dependency references.
- Recording informational archive indicators such as path traversal entries, absolute paths, symlinks, hardlinks, executable bits, nested archives, sensitive-looking filenames, manifest filenames, large estimated uncompressed size, high compression ratio, and truncated analysis.
- Calculating cryptographic hashes.
- Running passive PDF validation.
- Listing and deleting locally uploaded PDFs, images, manifests, and archives.
- Storing local JSON audit results.
- Exporting local reports from stored job JSON as Markdown, HTML, XML, and PDF.
- Exporting offline SBOMs from completed manifest and project-archive manifest jobs as CycloneDX JSON and SPDX JSON.
- Running a controlled `web_basic` audit against one explicitly authorized HTTP/HTTPS URL.
- Recording web configuration indicators such as status, redirects, response headers, security headers, cookies, TLS certificate summary, `robots.txt`, and `security.txt`.
- Running a controlled `domain_basic` DNS baseline audit against one explicitly authorized domain.
- Recording DNS configuration indicators for bounded `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `CAA`, `SOA`, `_dmarc`, and `www` checks.
- Running a controlled `subdomain_inventory_basic` audit for explicit subdomain candidates under one authorized root domain.
- Recording bounded `A`, `AAAA`, and `CNAME` answers plus candidate normalization, private/reserved IP indicators, external CNAME indicators, and wildcard-DNS heuristics for those explicit candidates.
- Recording Django configuration indicators such as DEBUG, SECRET_KEY handling, ALLOWED_HOSTS, cookie/HTTPS/proxy settings, CORS, database hints, static/media hints, and deployment-file signals.
- Recording Docker/Compose configuration indicators such as missing or root `USER`, mutable image tags, privileged services, host networking, Docker socket mounts, published database/cache ports, and sensitive-looking environment names.
- Recording Node package configuration indicators such as lifecycle scripts, broad or wildcard dependency declarations, Git/URL/file/workspace dependencies, npm config token references, lockfile consistency, and simple JS/TS config hints.
- Recording CI/CD configuration indicators such as broad or privileged triggers, missing or broad permissions, action/image pinning signals, inline secret-like env values, curl-pipe-shell scripts, publish/deploy commands, self-hosted runner usage, and artifact/cache/service-container hints.
- Recording Terraform/OpenTofu/Terragrunt configuration indicators such as secret-like tfvars/default/output/backend/provider values, state-file presence, missing version/backend/lockfile signals, unpinned provider/module references, AWS world-ingress security group hints, IAM wildcard hints, and S3 public-access hints.
- Recording Docker Compose configuration indicators such as secret-like environment values, env/secret file references, published ports, privileged services, host network/PID/IPC modes, Docker socket and sensitive bind mounts, mutable image tags, build contexts, external networks, legacy links, healthcheck/restart/resource posture, multiple Compose files, and override files.
- Recording database configuration indicators such as PostgreSQL listen/pg_hba/TLS/logging/backup/replication posture, MySQL/MariaDB bind/auth/TLS/logging/backup posture, include directives, sensitive credential/dump/backup files present, and secret-like database values.
- Recording SQL database configuration indicators such as PostgreSQL listen/pg_hba/TLS/logging/backup/replication posture, MySQL/MariaDB bind/auth/TLS/logging/backup posture, include directives, sensitive credential/dump/backup/data files present, and secret-like SQL database values.
- Recording Redis configuration indicators such as bind/protected-mode exposure, `requirepass`/`masterauth` posture, ACL references, TLS posture, persistence/backup posture, replication/Sentinel settings, dangerous command renames, module loading, runtime/logging/resource signals, include directives, sensitive adjacent files present, and secret-like Redis values.
- Using the local web UI to perform implemented UI actions where available for the same bounded audit families.

## Passive Technical Alpha Principles

The passive technical alpha is closed for new module expansion. Its shared principles are:

- Passive analysis first.
- User-supplied files, archives, URLs, domains, or explicit candidates only.
- Archive-only config analyzers for uploaded files registered as `kind: "archive"`.
- Bounded reads and controlled errors/truncation.
- Local storage and local report generation.
- Redaction-first evidence and defensive redaction again at reporting/UI boundaries.
- No runtime execution of user projects, package managers, databases, caches, orchestrators, Docker, Kubernetes, Terraform, Nginx, Redis, or SQL database clients/servers for passive config modules.
- No active pentesting, exploitation, brute force, network scanning, port scanning, credential validation, live reachability claims, or compromise/breach claims.
- No registry, provider, CVE, advisory, or external lookup for passive config modules.
- Findings are heuristic review indicators requiring human validation, not confirmed vulnerabilities or complete coverage guarantees.

For modules that mark `.env`, credential files, dumps, backups, data files, ACL files, state files, or other sensitive adjacent files as no-read, Inspectra records safe context only and does not read those contents. Uploaded archive bytes may still contain secrets and are stored locally according to the MVP data model.

Tools used in this phase:

- `pdfinfo`
- `exiftool`
- `qpdf --check`
- `file`

For images, Inspectra uses `file` and `exiftool` passively. It records informational privacy indicators when metadata suggests GPS data, author/creator values, serial numbers, device information, or software/toolchain information.

For manifests, Inspectra uses local Python parsing. It does not install dependencies, resolve transitive dependencies, run package managers, run project scripts, or call external vulnerability services. Findings are heuristic indicators for review, not confirmed vulnerabilities.

For archives, Inspectra uses local Python metadata parsing. It does not extract archives broadly to the filesystem, follow symlinks, execute files, install dependencies, or call external services. Findings are extraction-risk and review indicators, not proof that a package is malicious.

For project archives, Inspectra may read supported internal manifests (`package.json`, `requirements.txt`, and `pyproject.toml`) into bounded memory buffers and parse them with the same local manifest parser used for standalone manifests. It detects other manifest filenames but does not parse them in this phase.

For Django config audits, Inspectra reads only bounded text from Django-related files inside uploaded archives and reports heuristic indicators for manual review. It does not execute Python, import settings modules, run `manage.py`, install dependencies, connect to databases, read real `.env` files, extract the project broadly, follow symlinks or hardlinks, query CVEs, or call the internet. Real `.env` and `.env.*` files are detected but not read; explicit environment templates and samples may be read within limits. Secret-like evidence is redacted.

For Docker config audits, Inspectra reads only bounded text from Dockerfile, Docker Compose, and `.dockerignore` candidates inside uploaded archives and reports heuristic indicators for manual review. It does not execute Docker, invoke `docker compose`, build images, start containers, inspect or mount the Docker socket, download images, resolve image tags, scan ports, read real `.env` files, extract the project broadly, follow symlinks or hardlinks, query CVEs, or call the internet. Secret-like evidence is redacted best-effort.

For secrets review audits, Inspectra reads only bounded text from candidate files inside uploaded archives and reports redacted heuristic indicators for manual review. It detects real `.env`, `.env.*`, and `.envrc` files but does not read their content. It does not validate credentials, call providers, scan Git history, run external secret scanners, compute secret fingerprints, execute code, extract the project broadly, follow symlinks or hardlinks, query CVEs, or call the internet.

For Node package config audits, Inspectra reads only bounded text from Node package/config candidates inside uploaded archives and reports heuristic indicators for manual review. It detects real `.env`, `.env.*`, and `.envrc` files but does not read their content. It does not execute npm, pnpm, yarn, bun, npx, lifecycle scripts, JavaScript, TypeScript, or config files; install dependencies; resolve transitive dependencies; download packages; query package registries; run `npm audit`; query CVEs/advisories; or call the internet. Secret-like npm config values and credential-bearing URLs are redacted best-effort.

For CI/CD config audits, Inspectra reads only bounded text from CI/CD workflow/config candidates inside uploaded archives and reports heuristic indicators for manual review. It detects real `.env`, `.env.*`, and `.envrc` files but does not read their content. It does not execute workflows, emulate runners, evaluate dynamic expressions, call provider APIs, validate tokens, execute scripts, install dependencies, resolve remote actions or reusable workflows, download actions/images, query CVEs/advisories, or call the internet. Secret-like CI values, credential-bearing URLs, sensitive query parameters, provider-token-like strings, and private key blocks are redacted best-effort.

For Terraform config audits, Inspectra reads only bounded text from Terraform/OpenTofu-compatible `.tf`, `.tf.json`, `.tfvars`, `.tfvars.json`, `.auto.tfvars*`, `.terraform.lock.hcl`, and Terragrunt `.hcl` candidates inside uploaded archives and reports heuristic indicators for manual review. It detects Terraform state files as sensitive files present but does not read their content. It does not execute Terraform, OpenTofu, or Terragrunt; run init, validate, plan, apply, destroy, state, refresh, import, or output commands; download providers or modules; resolve remote module sources; evaluate expressions or variables; access remote state; call cloud or Kubernetes APIs; query registries; query CVEs/advisories; or call the internet. Secret-like Terraform values, state-content-like fields, credential-bearing URLs, sensitive query parameters, and private key blocks are redacted best-effort.

For Nginx config audits, Inspectra reads only bounded text from Nginx/reverse-proxy config candidates inside uploaded archives and reports heuristic indicators for manual review. It detects `include` directives as context but does not resolve them, read host absolute paths, or read outside the archive. It does not execute Nginx, run `nginx -t`, start containers, perform DNS lookups, scan ports, validate live servers or certificates, query CVEs/advisories, or call the internet. Inline basic auth, credential-bearing `proxy_pass` URLs, Authorization headers, cookies/session values, private key blocks, and secret-like variables are redacted best-effort.

For Docker Compose config audits, Inspectra reads only bounded text from Docker Compose and Compose-like candidates inside uploaded archives and reports heuristic indicators for manual review. It detects real `.env`, `.env.*`, and `.envrc` files as sensitive files present without reading their content, and records `env_file` and `secrets.file` references without resolving or reading those referenced files. It does not execute Docker or Docker Compose; run `docker compose config`, `up`, `build`, `pull`, `push`, or `logs`; inspect images; contact registries; interpolate env vars; merge multiple Compose files into an effective configuration; query CVEs/advisories; or call the internet. Secret-like environment values, credential-bearing URLs, registry credentials, database/Redis URLs, private key blocks, labels, command/entrypoint fragments, exports, and errors are redacted best-effort.

For Redis config audits, Inspectra reads only bounded text from Redis and Sentinel config candidates inside uploaded archives and reports heuristic indicators for manual review. It detects real `.env`, `.env.*`, `.envrc`, ACL, RDB, AOF, appendonly, dump, and backup files as sensitive files present without reading their content, and records Redis include directives without resolving them. It does not execute Redis or Sentinel; run `redis-server`, `redis-cli`, `redis-sentinel`, `redis-benchmark`, or similar tools; open sockets; connect to Redis or Sentinel; validate credentials; resolve includes; read host paths; read sensitive adjacent file contents; query CVEs/advisories; or call the internet. Redis passwords, Sentinel auth values, Redis URLs with credentials, ACL-like values, private key blocks, exports, and errors are redacted best-effort.

For SBOM export, Inspectra uses only declared dependencies already present in completed `manifest_basic` or `project_archive_basic` job results. It does not execute package managers, install packages, resolve transitive dependencies, infer licenses, query CVEs, verify URL/VCS identities, or call package registries. Version ranges remain ranges unless the manifest declares an exact local pin that can be represented as such. Package URLs are generated only for dependencies that look like clear npm or PyPI registry packages; URL, VCS, local, editable, workspace, and alias declarations are preserved without inferred package URLs.

For web baseline audits, Inspectra makes bounded HTTP/HTTPS requests only to the authorized URL, validated redirects, and common same-origin `robots.txt`/`security.txt` paths. It does not execute JavaScript, render HTML, crawl links, fuzz, brute-force, exploit, scan ports, use Nmap, query CVEs, or call third-party reputation APIs. Missing headers and exposed metadata are reported as indicators for manual review, not confirmed vulnerabilities.

For domain baseline audits, Inspectra makes bounded DNS queries only for the authorized domain, `_dmarc.<domain>`, and `www.<domain>`. It does not brute-force subdomains, use wordlists, attempt zone transfers, perform reverse DNS sweeps, crawl sites, scan ports, query CVEs, or call reputation APIs. Missing SPF, DMARC, CAA, MX, or `www` records are reported as indicators for manual review, not confirmed vulnerabilities.

For subdomain inventory audits, Inspectra resolves only candidates explicitly supplied by the user under the authorized root domain, plus at most a small configured number of random wildcard-DNS probes. It does not generate candidate permutations, use wordlists, query Certificate Transparency, call third-party APIs, attempt AXFR, crawl, scan ports, use Nmap, or brute-force names. Findings such as private IP responses, external CNAMEs, rejected candidates, or possible wildcard DNS are indicators for manual review.

## Active/Network Dry-Run Scope

Active/Nmap/network work is not part of the Passive Technical Alpha. The first post-alpha Active scope decision is recorded in `docs/future/active-network-block-01-docs-first-scope.md`, the docs-first runbook/threat model is recorded in `docs/future/active-network-block-02-runbook-and-threat-model.md`, the dry-run contract design is recorded in `docs/future/active-network-block-03-dry-run-contracts-design.md`, the separated no-network skeleton is recorded in `docs/future/active-network-block-04-dry-run-skeleton-no-network.md`, the backend/job/storage/reporting contract design is recorded in `docs/future/active-network-block-05-dry-run-backend-contract-design.md`, the backend integration is recorded in `docs/future/active-network-block-06-dry-run-backend-integration-no-network.md`, the frontend design is recorded in `docs/future/active-network-block-07-dry-run-frontend-design.md`, the frontend implementation is recorded in `docs/future/active-network-block-08-dry-run-frontend-implementation-no-network.md`, the end-to-end contract/redaction review is recorded in `docs/future/active-network-block-09-end-to-end-dry-run-contract-redaction-review.md`, the v0 dry-run closeout is recorded in `docs/future/active-network-block-10-dry-run-closeout.md`, the dry-run hardening review before live design is recorded in `docs/future/active-network-block-11-dry-run-hardening-review.md`, the first live HTTP header probe design is recorded in `docs/future/active-network-block-12-authorized-http-header-probe-design.md`, the first runner/backend implementation is recorded in `docs/future/active-network-block-13-authorized-http-header-probe-runner-backend-no-frontend.md`, the backend-only end-to-end review is recorded in `docs/future/active-network-block-14-end-to-end-authorized-http-header-probe-contract-redaction-review.md`, the frontend design is recorded in `docs/future/active-network-block-15-authorized-http-header-probe-frontend-design.md`, the frontend implementation is recorded in `docs/future/active-network-block-16-authorized-http-header-probe-frontend-implementation.md`, and the frontend E2E review is recorded in `docs/future/active-network-block-17-end-to-end-authorized-http-header-probe-frontend-review.md`.

Current decision: `ACTIVE_NETWORK_SCOPE_FROZEN_DOCS_FIRST_NO_RUNTIME`.

Runbook decision: `ACTIVE_RUNBOOK_THREAT_MODEL_FROZEN_NO_RUNTIME`.

Dry-run contract decision: `ACTIVE_DRY_RUN_CONTRACTS_DESIGNED_NO_RUNTIME`.

Skeleton decision: `ACTIVE_DRY_RUN_SKELETON_IMPLEMENTED_NO_NETWORK`.

Backend contract decision: `ACTIVE_DRY_RUN_BACKEND_CONTRACT_DESIGNED_NO_RUNTIME_INTEGRATION`.

Backend integration decision: `ACTIVE_DRY_RUN_BACKEND_INTEGRATED_NO_NETWORK`.

Frontend design decision: `ACTIVE_DRY_RUN_FRONTEND_DESIGNED_NO_UI_RUNTIME`.

Closeout decision: `ACTIVE_DRY_RUN_V0_CLOSED_NO_NETWORK`.

Hardening review decision: `ACTIVE_DRY_RUN_HARDENING_ACCEPTED_FOR_LIVE_PROBE_DESIGN`.

HTTP header probe design decision: `ACTIVE_HTTP_HEADER_PROBE_DESIGNED_NO_RUNTIME`.

HTTP header probe backend decision: `ACTIVE_HTTP_HEADER_PROBE_RUNNER_BACKEND_IMPLEMENTED_NO_FRONTEND`.

HTTP header probe review decision: `ACTIVE_HTTP_HEADER_PROBE_E2E_REVIEW_PASSED_BACKEND_ONLY`.

HTTP header probe frontend design decision: `ACTIVE_HTTP_HEADER_PROBE_FRONTEND_DESIGNED_NO_UI_RUNTIME`.

HTTP header probe frontend review decision: `ACTIVE_HTTP_HEADER_PROBE_FRONTEND_E2E_REVIEW_PASSED`.

This means:

- The backend endpoint `POST /active/network/dry-run` exists but is disabled by default through `INSPECTRA_ACTIVE_DRY_RUN_ENABLED=false`.
- Active dry-run jobs use `active_network_dry_run`, are target-based, have no `file_id`, and preserve `network_requests_sent: 0`.
- Active dry-run storage summaries, reporting sections, and Markdown/HTML/XML/PDF exports exist with defensive redaction.
- Active frontend UI now includes a separate dry-run panel, required authorization, `POST /active/network/dry-run` client call, catalog/filter label, redacted job-table target display, job report, and redacted Raw JSON.
- Active frontend UI is not an archive action and does not expose live probing, Nmap, DNS, socket, HTTP, or port-check controls.
- No Nmap runtime exists yet.
- The `tools/active_runner/` skeleton is backend-integrated only through a no-network dry-run service and performs no network, DNS, HTTP, subprocess, or Nmap behavior.
- Dry-run design requires `network_requests_sent: 0`, no DNS resolution, no live data, no response headers, no status codes, and no Nmap output.
- Any future non-dry-run Active work must start with explicit authorization, target validation, dry-run behavior, rate limits, timeouts, audit logging, and clear no-scope copy.
- The Active block must preserve audit logs without storing secrets, use controlled failure states, and fail closed on ambiguous targets.
- Active code must not be added to the passive runner monolith in `tools/runner/main.py`.
- Passive archive/file analyzers keep their no-network guarantee.
- The backend endpoint `POST /active/network/http-header-probe` exists but is disabled by default through `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED=false`.
- Active HTTP header probe jobs use `active_http_header_probe`, are target-based, have no `file_id`, and require explicit live authorization plus `mode: live_header_probe` and `profile: http_header_probe`.
- DNS resolution is allowed only after the feature flag, authorization, target, profile, and limits pass. Any blocked resolved address fails closed before HTTP.
- Allowed live traffic is capped to one HTTP `HEAD` request, no redirects, no response body read, no retries, and no concurrency.
- Active HTTP header probe storage summaries, reporting sections, API responses, errors, response headers, and Markdown/HTML/XML/PDF exports use defensive redaction.
- The backend-only review confirms disabled/enabled behavior, DNS fail-closed behavior, one-HEAD behavior, no GET fallback, no body read, no redirects, dry-run flag independence, and public API/export redaction.
- The future frontend design requires a separate `Authorized HTTP Header Probe` panel, double authorization, live-traffic warning copy, exact one-HEAD request contract, redacted report/Raw JSON rendering, and no archive action integration. It does not implement frontend runtime yet.
- The frontend implementation now exposes that separate panel and report while preserving double authorization, disabled-state copy, the exact one-HEAD request body, redacted job-table/report/Raw JSON rendering, and no archive action integration.
- The frontend review confirms disabled-state behavior, exact request body, catalog/filter behavior, successful/blocked/failed/sparse report rendering, DOM/Raw JSON redaction, forbidden-copy absence, and no archive action integration.
- Nmap remains unimplemented and out of scope.

The future Active block must reject exploitation, exploit payloads, stealth, evasion, brute force, credential attacks, credential validation, fuzzing, destructive checks, DoS/stress behavior, broad scans, and third-party scanning without authorization.

## Out of Scope

The MVP does not include:

- Exploit execution.
- Vulnerability exploitation.
- Network or port scanning.
- Web crawling.
- Subdomain brute force or wordlist enumeration.
- Certificate Transparency subdomain discovery.
- DNS zone transfer attempts (`AXFR`).
- Internet-wide enumeration.
- Brute force checks.
- Credential attacks.
- Credential validity checks or provider token validation.
- Git history secret scanning.
- External secret scanners or provider API lookups.
- Malware detonation.
- Fuzzing.
- Aggressive automation against external services.
- Running Nmap or network scanners.
- Image rendering, conversion, detonation, or embedded-content execution.
- Installing dependencies from uploaded manifests.
- Running npm, pip, Poetry, pnpm, yarn, or package lifecycle scripts against uploaded manifests.
- Running npm, pnpm, yarn, bun, npx, Node lifecycle scripts, JavaScript, TypeScript, or package config files for Node package config review.
- Downloading Node packages, querying registries, running `npm audit`, querying advisories/CVEs, resolving transitive dependencies, or making malicious-package verdicts for Node package config review.
- Executing workflows, emulating CI/CD runners, evaluating provider expressions dynamically, calling provider APIs, validating tokens, downloading actions/images, resolving remote reusable workflows/includes, querying advisories/CVEs, or claiming pipeline exploitability for CI/CD config review.
- Running `kubectl`, connecting to clusters, validating manifests against API servers, applying manifests, rendering Helm, building Kustomize overlays, resolving remote bases/charts/includes/CRDs, downloading images, querying registries/CVEs/advisories, or claiming exploitability for Kubernetes config review.
- Executing Terraform, OpenTofu, or Terragrunt; running init/validate/plan/apply/destroy/state/refresh/import/output commands; downloading providers or modules; resolving remote modules; evaluating variables or expressions; reading remote state; calling cloud/Kubernetes APIs; querying registries/CVEs/advisories; or claiming exploitability for Terraform config review.
- Executing Docker or Docker Compose for Compose config review; running `docker compose config`, `up`, `run`, `exec`, `build`, `pull`, `push`, or `logs`; inspecting images; contacting registries; interpolating `.env` values; merging multiple Compose files into an effective config; reading referenced env/secret files; querying CVEs/advisories; or claiming exploitability for Compose config review.
- Executing database clients or servers for Database config review; running `psql`, `mysql`, `mariadb`, `pg_ctl`, `postgres`, `mysqld`, `mysqladmin`, `pg_dump`, `mysqldump`, or similar tools; connecting to database servers; validating configs against live instances; resolving includes; reading host paths; reading dumps, backups, hidden credential files, `.env`, `.env.*`, or `.envrc` contents; querying CVEs/advisories; or claiming exploitability for Database config review.
- Executing database clients or servers for SQL DB config review; running `psql`, `mysql`, `mysqladmin`, `mysqld`, `postgres`, `pg_ctl`, `mariadb`, `mariadbd`, `pg_dump`, `mysqldump`, or similar tools; opening sockets; connecting to database servers; validating configs against live instances; resolving includes; reading host paths; reading dumps, backups, hidden credential files, data/WAL/binlog/InnoDB files, private keys, certificates, `.env`, `.env.*`, or `.envrc` contents; querying CVEs/advisories; or claiming exploitability, compromise, breach, or live reachability for SQL DB config review.
- Executing Redis or Sentinel for Redis config review; running `redis-server`, `redis-cli`, `redis-sentinel`, `redis-benchmark`, or similar tools; opening sockets; connecting to Redis/Sentinel; validating credentials; resolving includes; reading host paths; reading `.env`, `.env.*`, `.envrc`, ACL, RDB, AOF, appendonly, dump, or backup contents; querying CVEs/advisories; or claiming exploitability for Redis config review.
- Extracting uploaded archives broadly to the filesystem.
- Executing files, scripts, binaries, symlinks, or hardlinks from uploaded archives.
- Installing or resolving dependencies discovered inside archives.
- Parsing unsupported internal archive manifests beyond filename detection.
- Running package managers or dependency resolvers against content found inside archives.
- Running Django, importing Django settings modules, running `manage.py check`, connecting to databases, reading real `.env` files from archives, or treating Django config heuristics as confirmed vulnerabilities.
- Executing Docker, invoking `docker compose`, building images, starting containers, inspecting the Docker socket, downloading images, resolving image tags, or treating Docker config heuristics as confirmed vulnerabilities.
- Resolving transitive dependencies for SBOM generation.
- Inferring package licenses, suppliers, download locations, or registry identity for URL/VCS/local dependency declarations.
- External CVE, advisory, package registry, or vulnerability database lookups.
- Claiming a heuristic dependency signal is a confirmed vulnerability.
- Treating missing web headers as confirmed vulnerabilities without manual validation.

These exclusions are intentional. Inspectra should evolve carefully and keep each new capability scoped, documented, and defensive.

## Data Handling

Uploaded files are stored locally under `data/uploads`. Results are stored under `data/results/jobs`. Do not upload confidential files unless you accept this local storage behavior.

Audit results may include document metadata such as author names, producer strings, timestamps, paths, or other embedded values. Treat results as potentially sensitive.

JSON metadata writes use atomic replacement and a local file lock to reduce concurrent update races. This improves consistency for local MVP workflows, but it does not add authentication, authorization, encryption, or database-grade multi-user transaction semantics.

Deleting a file through `DELETE /files/{file_id}` removes the uploaded source file and its metadata. It does not delete historical job results; associated jobs are marked so it is clear that the source file is no longer present.

The backend limits uploads with `INSPECTRA_MAX_UPLOAD_BYTES`, defaulting to 20 MB. This is a usability and resource guardrail, not content sanitization.

The frontend does not add authentication or authorization. Run Inspectra only on trusted local development machines or behind controls you manage.

Image analysis does not render previews in this phase. Uploaded images are treated as local files for passive metadata and identification only.

Manifest analysis does not execute project code or package scripts. Uploaded manifests are treated as local text inputs for extraction and reporting only.

Archive analysis reads container metadata and bounded entry listings. Project archive analysis may additionally read supported manifest text from the archive in bounded memory. Uploaded archives are not generally extracted, and internal files are not executed, installed, rendered, or resolved. ZIP analysis includes a standard metadata preflight for entry count and central directory size before detailed parsing, but archive limits reduce resource risk rather than proving parser safety against every specially crafted file.

Django config analysis may read bounded text from candidate config, dependency, environment-template, and deployment files inside uploaded archives. It does not read real `.env` or `.env.*` content and redacts values associated with `SECRET_KEY`, passwords, tokens, API keys, database URLs, private keys, and similar patterns in runner findings, exports, and the Django config UI report. This redaction is best-effort and does not remove secrets from the uploaded archive bytes stored locally. Because this is heuristic static analysis, findings require manual validation before being treated as production security issues.

Docker config analysis may read bounded text from Dockerfile, Docker Compose, and `.dockerignore` candidates inside uploaded archives. It does not read real `.env` content referenced by Compose files and redacts values associated with passwords, tokens, API keys, database URLs, private keys, and similar patterns in runner findings and exports. This redaction is best-effort and does not remove secrets from the uploaded archive bytes stored locally. Docker findings are review indicators and require manual validation before being treated as production security issues.

Secrets review analysis may read bounded text from explicit candidate environment templates, app config, CI/CD config, Docker/Compose, Kubernetes, and Terraform-style files inside uploaded archives. It detects real `.env`, `.env.*`, and `.envrc` files as sensitive files present but does not read their content. Findings are heuristic indicators such as secret-like assignments, private key blocks, credential-bearing URLs, JWT-like values, and inline CI/Docker/Kubernetes/Terraform secret patterns. Inspectra does not validate tokens, call provider APIs, scan Git history, run external secret scanners, compute secret fingerprints, or claim that a credential is valid, leaked, active, or compromised. Evidence, exports, and errors are redacted best-effort without prefixes or suffixes, but uploaded archive bytes may still contain secrets and are stored locally.

Node package config analysis may read bounded text from package manifests, lockfiles, package-manager config, workspace config, JS/TS tool config, CI/publishing hints, and environment templates inside uploaded archives. It detects real `.env`, `.env.*`, and `.envrc` files as sensitive files present but does not read their content. Findings are heuristic indicators such as lifecycle scripts, broad dependency ranges, Git/URL/file/workspace dependencies, npm config token references, lockfile consistency, and simple framework/config hints. Inspectra does not execute package managers, lifecycle scripts, JavaScript, TypeScript, or config files; install dependencies; resolve transitive dependencies; download packages; query registries; run `npm audit`; query CVEs/advisories; or claim that a package is malicious. Secret-like `.npmrc` values, credential-bearing URLs, sensitive query parameters, exports, and errors are redacted best-effort, but uploaded archive bytes may still contain secrets and are stored locally.

CI/CD config analysis may read bounded text from CI/CD workflow/config candidates inside uploaded archives. It detects real `.env`, `.env.*`, and `.envrc` files as sensitive files present but does not read their content. Findings are heuristic indicators such as broad triggers, privileged trigger modes, missing or broad permissions, action/image pinning signals, inline secret-like environment values, curl-pipe-shell scripts, publish/deploy commands, self-hosted runner usage, and artifact/cache/service-container hints. Inspectra does not execute workflows, emulate runners, evaluate dynamic provider expressions, call provider APIs, validate tokens, execute scripts, install dependencies, resolve remote actions or reusable workflows, download actions/images, query CVEs/advisories, or claim that a pipeline is exploitable or compromised. Secret-like CI values, credential-bearing URLs, sensitive query parameters, provider-token-like strings, private key blocks, exports, and errors are redacted best-effort, but uploaded archive bytes may still contain secrets and are stored locally.

Compose config analysis may read bounded text from Docker Compose and Compose-like candidates inside uploaded archives. It detects real `.env`, `.env.*`, and `.envrc` files as sensitive files present without reading their content, and records `env_file` and `secrets.file` references without reading referenced content. Findings are heuristic indicators such as secret-like environment values, published ports, privileged services, host modes, Docker socket mounts, sensitive bind mounts, image/build signals, external networks, missing healthchecks/restart/resource limits, and multiple/override files. Inspectra does not execute Docker or Docker Compose, run `docker compose config`, build or pull images, inspect images, contact registries, interpolate env vars, merge multiple Compose files, query CVEs/advisories, or claim that a deployment is exploitable. Secret-like values, credential URLs, database/Redis URLs, registry credentials, private key blocks, labels, command/entrypoint fragments, errors, and exports are redacted best-effort, but uploaded archive bytes may still contain secrets and are stored locally.

Database config analysis may read bounded text from PostgreSQL, MySQL, and MariaDB config candidates inside uploaded archives. It detects real `.env`, `.env.*`, `.envrc`, hidden client credential files, dumps, and backups as sensitive files present without reading their content, and records database include directives without resolving them. Findings are heuristic indicators such as PostgreSQL listen/pg_hba/TLS/logging/backup/replication posture, MySQL/MariaDB bind/auth/TLS/logging/backup posture, include directives, sensitive files present, and secret-like database values. Inspectra does not execute database clients or servers, connect to databases, validate configs against live instances, resolve includes, read host paths, read dump/backup/credential file contents, query CVEs/advisories, or claim that a database is exploitable. Database credentials, DSNs, `PGPASSWORD`/`MYSQL_PWD`, private key blocks, errors, and exports are redacted best-effort, but uploaded archive bytes may still contain secrets and are stored locally.

SQL DB config analysis may read bounded text from PostgreSQL, MySQL, and MariaDB config candidates inside uploaded archives. It detects real `.env`, `.env.*`, `.envrc`, hidden client credential files such as `.pgpass`, `.my.cnf`, and `.mylogin.cnf`, dumps, backups, data files, WAL/binlog/InnoDB files, and key/certificate-like files as sensitive files present without reading their content, and records SQL database include directives without resolving them. Findings are heuristic indicators such as PostgreSQL listen/pg_hba/TLS/logging/backup/replication posture, MySQL/MariaDB bind/auth/TLS/logging/backup posture, include directives, sensitive files present, and secret-like SQL database values. Inspectra does not execute database clients or servers, open sockets, connect to databases, validate configs against live instances, resolve includes, read host paths, read dump/backup/credential/data/private-key/certificate file contents, query CVEs/advisories, or claim that a SQL database is exploitable, reachable, breached, compromised, or confirmed vulnerable. SQL database credentials, DSNs, `PGPASSWORD`/`MYSQL_PWD`, private key blocks, errors, API responses, exports, frontend reports, and raw JSON are redacted best-effort, but uploaded archive bytes may still contain secrets and are stored locally.

Redis config analysis may read bounded text from Redis and Sentinel config candidates inside uploaded archives. It detects real `.env`, `.env.*`, `.envrc`, ACL, RDB, AOF, appendonly, dump, and backup files as sensitive files present without reading their content, and records Redis include directives without resolving them. Findings are heuristic indicators such as bind/protected-mode exposure, `requirepass`/`masterauth` posture, ACL references, TLS posture, persistence/backup posture, replication/Sentinel settings, dangerous command renames, module loading, runtime/logging/resource signals, include directives, sensitive files present, and secret-like Redis values. Inspectra does not execute Redis or Sentinel, run `redis-cli`, open sockets, connect to Redis/Sentinel, validate credentials, resolve includes, read host paths, read sensitive adjacent file contents, query CVEs/advisories, or claim that a Redis deployment is exploitable. Redis passwords, Sentinel auth values, Redis URLs with credentials, ACL-like values, private key blocks, errors, and exports are redacted best-effort, but uploaded archive bytes may still contain secrets and are stored locally.

Report exports are generated locally from existing job results. The generated HTML is static, self-contained, and does not include JavaScript or external CSS. Inspectra escapes dynamic content before writing HTML and XML reports, and Markdown reports render dynamic values as code spans or fenced code blocks to reduce misleading links, images, inline HTML, headings, tables, and blockquotes in external renderers. Exporting a report does not execute uploaded files, manifest scripts, or result content.

SBOM exports are generated locally from existing completed dependency-analysis jobs. They may include package names, declared version ranges, manifest paths inside uploaded archives, and conservative package URLs for clear npm/PyPI registry dependencies. Ambiguous URL, VCS, local, editable, workspace, or alias dependencies keep the original declaration and an omitted-`purl` reason. They do not include vulnerability assertions.

Web audit results are generated from bounded HTTP/HTTPS responses. Anti-SSRF validation blocks localhost, private ranges, link-local addresses, multicast/reserved addresses, and cloud metadata targets by default. `INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS=true` can be used for authorized lab targets, but metadata/link-local/multicast/reserved addresses remain blocked. `INSPECTRA_WEB_ALLOWED_PORTS` defaults to `80,443`; adding other ports should be limited to authorized labs and does not make Inspectra scan ports. These checks reduce risk but do not replace network-level egress controls, especially against DNS rebinding or resolver time-of-check/time-of-use races.

Web results redact cookie values, sensitive response headers, and common sensitive query parameters before storage and export. Inspectra uses the full submitted URL for the authorized request, but stores a safer display URL where parameters such as `token`, `api_key`, `session`, `password`, `code`, and `state` are replaced with `REDACTED`. This is a best-effort guardrail; users should still avoid submitting real secrets because unusual parameter names may not be recognized. Inspectra is a local MVP and should not be exposed publicly without authentication, authorization, TLS, and deployment hardening.

Domain audit results can include operational DNS metadata from TXT, SOA, NS, MX, CAA, and related records. TXT values are bounded and obvious `token`, `secret`, `password`, and key-style assignments are redacted best-effort, but DNS records should still be treated as potentially sensitive local result data.

Subdomain inventory results can include hostnames, CNAME targets, IP addresses, and private/internal addressing indicators for explicitly supplied candidates. Private/reserved IP indicators are inventory signals for manual review, not confirmed vulnerabilities. Treat these results as potentially sensitive inventory data.

## Container Boundary

External audit tools run in the `audit-tools` container, not on the host and not in the backend container. The MVP also avoids mounting the Docker socket into the backend.

The container boundary reduces host exposure, but it is not a perfect sandbox. Parser bugs in file tooling are still possible, so the tool container is constrained with:

- Internal Compose networking for backend-to-runner traffic; the runner also has a separate egress-capable network for explicit `web_basic` HTTP/HTTPS requests and bounded `domain_basic`/`subdomain_inventory_basic` DNS queries.
- Read-only root filesystem.
- Read-only access to `data/`.
- Dropped Linux capabilities.
- `no-new-privileges`.
- Temporary storage limited to `/tmp`.
- Per-tool command timeouts through `INSPECTRA_TOOL_TIMEOUT_SECONDS`, defaulting to 10 seconds.
- Web audit timeouts, response byte limits, redirect limits, allowed-port controls, and anti-SSRF checks through `INSPECTRA_WEB_TIMEOUT_SECONDS`, `INSPECTRA_WEB_MAX_RESPONSE_BYTES`, `INSPECTRA_WEB_MAX_REDIRECTS`, `INSPECTRA_WEB_ALLOWED_PORTS`, and `INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS`.
- Domain DNS query timeouts through `INSPECTRA_DOMAIN_DNS_TIMEOUT_SECONDS`; the backend gives the runner a larger calculated call timeout for the full bounded DNS baseline.
- Subdomain inventory candidate, wildcard-probe, and whole-job deadline limits through `INSPECTRA_SUBDOMAIN_MAX_CANDIDATES`, `INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS`, and `INSPECTRA_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS`. The deadline is a guardrail for availability and can produce partial/truncated results.
- The public subdomain inventory API rejects the whole request if any submitted candidate is invalid; the runner is not called for rejected public requests. Wildcard probes are the only generated DNS names and can be disabled with `INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS=0`.
- Archive-specific analysis limits for entries, estimated uncompressed size, entry-name length, and listed entries.
- ZIP central directory metadata limits before detailed ZIP parsing.
- Django config analysis limits through `INSPECTRA_DJANGO_CONFIG_MAX_FILES`, `INSPECTRA_DJANGO_CONFIG_MAX_FILE_BYTES`, and `INSPECTRA_DJANGO_CONFIG_MAX_TOTAL_BYTES`.
- Docker config analysis limits through `INSPECTRA_DOCKER_CONFIG_MAX_FILES`, `INSPECTRA_DOCKER_CONFIG_MAX_FILE_BYTES`, and `INSPECTRA_DOCKER_CONFIG_MAX_TOTAL_BYTES`.
- Secrets review analysis limits through `INSPECTRA_SECRETS_REVIEW_MAX_FILES`, `INSPECTRA_SECRETS_REVIEW_MAX_FILE_BYTES`, and `INSPECTRA_SECRETS_REVIEW_MAX_TOTAL_BYTES`.
- Node package config analysis limits through `INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILES`, `INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILE_BYTES`, and `INSPECTRA_NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES`.
- CI/CD config analysis limits through `INSPECTRA_CI_CD_CONFIG_MAX_FILES`, `INSPECTRA_CI_CD_CONFIG_MAX_FILE_BYTES`, and `INSPECTRA_CI_CD_CONFIG_MAX_TOTAL_BYTES`.
- Kubernetes config analysis limits through `INSPECTRA_K8S_CONFIG_MAX_FILES`, `INSPECTRA_K8S_CONFIG_MAX_FILE_BYTES`, and `INSPECTRA_K8S_CONFIG_MAX_TOTAL_BYTES`.
- Terraform config analysis limits through `INSPECTRA_TERRAFORM_CONFIG_MAX_FILES`, `INSPECTRA_TERRAFORM_CONFIG_MAX_FILE_BYTES`, and `INSPECTRA_TERRAFORM_CONFIG_MAX_TOTAL_BYTES`.
- Nginx config analysis limits through `INSPECTRA_NGINX_CONFIG_MAX_FILES`, `INSPECTRA_NGINX_CONFIG_MAX_FILE_BYTES`, and `INSPECTRA_NGINX_CONFIG_MAX_TOTAL_BYTES`.
- Compose config analysis limits through `INSPECTRA_COMPOSE_CONFIG_MAX_FILES`, `INSPECTRA_COMPOSE_CONFIG_MAX_FILE_BYTES`, and `INSPECTRA_COMPOSE_CONFIG_MAX_TOTAL_BYTES`.
- Database config analysis limits through `INSPECTRA_DATABASE_CONFIG_MAX_FILES`, `INSPECTRA_DATABASE_CONFIG_MAX_FILE_BYTES`, and `INSPECTRA_DATABASE_CONFIG_MAX_TOTAL_BYTES`.
- SQL DB config analysis limits through `INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILES`, `INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILE_BYTES`, and `INSPECTRA_SQL_DATABASE_CONFIG_MAX_TOTAL_BYTES`.
- Redis config analysis limits through `INSPECTRA_REDIS_CONFIG_MAX_FILES`, `INSPECTRA_REDIS_CONFIG_MAX_FILE_BYTES`, and `INSPECTRA_REDIS_CONFIG_MAX_TOTAL_BYTES`.
- Explicit development CORS origins through `INSPECTRA_CORS_ORIGINS`.

## Operational Guidance

- Keep Docker and base images patched.
- Rebuild images after dependency updates.
- Review tool additions before enabling them.
- Prefer passive checks.
- Add timeouts to every external command.
- Do not add network scanners or exploit frameworks in this phase.
