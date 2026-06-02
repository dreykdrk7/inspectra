# compose_config_basic Closeout

Status: `compose_config_basic` is implemented and stable as a v1 passive archive-based Docker Compose config audit module.

This closeout records the runtime scope, smoke checks, redaction posture, residual risks, and product decision for Docker Compose and Compose-like config audits. The original docs-first design remains in `docs/future/compose-config-basic-design.md`.

## Commit Series

- `3d3e9fe docs(compose): design passive compose config audit`
- `3bcfdd3 feat(compose): add passive config runner analysis`
- `d012a07 feat(compose): add config backend job`
- `9ea97c6 feat(compose): add config report frontend ux`
- `610245b fix(compose): align config contract and redaction`

## Implemented Surfaces

- Runner endpoint: `POST /analyze/compose-config`.
- Backend endpoint: `POST /audits/compose-config/{file_id}`.
- Audit type: `compose_config_basic`.
- Source files: uploaded files registered as `kind: "archive"`.
- Frontend action: `Analyze Compose config`, shown only for archive files.
- Reporting/export: Markdown, HTML, XML, and PDF sections for Compose summary data, files, services, images/build contexts, ports, volumes, networks, secrets/env file references, findings, limits, redaction notes, and errors.
- Frontend raw JSON is defensively redacted before rendering.

## Capabilities

`compose_config_basic` passively reviews bounded Docker Compose and Compose-like YAML text from uploaded archives. It detects candidate Compose files, `.env`, `.env.*`, and `.envrc` as sensitive files present, `env_file` references, `secrets.file` references, multiple Compose files, and override files.

Real `.env` files, `env_file` targets, and Compose secret files are not read. Multiple Compose files and overrides are recorded as context and are not merged into an effective runtime configuration.

The v1 model returns review context for:

- Files detected and reviewed.
- Services.
- Images and build contexts.
- Published ports.
- Volumes and mounts.
- Networks.
- Secrets and env file references.

The v1 finding model focuses on conservative review indicators for:

- Secret-like environment values.
- Published ports and database/admin/dashboard exposure hints.
- Privileged containers and host network/PID/IPC modes.
- Docker socket mounts and sensitive host paths.
- Latest or unpinned image references.
- Missing healthcheck, restart, and resource posture.
- External networks.
- Multiple Compose files and override files.

Findings are review indicators for human triage. They are not confirmed vulnerabilities, exploitability claims, runtime exposure truth, or proof of compromised infrastructure.

## Explicit Scope

- Archive-only.
- Local.
- Bounded.
- Passive.
- Heuristic.
- Redaction-first.
- No execution.
- No external services.
- Controlled errors and truncation instead of broad extraction or best-effort execution.

## Explicit Non-Scope

- No Docker execution.
- No Docker Compose execution.
- No `docker compose config`.
- No container startup.
- No build, pull, push, run, exec, or logs.
- No Docker daemon validation.
- No image inspection.
- No registry lookup.
- No CVE or advisory lookup.
- No network calls.
- No real `.env`, `.env.*`, or `.envrc` content reads.
- No secret file content reads.
- No full env interpolation.
- No effective multi-file merge.
- No runtime exposure truth.
- No exploitability, compromise, or confirmed-vulnerability claims.

## Redaction Guarantees

The module treats Compose secrets defensively and best-effort:

- Secret-like environment values are redacted.
- `.env`, `env_file`, and secret file contents are not read.
- Credential-bearing URLs are redacted.
- Registry credentials are redacted.
- Database and Redis URLs with credentials are redacted.
- API keys, tokens, passwords, and client secrets are redacted.
- Private key blocks are redacted without preserving `PRIVATE KEY`.
- Secret-like labels, command fragments, and entrypoint fragments are redacted.
- Evidence may show safe context such as file path, service name, field path, key name, port, protocol, mount target, non-secret image name/tag, network name, or `[REDACTED]`.
- The implementation does not intentionally emit prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers.

Uploaded archive bytes may still contain secrets and are stored locally; redaction protects Inspectra results and reports, not the original uploaded archive.

## Smoke Checklist

Recommended manual smoke before opening the next module:

1. Upload a small `.zip` or `.tar.gz` archive containing Compose files.
2. Confirm the uploaded file is registered as `kind: "archive"`.
3. Confirm `Analyze Compose config` appears for the archive file.
4. Launch the analysis from the UI or call `POST /audits/compose-config/{file_id}`.
5. Confirm the job appears as `compose_config_basic` and transitions through queued/running to completed or a controlled failed state.
6. Open the frontend report and confirm summary, files, services, images/build contexts, ports, volumes, networks, secrets/env files, findings, limits/errors, redaction notes, and raw JSON render clearly.
7. Export the job as Markdown, HTML, XML, and PDF.
8. Confirm `.env`, `.env.*`, `.envrc`, `env_file`, and `secrets.file` are shown as detected/no-read or referenced/not read.
9. Confirm multiple/override Compose files are shown as detected and are not merged into an effective config.
10. Confirm fixture secrets do not appear in UI, raw JSON, API responses, exports, or controlled errors.
11. Upload a non-archive file and confirm the Compose action is not shown or is rejected by the backend according to the standard archive-only pattern.
12. Confirm the smoke does not run Docker, `docker compose config`, builds, pulls, image inspection, registry/CVE/advisory lookups, env interpolation, file merge, network calls, or external services.

Suggested fixture secret strings for negative checks:

- `super-secret-password`
- `raw-api-key-123456`
- `token_should_never_render`
- `POSTGRES_PASSWORD=super-secret-password`
- `DATABASE_URL=postgres://user:pass@example.com/db`
- `redis://:super-secret-password@redis:6379/0`
- `registry-user:registry-pass`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`
- `db_password_plaintext`
- `compose_secret_file_should_not_render`

## Reference Validations

The end-to-end closeout series used focused runner, backend, frontend, build, and redaction checks, including:

```bash
.venv/bin/python -m pytest tools/tests/test_runner.py -k compose_config
.venv/bin/python -m pytest backend/tests/test_backend.py -k compose_config
.venv/bin/python -m pytest backend/tests/test_backend.py
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
npm run test -- --run ComposeConfigJobReport reportHelpers App dashboardFilters
npm run test -- --run
npm run build
git diff --check
git diff --cached --check
```

For docs-only changes, the minimum validation is:

```bash
git status --short
git diff --check
git diff --cached --check
```

## Residual Risks

- YAML-like heuristics can produce false positives and false negatives.
- Compose schema support is best-effort.
- Multiple Compose files and overrides are detected but not merged.
- `.env` variables are not interpolated.
- `env_file` and secret files are not read.
- Effective runtime configuration is not calculated.
- Docker daemon behavior is not validated.
- Images are not pulled, inspected, or checked against registries/CVEs.
- Published ports are declared configuration, not verified runtime exposure.
- Networks, volumes, and mounts are static declarations, not runtime truth.
- Redaction is best-effort and may miss uncommon secret formats.

## Product Decision

`compose_config_basic` v1 is ready to close. It fits the Inspectra passive module pattern: docs-first scope, bounded runner analysis, backend job/reporting, frontend report UX, and end-to-end contract/redaction review.

Do not add more Compose implementation now. Future Compose expansions should be separate docs-first modules or microphases after broader Inspectra coverage improves.

Potential backlog:

- Richer Compose schema support.
- Optional multi-file merge simulation without Docker execution.
- Richer reverse proxy label interpretation.
- Richer deploy/resources analysis.
- Richer profiles and support matrix.
- Optional Dockerfile handoff to `docker_config_basic`.
- Optional SBOM/image advisory handoff in a separate future module, not v1.

Recommended next docs-first module: `database_config_basic`.

Rationale: PostgreSQL, MySQL, and MariaDB config files appear frequently in real deployments. They expose high-value posture signals around bind addresses, authentication methods, SSL, logging, dangerous modes, replication, backups, and default credentials while still fitting Inspectra's passive archive-only model. This complements Compose, Docker, Nginx, Kubernetes, and Terraform by reviewing the data layer.

Alternative future candidates:

- `apache_config_basic`, if the product wants to continue web-edge coverage.
- `cloudflare_config_basic`, if users provide exported/static configuration.
- `redis_config_basic`, as a smaller data/cache config module.
