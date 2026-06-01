# nginx_config_basic Closeout

Status: `nginx_config_basic` is implemented and stable as a v1 passive archive-based web-edge config audit module.

This closeout records the runtime scope, smoke checks, redaction posture, residual risks, and product decision for Nginx/reverse-proxy config audits. The original docs-first design remains in `docs/future/nginx-config-basic-design.md`.

## Commit Series

- `f589075 docs(nginx): design passive reverse proxy config audit`
- `648b30c feat(nginx): add passive config runner analysis`
- `017b120 feat(nginx): add config backend job`
- `d3170cf feat(nginx): add config report frontend ux`
- `fe982ca fix(nginx): align config contract and redaction`

## Implemented Surfaces

- Runner endpoint: `POST /analyze/nginx-config`.
- Backend endpoint: `POST /audits/nginx-config/{file_id}`.
- Audit type: `nginx_config_basic`.
- Source files: uploaded files registered as `kind: "archive"`.
- Frontend action: `Analyze Nginx config`, shown only for archive files.
- Reporting/export: Markdown, HTML, XML, and PDF sections for Nginx summary data, files, server blocks, locations, upstreams, includes, directives, findings, limits, redaction notes, and errors.
- Frontend raw JSON is defensively redacted before rendering.

## Capabilities

`nginx_config_basic` passively reviews bounded Nginx/reverse-proxy config text from uploaded archives. It detects candidate config files and uses a textual Nginx-like parser for directives and basic blocks.

The v1 model returns review context for:

- Files detected and reviewed.
- Server blocks.
- Locations.
- Upstreams and proxy targets.
- `include` directives.
- Directives and their safe, redacted arguments.

Includes are detected as context and are not resolved. If an included file is also a normal archive candidate, it can be analyzed by ordinary candidate scanning, not by include resolution.

The v1 finding model focuses on conservative review indicators for:

- TLS/HTTPS posture.
- Missing or weak security headers.
- Server exposure.
- `autoindex`, `stub_status`, hidden files, backup paths, and sensitive locations.
- Proxy and CORS behavior.
- Upload/body-size, timeout, and logging posture.
- `proxy_pass` credentials.
- Authorization/header/variable secret-like values.

Findings are review indicators for human triage. They are not confirmed vulnerabilities, exploitability claims, live-server truth, or proof of compromised infrastructure.

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

- No Nginx execution.
- No `nginx -t`.
- No Docker or container startup.
- No server startup.
- No network calls.
- No DNS resolution.
- No port scanning.
- No live server validation.
- No real certificate validation.
- No include resolution outside normal archive candidate scanning.
- No host path reads.
- No real `.env`, `.env.*`, or `.envrc` reads.
- No Apache, Caddy, Traefik, HAProxy, or Envoy runtime support in v1.
- No CVE or advisory lookup.
- No exploitability, compromise, or confirmed-vulnerability claims.

## Redaction Guarantees

The module treats Nginx/web-edge secrets defensively and best-effort:

- Inline basic auth credentials are redacted.
- `proxy_pass` URLs with embedded credentials are redacted.
- Authorization headers and bearer/basic tokens are redacted.
- API keys, tokens, client secrets, passwords, cookies, and session values are redacted.
- Private key blocks are redacted without preserving `PRIVATE KEY`.
- Certificate and private key contents are redacted.
- Upstream URLs with credentials are redacted.
- Secret-like variable, map, header, directive, and argument values are redacted.
- Evidence may show safe context such as file path, directive name, block type, server name, location path, upstream name, line number, or `[REDACTED]`.
- The implementation does not intentionally emit prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers.

Uploaded archive bytes may still contain secrets and are stored locally; redaction protects Inspectra results and reports, not the original uploaded archive.

## Smoke Checklist

Recommended manual smoke before opening the next module:

1. Upload a small `.zip` or `.tar.gz` archive containing Nginx config files.
2. Confirm the uploaded file is registered as `kind: "archive"`.
3. Confirm `Analyze Nginx config` appears for the archive file.
4. Launch the analysis from the UI or call `POST /audits/nginx-config/{file_id}`.
5. Confirm the job appears as `nginx_config_basic` and transitions through queued/running to completed or a controlled failed state.
6. Open the frontend report and confirm summary, files, server blocks, locations, upstreams/proxy targets, includes, directives, findings, limits/errors, redaction notes, and raw JSON render clearly.
7. Export the job as Markdown, HTML, XML, and PDF.
8. Confirm includes are shown as detected and not resolved.
9. Confirm fixture secrets do not appear in UI, raw JSON, API responses, exports, or controlled errors.
10. Upload a non-archive file and confirm the Nginx action is not shown or is rejected by the backend according to the standard archive-only pattern.
11. Confirm the smoke does not run Nginx, `nginx -t`, Docker, DNS, port scans, certificate validation, CVE/advisory lookups, or external services.

Suggested fixture secret strings for negative checks:

- `super-secret-password`
- `raw-api-key-123456`
- `token_should_never_render`
- `Authorization: Bearer token_should_never_render`
- `http://user:pass@example.com`
- `registry-user:registry-pass`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`
- `sessionid=secret-session-cookie`
- `proxy_password_should_not_render`

## Reference Validations

The end-to-end closeout series used focused runner, backend, frontend, build, and redaction checks, including:

```bash
.venv/bin/python -m pytest tools/tests/test_runner.py -k nginx_config
.venv/bin/python -m pytest backend/tests/test_backend.py -k nginx_config
.venv/bin/python -m pytest backend/tests/test_backend.py
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
npm run test -- --run NginxConfigJobReport reportHelpers App dashboardFilters
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

- Nginx-like heuristics can produce false positives and false negatives.
- Full Nginx inheritance is not modeled.
- Includes are detected but not resolved.
- Missing security header and HTTPS redirect findings may be low confidence because snippets/includes may be unresolved.
- Variables are not evaluated.
- Maps and conditionals are not fully interpreted.
- Real TLS and certificate status are not checked.
- Live server behavior is not validated.
- Redaction is best-effort and may miss uncommon secret formats.

## Product Decision

`nginx_config_basic` v1 is ready to close. It fits the Inspectra passive module pattern: docs-first scope, bounded runner analysis, backend job/reporting, frontend report UX, and end-to-end contract/redaction review.

Do not add more Nginx implementation now. Future reverse-proxy expansions should be separate docs-first modules or microphases after broader Inspectra coverage improves.

Potential backlog:

- Apache config basic.
- Caddy config basic.
- Traefik static config basic.
- HAProxy config basic.
- Richer Nginx include modeling.
- Richer Nginx inheritance modeling.
- Optional certificate file metadata review without external validation.

Recommended next docs-first module: `compose_config_basic`.

Rationale: Docker Compose appears in many real deployments and bridges Docker config, secrets, environment, ports, volumes, networks, and reverse proxy wiring. It remains archive-only and passive, and it can reuse much of the Docker, Kubernetes, Terraform, and Nginx redaction posture.

Alternative future candidates:

- `database_config_basic`, for PostgreSQL/MySQL configuration files.
- `apache_config_basic`, if the product wants to continue web-edge coverage.
- `cloudflare_config_basic`, if users provide exported/static configuration.
