# Inspectra web_basic security review

## 1. Executive summary

The `web_basic` module is integrated coherently with the current Inspectra MVP. The backend requires explicit authorization confirmation, supports jobs without `file_id`, stores `target_url`, and delegates analysis to the `audit-tools` runner. The runner keeps the audit bounded: it accepts only absolute HTTP/HTTPS URLs, applies SSRF checks, validates every redirect, enforces allowed ports, limits redirects and response bytes, redacts cookie values and sensitive response headers, and does not crawl, fuzz, brute-force, scan ports, execute JavaScript, or query CVE/reputation services.

Overall recommendation: continue to the next phase after accepting the low/info items below. No critical or high findings were observed. The most important follow-up before more active web/infrastructure checks is to decide whether target URL query strings should be redacted or explicitly accepted as stored local audit input.

Main strengths:

- Clear public endpoint and internal runner boundary for `web_basic`.
- Defense-in-depth validation in both backend and runner.
- Explicit authorization confirmation at the API and UI level.
- Conservative default port policy through `INSPECTRA_WEB_ALLOWED_PORTS=80,443`.
- Cookie values and sensitive headers are redacted in stored results and exports.
- Compose keeps `audit-tools` unexposed while giving it a separate egress-capable network for authorized HTTP/HTTPS requests.
- Tests cover authorization, URL validation, private/metadata blocking, ports, redirects, cookie redaction, exports, and frontend launch flow.

Main risks:

- Target URLs, including query strings, are stored and exported as job data.
- DNS validation is pre-connect; Python's HTTP/TLS stack resolves again at connection time, so DNS rebinding/TOCTOU is reduced but not eliminated.
- TLS test coverage is helper-level only; there is no local HTTPS integration fixture yet.

## 2. Scope reviewed

- Backend: `backend/app/main.py`, `backend/app/models.py`, `backend/app/services.py`, `backend/app/storage.py`, `backend/app/reporting.py`, `backend/app/web_security.py`, backend tests.
- Runner: `tools/runner/main.py`, web SSRF/DNS helpers, redirects, cookies, TLS, `robots.txt`, `security.txt`, runner tests.
- Frontend: `frontend/src/App.tsx`, `frontend/src/api.ts`, `frontend/src/types.ts`, `frontend/src/WebJobReport.tsx`, `frontend/src/webReport.ts`, `frontend/src/dashboardFilters.ts`, frontend tests.
- Reporting/export: Markdown, HTML, XML, PDF paths for `web_basic`.
- Docker: `docker-compose.yml`, service networks, mounts, exposed ports, security options.
- Documentation: `README.md`, `docs/architecture.md`, `docs/security-scope.md`, previous MVP audit.
- Tests and local risk-pattern searches.

## 3. Validations executed

| Command | Result | Observations |
| --- | --- | --- |
| `git status --short` initial | Passed | Working tree was clean. |
| `git log --oneline -10` | Passed | Includes `58ee471 feat(audits): add basic web configuration audit` and `d644500 fix(web): harden SSRF redirects ports and cookie redaction`. |
| `docker compose config` | Passed | `audit-tools` is on internal backend network and separate `inspectra_web_egress`; runner port is exposed only inside Compose. |
| `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools` | Passed | Python sources compile. |
| `.venv/bin/python -m pytest` | Passed | `89 passed`. Required elevated execution because sandbox blocks local HTTP server bind/listen on `127.0.0.1`; no internet targets were used. |
| `npm run build` in `frontend` | Passed | TypeScript and Vite production build completed. |
| `npm run test -- --run` in `frontend` | Passed | `14 passed`. |
| Risk-pattern searches | Passed with expected hits | No `shell=True`, `os.system`, `eval(`, `exec(`, `dangerouslySetInnerHTML`, `docker.sock`, wildcard CORS, Nmap, fuzzing, brute-force, or crawler implementation found. Hits for HTTP URLs, package-manager names, and sensitive strings were documentation, tests, local healthchecks, or passive parser/reporting code. |
| `git diff --check` | Passed | No whitespace errors. |
| `git diff --cached --check` | Passed | No staged whitespace errors before commit. |

## 4. Findings

### INSPECTRA-WEB-REVIEW-001

- Severity: low
- Area: backend, frontend, reporting
- Status: open
- Evidence: `backend/app/storage.py:288-289`, `frontend/src/WebJobReport.tsx:32`, `README.md:239`
- Description: `web_basic` stores and displays the target URL as submitted after normalization. Userinfo is rejected, but query strings remain part of `target_url`, job JSON, UI raw JSON, and exports.
- Impact: If a user submits a URL with secrets in query parameters, such as `token`, `api_key`, `session`, or `password`, those values can persist in local job results and exported reports. This is currently documented, but it is easy for users to overlook.
- Recommendation: Add a future microfase for query-parameter handling. Options: warn in UI before submission, redact common sensitive query parameter names in stored/reporting views, or store both `request_url` internally and `display_url` redacted for results.
- Priority suggested: P2 before exposing Inspectra beyond trusted local use.

### INSPECTRA-WEB-REVIEW-002

- Severity: low
- Area: runner
- Status: accepted-risk
- Evidence: `tools/runner/main.py:653-671`, `tools/runner/main.py:601`, `tools/runner/main.py:795`, `docs/architecture.md:95`
- Description: SSRF validation resolves hostnames before each request and redirect, but `http.client` and `socket.create_connection` connect by hostname later and can resolve again internally. This leaves a DNS rebinding/time-of-check-to-time-of-use limitation.
- Impact: A hostile DNS setup could theoretically return safe addresses during validation and blocked addresses during connection. The risk is reduced by repeated validation, default private-range blocking, port restrictions, and container isolation, but it is not eliminated in application code.
- Recommendation: Keep the documented limitation. For a later hardening phase, consider connecting to a prevalidated IP while preserving Host/SNI, or enforce network-level egress policy at Docker/host/firewall level. Avoid complex custom DNS/socket code until there is a clear deployment need.
- Priority suggested: P2 for any non-local or multi-user deployment.

### INSPECTRA-WEB-REVIEW-003

- Severity: info
- Area: tests
- Status: open
- Evidence: `tools/tests/test_runner.py:798-805`, `tools/runner/main.py:786-806`
- Description: TLS coverage currently validates certificate summary parsing with simulated certificate data, while the full HTTPS path is not exercised by a local TLS server fixture.
- Impact: The TLS code path uses standard library primitives and handles inspection errors, but regressions around a real TLS handshake, self-signed certificates, SNI behavior, or local certificate parsing may be missed.
- Recommendation: Add a small local HTTPS integration fixture in a future tests-focused microfase if it can be done without brittle dependencies. Continue avoiding internet-dependent tests.
- Priority suggested: P3 before deeper TLS checks.

### INSPECTRA-WEB-REVIEW-004

- Severity: info
- Area: runner, tests
- Status: open
- Evidence: `tools/runner/main.py:844-906`, `tools/tests/test_runner.py:557-591`
- Description: `robots.txt` and `security.txt` checks are bounded and same-origin, but the helper performs a header/status request and then a second bounded request to read text content when the resource exists.
- Impact: This remains passive and low-volume, but it means the audit can make more requests than the conceptual one-per-resource model. For static files this is acceptable, but it is worth documenting in test/architecture expectations if request counts become important.
- Recommendation: In a future cleanup, either keep this as accepted behavior or refactor `fetch_http_once` to optionally return a bounded text body only for these resources, avoiding the duplicate request without storing page bodies.
- Priority suggested: P4 cleanup.

## 5. Acceptable MVP risks

- No authentication or authorization layer: acceptable only for local/dev use; do not expose publicly.
- `web_basic` performs bounded HTTP/HTTPS requests but does not provide network isolation guarantees by itself; use Docker/host egress controls for stricter environments.
- DNS rebinding/TOCTOU is documented and accepted for MVP.
- TLS inspection is baseline only, not a TLS scanner.
- No crawling, no JavaScript execution, no screenshots/browser rendering.
- No Nmap, no port scanning, no fuzzing, no brute force, no exploit checks.
- No CVE enrichment or external reputation/API lookups.
- Findings are configuration indicators for manual review, not confirmed vulnerabilities.
- Target URLs and query strings may be stored locally unless a future redaction policy is added.

## 6. Test gaps

Priority order:

1. Add a local HTTPS integration test for `web_basic` with a temporary self-signed certificate, if stable in CI/local.
2. Add explicit runner tests for malformed `Set-Cookie` parsing to confirm no raw cookie value is returned on parse errors.
3. Add frontend test for submitting the web form without authorization confirmation and rendering the backend error clearly.
4. Add export regression tests for queued/running/failed `web_basic` jobs with sparse result fields.
5. Add query-string handling tests once a redaction or warning policy is chosen.

## 7. Documentation gaps

- Documentation already covers authorization, variables, no crawling/fuzzing/Nmap/CVEs, cookie/header redaction, and DNS rebinding/TOCTOU limits.
- A future README/UI note could be more prominent about not submitting secrets in URL query parameters.
- If request counts matter, document that `robots.txt` and `security.txt` checks can make a bounded status/header request plus a bounded body read request.
- If Inspectra is deployed beyond local development, add an operational hardening page covering authentication, TLS termination, egress firewalling, logs, and data retention.

## 8. Recommendation for next microphases

1. No critical/high fixes are required before continuing.
2. Address low web hardening items if Inspectra will be used outside a trusted local lab:
   - query-string redaction/warning,
   - optional egress firewall guidance,
   - local HTTPS integration test.
3. Add `domain_basic` DNS baseline next, keeping it passive and bounded.
4. Add subdomain inventory only from explicit user-provided sources or passive local inputs; avoid brute force.
5. Add `django_config_basic` for uploaded local config files before internet-facing framework probes.
6. Add `infra_basic` with Nmap only in a later phase, with explicit authorization, target allowlists, strict rate/port controls, and separate documentation.
