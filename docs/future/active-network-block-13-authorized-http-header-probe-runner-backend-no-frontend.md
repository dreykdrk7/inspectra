# Active Network Block 13 Authorized HTTP Header Probe Runner Backend No Frontend

Status: `ACTIVE_HTTP_HEADER_PROBE_RUNNER_BACKEND_IMPLEMENTED_NO_FRONTEND`.

Follow-up review: `docs/future/active-network-block-14-end-to-end-authorized-http-header-probe-contract-redaction-review.md`.

Base design: `docs/future/active-network-block-12-authorized-http-header-probe-design.md`

Commit scope: runner/backend implementation, backend reporting, tests, and minimal documentation alignment.

## Implemented Surface

- Added the separate `tools/active_runner` HTTP header probe runtime.
- Added backend feature flag `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED=false`.
- Added backend endpoint `POST /active/network/http-header-probe`.
- Added job/audit type `active_http_header_probe`.
- Added backend job storage summaries and public API redaction.
- Added Markdown/HTML/XML/PDF reporting sections for the header probe.
- Added tests for runner policy, backend endpoint behavior, redaction, exports, and sparse payload tolerance.

## Request Contract

The endpoint accepts a single-target live request with:

- `mode: live_header_probe`
- `profile: http_header_probe`
- authorization confirmation and live traffic confirmation
- one target URL with explicit `http://` or `https://`
- v0 limits capped to one `HEAD` request, no redirects, no body read, no retries, and one target

Unknown request, authorization, or limit fields are rejected before job creation.

## Scope Preserved

- No frontend changes.
- No archive action integration.
- No dry-run auto-run integration.
- No `tools/runner/main.py` changes.
- No Nmap.
- No subprocesses.
- No browser automation.
- No redirects.
- No response body read.
- No request body.
- No custom user-supplied headers.
- No port scanning, crawling, fuzzing, exploit checks, credential validation, or certificate inventory.

## Runtime Safety

The backend rejects the endpoint without job creation unless `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED=true`.

The active runner performs DNS resolution only after feature flag gating, authorization parsing, target validation, profile validation, and limit validation have passed. DNS answers are bounded and every resolved address is checked against blocked address classes. If any answer is blocked, the probe fails closed and sends no HTTP request.

When allowed, the runner sends exactly one HTTP `HEAD` request with fixed headers:

- `User-Agent: Inspectra active-header-probe`
- `Accept: */*`

The runner does not follow redirects and does not read the response body. `network_requests_sent` is `1` only after the HEAD request is attempted; blocked or pre-request errors preserve `network_requests_sent: 0`.

## Reporting

Reports include:

- Active Scope Notice
- Target Summary
- Authorization Summary
- Policy Decision
- DNS Policy Summary
- Request Sent
- Response Headers
- Observations
- Findings
- Blocked Reasons
- Limits
- Audit Log
- Errors
- Redacted Raw JSON

Reports use controlled copy such as `One authorized HTTP HEAD request was sent.`, `No HTTP request was sent.`, and `Response body was not read.`.

## Redaction Guarantees

Runner, backend storage, API responses, summaries, exports, errors, and Raw JSON defensively redact:

- Authorization headers
- Bearer and Basic credentials
- cookie/session values
- URL userinfo
- sensitive query parameters
- token/password/API key/client secret assignments
- credential URLs
- private key blocks and `PRIVATE KEY` text

The placeholder is fixed:

```text
[REDACTED]
```

The implementation does not intentionally emit secret prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

## Reference Validations

```text
git status --short
git status --branch --short
git log --oneline -12
python3 -m compileall backend tools/active_runner
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools/active_runner
.venv/bin/python -m pytest tools/tests/test_active_runner.py
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_http or http_header"
.venv/bin/python -m pytest backend/tests/test_backend.py
rg "subprocess|nmap|selenium|playwright|puppeteer" tools/active_runner backend/app backend/tests tools/tests
git diff --check
git diff --cached --check
```

Frontend/npm validation is not required for this block because no frontend files are changed.

## Residual Risks

- This is a live probe capability when enabled; it sends one authorized HTTP HEAD request.
- DNS and HTTP behavior depend on the local runtime and target behavior.
- HEAD may still be logged by the target.
- Header observations are heuristics and do not prove exploitability, compromise, or safe posture.
- Frontend controls are intentionally absent until a separate UX block.
- Redaction is defensive and best-effort; users should avoid submitting secrets in targets.

## Next Microphase

Recommended next microphase:

```text
ACTIVE-NETWORK-BLOCK-14-END-TO-END-AUTHORIZED-HTTP-HEADER-PROBE-CONTRACT-REDACTION-REVIEW
```

That review should verify the full enabled/disabled contract, DNS fail-closed behavior, no-body-read behavior, reporting/export redaction, and API/storage redaction without adding frontend controls or broadening live network behavior.
