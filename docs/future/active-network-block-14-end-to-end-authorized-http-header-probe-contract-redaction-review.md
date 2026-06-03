# Active Network Block 14 End-to-End Authorized HTTP Header Probe Contract Redaction Review

Status: `ACTIVE_HTTP_HEADER_PROBE_E2E_REVIEW_PASSED_BACKEND_ONLY`.

Base implementation: `docs/future/active-network-block-13-authorized-http-header-probe-runner-backend-no-frontend.md`

Commit scope: contract review tests, minimal target-policy fix, and documentation alignment. No frontend was added.

## Reviewed Contract

The review confirmed the backend-only `active_http_header_probe` contract:

- Feature flag: `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED=false` by default.
- Endpoint: `POST /active/network/http-header-probe`.
- Job type: `active_http_header_probe`.
- Runner module: `tools/active_runner/http_header_probe.py`.
- Passive runner monolith: `tools/runner/main.py` remains untouched.
- Request mode: `live_header_probe`.
- Profile: `http_header_probe`.
- Method: one HTTP `HEAD` request only.
- Redirects followed: `0`.
- Response body read: no.
- Response body bytes read: `0`.
- Custom user headers: not accepted.
- Nmap/subprocess: not implemented.

## Disabled-State Result

With the feature flag disabled, the backend returns:

```text
Active HTTP header probe is disabled in this environment.
```

No job is created. The disabled response does not include `.env` guidance, bypass guidance, retry guidance, DNS claims, or HTTP target-processing claims.

## Enabled Valid Result

With the feature flag enabled and a valid request, tests verify:

- job type is `active_http_header_probe`;
- `file_id` is `null`;
- job completes through the existing job lifecycle;
- `network_requests_sent` is `1` only after the HEAD request is attempted;
- request method is `HEAD`;
- outgoing headers are fixed to `User-Agent` and `Accept`;
- no `Authorization` or `Cookie` request headers are sent;
- no response body is read;
- response headers are captured, bounded, and redacted;
- Markdown/HTML/XML/PDF exports render the active sections.

## DNS Fail-Closed Result

Runner tests use fake resolvers and fake transports. They verify no HTTP request is sent when DNS returns:

- private addresses;
- loopback addresses;
- metadata address `169.254.169.254`;
- mixed allowed and blocked answers;
- more answers than the configured cap;
- no usable answers;
- controlled resolver failures.

All of these preserve:

```text
network_requests_sent: 0
```

## Target Policy Review

Target rejection is tested before DNS or HTTP for:

- URL userinfo;
- CIDR/ranges;
- wildcards;
- unsupported schemes;
- `file:` URLs;
- private IP URLs;
- loopback URLs;
- metadata IP URLs;
- suspicious shell-like input;
- multiple-target-like malformed input;
- bare hostnames without an explicit URL scheme.

## Bug Fixed

The review found a small target-policy consistency gap: live targets without `://` were classified as `live_url_required` before CIDR/range/wildcard/suspicious checks could produce their more precise blocker. The runner now reuses the shared target normalizer for no-scheme inputs first, preserving specific fail-closed reasons while still rejecting valid bare hostnames as `live_url_required`.

## Redaction Review

Runner, backend storage, `GET /jobs`, `GET /jobs/{job_id}`, Markdown export, HTML export, XML export, PDF export, controlled errors, and Raw JSON are tested against legacy/malformed payloads containing:

- `super-secret-password`
- `token_should_never_render`
- `raw-api-key-123456`
- `http://user:pass@example.com`
- `Authorization: Bearer token_should_never_render`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`
- `session_should_not_render`
- `cookie_should_not_render`

The expected placeholder is:

```text
[REDACTED]
```

The implementation does not intentionally emit secret prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

## Reporting Review

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

The copy includes:

- `One authorized HTTP HEAD request was sent.`
- `No HTTP request was sent.`
- `Response body was not read.`

The copy avoids claims such as:

- vulnerability confirmed;
- target is safe;
- credential valid;
- bypass;
- evade;
- Nmap scan;
- live exploitability.

## Dry-Run Regression Review

Active dry-run tests still verify:

- `active_network_dry_run` remains no-network;
- `network_requests_sent` remains `0`;
- dry-run and live probe feature flags are independent;
- enabling the live flag does not enable dry-run;
- dry-run output still contains no DNS results, response headers, HTTP status codes, or Nmap output.

## Safety Grep

The review runs:

```text
rg "subprocess|nmap|selenium|playwright|puppeteer|GET|allow_redirect|redirect|read\(|recv\(" tools/active_runner backend/app backend/tests tools/tests
```

Expected interpretation:

- no subprocess import or invocation;
- no Nmap runtime;
- no Selenium/Playwright/Puppeteer;
- no GET fallback;
- no response body `.read()`/`.recv()` in `tools/active_runner/http_header_probe.py`;
- `GET /jobs` and no-scope test strings are acceptable matches.

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
.venv/bin/python -m pytest
git diff --check
git diff --cached --check
```

No npm validation is required because no frontend files are touched.

## Residual Risks

- When enabled, this is live traffic and may be logged by the target.
- DNS and HTTP behavior depend on the local runtime and target behavior.
- Header observations are heuristic and do not prove exploitability, compromise, or safe posture.
- Frontend controls remain intentionally absent.
- Redaction remains defensive and best-effort.

## Final Decision

`active_http_header_probe` is accepted for backend-only status after end-to-end contract and redaction review.

The feature remains disabled by default, limited to one authorized HEAD request, and separate from any Nmap or broader Active scanning work.

## Next Microphase

Recommended next microphase:

```text
ACTIVE-NETWORK-BLOCK-15-AUTHORIZED-HTTP-HEADER-PROBE-FRONTEND-DESIGN-NO-RUNTIME
```

That block should be docs-first and UI-design-only unless explicitly approved otherwise.
