# Active Network Block 17 End-to-End Authorized HTTP Header Probe Frontend Review

Status: `ACTIVE_HTTP_HEADER_PROBE_FRONTEND_E2E_REVIEW_PASSED`.

Frontend implementation: `docs/future/active-network-block-16-authorized-http-header-probe-frontend-implementation.md`

Frontend design: `docs/future/active-network-block-15-authorized-http-header-probe-frontend-design.md`

Backend review: `docs/future/active-network-block-14-end-to-end-authorized-http-header-probe-contract-redaction-review.md`

Commit scope: frontend E2E-style tests, redaction regression tests, and documentation alignment. No backend, runner, passive analyzer, or `tools/runner/main.py` changes were made.

## Reviewed Surfaces

- Dashboard panel: `Authorized HTTP Header Probe`.
- API helper: `POST /active/network/http-header-probe`.
- Request body for `live_header_probe` / `http_header_probe`.
- Double-confirmation form behavior.
- Disabled backend state.
- Job catalog/filter metadata.
- Job-table target display.
- `ActiveHttpHeaderProbeJobReport`.
- Response header display.
- Redacted Raw JSON.
- Forbidden wording in the new probe UI.
- Archive action isolation.

## Disabled-State Review

Frontend tests verify that a backend `403` with:

```text
Active HTTP header probe is disabled in this environment.
```

renders:

```text
Active HTTP header probe is disabled in this environment.
This deployment has not enabled live header probes.
```

The disabled UI does not show `.env` guidance, bypass guidance, retry spam, claims that DNS/HTTP was attempted, or the raw submitted target containing URL userinfo or sensitive query parameters.

The mocked disabled flow does not create a job or trigger an additional job refresh after the rejected creation request.

## Form Contract Review

Tests verify:

- the live probe panel renders separately from `Active / Network dry-run`;
- target is required;
- authorization checkbox is required;
- live traffic checkbox is required;
- submit stays disabled until target plus both confirmations are present;
- submit calls `POST /active/network/http-header-probe`;
- request body has only `target`, `authorization`, `mode`, `profile`, and `limits`;
- authorization has only `confirmed`, `live_traffic_confirmed`, `statement`, and `scope`;
- limits have only the v0 limit keys;
- the body contains no `file_id`, custom headers, cookies, auth headers, or unknown fields.

Expected request contract:

```json
{
  "target": "https://example.test/",
  "authorization": {
    "confirmed": true,
    "live_traffic_confirmed": true,
    "statement": "I confirm I own or am authorized to test this target.",
    "scope": "single-target"
  },
  "mode": "live_header_probe",
  "profile": "http_header_probe",
  "limits": {
    "max_targets": 1,
    "max_requests": 1,
    "timeout_seconds": 3,
    "max_redirects": 0,
    "response_body_bytes": 0,
    "max_response_header_bytes": 32768,
    "max_dns_answers": 8,
    "retries": 0,
    "concurrency": 1
  }
}
```

## Job Catalog And Filter Review

Tests verify:

- audit type: `active_http_header_probe`;
- label: `Authorized HTTP header probe`;
- category: `Active / Network`;
- source family: `target`;
- job type filters include it;
- search by label and category works;
- it remains separate from `active_network_dry_run`;
- it is not added to archive action groups or run-all style controls.

## Report Review

Tests cover completed, blocked, running, failed, sparse, malformed, and legacy payloads.

Successful completed payloads render:

- Live Probe Scope Notice
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

Required badges and copy are present:

- `Active / Network`
- `Live HEAD request`
- `Body not read`
- `Redirects not followed`
- `One authorized HTTP HEAD request was sent.`
- `Response body was not read.`
- `Redirects were not followed.`
- `Header observations are review indicators, not confirmed vulnerabilities.`

Blocked or pre-request payloads render:

```text
No HTTP request was sent.
```

without implying that live traffic occurred.

## Redaction Review

Tests verify that the job table, report target summary, response headers, observations, findings, controlled errors, and Raw JSON do not contain:

- `super-secret-password`
- `token_should_never_render`
- `raw-api-key-123456`
- `Authorization: Bearer token_should_never_render`
- `http://user:pass@example.com`
- `session_should_not_render`
- `cookie_should_not_render`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`

Expected placeholder:

```text
[REDACTED]
```

The frontend does not intentionally emit secret prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

## Forbidden Copy Review

The review checks the new probe UI for forbidden copy such as:

- `Run Nmap`
- `Nmap scan`
- `port scan`
- `brute force`
- `credential valid`
- `vulnerability confirmed`
- `target is safe`
- `bypass`
- `evade`
- `exploit`
- `attack`

The new live panel avoids `Scan` as action wording and uses `Create authorized header probe job`.

## Optional Local Smoke

No local live smoke was executed in this block. The review relies on mocked frontend/API tests, report helper tests, and existing backend-only review coverage. This avoids starting additional local services or widening the no-external-network posture during a frontend review.

A future smoke may use only a local controlled HTTP server and the already reviewed backend feature flag, with no third-party targets and no external network.

## Scope Preserved

- No backend changes.
- No runner changes.
- No `tools/runner/main.py` changes.
- No passive analyzer changes.
- No Nmap.
- No subprocesses.
- No redirects.
- No response body reads.
- No custom headers.
- No auth/cookies.
- No multi-target.
- No CIDR/ranges.
- No local-lab expansion.
- No external network tests.
- No exploit/fuzz/brute-force behavior.
- No tag, release, push, or `.env` guidance.

## Reference Validations

```text
git status --short
git status --branch --short
git log --oneline -12
npm run test -- --run ActiveHttpHeaderProbeJobReport App dashboardFilters reportHelpers
npm run test -- --run
npm run build
rg "Run Nmap|Nmap scan|port scan|brute force|credential valid|vulnerability confirmed|target is safe|bypass|evade|exploit|attack" frontend/src/ActiveHttpHeaderProbeJobReport.tsx frontend/src/App.tsx frontend/src/*Header* frontend/src/*Probe*
git diff --check
git diff --cached --check
```

Backend pytest is not required for this block because backend and runner runtime were not changed.

## Residual Risks

- When enabled by deployment configuration, the feature sends a live HEAD request and may be logged by the target.
- Frontend redaction is defensive and complements backend/API/export redaction; it does not sanitize stored source data elsewhere.
- The frontend does not prove target ownership or safety. Authorization remains a user assertion.
- Broader Active functionality still requires separate docs-first design and review.

## Final Decision

```text
ACTIVE_HTTP_HEADER_PROBE_FRONTEND_E2E_REVIEW_PASSED
```

The Authorized HTTP Header Probe frontend is accepted after E2E-style contract, UI, filter, report, redaction, and copy review.

## Next Microphase

Recommended next microphase:

```text
ACTIVE-NETWORK-BLOCK-18-AUTHORIZED-HTTP-HEADER-PROBE-DOCS-SMOKE-CLOSEOUT
```

That block should close the first live header probe UI/backend path with documentation and a manual smoke checklist, without widening Active scope.
