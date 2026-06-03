# Active Network Block 16 Authorized HTTP Header Probe Frontend Implementation

Status: `ACTIVE_HTTP_HEADER_PROBE_FRONTEND_IMPLEMENTED`.

Base design: `docs/future/active-network-block-15-authorized-http-header-probe-frontend-design.md`

Backend review: `docs/future/active-network-block-14-end-to-end-authorized-http-header-probe-contract-redaction-review.md`

Commit scope: frontend implementation, frontend tests, and documentation alignment. No backend, runner, passive analyzer, or `tools/runner/main.py` changes were made.

## Implemented Surface

- Added a separate dashboard panel titled `Authorized HTTP Header Probe`.
- Kept the panel in the `Active / Network` dashboard area and visually separate from `Active / Network dry-run`.
- Added target URL input with placeholder `https://example.test/`.
- Added exact request contract helper for `POST /active/network/http-header-probe`.
- Added required authorization checkbox:
  - `I confirm I own or am authorized to test this target.`
- Added required live traffic checkbox:
  - `I understand this will send one HTTP HEAD request to the target.`
- Submit remains disabled until target, authorization, and live traffic confirmation are present.
- Added catalog/filter metadata for `active_http_header_probe`.
- Added job-table target redaction and summary display for `active_http_header_probe`.
- Added `ActiveHttpHeaderProbeJobReport`.
- Added defensive frontend redaction for report sections and Redacted Raw JSON.

## Request Contract

The frontend sends only:

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

The UI does not send custom headers, cookies, auth, archive `file_id`, unknown fields, or any request body beyond the backend job creation JSON.

## UX Copy

The panel uses controlled live-copy:

- `Live request`
- `One HTTP HEAD request`
- `No body read`
- `Redirects not followed`
- `Create authorized header probe job`

The panel states:

```text
Create a job for one authorized HTTP HEAD request to one explicit URL. This may be logged by the target. No redirects are followed and no response body is read.
```

Disabled backend response copy is controlled:

```text
Active HTTP header probe is disabled in this environment.
This deployment has not enabled live header probes.
```

The frontend does not provide `.env` editing guidance, bypass guidance, retry spam, or claims that DNS/HTTP was attempted when the backend rejects the request.

## Report Sections

`ActiveHttpHeaderProbeJobReport` renders:

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

Badges:

- `Active / Network`
- `Live HEAD request`
- `Body not read`
- `Redirects not followed`

The report handles queued, running, completed, failed, blocked, sparse, malformed, and legacy payloads without crashing.

## Redaction Guarantees

Frontend report rendering, job target display, form feedback, errors, observations, findings, response headers, and Raw JSON defensively redact:

- URL userinfo
- sensitive query parameters
- response headers
- cookies and sessions
- bearer/basic credentials
- API keys
- passwords
- tokens
- client secrets
- credential URLs
- private key blocks and `PRIVATE KEY` text
- legacy payload fields

The fixed placeholder is:

```text
[REDACTED]
```

The frontend does not intentionally emit secret prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

## Scope Preserved

- No backend changes.
- No runner changes.
- No `tools/runner/main.py` changes.
- No passive analyzer changes.
- No archive/file action integration.
- No run-all integration.
- No Nmap.
- No redirects.
- No body read.
- No custom headers.
- No auth/cookies.
- No port checks.
- No crawling.
- No live behavior changes.
- No tag, release, push, or `.env` guidance.

## Reference Validations

```text
git status --short
git status --branch --short
git log --oneline -12
npm run test -- --run ActiveHttpHeaderProbeJobReport App dashboardFilters reportHelpers
npm run test -- --run
npm run build
git diff --check
git diff --cached --check
```

Backend pytest is not required for this block because backend and runner runtime were not changed.

## Residual Risks

- When the backend feature flag is enabled, this remains a live request workflow and may be logged by the target.
- Frontend redaction is defensive and complements backend/API/export redaction; it does not sanitize stored source data elsewhere.
- The frontend presents backend results; it does not establish live target truth beyond the backend contract.
- Future broad Active work still requires separate docs-first design and review.

## Next Microphase

Completed next microphase:

```text
ACTIVE-NETWORK-BLOCK-17-END-TO-END-AUTHORIZED-HTTP-HEADER-PROBE-FRONTEND-REVIEW
```

Review record: `docs/future/active-network-block-17-end-to-end-authorized-http-header-probe-frontend-review.md`

That block reviews the full frontend/API/reporting redaction path without changing backend, runner, Nmap scope, request limits, or live behavior.
