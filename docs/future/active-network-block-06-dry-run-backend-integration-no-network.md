# Active Network Block 06 Dry-Run Backend Integration No-Network

Status: `ACTIVE_DRY_RUN_BACKEND_INTEGRATED_NO_NETWORK`.

Base skeleton: `docs/future/active-network-block-04-dry-run-skeleton-no-network.md`

Base backend contract: `docs/future/active-network-block-05-dry-run-backend-contract-design.md`

End-to-end review: `docs/future/active-network-block-09-end-to-end-dry-run-contract-redaction-review.md`

Commit scope: backend endpoint, job/storage/reporting integration, defensive redaction, and backend tests.

Frontend design note: future UI/UX for this backend surface is designed in `docs/future/active-network-block-07-dry-run-frontend-design.md`.

This document records the first backend integration for the separated Active dry-run skeleton. It does not add frontend UI, run Nginx/Docker/Nmap, resolve DNS, open sockets, perform HTTP requests, call network services, start subprocess probes, add live checks, create tags, push releases, or mutate the Passive Alpha release line.

## Implemented Surface

Implemented backend endpoint:

```text
POST /active/network/dry-run
```

Implemented audit/job type:

```text
active_network_dry_run
```

Implemented backend service call:

```python
run_active_network_dry_run(active_request)
```

The backend calls the separated package under:

```text
tools/active_runner/
```

The passive runner monolith remains unchanged:

```text
tools/runner/main.py
```

## Feature Flag

The backend endpoint is disabled by default.

Environment flag:

```text
INSPECTRA_ACTIVE_DRY_RUN_ENABLED=false
```

When the flag is not enabled, `POST /active/network/dry-run` returns `403` and does not create a job.

When enabled, the endpoint accepts a dry-run request body, validates it through `ActiveDryRunRequest.from_mapping`, creates a target-based job with `file_id: null`, and executes the no-network dry-run service through the normal job pipeline.

## Request And Job Contract

The endpoint accepts the Active dry-run request contract:

```json
{
  "target": "https://example.test",
  "authorization": {
    "confirmed": true,
    "statement": "I confirm I own or am authorized to test this target.",
    "scope": "single-target"
  },
  "mode": "dry_run",
  "profile": "http_header_probe_preview",
  "limits": {
    "max_requests": 0,
    "timeout_seconds": 0,
    "max_redirects": 0,
    "response_size_bytes": 0
  }
}
```

The backend rejects malformed JSON shapes, missing targets, and unknown fields before job creation.

Policy blocks from the active runner, such as missing authorization, live mode, Nmap-like profiles, private targets, URL credentials, and nonzero dry-run limits, are stored as completed dry-run jobs with `policy.allowed: false` and `network_requests_sent: 0`.

Runner or service exceptions become controlled failed jobs with redacted errors.

## Storage And Summary

Stored results preserve the active runner result shape:

- `analyzer`
- `mode`
- `profile`
- `target`
- `authorization`
- `policy`
- `limits`
- `planned_checks`
- `blocked_reasons`
- `findings`
- `audit_log`
- `errors`
- `summary`

`GET /jobs` includes compact active dry-run metrics:

- `analyzer`
- `target_display`
- `mode`
- `profile`
- `allowed`
- `planned_checks_count`
- `blocked_reasons_count`
- `network_requests_sent`
- `blocked_reason_codes`
- `policy_version`

Sparse, malformed, queued, running, failed, and legacy payloads are tolerated defensively.

## Reporting And Export

Markdown, HTML, XML, and PDF reporting now include Active dry-run sections:

- Active Scope Notice
- Target Summary
- Authorization Summary
- Policy Decision
- Planned Checks
- Blocked Reasons
- Limits
- Audit Log
- Errors
- Redacted Raw JSON

The report copy explicitly says:

```text
No network traffic was sent
```

Reports do not include live response headers, HTTP status codes, DNS answers, Nmap output, exploit payloads, bypass guidance, stealth/evasion language, or vulnerability-confirmation claims.

## Redaction

Backend storage/reporting applies defensive redaction for active dry-run payloads, including legacy or malformed records.

Redacted surfaces include:

- target display and `target_url`;
- result JSON;
- `GET /jobs/{job_id}`;
- `GET /jobs`;
- job errors;
- Markdown exports;
- HTML exports;
- XML exports;
- PDF exports;
- redacted raw JSON sections.

The backend redacts:

- URL userinfo credentials;
- sensitive query parameters;
- Authorization headers;
- bearer/basic tokens;
- password/token/API-key/client-secret assignments;
- private key blocks;
- common fixture secret strings.

The fixed placeholder is:

```text
[REDACTED]
```

No prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers are intentionally emitted.

## No-Network Guarantee

This integration preserves the Active dry-run no-network boundary:

- no DNS resolution;
- no HTTP requests;
- no sockets;
- no subprocess probes;
- no Nmap runtime;
- no redirects;
- no live response headers;
- no HTTP status codes;
- no live data;
- no frontend trigger yet.

The active dry-run result remains expected to report:

```text
network_requests_sent = 0
```

The backend integration does not import or call `tools/runner/main.py`.

## Tests

Backend tests cover:

- endpoint disabled by default and no job created;
- enabled endpoint creates `active_network_dry_run` jobs;
- backend service invokes `run_active_network_dry_run`;
- private/internal targets complete as blocked dry-runs;
- missing authorization, live mode, Nmap profile, and nonzero limits block without network;
- unknown fields reject before job creation;
- target URL credentials are redacted;
- active dry-run summaries render in `GET /jobs`;
- Markdown/HTML/XML/PDF exports render active sections;
- legacy payloads with raw secrets are redacted in API and exports;
- sparse, queued, running, and failed jobs export without breaking.

Runner tests continue to cover the separated no-network dry-run skeleton.

Reference validation commands:

```bash
python3 -m compileall backend tools/active_runner
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools/active_runner
.venv/bin/python -m pytest tools/tests/test_active_runner.py
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_network or dry_run"
.venv/bin/python -m pytest backend/tests/test_backend.py
git diff --check
git diff --cached --check
```

The prompt-requested pytest expression `active_network or active dry run or dry_run` is not valid pytest `-k` syntax because `active dry run` contains spaces without boolean operators. The equivalent focused expression used for validation is:

```bash
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_network or dry_run"
```

## Residual Risks

- This is still dry-run planning only, not an Active scanner.
- At this backend-only block, there was no frontend UI yet.
- The endpoint is disabled by default and requires explicit environment opt-in.
- Authorization is an explicit user assertion, not ownership proof.
- Redaction is defensive best-effort for legacy payloads.
- Future real network probes would require a separate design, explicit authorization, target validation, rate limits, timeouts, audit logging, network egress controls, and additional tests.

## Decision

Final decision:

```text
ACTIVE_DRY_RUN_BACKEND_INTEGRATED_NO_NETWORK
```

Meaning:

- `POST /active/network/dry-run` exists behind `INSPECTRA_ACTIVE_DRY_RUN_ENABLED`.
- Jobs use `active_network_dry_run`.
- Jobs are target-based and have no `file_id`.
- Storage summaries and exports are integrated.
- Results and legacy payloads are redacted before public API/reporting exposure.
- No network behavior exists.
- No Nmap runtime exists.
- No frontend UI exists yet.
- `tools/runner/main.py` remains untouched.

Next recommended microphase:

```text
ACTIVE-NETWORK-BLOCK-07-DRY-RUN-FRONTEND-DESIGN
```

Alternative if product wants another safety pass first:

```text
ACTIVE-NETWORK-BLOCK-07-DRY-RUN-BACKEND-CONTRACT-REVIEW
```
