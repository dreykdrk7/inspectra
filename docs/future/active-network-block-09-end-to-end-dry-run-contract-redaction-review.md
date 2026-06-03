# Active Network Block 09 End-to-End Dry-Run Contract Redaction Review

Status: `ACTIVE_DRY_RUN_E2E_REVIEW_PASSED_NO_NETWORK`.

Frontend base: `docs/future/active-network-block-08-dry-run-frontend-implementation-no-network.md`

Backend base: `docs/future/active-network-block-06-dry-run-backend-integration-no-network.md`

Commit scope: contract tests, redaction tests, no-network verification, minimal frontend defensive redaction, and documentation alignment.

## Reviewed Contract

The review covers:

- Frontend form and API request contract.
- Backend feature flag behavior.
- Backend job creation and storage.
- `GET /jobs` summaries.
- `GET /jobs/{job_id}` result payloads.
- Markdown, HTML, XML, and PDF exports.
- Frontend report rendering and Redacted Raw JSON.
- Active dry-run no-network safety posture.

## Cases Covered

### Disabled Flag

- `INSPECTRA_ACTIVE_DRY_RUN_ENABLED=false` or omitted.
- `POST /active/network/dry-run` returns `403`.
- No job is created.
- Frontend shows `Active dry-run checks are disabled in this environment.`
- The UI gives controlled administrator-facing guidance without `.env`, retry, bypass, or target-execution instructions.

### Valid Dry-Run

Target:

```text
https://example.test
```

Contract:

- `authorization.confirmed: true`
- `mode: dry_run`
- `profile: http_header_probe_preview`
- `limits.max_requests: 0`
- `limits.timeout_seconds: 0`
- `limits.max_redirects: 0`
- `limits.response_size_bytes: 0`

Expected and tested:

- Job type is `active_network_dry_run`.
- `file_id` is `null`.
- Result status reaches `completed`.
- `result.policy.allowed` is `true`.
- `summary.planned_checks_count` is `1`.
- `summary.network_requests_sent` is `0`.
- First planned check has `would_contact_target: false`.
- First planned check has `network_disabled: true`.
- `GET /jobs` summary is populated.
- `GET /jobs/{job_id}` result is complete and redacted.
- Exports include no-network copy.
- Frontend report renders target, authorization, policy, planned checks, limits, audit log, and Redacted Raw JSON.

### Blocked Targets

Blocked targets remain controlled completed dry-runs:

- private range targets such as `10.0.0.1`;
- loopback targets in runner tests such as `127.0.0.1`;
- URL userinfo targets such as `http://user:pass@example.com`;
- unsupported `nmap` profile requests.

Expected and tested:

- `policy.allowed` is `false`.
- Blocked reason codes are returned.
- `planned_checks` are not executed.
- `network_requests_sent` remains `0`.
- Reports show blocked reasons safely.
- No bypass guidance is emitted.

### Sensitive Query And Legacy Payloads

Sensitive query values and legacy raw target values are tested against public surfaces. The following fixture strings must not appear:

- `super-secret-password`
- `token_should_never_render`
- `http://user:pass@example.com`
- `Authorization: Bearer token_should_never_render`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`

Checked surfaces:

- runner serialized JSON;
- `GET /jobs`;
- `GET /jobs/{job_id}`;
- Markdown export;
- HTML export;
- XML export;
- PDF export;
- frontend job table;
- frontend report DOM;
- frontend Redacted Raw JSON;
- controlled errors.

Expected placeholder:

```text
[REDACTED]
```

## No-Network Verification

The active dry-run contract preserves:

- no DNS resolution;
- no HTTP request behavior;
- no sockets;
- no subprocess probes;
- no Nmap runtime;
- no live port checks;
- no call into `tools/runner/main.py`;
- `network_requests_sent: 0`.

The runner test suite includes source-level import checks for forbidden active runtime modules in `tools/active_runner/`. Safety grep is also run as a review aid; known safe matches include `network_requests_sent`, `max_requests`, `nmap_not_allowed`, test names, docs text, and unrelated existing web/domain code.

## Minimal Fix

The frontend job table now applies Active dry-run redaction to target display values. This is defensive compatibility for legacy or malformed job summaries and does not change the backend contract.

## Validation Commands

Reference validation set:

```text
git status --short
git status --branch --short
git log --oneline -12
python3 -m compileall backend tools/active_runner
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools/active_runner
.venv/bin/python -m pytest tools/tests/test_active_runner.py
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_network or dry_run"
.venv/bin/python -m pytest backend/tests/test_backend.py
npm run test -- --run ActiveDryRunJobReport App dashboardFilters reportHelpers
npm run test -- --run
npm run build
rg "requests|httpx|aiohttp|socket|subprocess|nmap|dns|tools.runner.main" backend/app tools/active_runner frontend/src backend/tests tools/tests
git diff --check
git diff --cached --check
git status --short
```

## Residual Risks

- The Active dry-run is not a live check and establishes no live target truth.
- Frontend redaction is best-effort and complements backend/API/export redaction.
- Future non-dry-run Active work must remain docs-first, separately gated, and explicitly authorized before any live network behavior is introduced.
- The current implementation intentionally does not add local-lab mode, Nmap, DNS, sockets, HTTP probes, or port checks.

## Decision

`active_network_dry_run` is ready for dry-run closeout.

Recommended next microphase:

```text
ACTIVE-NETWORK-BLOCK-10-DRY-RUN-CLOSEOUT
```

Do not proceed to live HTTP header probing, DNS, Nmap, or local-lab behavior until a separate docs-first design block is opened and reviewed.
