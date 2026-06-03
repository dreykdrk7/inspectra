# Active Network Block 08 Dry-Run Frontend Implementation No Network

Status: `ACTIVE_DRY_RUN_FRONTEND_IMPLEMENTED_NO_NETWORK`.

End-to-end review: `docs/future/active-network-block-09-end-to-end-dry-run-contract-redaction-review.md`

Base design: `docs/future/active-network-block-07-dry-run-frontend-design.md`

Backend base: `docs/future/active-network-block-06-dry-run-backend-integration-no-network.md`

Commit scope: frontend implementation, tests, and minimal documentation alignment.

## Implemented Surface

- Added a separate dashboard panel titled `Active / Network dry-run`.
- Added a required target input and authorization checkbox.
- Added frontend API helper for `POST /active/network/dry-run`.
- Sends the dry-run-only request contract:
  - `mode: dry_run`
  - `profile: http_header_probe_preview`
  - `authorization.confirmed: true`
  - `authorization.scope: single-target`
  - all request limits set to `0`.
- Added catalog and dashboard filter metadata for `active_network_dry_run`.
- Added an `ActiveDryRunJobReport` report component.
- Added defensive frontend redaction for report sections and Raw JSON.

## Scope Preserved

- No backend changes.
- No runner changes.
- No changes to `tools/runner/main.py`.
- No archive action integration.
- No run-all integration.
- No live probes.
- No DNS resolution.
- No socket traffic.
- No browser-side network checks beyond the normal backend API call.
- No subprocesses.
- No Nmap.
- No port checks.
- No target validation against live infrastructure.

## UX Decisions

The Active dry-run UI is intentionally separate from uploaded file and archive actions. It is placed near other target-based dashboard panels, but uses dry-run copy and required authorization so users do not confuse it with passive archive review or live probing.

Controlled copy uses:

- `dry-run`
- `plan`
- `preview`
- `no network traffic`
- `authorization required`
- `network requests sent: 0`

The UI avoids action wording such as `Run Nmap`, `Scan`, `Attack`, and `Exploit`.

## Disabled Backend State

If the backend returns:

```text
Active dry-run checks are disabled in this environment.
```

the frontend shows a controlled disabled state and supporting administrator-facing guidance. It does not mention `.env` editing, bypass guidance, retries, or target execution.

## Report Sections

The report renders:

- General summary and overview metrics.
- Target summary.
- Authorization summary.
- Policy decision.
- Limits.
- Planned checks.
- Blocked reasons.
- Audit log.
- Controlled errors.
- Redacted Raw JSON.

Queued, running, failed, sparse, malformed, and blocked payloads are tolerated without breaking the UI.

## Redaction Guarantees

Frontend report rendering and Raw JSON defensively redact:

- Authorization headers.
- Bearer/Basic credentials.
- URL userinfo.
- Sensitive query parameters.
- Secret-like assignments.
- Token/password/API key/client secret values.
- Private key blocks and `PRIVATE KEY` text.

The redaction placeholder is fixed:

```text
[REDACTED]
```

The implementation does not intentionally emit secret prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

## Validation Plan

Reference checks for this block:

```text
git status --short
npm run test -- --run ActiveDryRunJobReport App dashboardFilters reportHelpers
npm run test -- --run
npm run build
git diff --check
git diff --cached --check
git status --short
```

Backend and runner tests are not required for this block because backend and runner runtime were not changed.

## Residual Risks

- This is still dry-run planning only; no live target truth is established.
- Target values entered by users are sent to the backend endpoint as part of the normal dry-run creation request.
- Frontend redaction is best-effort and complements backend/API/export redaction; it does not sanitize stored source data elsewhere.
- Future Active behavior must remain docs-first and separately gated before any non-dry-run network capability is considered.

## Next Microphase

Completed next microphase:

```text
ACTIVE-NETWORK-BLOCK-09-END-TO-END-DRY-RUN-CONTRACT-REDACTION-REVIEW
```

That block verifies the full dry-run contract across frontend, API, storage, reporting/export, disabled-state handling, and redaction without adding live network behavior.
