# Active Network Block 05 Dry-Run Backend Contract Design

Status: `ACTIVE_DRY_RUN_BACKEND_CONTRACT_DESIGNED_NO_RUNTIME_INTEGRATION`.

Implementation note: the backend integration designed here was implemented later and recorded in `docs/future/active-network-block-06-dry-run-backend-integration-no-network.md`.

Base skeleton: `docs/future/active-network-block-04-dry-run-skeleton-no-network.md`

Base dry-run contract: `docs/future/active-network-block-03-dry-run-contracts-design.md`

Commit scope: backend/job/storage/reporting contract design only.

This document designs the future backend integration for the separated Active dry-run skeleton. It does not implement backend routes, create jobs, change storage, change reporting, touch frontend, modify `tools/runner/main.py`, add network behavior, resolve DNS, perform HTTP requests, run Nmap, create tags, create releases, or mutate the Passive Alpha.

## A. Starting State

The Active dry-run skeleton exists under:

```text
tools/active_runner/
```

It exposes a pure local function:

```python
run_active_network_dry_run(request: ActiveDryRunRequest) -> ActiveDryRunResult
```

The skeleton is not integrated with:

- backend routes;
- backend job creation;
- storage summaries;
- reporting/export;
- frontend actions;
- public APIs.

The skeleton remains no-network:

- no DNS;
- no HTTP;
- no sockets;
- no subprocess;
- no Nmap;
- no live probe;
- no response headers;
- no HTTP status codes;
- no live data.

This document designs the contract for the next backend phase while preserving that safety posture.

## B. Endpoint Shape

Candidate endpoint shapes:

| Option | Pros | Cons |
| --- | --- | --- |
| `POST /active/network/dry-run` | Clearly marked Active, clearly network-scoped, clearly dry-run, separate from passive file/archive audits. | Requires a new route family. |
| `POST /audits/active-network-dry-run` | Reuses the audit language and sits near existing job-producing endpoints. | Blurs passive `/audits/.../{file_id}` with target-based Active work. |
| `POST /active/dry-run` | Short and clearly Active. | Too broad if later Active families exist beyond network. |

Recommended future endpoint:

```text
POST /active/network/dry-run
```

Rationale:

- It separates Active from passive `/audits/...` endpoints.
- It avoids implying an uploaded file or archive `file_id`.
- It makes the mode explicit at the route boundary.
- It leaves room for future Active families without mixing them into passive module names.
- It keeps target-based work visually distinct from archive-based config audits.

## C. Audit And Job Type

Future audit type:

```text
active_network_dry_run
```

Category:

```text
Active / Network
```

Mode:

```text
dry_run
```

Source:

```text
target
```

The future job should not require `file_id`. It is target-based, not uploaded-file-based.

Recommended job metadata:

- raw target, redacted before storage if needed;
- normalized target;
- authorization confirmed boolean;
- authorization statement version;
- authorization scope;
- mode;
- profile;
- policy decision;
- blocked reason codes;
- limits;
- planned check count;
- `network_requests_sent = 0`.

Active jobs should not include source file hashes, archive metrics, file kind, or passive analyzer labels unless a later design intentionally introduces an uploaded Active input.

## D. Backend Request Contract

Future backend request body should mirror the active runner request contract:

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

Backend validation should:

- reject unknown top-level fields;
- reject unknown nested `authorization` fields;
- reject unknown nested `limits` fields;
- require `target`;
- require exact `mode: dry_run`;
- require authorization confirmation;
- require the approved authorization statement version;
- require an allowlisted authorization scope;
- require an allowlisted profile;
- require all initial limits to be zero;
- never infer authorization from target text, domain ownership hints, environment, or previous uploads.

The backend should convert the validated request to:

```python
ActiveDryRunRequest
```

and call only:

```python
tools.active_runner.dry_run.run_active_network_dry_run
```

## E. Response And Execution Model

Two integration options exist.

Option 1: synchronous execution and immediate result response.

Pros:

- Simple for a pure function that completes quickly.
- No background task needed for dry-run v0.

Cons:

- Does not appear naturally in the existing jobs dashboard.
- Does not exercise storage/reporting/export contracts.
- Creates a separate path when future Active checks may become asynchronous.

Option 2: create a job and execute through the job pipeline.

Pros:

- Consistent with existing Inspectra job UX.
- Lets Active appear in `GET /jobs`.
- Stores audit trail and result JSON.
- Supports future async Active probes without redesigning the API.
- Allows Markdown/HTML/XML/PDF reporting to reuse the current job export model.

Cons:

- Slightly more backend plumbing for a dry-run-only function.

Recommended model:

```text
Use the job pipeline, even for dry-run.
```

Initial endpoint response:

```json
{
  "job_id": "example-job-id",
  "audit_type": "active_network_dry_run",
  "status": "queued"
}
```

If the existing API returns full `JobRecord` objects for job creation, the first implementation may return the same shape as current endpoints, with `audit_type: active_network_dry_run`, `file_id: null`, and a redacted target field or active metadata field.

The job may complete quickly, but the public contract should tolerate `queued`, `running`, `completed`, and `failed`.

## F. Storage And Result Shape

The stored result should preserve the active runner result:

- `analyzer`;
- `mode`;
- `profile`;
- `target`;
- `authorization`;
- `policy`;
- `limits`;
- `planned_checks`;
- `blocked_reasons`;
- `findings`;
- `audit_log`;
- `errors`;
- `summary`.

The stored result must not include:

- URL credentials;
- sensitive query values;
- raw headers;
- request bodies;
- live response data;
- DNS answers;
- Nmap output;
- raw private key material;
- bypass guidance.

If malformed or legacy payloads reach storage/reporting, backend defensive redaction must run before public API, exports, and raw JSON surfaces.

## G. Status Model

Possible Active-specific statuses:

- `queued`;
- `running`;
- `completed`;
- `blocked`;
- `failed_controlled`.

The current backend model uses:

- `queued`;
- `running`;
- `completed`;
- `failed`.

Recommended first integration:

```text
Preserve existing job statuses.
```

Mapping:

| Active condition | Existing job status | Active-specific detail |
| --- | --- | --- |
| Accepted request waiting for work | `queued` | `result` absent. |
| Dry-run function executing | `running` | `result` absent. |
| Dry-run allowed | `completed` | `result.policy.allowed = true`. |
| Dry-run blocked by safety policy | `completed` | `result.policy.allowed = false`, `blocked_reasons` populated. |
| Controlled internal error | `failed` | `error` redacted; optional controlled error in result if available. |

Rationale:

- Avoid DB/model changes in the first backend integration.
- Keep blocked dry-runs reportable/exportable.
- Represent safety decisions inside `result.policy` and `result.summary`, not as a new persistent status yet.

If a later Active runtime needs richer state, add it in a separate docs-first model migration.

## H. Reporting And Export Sections

Future Markdown/HTML/XML/PDF reports should include:

- Active Scope Notice.
- Target Summary.
- Authorization Summary.
- Policy Decision.
- Planned Checks.
- Blocked Reasons.
- Limits.
- Audit Log.
- Errors.
- Redacted Raw JSON, if the current reporting pattern includes raw payload sections.

Required report copy:

```text
No network traffic was sent.
```

```text
This dry run records planned checks after authorization and target validation.
```

```text
Do not scan third-party systems without permission.
```

Reports must avoid:

- "vulnerability confirmed";
- "target is safe";
- "credential valid";
- "bypass";
- "evade";
- Nmap scan claims;
- live reachability claims;
- DNS result claims;
- HTTP response claims.

For blocked dry-runs, reports should still render target summary, policy decision, blocked reasons, limits, audit log, errors, and redacted raw JSON.

## I. GET /jobs Summary

Future `GET /jobs` compact summary for `active_network_dry_run` should include:

- `target_display`;
- `mode`;
- `profile`;
- `allowed`;
- `planned_checks_count`;
- `blocked_reasons_count`;
- `network_requests_sent`;
- `blocked_reason_codes`;
- `policy_version`.

Suggested source mapping:

| Summary field | Source |
| --- | --- |
| `target_display` | `result.target.normalized` or redacted `result.target.raw`. |
| `mode` | `result.mode`. |
| `profile` | `result.profile`. |
| `allowed` | `result.policy.allowed` or `result.summary.allowed`. |
| `planned_checks_count` | `result.summary.planned_checks_count`. |
| `blocked_reasons_count` | `result.summary.blocked_reasons_count`. |
| `network_requests_sent` | `result.summary.network_requests_sent`. |
| `blocked_reason_codes` | codes from `result.blocked_reasons`. |
| `policy_version` | `result.policy.policy_version`. |

Summary extraction must tolerate sparse, null, malformed, or legacy results without raising exceptions.

## J. Redaction Requirements

Backend defensive redaction must cover:

- target URL userinfo;
- sensitive query params;
- authorization text if it ever contains secrets;
- audit log details;
- planned check URLs;
- blocked reason messages;
- errors;
- malformed or legacy nested result payloads;
- raw JSON exported through reporting;
- job errors.

Redaction must preserve:

```text
[REDACTED]
```

Redaction must not emit:

- prefixes;
- suffixes;
- hashes;
- fingerprints;
- reversible secret identifiers.

Fixture values for future negative tests:

- `super-secret-password`;
- `token_should_never_render`;
- `http://user:pass@example.com`;
- `Authorization: Bearer token_should_never_render`;
- `-----BEGIN PRIVATE KEY-----`;
- `PRIVATE KEY`.

## K. No-Network Preservation

Backend integration must not:

- call network;
- perform DNS;
- import or call HTTP clients for Active dry-run execution;
- call subprocess;
- call Nmap;
- call `tools/runner/main.py`;
- call existing `web_basic`;
- call existing domain or subdomain flows;
- expand Active into live domain/web probing.

Backend integration should only call:

```python
run_active_network_dry_run(request)
```

and persist/report the returned JSON.

Future implementation tests should include a static grep or monkeypatch guard for:

- `requests`;
- `httpx`;
- `aiohttp`;
- `socket`;
- `subprocess`;
- `nmap`;
- `dns`.

Expected safe matches may include schema fields such as `network_requests_sent`, `max_requests`, and blocked reason names such as `nmap_not_allowed`. Imports and runtime calls must not appear.

## L. Future Test Plan

Backend endpoint tests:

- `POST /active/network/dry-run` creates a job.
- Valid target returns queued or completed job.
- Job has `audit_type: active_network_dry_run`.
- Job has `file_id: null`.
- No archive kind is needed.
- `GET /jobs` shows active summary fields.
- `GET /jobs/{job_id}` includes the stored result.
- Authorization missing produces a blocked result or validation error according to the final route design.
- URL credentials are rejected and redacted.
- Private IP is blocked.
- Nmap profile is blocked.
- `network_requests_sent` is always `0`.
- Endpoint does not call passive runner services.
- Endpoint does not call `web_basic`.
- Endpoint does not import or call network libraries.
- Unknown fields are rejected.

Reporting/export tests:

- Markdown renders Active Scope Notice, Target Summary, Authorization Summary, Policy Decision, Planned Checks, Blocked Reasons, Limits, Audit Log, Errors, and redacted raw JSON.
- HTML escapes dynamic target and error content.
- XML tolerates sparse payloads.
- PDF tolerates sparse payloads.
- Blocked reasons render safely.
- Reports include "No network traffic was sent."
- Reports include no bypass wording.
- Redacted raw JSON does not leak fixture secrets.

Storage/API tests:

- Audit log is stored redacted.
- Legacy malformed active payloads are redacted before public result/export.
- Job summaries tolerate null, missing, or wrong-typed `summary`, `target`, `policy`, `blocked_reasons`, and `audit_log`.
- Controlled errors are redacted.

Regression guard:

- Existing passive archive/file jobs still work.
- `tools/runner/main.py` remains untouched.

## M. Frontend Future Expectations

Frontend work should remain a later microphase.

Expected future UX:

- Active form separate from file upload.
- Authorization checkbox or confirmation control.
- Dry-run badge.
- Clear target summary before submission.
- No automatic run on page load.
- Report shell that clearly says no network traffic was sent.
- Blocked reason display with safe copy.
- Redacted raw JSON.

Frontend copy should say:

```text
Do not scan third-party systems without permission.
```

Frontend copy must not describe this as live scanning, Nmap execution, reachability validation, DNS validation, or vulnerability confirmation.

## N. Open Questions

Open questions for later phases:

- Should the final endpoint path remain `POST /active/network/dry-run`?
- Should job creation return full `JobRecord` or a smaller `{job_id, audit_type, status}` response?
- Should the first backend integration complete synchronously inside the route or enqueue a background task?
- Should blocked dry-runs always store as `completed` with `policy.allowed=false`?
- Should Active results be exportable in the first backend integration?
- Should Active dry-run require an environment flag?
- If an environment flag exists, should the default be false?
- Should the job model gain an explicit `target_display` field, or reuse `target_url` for a redacted target?
- Should active audit logs remain inside result JSON or move to append-only records later?
- How should authenticated user identity populate `requested_by` once auth exists?

Recommendation for environment flag:

```text
Require INSPECTRA_ACTIVE_DRY_RUN_ENABLED=true before exposing the endpoint.
```

Rationale:

- Keeps Active disabled by default.
- Preserves the Passive Alpha safety boundary.
- Lets deployments opt in explicitly even for no-network dry-run.

If the endpoint is disabled, it should return a controlled response with safe copy and no target processing beyond minimal request validation needed to avoid logging secrets.

## O. Implementation Notes For Next Phase

The next implementation phase should be small and backend-only.

It should add:

- request model;
- audit type literal;
- job creation helper;
- service wrapper that calls `run_active_network_dry_run`;
- defensive redaction helper for active payloads;
- storage summary extraction;
- reporting sections;
- backend tests.

It should not add:

- frontend action;
- live network;
- DNS;
- HTTP clients;
- subprocess;
- Nmap;
- local-lab mode;
- passive runner changes.

## P. Decision Field

Final decision:

```text
ACTIVE_DRY_RUN_BACKEND_CONTRACT_DESIGNED_NO_RUNTIME_INTEGRATION
```

Meaning:

- Endpoint recommendation is decided.
- Job/audit type is designed.
- Request contract is designed.
- Response/job execution model is designed.
- Storage/result shape is designed.
- Status mapping is designed.
- Reporting/export sections are designed.
- `GET /jobs` summary fields are designed.
- Redaction requirements are designed.
- No-network backend integration requirements are designed.
- Future tests are listed.
- Open questions are documented.
- No backend/runtime/frontend code changed.
- No network or DNS behavior exists.
- No Nmap runtime exists.

Next recommended microphase:

```text
ACTIVE-NETWORK-BLOCK-06-DRY-RUN-BACKEND-INTEGRATION-NO-NETWORK
```

Alternative:

```text
ACTIVE-NETWORK-BLOCK-06-DRY-RUN-BACKEND-CONTRACT-REVIEW
```

If implementation begins next, it must preserve this document's no-network and no-passive-runner constraints.
