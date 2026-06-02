# Active Network Block 03 Dry-Run Contracts Design

Status: `ACTIVE_DRY_RUN_CONTRACTS_DESIGNED_NO_RUNTIME`.

Scope source: `docs/future/active-network-block-01-docs-first-scope.md`

Threat model source: `docs/future/active-network-block-02-runbook-and-threat-model.md`

Passive release: `https://github.com/dreykdrk7/inspectra/releases/tag/v0.1.0-passive-alpha`

This document designs future Active/Network dry-run contracts. It does not implement backend behavior, create endpoints, create an active runner, touch frontend, modify the passive runner, execute DNS, execute network requests, run Nmap, create tags, create releases, or mutate the Passive Alpha.

## A. Starting State

Active scope and threat model are frozen:

```text
ACTIVE_NETWORK_SCOPE_FROZEN_DOCS_FIRST_NO_RUNTIME
ACTIVE_RUNBOOK_THREAT_MODEL_FROZEN_NO_RUNTIME
```

This document designs the first dry-run contracts only.

Dry-run means:

- no network boundary is crossed;
- no DNS resolution is performed;
- no HTTP request is sent;
- no redirects are followed;
- no Nmap command is planned for execution;
- no live data, response headers, status codes, DNS answers, or Nmap output exist.

Nmap remains outside runtime scope.

## B. Dry-Run Objective

The dry-run contract should prove Active safety before any live probe exists.

Dry-run should:

- validate target parsing;
- normalize targets safely;
- capture explicit authorization;
- apply rejected target policy;
- plan checks without executing them;
- record policy decisions;
- record blocked reasons;
- record limits;
- record audit metadata;
- prepare backend, frontend, reporting, and export contracts;
- demonstrate no-network behavior before live probes.

The successful dry-run output is a planning artifact, not an active scan result.

## C. Core Concepts

- Active request: user-supplied target, authorization, mode, profile, and limits.
- Target: raw user input before normalization.
- Normalized target: safe structured representation derived from the raw input.
- Authorization confirmation: explicit user statement that they own or are authorized to test the target.
- Policy decision: allow/block decision made from mode, target, profile, authorization, limits, and environment policy.
- Dry-run mode: no-network planning mode.
- Planned check: a check that would be considered in a later live phase, but is not executed in dry-run.
- Blocked reason: structured policy reason explaining why planning or execution is blocked.
- Audit event: structured safety event recorded during request handling.
- Active job: future job record category for Active/Network work, separate from passive archive/file jobs.
- Active report: future report surface showing target, authorization, policy, planned checks, blocked reasons, limits, audit events, and errors.

## D. Request Contract

Proposed dry-run request:

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

Validation rules:

- `target` is required.
- `authorization.confirmed` must be `true`.
- `authorization.statement` should match an approved statement version.
- `authorization.scope` must be allowlisted.
- `mode` must be `dry_run` in v0.
- `profile` must be allowlisted.
- `limits.max_requests` must be `0` for initial dry-run.
- `limits.timeout_seconds` must be `0` for initial dry-run.
- `limits.max_redirects` must be `0` for initial dry-run.
- `limits.response_size_bytes` must be `0` for initial dry-run.
- Unknown fields should be rejected in v0.

Rationale for rejecting unknown fields: Active contracts should fail closed while the safety model is young. Silent acceptance of unknown fields can hide unsafe intent or future compatibility mistakes.

## E. Target Normalized Contract

Allowed URL target example:

```json
{
  "raw": "https://example.test",
  "normalized": "https://example.test/",
  "type": "url",
  "scheme": "https",
  "host": "example.test",
  "port": 443,
  "path": "/",
  "query_redacted": "",
  "classification": "public_hostname",
  "local_lab": false
}
```

Allowed hostname/domain target example:

```json
{
  "raw": "example.test",
  "normalized": "example.test",
  "type": "hostname",
  "scheme": null,
  "host": "example.test",
  "port": null,
  "path": null,
  "query_redacted": "",
  "classification": "public_hostname",
  "local_lab": false
}
```

Allowed single IP target example:

```json
{
  "raw": "203.0.113.10",
  "normalized": "203.0.113.10",
  "type": "ip",
  "scheme": null,
  "host": "203.0.113.10",
  "port": null,
  "path": null,
  "query_redacted": "",
  "classification": "single_public_ip",
  "local_lab": false
}
```

Loopback/local-lab target example for a future explicit local-lab mode:

```json
{
  "raw": "http://127.0.0.1:8080",
  "normalized": "http://127.0.0.1:8080/",
  "type": "url",
  "scheme": "http",
  "host": "127.0.0.1",
  "port": 8080,
  "path": "/",
  "query_redacted": "",
  "classification": "loopback",
  "local_lab": true
}
```

Rejected targets should produce a redacted target summary and blocked reasons. Credentials must not be stored. URLs with userinfo should be rejected and redacted before logs or reports.

Dry-run v0 should not perform DNS resolution. Hostname classification should be syntactic only unless a later design explicitly adds controlled DNS validation.

## F. Policy Decision Contract

Allowed dry-run policy:

```json
{
  "allowed": true,
  "mode": "dry_run",
  "policy_version": "active-network-v0-dry-run",
  "reasons": [],
  "blocked_reasons": [],
  "warnings": []
}
```

Blocked policy:

```json
{
  "allowed": false,
  "mode": "blocked",
  "policy_version": "active-network-v0-dry-run",
  "reasons": [],
  "blocked_reasons": [
    {
      "code": "private_range_blocked",
      "message": "This target is blocked by the active safety policy."
    }
  ],
  "warnings": []
}
```

Policy decisions should include:

- mode;
- policy version;
- allow/block status;
- safe warnings;
- blocked reason objects;
- no bypass guidance.

## G. Blocked Reason Codes

Initial blocked reason codes:

- `authorization_missing`
- `active_disabled`
- `unsupported_scheme`
- `url_credentials_rejected`
- `target_parse_failed`
- `target_cidr_rejected`
- `target_range_rejected`
- `wildcard_rejected`
- `private_range_blocked`
- `loopback_requires_local_lab`
- `metadata_target_blocked`
- `link_local_blocked`
- `multicast_blocked`
- `broadcast_blocked`
- `unspecified_address_blocked`
- `overlong_hostname`
- `invalid_idna`
- `suspicious_target_input`
- `unknown_profile`
- `live_mode_not_available`
- `limits_exceed_dry_run`
- `nmap_not_allowed`

Blocked reason messages should use safe generic copy. They should not suggest alternate encodings, proxies, flags, or ways to bypass the policy.

## H. Planned Checks Contract

Allowed dry-run planned check:

```json
[
  {
    "id": "http_header_probe_preview",
    "title": "HTTP header probe preview",
    "would_contact_target": false,
    "method": "HEAD",
    "url": "https://example.test/",
    "network_disabled": true,
    "reason": "dry_run"
  }
]
```

Rules:

- `would_contact_target` must be `false`.
- `network_disabled` must be `true`.
- Planned checks are descriptions, not actions.
- No response data is present.
- No DNS data is present.
- No Nmap commands are present.

Blocked dry-run result:

- `planned_checks` is empty.
- `blocked_reasons` is populated.
- `network_requests_sent` remains `0`.

## I. Audit Log Contract

Proposed audit events:

```json
[
  {
    "event": "active_request_received",
    "timestamp": "2026-01-01T00:00:00Z",
    "details": {}
  },
  {
    "event": "target_normalized",
    "timestamp": "2026-01-01T00:00:01Z",
    "details": {}
  },
  {
    "event": "policy_evaluated",
    "timestamp": "2026-01-01T00:00:02Z",
    "details": {}
  },
  {
    "event": "dry_run_planned",
    "timestamp": "2026-01-01T00:00:03Z",
    "details": {}
  }
]
```

Required event families:

- `active_request_received`
- `authorization_checked`
- `target_normalized` or `target_rejected`
- `policy_evaluated`
- `dry_run_planned` or `dry_run_blocked`
- `controlled_error_recorded` when applicable

Audit log redaction:

- no URL credentials;
- no sensitive query values;
- no tokens;
- no raw headers;
- no request bodies;
- no private keys;
- no secrets in error details.

Audit logs should contain policy decisions and safety metadata, not secrets.

## J. Result Contract

Full allowed dry-run result:

```json
{
  "analyzer": "active_network_dry_run",
  "mode": "dry_run",
  "profile": "http_header_probe_preview",
  "target": {
    "raw": "https://example.test",
    "normalized": "https://example.test/",
    "type": "url",
    "scheme": "https",
    "host": "example.test",
    "port": 443,
    "path": "/",
    "query_redacted": "",
    "classification": "public_hostname",
    "local_lab": false
  },
  "authorization": {
    "confirmed": true,
    "statement_version": "active-authorization-v1",
    "scope": "single-target"
  },
  "policy": {
    "allowed": true,
    "mode": "dry_run",
    "policy_version": "active-network-v0-dry-run",
    "reasons": [],
    "blocked_reasons": [],
    "warnings": []
  },
  "limits": {
    "max_requests": 0,
    "timeout_seconds": 0,
    "max_redirects": 0,
    "response_size_bytes": 0
  },
  "planned_checks": [
    {
      "id": "http_header_probe_preview",
      "title": "HTTP header probe preview",
      "would_contact_target": false,
      "method": "HEAD",
      "url": "https://example.test/",
      "network_disabled": true,
      "reason": "dry_run"
    }
  ],
  "blocked_reasons": [],
  "findings": [],
  "audit_log": [],
  "errors": [],
  "summary": {
    "allowed": true,
    "planned_checks_count": 1,
    "blocked_reasons_count": 0,
    "network_requests_sent": 0
  }
}
```

Always required:

- `network_requests_sent: 0`.
- No live data.
- No response headers.
- No HTTP status codes.
- No DNS results.
- No Nmap output.
- No exploitability claims.
- No credential validity claims.

Blocked result should keep the same shape but set `policy.allowed` to `false`, `policy.mode` to `blocked`, `planned_checks` to `[]`, and `blocked_reasons_count` above zero.

## K. Job Model Relationship

Future Active dry-run jobs can integrate with the existing jobs concept while staying clearly distinct from passive file/archive jobs.

Suggested future job metadata:

- audit type: `active_network_dry_run`;
- category: `Active / Network`;
- status: `completed`, `blocked`, or `failed_controlled`;
- source: target, not file;
- mode: `dry_run`;
- target summary;
- authorization confirmed;
- policy decision;
- active-specific audit metadata;
- network requests sent count.

Active jobs should not pretend to be passive archive/file jobs. They should not have source file hashes, archive summaries, or passive analyzer labels unless explicitly applicable.

This section is design only. No job model changes are implemented here.

## L. Reporting And Frontend Expectations

Future report sections:

- Active scope notice.
- Target summary.
- Authorization summary.
- Policy decision.
- Planned checks.
- Blocked reasons.
- Limits.
- Audit log.
- Errors.
- Raw JSON redacted.

Required copy:

```text
No network traffic was sent.
```

```text
This dry run records planned checks after authorization and target validation.
```

```text
Do not scan third-party systems without permission.
```

Reports should avoid:

- "vulnerability confirmed";
- "target is safe";
- "credential valid";
- bypass guidance;
- Nmap scan claims;
- live reachability claims.

## M. Error And Failure Mapping

| Code | Safe user copy |
| --- | --- |
| `authorization_missing` | Active checks require explicit confirmation that you own or are authorized to test the target. |
| `active_disabled` | Active checks are disabled in this environment. |
| `unsupported_scheme` | This target type is not supported for active checks. |
| `url_credentials_rejected` | URLs with embedded credentials are not accepted. |
| `target_parse_failed` | This target could not be parsed as an allowed active target. |
| `target_cidr_rejected` | Broad network ranges are not accepted for this active mode. |
| `target_range_rejected` | Target ranges are not accepted for this active mode. |
| `wildcard_rejected` | Wildcard targets are not accepted for this active mode. |
| `private_range_blocked` | This target is blocked by the active safety policy. |
| `loopback_requires_local_lab` | This target requires explicit local-lab mode, which is not enabled. |
| `metadata_target_blocked` | This target is blocked by the active safety policy. |
| `link_local_blocked` | This target is blocked by the active safety policy. |
| `multicast_blocked` | This target is blocked by the active safety policy. |
| `broadcast_blocked` | This target is blocked by the active safety policy. |
| `unspecified_address_blocked` | This target is blocked by the active safety policy. |
| `overlong_hostname` | This target is not accepted because the hostname is too long. |
| `invalid_idna` | This target could not be normalized safely. |
| `suspicious_target_input` | This target is blocked by the active safety policy. |
| `unknown_profile` | This active profile is not available. |
| `live_mode_not_available` | Live active checks are not available in this phase. |
| `limits_exceed_dry_run` | Dry-run limits must not allow network requests. |
| `nmap_not_allowed` | Nmap runtime is not enabled for this phase. |

No error message should include bypass instructions.

## N. Redaction

Redaction rules:

- URLs with userinfo are rejected.
- Sensitive query parameters are redacted before logs, reports, or raw JSON.
- Raw target may be redacted before audit log storage.
- Audit log details are minimal.
- Exports must not leak credentials.
- Use `[REDACTED]` as the placeholder.
- Do not emit prefixes, suffixes, hashes, fingerprints, or reversible identifiers for secrets.

Sensitive query names should include at least:

- `token`;
- `access_token`;
- `refresh_token`;
- `id_token`;
- `api_key`;
- `key`;
- `secret`;
- `client_secret`;
- `password`;
- `session`;
- `auth`;
- `authorization`;
- `jwt`;
- `signature`;
- `code`;
- `state`.

## O. Future Test Plan

Future phases should test:

- valid URL dry-run allowed;
- valid hostname dry-run allowed;
- authorization missing blocked;
- live mode rejected;
- unknown profile rejected;
- URL credentials rejected;
- sensitive query values redacted;
- private IP blocked;
- metadata IP blocked;
- CIDR blocked;
- wildcard blocked;
- suspicious shell-like input blocked;
- dry-run sends zero network calls;
- dry-run performs no DNS resolution in v0;
- audit log contains no secrets;
- report copy contains no bypass wording;
- blocked reason copy is safe;
- Nmap profile blocked;
- `network_requests_sent` is always `0`;
- planned checks have `would_contact_target: false`.

## P. Open Questions

Open questions for later phases:

- Final backend endpoint shape: `/active/...` or `/audits/active/...`.
- Whether Active jobs share the existing Job model or use a separate table/storage path.
- How authentication/user identity will populate `requested_by`.
- Final local-lab mode shape.
- Whether local-lab mode allows only loopback or selected private targets.
- Whether hostname DNS resolution ever happens in dry-run.
- How policy versions are represented across backend, runner, and reports.
- Whether active audit logs live inside job result JSON or separate append-only records.

Recommendation: no DNS in dry-run v0.

## Q. Decision Field

Final decision:

```text
ACTIVE_DRY_RUN_CONTRACTS_DESIGNED_NO_RUNTIME
```

Meaning:

- Request contract is designed.
- Target normalization contract is designed.
- Policy decision contract is designed.
- Blocked reason codes are designed.
- Planned checks contract is designed.
- Audit log contract is designed.
- Result/report expectations are designed.
- Future tests are documented.
- No backend/runtime/frontend code exists.
- No network or DNS behavior exists.
- No Nmap runtime exists.

Next recommended microphase:

```text
ACTIVE-NETWORK-BLOCK-04-DRY-RUN-SKELETON-NO-NETWORK
```

That no-network skeleton is documented in:

```text
docs/future/active-network-block-04-dry-run-skeleton-no-network.md
```

Decision:

```text
ACTIVE_DRY_RUN_SKELETON_IMPLEMENTED_NO_NETWORK
```

The future backend/job/storage/reporting contract design is documented in:

```text
docs/future/active-network-block-05-dry-run-backend-contract-design.md
```

Decision:

```text
ACTIVE_DRY_RUN_BACKEND_CONTRACT_DESIGNED_NO_RUNTIME_INTEGRATION
```
