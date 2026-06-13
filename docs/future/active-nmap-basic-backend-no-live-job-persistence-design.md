# Active Nmap Basic: Backend No-Live Job Persistence Design

Status:

`ACTIVE_NMAP_BASIC_49_BACKEND_ACTIVE_NMAP_NO_LIVE_JOB_PERSISTENCE_DESIGN_ACCEPTED`

## Objective

Design how a future `active_nmap_basic` lifecycle result may become an
owner-scoped Inspectra job while the capability remains no-live. This is a
documentation-only phase. It does not add storage code, create jobs, call
`active-tools`, execute Nmap, change frontend runtime, create exports, or touch
archive/run-all or `tools/runner/main.py`.

Microphase 48 intentionally returns controlled lifecycle metadata directly from
`POST /active/network/nmap-basic` and does not persist jobs. A later
implementation may reintroduce persistence only after this design is accepted
and covered by focused tests.

## Authority Boundary

The backend remains the authority for:

- authentication and anonymous denial before validation;
- owner scope and wrong-owner responses;
- request validation and dangerous-field rejection;
- local/private/self-hosted target policy;
- handoff construction;
- lifecycle invocation and controlled-state normalization;
- storage admission;
- redaction for detail, list, Raw JSON, and future report/export rendering.

The lifecycle should not write storage directly. It should return a controlled
result to a backend-owned persistence adapter. That adapter decides whether the
result is safe to store and must fail closed if any unsafe marker appears.

## Persistence Preconditions

A future persistence phase may create an `active_nmap_basic` job only when all
of the following are true:

- `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED` is explicitly enabled;
- the request already passed the exact backend contract and target policy;
- auth-required modes already resolved an owner before validation details are
  exposed;
- the lifecycle result is one of the accepted no-live states below;
- `job_created`, `storage_persisted`, `active_tools_real_call_allowed`,
  `nmap_executed`, `subprocess_invoked`, `target_expansion_performed`, and
  `evidence_available` are false;
- `network_requests_sent` and `dns_queries_sent` are zero;
- observations, evidence, raw output, commands, target expansion, banners,
  versions, and service details are absent;
- the persistence adapter can produce a redacted storage payload without raw
  target or payload values.

If any precondition fails, the route should return a controlled error without
creating or updating a job.

## Accepted States

Only these lifecycle states are eligible for future no-live persistence:

- `blocked_unconfigured`;
- `blocked_missing_approval`;
- `not_executed`;
- `client_error_controlled`;
- `completed_no_live`;
- `unsafe_lifecycle_result`.

`unsafe_lifecycle_result` may be stored only as a sanitized controlled-error
record. It must not preserve the unsafe fields that caused the downgrade.

`not_executed` is not a completed scan. `completed_no_live` means the no-live
lifecycle completed successfully; it does not mean Nmap ran or that any network
observation exists.

## Job Shape

Future job creation should use the existing target-based job model:

- `audit_type: active_nmap_basic`;
- `file_id: null`;
- `owner_id` set to the current effective owner;
- `status` derived from the controlled lifecycle state, not from target reach;
- `target_url` either null or a display-safe placeholder such as
  `[REDACTED_TARGET]`;
- `target_domain` null;
- `result` containing only the sanitized no-live payload described below;
- `error` containing only a controlled reason code when needed.

Wrong-owner job detail, Raw JSON, delete, and future export reads must use the
same generic not-found behavior as existing owner-scoped job paths. They must
not reveal whether the job exists, which target was requested, or why another
owner cannot access it.

## Allowed Result Fields

The stored `result` should be an allowlisted document, for example:

- `audit_type: active_nmap_basic`;
- `capability: active_nmap_basic`;
- `mode: live_nmap_basic`;
- `profile: tcp_connect_small`;
- `status` using a controlled no-live status;
- `lifecycle_state` from the accepted state list;
- `reason` from the controlled reason allowlist;
- `summary` with counts only, such as `target_count`, `port_count`,
  `target_port_checks`, `observation_count: 0`, and
  `manual_validation_required: true`;
- `limits` with bounded no-live metadata, such as `output_truncated: false`,
  `stderr_truncated: false`, `timed_out: false`, and storage-size ceilings;
- `execution` booleans proving no execution occurred:
  `nmap_executed: false`, `network_requests_sent: 0`, `dns_queries_sent: 0`,
  `subprocess_invoked: false`, `active_tools_real_call_allowed: false`,
  `target_expansion_performed: false`, `evidence_available: false`;
- `authorization` with booleans confirming operator acknowledgements, but no
  claim of ownership proof;
- `policy` with allow/blocked state and redacted reason codes only;
- `errors` and `warnings` as controlled codes without target values;
- `redaction_notes` explaining that raw target, payload, command, output, and
  evidence fields were not stored.

Any target reference should be minimal and display-safe. If product value later
requires target correlation, prefer a one-way digest with a per-install secret
or a coarse label such as `single_authorized_target_redacted`; do not store raw
hostnames, raw IP input, full URLs, PTR names, resolved IPs, or submitted
payloads.

## Forbidden Storage Fields

The persistence adapter must reject or remove:

- raw target values, raw request payloads, raw command values, raw arguments,
  stdout, stderr, XML, parser source payloads, stylesheet references, PTR data,
  resolved IP values, banners, version strings, service details, headers,
  cookies, tokens, credentials, supplied secrets, local file paths, target
  files, shell snippets, custom profiles, script names, and target expansion
  output;
- port observations, evidence arrays, findings, service summaries, confidence
  scores, CVE mappings, severity upgrades, or any field that suggests a live
  result while the phase remains no-live;
- arbitrary nested fields from lifecycle or client responses.

Unexpected keys should be treated as unsafe unless explicitly allowlisted in
the future implementation.

## Redaction Surfaces

Job detail should return only the sanitized job record and public result. It
must not include target or payload values in `error`, `warnings`, `summary`, or
nested metadata.

Job list should keep `target_url` null or `[REDACTED_TARGET]`, show only
owner-owned rows, and summarize no-live state with counts and controlled reason
codes.

Raw JSON should be redacted-first and match the persisted public result. It
should be safe even if copied outside Inspectra, while still warning that local
storage and manual downloads are operator responsibilities.

Future Markdown, HTML, XML, and PDF rendering should state:

- no Nmap was executed;
- no network requests were sent;
- no evidence was collected;
- no observations are available;
- manual validation is required;
- the result is a controlled no-live lifecycle record, not a target finding.

The wording should use "observed exposure" and "review indicator" only for
future phases that actually receive allowed observations. In this no-live
persistence phase, reports should prefer "no-live lifecycle record" and
"manual validation required".

## State-To-Job Mapping

Suggested mapping for a later implementation:

- `blocked_unconfigured`: job may be `failed` with reason
  `active_nmap_basic_not_configured`, or no job may be created if the route
  fails before persistence admission. If stored, it must show no execution.
- `blocked_missing_approval`: job may be `failed` with a controlled approval or
  bounded-plan reason. Do not store missing approval payload details.
- `not_executed`: job may be `completed` only if copy clearly says the lifecycle
  did not execute anything; otherwise prefer `failed` or a future explicit
  no-live status if the model supports it.
- `client_error_controlled`: job may be `failed` with the normalized client
  error code only.
- `completed_no_live`: job may be `completed` with no-live metadata only and
  zero observations.
- `unsafe_lifecycle_result`: job may be `failed` with reason
  `unsafe_lifecycle_result` after dropping unsafe fields.

The current `JobStatus` model should not be interpreted as scan semantics for
this audit type. UI and exports must read `result.status` and
`result.lifecycle_state` before displaying meaning.

## Future Tests

The future implementation should add backend tests for:

- disabled feature flag rejects without job creation;
- auth-required anonymous fails before validation or persistence;
- invalid request and target-policy rejection do not create jobs;
- valid no-live route creates at most one owner-scoped `active_nmap_basic` job
  with `file_id: null`;
- wrong-owner detail, Raw JSON, delete, and future export reads return generic
  not-found responses;
- each accepted lifecycle state maps to a safe job state and public result;
- unsafe lifecycle fields are dropped and recorded only as
  `unsafe_lifecycle_result`;
- job detail, list, Raw JSON, Markdown, HTML, XML, and PDF surfaces do not
  render target, payload, command, output, PTR, resolved IP, banner, version,
  service, credential, header, cookie, or token values;
- source guardrails confirm no frontend runtime, export implementation,
  archive/run-all, `tools/runner/main.py`, Docker, Nmap, probe, DNS, external
  HTTP, real `active-tools`, or storage bypass behavior is introduced.

## Acceptance Criteria

A later persistence implementation is acceptable only when:

- persistence remains disabled behind the existing feature gate unless explicitly
  enabled for the active flow;
- jobs are owner-scoped, target-based, and `file_id: null`;
- stored results are allowlisted, minimal, and redacted before write;
- no-live states cannot be confused with live execution;
- wrong-owner responses are generic;
- Raw JSON and future report/export surfaces preserve the no-live caveats;
- unsafe lifecycle data cannot survive into storage or public rendering;
- tests prove no job is created for disabled, invalid, unauthorized, or
  rejected requests;
- source guardrails prove no real active-tools call, Nmap execution, target
  probe, frontend runtime change, archive/run-all path, or passive runner path
  was introduced.

This design freezes only the persistence shape. It does not approve live
execution, storage implementation, frontend changes, export changes, migrations,
release, tag, or push state.
