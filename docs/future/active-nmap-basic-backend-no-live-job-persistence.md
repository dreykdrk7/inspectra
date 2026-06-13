# Active Nmap Basic: Backend No-Live Job Persistence

Status:

`ACTIVE_NMAP_BASIC_50_BACKEND_ACTIVE_NMAP_NO_LIVE_JOB_PERSISTENCE_PASSED`

## Objective

Implement backend no-live persistence for `active_nmap_basic` after the route
has passed the feature gate, auth/owner resolution, request validation, target
policy, handoff construction, lifecycle execution, and persistence-adapter
validation.

This phase reintroduces a persistent job only for safe no-live lifecycle
results. It does not call real `active-tools`, execute Nmap, run Docker or
Compose, perform probes, perform DNS checks, send external HTTP, change frontend
runtime, create new export behavior, integrate archive/run-all, or touch
`tools/runner/main.py`.

## Runtime Shape

`POST /active/network/nmap-basic` now returns a `202` `JobRecord` when the
feature is enabled and the no-live lifecycle result is persistible.

The job is:

- owner-scoped to the current effective owner;
- target-based with `file_id: null`;
- `audit_type: active_nmap_basic`;
- `target_url: [REDACTED_TARGET]`;
- `target_domain: null`;
- completed only for `completed_no_live`;
- failed for blocked, controlled client-error, `not_executed`, or unsafe
  lifecycle states.

The lifecycle remains storage-free. The route calls a backend-owned persistence
adapter that builds an allowlisted result payload before a single job is
created.

## Persisted Payload

The persisted result includes only:

- audit/capability/mode/profile identifiers;
- `status: not_executed`;
- `lifecycle_state` and controlled `reason`;
- count-only summary fields;
- bounded no-live limits;
- execution flags proving no Nmap, subprocess, DNS, network request, target
  expansion, evidence, or observations;
- authorization booleans that do not claim ownership proof;
- redacted policy reason codes;
- controlled errors/warnings;
- redaction notes.

The payload does not store raw target, raw payload, command, args, stdout,
stderr, XML, PTR, resolved IP, banner, version, service details, credentials,
headers, cookies, tokens, observations, evidence, or findings.

## Owner Scope

Job detail, list, delete, Raw JSON-style API reads, and existing report/export
routes continue to use owner-scoped job access. Wrong-owner reads and deletes
return generic not-found responses and do not reveal target values or resource
existence.

## Tests

Backend coverage verifies:

- disabled feature flag rejects without job creation;
- auth-required anonymous requests fail before validation and without jobs;
- invalid requests and target-policy rejection do not create jobs;
- valid no-live requests create exactly one owner-scoped `active_nmap_basic`
  job with `file_id: null`;
- owner list/detail surfaces show redacted no-live metadata;
- wrong-owner detail/export/delete is generic;
- every accepted lifecycle state maps to a safe job result;
- unsafe lifecycle output is downgraded to `unsafe_lifecycle_result`;
- legacy mock executor state is ignored;
- source guardrails keep real active-tools, Nmap, subprocess, Docker, DNS,
  probes, external HTTP, frontend, archive/run-all, and `tools/runner/main.py`
  out of this path.

## Acceptance

This phase is accepted when focused active/nmap backend tests, the full backend
suite, whitespace checks, and guardrail searches pass, and the repository
contains only the no-live persistence implementation plus documentation.
