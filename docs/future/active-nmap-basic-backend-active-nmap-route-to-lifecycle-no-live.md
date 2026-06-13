# Active Nmap Basic: Backend Active Nmap Route To Lifecycle No-Live

Status:

`ACTIVE_NMAP_BASIC_48_BACKEND_ACTIVE_NMAP_ROUTE_TO_LIFECYCLE_NO_LIVE_PASSED`

## Objective

Connect the existing backend endpoint `POST /active/network/nmap-basic` to the
internal `active_nmap_lifecycle` skeleton in no-live mode only. The endpoint
continues to use the existing backend request contract, target policy, and
handoff builder, then invokes the lifecycle skeleton with an explicitly marked
`fake_no_live` client.

This phase deliberately removes persistent job creation from the route path.

## Runtime Shape

The route now:

- remains disabled by default through `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=false`;
- denies auth-required anonymous requests before request validation;
- validates the existing `live_nmap_basic` / `tcp_connect_small` request
  contract;
- applies the existing local/private/self-hosted target policy before lifecycle
  invocation;
- builds a prevalidated handoff plan;
- calls the lifecycle skeleton with `internal_approval_confirmed: true`,
  `fake_client_approved: true`, and `client_mode: fake_no_live`;
- returns a controlled lifecycle response.

The controlled response states that no job was created, no storage was
persisted, no real `active-tools` call is allowed, no Nmap execution happened,
no subprocess ran, no DNS queries or network requests were sent, no target
expansion occurred, and no evidence or observations are available.

## Guardrails

- Disabled flag rejects before lifecycle invocation.
- Invalid request bodies reject before lifecycle invocation.
- Target-policy rejection rejects before lifecycle invocation.
- Lifecycle errors are normalized without reflecting target or payload values.
- Unsafe lifecycle results are downgraded to a controlled error.
- Any result that implies `job_created: true`, `storage_persisted: true`,
  `active_tools_real_call_allowed: true`, `nmap_executed: true`, nonzero
  network/DNS requests, target expansion, evidence, observations, stdout,
  stderr, XML, raw commands, banners, versions, or service details is treated as
  unsafe.

## Explicit No-Scope

- No Nmap execution.
- No `nmap --version`.
- No Docker or Compose.
- No real `active-tools` call.
- No real `/active/nmap-basic` call.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No VPS, LAN, domains, or real targets.
- No persistent jobs.
- No storage persistence.
- No exports.
- No frontend runtime changes.
- No archive/run-all.
- No `tools/runner/main.py`.
- No migrations, release, tag, or push.

## Tests

Backend tests cover:

- disabled flag rejects without lifecycle calls or jobs;
- auth-required anonymous requests fail before validation/lifecycle;
- invalid request and target-policy rejection skip lifecycle;
- enabled valid request invokes lifecycle with a `fake_no_live` client;
- no-live response reports `not_executed`, no persistent job, no storage, no
  real active-tools, no Nmap, no network requests, no evidence, and no
  observations;
- lifecycle client errors are normalized without target/payload leakage;
- unsafe lifecycle results are converted into controlled errors;
- source guardrails confirm no storage/job persistence, frontend/export,
  archive/run-all, `tools/runner/main.py`, Docker, Nmap, DNS, probe, or external
  HTTP integration in the route path.

## Acceptance

This phase is accepted when the existing route is connected only to the no-live
lifecycle skeleton, focused and full backend tests pass, guardrail searches show
no prohibited integration, and the repository records only the no-live route
connection.
