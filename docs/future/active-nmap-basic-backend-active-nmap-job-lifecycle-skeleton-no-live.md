# Active Nmap Basic: Backend Active Nmap Job Lifecycle Skeleton No-Live

Status:

`ACTIVE_NMAP_BASIC_47_BACKEND_ACTIVE_NMAP_JOB_LIFECYCLE_SKELETON_NO_LIVE_PASSED`

## Objective

Add an isolated backend lifecycle skeleton for a future `active_nmap_basic` job
without enabling live execution. The skeleton models how a prevalidated internal
handoff could be blocked, passed to an explicitly injected fake/no-live client,
and normalized into controlled lifecycle states.

This phase does not connect the skeleton to public routes, real jobs, frontend,
exports, archive/run-all, `tools/runner/main.py`, or a real `active-tools`
service call.

## Scope

Backend adds an internal module:

```text
backend/app/active_nmap_lifecycle.py
```

The skeleton:

- accepts only an already validated `ActiveNmapBasicHandoffPlan`;
- requires `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=true` and a configured
  `INSPECTRA_ACTIVE_TOOLS_URL` before considering a fake client call;
- requires explicit internal approval flags before building any internal
  boundary request;
- requires an injected client with `client_mode: fake_no_live`;
- permits only one target unit and one TCP port in this no-live lifecycle
  skeleton;
- calls only the injected fake/no-live client in tests;
- returns controlled state objects with no job creation, no storage
  persistence, no Nmap execution, no subprocess invocation, no DNS queries, no
  target expansion, no evidence, and no observations.

## Controlled States

The lifecycle skeleton uses these no-live states:

```text
blocked_unconfigured
blocked_missing_approval
not_executed
client_error_controlled
completed_no_live
```

Blocked states happen before any fake client invocation. Client error states
record that only the injected fake client was invoked, while preserving
`job_created: false`, `storage_persisted: false`, `nmap_executed: false`,
`network_requests_sent: 0`, and `active_tools_real_call_allowed: false`.

## Guardrails

- Disabled by default.
- Internal approval required.
- Fake/no-live client required.
- No route/public API integration.
- No persistent job creation.
- No target input accepted by a new endpoint.
- No target expansion.
- No raw target values in lifecycle errors.
- No stdout, stderr, raw XML, command preview, banners, versions, service
  details, or evidence storage.
- Any result implying execution, network requests, target expansion, job
  creation, evidence, observations, or Nmap execution is treated as a controlled
  error rather than success.

## Tests

Backend tests cover:

- blocked lifecycle when Active Nmap is unconfigured;
- blocked lifecycle when internal approval is missing;
- blocked lifecycle when no fake/no-live client is injected;
- bounded single-target/single-port enforcement before the fake client;
- success normalization for a no-live `not_executed` fake client result;
- controlled client errors without target or payload leakage;
- rejection of dangerous fake client flags such as execution enabled, target
  input allowed, job creation, target expansion, network requests, Nmap
  execution, evidence, or observations;
- source guardrails showing no route, service, storage, reporting, frontend,
  export, archive/run-all, or `tools/runner/main.py` integration.

## Explicit No-Scope

- No Nmap execution.
- No `nmap --version`.
- No Docker or Compose.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No VPS, LAN, domains, real targets, or arbitrary internet scanning.
- No real `active-tools` call.
- No real `/active/nmap-basic` call.
- No public endpoint that accepts targets.
- No frontend changes.
- No exports.
- No archive/run-all.
- No `tools/runner/main.py`.
- No migrations, release, tag, or push.

## Acceptance

This phase is accepted when focused backend tests and source guardrails pass,
the new lifecycle module remains isolated from runtime routes/jobs/frontend, and
the repository records only no-live lifecycle skeleton behavior.
