# Active Pre-Alpha VPS Deploy Plan

Decision: `ACTIVE_PRE_ALPHA_VPS_DEPLOY_PLAN_09_ACCEPTED`

Status: docs-only VPS deploy and smoke plan for the published Inspectra Active
Technical Alpha. This phase does not deploy to the VPS, use SSH, modify Caddy,
run Docker, run the app, invoke Nmap, submit Active jobs, contact targets,
capture screenshots, create tags or releases, or push commits.

## Deployment Objective

Deploy Inspectra Active Technical Alpha `v0.2.0-alpha.1` to the existing
multi-app/hobby VPS in a later execution phase.

The deployment should:

- use the Docker Compose package validated in
  `ACTIVE_PRE_ALPHA_DOCKER_PACKAGING_VALIDATION_06`;
- put Caddy in front as the VPS reverse proxy;
- use a temporary/staging-style subdomain under `urlbreve.es`;
- keep the alpha private or controlled-access, not promoted as a broad public
  service;
- preserve disabled-by-default Active capabilities;
- start smoke with no Active live traffic;
- use the operator's own projects or local fixtures for first result review.

## Domain Strategy

Use a temporary or staging-style subdomain under `urlbreve.es`, such as a
placeholder `<active-alpha-subdomain>.urlbreve.es`, chosen during the execution
phase.

Do not buy, configure, or promote a dedicated Inspectra domain yet. A dedicated
domain and public social promotion are deferred until Inspectra is more robust,
more powerful, and ready for wider product presentation.

This avoids unnecessary cost, keeps the alpha consistent with the operator's
existing project infrastructure, and makes the deployment easier to treat as a
controlled technical validation rather than a public launch.

## VPS And Caddy Strategy

Use existing VPS conventions and the existing Caddy reverse proxy. Do not edit
Caddy in this planning phase.

Expected app path:

```text
/opt/apps/inspectra
```

If the VPS uses a different convention, record the real path during the deploy
execution phase before changing anything.

Conceptual Caddy routing:

- terminate TLS at Caddy for the chosen `urlbreve.es` subdomain;
- route the frontend through the subdomain;
- route backend API paths to the backend service if split routing is needed;
- keep backend direct internet exposure blocked;
- document whether `/health` is publicly reachable, private, or restricted by
  Caddy policy;
- optionally add Basic Auth or IP allowlisting for the alpha subdomain if the
  operator wants extra access control.

Do not include Caddyfile contents, secrets, credentials, or real environment
values in this plan.

## Deployment Inputs

Release/tag:

```text
v0.2.0-alpha.1
```

Tag target:

```text
45a50b8738dd54e43973d6a7568620095cf7f0aa
```

Release URL:

```text
https://github.com/dreykdrk7/inspectra/releases/tag/v0.2.0-alpha.1
```

Source documents:

- `docs/future/active-pre-alpha-release-publication.md`;
- `docs/future/active-pre-alpha-release-notes.md`;
- `docs/future/active-pre-alpha-docker-packaging-validation.md`;
- `docker-compose.yml`;
- `backend/Dockerfile`;
- `frontend/Dockerfile`;
- `tools/Dockerfile`;
- `docker-compose.active-tools.example.yml`.

Environment variable categories to prepare later, without values:

- deployment mode and auth mode;
- admin password hash or equivalent private admin credential material;
- CORS/frontend origin;
- data directory and persistence paths;
- upload/body size limits;
- session and auth-state persistence settings, if used;
- Active capability gates;
- DNS OSINT CT source gate and source URL, only if intentionally enabled;
- HTTP live HEAD second gate, only if intentionally enabled;
- Compose host port overrides if the VPS needs non-default local bindings.

## Active Flags Plan

Start with Active capabilities disabled.

Enable only one specific capability at a time in a later smoke phase, and only
after documenting the intended owned/lab target, expected traffic, and cleanup.

Flag groups to review later:

- Nmap basic gate and active-tools execution gate;
- TLS basic gate;
- DNS inventory gate;
- DNS OSINT CT gate and source gate;
- HTTP basic/header review gate;
- HTTP live HEAD second gate.

Do not add secrets, real target names, or production values to shared docs.

## Later Deploy Checklist

This checklist is for `ACTIVE_PRE_ALPHA_VPS_DEPLOY_SMOKE_10` or another
explicit execution phase.

Preflight:

- confirm local branch state and publication record state;
- confirm `v0.2.0-alpha.1` exists locally and remotely;
- confirm the tag target is `45a50b8738dd54e43973d6a7568620095cf7f0aa`;
- confirm no uncommitted local runtime changes exist;
- confirm the publication record commit is pushed if the team wants the VPS to
  fetch it from `main`;
- confirm the chosen `urlbreve.es` subdomain and DNS plan;
- confirm the app path on the VPS.

Deploy preparation:

- use the tagged source, or document why `main` plus the publication record is
  being used;
- prepare private environment configuration from categories only;
- avoid storing secrets in git or shared notes;
- review Caddy routing before editing the VPS;
- confirm rollback point before starting.

Compose and service checks:

- build or pull the Compose package from the selected source;
- start services;
- check container status;
- check backend health through the intended private path;
- check frontend through Caddy;
- review logs for tracebacks and accidental sensitive output;
- confirm Active disabled-state behavior;
- confirm no unexpected public target access occurred;
- record cleanup and rollback actions.

Rollback:

- stop the new Compose project;
- restore the previous Caddy route if it was changed;
- restore the previous app directory or release pointer;
- keep logs only if they contain no sensitive data.

## Later Smoke Plan

Phase 1: disabled-state smoke.

- Confirm the frontend loads through Caddy.
- Confirm backend health behavior matches the exposure policy.
- Confirm Active controls are disabled unless explicit flags are set.
- Confirm disabled submissions do not create jobs or target traffic.

Phase 2: passive/project analysis smoke.

- Use owned project archives or local fixtures only.
- Run a small number of passive/project analyses.
- Review generated reports for usefulness, redaction, noise, missing context,
  and report readability.
- Confirm exports and Raw JSON behavior remain consistent with alpha notes.

Phase 3: no-live HTTP header review smoke.

- Enable only the capability gate needed for no-live HTTP basic/header review.
- Use placeholder or owned/lab URL shape only.
- Confirm no-live result copy, redaction, and lifecycle wording.

Phase 4: optional live Active smoke.

- Use only the operator's own projects, domains, or lab targets.
- Document explicit authorization, expected traffic, flags, target, and cleanup
  before enabling any live capability.
- Prefer one capability at a time.
- Do not use third-party targets.

Report review after smoke:

- usefulness;
- redaction;
- false positives and noise;
- missing context;
- UX and report readability;
- whether smoke evidence should update release docs or issue backlog.

## Security And Exposure Boundaries

- Keep admin/API/auth assumptions explicit.
- Do not position the alpha as open target intake.
- Keep broad Active flags disabled by default.
- Do not enable target-aware capabilities for unauthenticated visitors.
- Logs must not expose secrets, cookies, tokens, raw reports, request bodies,
  or target data.
- Caddy should terminate TLS.
- Backend should not be directly exposed to the internet.
- Use explicit allowed origins; avoid wildcard credentialed CORS.
- Basic Auth or IP allowlisting is acceptable as an alpha access-control
  option if the operator wants it, but it is not implemented in this plan.
- No third-party targets in smoke.

## Known Gaps Before Deploy

- Publication record state should be confirmed against `origin/main` before
  the VPS fetches source.
- Frontend dependency audit warnings from the uncached Docker build remain
  untriaged.
- Active tools remains separate/example-only.
- Image tag/provenance beyond the Git tag remains limited.
- No VPS smoke has been run yet.
- Dedicated Inspectra domain selection is deferred.
- Public promotion is deferred.

## Suggested Next Phase

Recommended next phase:

```text
ACTIVE_PRE_ALPHA_VPS_DEPLOY_SMOKE_10
```

Scope: execute VPS deploy/smoke with Caddy and a `urlbreve.es` subdomain,
starting with Active flags disabled.

## Decision

```text
ACTIVE_PRE_ALPHA_VPS_DEPLOY_PLAN_09_ACCEPTED
```
