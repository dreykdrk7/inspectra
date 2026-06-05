# Passive Alpha Deployment Hardening Closeout

Status: `PASSIVE_ALPHA_DEPLOYMENT_HARDENING_CLOSED`.

Base design: `docs/future/passive-alpha-deployment-hardening-design.md`

Base runbook: `docs/future/passive-alpha-deployment-hardening-runbook.md`

Base README polish: `docs/future/passive-alpha-readme-launch-copy-polish.md`

Commit scope: documentation-only closeout for the Passive Alpha deployment hardening line. This block does not add runtime behavior, backend changes, frontend changes, tests, Docker execution, deployment execution, exposed production approval, public/community readiness, SaaS/billing/tenant/quota/paid-plan behavior, Nmap behavior, Active expansion, push, tag, or release state.

## Status

```text
PASSIVE_ALPHA_DEPLOYMENT_HARDENING_CLOSED
```

The deployment hardening line is closed at the docs/product level. It consolidates the deployment hardening design, operator runbook, and README launch-copy polish before moving to persistent auth-state planning.

## Scope

This closeout is docs-only.

It does not:

- change backend runtime behavior;
- change frontend runtime behavior;
- change Docker or Compose configuration;
- execute Docker;
- execute deployment commands;
- approve exposed production deployment;
- approve public/community readiness;
- add SaaS, billing, tenant billing, subscription, quota, paid-plan, or enterprise behavior;
- add Nmap behavior or Active expansion;
- push, tag, or publish a release.

## Closed Chain

1. `PASSIVE_ALPHA_DEPLOYMENT_HARDENING_DESIGN_ACCEPTED`

   Designed the private self-hosted deployment hardening direction for TLS/HTTPS, reverse proxy placement, secure-cookie expectations, trusted proxy headers, CORS/origin boundaries, and deployment limits.

2. `PASSIVE_ALPHA_DEPLOYMENT_HARDENING_RUNBOOK_READY`

   Converted the design into an operator checklist for private/self-hosted pre-exposure review, including mode selection, proxy posture, cookie/session caveats, rate-limit caveats, CORS, logging, smoke checks, red flags, and residual risks.

3. `PASSIVE_ALPHA_README_LAUNCH_COPY_POLISH_ACCEPTED`

   Polished README and alpha launch copy so Passive Alpha is presented clearly as local-first, self-hosted-first, passive, private-alpha ready, and explicitly not production/public/community/SaaS/Nmap-ready.

## Current Accepted Posture

- Inspectra Passive Alpha remains open-source, altruistic, local-first, and self-hosted-first.
- `trusted_local_no_auth` is limited to localhost/dev/local trusted use.
- `self_hosted_single_admin` is the current private self-hosted single-admin mode.
- Any use outside localhost is expected to use HTTPS/TLS.
- A reverse proxy should sit in front of the backend.
- The backend should not be exposed directly to the internet.
- Browser origins should be explicit.
- Credentialed CORS should not use wildcard origins.
- Logs should avoid secrets, cookies, tokens, request bodies, Raw JSON, report contents, and SBOM contents.
- Public/community hosting is not accepted.
- Production-ready claims are not accepted.
- SaaS, billing, tenant billing, subscription, quota, paid-plan, and enterprise tenancy behavior remain out of scope.
- Nmap and Active expansion are not part of this block.

## Deployment Hardening Boundaries

- The runbook helps an operator decide whether to stop before exposure.
- The runbook does not make an exposed deployment safe by itself.
- There is no production recipe.
- No deployment was executed.
- No real reverse proxy was validated.
- Secure-cookie runtime enforcement was not implemented by this docs line.
- Trusted proxy runtime enforcement was not implemented by this docs line.
- Persistent auth state does not exist yet.

## Residual Gaps Passed To Pathing C

- Sessions remain in memory.
- Login attempts and rate-limit state remain in memory.
- Multiple backend processes do not share session or attempt state.
- There is no persistent session store.
- There is no persistent rate-limit store.
- Session cleanup, expiration, and rotation need dedicated design.
- Key/session rotation remains pending.
- Admin recovery and setup guidance remain pending.
- Secure-cookie runtime enforcement remains pending if not already implemented.
- Trusted proxy runtime enforcement remains pending.
- Public/community anti-abuse remains pending.

## Next Block

```text
PASSIVE-ALPHA-PERSISTENT-AUTH-STATE-DESIGN
```

Pathing C should decide:

- the store for sessions;
- the store for login attempts;
- expiration and cleanup behavior;
- logout and invalidation semantics;
- restart behavior;
- multiprocess expectations;
- whether migration is needed;
- tests and smoke evidence;
- how the work stays private/self-hosted alpha hardening rather than becoming SaaS, multi-user, public/community runtime, or production approval.

## Final Decision

```text
PASSIVE_ALPHA_DEPLOYMENT_HARDENING_CLOSED
```

The Passive Alpha deployment hardening line is closed as docs-only. The next product/architecture move is persistent auth-state design, not Nmap, Active expansion, public/community hosting, or production release.
