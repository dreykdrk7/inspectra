# Passive Alpha Runtime 01 Auth Mode Flag And Local Operator

Status: `PASSIVE_ALPHA_RUNTIME_AUTH_MODE_LOCAL_OPERATOR_ACCEPTED`.

Base P0 runtime planning closeout: `docs/future/passive-alpha-p0-07-p0-runtime-planning-closeout.md`

Base auth-boundary runtime plan: `docs/future/passive-alpha-p0-01-auth-boundary-design-to-runtime-plan.md`

Base owner model and storage migration plan: `docs/future/passive-alpha-p0-02-owner-model-and-storage-migration-plan.md`

Base deny-anonymous API guards plan: `docs/future/passive-alpha-p0-03-deny-anonymous-reads-api-guards.md`

Commit scope: minimal backend runtime slice for explicit auth mode naming and the default local/admin operator concept. This block does not change endpoint access, job creation, reports, exports, Raw JSON, Active behavior, target policy, storage schema, migrations, frontend UI, runner behavior, login, sessions, cookies, passwords, owner checks, API guards, delete/retention runtime, cleanup, or deployment hardening.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_AUTH_MODE_LOCAL_OPERATOR_ACCEPTED
```

Inspectra now has a small runtime representation of auth mode and the default local/admin operator needed by later owner-mapping work.

The default remains `trusted_local_no_auth`, preserving the current trusted local development and demo behavior. This mode is only for localhost/dev/local trusted use and is not approval for exposed, public, private-team, or community deployments.

## What Was Implemented

- Backend config now accepts `INSPECTRA_AUTH_MODE`.
- Supported mode values are:
  - `trusted_local_no_auth`
  - `self_hosted_single_admin`
  - `private_team_lightweight_users`
  - `public_community_limited_instance`
- Default auth mode is `trusted_local_no_auth`.
- Unknown auth mode values fail in controlled config parsing with a clear `ValueError`.
- A docs-friendly default local/admin operator exists as immutable runtime data:
  - id: `local-admin`
  - label: `Default local/admin operator`
  - kind: `local_admin`
- Backend startup stores the parsed `auth_mode` and default local operator in `app.state`.
- Backend tests cover default mode, stable operator id, accepted future mode parsing, unknown mode rejection, health, and selected file/job behavior.

## What Was Not Implemented

- Login.
- Password authentication.
- Sessions.
- Cookies.
- CSRF changes.
- Login UI.
- `owner_id` fields.
- Storage migrations.
- Deny-anonymous API guards.
- Ownership enforcement.
- Owner-scoped list/read/export/delete behavior.
- Delete or retention runtime.
- Cleanup scheduler.
- Deployment hardening runtime.
- Public/community runtime.
- Multi-user runtime.
- Billing, SaaS, tenant billing, enterprise multi-tenant, or paid-plan behavior.
- Nmap.
- New Active behavior.
- New Passive analyzers.

## Compatibility

`trusted_local_no_auth` remains the default and current endpoint behavior is unchanged.

This slice intentionally does not deny anonymous requests yet. Sensitive endpoint guards are reserved for `PASSIVE-ALPHA-RUNTIME-03-DENY-ANONYMOUS-SENSITIVE-ROUTES` after the single-admin auth skeleton exists.

`self_hosted_single_admin` can be parsed as an accepted mode, but this slice does not make it a protected deployment mode yet. It is a preparatory flag only until login, sessions, guards, owner metadata, and deployment hardening are implemented.

## Security And Scope Notes

- The auth mode flag is not a security boundary by itself.
- The default local/admin operator is a stable local principal concept, not a real user account.
- The operator does not have a password, session, cookie, token, role table, or owner records in this slice.
- The backend does not expose a new endpoint for auth mode or operator details.
- No existing file, job, report, export, Raw JSON, target, or Active route changes behavior.
- No `.env`, `.env.*`, or `.envrc` files are read.
- No probes, DNS, HTTP, sockets, Docker, Nmap, or external traffic are introduced.

## Residual Risks

- `trusted_local_no_auth` still has no endpoint protections and must remain localhost/dev/local trusted only.
- Exposed deployments are still not protected by auth or owner checks.
- Sensitive endpoints remain unguarded until the later deny-anonymous runtime slice.
- Future runtime work must avoid treating the auth mode flag as sufficient protection.
- Future owner migration must explicitly map legacy local records to the default local/admin operator.
- Frontend assumptions about public API access remain until UI and API guard slices are implemented.

## Acceptance Criteria

- Default auth mode is `trusted_local_no_auth`.
- The default local/admin operator has stable id `local-admin`.
- `self_hosted_single_admin` is accepted by config parsing.
- Unknown auth mode values fail with a controlled error.
- Backend startup records the parsed mode and default operator in `app.state`.
- Current trusted-local health/file/job smoke behavior remains unchanged.
- No login, sessions, cookies, owner metadata, API guards, migrations, or deployment hardening are added.
- No new Active behavior, Passive analyzer, Nmap, Docker execution, probes, or external traffic is added.

## Reference Validation Commands

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "auth_mode or health or files or jobs"
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend code.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-02-SINGLE-ADMIN-AUTH-SKELETON
```

Next runtime work should add a minimal single-admin auth skeleton without jumping ahead to owner fields, migrations, deny-anonymous guards, retention/delete runtime, deployment hardening, billing/SaaS concepts, Nmap, new Active behavior, or new analyzers.
