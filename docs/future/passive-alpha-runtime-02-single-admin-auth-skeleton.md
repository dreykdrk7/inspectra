# Passive Alpha Runtime 02 Single Admin Auth Skeleton

Status: `PASSIVE_ALPHA_RUNTIME_SINGLE_ADMIN_AUTH_SKELETON_ACCEPTED`.

Successor runtime 03 deny-anonymous guard: `docs/future/passive-alpha-runtime-03-deny-anonymous-sensitive-routes.md`

Successor runtime 04 owner metadata write path: `docs/future/passive-alpha-runtime-04-owner-metadata-write-path.md`

Successor Runtime-10 login/session plan: `docs/future/passive-alpha-runtime-10-single-admin-login-session-plan.md`

Base runtime 01 auth-mode/local-operator slice: `docs/future/passive-alpha-runtime-01-auth-mode-flag-and-local-operator.md`

Base P0 runtime planning closeout: `docs/future/passive-alpha-p0-07-p0-runtime-planning-closeout.md`

Base auth-boundary runtime plan: `docs/future/passive-alpha-p0-01-auth-boundary-design-to-runtime-plan.md`

Commit scope: minimal backend auth-status skeleton for `self_hosted_single_admin`. This block adds safe status/config representation only. It does not change existing endpoint permissions, create sessions, implement login, verify passwords, create users, add owner metadata, add migrations, add deny-anonymous guards, enforce ownership, change retention/delete behavior, touch frontend UI, touch the runner, expand Active, add Nmap, or add new capabilities.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_SINGLE_ADMIN_AUTH_SKELETON_ACCEPTED
```

Inspectra now has a backend skeleton that can represent whether single-admin auth would be required and whether the future admin credential hash is configured.

`trusted_local_no_auth` remains the default and current behavior remains unchanged.

## What Was Implemented

- Backend config now reads `INSPECTRA_ADMIN_PASSWORD_HASH` as an optional future single-admin credential hash.
- The hash value is stored only in backend settings for future use and is not rendered by the auth status API.
- Added safe helpers:
  - `is_auth_required(settings)`
  - `is_single_admin_auth_configured(settings)`
- Added `GET /auth/status`.
- `GET /auth/status` returns:
  - `auth_mode`
  - `auth_required`
  - `configured`
  - `trusted_local`
  - `default_operator_id`
  - `login_available`
- `trusted_local_no_auth` reports `auth_required=false`, `configured=false`, `trusted_local=true`, and `login_available=false`.
- `self_hosted_single_admin` reports `auth_required=true`.
- `self_hosted_single_admin` without `INSPECTRA_ADMIN_PASSWORD_HASH` reports `configured=false`.
- `self_hosted_single_admin` with `INSPECTRA_ADMIN_PASSWORD_HASH` reports `configured=true` without exposing the hash.
- Backend startup records `single_admin_auth_configured` in `app.state` for future slices.
- Backend tests cover default status, self-hosted missing credential, self-hosted configured credential redaction, unknown auth mode rejection, health, files, and jobs.

## New Endpoint

```text
GET /auth/status
```

The endpoint is intentionally read-only and safe for this skeleton phase. It does not authenticate a user, create a session, set cookies, return a token, return a password hash, or expose sensitive config.

Example trusted local response:

```json
{
  "auth_mode": "trusted_local_no_auth",
  "auth_required": false,
  "configured": false,
  "trusted_local": true,
  "default_operator_id": "local-admin",
  "login_available": false
}
```

Example `self_hosted_single_admin` response with a configured hash:

```json
{
  "auth_mode": "self_hosted_single_admin",
  "auth_required": true,
  "configured": true,
  "trusted_local": false,
  "default_operator_id": "local-admin",
  "login_available": false
}
```

## Configuration

```text
INSPECTRA_AUTH_MODE=trusted_local_no_auth
INSPECTRA_ADMIN_PASSWORD_HASH=
```

`INSPECTRA_ADMIN_PASSWORD_HASH` is reserved for future single-admin auth work. In this slice, it is only checked for presence when `INSPECTRA_AUTH_MODE=self_hosted_single_admin`.

No `.env`, `.env.*`, or `.envrc` files are read by this work. Operators may provide environment variables through their deployment mechanism later, but this microphase does not add deployment guidance or secret management automation.

## What Was Not Implemented

- Login.
- Password verification.
- Password hashing.
- Password reset.
- Session creation.
- Cookies.
- CSRF changes.
- Login UI.
- DB users.
- `owner_id`.
- Storage migrations.
- Deny-anonymous guards for sensitive endpoints.
- Ownership enforcement.
- Owner-scoped file/job/result/export access.
- Delete or retention runtime.
- Cleanup scheduler.
- Deployment hardening runtime.
- Multi-user runtime.
- Public/community runtime.
- OAuth/OIDC, email, magic links, or SSO.
- Billing, SaaS, tenant billing, enterprise multi-tenant, quota monetization, or paid-plan behavior.
- Nmap.
- New Active behavior.
- New Passive analyzers.

## Compatibility

`trusted_local_no_auth` remains the default. Existing file uploads, jobs, reports, exports, Raw JSON, target flows, and Active feature flags keep their current behavior.

This skeleton itself did not apply guards to existing endpoints. Deny-anonymous behavior is now handled by `PASSIVE-ALPHA-RUNTIME-03-DENY-ANONYMOUS-SENSITIVE-ROUTES`.

## Security Notes

- `GET /auth/status` never returns `INSPECTRA_ADMIN_PASSWORD_HASH`.
- `configured=false` is not an auth bypass; it means the future single-admin credential is not configured yet.
- `login_available=false` is explicit because this slice does not implement login.
- `self_hosted_single_admin` being selected does not make the deployment protected until later auth/session and guard slices are implemented.
- The auth status endpoint does not reveal filesystem paths, stored files, jobs, targets, feature-flag details beyond auth mode, or secrets.

## Residual Risks

- Exposed deployments are still not protected by auth.
- Sensitive routes were unguarded in this slice; Runtime-03 now denies anonymous sensitive routes when auth mode requires it.
- No session/cookie security exists yet.
- The configured hash is not used for verification yet.
- Future slices must avoid treating `configured=true` as proof of a complete secure deployment.
- Frontend UI still has no login/status handling.

## Acceptance Criteria

- `trusted_local_no_auth` remains default.
- `GET /auth/status` exists and does not leak secrets.
- `self_hosted_single_admin` reports `auth_required=true`.
- Missing admin hash reports `configured=false`.
- Present admin hash reports `configured=true` without rendering the hash.
- No global guards are added yet.
- No login, sessions, cookies, DB users, owner metadata, migrations, frontend UI, runner changes, Active expansion, Nmap, or new capabilities are added.

## Reference Validation Commands

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "auth_mode or auth_status or health or files or jobs"
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend code.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-05-LEGACY-LOCAL-DATA-MAPPING
```

Next runtime work should define trusted-local handling for existing ownerless records, while preserving `trusted_local_no_auth` behavior and keeping owner-scoped reads, broader migrations, delete/retention runtime, deployment hardening, billing/SaaS concepts, Nmap, new Active behavior, and new analyzers separately scoped.

Historical note: Runtime-05 through Runtime-09 have since closed the trusted-local hardened P0 line. Runtime-10 now defines the docs-first plan for future single-admin login/session behavior and recommends `PASSIVE-ALPHA-RUNTIME-11-PASSWORD-VERIFY-HELPER` as the next implementation slice.
