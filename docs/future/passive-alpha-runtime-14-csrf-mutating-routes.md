# Passive Alpha Runtime 14 CSRF Mutating Routes

Status: `PASSIVE_ALPHA_RUNTIME_CSRF_MUTATING_ROUTES_ACCEPTED`.

Base Runtime-13 login/logout endpoints: `docs/future/passive-alpha-runtime-13-login-logout-endpoints.md`

Base Runtime-12 session/cookie skeleton: `docs/future/passive-alpha-runtime-12-session-cookie-skeleton.md`

Base Runtime-10 login/session plan: `docs/future/passive-alpha-runtime-10-single-admin-login-session-plan.md`

Commit scope: backend CSRF token generation, authenticated mutating-route guard, `/auth/status` token exposure for valid sessions, focused tests, and documentation alignment. This block does not add frontend login, frontend CSRF integration, rate limiting, lockout, multi-user auth, OAuth/OIDC, public/community readiness, target policy changes, Active expansion, Nmap, tags, releases, deployment behavior, or any billing/SaaS/tenant model.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_CSRF_MUTATING_ROUTES_ACCEPTED
```

Inspectra now has minimal backend CSRF protection for cookie-auth mutating routes in `self_hosted_single_admin`.

The implementation preserves:

- open-source, altruistic, local-first, self-hosted-first framing;
- `trusted_local_no_auth` as the default localhost/dev/trusted-local mode;
- backend authority for auth and owner checks;
- Active Alpha v0 as internal and limited;
- Nmap out of scope.

## What Was Implemented

- A per-session server-side CSRF token on `AdminSession`.
- `X-CSRF-Token` as the required request header for cookie-auth mutating routes.
- `/auth/status` now reports `csrf_required`.
- `/auth/status` returns `csrf_token` only when a valid session cookie is present.
- The auth middleware now checks, in order:
  - public-safe route allowance;
  - whether auth is required;
  - valid session presence;
  - CSRF token for mutating routes;
  - normal route/owner handling.
- `POST /auth/logout` now requires a valid session and matching CSRF token in `self_hosted_single_admin`.
- CSRF failure returns a controlled generic `403`.

## CSRF Model

The selected model is server-side session-bound CSRF:

- each successful login creates an in-memory `AdminSession`;
- each session receives an opaque random CSRF token;
- the token is stored server-side with the session;
- clients must echo the token through `X-CSRF-Token` for mutating routes;
- validation uses constant-time comparison;
- logout, expiry, or invalidation removes both session and CSRF token;
- a new login receives a new session id and a new CSRF token.

Double-submit cookies were not chosen for this slice because the existing Runtime-12 store already provides a small server-side session container. Keeping CSRF tied to `AdminSession` avoids adding a non-HttpOnly CSRF cookie and keeps the backend as the source of truth.

## Token Retrieval And Status Behavior

`GET /auth/status` remains public-safe.

Unauthenticated status in `self_hosted_single_admin`:

```json
{
  "csrf_required": true,
  "csrf_token": null,
  "authenticated": false
}
```

Authenticated status with a valid `inspectra_session` cookie:

```json
{
  "csrf_required": true,
  "csrf_token": "opaque per-session token",
  "authenticated": true,
  "operator_id": "local-admin"
}
```

`GET /auth/status` does not expose password hashes, passwords, session ids, cookie values, file ids, job ids, target history, storage paths, feature flag internals, Raw JSON, reports, exports, or bypass guidance.

`POST /auth/login` does not require CSRF because it does not mutate an existing authenticated session. It creates a new session only after explicit password verification and still returns generic failures.

## Protected Mutating Routes

When `INSPECTRA_AUTH_MODE=self_hosted_single_admin` and a valid cookie session is present, these mutating routes require `X-CSRF-Token`:

- `POST /files/*`
- `DELETE /files/{file_id}`
- `POST /audits/*`
- `POST /audits/web/basic`
- `POST /audits/domain/basic`
- `POST /audits/subdomains/basic`
- `POST /active/network/dry-run`
- `POST /active/network/http-header-probe`
- `DELETE /jobs/{job_id}`
- `POST /auth/logout`
- future mutating reset, cleanup, admin, or config routes unless explicitly exempted in a later accepted design.

The implementation uses method-level middleware for current mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`) after public-safe route handling and after session authentication.

## Routes Not Requiring CSRF

- `GET /health`
- `GET /auth/status`
- `POST /auth/login`
- `OPTIONS`

Rationale:

- health exposes no sensitive state;
- auth status is safe and only returns a CSRF token when the caller already has a valid session cookie;
- login has no prior session mutation to protect and already requires the admin password;
- preflight remains public-safe.

## Trusted Local Behavior

`trusted_local_no_auth` remains compatible:

- no login is required;
- no session cookie is required;
- no CSRF token is required;
- current owner remains the default local operator, `local-admin`.

This preserves the current localhost/dev/trusted-local alpha flow.

## Auth-Required Behavior

In auth-required mode:

- anonymous requests to sensitive routes receive generic `401` before CSRF details;
- valid session plus missing CSRF on mutating routes receives generic `403`;
- valid session plus wrong CSRF receives generic `403`;
- valid session plus correct CSRF can continue to normal route validation and owner checks;
- resource existence is still not revealed before auth, CSRF, and owner checks.

CSRF failure response:

```json
{"detail": "CSRF validation failed."}
```

The response does not include token values, session ids, cookie values, passwords, hashes, owner internals, file ids, job ids, or target details.

## What Was Not Implemented

- No frontend login UI.
- No frontend CSRF header integration.
- No rate limiting, backoff, or lockout.
- No password setup CLI.
- No persistent session DB.
- No multi-user runtime.
- No OAuth/OIDC.
- No reverse-proxy trusted-header auth.
- No public/community readiness.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No Active expansion.
- No Nmap.
- No target policy relaxation.

## Tests

Focused backend tests cover:

- session creation includes an opaque CSRF token;
- trusted-local `/auth/status` reports `csrf_required=false`;
- self-hosted unauthenticated `/auth/status` reports `csrf_required=true` and no token;
- login succeeds without CSRF and does not expose session id/cookie value/password/hash;
- authenticated `/auth/status` returns a CSRF token without exposing session/cookie material;
- authenticated GET routes do not require CSRF;
- authenticated mutating route without CSRF returns `403`;
- authenticated mutating route with wrong CSRF returns `403`;
- authenticated mutating route with correct CSRF succeeds;
- CSRF token is not serialized into stored file list responses;
- anonymous logout returns `401` before CSRF details;
- logout without CSRF returns `403`;
- logout with wrong CSRF returns `403`;
- logout with correct CSRF clears cookie and invalidates session;
- trusted-local uploads remain compatible without CSRF;
- anonymous sensitive routes still return generic `401`.

Reference validation commands:

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "csrf or login or logout or session or cookie or auth_status or anonymous or owner or files or jobs"
.venv/bin/python -m pytest backend/tests/test_backend.py
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend code.

## Residual Risks

- At Runtime-14 closeout, frontend login/status/logout UX and CSRF header wiring were not implemented yet; Runtime-15 later accepts that frontend wiring.
- Rate limiting, backoff, and lockout are not implemented yet.
- In-memory sessions and CSRF tokens do not survive backend restart.
- Secure cookie behavior for non-local deployments still needs TLS/reverse-proxy hardening.
- Persistent sessions, session rotation, key rotation, and admin recovery remain future work.
- Public/community readiness remains blocked.

## No-Scope Preserved

- No `.env`, `.env.*`, or `.envrc` reads.
- No frontend changes.
- No rate limiting or lockout.
- No multi-user runtime.
- No OAuth/OIDC.
- No public/community runtime.
- No Docker execution.
- No probes, DNS, external HTTP, Nmap, port scanning, or live target traffic.
- No Active expansion.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.

## Successor Status

```text
PASSIVE_ALPHA_RUNTIME_FRONTEND_AUTH_LOGIN_UX_ACCEPTED
```

Runtime-15 now accepts frontend auth status, login, logout, in-memory CSRF handling, and global `401`/`403` auth-state handling without adding rate limiting, multi-user auth, OAuth/OIDC, Active expansion, Nmap, or SaaS/billing behavior. Runtime-14 remains the historical backend CSRF mutating-route guard slice.
