# Passive Alpha Runtime 12 Session Cookie Skeleton

Status: `PASSIVE_ALPHA_RUNTIME_SESSION_COOKIE_SKELETON_ACCEPTED`.

Base Runtime-11 password verifier: `docs/future/passive-alpha-runtime-11-password-verify-helper.md`

Base Runtime-10 login/session plan: `docs/future/passive-alpha-runtime-10-single-admin-login-session-plan.md`

Base Runtime-09 closeout: `docs/future/passive-alpha-runtime-09-runtime-p0-closeout.md`

Commit scope: backend session/cookie skeleton, focused tests, and minimal documentation alignment. This block does not add login, logout, session principal integration, frontend login, CSRF, rate limiting, endpoint permission changes, guard changes, target policy changes, Active changes, Nmap, tags, releases, or deployment behavior.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_SESSION_COOKIE_SKELETON_ACCEPTED
```

Inspectra now has an isolated backend session/cookie skeleton for future `self_hosted_single_admin` login work.

The skeleton is intentionally not wired to public login/logout endpoints yet. It does not authenticate requests, set cookies on responses, or change sensitive route permissions. `/auth/status` still reports `login_available=false`.

## What Was Implemented

Backend auth helpers now include:

- `AdminSession`
- `AdminSessionStore`
- `SessionCookieSettings`
- `build_session_cookie_settings(...)`

Backend settings now include:

```text
INSPECTRA_SESSION_TTL_SECONDS
```

Default:

```text
3600
```

Backend startup now registers internal state:

- `app.state.admin_sessions`
- `app.state.session_cookie_settings`

These are internal preparation points for Runtime-13. They are not exposed through an endpoint.

## Session Model

The first session store is server-side and in-memory.

Session metadata:

- `session_id`
- `operator_id`
- `created_at`
- `expires_at`
- `auth_mode`

Initial `operator_id` is expected to be:

```text
local-admin
```

Initial `auth_mode` is:

```text
self_hosted_single_admin
```

Session ids are opaque random values generated with Python `secrets.token_urlsafe(32)`. Sessions do not store passwords, password hashes, CSRF tokens, cookies, uploaded file data, job data, targets, exports, Raw JSON, or billing/tenant data.

Implemented store behavior:

- create admin session;
- retrieve session by id only if still valid;
- check validity against store membership and expiry;
- invalidate session id;
- purge expired sessions;
- normalize naive test clocks to UTC for safety.

## Cookie Settings

Cookie skeleton settings:

- name: `inspectra_session`
- `HttpOnly`: true
- `SameSite`: `lax`
- `Secure`: false by default for localhost/dev skeleton use
- path: `/`
- max age: `INSPECTRA_SESSION_TTL_SECONDS`

The helper can build secure-cookie settings for future non-local/TLS deployments, but this slice does not set cookies on any response.

Future non-local use should require TLS or a trusted TLS-terminating reverse proxy before secure cookie auth is considered usable.

## Config

New config:

```text
INSPECTRA_SESSION_TTL_SECONDS
```

Rules:

- default is `3600` seconds;
- must be a positive integer;
- invalid values fail with a controlled `ValueError` through the existing config parsing pattern;
- the value is used for the in-memory store TTL and cookie max age.

No secret values are introduced. The setting does not expose session ids.

## What Was Not Implemented

- No `POST /auth/login`.
- No `POST /auth/logout`.
- No cookie is set on a response.
- No session principal is integrated with the deny-anonymous guard.
- No authenticated sensitive route access.
- No frontend login.
- No frontend auth-state handling.
- No CSRF protection.
- No rate limiting or lockout.
- No persistent session DB.
- No multi-user runtime.
- No public/community runtime.
- No OAuth/OIDC.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No Active expansion.
- No Nmap.
- No target policy relaxation.

## Tests

Focused backend tests cover:

- session creation returns an opaque id;
- session stores `operator_id=local-admin`;
- valid session is accepted before expiry;
- expired session is invalid;
- invalidated session is invalid;
- expired sessions are purged;
- session metadata does not include password or hash material;
- cookie settings include name, `HttpOnly`, `SameSite`, path, max age, and optional secure flag;
- session TTL config defaults and overrides;
- invalid session TTL config fails controlled;
- `/auth/status` remains hash/session-redacted and `login_available=false`;
- existing password/auth-status/auth-mode/anonymous/health behavior remains compatible.

Reference validation commands:

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "session or cookie or password or auth_status or auth_mode or anonymous or health"
.venv/bin/python -m pytest backend/tests/test_backend.py
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend code.

## Residual Risks

- In-memory sessions do not survive backend restart.
- There is still no usable login endpoint.
- There is still no logout endpoint.
- Sessions are not integrated with request authorization yet.
- CSRF protection remains future work.
- Frontend login/status UX remains future work.
- Rate limiting, backoff, and lockout remain future work.
- Persistent session storage, key rotation, and admin recovery flows remain future work.

## No-Scope Preserved

- No `.env`, `.env.*`, or `.envrc` reads.
- No login endpoint.
- No logout endpoint.
- No guard integration.
- No frontend changes.
- No CSRF implementation.
- No sensitive endpoint permission changes.
- No Docker execution.
- No probes, DNS, external HTTP, Nmap, port scanning, or live target traffic.
- No Active expansion.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-13-LOGIN-LOGOUT-ENDPOINTS
```

Next runtime work should wire the existing password verifier and session/cookie skeleton into explicit login/logout endpoints, while preserving generic failures, keeping `/auth/status` safe, and not broadening the guard beyond valid session principal resolution.
