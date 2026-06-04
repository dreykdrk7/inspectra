# Passive Alpha Runtime 13 Login Logout Endpoints

Status: `PASSIVE_ALPHA_RUNTIME_LOGIN_LOGOUT_ENDPOINTS_ACCEPTED`.

Base Runtime-12 session/cookie skeleton: `docs/future/passive-alpha-runtime-12-session-cookie-skeleton.md`

Base Runtime-11 password verifier: `docs/future/passive-alpha-runtime-11-password-verify-helper.md`

Base Runtime-10 login/session plan: `docs/future/passive-alpha-runtime-10-single-admin-login-session-plan.md`

Base Runtime-09 closeout: `docs/future/passive-alpha-runtime-09-runtime-p0-closeout.md`

Commit scope: minimal backend login/logout endpoints, session-cookie issuance/clearing, session principal integration with the existing auth-required guard, focused tests, and documentation alignment. This block does not add frontend login, CSRF, rate limiting, lockout, multi-user auth, OAuth/OIDC, public/community readiness, target policy changes, Active changes, Nmap, tags, releases, or deployment behavior.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_LOGIN_LOGOUT_ENDPOINTS_ACCEPTED
```

Inspectra now has a minimal backend authentication path for `self_hosted_single_admin`.

The implementation connects:

- Runtime-11 password verification;
- Runtime-12 in-memory sessions and cookie settings;
- Runtime-03 deny-anonymous sensitive route behavior;
- the existing single-admin owner model with `local-admin`.

## What Was Implemented

- `POST /auth/login`
- `POST /auth/logout`
- `/auth/status` authenticated-state reporting
- session-cookie issuance on successful login
- session-cookie clearing on logout
- valid-session principal resolution for auth-required sensitive routes
- generic login failure responses
- tests for success, failure, cookie flags, protected-route access, logout invalidation, and redaction

The public-safe backend auth routes are now:

- `GET /health`
- `GET /auth/status`
- `POST /auth/login`
- `POST /auth/logout`
- `OPTIONS` preflight

`POST /auth/login` and `POST /auth/logout` expose no file, job, target, report, export, SBOM, Raw JSON, storage path, password hash, session id, cookie value, or CSRF secret in response JSON.

## Login Behavior

Endpoint:

```text
POST /auth/login
```

Request body:

```json
{"password": "operator supplied password"}
```

Optional username behavior:

- username is not required;
- if supplied, only `admin` is accepted;
- unsupported username values return the same generic credential failure.

Login succeeds only when all are true:

- `INSPECTRA_AUTH_MODE=self_hosted_single_admin`;
- `INSPECTRA_ADMIN_PASSWORD_HASH` is present;
- the hash is in the supported `pbkdf2_sha256$iterations$salt$digest` format;
- the supplied password verifies through `verify_admin_password(...)`.

Generic failure response:

```json
{"detail": "Invalid credentials."}
```

This same response is used for wrong password, missing hash, unsupported hash, wrong auth mode, or unsupported username. It intentionally does not reveal which condition failed.

Success response:

```json
{
  "authenticated": true,
  "operator_id": "local-admin",
  "auth_mode": "self_hosted_single_admin"
}
```

The success JSON does not include the session id, cookie value, password, password hash, CSRF token, or any target/file/job data.

## Logout Behavior

Endpoint:

```text
POST /auth/logout
```

Logout behavior:

- reads the session cookie if present;
- invalidates the session if it exists;
- clears the session cookie;
- returns generic success even when no valid session existed;
- does not reveal whether a session existed.

Success response:

```json
{
  "authenticated": false,
  "operator_id": null,
  "auth_mode": "self_hosted_single_admin"
}
```

Logout is a mutating route. Runtime-14 must add CSRF protection before cookie-auth browser use is considered complete.

## Session Guard Integration

In `trusted_local_no_auth`:

- behavior remains compatible with the existing local trusted operator flow;
- current owner remains `local-admin`;
- login is not required.

In `self_hosted_single_admin`:

- anonymous requests to sensitive routes still receive generic `401`;
- a valid `inspectra_session` cookie resolves the current principal as `local-admin`;
- the existing owner-scoped file/job/report/export/SBOM/Raw JSON/delete checks continue to use that principal;
- expired, missing, unknown, or invalidated sessions are denied.

No multi-user identity or admin read-all behavior is added.

## Auth Status Changes

`GET /auth/status` remains public-safe.

Trusted-local response remains unauthenticated and no-auth:

```json
{
  "auth_required": false,
  "trusted_local": true,
  "login_available": false,
  "authenticated": false,
  "operator_id": null
}
```

`self_hosted_single_admin` with a supported hash reports:

```json
{
  "auth_required": true,
  "configured": true,
  "trusted_local": false,
  "login_available": true,
  "authenticated": false,
  "operator_id": null
}
```

With a valid session, it reports:

```json
{
  "login_available": true,
  "authenticated": true,
  "operator_id": "local-admin"
}
```

The response does not include password hashes, passwords, session ids, cookie values, CSRF tokens, file ids, job ids, target history, storage paths, or bypass guidance.

If a hash is absent or unsupported, `login_available=false` and login fails generically.

## Cookie Behavior

Login sets the `inspectra_session` cookie using Runtime-12 settings:

- `HttpOnly`;
- `SameSite=lax`;
- `Path=/`;
- `Max-Age=INSPECTRA_SESSION_TTL_SECONDS`;
- `Secure=false` in the current localhost/dev skeleton settings.

Logout clears the same cookie with `Max-Age=0`.

Secure cookies for non-local deployments remain future deployment hardening work. Self-hosted exposed use still needs TLS or a trusted TLS-terminating reverse proxy.

## What Was Not Implemented

- No frontend login UI.
- No frontend auth-state handling.
- No CSRF protection.
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

- trusted-local auth status compatibility;
- missing hash login failure with generic response;
- unsupported hash login failure with generic response;
- wrong password login failure with generic response;
- successful login sets an `HttpOnly` `SameSite=lax` session cookie;
- login success JSON excludes password, password hash, cookie name, and session id;
- non-admin username fails generically;
- protected route remains denied without a cookie;
- protected route succeeds with a valid session cookie;
- `/auth/status` reports `authenticated=true` and `operator_id=local-admin` with a valid session;
- `/auth/status` does not leak password/hash/session/cookie material;
- logout clears the cookie and invalidates the session;
- protected route is denied after logout;
- repeated logout remains generic success.

Reference validation commands:

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "login or logout or session or cookie or password or auth_status or auth_mode or anonymous or owner or files or jobs"
.venv/bin/python -m pytest backend/tests/test_backend.py
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend code.

## Residual Risks

- CSRF protection is not implemented yet.
- Frontend login/status/logout UX is not implemented yet.
- Rate limiting, backoff, and lockout are not implemented yet.
- In-memory sessions do not survive backend restart.
- Secure cookie behavior for non-local deployments still needs TLS/reverse-proxy hardening.
- Persistent sessions, session rotation, key rotation, and admin recovery remain future work.
- Public/community readiness remains blocked.

## No-Scope Preserved

- No `.env`, `.env.*`, or `.envrc` reads.
- No frontend changes.
- No CSRF implementation.
- No rate limiting or lockout.
- No multi-user runtime.
- No OAuth/OIDC.
- No public/community runtime.
- No Docker execution.
- No probes, DNS, external HTTP, Nmap, port scanning, or live target traffic.
- No Active expansion.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-14-CSRF-MUTATING-ROUTES
```

Next runtime work should add CSRF protection for cookie-auth mutating routes before frontend login UX or broader browser-auth use is considered complete.
