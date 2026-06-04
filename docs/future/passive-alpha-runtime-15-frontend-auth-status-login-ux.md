# Passive Alpha Runtime 15 Frontend Auth Status Login UX

Status: `PASSIVE_ALPHA_RUNTIME_FRONTEND_AUTH_LOGIN_UX_ACCEPTED`.

Base Runtime-14 CSRF mutating-route guard: `docs/future/passive-alpha-runtime-14-csrf-mutating-routes.md`

Base Runtime-13 login/logout endpoints: `docs/future/passive-alpha-runtime-13-login-logout-endpoints.md`

Base Runtime-10 login/session plan: `docs/future/passive-alpha-runtime-10-single-admin-login-session-plan.md`

Commit scope: frontend auth status, login, logout, in-memory CSRF handling, global 401/403 handling, focused frontend/backend tests, and minimal documentation alignment. This block does not add rate limiting, lockout, multi-user auth, OAuth/OIDC, public/community runtime, Active expansion, Nmap, deployment approval, tags, releases, or billing/SaaS/tenant behavior.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_FRONTEND_AUTH_LOGIN_UX_ACCEPTED
```

Inspectra now has minimal frontend support for `self_hosted_single_admin` while preserving `trusted_local_no_auth` as the default local/dev/trusted flow.

The work keeps Inspectra open-source, altruistic, local-first, and self-hosted-first. Auth/session/CSRF are safety controls for local, self-hosted, private/internal, and optional future community use. They are not SaaS, billing, quota, paid-plan, tenant billing, or enterprise multi-tenant work.

## What Was Implemented

- Frontend calls `GET /auth/status` on startup.
- Frontend tracks:
  - `authRequired`;
  - `configured`;
  - `loginAvailable`;
  - `authenticated`;
  - `operatorId`;
  - `csrfRequired`;
  - `csrfToken`.
- Login gate appears only when auth is required and no valid session exists.
- `POST /auth/login` sends `{ "password": "..." }` with credentials included.
- Password state is cleared immediately on submit.
- On login success, the frontend refreshes `/auth/status` and keeps the CSRF token only in app memory.
- Mutating API requests send `X-CSRF-Token` only when CSRF is required and a token exists.
- GET requests do not receive a CSRF header.
- `POST /auth/logout` sends credentials and the CSRF header.
- Global `401` and `403` auth failures refresh auth status and return the UI to a login/session-expired state when appropriate.
- The backend CORS middleware now allows credentials for configured origins so the local frontend/backend split can use cookie auth.

## Auth Status Behavior

Startup flow:

1. Call `GET /auth/status`.
2. Configure the frontend API helper with `csrfRequired` and the in-memory `csrfToken`.
3. If auth is not required, load health, files, and jobs as before.
4. If auth is required and authenticated, load private dashboard data.
5. If auth is required and unauthenticated, load only public-safe health and show the auth gate.

The frontend does not store password, session id, cookie value, password hash, or CSRF token in `localStorage` or `sessionStorage`.

## Trusted Local Behavior

When `/auth/status` reports `auth_required=false`:

- the dashboard remains available;
- upload, audit, job, report, export, and Active panels keep their previous UX;
- no login gate is shown;
- no CSRF header is required by the frontend.

This preserves the current localhost/dev/trusted-local alpha experience.

## Login Behavior

When auth is required, login is available, and the user is unauthenticated:

- the frontend shows a small login panel;
- copy says: `Authentication required for this self-hosted instance.`;
- only a password field is shown;
- login failure shows a generic credential error;
- Runtime-21 adds controlled frontend copy for login `429` rate-limit responses while keeping normal credential failures generic;
- the password is cleared after submit;
- no hash, session id, cookie value, CSRF token, config secret, `.env` guidance, or bypass guidance is rendered.

When auth is required but login is unavailable, the frontend shows a controlled unavailable state without setup secrets or bypass instructions.

## Logout Behavior

When authenticated:

- the header shows `Signed in as local-admin`;
- the user can sign out;
- logout sends `POST /auth/logout` with credentials and `X-CSRF-Token`;
- on success, local authenticated state and CSRF state are cleared;
- `/auth/status` is refreshed;
- private UI state is cleared.

If logout fails due to `401` or `403`, the frontend clears local private state, refreshes auth status, and returns to login/session-expired state.

## CSRF Frontend Behavior

The API helper:

- always uses `credentials: "include"` for backend API requests;
- sends `X-CSRF-Token` for `POST`, `PUT`, `PATCH`, and `DELETE` only when `csrfRequired=true` and a token is in memory;
- does not send CSRF for `GET`;
- does not send CSRF to `POST /auth/login`;
- keeps the token out of DOM, URL, Raw JSON, reports, exports, local storage, and session storage.

## Global 401/403 Behavior

For backend `401` or `403` responses outside explicit login failure handling:

- the frontend refreshes `/auth/status`;
- if auth is required and the session is gone, files/jobs/selected job state are cleared;
- users see controlled session-expired or session-verification messages;
- internal route details, cookie values, token values, hashes, and config hints are not shown.

## What Was Not Implemented

- No rate limiting, backoff, or lockout.
- No password setup CLI.
- No persistent session DB.
- No multi-user runtime.
- No OAuth/OIDC.
- No reverse-proxy trusted-header auth.
- No public/community runtime.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No Active expansion.
- No Nmap.
- No target policy relaxation.

## Tests

Frontend tests cover:

- trusted-local auth status preserves dashboard content and avoids login gate;
- auth-required unauthenticated state shows login;
- auth-required unavailable state is controlled and avoids `.env`/bypass guidance;
- login success calls `/auth/login`, refreshes `/auth/status`, hides login, and clears password;
- login failure shows a generic error and clears password;
- CSRF token from auth status is sent on mutating upload;
- CSRF token is not sent on GET;
- CSRF token is not rendered in DOM;
- logout sends the CSRF header and returns to login state;
- global `401` refreshes auth and returns to login/session-expired state;
- existing dashboard, passive actions, Active dry-run, Active header-probe, and report tests remain passing.

Backend focused tests cover:

- auth/login/logout/session/CSRF status behavior remains compatible;
- configured-origin CORS preflight allows credentials for cookie auth.

Reference validation commands:

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "csrf or login or logout or session or auth_status or anonymous or cors"
npm run test -- --run App
npm run test -- --run
npm run build
git diff --check
git diff --cached --check
git status --short
```

No Docker, external probes, DNS, external HTTP, Nmap, or live target traffic are required for this block.

## Residual Risks

- Rate limiting, backoff, and lockout are still not implemented.
- Backend sessions and CSRF tokens remain in memory and do not survive backend restart.
- TLS/reverse-proxy deployment hardening remains required before exposed self-hosted use.
- Secure-cookie deployment behavior still needs non-local hardening.
- Persistent sessions, session rotation, key rotation, and admin recovery remain future work.
- Public/community readiness remains blocked.

## No-Scope Preserved

- No `.env`, `.env.*`, or `.envrc` reads.
- Runtime-15 itself did not implement rate limiting or lockout; Runtime-21 later added controlled frontend copy for backend login `429` responses.
- No multi-user runtime.
- No OAuth/OIDC.
- No public/community runtime.
- No Docker execution.
- No probes, DNS, external HTTP, Nmap, port scanning, or live target traffic.
- No Active expansion.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.

## Successor Status

```text
PASSIVE_ALPHA_RUNTIME_AUTH_FLOW_SMOKE_PASSED
```

Runtime-16 now accepts the backend plus frontend auth flow smoke and recommends `PASSIVE-ALPHA-RUNTIME-17-SELF-HOSTED-AUTH-CLOSEOUT` before opening rate limiting/lockout as a separate hardening slice. Runtime-15 remains the historical frontend auth status/login/logout UX slice.
