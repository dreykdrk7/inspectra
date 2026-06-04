# Passive Alpha Runtime 16 Auth Flow Smoke

Status: `PASSIVE_ALPHA_RUNTIME_AUTH_FLOW_SMOKE_PASSED`.

Base Runtime-15 frontend auth UX: `docs/future/passive-alpha-runtime-15-frontend-auth-status-login-ux.md`

Base Runtime-14 CSRF mutating-route guard: `docs/future/passive-alpha-runtime-14-csrf-mutating-routes.md`

Base Runtime-13 login/logout endpoints: `docs/future/passive-alpha-runtime-13-login-logout-endpoints.md`

Commit scope: smoke validation and documentation for the frontend plus backend single-admin auth flow. This block does not add runtime behavior, rate limiting, lockout, multi-user auth, OAuth/OIDC, public/community runtime, Active expansion, Nmap, deployment approval, tags, releases, or billing/SaaS/tenant behavior.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_AUTH_FLOW_SMOKE_PASSED
```

The Runtime-16 smoke passed for the current `self_hosted_single_admin` flow while preserving `trusted_local_no_auth` as the default local/dev/trusted mode.

Inspectra remains open-source, altruistic, local-first, and self-hosted-first. Auth/session/CSRF are safety controls for self-hosted, local, private/internal, and optional future community use. They are not SaaS, billing, quotas, paid plans, tenant billing, or enterprise multi-tenant work.

## Commands Run

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "login or logout or csrf or session or cookie or auth_status or anonymous or cors"
.venv/bin/python -m pytest backend/tests/test_backend.py
npm run test -- --run App
npm run test -- --run
npm run build
rg -n "Nmap|port scan|crawler|credential valid|vulnerability confirmed|exploitability confirmed|safe target|production ready|SaaS|billing|tenant billing|subscription|localStorage|sessionStorage" README.md docs/architecture.md docs/security-scope.md docs/future/passive-alpha-runtime-1*.md frontend/src backend/app backend/tests
rg -n "localStorage|sessionStorage" frontend/src backend/app backend/tests
git diff --check
git diff --cached --check
git status --short
```

## Results

- Initial git state was clean on `main...origin/main [ahead 60]`.
- Latest commit before the smoke was `cd989e5 feat(alpha): add frontend single admin auth ux`.
- `compileall backend` passed.
- Focused backend auth smoke passed: `30 passed, 234 deselected`.
- Full backend suite passed: `264 passed`.
- Focused frontend App smoke passed: `36 passed`.
- Full frontend suite passed: `126 passed`.
- Frontend build passed with `tsc --noEmit && vite build`.
- `git diff --check` passed.
- `git diff --cached --check` passed.

## Coverage Confirmed

- `trusted_local_no_auth` still loads the dashboard without a login gate.
- `self_hosted_single_admin` unauthenticated state shows a password-only login gate.
- Login success calls `POST /auth/login`, then refreshes `GET /auth/status`.
- Login failure remains generic and does not reveal whether a hash exists, a password is wrong, or login is unavailable.
- Authenticated `/auth/status` returns `authenticated=true`, `operator_id=local-admin`, `csrf_required=true`, and a session-bound CSRF token.
- Mutating frontend API requests send `X-CSRF-Token` when CSRF is required and a token is in memory.
- GET requests do not send `X-CSRF-Token`.
- Logout sends `POST /auth/logout` with credentials and `X-CSRF-Token`, then clears local authenticated UI state.
- Global `401` and `403` handling refreshes auth state and returns to controlled login/session-expired messaging when appropriate.
- Password values are cleared after submit and are not rendered in the DOM.
- CSRF token is kept in frontend memory only and is not rendered in the DOM.
- No `localStorage` or `sessionStorage` use exists in `frontend/src`, `backend/app`, or `backend/tests`.
- Configured-origin CORS preflight allows credentials for the local split frontend/backend cookie flow.
- Backend and frontend full suites pass.

## Public Routes Confirmed

The current public-safe backend surface remains limited to:

- `GET /health`;
- `GET /auth/status`;
- `POST /auth/login`;
- `OPTIONS`;
- `POST /auth/logout` only with its session and CSRF semantics in auth-required mode.

These routes do not expose password hashes, passwords, session ids, cookie values, file ids, job ids, targets, storage paths, reports, exports, Raw JSON, or bypass guidance.

## Sensitive Routes Confirmed

In auth-required mode, sensitive routes remain protected before resource-specific work:

- uploads and file reads/deletes;
- file-based audit launches;
- target-based baseline jobs;
- Active dry-run and limited header-probe jobs;
- job lists and job details;
- reports and Markdown/HTML/XML/PDF exports;
- SBOM exports;
- Raw JSON/job payloads;
- owner-scoped delete operations.

Anonymous requests receive generic denial before route handlers can reveal resource existence. Authenticated mutating requests require a matching session-bound `X-CSRF-Token`.

## No-Scope Review

The optional text/source review was run for Nmap, port scanning, crawler language, confirmed-vulnerability language, production-readiness language, SaaS/billing/tenant language, and browser storage usage.

Expected hits were found in:

- docs and UI copy that explicitly say Nmap, port scanning, broader Active behavior, SaaS, billing, and tenant billing are out of scope;
- tests that assert prohibited copy such as `Run Nmap`, `Scan`, `Attack`, `Exploit`, `port scan`, `crawl`, `fuzz`, and `brute force` is not shown;
- historical docs that describe the open-source, local-first, self-hosted-first posture.

No source usage of `localStorage` or `sessionStorage` was found in `frontend/src`, `backend/app`, or `backend/tests`.

## No-Scope Preserved

- No rate limiting, backoff, or lockout.
- No multi-user runtime.
- No OAuth/OIDC.
- No public/community runtime.
- No Active expansion.
- No Nmap.
- No port scanning, crawling, external probes, DNS checks, or external HTTP traffic.
- No Docker execution.
- No tags, releases, or push.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No `.env`, `.env.*`, or `.envrc` reads.

## Remaining Gaps

- Rate limiting, backoff, and lockout remain future hardening work.
- Backend sessions and CSRF tokens are in memory and do not survive backend restart.
- TLS/reverse proxy and secure-cookie deployment hardening remain required before exposed self-hosted use.
- Persistent sessions, session rotation, key rotation, and admin recovery remain future work.
- Public/community readiness remains blocked.
- Optional release notes can summarize the trusted-local plus self-hosted auth line when product timing is right.

## Successor Status

```text
PASSIVE_ALPHA_SELF_HOSTED_AUTH_CLOSED
```

Runtime-17 now closes the current self-hosted single-admin auth line and recommends `PASSIVE-ALPHA-RUNTIME-18-RATE-LIMIT-LOCKOUT-PLAN` as the next hardening slice before self-hosted release notes.
