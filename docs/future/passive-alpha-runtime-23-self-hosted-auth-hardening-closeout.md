# Passive Alpha Runtime 23 Self-Hosted Auth Hardening Closeout

Status: `PASSIVE_ALPHA_SELF_HOSTED_AUTH_HARDENING_CLOSED`.

Base auth hardening smoke: `docs/future/passive-alpha-runtime-22-auth-hardening-smoke.md`

Base frontend rate-limit copy: `docs/future/passive-alpha-runtime-21-frontend-rate-limit-copy.md`

Base login rate-limit/backoff runtime: `docs/future/passive-alpha-runtime-20-login-rate-limit-backoff.md`

Base self-hosted auth closeout: `docs/future/passive-alpha-runtime-17-self-hosted-auth-closeout.md`

Commit scope: documentation-only closeout for the self-hosted auth hardening line. This block does not add runtime behavior, backend changes, frontend changes, tests, fixtures, persistent storage, admin recovery, multi-user auth, OAuth/OIDC, public/community runtime, Active expansion, Nmap behavior, Docker execution, release/tag state, push, or billing/SaaS/quota behavior.

## Final Decision

```text
PASSIVE_ALPHA_SELF_HOSTED_AUTH_HARDENING_CLOSED
```

The self-hosted single-admin auth hardening line is closed for the current Passive Alpha scope. Runtime-17 closed the usable self-hosted auth flow; Runtime-18 through Runtime-22 added and smoke-validated the first login hardening layer without changing Inspectra into a SaaS, billing, quota, paid-plan, tenant-billing, or enterprise multi-tenant product.

Inspectra remains open-source, altruistic, local-first, and self-hosted-first. Auth/session/CSRF/rate-limit controls are safety controls for local, self-hosted, private/internal, and optional future community use.

## Runtime Chain

| Block | Decision | Closeout summary |
| --- | --- | --- |
| Runtime-17 | `PASSIVE_ALPHA_SELF_HOSTED_AUTH_CLOSED` | Closed the initial self-hosted single-admin auth flow with password verification, login/logout, session cookie, CSRF, frontend auth UX, global `401`/`403`, owner-scoped backend protections, and Runtime-16 smoke evidence. |
| Runtime-18 | `PASSIVE_ALPHA_RATE_LIMIT_LOCKOUT_PLAN_ACCEPTED` | Defined the docs-first rate-limit/backoff/soft-lockout policy for `self_hosted_single_admin` without implementing runtime behavior. |
| Runtime-19 | `PASSIVE_ALPHA_RUNTIME_LOGIN_ATTEMPT_STORE_ACCEPTED` | Added the isolated in-memory `LoginAttemptStore` and bounded configuration for future login throttling. |
| Runtime-20 | `PASSIVE_ALPHA_RUNTIME_LOGIN_RATE_LIMIT_BACKOFF_ACCEPTED` | Wired the attempt store into `POST /auth/login`, returning generic `429` with safe `Retry-After` for locked client keys. |
| Runtime-21 | `PASSIVE_ALPHA_RUNTIME_FRONTEND_RATE_LIMIT_COPY_ACCEPTED` | Added controlled frontend copy for login `429` while keeping normal `401` login failures generic. |
| Runtime-22 | `PASSIVE_ALPHA_RUNTIME_AUTH_HARDENING_SMOKE_PASSED` | Smoke-validated backend and frontend auth hardening, no browser auth storage, backend/frontend regressions, and no-scope boundaries. |

## Supported State

- `trusted_local_no_auth` remains the default localhost/dev/local trusted mode.
- `self_hosted_single_admin` is available as the private/self-hosted single-admin mode when configured with a supported admin password hash.
- Login/logout are available through backend endpoints and frontend auth UX.
- Successful login issues an `HttpOnly` session cookie.
- CSRF is required on mutating cookie-auth routes through `X-CSRF-Token`.
- Sensitive routes remain owner-scoped for files, jobs, reports, Raw JSON, exports, SBOM, target jobs, Active job creation, and delete flows.
- Invalid login remains generic `401` with `Invalid credentials.`.
- Locked login receives controlled `429` with safe `Retry-After` from the backend.
- Frontend login `429` copy is controlled: `Too many attempts. Try again later.`
- Logout clears session state and returns to controlled unauthenticated behavior.
- Global `401` and `403` handling remains controlled in the frontend.
- Configured-origin CORS credential support remains covered by tests.
- No frontend `localStorage` or `sessionStorage` is used for auth state.

## Explicit No-Scope

- No runtime behavior changes.
- No SaaS.
- No billing.
- No tenant billing.
- No subscriptions.
- No quotas.
- No paid plans.
- No public/community runtime.
- No OAuth/OIDC.
- No multi-user runtime.
- No persistent sessions.
- No persistent rate-limit store.
- No admin recovery.
- No Docker execution.
- No Nmap.
- No port scanning.
- No crawling.
- No probes, DNS, or external HTTP.
- No Active expansion.
- No release, tag, or push.
- No `.env`, `.env.*`, or `.envrc` reads.

## Residual Gaps

- Sessions remain in memory and do not survive backend restart.
- Login attempt and soft-lockout state remains in memory and does not survive backend restart.
- Multiple backend processes do not share session or attempt state.
- Reverse proxy, TLS, and secure-cookie deployment hardening remain required before exposed self-hosted use.
- Trusted proxy header handling remains future deployment design.
- Session rotation and key rotation remain future work.
- Admin recovery and setup guidance remain future work.
- Public/community anti-abuse remains blocked until separate design and controls exist.
- Release notes remain a separate docs/product step.

## Validation Reference

Runtime-22 recorded the active smoke evidence:

```text
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "login or logout or csrf or session or cookie or auth_status or anonymous or owner or rate or lockout or files or jobs or export or sbom or active"
.venv/bin/python -m pytest backend/tests/test_backend.py
cd frontend && npm run test -- --run App
cd frontend && npm run test -- --run
cd frontend && npm run build
rg -n "localStorage|sessionStorage" frontend/src backend/app backend/tests
```

Runtime-23 is docs-only. Its validation is limited to source/no-scope review and diff hygiene:

```text
rg -n "localStorage|sessionStorage" frontend/src backend/app backend/tests
rg -n "Nmap|port scan|crawler|credential valid|vulnerability confirmed|exploitability confirmed|safe target|production ready|SaaS|billing|tenant billing|subscription|quota|paid plan" README.md docs/architecture.md docs/security-scope.md docs/future/passive-alpha-runtime-1*.md docs/future/passive-alpha-runtime-2*.md frontend/src backend/app backend/tests
git diff --check
git diff --cached --check
```

## Next Recommendation

```text
PASSIVE-ALPHA-SELF-HOSTED-RELEASE-NOTES
```

The next step should be a docs/product release-notes pass that explains the trusted-local and self-hosted single-admin auth state, the hardening smoke evidence, and the remaining non-production/public/community gaps. It should not add runtime behavior.
