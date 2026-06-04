# Passive Alpha Runtime 22 Auth Hardening Smoke

Status: `PASSIVE_ALPHA_RUNTIME_AUTH_HARDENING_SMOKE_PASSED`.

Base frontend rate-limit copy: `docs/future/passive-alpha-runtime-21-frontend-rate-limit-copy.md`

Base login rate-limit/backoff runtime: `docs/future/passive-alpha-runtime-20-login-rate-limit-backoff.md`

Base self-hosted auth closeout: `docs/future/passive-alpha-runtime-17-self-hosted-auth-closeout.md`

Base auth flow smoke: `docs/future/passive-alpha-runtime-16-auth-flow-smoke.md`

Commit scope: smoke validation and documentation for the self-hosted auth hardening line. This block does not add runtime behavior, rate-limit rules, persistent storage, admin recovery, multi-user auth, OAuth/OIDC, public/community runtime, Active expansion, Nmap behavior, Docker execution, release/tag state, or billing/SaaS/quota behavior.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_AUTH_HARDENING_SMOKE_PASSED
```

The current self-hosted auth hardening line passes smoke across backend and frontend coverage: login/logout/session/CSRF, owner-scoped sensitive routes, backend login `429`, frontend controlled rate-limit copy, and no browser storage for auth state.

Inspectra remains open-source, altruistic, local-first, and self-hosted-first. Auth/session/CSRF/rate-limit controls are safety controls for local, self-hosted, private/internal, and optional future community use. They are not SaaS, billing, quotas, paid plans, tenant billing, or enterprise multi-tenant work.

## Commands Run

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "login or logout or csrf or session or cookie or auth_status or anonymous or owner or rate or lockout or files or jobs or export or sbom or active"
.venv/bin/python -m pytest backend/tests/test_backend.py
cd frontend && npm run test -- --run App
cd frontend && npm run test -- --run
cd frontend && npm run build
rg -n "localStorage|sessionStorage" frontend/src backend/app backend/tests
rg -n "Nmap|port scan|crawler|credential valid|vulnerability confirmed|exploitability confirmed|safe target|production ready|SaaS|billing|tenant billing|subscription|quota|paid plan" README.md docs/architecture.md docs/security-scope.md docs/future/passive-alpha-runtime-1*.md frontend/src backend/app backend/tests
git diff --check
git diff --cached --check
git status --short
```

The frontend npm commands were run from `frontend/`, because the repository root does not contain a root `package.json`.

## Results

- Initial git state was clean on `main...origin/main [ahead 66]`.
- Latest commit before the smoke was `b5708d5 feat(alpha): add frontend rate limit copy`.
- `compileall backend` passed.
- Focused backend auth hardening smoke passed: `148 passed, 134 deselected`.
- Full backend suite passed: `282 passed`.
- Focused frontend App suite passed: `37 passed`.
- Full frontend suite passed: `127 passed`.
- Frontend build passed with `tsc --noEmit && vite build`.
- `rg -n "localStorage|sessionStorage" frontend/src backend/app backend/tests` returned no matches.
- No-scope text/source review found expected hits only.
- `git diff --check` passed.
- `git diff --cached --check` passed.

## Coverage Confirmed

- `trusted_local_no_auth` remains the default trusted local/dev mode.
- `self_hosted_single_admin` unauthenticated state shows the frontend login gate.
- Password verifier behavior remains fail-closed and generic.
- `POST /auth/login` issues an `HttpOnly` session cookie on success.
- Authenticated `/auth/status` reports authenticated state, operator id, CSRF requirement, and a session-bound CSRF token.
- Mutating cookie-auth routes require `X-CSRF-Token`.
- Owner-scoped sensitive routes remain protected for files, jobs, reports, Raw JSON, exports, SBOM, target jobs, Active job creation, and delete flows.
- Backend login rate limit returns controlled `429` with safe `Retry-After`.
- Frontend login `429` renders controlled copy: `Too many attempts. Try again later.`
- Frontend login `401` remains generic: `Invalid credentials.`
- Logout clears session state and returns to controlled unauthenticated behavior.
- Global `401`/`403` frontend handling refreshes auth status and clears private UI state when appropriate.
- Configured-origin CORS credential support remains covered.
- No browser `localStorage` or `sessionStorage` usage exists in `frontend/src`, `backend/app`, or `backend/tests`.
- Backend and frontend full suites plus frontend build pass.

## No-Scope Review

The broad text/source review for Nmap, port scanning, crawler language, credential-validity wording, confirmed-vulnerability wording, production-readiness wording, SaaS/billing/tenant/quota wording, and paid-plan language found expected hits only:

- docs and README copy that explicitly keep Nmap, port scanning, broader Active behavior, production readiness, external-user readiness, SaaS, billing, tenant billing, subscriptions, quotas, and paid plans out of scope;
- security-scope entries documenting historical decisions and explicit no-scope boundaries;
- tests that assert prohibited copy such as `Run Nmap`, `Scan`, `Attack`, `Exploit`, `port scan`, `crawl`, `fuzz`, and `brute force` is not shown;
- backend reporting copy that explicitly describes the limited Active header probe as no-Nmap/no-subprocess/no-redirect.

No unexpected runtime approval, production-readiness claim, credential-validity claim, confirmed-vulnerability claim, billing/quota feature, Nmap feature, port-scanning feature, or browser auth-state storage was found.

## No-Scope Preserved

- No new runtime behavior.
- No backend auth/rate-limit logic changes.
- No frontend feature changes.
- No new rate-limit rules.
- No persistent rate-limit store.
- No persistent sessions.
- No admin recovery.
- No multi-user runtime.
- No OAuth/OIDC.
- No public/community runtime.
- No Active expansion.
- No Nmap.
- No Docker execution.
- No probes, DNS, external HTTP, port scanning, crawling, or live target traffic.
- No tags, releases, or push.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No `.env`, `.env.*`, or `.envrc` reads.

## Remaining Gaps

- Sessions remain in memory and do not survive backend restart.
- Login attempt state remains in memory and does not survive backend restart.
- Multiple backend processes do not share session or attempt state.
- Reverse proxy/TLS/secure-cookie hardening remains required before exposed self-hosted use.
- Persistent sessions, session rotation, key rotation, and admin recovery/setup guidance remain future work.
- Trusted proxy header handling remains future deployment design.
- Public/community anti-abuse remains blocked until separate design and controls exist.
- Release notes remain a separate product/docs step.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-23-SELF-HOSTED-AUTH-HARDENING-CLOSEOUT
```

Runtime-23 should close the self-hosted auth hardening line as documentation-only, summarizing Runtime-17 through Runtime-22, current supported state, residual gaps, and the recommended release-notes path. `PASSIVE-ALPHA-SELF-HOSTED-RELEASE-NOTES` should follow after the closeout.
