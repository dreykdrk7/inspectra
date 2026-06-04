# Passive Alpha Runtime 17 Self-Hosted Auth Closeout

Status: `PASSIVE_ALPHA_SELF_HOSTED_AUTH_CLOSED`.

Base Runtime-16 auth flow smoke: `docs/future/passive-alpha-runtime-16-auth-flow-smoke.md`

Base Runtime-15 frontend auth UX: `docs/future/passive-alpha-runtime-15-frontend-auth-status-login-ux.md`

Base Runtime-14 CSRF mutating-route guard: `docs/future/passive-alpha-runtime-14-csrf-mutating-routes.md`

Base Runtime-13 login/logout endpoints: `docs/future/passive-alpha-runtime-13-login-logout-endpoints.md`

Base Runtime-09 trusted-local hardened closeout: `docs/future/passive-alpha-runtime-09-runtime-p0-closeout.md`

Commit scope: documentation-only closeout for the current self-hosted single-admin auth line. This block does not change backend, frontend, runner, tests, fixtures, auth runtime, Active behavior, Nmap behavior, deployment behavior, release/tag state, or billing/SaaS/tenant behavior.

## Final Decision

```text
PASSIVE_ALPHA_SELF_HOSTED_AUTH_CLOSED
```

The `self_hosted_single_admin` auth line is closed for the current Passive Alpha scope.

Inspectra now has a usable self-hosted single-admin auth flow with backend and frontend support: password hash verification, login/logout, an `HttpOnly` session cookie, session-bound CSRF, frontend auth status loading, a password-only login gate, frontend logout, in-memory CSRF handling, global `401`/`403` handling, existing owner-scoped backend protections, and passing smoke evidence.

This closeout preserves Inspectra's framing: open-source, altruistic, local-first, and self-hosted-first. Auth/session/CSRF are safety controls for self-hosted, local, private/internal, and optional future community use. They are not SaaS, billing, quotas, paid plans, tenant billing, or enterprise multi-tenant work.

## Closed Blocks

| Block | Decision | Result |
| --- | --- | --- |
| Runtime-10 | `PASSIVE_ALPHA_SINGLE_ADMIN_LOGIN_SESSION_PLAN_ACCEPTED` | Defined the single-admin login/session plan, CSRF implications, frontend auth-state expectations, and future slice order. |
| Runtime-11 | `PASSIVE_ALPHA_RUNTIME_PASSWORD_VERIFY_HELPER_ACCEPTED` | Added fail-closed `pbkdf2_sha256$iterations$salt$digest` admin password hash verification. |
| Runtime-12 | `PASSIVE_ALPHA_RUNTIME_SESSION_COOKIE_SKELETON_ACCEPTED` | Added in-memory admin sessions, opaque session ids, cookie metadata, and `INSPECTRA_SESSION_TTL_SECONDS`. |
| Runtime-13 | `PASSIVE_ALPHA_RUNTIME_LOGIN_LOGOUT_ENDPOINTS_ACCEPTED` | Added backend `POST /auth/login`, `POST /auth/logout`, session-cookie issuance/clearing, and authenticated principal resolution. |
| Runtime-14 | `PASSIVE_ALPHA_RUNTIME_CSRF_MUTATING_ROUTES_ACCEPTED` | Added session-bound CSRF tokens, authenticated `/auth/status` token exposure, and `X-CSRF-Token` checks for mutating cookie-auth routes. |
| Runtime-15 | `PASSIVE_ALPHA_RUNTIME_FRONTEND_AUTH_LOGIN_UX_ACCEPTED` | Added frontend auth status loading, login gate, login/logout calls, in-memory CSRF handling, and global `401`/`403` UX. |
| Runtime-16 | `PASSIVE_ALPHA_RUNTIME_AUTH_FLOW_SMOKE_PASSED` | Validated the backend plus frontend auth flow with focused/full backend and frontend test suites and build. |

## Implemented State

- `INSPECTRA_AUTH_MODE` controls deployment/auth mode.
- `trusted_local_no_auth` remains the default localhost/dev/trusted mode.
- `self_hosted_single_admin` is usable when a supported admin password hash is configured.
- `INSPECTRA_ADMIN_PASSWORD_HASH` accepts the supported `pbkdf2_sha256$iterations$salt$digest` format.
- `INSPECTRA_SESSION_TTL_SECONDS` controls in-memory admin session TTL and session-cookie max age.
- `GET /auth/status` reports safe auth mode, configured/login availability, authenticated state, operator id, CSRF requirement, and authenticated CSRF token when a valid session exists.
- `POST /auth/login` verifies the configured hash and issues the `inspectra_session` cookie on success.
- `POST /auth/logout` clears the session with session and CSRF semantics.
- The `inspectra_session` cookie is `HttpOnly`, `SameSite=lax`, path-scoped to `/`, and currently remains localhost/dev oriented.
- CSRF uses `X-CSRF-Token` with a server-side token bound to the current admin session.
- Cookie-auth mutating routes require a valid session and matching CSRF token.
- Frontend startup calls `GET /auth/status`.
- Frontend preserves the trusted-local dashboard when auth is not required.
- Frontend shows a password-only login gate when `self_hosted_single_admin` requires auth and no session exists.
- Frontend calls login/logout endpoints with credentials included.
- Frontend keeps CSRF state in memory only and sends `X-CSRF-Token` on mutating requests when required.
- Frontend does not send CSRF on GET requests.
- Frontend handles global `401` and `403` auth failures by refreshing auth status and clearing private UI state when appropriate.
- Existing owner-scoped backend reads, writes, exports, SBOM, Raw JSON, target-job ownership, and delete semantics continue to apply.

## Evidence Preserved

Runtime-16 recorded the auth flow smoke evidence:

- `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend`: passed.
- Backend focused auth smoke: `30 passed, 234 deselected`.
- Full backend suite: `264 passed`.
- Frontend App suite: `36 passed`.
- Full frontend suite: `126 passed`.
- `npm run build`: passed.
- No `localStorage` or `sessionStorage` usage found in `frontend/src`, `backend/app`, or `backend/tests`.
- No-scope review found expected hits only: docs/UI copy that explicitly keeps Nmap, port scanning, broader Active behavior, SaaS, billing, and tenant billing out of scope, plus tests asserting prohibited copy is not shown.

## Current Supported Modes

### `trusted_local_no_auth`

- Default mode.
- No login gate.
- No session cookie required.
- No CSRF required.
- Uses the default local/admin operator `local-admin`.
- Intended only for localhost/dev/local trusted use.

### `self_hosted_single_admin`

- Usable for the current self-hosted single-admin scope when `INSPECTRA_ADMIN_PASSWORD_HASH` is configured with a supported hash.
- Uses password verification, session cookie, CSRF, frontend login/logout UX, and owner-scoped backend protections.
- Still needs TLS/reverse-proxy hardening and secure-cookie deployment guidance before exposed self-hosted use.

### `private_team_lightweight_users`

- Accepted as a future mode name only.
- Not ready and not implemented as a multi-user runtime.

### `public_community_limited_instance`

- Accepted as a future mode name only.
- Not ready and not implemented as a public/community runtime.

## Remaining Gaps

- Rate limiting, backoff, and lockout remain future hardening work.
- In-memory sessions do not survive backend restart.
- Persistent sessions, session rotation, key rotation, and admin recovery remain future work.
- Operators still need explicit password-hash generation/setup guidance.
- TLS/reverse proxy hardening docs and runtime smoke remain future work.
- Secure-cookie behavior outside localhost/dev remains future deployment hardening.
- Public/community anti-abuse controls remain future work.
- Multi-user runtime remains future work.
- OAuth/OIDC remains future work.
- Release notes for the trusted-local plus self-hosted auth line remain optional future work.

## Risk Register

- Brute-force risk remains without rate limiting, backoff, or lockout.
- Active sessions are lost on backend restart because sessions are in memory.
- Incorrect hash generation or storage can make login unavailable or unsafe for operators.
- Exposed self-hosted use requires TLS/reverse-proxy hardening before it should be treated as deployment-ready.
- Frontend auth state now exists and must stay covered by tests in future UI changes.
- Future mutating routes must keep the same auth and CSRF guard expectations.
- Future public/community use remains blocked until separate anti-abuse, isolation, retention, logging, and deployment controls exist.

## Recommended Next Paths

Primary recommendation:

```text
PASSIVE-ALPHA-RUNTIME-18-RATE-LIMIT-LOCKOUT-PLAN
```

If the product goal is security before broader publication, the next docs-first block should plan rate limiting, backoff, lockout, and safe failure semantics for `self_hosted_single_admin`.

Follow-up recommendation:

```text
PASSIVE-ALPHA-SELF-HOSTED-RELEASE-NOTES
```

After the rate-limit/lockout plan, or if the immediate goal is explaining current state rather than hardening it, prepare release notes that clearly describe trusted-local and self-hosted single-admin status without implying production/public/community readiness.

Recommended order:

1. `PASSIVE-ALPHA-RUNTIME-18-RATE-LIMIT-LOCKOUT-PLAN`
2. `PASSIVE-ALPHA-SELF-HOSTED-RELEASE-NOTES`

## No-Scope Preserved

- No code changes.
- No backend changes.
- No frontend changes.
- No runner changes.
- No tests or fixture changes.
- No rate limiting implementation.
- No multi-user runtime.
- No OAuth/OIDC.
- No public/community runtime.
- No Docker execution.
- No Nmap.
- No Active expansion.
- No probes, DNS, external HTTP, port scanning, or live target traffic.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No `.env`, `.env.*`, or `.envrc` reads.

## Acceptance Criteria

- Decisions from Runtime-10 through Runtime-16 are summarized.
- Implemented auth state is explicit.
- Runtime-16 evidence is preserved.
- Supported modes are clear.
- Remaining gaps and risks are clear.
- Next path is recommended.
- No runtime or capability changes are introduced.
