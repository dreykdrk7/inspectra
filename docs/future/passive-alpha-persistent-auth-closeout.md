# Passive Alpha Persistent Auth Closeout

Status: `PASSIVE_ALPHA_PERSISTENT_AUTH_CLOSED`

Base deployment hardening closeout: `docs/future/passive-alpha-deployment-hardening-closeout.md`

Base auth-state design: `docs/future/passive-alpha-persistent-auth-state-design.md`

Cleanup/rotation smoke: `docs/future/passive-alpha-auth-state-cleanup-rotation-smoke.md`

Commit scope: documentation-only closeout for the Passive Alpha private/self-hosted persistent auth-state line. This block consolidates SQLite auth-state design, scaffold, session persistence, login-attempt persistence, cleanup/rotation design, and smoke evidence without adding runtime behavior.

## Status

```text
PASSIVE_ALPHA_PERSISTENT_AUTH_CLOSED
```

The persistent auth-state line is closed for the private/self-hosted Passive Alpha path. It improves restart-stable session and lockout behavior when explicitly enabled for `self_hosted_single_admin`, while preserving the local-first default and keeping production/public/community readiness out of scope.

## Scope

This closeout is docs-only.

It does not:

- change backend runtime behavior;
- change frontend runtime behavior;
- change API, cookie, session, CSRF, `401`, `403`, `429`, or `Retry-After` contracts;
- add an admin recovery endpoint;
- add trusted-proxy runtime behavior;
- add secure-cookie runtime enforcement;
- add public/community anti-abuse;
- add SaaS, billing, tenant billing, subscriptions, quotas, paid plans, or enterprise behavior;
- add OAuth/OIDC;
- add multi-user runtime;
- add Nmap behavior or Active expansion;
- approve production-ready use;
- push, tag, or publish a release.

## Closed Chain

1. `PASSIVE_ALPHA_PERSISTENT_AUTH_STATE_DESIGN_ACCEPTED`

   Accepted a local SQLite auth-state store as the future direction for private/self-hosted sessions and login attempts. The design kept `trusted_local_no_auth` as the default and avoided public/community runtime, production readiness, SaaS/billing behavior, OAuth/OIDC, multi-user auth, Nmap, and broader Active behavior.

2. `PASSIVE_ALPHA_SQLITE_AUTH_STORE_SCAFFOLD_ACCEPTED`

   Added `SQLiteAuthStateStore`, schema initialization, auth-state metadata, hashing helpers, session methods, login-attempt methods, and isolated tests without wiring the store into live routes.

3. `PASSIVE_ALPHA_PERSISTENT_SESSION_STORE_INTEGRATED`

   Integrated SQLite-backed sessions for `self_hosted_single_admin` when `INSPECTRA_AUTH_STATE_STORE=sqlite`, with `INSPECTRA_AUTH_STATE_DB_PATH` selecting the local DB path. Existing login/logout/status/cookie/CSRF/owner-scope contracts were preserved.

4. `PASSIVE_ALPHA_PERSISTENT_LOGIN_ATTEMPT_STORE_DESIGN_ACCEPTED`

   Froze the semantics for SQLite-backed login attempts, soft lockout persistence, cleanup, row bounds, operator-lockout caveats, and trusted-proxy non-use before runtime integration.

5. `PASSIVE_ALPHA_PERSISTENT_LOGIN_ATTEMPT_STORE_INTEGRATED`

   Integrated SQLite-backed login-attempt and rate-limit state for `self_hosted_single_admin` when `INSPECTRA_AUTH_STATE_STORE=sqlite`, preserving memory defaults, generic `429`, safe `Retry-After`, current backend-observed client-key semantics, and ignored forwarded headers.

6. `PASSIVE_ALPHA_AUTH_STATE_CLEANUP_ROTATION_DESIGN_ACCEPTED`

   Designed cleanup, retention, local DB rotation semantics, backup sensitivity, offline operator intervention boundaries, and smoke criteria for the SQLite auth-state DB.

7. `PASSIVE_ALPHA_AUTH_STATE_CLEANUP_ROTATION_SMOKE_PASSED`

   Validated cleanup, pruning, expiration, revocation, restart/store recreation, redaction, ignored forwarded headers, and preserved auth contracts with focused backend smoke coverage.

## Current Accepted State

- `INSPECTRA_AUTH_STATE_STORE=memory` remains the default.
- `trusted_local_no_auth` remains local/dev/trusted and memory-backed.
- `self_hosted_single_admin` may opt in to SQLite auth state with `INSPECTRA_AUTH_STATE_STORE=sqlite`.
- `INSPECTRA_AUTH_STATE_DB_PATH` defines the local SQLite DB path; when unset, the path resolves under the local data directory as `runtime/auth_state.sqlite3`.
- SQLite mode persists single-admin sessions.
- SQLite mode persists CSRF hash/session binding.
- SQLite mode persists login attempts and soft lockouts.
- Login, logout, and `/auth/status` preserve current response contracts.
- Cookie behavior remains the existing opaque `inspectra_session` session id in an `HttpOnly` cookie.
- Raw session ids are not stored in SQLite.
- Raw CSRF tokens are not stored in SQLite.
- Raw login client keys are not stored in SQLite.
- Password values and admin password hashes are not stored in SQLite auth state.
- Generic `401`, controlled `403`, controlled `429`, and safe `Retry-After` behavior are preserved.
- `X-Forwarded-For`, `X-Forwarded-Proto`, and `Forwarded` remain ignored until a separate trusted-proxy policy exists.
- The frontend does not use browser `localStorage` or `sessionStorage` for auth state.
- Backend focused smoke and the full backend suite pass for this line.

## Validation Evidence

Recent validation evidence accumulated by the Pathing C blocks:

- SQLite auth store scaffold focused tests: `23 passed`.
- Persistent session focused tests: `58 passed`.
- Persistent login-attempt focused tests: `65 passed`.
- Cleanup/rotation focused smoke: `67 passed, 241 deselected`.
- Backend full suite final: `308 passed`.
- `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend` passed.
- `rg -n "localStorage|sessionStorage" frontend/src backend/app backend/tests` returned no matches.
- The broad no-scope text search returned expected docs/test-copy hits only.
- `git diff --check` passed.
- `git diff --cached --check` passed.

## Boundaries Preserved

- No frontend runtime changes.
- No backend runtime changes in this closeout block.
- No API, cookie, session, CSRF, `401`, `403`, `429`, or `Retry-After` contract changes.
- No admin recovery endpoint.
- No trusted-proxy runtime behavior.
- No secure-cookie runtime enforcement.
- No public/community runtime.
- No production-ready approval.
- No SaaS, billing, tenant billing, quota, subscription, paid-plan, or enterprise behavior.
- No OAuth/OIDC.
- No multi-user runtime.
- No Docker execution in this line.
- No Nmap.
- No Active expansion.
- No probes, DNS, or external HTTP.
- No push, tag, release, or GitHub release.
- No `.env`, `.env.*`, or `.envrc` reads.

## Residual Gaps After Pathing C

- Admin recovery/setup guidance remains pending.
- Secure-cookie runtime enforcement remains pending.
- Trusted-proxy runtime enforcement remains pending.
- Public/community anti-abuse remains pending.
- Session/key rotation remains pending.
- Local/offline operator tooling remains pending.
- Release candidate checklist remains pending.
- Tag/release/push remains pending.
- Active/Nmap/CVE expansion remains pending under separate docs-first, opt-in, bounded design.

## Release Readiness Position

Persistent auth-state is closed for the private/self-hosted Passive Alpha path. It improves restart-stable authentication and lockout behavior for `self_hosted_single_admin` when SQLite auth state is explicitly enabled.

This does not make Inspectra production-ready. It does not approve public/community hosting, does not replace deployment hardening, and does not provide TLS, reverse proxy, trusted-proxy, secure-cookie, or recovery controls by itself.

The next product step should be a release-candidate checklist, not Nmap or a new Active capability.

## Next Recommendation

```text
PASSIVE-ALPHA-RELEASE-CANDIDATE-CHECKLIST
```

After that, continue with tag/release/push preparation, GitHub release planning, and any Active/Nmap/CVE work only through separate docs-first, opt-in, bounded design.

## Final Decision

```text
PASSIVE_ALPHA_PERSISTENT_AUTH_CLOSED
```

Pathing C is closed. The private/self-hosted Persistent Auth line is coherent enough to proceed to release-candidate checklist work while keeping production/public/community readiness and broader Active/Nmap/CVE work separate.
