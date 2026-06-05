# Passive Alpha Persistent Session Store Integration

Status: `PASSIVE_ALPHA_PERSISTENT_SESSION_STORE_INTEGRATED`

Base design: `docs/future/passive-alpha-persistent-auth-state-design.md`

Store scaffold: `docs/future/passive-alpha-sqlite-auth-store-scaffold.md`

Commit scope: backend session-store integration, tests, and minimal documentation alignment. This block does not change frontend behavior, does not add persistent login-attempt storage, does not add public/community runtime, and does not broaden Active/Nmap behavior.

## Integrated Surface

- Added backend config for `INSPECTRA_AUTH_STATE_STORE` with accepted values `memory` and `sqlite`.
- Kept `memory` as the default store.
- Added backend config for `INSPECTRA_AUTH_STATE_DB_PATH`.
- Default SQLite path, when SQLite is enabled, is `data/runtime/auth_state.sqlite3` under `INSPECTRA_DATA_DIR`.
- Wired `SQLiteAdminSessionStore` into `self_hosted_single_admin` only when `INSPECTRA_AUTH_STATE_STORE=sqlite`.
- Preserved the existing in-memory `AdminSessionStore` for default `trusted_local_no_auth`.
- Preserved the existing in-memory `LoginAttemptStore` for login rate-limit/backoff.

## Preserved Contracts

- `POST /auth/login` still returns the same response shape.
- `POST /auth/logout` still clears the `inspectra_session` cookie.
- `GET /auth/status` still returns safe authenticated state and a CSRF token only for an authenticated session.
- The browser cookie still contains only an opaque session id.
- CSRF remains required for mutating cookie-auth routes.
- Owner-scoped sensitive routes continue to use the current authenticated operator.
- Generic `401`, controlled `403`, and controlled login `429` behavior are unchanged.
- Frontend auth state remains in memory only.

## SQLite Session Behavior

- Successful login creates a persistent session row with hashed session id and hashed CSRF material.
- `/auth/status` can authenticate an unexpired, non-revoked SQLite-backed session after the session store is recreated with the same DB path.
- CSRF verification accepts a valid persisted CSRF hash after store recreation.
- If `/auth/status` needs to issue a fresh CSRF token after a backend/store recreation, the raw token is returned to the authenticated client and only its hash is persisted.
- Logout revokes the persisted session.
- Expired or revoked sessions are rejected after store recreation.
- SQLite initialization failures in `self_hosted_single_admin` with `INSPECTRA_AUTH_STATE_STORE=sqlite` fail closed as controlled backend initialization errors.

## Redaction And Storage Guarantees

- Raw session ids are not stored in SQLite.
- Raw CSRF tokens are not stored in SQLite.
- Admin password hashes are not stored in SQLite auth sessions.
- Cookies, password values, frontend storage, file/job data, reports, SBOMs, Raw JSON, and target histories are not added to auth state.
- No prefixes, suffixes, hashes intended as user-facing fingerprints, or reversible token identifiers are emitted.

## Explicit No-Scope

- No persistent login-attempt/rate-limit store integration in this block.
- No frontend changes.
- No multi-user runtime.
- No OAuth/OIDC.
- No public/community runtime.
- No SaaS, billing, tenant billing, subscriptions, quotas, or paid plans.
- No admin recovery/setup flow.
- No secure-cookie or trusted-proxy runtime hardening.
- No Docker execution.
- No Nmap.
- No port scanning.
- No crawling.
- No probes, DNS, external HTTP, or network traffic.
- No release, tag, or push.
- No `.env`, `.env.*`, or `.envrc` reads.

## Validation

Reference checks for this block:

```text
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "auth_state or sqlite or session or csrf or login or logout or auth_status"
.venv/bin/python -m pytest backend/tests/test_backend.py
rg -n "localStorage|sessionStorage" frontend/src backend/app backend/tests
rg -n "Nmap|port scan|crawler|credential valid|vulnerability confirmed|exploitability confirmed|safe target|production ready|SaaS|billing|tenant billing|subscription|quota|paid plan" README.md docs/architecture.md docs/security-scope.md docs/future/passive-alpha-runtime-1*.md docs/future/passive-alpha-runtime-2*.md frontend/src backend/app backend/tests
git diff --check
git diff --cached --check
```

## Residual Risks

- Persistent login attempts remain in memory and reset on backend restart.
- SQLite is a local file store, not a distributed auth service.
- Multi-process deployments do not share in-memory CSRF token cache state, although persisted CSRF hashes are accepted when clients present a valid token.
- SQLite file permissions, backups, and placement remain operator responsibilities.
- Secure-cookie runtime enforcement and trusted-proxy header handling remain separate hardening work.
- Session rotation, key rotation, and admin recovery/setup guidance remain future work.
- Public/community anti-abuse remains blocked until separate design.

## Decision

`PASSIVE_ALPHA_PERSISTENT_SESSION_STORE_INTEGRATED`

The private/self-hosted single-admin alpha line now has opt-in persistent session storage backed by the isolated SQLite auth-state store. The default local/dev mode stays memory-backed, and login-attempt persistence remains separate backlog.

## Next Recommendation

```text
PASSIVE-ALPHA-PERSISTENT-LOGIN-ATTEMPT-STORE-DESIGN
```

The next auth-state block should stay docs-first and decide whether to integrate SQLite-backed login-attempt persistence, including recovery/operator-lockout caveats, before any runtime change.
