# Passive Alpha SQLite Auth Store Scaffold

Status: `PASSIVE_ALPHA_SQLITE_AUTH_STORE_SCAFFOLD_ACCEPTED`.

Base design: `docs/future/passive-alpha-persistent-auth-state-design.md`

Commit scope: isolated backend SQLite auth-state store, unit tests, and minimal documentation alignment. This block does not connect the store to live login/session/auth routes, does not change frontend behavior, does not change API responses/cookies, and does not add public/community runtime, production readiness, SaaS/billing/quota behavior, Nmap, or Active expansion.

## Final Decision

```text
PASSIVE_ALPHA_SQLITE_AUTH_STORE_SCAFFOLD_ACCEPTED
```

The isolated SQLite auth-state scaffold is accepted as the base for future persistent self-hosted auth work. The current live `self_hosted_single_admin` flow still uses the existing in-memory `AdminSessionStore` and `LoginAttemptStore`; this scaffold is not wired into runtime routes yet.

## Implemented Scope

- Added `backend/app/auth_state_sqlite.py`.
- Added `SQLiteAuthStateStore`.
- Added idempotent SQLite schema initialization.
- Added token/client-key hashing helpers using stdlib hashing.
- Added session methods for create, get, revoke, touch, and cleanup.
- Added login-attempt methods for record failure, get, reset, and cleanup.
- Added schema metadata with `schema_version = 1`.
- Added unit tests in `backend/tests/test_backend.py`.

## Schema Summary

The scaffold creates three local tables:

- `auth_sessions`
- `auth_login_attempts`
- `auth_state_metadata`

`auth_sessions` stores hashed session ids and hashed CSRF tokens, not raw token values. It records operator/auth metadata, created/last-seen/expires timestamps, optional revocation metadata, and optional hashed client/user-agent context.

`auth_login_attempts` stores hashed client keys, failure counts, failed-at timestamps, optional lockout timestamps, and update timestamps.

`auth_state_metadata` stores at least `schema_version = 1`.

## Redaction and Secret Handling

- Raw session ids are not stored.
- Raw CSRF tokens are not stored.
- Raw client keys are not stored.
- Passwords and admin password hashes are not stored.
- Cookies, request bodies, uploads, reports, Raw JSON, SBOMs, and secret values are not stored.
- Store errors use controlled messages and do not include token or hash material.

## Test Summary

The focused backend tests cover:

- schema init idempotency;
- metadata schema version;
- create/get session metadata;
- absence of raw session and CSRF tokens from returned objects and DB bytes;
- expired sessions returning `None`;
- revoked sessions returning `None`;
- revocation persistence across a new store instance;
- cleanup of expired and old revoked sessions;
- login failure record creation and increment;
- window reset behavior;
- lockout timestamp behavior;
- lockout persistence across a new store instance;
- reset of login-attempt records;
- sharing session and attempt state across two store instances using the same SQLite file;
- login-attempt cleanup.

Reference focused validation:

```text
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "auth_state or sqlite or session_store or login_attempt"
```

## Explicit No-Scope

- No live auth integration.
- No replacement of the current in-memory session store.
- No replacement of the current in-memory login-attempt store.
- No frontend changes.
- No user-visible runtime behavior changes.
- No API response or cookie contract changes.
- No persistent users table.
- No multi-user runtime.
- No OAuth/OIDC.
- No admin recovery implementation.
- No trusted proxy header runtime behavior.
- No secure-cookie runtime enforcement.
- No public/community runtime.
- No production-ready claim.
- No SaaS.
- No billing.
- No tenant billing.
- No subscriptions.
- No quotas.
- No paid plans.
- No Docker execution.
- No Nmap.
- No Active expansion.
- No probes, DNS, external HTTP, crawling, or port scanning.
- No release, tag, or push.
- No `.env`, `.env.*`, or `.envrc` reads.

## Residual Risks

- The scaffold is not yet wired into the live auth flow.
- SQLite file placement and permissions still need runtime integration decisions.
- A single SQLite file is not a distributed auth service.
- Secure-cookie and trusted-proxy runtime behavior remain separate hardening work.
- Admin recovery/setup guidance remains separate work.
- Public/community anti-abuse remains blocked until separate design.

## Next Recommendation

```text
PASSIVE-ALPHA-PERSISTENT-SESSION-STORE-INTEGRATION
```

The next block should wire persistent sessions into `self_hosted_single_admin` while preserving current route, cookie, CSRF, owner-scope, and response contracts. It should not add frontend changes unless the backend contract forces a minimal update, and it should keep public/community runtime, SaaS/billing behavior, Nmap, and Active expansion out of scope.
