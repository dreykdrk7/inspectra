# Passive Alpha Persistent Login Attempt Store Integration

Status: `PASSIVE_ALPHA_PERSISTENT_LOGIN_ATTEMPT_STORE_INTEGRATED`

Base design: `docs/future/passive-alpha-persistent-login-attempt-store-design.md`

Session integration: `docs/future/passive-alpha-persistent-session-store-integration.md`

Commit scope: backend login-attempt store integration, tests, and minimal documentation alignment. This block does not change frontend behavior, API response shapes, cookie/session/CSRF contracts, admin recovery, trusted proxy handling, secure-cookie enforcement, public/community runtime, SaaS/billing/quota behavior, Nmap, broader Active behavior, release/tag state, or new capabilities.

## Integrated Surface

- Added a SQLite-backed login-attempt adapter around the existing `SQLiteAuthStateStore`.
- Wired login attempts to SQLite only when `get_auth_mode(settings) == "self_hosted_single_admin"` and `INSPECTRA_AUTH_STATE_STORE=sqlite`.
- Kept `LoginAttemptStore` as the default memory-backed store.
- Kept `trusted_local_no_auth` memory-backed even if SQLite auth state is configured.
- Reused the existing login-attempt settings:
  - `INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS`
  - `INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES`
  - `INSPECTRA_LOGIN_LOCKOUT_SECONDS`
  - `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS`
- Reused the same SQLite DB path as persistent sessions through `INSPECTRA_AUTH_STATE_DB_PATH`.

## Runtime Behavior

- Failed login attempts in SQLite mode persist in `auth_login_attempts`.
- Failure counts increment inside the configured window and reset when the window expires.
- Soft lockouts persist across backend/store recreation when the same SQLite DB path is used.
- Successful login resets the matching persistent attempt record.
- Completed lockouts and expired attempt windows are cleaned by the same login path that already ran in-memory cleanup.
- SQLite row growth is bounded by pruning oldest non-locked rows after cleanup when the configured max-key limit is exceeded.
- Multiple store instances using the same DB path observe the same lockout state.

## Preserved Contracts

- `POST /auth/login` keeps the existing success, generic `401`, generic `429`, and safe `Retry-After` behavior.
- `/auth/status`, logout, session cookies, CSRF, and owner-scoped sensitive routes keep their existing contracts.
- Frontend behavior remains unchanged.
- `trusted_local_no_auth` remains the default local/dev mode and does not require persistent auth state.
- The login client key remains the backend-observed `request.client.host`.
- `X-Forwarded-For`, `X-Forwarded-Proto`, and `Forwarded` remain ignored until a separate trusted-proxy design is accepted.

## Storage And Redaction Guarantees

- Raw client keys are not stored in SQLite; login attempts store only hashed client-key material.
- Password values are not stored.
- Admin password hashes are not stored in login-attempt rows.
- Session ids, CSRF tokens, cookies, request bodies, uploads, job data, reports, Raw JSON, SBOMs, and target histories are not stored in login-attempt rows.
- Responses do not expose counters, thresholds, raw client keys, client-key hashes, DB paths, password correctness, or recovery guidance.
- Errors remain controlled and must not include secrets or lockout internals.

## Explicit No-Scope

- No frontend changes.
- No API/cookie/session/CSRF contract changes.
- No admin recovery endpoint.
- No trusted-proxy runtime behavior.
- No secure-cookie runtime enforcement.
- No public/community anti-abuse system.
- No OAuth/OIDC.
- No multi-user runtime.
- No SaaS, billing, tenant billing, subscriptions, quotas, or paid plans.
- No Docker execution.
- No Nmap.
- No port scanning.
- No crawling.
- No probes, DNS, external HTTP, or network traffic.
- No release, tag, push, or GitHub release.
- No `.env`, `.env.*`, or `.envrc` reads.

## Validation

Reference checks for this block:

```text
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "auth_state or sqlite or session or csrf or login or logout or auth_status or rate or lockout or attempt"
.venv/bin/python -m pytest backend/tests/test_backend.py
rg -n "localStorage|sessionStorage" frontend/src backend/app backend/tests
rg -n "Nmap|port scan|crawler|credential valid|vulnerability confirmed|exploitability confirmed|safe target|production ready|SaaS|billing|tenant billing|subscription|quota|paid plan" README.md docs/architecture.md docs/security-scope.md docs/future/passive-alpha-*.md frontend/src backend/app backend/tests
git diff --check
git diff --cached --check
```

## Residual Risks

- SQLite is a local file store, not a distributed auth service.
- SQLite file permissions, backups, snapshots, and placement remain operator responsibilities.
- A locked private operator can remain locked after backend restart.
- There is still no HTTP admin recovery or setup flow.
- Secure-cookie runtime enforcement remains separate.
- Trusted proxy header handling remains separate.
- Session/key rotation and auth-state cleanup/rotation guidance remain future work.
- Public/community anti-abuse remains blocked until separate design.

## Decision

`PASSIVE_ALPHA_PERSISTENT_LOGIN_ATTEMPT_STORE_INTEGRATED`

The private `self_hosted_single_admin` alpha line now has opt-in SQLite-backed persistence for both sessions and login-attempt lockout state when `INSPECTRA_AUTH_STATE_STORE=sqlite`. Default local/dev behavior remains memory-backed, and the integration preserves existing auth, CSRF, owner-scope, response, and frontend contracts.

## Next Recommendation

```text
PASSIVE-ALPHA-AUTH-STATE-CLEANUP-ROTATION-DESIGN
```

The next block should stay docs-first and define cleanup, rotation, offline recovery/operator guidance, and retention expectations for the local SQLite auth-state DB before adding more runtime auth behavior.
