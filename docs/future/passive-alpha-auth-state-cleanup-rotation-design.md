# Passive Alpha Auth State Cleanup Rotation Design

Status: `PASSIVE_ALPHA_AUTH_STATE_CLEANUP_ROTATION_DESIGN_ACCEPTED`

Base auth-state design: `docs/future/passive-alpha-persistent-auth-state-design.md`

SQLite scaffold: `docs/future/passive-alpha-sqlite-auth-store-scaffold.md`

Persistent session integration: `docs/future/passive-alpha-persistent-session-store-integration.md`

Persistent login-attempt integration: `docs/future/passive-alpha-persistent-login-attempt-store-integration.md`

Commit scope: documentation-only design for cleanup, rotation, retention, backup sensitivity, offline operator intervention, and operational limits for the local SQLite auth-state DB. This block does not change backend runtime behavior, frontend behavior, API responses, cookie/session/CSRF contracts, deployment behavior, release/tag state, Nmap/Active behavior, public/community readiness, or SaaS/billing behavior.

## Scope

This block freezes the cleanup and rotation model for the Passive Alpha SQLite auth-state DB before the next smoke/closeout work. It documents current behavior from the implemented backend and defines accepted expectations for validation and future operator guidance.

Explicitly out of scope:

- No runtime changes.
- No frontend changes.
- No API, cookie, session, CSRF, `429`, or `Retry-After` contract changes.
- No admin recovery endpoint.
- No trusted-proxy runtime behavior.
- No secure-cookie runtime enforcement.
- No public/community anti-abuse system.
- No SaaS.
- No billing.
- No tenant billing.
- No subscriptions.
- No quotas.
- No paid plans.
- No OAuth/OIDC.
- No multi-user runtime.
- No Nmap.
- No Active expansion.
- No production-ready claim.
- No release, tag, push, or GitHub release.
- No `.env`, `.env.*`, or `.envrc` reads.

## Current State Summary

The current auth-state implementation has two storage modes:

- `memory`, the default for local/dev and trusted-local use;
- `sqlite`, opt-in for `self_hosted_single_admin` through `INSPECTRA_AUTH_STATE_STORE=sqlite`.

When SQLite is enabled for `self_hosted_single_admin`, the backend uses the same local SQLite DB for:

- persistent single-admin sessions through `SQLiteAdminSessionStore`;
- persistent login attempts and soft lockouts through `SQLiteLoginAttemptStore`.

The DB is initialized by `SQLiteAuthStateStore` when the store is constructed. Initialization creates the parent directory, creates `auth_sessions`, `auth_login_attempts`, and `auth_state_metadata` tables if needed, creates supporting indexes, writes `schema_version = 1`, and fails closed with a controlled `SQLiteAuthStateError` if schema initialization fails.

### Sessions

SQLite sessions store hashed session ids and hashed CSRF tokens. They also store operator/auth metadata, timestamps, optional revocation metadata, and optional hashed client/user-agent context. Raw session ids and raw CSRF tokens are not stored.

Current behavior:

- `INSPECTRA_SESSION_TTL_SECONDS` controls absolute session expiration.
- `get_session` rejects missing, unknown, expired, or revoked sessions.
- `verify_session_csrf_token` rejects expired or revoked sessions.
- `update_session_csrf_token` updates only non-revoked, unexpired sessions.
- `touch_session` updates only non-revoked, unexpired sessions.
- `invalidate_session` revokes a session by setting `revoked_at` and `revocation_reason = logout`.
- Logout clears the browser cookie and revokes the persisted session when SQLite is enabled.
- A restarted store accepts unexpired, non-revoked sessions using the same DB path.
- A restarted store can verify an existing CSRF hash or issue a fresh CSRF token through authenticated `/auth/status`.
- Expired or revoked sessions are invalid immediately at read/verification time.
- `cleanup_sessions(now, revoked_retention_seconds=0)` deletes expired sessions and revoked sessions older than the retention window.
- `SQLiteAdminSessionStore.purge_expired_sessions()` calls `cleanup_sessions()` with the default zero revoked-session retention.

Current cleanup invocation caveat:

- No scheduler exists.
- `purge_expired_sessions()` exists but is not wired into every auth route today.
- Session rows can remain in the DB after expiration or revocation until cleanup is explicitly invoked, but they are invalid at read/verification time.

### Login Attempts

SQLite login attempts store hashed client-key material, failure counts, first/last failure timestamps, optional `locked_until`, and update timestamps. Raw client keys, passwords, admin password hashes, session ids, CSRF tokens, cookies, request bodies, uploads, reports, Raw JSON, SBOMs, and target histories are not stored in login-attempt rows.

Current behavior:

- `INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS` controls the failure-count window.
- `INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES` controls the lockout threshold.
- `INSPECTRA_LOGIN_LOCKOUT_SECONDS` controls soft lockout duration.
- `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS` bounds retained rows for SQLite as well as retained keys for memory mode.
- `POST /auth/login` calls `login_attempts.purge_expired()` before checking lockout in `self_hosted_single_admin`.
- `purge_expired()` deletes attempts outside the window and completed lockouts.
- Active lockouts survive backend/store recreation when the same DB path is reused.
- `record_failure()` increments inside the window, resets after the window expires, and preserves active lockout state.
- `record_failure()` prunes after writing when row count exceeds `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS`.
- Pruning removes oldest non-locked rows or completed lockouts first; active lockouts are not pruned solely because the table exceeds the max-key limit.
- Successful login calls `reset_success(client_key)`, deleting the matching persistent attempt row.
- `is_locked()` and `seconds_until_unlock()` treat completed lockouts as expired and trigger opportunistic cleanup.
- The login client key is still the backend-observed `request.client.host`.
- `X-Forwarded-For`, `X-Forwarded-Proto`, and `Forwarded` are ignored until a separate trusted-proxy policy is accepted.

### Restart And Multiprocess Caveats

- SQLite-backed sessions and lockouts survive backend restart when the same DB path is reused.
- Multiple store instances using the same DB path observe shared session and attempt state.
- SQLite is still a local file store, not a distributed auth service.
- Multi-process behavior depends on local SQLite file semantics and correct deployment placement.
- The in-memory CSRF token cache is process-local, but persisted CSRF hashes can be accepted when the client presents a valid token.

## Cleanup Model

### Sessions

Accepted model:

- Expired sessions must be invalid at read and CSRF-verification time.
- Revoked sessions must be invalid immediately after revocation.
- Cleanup should purge expired sessions.
- Cleanup should purge revoked sessions after a bounded retention window.
- A short revoked-session retention window may be useful for local troubleshooting if explicitly configured or implemented later.
- Zero revoked-session retention remains acceptable for v1 because revocation is already persisted and invalid at read time.
- No scheduler is required in v1.
- Opportunistic cleanup during `auth/status`, login, logout, or startup is acceptable if a future implementation chooses to wire it.
- Cleanup must remain local, deterministic, bounded, and controlled.

Important distinction:

- Invalidating a session and deleting its row are separate operations.
- Expired or revoked sessions are already invalid even if the row remains until cleanup.

### Login Attempts

Accepted model:

- Attempts outside `INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS` should be removed by cleanup.
- Completed lockouts should be removed by cleanup.
- Active lockouts must not be pruned solely because row count exceeds `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS`.
- Cleanup should run before lockout checks on `POST /auth/login`, matching current behavior.
- Bounded pruning should run after cleanup/recording to prevent unbounded SQLite growth.
- `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS` is the accepted v1 growth bound for SQLite rows as well as memory keys.
- Pruning should prefer oldest non-locked rows by update time.
- Errors must remain controlled and must not expose raw client keys, hashes, passwords, DB internals, or recovery instructions.

## Rotation Model

Rotation in this alpha means operator-controlled replacement or invalidation of local auth state, not automatic key rotation or HTTP recovery.

Accepted model:

- Full session rotation is not implemented in this block.
- Key/session rotation remains future work.
- Rotating or deleting the SQLite auth-state DB manually invalidates persisted sessions and lockouts because the state is removed.
- Removing the DB is a local/offline intervention, not an app feature.
- No HTTP endpoint should clear lockouts, recover admin access, rotate sessions, or bypass auth in this line.
- No frontend bypass, `.env` guidance, or retry strategy should be added.
- Any future tooling must be local-only, offline, auditable, and separated from the HTTP app.
- Any future rotation feature must preserve generic auth failures and must not reveal password correctness, client keys, session ids, CSRF tokens, or internal hashes.

## Backup And File Sensitivity

The SQLite auth-state DB is sensitive operational state.

Guidance:

- Treat the DB as an operational secret even though it stores hashes rather than raw tokens.
- Do not commit the DB.
- Do not attach the DB to public issues, support threads, reports, exports, or demos.
- Do not include the DB in generated audit reports or Raw JSON.
- Store the DB under a restrictive local data directory.
- Apply restrictive file and directory permissions where the platform allows.
- Protect backups and snapshots that include the DB.
- Document that restoring an old backup can restore unexpired sessions and active lockouts according to the timestamps in that backup.
- Document that deleting the DB loses local auth state and can force re-login or clear lockout state, but this is an offline operator intervention rather than a supported app recovery flow.

The DB must not store:

- passwords;
- admin password hashes;
- raw session ids;
- raw CSRF tokens;
- raw client keys;
- cookies;
- request bodies;
- uploaded files;
- job results;
- reports;
- Raw JSON;
- SBOMs;
- target histories.

## Operator Lockout Guidance

Persistent lockout is expected when SQLite auth state is enabled.

Guidance:

- A locked operator can remain locked after backend restart.
- This is expected and is part of restart-stable rate-limit behavior.
- Inspectra must not reveal whether a submitted password would otherwise have been correct.
- Login `429` should remain generic and should expose only safe `Retry-After`.
- No HTTP bypass or clear-lockout endpoint should be added in this path.
- In rare local alpha recovery cases, intervention may require local/offline handling of the auth-state DB or login-attempt rows.
- Detailed command guidance for manipulating the DB is out of scope for this microfase.
- Admin recovery/setup guidance should be designed separately before any operator-facing recovery flow is added.

## Config Guidance

Relevant variables:

- `INSPECTRA_AUTH_STATE_STORE`
- `INSPECTRA_AUTH_STATE_DB_PATH`
- `INSPECTRA_SESSION_TTL_SECONDS`
- `INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS`
- `INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES`
- `INSPECTRA_LOGIN_LOCKOUT_SECONDS`
- `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS`

Guidance:

- `INSPECTRA_AUTH_STATE_STORE=memory` remains the default.
- Memory mode preserves local/dev behavior and does not persist sessions or lockouts.
- `INSPECTRA_AUTH_STATE_STORE=sqlite` persists sessions and login attempts only for `self_hosted_single_admin`.
- `trusted_local_no_auth` remains memory-backed even if SQLite auth state is configured.
- `INSPECTRA_AUTH_STATE_DB_PATH` chooses the local DB path; the default path is under `INSPECTRA_DATA_DIR`.
- Lower session TTLs reduce maximum session lifetime but can increase login friction.
- Lower login windows or lockout durations reduce retained attempt state but may weaken throttling.
- Higher max-failure or shorter lockout settings may weaken brute-force resistance.
- Very low max-key settings can increase churn and reduce useful lockout history.
- Very high max-key settings can increase DB growth.
- Do not document real `.env` contents or secret values.

## Failure Behavior

Accepted expectations:

- SQLite initialization failure in `self_hosted_single_admin` with `INSPECTRA_AUTH_STATE_STORE=sqlite` must fail closed and controlled.
- The app must not silently fall back to memory in SQLite auth-state mode, because that would weaken restart-stable session and lockout expectations.
- SQLite operation failures during auth should produce controlled errors rather than leaking internals.
- Errors must not include passwords, admin password hashes, raw session ids, raw CSRF tokens, cookies, raw client keys, client-key hashes, or request bodies.
- Operator-facing startup errors may identify that SQLite auth-state initialization failed, but should avoid unnecessary sensitive detail.
- Public/API responses must preserve existing generic auth and rate-limit contracts.

## Testing Plan For Next Smoke

Recommended next smoke tests:

- Expired SQLite sessions are invalid.
- Cleanup removes expired session rows.
- Logout/revoked sessions are invalid immediately.
- Cleanup removes old revoked session rows.
- Active revoked sessions remain invalid even before cleanup.
- Attempts outside the login window are cleaned.
- Completed lockouts are cleaned.
- Active lockouts are not pruned solely by max-row pressure.
- Non-locked rows are pruned by `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS`.
- Store recreation preserves unexpired sessions, valid CSRF hashes, and active lockouts.
- Successful login resets the persistent attempt record.
- Deleting the local DB behaves like local auth-state loss and does not break `trusted_local_no_auth`.
- DB bytes do not contain raw session ids, CSRF tokens, passwords, admin password hashes, or raw client keys.
- `X-Forwarded-For`, `X-Forwarded-Proto`, and `Forwarded` remain ignored.
- Frontend auth state still avoids `localStorage` and `sessionStorage`.
- API, cookie, CSRF, `401`, `403`, `429`, and `Retry-After` contracts remain unchanged.

## Documentation And Runbook Updates For Next Smoke

The next smoke or closeout block should update, if needed:

- `docs/future/passive-alpha-deployment-hardening-runbook.md`;
- `README.md`;
- `docs/architecture.md`;
- `docs/security-scope.md`;
- a Pathing C closeout document after smoke passes.

Future runbook copy should cover:

- DB sensitivity;
- backup/snapshot handling;
- permission expectations;
- restart behavior;
- operator lockout caveats;
- no HTTP recovery/bypass endpoint;
- remaining secure-cookie and trusted-proxy gaps.

## Recommended Next Path

Recommended sequence:

1. `PASSIVE-ALPHA-AUTH-STATE-CLEANUP-ROTATION-SMOKE`
2. `PASSIVE-ALPHA-PERSISTENT-AUTH-CLOSEOUT`
3. `PASSIVE-ALPHA-RELEASE-CANDIDATE-CHECKLIST`
4. Tag, release, and push preparation.
5. Active/Nmap/CVE design only under separate docs-first, opt-in, bounded review.

## Residual Gaps After This Design

- Cleanup/rotation smoke remains pending.
- Admin recovery/setup guidance remains pending.
- Secure-cookie runtime enforcement remains pending.
- Trusted-proxy runtime enforcement remains pending.
- Public/community anti-abuse remains pending.
- Session/key rotation remains pending.
- Local/offline operator tooling remains pending.
- Release/tag/push remains pending.

## Final Decision

`PASSIVE_ALPHA_AUTH_STATE_CLEANUP_ROTATION_DESIGN_ACCEPTED`

Cleanup, rotation, backup sensitivity, and local/offline intervention expectations for the SQLite auth-state DB are accepted as docs-first design. The next step is a focused smoke/review block that validates existing cleanup and persistence behavior without changing frontend runtime, broadening auth scope, or approving production/public/community use.
