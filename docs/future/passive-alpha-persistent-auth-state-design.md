# Passive Alpha Persistent Auth State Design

Status: `PASSIVE_ALPHA_PERSISTENT_AUTH_STATE_DESIGN_ACCEPTED`.

Base closeout: `docs/future/passive-alpha-deployment-hardening-closeout.md`

Base auth hardening closeout: `docs/future/passive-alpha-runtime-23-self-hosted-auth-hardening-closeout.md`

Commit scope: documentation-only design for persistent private/self-hosted auth state. This block does not add runtime behavior, backend changes, frontend changes, tests, persistent storage implementation, migrations, Docker execution, Nmap behavior, Active expansion, public/community runtime, production-ready claims, release/tag/push state, or billing/SaaS/quota behavior.

## Final Decision

```text
PASSIVE_ALPHA_PERSISTENT_AUTH_STATE_DESIGN_ACCEPTED
```

The accepted direction is a small local SQLite auth-state store for the Passive Alpha private/self-hosted line. The store should persist single-admin sessions and login attempt lockout state across backend restarts without introducing a SaaS tenant model, multi-user runtime, billing behavior, public/community readiness, or production approval.

This design is intentionally narrow. It keeps `trusted_local_no_auth` as the default local/dev/trusted mode and targets `self_hosted_single_admin` as the first private/self-hosted runtime that needs restart-stable auth state.

## Current Runtime State

Current backend auth state is in memory:

- `AdminSessionStore` keeps a process-local `dict` of `AdminSession` records.
- Session ids are opaque random values.
- Each session carries an in-memory CSRF token.
- Session expiration uses `expires_at = now + INSPECTRA_SESSION_TTL_SECONDS`.
- `get_session` rejects missing/unknown/expired ids and lazily removes expired sessions.
- `invalidate_session` removes the session id on logout.
- The `inspectra_session` cookie is `HttpOnly`, `SameSite=lax`, path `/`, and uses the same max age as the session TTL.
- `LoginAttemptStore` keeps a process-local `dict` of failure records keyed by the backend-observed client host.
- Login attempt settings come from `INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS`, `INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES`, `INSPECTRA_LOGIN_LOCKOUT_SECONDS`, and `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS`.
- Login `429` uses a generic message and safe `Retry-After`.
- The backend does not trust proxy forwarding headers for login client keys today.

Known gaps from the current state:

- Sessions do not survive backend restart.
- Login attempts and soft-lockouts do not survive backend restart.
- Multiple backend processes do not share session or attempt state.
- Cleanup is lazy and process-local.
- Secure-cookie and trusted-proxy runtime enforcement remain separate deployment hardening work.

## Storage Decision

SQLite is the accepted storage backend for the next runtime design/implementation slice.

| Option | Decision | Rationale |
| --- | --- | --- |
| Keep in memory | Rejected for this path | Simple and already implemented, but restart and multiprocess behavior remain weak. |
| Local SQLite file | Accepted | Fits a local-first/self-hosted alpha, uses the Python standard library, requires no external service, can persist across restart, and can be covered with deterministic tests. |
| Redis/external store | Deferred | Adds an external dependency and operational surface that does not fit the current single-admin alpha minimum. |

The SQLite store should be local to the backend data directory, not a remote service. A future implementation can use a path such as `INSPECTRA_AUTH_STATE_DB_PATH` with a conservative default under the existing local data directory, for example `data/runtime/auth_state.sqlite3`.

## Data Model

Proposed tables are intentionally small and auth-specific.

### `auth_sessions`

Suggested fields:

- `session_id_hash`
- `csrf_token_hash`
- `operator_id`
- `auth_mode`
- `created_at`
- `last_seen_at`
- `expires_at`
- `revoked_at`
- `revocation_reason`
- `client_key_hash` optional
- `user_agent_hash` optional

Rules:

- Store hashes of session ids and CSRF tokens, not raw tokens.
- Use constant-time comparison where practical for token verification.
- Keep `operator_id` limited to the current single-admin/local operator shape.
- Treat `revoked_at` as invalid even if `expires_at` is in the future.
- Keep `last_seen_at` for audit/cleanup only in v1; do not introduce sliding sessions unless separately accepted.

### `auth_login_attempts`

Suggested fields:

- `client_key_hash`
- `failure_count`
- `first_failed_at`
- `last_failed_at`
- `locked_until`
- `updated_at`

Rules:

- Preserve current fail-closed lockout semantics.
- Successful login deletes or resets the matching client key.
- Expired records are removed by cleanup.
- Do not store submitted usernames, passwords, password hashes, cookies, CSRF tokens, request bodies, or frontend state.

### `auth_state_metadata`

Optional fields:

- `schema_version`
- `created_at`
- `updated_at`

Rules:

- Use simple idempotent migration/initialization.
- Fail closed in persistent mode if the store cannot be initialized safely.

## Session Semantics

The first persistent implementation should preserve current user-visible semantics:

- Default TTL remains `INSPECTRA_SESSION_TTL_SECONDS`, currently `3600`.
- Sessions use absolute expiration.
- Logout revokes the current session and clears the cookie.
- Expired and revoked sessions are denied.
- CSRF remains session-bound.
- Restart should preserve unexpired, non-revoked sessions only if persistent auth state is enabled.
- In-memory behavior can remain available for local/dev compatibility if explicitly retained.

Sliding expiration is not accepted for v1. It can be revisited later if operator experience requires it and tests cover renewal, idle timeout, and logout race behavior.

## Login Attempt Semantics

The persistent login attempt store should preserve the current rate-limit/backoff contract:

- Failed attempts are counted by a conservative backend-observed client key.
- The first persistent version should not trust `X-Forwarded-For` or other proxy headers.
- A configured trusted-proxy header policy must be a separate design/runtime slice before proxy-derived client keys are used.
- Lockout survives backend restart.
- `Retry-After` remains safe and does not expose counters, thresholds, client keys, password state, or recovery guidance.
- Successful login resets the matching client key.
- Cleanup removes expired windows and completed lockouts.
- Multiple backend processes sharing the same SQLite store should observe the same lockout state.

## Cleanup and Expiration

The runtime slice should include bounded cleanup:

- Purge expired sessions.
- Purge revoked sessions after a short retention window if retention is needed for local audit troubleshooting.
- Purge expired login attempt records.
- Run cleanup opportunistically during login/status/session checks and optionally at startup.
- Keep cleanup local and deterministic; no scheduler is required for the first slice.

## File Placement and Permissions

Recommended implementation constraints:

- Place the auth-state DB under the existing local data area.
- Ensure parent directories are created with restrictive permissions where the platform allows.
- Do not commit the generated database.
- Document backups as sensitive because valid session hashes and lockout metadata are auth state.
- Do not store source uploads, job results, reports, Raw JSON, SBOMs, request bodies, passwords, admin password hashes, cookies, or secrets in the auth-state DB.

## Migration and Compatibility

The implementation should be compatible with current modes:

- `trusted_local_no_auth` does not require persistent auth state.
- `self_hosted_single_admin` is the primary consumer.
- Existing in-memory tests should remain meaningful.
- Persistent-store tests should verify restart behavior by constructing a new store against the same temporary SQLite file.
- Any store initialization failure in auth-required persistent mode should fail closed.
- A future config flag can decide whether persistent state is required or optional, but the default should not silently weaken self-hosted expectations once the feature is accepted.

## No-Scope

- No runtime behavior in this block.
- No backend implementation.
- No frontend implementation.
- No storage migration in this block.
- No Docker execution.
- No Nmap.
- No port scanning.
- No crawling.
- No probes, DNS, or external HTTP.
- No public/community runtime.
- No production-ready claim.
- No SaaS.
- No billing.
- No tenant billing.
- No subscriptions.
- No quotas.
- No paid plans.
- No enterprise tenancy.
- No OAuth/OIDC.
- No multi-user runtime.
- No persistent users table.
- No admin recovery implementation.
- No trusted proxy header runtime behavior.
- No secure-cookie runtime enforcement.
- No release, tag, or push.
- No `.env`, `.env.*`, or `.envrc` reads.

## Test Plan for Future Runtime

Future implementation tests should cover:

- Existing in-memory `AdminSessionStore` behavior remains compatible.
- Persistent session creation stores only hashed session and CSRF material.
- Login returns the same safe response shape and cookie behavior.
- Authenticated `/auth/status` works after a simulated backend restart when session is unexpired.
- Expired sessions fail after restart.
- Logout revokes the session and remains revoked after restart.
- Mutating routes still require the session-bound CSRF token.
- Persistent login failures lock the client key after the configured threshold.
- Lockout survives restart and returns generic `429` with safe `Retry-After`.
- Successful login resets the persistent attempt record.
- Multiple store instances sharing the same SQLite path observe the same lockout state.
- Store cleanup removes expired sessions and attempts.
- Store initialization failure in auth-required persistent mode is controlled and fail-closed.
- Serialized API responses, logs in tests, and frontend state do not expose password material, session ids, CSRF tokens, admin password hashes, cookies, or private config values.
- No frontend `localStorage` or `sessionStorage` auth state is introduced.

## Implementation Microphases

Recommended sequence:

1. `PASSIVE-ALPHA-SQLITE-AUTH-STORE-SCAFFOLD`

   Add an isolated SQLite-backed auth-state store with schema initialization, token hashing helpers, and unit tests. Do not wire it into live auth flow yet.

2. `PASSIVE-ALPHA-PERSISTENT-SESSION-STORE-INTEGRATION`

   Wire persistent sessions into `self_hosted_single_admin` while preserving current route and response contracts.

3. `PASSIVE-ALPHA-PERSISTENT-LOGIN-ATTEMPT-STORE-INTEGRATION`

   Wire persistent login attempts and lockout state into `POST /auth/login`.

4. `PASSIVE-ALPHA-AUTH-STATE-CLEANUP-SMOKE`

   Validate expiration, cleanup, restart behavior, logout invalidation, CSRF, and lockout persistence.

5. `PASSIVE-ALPHA-AUTH-STATE-DOCS-RUNBOOK-UPDATE`

   Update deployment/runbook copy for backup sensitivity, DB path, restart expectations, and remaining non-production boundaries.

## Residual Risks After This Design

- SQLite file permissions and backups need careful operator handling.
- A single local SQLite file is not a distributed auth system.
- Multi-process behavior depends on correct SQLite transaction usage.
- A stolen valid browser cookie can still authenticate until expiration or logout unless other deployment controls reduce exposure.
- Secure-cookie enforcement and trusted proxy behavior remain separate hardening work.
- Admin recovery/setup guidance remains separate work.
- Public/community anti-abuse remains blocked until separate design.

## Next Recommendation

```text
PASSIVE-ALPHA-SQLITE-AUTH-STORE-SCAFFOLD
```

The next block should implement only the isolated SQLite auth-state store and tests. It should not change frontend behavior, add public/community runtime, introduce SaaS/billing concepts, add Nmap/Active behavior, push, tag, or publish a release.
