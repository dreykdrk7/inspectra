# Passive Alpha Persistent Login Attempt Store Design

Status: `PASSIVE_ALPHA_PERSISTENT_LOGIN_ATTEMPT_STORE_DESIGN_ACCEPTED`

Historical note: this docs-first design was implemented by `docs/future/passive-alpha-persistent-login-attempt-store-integration.md`. It remains the design reference for scope and acceptance criteria.

Base auth-state design: `docs/future/passive-alpha-persistent-auth-state-design.md`

SQLite scaffold: `docs/future/passive-alpha-sqlite-auth-store-scaffold.md`

Persistent session integration: `docs/future/passive-alpha-persistent-session-store-integration.md`

Commit scope: documentation-only design for SQLite-backed login-attempt/rate-limit persistence. This block does not change backend runtime behavior, frontend behavior, API responses, cookie/session contracts, deployment behavior, release/tag state, Nmap/Active behavior, or public/community readiness.

## Scope

This block designs how future `self_hosted_single_admin` login-attempt persistence should use the existing `SQLiteAuthStateStore` and its `auth_login_attempts` table. It freezes semantics, cleanup, operator-lockout caveats, test expectations, and no-scope before any live integration.

Explicitly out of scope for this block:

- No runtime changes.
- No frontend changes.
- No API response contract changes.
- No cookie or session contract changes.
- No persistent login-attempt integration yet.
- No SaaS.
- No billing.
- No tenant billing.
- No subscriptions.
- No quotas.
- No paid plans.
- No enterprise tenancy.
- No public/community runtime.
- No OAuth/OIDC.
- No multi-user runtime.
- No Nmap.
- No Active expansion.
- No production-ready claim.
- No `.env`, `.env.*`, or `.envrc` reads.

## Current State Summary

Current live login-attempt/rate-limit behavior is process-local:

- `LoginAttemptStore` stores attempts in an in-memory `dict`.
- Records are keyed by the current client key returned from `login_client_key_for_request`.
- The current client key is `request.client.host` stripped of surrounding whitespace, or `unknown` if unavailable.
- The backend does not trust `X-Forwarded-For`, `X-Forwarded-Proto`, or `Forwarded` for login client keys.
- `INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS` controls the failure window, default `600`.
- `INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES` controls the soft-lock threshold, default `5`.
- `INSPECTRA_LOGIN_LOCKOUT_SECONDS` controls lockout duration, default `900`.
- `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS` bounds process-local retained keys, default `1024`.
- `POST /auth/login` calls `purge_expired()` before checking lockout in `self_hosted_single_admin`.
- Locked client keys receive generic `429` with `Too many attempts. Try again later.`.
- `Retry-After` is calculated from `seconds_until_unlock()` and only emitted when positive.
- Failed login in `self_hosted_single_admin` records a failure after password verification fails.
- Successful login calls `reset_success(client_key)`.
- `trusted_local_no_auth` is not rate-limited.
- `INSPECTRA_AUTH_STATE_STORE=sqlite` currently persists sessions only; login attempts still use `LoginAttemptStore`.

Current limitations:

- Backend restart clears all failed-attempt and lockout state.
- Multiple backend processes do not share attempt state.
- `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS` is process-local and does not bound SQLite rows.
- This is not a public/community anti-abuse system.
- There is no admin recovery or lockout-clear endpoint.

## Design Decision

`PASSIVE_ALPHA_PERSISTENT_LOGIN_ATTEMPT_STORE_DESIGN_ACCEPTED`

Future runtime should accept SQLite-backed login attempts when all of these are true:

- `INSPECTRA_AUTH_STATE_STORE=sqlite`;
- `get_auth_mode(settings) == "self_hosted_single_admin"`;
- the existing SQLite auth-state DB can initialize safely.

Future runtime should keep memory-backed login attempts when:

- `INSPECTRA_AUTH_STATE_STORE=memory`; or
- the app is running in default/local `trusted_local_no_auth`.

This keeps the default local/dev path simple, uses the already accepted local SQLite auth-state file for private self-hosted state, and avoids adding Redis or another external dependency. It also keeps current client-key semantics rather than adding trusted-proxy behavior in the same slice.

Rationale:

- Soft lockout should survive backend restart when persistent auth state is enabled.
- Multiple backend processes using the same SQLite DB path should observe the same lockout state.
- SQLite fits the local-first/self-hosted alpha posture and has no extra service dependency.
- Reusing `INSPECTRA_AUTH_STATE_STORE` keeps sessions and attempts under one explicit auth-state mode.
- Keeping current response contracts avoids leaking credential-validity or counter state.

## Proposed Runtime Behavior For Next Implementation

When `INSPECTRA_AUTH_STATE_STORE=memory`:

- `LoginAttemptStore` remains the live store.
- Current in-memory behavior and tests remain valid.

When `INSPECTRA_AUTH_STATE_STORE=sqlite` and `self_hosted_single_admin`:

- Login attempts use a SQLite-backed adapter around `SQLiteAuthStateStore`.
- The adapter exposes the same methods currently used by `POST /auth/login`: `purge_expired`, `is_locked`, `seconds_until_unlock`, `record_failure`, and `reset_success`.
- Failure counts increment inside the configured window.
- Failure counts reset to `1` after the configured window expires.
- Reaching `INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES` sets `locked_until`.
- `locked_until` persists after backend restart or store recreation.
- Successful login deletes or resets the matching persistent record.
- `429` remains generic.
- `Retry-After` remains safe and derives only from the lockout duration.
- Internal counters, thresholds, client keys, DB paths, and password correctness are not exposed in responses.
- Plain IP/client-key values are not stored; the existing SQLite helper hashes client keys.
- `X-Forwarded-For`, `X-Forwarded-Proto`, and `Forwarded` remain ignored until a separate trusted-proxy design is accepted.

When `trusted_local_no_auth`:

- Persistent login attempts are unnecessary.
- Auth-state SQLite may still be configured, but no login-attempt persistence should be created merely for trusted-local mode.

DB failures:

- In SQLite auth-state mode, initialization failure should remain fail-closed and controlled.
- During login, SQLite operation failure should block login with a controlled server error rather than silently falling back to memory and weakening lockout semantics.
- Error messages must not include client keys, hashes, password material, cookie values, session ids, CSRF tokens, or DB internals beyond a controlled operator-safe message.

## Operator Lockout Caveat

Persistent lockout is useful because it survives restart, but it also changes operator experience:

- A locked operator may remain locked after restarting the backend.
- Inspectra must not reveal whether the password would otherwise have been correct.
- No HTTP bypass endpoint should be added.
- No frontend bypass, `.env` guidance, or retry strategy should be added in this integration.
- Admin recovery remains separate design work.
- For alpha, local operators may need an offline local intervention, such as deleting the auth-state DB or clearing the login-attempt rows manually, but this block does not implement or recommend an app endpoint for that.
- Any future recovery tooling should be local-only, offline, auditable, and separated from the HTTP app.

## Cleanup Semantics

Future SQLite login-attempt cleanup should remove:

- records with completed `locked_until`;
- records without lockout where `last_failed_at + INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS <= now`;
- malformed or incompatible rows only through controlled future migration/repair work, not ad hoc runtime guesses.

Recommended first implementation:

- Run cleanup during `POST /auth/login` before lockout checks, matching current in-memory behavior.
- Optionally run cleanup at app startup after DB initialization.
- Do not add a scheduler in v1.
- Keep cleanup deterministic and bounded.

Growth bounds:

- `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS` currently bounds in-memory records. A SQLite adapter should provide an equivalent row-bound policy or explicit pruning strategy before integration is accepted.
- A practical v1 approach is to run expiry cleanup first, then prune oldest non-locked rows by `updated_at` if row count still exceeds `max_keys`.
- Active lockouts should not be pruned just because the table exceeds `max_keys`, unless their `locked_until` has completed.
- The table must not grow without bound.

## Config Compatibility

Keep current variables:

- `INSPECTRA_AUTH_STATE_STORE`
- `INSPECTRA_AUTH_STATE_DB_PATH`
- `INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS`
- `INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES`
- `INSPECTRA_LOGIN_LOCKOUT_SECONDS`
- `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS`

No new runtime variable is required for the first integration unless tests show that SQLite row pruning needs a separate knob. Prefer reusing `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS` for both memory key count and SQLite row count.

When `INSPECTRA_AUTH_STATE_STORE=sqlite`, the same SQLite DB should hold both `auth_sessions` and `auth_login_attempts`. This makes backups sensitive auth state and keeps session/attempt behavior aligned under one operator decision.

## Security Boundaries

Future implementation must preserve these boundaries:

- Store `client_key_hash`, not raw IPs/client keys.
- Do not store passwords.
- Do not store admin password hashes.
- Do not store usernames beyond current single-admin semantics.
- Do not store request bodies.
- Do not store cookies.
- Do not store session ids.
- Do not store CSRF tokens in login-attempt rows.
- Do not store uploaded files, job data, reports, Raw JSON, SBOMs, or target histories.
- Do not log raw client keys or client-key hashes.
- Do not trust proxy headers until trusted-proxy runtime policy exists.
- SQLite local persistence does not protect against a compromised host.
- SQLite login-attempt persistence is not sufficient public/community anti-abuse.

## Test Plan For Next Implementation

Future runtime tests should cover:

- Memory mode preserves current login-attempt behavior.
- SQLite mode records a failed attempt in `auth_login_attempts`.
- Failure count increments inside the configured window.
- Failure count resets outside the configured window.
- Threshold creates `locked_until`.
- Generic `429` is preserved.
- Safe `Retry-After` is preserved.
- Lockout persists after recreating app state or the attempt store with the same DB path.
- Successful login deletes or resets the persistent record.
- Two app/store instances with the same DB path share lockout state.
- Raw client key does not appear in the DB bytes.
- Password and admin password hash do not appear in the DB bytes.
- `X-Forwarded-For`, `X-Forwarded-Proto`, and `Forwarded` do not influence the client key.
- Cleanup removes expired windows and completed lockouts.
- SQLite row pruning respects `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS` or a documented equivalent.
- DB initialization failure in SQLite auth-state mode fails closed and controlled.
- Existing SQLite session behavior remains working.
- Frontend behavior remains unchanged.
- No browser `localStorage` or `sessionStorage` auth state appears.
- API responses do not expose counters, thresholds, client keys, hashes, DB paths, or recovery guidance.

## Implementation Recommendation

Recommended next microfase:

```text
PASSIVE-ALPHA-PERSISTENT-LOGIN-ATTEMPT-STORE-INTEGRATION
```

That block should implement:

- a SQLite adapter/wrapper with the `LoginAttemptStore` method surface used by `POST /auth/login`;
- conditional wiring when `INSPECTRA_AUTH_STATE_STORE=sqlite` and `self_hosted_single_admin`;
- reuse of existing login-attempt settings;
- restart and multiprocess-style tests using the same temporary DB path;
- tests proving raw client keys/passwords/hashes are not persisted;
- minimal docs alignment.

Recommended follow-up after integration:

```text
PASSIVE-ALPHA-AUTH-STATE-CLEANUP-ROTATION
```

That later block should design broader cleanup, rotation, retention, offline recovery, and operator runbook guidance across sessions and login attempts.

## Residual Gaps After Design

- Persistent login-attempt integration is not implemented yet.
- Admin recovery remains pending.
- General auth-state cleanup/rotation remains pending.
- Secure-cookie runtime enforcement remains pending.
- Trusted proxy runtime enforcement remains pending.
- Public/community anti-abuse remains pending.
- Release/tag/push remains pending.

## Final Decision

`PASSIVE_ALPHA_PERSISTENT_LOGIN_ATTEMPT_STORE_DESIGN_ACCEPTED`

SQLite-backed login-attempt persistence is accepted as the next runtime direction for private `self_hosted_single_admin` when `INSPECTRA_AUTH_STATE_STORE=sqlite`. The design preserves memory defaults, current client-key semantics, current `429`/`Retry-After` contracts, and explicit non-SaaS/non-public boundaries.
