# Passive Alpha Runtime 19 Login Attempt Store

Status: `PASSIVE_ALPHA_RUNTIME_LOGIN_ATTEMPT_STORE_ACCEPTED`.

Base rate-limit/lockout plan: `docs/future/passive-alpha-runtime-18-rate-limit-lockout-plan.md`

Base self-hosted auth closeout: `docs/future/passive-alpha-runtime-17-self-hosted-auth-closeout.md`

Base login/logout endpoints: `docs/future/passive-alpha-runtime-13-login-logout-endpoints.md`

Commit scope: backend-only isolated login-attempt store, configuration, focused tests, and documentation alignment. This block does not wire enforcement into `POST /auth/login`, change login responses, add frontend copy, add persistent storage, add admin recovery, add multi-user auth, add public/community runtime, add Active behavior, add Nmap behavior, or add billing/SaaS/quota behavior.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_LOGIN_ATTEMPT_STORE_ACCEPTED
```

Inspectra now has an isolated in-memory `LoginAttemptStore` for future `self_hosted_single_admin` login throttling work. The store can record failed attempts by caller-provided client key, calculate soft temporary lockout state, report remaining lockout seconds, reset state after success, purge expired records, and bound retained client keys.

The store is initialized on app state for future use, but it is intentionally not connected to `POST /auth/login` yet. Runtime-20 should wire enforcement and generic `429` behavior.

## Implemented

- `LoginAttemptRecord` in `backend/app/auth.py`.
- `LoginAttemptStore` in `backend/app/auth.py`.
- Positive integer configuration in `backend/app/config.py`.
- `app.state.login_attempts` initialization in `backend/app/main.py`.
- Focused backend tests for store behavior, config defaults/validation, and current login behavior.

## Config Added

Defaults are based on Runtime-18:

- `INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS`: default `600`.
- `INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES`: default `5`.
- `INSPECTRA_LOGIN_LOCKOUT_SECONDS`: default `900`.
- `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS`: default `1024`.

All values must be positive integers. Invalid values fail during settings load using the existing controlled `ValueError` config pattern.

These settings are security controls for self-hosted/local/private/community hardening. They are not billing quotas, account quotas, paid-plan limits, commercial tenant controls, or SaaS metering.

## Store Behavior

The store:

- accepts a string `client_key` from its caller;
- normalizes blank or non-string client keys to `unknown`;
- records failed attempts inside a bounded time window;
- soft-locks a client key when failures reach the configured threshold;
- reports lockout state through `is_locked(client_key)`;
- reports seconds remaining through `seconds_until_unlock(client_key)`;
- clears state through `reset_success(client_key)`;
- purges expired unlocked or expired locked records through `purge_expired()`;
- evicts oldest records when retained keys exceed `max_keys`;
- stores only client key and timing/count metadata.

The current slice does not extract the client key from a real request. Future integration should use the backend-observed request client address and should not trust `X-Forwarded-For` by default.

## Soft Lockout Semantics

- Lockout is temporary.
- Lockout is scoped to the client key.
- Lockout state is in memory only.
- Backend restart clears attempt state.
- No permanent account lockout is implemented.
- No admin account disablement is implemented.
- No public recovery or bypass endpoint is implemented.

This keeps the first hardening step self-hosted-friendly and avoids irreversible operator lockout.

## Not Implemented

- No enforcement in `POST /auth/login`.
- No changed login responses.
- No `429 Too Many Requests` behavior.
- No effective backoff/cooldown route behavior.
- No frontend rate-limit copy.
- No persistent DB/storage.
- No admin recovery.
- No multi-user runtime.
- No OAuth/OIDC.
- No public/community runtime.
- No global API rate limiting.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No Active expansion.
- No Nmap.
- No Docker execution.
- No probes, DNS, external HTTP, port scanning, or live target traffic.
- No `.env`, `.env.*`, or `.envrc` reads.

## Tests

Focused tests cover:

- store starts unlocked;
- failures increment counters;
- threshold activates soft lockout;
- lockout expires and clears state;
- successful reset clears counter/lockout state;
- purge removes expired records;
- max keys bounds retained records;
- store metadata does not include password/hash/session/cookie/CSRF material;
- config defaults and env overrides;
- invalid config values fail with controlled settings errors;
- current `POST /auth/login` behavior remains unchanged because the store is not integrated.

Reference validation commands:

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "attempt or rate or lockout or login or auth_status or auth_mode"
.venv/bin/python -m pytest backend/tests/test_backend.py
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend code.

## Residual Risks

- The store does not protect login until Runtime-20 wires enforcement.
- In-memory state is lost on backend restart.
- Multiple backend processes would not share attempt state.
- Client key extraction behind reverse proxies remains pending.
- Distributed attacks across many client keys remain out of scope for this first self-hosted hardening slice.
- Public/community anti-abuse still requires separate design and controls.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-20-LOGIN-RATE-LIMIT-BACKOFF
```

Runtime-20 should wire the attempt store into `POST /auth/login`, preserve generic failures, add temporary `429`/cooldown behavior, avoid detailed public counters or bypass guidance, and keep `trusted_local_no_auth` unaffected.

## Successor Status

```text
PASSIVE_ALPHA_RUNTIME_LOGIN_RATE_LIMIT_BACKOFF_ACCEPTED
```

Runtime-20 now wires the attempt store into `POST /auth/login` for `self_hosted_single_admin`, preserves generic invalid-credential failures, adds temporary generic `429` lockout behavior with safe `Retry-After`, and keeps `trusted_local_no_auth` unaffected. Runtime-19 remains the historical isolated store slice.
