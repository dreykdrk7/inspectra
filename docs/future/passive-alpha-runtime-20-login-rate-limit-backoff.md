# Passive Alpha Runtime 20 Login Rate Limit Backoff

Status: `PASSIVE_ALPHA_RUNTIME_LOGIN_RATE_LIMIT_BACKOFF_ACCEPTED`.

Base login-attempt store: `docs/future/passive-alpha-runtime-19-login-attempt-store.md`

Base rate-limit/lockout plan: `docs/future/passive-alpha-runtime-18-rate-limit-lockout-plan.md`

Base self-hosted auth closeout: `docs/future/passive-alpha-runtime-17-self-hosted-auth-closeout.md`

Commit scope: backend-only login rate-limit enforcement for `self_hosted_single_admin`, focused tests, full backend regression, and documentation alignment. This block does not change frontend runtime, add frontend rate-limit copy, add persistent storage, add admin recovery, add multi-user auth, add public/community runtime, add Active behavior, add Nmap behavior, or add billing/SaaS/quota behavior.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_LOGIN_RATE_LIMIT_BACKOFF_ACCEPTED
```

Inspectra now wires the Runtime-19 `LoginAttemptStore` into `POST /auth/login` for `self_hosted_single_admin`. Failed login attempts are tracked by backend-observed client key, temporary soft lockout is enforced after the configured threshold, and locked requests receive a generic `429` response.

`trusted_local_no_auth` remains unaffected.

## Implemented

- Backend helper for login client key extraction.
- `POST /auth/login` purge/check/record/reset flow.
- Generic `429 Too Many Requests` response for locked client keys.
- Safe `Retry-After` header with remaining lockout seconds.
- Focused backend tests for threshold, lockout, expiry, reset, X-Forwarded-For handling, generic failures, and trusted-local compatibility.

## Client Key Behavior

The initial client key uses:

```text
request.client.host
```

If the request client is absent or blank, the key falls back to:

```text
unknown
```

The backend does not trust `X-Forwarded-For` by default and does not expose the client key in public responses. Trusted proxy header handling remains future deployment design.

## Login Enforcement Behavior

For `self_hosted_single_admin`:

1. Expired attempt records are purged.
2. The current client key is checked for soft lockout before password verification.
3. Locked requests receive `429` and do not create sessions.
4. Failed login attempts record a failure and return the existing generic credential error.
5. Successful login resets the attempt record for the client key and then creates the existing admin session.

Wrong password, missing hash, unsupported hash, unsupported username, and other self-hosted login failures remain generic. The failure that reaches the threshold still returns the normal generic `401`; following attempts during the lockout window receive `429`.

## Response Behavior

Invalid credentials continue to return:

```json
{"detail": "Invalid credentials."}
```

Locked/rate-limited requests return:

```json
{"detail": "Too many attempts. Try again later."}
```

The locked response uses `429 Too Many Requests` and includes `Retry-After` when remaining lockout seconds are available.

Responses do not include counters, thresholds, client keys, password/hash state, config values, lockout internals, recovery instructions, or bypass guidance.

## Soft Lockout Behavior

- Lockout is temporary.
- Lockout is scoped to the client key.
- Lockout state is in memory only.
- Backend restart clears attempt state.
- No permanent account lockout is implemented.
- No admin account disablement is implemented.
- No public recovery or bypass endpoint is implemented.

## Not Implemented

- No frontend rate-limit copy.
- No persistent DB/storage.
- No admin recovery.
- No multi-user runtime.
- No OAuth/OIDC.
- No public/community anti-abuse runtime.
- No global API rate limiting.
- No trusted proxy header mode.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No Active expansion.
- No Nmap.
- No Docker execution.
- No probes, DNS, external HTTP, port scanning, or live target traffic.
- No `.env`, `.env.*`, or `.envrc` reads.

## Tests

Focused tests cover:

- failed attempts increment and trigger later `429`;
- configured threshold and lockout values are honored;
- locked client receives `429` before a correct password can create a session;
- lockout expires and a correct password can log in afterward;
- successful login resets the failure counter;
- missing hash, unsupported hash, wrong password, and unsupported username remain generic and count where appropriate;
- `Retry-After` is present and safe;
- responses do not expose counters, client keys, password, hash, thresholds, or config details;
- `X-Forwarded-For` is ignored by default;
- `trusted_local_no_auth` remains unaffected;
- `/auth/status` remains unaffected;
- existing auth, CSRF, owner, and backend tests pass.

Reference validation commands:

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "attempt or rate or lockout or login or logout or session or cookie or auth_status or csrf"
.venv/bin/python -m pytest backend/tests/test_backend.py
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend runtime.

## Residual Risks

- In-memory state is lost on backend restart.
- Multiple backend processes do not share attempt state.
- Reverse proxy topology can collapse multiple operators into one backend-observed client key.
- Trusted proxy header handling remains future work.
- Distributed attacks across many client keys remain out of scope for this first self-hosted control.
- Frontend-specific rate-limit copy is still pending.
- Public/community anti-abuse requires separate design and controls.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-21-FRONTEND-RATE-LIMIT-COPY
```

Runtime-21 should add controlled frontend copy for `429` login responses without exposing counters, lockout internals, client keys, config values, recovery instructions, or bypass guidance.

Runtime-21 is now accepted in `docs/future/passive-alpha-runtime-21-frontend-rate-limit-copy.md` with final decision `PASSIVE_ALPHA_RUNTIME_FRONTEND_RATE_LIMIT_COPY_ACCEPTED`.
