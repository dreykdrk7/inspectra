# Passive Alpha Runtime 21 Frontend Rate Limit Copy

Status: `PASSIVE_ALPHA_RUNTIME_FRONTEND_RATE_LIMIT_COPY_ACCEPTED`.

Base login rate-limit/backoff runtime: `docs/future/passive-alpha-runtime-20-login-rate-limit-backoff.md`

Base frontend auth UX: `docs/future/passive-alpha-runtime-15-frontend-auth-status-login-ux.md`

Commit scope: frontend login `429` copy, focused frontend tests, backend contract validation, and minimal documentation alignment. This block does not change backend rate-limit logic, add persistent storage, add admin recovery, add multi-user auth, add OAuth/OIDC, add public/community runtime, add Active behavior, add Nmap behavior, or add billing/SaaS/quota behavior.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_FRONTEND_RATE_LIMIT_COPY_ACCEPTED
```

Inspectra now distinguishes login rate-limit responses in the frontend while preserving generic credential failures for normal invalid-login cases.

The work keeps Inspectra open-source, altruistic, local-first, and self-hosted-first. Login rate limiting and frontend cooldown copy are self-hosted safety controls, not SaaS quotas, billing plans, paid tiers, tenant limits, or enterprise multi-tenant behavior.

## Implemented

- The login submit handler now recognizes `429 Too Many Requests` from `POST /auth/login`.
- Login `429` renders the controlled message:

```text
Too many attempts. Try again later.
```

- Login `401` and other login failures continue to render the generic message:

```text
Invalid credentials.
```

- The password input is cleared immediately after submit before either response is handled.
- Auth state is not promoted to authenticated after `429`.
- CSRF state is not changed after `429`.
- No frontend `localStorage` or `sessionStorage` storage was introduced.

## Login 401 Behavior

Invalid credentials, missing hash, unsupported hash, unsupported username, and other self-hosted login failures remain indistinguishable to the frontend. The UI shows only generic credential copy and does not expose password/hash/config state.

## Login 429 Behavior

Locked or rate-limited login attempts receive controlled cooldown copy. The UI does not show counters, thresholds, backend-observed client keys, lockout internals, config values, recovery instructions, or bypass guidance.

The message is intentionally short so it can be used safely across local, self-hosted, private/internal, and future community contexts without revealing rate-limit policy details.

## Retry-After Behavior

The backend may include a safe `Retry-After` header on locked responses. Runtime-21 does not render the header value in the UI. The frontend keeps qualitative copy only:

```text
Too many attempts. Try again later.
```

This avoids exposing cooldown seconds as a visible policy detail and keeps the UI stable if the header is absent, malformed, or changed later.

## Not Exposed

- No counters.
- No thresholds.
- No client key or IP/client identity wording.
- No password hash or config state.
- No lockout internals.
- No `.env` guidance.
- No recovery instructions.
- No bypass guidance.
- No session cookie or CSRF token values.

## Tests

Focused frontend tests cover:

- login `429` shows controlled rate-limit copy;
- login `429` clears the password;
- login `429` does not render the submitted password, `Retry-After`, cooldown seconds, client-key wording, threshold wording, recovery/bypass wording, or `.env` guidance;
- login `401` still shows generic credential failure;
- successful login still refreshes auth status, hides the login gate, and clears the password;
- trusted-local mode still avoids the login gate.

Focused backend validation confirms the existing `self_hosted_single_admin` login/rate-limit contract remains intact.

Reference validation commands:

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "rate or lockout or login or auth_status"
npm run test -- --run App
npm run test -- --run
npm run build
rg -n "localStorage|sessionStorage" frontend/src backend/app backend/tests
git diff --check
git diff --cached --check
git status --short
```

No Docker, external probes, DNS, external HTTP, Nmap, port scanning, live target traffic, tags, releases, or pushes are required for this block.

## Not Implemented

- No backend rate-limit logic changes.
- No new rate-limit rules.
- No persistent attempt storage.
- No admin recovery.
- No global API rate limiting UI.
- No multi-user runtime.
- No OAuth/OIDC.
- No public/community anti-abuse runtime.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No Active expansion.
- No Nmap.
- No Docker execution.
- No probes, DNS, external HTTP, port scanning, or live target traffic.

## Residual Risks

- Login attempt state remains in memory and is lost on backend restart.
- Multiple backend processes do not share attempt state.
- Reverse proxy topology can collapse multiple operators into one backend-observed client key.
- Trusted proxy header handling remains future work.
- Distributed attacks across many client keys remain out of scope for this first self-hosted control.
- Public/community anti-abuse still requires separate design and controls.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-22-AUTH-HARDENING-SMOKE
```

Runtime-22 should smoke the self-hosted auth hardening line end to end: login/logout/session/CSRF, owner-scoped sensitive routes, backend rate-limit `429`, frontend controlled rate-limit copy, no browser storage for auth state, and no public/community or Active expansion.
