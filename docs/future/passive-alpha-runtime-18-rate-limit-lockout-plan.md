# Passive Alpha Runtime 18 Rate Limit Lockout Plan

Status: `PASSIVE_ALPHA_RATE_LIMIT_LOCKOUT_PLAN_ACCEPTED`.

Base self-hosted auth closeout: `docs/future/passive-alpha-runtime-17-self-hosted-auth-closeout.md`

Base auth flow smoke: `docs/future/passive-alpha-runtime-16-auth-flow-smoke.md`

Base frontend auth UX: `docs/future/passive-alpha-runtime-15-frontend-auth-status-login-ux.md`

Base login/logout endpoints: `docs/future/passive-alpha-runtime-13-login-logout-endpoints.md`

Base login/session plan: `docs/future/passive-alpha-runtime-10-single-admin-login-session-plan.md`

Commit scope: documentation-only policy plan for future login rate limiting, backoff, and lockout. This block does not implement backend runtime, frontend runtime, tests, fixtures, persistent storage, admin recovery, Active behavior, Nmap behavior, public/community runtime, or billing/SaaS/tenant behavior.

## Final Decision

```text
PASSIVE_ALPHA_RATE_LIMIT_LOCKOUT_PLAN_ACCEPTED
```

Inspectra should add bounded, self-hosted-friendly login throttling for `self_hosted_single_admin` in later runtime slices. The policy should reduce brute-force risk without creating an irreversible lockout path for local/self-hosted operators.

This is docs-first only. It defines threat model, policy, caveats, future tests, and implementation sequencing. It does not implement rate limiting, backoff, lockout, persistent storage, admin recovery, multi-user auth, OAuth/OIDC, public/community runtime, Active expansion, Nmap, or SaaS/billing/quota behavior.

## Objective

Runtime-17 closed the current self-hosted single-admin auth flow as usable for Passive Alpha. Runtime-18 defines the next hardening layer: rate limiting, backoff, and soft lockout for `POST /auth/login`.

The goal is to:

- slow password guessing;
- preserve generic login failures;
- avoid leaking whether a hash is missing, unsupported, or wrong;
- avoid irreversible operator lockout;
- keep trusted-local mode unaffected;
- keep the design local-first and self-hosted-first.

## Threat Model

This plan addresses:

- brute force against `POST /auth/login`;
- guessing the single-admin password;
- flooding login requests to consume resources or create noisy logs;
- lockout abuse where an attacker tries to deny the legitimate operator access;
- accidental sensitive log exposure around passwords, hashes, CSRF tokens, cookies, IPs, or user agents;
- exposed self-hosted instances without proper TLS/reverse proxy hardening;
- future public/community abuse that would require stronger, separate controls.

This plan does not claim to solve:

- compromised admin password recovery;
- stolen cookie/session protection beyond existing session/CSRF behavior;
- distributed credential attacks across many IPs;
- production-grade WAF or reverse-proxy controls;
- public/community anti-abuse at scale.

## Design Principles

- Keep failures generic.
- Do not distinguish wrong password, missing hash, unsupported hash, disabled auth, unsupported username, rate-limited state, or internal auth configuration through detailed public responses.
- Do not log passwords, password hashes, CSRF tokens, session ids, cookie values, or raw Authorization-like values.
- Protect against repeated guesses with bounded attempt tracking.
- Prefer soft, time-bound lockout over permanent account lockout.
- Avoid irreversible lockout for self-hosted operators.
- Provide a future recovery path that is local/operator-controlled.
- Leave `trusted_local_no_auth` unaffected.
- Do not turn limits into billing, quota, paid-plan, tenant, or SaaS concepts.

## Initial Scope

P0 should apply only to:

- `POST /auth/login`;
- `self_hosted_single_admin`.

P0 should not apply yet to:

- `trusted_local_no_auth`;
- multi-user auth;
- OAuth/OIDC;
- public/community runtime;
- target-based audit flows;
- passive archive analysis;
- Active dry-run or limited live header-probe creation;
- global API rate limiting;
- billing/quota/account enforcement.

## Rate Limit Model

Recommended first implementation:

- Use an in-memory login-attempt store.
- Track failures by a conservative client key.
- Initial client key: request client IP as seen by the backend.
- Optionally combine the client key with a fixed `single-admin` label, not a user-supplied username.
- Use a sliding or fixed time window.
- Count only failed login attempts.
- Reset or substantially decay the failure counter after a successful login from the same client key.
- Keep counters out of public responses, reports, exports, Raw JSON, and frontend state.

Proposed starting defaults for future implementation:

- soft threshold: 5 failed attempts per 10 minutes per client key;
- temporary lockout/cooldown: 15 minutes per client key after threshold;
- maximum retained attempt records: bounded by time and size, with oldest records evicted;
- reset on backend restart in the first in-memory slice.

These defaults are intentionally conservative placeholders for implementation review. They are not billing quotas, account quotas, paid-plan limits, or SaaS tenant controls.

## Backoff Model

Recommended behavior:

- Do not use long blocking sleeps inside request handlers.
- After a small number of failures, either:
  - deny quickly once a threshold is reached; or
  - apply a short bounded delay if implementation can do so without tying up worker capacity.
- Prefer temporary cooldown denial after threshold over increasingly long blocking sleeps.
- Optionally include `Retry-After` for the lockout window if the response is otherwise safe and generic.
- Keep response bodies generic.

Pros of cooldown denial:

- simple to reason about;
- avoids tying up server workers;
- easier to test deterministically;
- safer for a small self-hosted app.

Cons:

- legitimate operators behind the same client key can be temporarily blocked;
- distributed attackers can rotate client keys;
- reverse proxy misconfiguration can collapse many users into one client key.

## Lockout Model

Recommended P0 lockout:

- soft lockout only;
- temporary duration only;
- scoped by client key;
- no permanent account lockout;
- no destructive or irreversible state;
- no admin account disablement;
- no secret reset through public endpoints.

Do not implement permanent single-admin lockout in P0. A permanent lockout can create a self-hosted denial-of-service footgun where an attacker or misconfigured automation prevents the real operator from using their own instance.

Possible future emergency brake:

- a temporary process-local global brake after severe repeated failures;
- disabled by default unless a clear operator recovery path exists;
- documented with local-only recovery and no public bypass guidance.

## Storage Plan

Recommended first slice:

- in-memory attempt store in the backend process;
- bounded by time window and maximum key count;
- no persistent DB requirement;
- restart clears counters as an acceptable self-hosted P0 tradeoff;
- minimal structured logs with redacted/generic event fields only.

Future storage may add:

- persistent attempt metadata;
- cross-process coordination;
- admin-visible local-only diagnostics;
- explicit recovery tooling.

Persistent storage should not be introduced until recovery, privacy, retention, and cleanup semantics are designed.

## Reverse Proxy And IP Caveats

The initial client key should use the backend's request client address.

Caveats:

- In deployments behind a reverse proxy, the backend may see only the proxy IP.
- Do not trust `X-Forwarded-For` by default.
- Trusted proxy headers should be accepted only after a separate explicit trusted-proxy configuration design.
- Deployment docs should explain how proxy topology affects rate limiting.
- Public/community deployments need stronger anti-abuse controls than this self-hosted P0 plan.

## Response Behavior

Recommended public response behavior:

- wrong password: generic invalid credentials;
- missing hash: generic invalid credentials;
- unsupported hash: generic invalid credentials;
- unsupported username: generic invalid credentials;
- rate-limited or soft-locked: generic `Too many attempts. Try again later.`;
- optional `Retry-After` header for the cooldown duration;
- no counter values;
- no hash/config state;
- no client key;
- no lockout internals;
- no bypass or recovery instructions in public responses.

The login endpoint may use a distinct `429 Too Many Requests` status for rate-limited/locked state. If used, the body should remain controlled and generic.

## Frontend Behavior Future

Future frontend behavior should:

- keep the password-only login gate;
- keep password clearing after submit;
- display generic login failure for normal auth failures;
- display `Too many attempts. Try again later.` for backend rate-limit responses;
- avoid exact counters, lockout internals, hash/config state, IP/client key, and recovery instructions;
- keep password, session, cookie, and CSRF values out of DOM, URL, Raw JSON, local storage, and session storage;
- not add multi-user, OAuth/OIDC, public/community, SaaS, billing, or quota UI concepts.

This plan does not implement frontend changes.

## Future Tests

Minimum backend tests for implementation:

- failed login attempts increment the in-memory counter;
- threshold blocks further login attempts for the same client key;
- correct password during soft lockout is denied until lockout expires;
- soft lockout expires after the configured cooldown;
- successful login before lockout resets or decays the failure counter;
- missing hash, unsupported hash, wrong password, and unsupported username remain generic;
- no password/hash/session/cookie/CSRF values appear in logs, responses, or stored state;
- `trusted_local_no_auth` remains unaffected;
- `GET /auth/status` remains public-safe and unaffected by login attempt counters;
- reverse proxy headers are ignored unless a later trusted-proxy mode is explicitly implemented;
- focused auth tests pass;
- full backend tests pass.

Future frontend tests:

- login rate-limit response shows controlled copy;
- exact counters are not shown;
- config/recovery/bypass guidance is not shown;
- password remains cleared and not rendered;
- trusted-local flow remains unchanged.

## Implementation Slices

Recommended future slices:

1. `PASSIVE-ALPHA-RUNTIME-19-LOGIN-ATTEMPT-STORE`
   - Add an isolated in-memory attempt store, config defaults, and unit tests.
   - Do not wire enforcement broadly until behavior is tested in isolation.
2. `PASSIVE-ALPHA-RUNTIME-20-LOGIN-RATE-LIMIT-BACKOFF`
   - Wire the attempt store into `POST /auth/login`.
   - Add generic `429`/cooldown behavior, focused backend tests, and full backend regression.
3. `PASSIVE-ALPHA-RUNTIME-21-FRONTEND-RATE-LIMIT-COPY`
   - Add controlled frontend copy for rate-limited login responses.
   - Preserve password clearing and no-storage behavior.
4. `PASSIVE-ALPHA-RUNTIME-22-AUTH-HARDENING-SMOKE`
   - Smoke the complete auth hardening flow across backend and frontend.
   - Reconfirm no `.env`, no network probes, no Docker, no Nmap, no SaaS/billing semantics.

Recommended next slice:

```text
PASSIVE-ALPHA-RUNTIME-19-LOGIN-ATTEMPT-STORE
```

## Successor Status

```text
PASSIVE_ALPHA_RUNTIME_LOGIN_ATTEMPT_STORE_ACCEPTED
```

Runtime-19 now implements the isolated in-memory login-attempt store, config, and tests recommended by this plan. Enforcement in `POST /auth/login`, generic `429`/cooldown behavior, frontend copy, and auth-hardening smoke remain future slices.

```text
PASSIVE_ALPHA_RUNTIME_LOGIN_RATE_LIMIT_BACKOFF_ACCEPTED
```

Runtime-20 now wires the attempt store into `POST /auth/login` for `self_hosted_single_admin`, adds generic temporary `429` lockout behavior with safe `Retry-After`, and keeps `trusted_local_no_auth` unaffected. Frontend rate-limit copy and auth-hardening smoke remain future slices.

## No-Scope Preserved

- No code changes.
- No backend changes.
- No frontend changes.
- No runner changes.
- No tests or fixture changes.
- No rate limiting implementation.
- No backoff implementation.
- No lockout implementation.
- No persistent DB/storage implementation.
- No admin recovery implementation.
- No multi-user runtime.
- No OAuth/OIDC.
- No public/community runtime.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No Active expansion.
- No Nmap.
- No Docker execution.
- No probes, DNS, external HTTP, port scanning, or live target traffic.
- No `.env`, `.env.*`, or `.envrc` reads.

## Acceptance Criteria

- Threat model is defined.
- Rate limit policy is defined.
- Backoff/cooldown policy is defined.
- Lockout is explicitly soft and not irreversible.
- Recovery and reverse-proxy caveats are documented.
- Future tests are defined.
- Implementation slices are defined.
- Runtime behavior is unchanged in this docs-first block.
