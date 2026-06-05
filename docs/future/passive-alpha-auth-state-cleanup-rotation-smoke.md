# Passive Alpha Auth State Cleanup Rotation Smoke

Status: `PASSIVE_ALPHA_AUTH_STATE_CLEANUP_ROTATION_SMOKE_PASSED`

Base design: `docs/future/passive-alpha-auth-state-cleanup-rotation-design.md`

Persistent session integration: `docs/future/passive-alpha-persistent-session-store-integration.md`

Persistent login-attempt integration: `docs/future/passive-alpha-persistent-login-attempt-store-integration.md`

Commit scope: smoke/tests/docs for existing SQLite auth-state cleanup, pruning, revocation, expiration, restart/store recreation, redaction, and auth-contract behavior. This block does not add frontend runtime, API/cookie/session/CSRF contract changes, admin recovery, trusted-proxy runtime behavior, secure-cookie runtime enforcement, public/community runtime, SaaS/billing/quota behavior, Nmap, Active expansion, release/tag state, or new dependencies.

## Scope

This smoke validates the current SQLite auth-state behavior after persistent sessions and persistent login-attempt lockouts were integrated for private `self_hosted_single_admin` mode.

Explicitly out of scope:

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
- No Docker execution.
- No Nmap.
- No Active expansion.
- No probes, DNS, external HTTP, or network traffic.
- No release, tag, push, or GitHub release.
- No `.env`, `.env.*`, or `.envrc` reads.

## Coverage Validated

### Sessions

Validated:

- Expired SQLite sessions are invalid.
- Revoked SQLite sessions are invalid immediately.
- Store recreation with the same DB path preserves valid unexpired, non-revoked sessions.
- Store recreation rejects expired or revoked sessions.
- CSRF hashes can be verified after store recreation.
- If `/auth/status` emits a fresh CSRF token after store recreation, only the hash is persisted.
- Cleanup removes expired session rows.
- Cleanup removes revoked sessions after the configured retention window.
- Recently revoked session rows can be retained for a short window while remaining invalid.
- Active/unexpired/non-revoked sessions are not deleted by cleanup.
- Logout clears the cookie and revokes the persisted session.
- Mutating routes still require CSRF.
- Owner-scoped sensitive routes remain protected.

### Login Attempts

Validated:

- Attempts outside the configured window are cleaned.
- Completed lockouts are cleaned.
- Active lockouts survive store/app recreation.
- Active lockouts are not pruned solely because `INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS` row pressure exists.
- Non-locked rows are pruned by the configured max-key bound.
- Successful login resets the persistent attempt record.
- Two store instances using the same DB path share lockout state.
- Forwarded headers do not influence the login client key or rate-limit state.

### Redaction And DB Bytes

Validated that SQLite DB bytes do not contain:

- raw session ids;
- raw CSRF tokens;
- raw client keys;
- submitted password fixture values;
- admin password hashes;
- spoofed forwarded-header IP values.

The DB stores hashed session, CSRF, and client-key material rather than raw auth tokens or raw client keys.

### Auth Contracts

Validated preserved contracts:

- `POST /auth/login` success shape remains stable.
- Invalid login remains generic `401`.
- Lockout remains generic `429`.
- `Retry-After` remains present and positive when lockout applies.
- `/auth/logout` clears the cookie and revokes the session.
- `/auth/status` remains safe and only exposes CSRF for an authenticated session.
- `trusted_local_no_auth` does not depend on the SQLite auth-state DB.
- No browser `localStorage` or `sessionStorage` auth state appears.

## Tests Executed

Reference validation commands for this smoke:

```text
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "auth_state or sqlite or session or csrf or login or logout or auth_status or rate or lockout or attempt or cleanup or rotation"
.venv/bin/python -m pytest backend/tests/test_backend.py
rg -n "localStorage|sessionStorage" frontend/src backend/app backend/tests
rg -n "Nmap|port scan|crawler|credential valid|vulnerability confirmed|exploitability confirmed|safe target|production ready|SaaS|billing|tenant billing|subscription|quota|paid plan" README.md docs/architecture.md docs/security-scope.md docs/future/passive-alpha-*.md frontend/src backend/app backend/tests
git diff --check
git diff --cached --check
git status --short
git status --branch --short
```

The broad text search is expected to return no-scope/test-copy hits where docs and tests explicitly reject Nmap, port scanning, production readiness, SaaS/billing, credential-validation, and confirmed-vulnerability claims.

## No-Scope Preserved

- No frontend runtime changed.
- No admin recovery was added.
- No trusted-proxy runtime behavior was added.
- No secure-cookie runtime enforcement was added.
- No public/community anti-abuse system was added.
- No API/cookie/session/CSRF contracts changed.
- No Docker, Nmap, probes, DNS, or external traffic was used.
- No release, tag, push, or GitHub release was created.

## Residual Gaps

- Admin recovery/setup guidance remains pending.
- Secure-cookie runtime enforcement remains pending.
- Trusted-proxy runtime enforcement remains pending.
- Public/community anti-abuse remains pending.
- Session/key rotation remains pending.
- Local/offline operator tooling remains pending.
- Release/tag/push remains pending.

## Decision

`PASSIVE_ALPHA_AUTH_STATE_CLEANUP_ROTATION_SMOKE_PASSED`

The existing SQLite auth-state cleanup, revocation, expiration, pruning, restart, and redaction behavior is coherent enough to proceed to Pathing C closeout. This smoke does not approve production/public/community use and does not add recovery or deployment-hardening runtime.

## Next Recommendation

```text
PASSIVE-ALPHA-PERSISTENT-AUTH-CLOSEOUT
```

The next block should close the persistent auth-state line across design, scaffold, session integration, login-attempt integration, and cleanup/rotation smoke before release-candidate checklist work.
