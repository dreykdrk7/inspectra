# Passive Alpha Runtime 11 Password Verify Helper

Status: `PASSIVE_ALPHA_RUNTIME_PASSWORD_VERIFY_HELPER_ACCEPTED`.

Base Runtime-10 login/session plan: `docs/future/passive-alpha-runtime-10-single-admin-login-session-plan.md`

Base Runtime-09 closeout: `docs/future/passive-alpha-runtime-09-runtime-p0-closeout.md`

Base Runtime-02 auth-status skeleton: `docs/future/passive-alpha-runtime-02-single-admin-auth-skeleton.md`

Successor Runtime-12 session/cookie skeleton: `docs/future/passive-alpha-runtime-12-session-cookie-skeleton.md`

Commit scope: backend password-verification helper, focused tests, and minimal documentation alignment. This block does not add login, logout, sessions, cookies, CSRF, frontend login, rate limiting, endpoint behavior changes, guard changes, target policy changes, Active changes, Nmap, tags, releases, or deployment behavior.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_PASSWORD_VERIFY_HELPER_ACCEPTED
```

Inspectra now has an isolated backend helper that can verify an operator-supplied password against a supported `INSPECTRA_ADMIN_PASSWORD_HASH` value for future `self_hosted_single_admin` login work.

The helper is intentionally not wired to a login endpoint yet. `/auth/status` still reports `login_available=false`.

## Algorithm Chosen

Runtime-11 uses:

```text
pbkdf2_sha256
```

The verifier is implemented with Python standard library primitives:

- `hashlib.pbkdf2_hmac("sha256", ...)`
- `hmac.compare_digest(...)`

Reasoning:

- The current backend dependency set is minimal and does not include `argon2`, `bcrypt`, `passlib`, or `werkzeug`.
- This slice must run without dependency installation, network access, Docker, or external services.
- PBKDF2-HMAC-SHA256 with an explicit salt and high iteration count avoids plaintext comparison, reversible encoding, raw SHA, and unsalted hashes.
- Future work may replace or extend this with Argon2 or bcrypt in a separate docs-first dependency slice.

## Supported Hash Format

The only supported format is:

```text
pbkdf2_sha256$<iterations>$<salt>$<digest_hex>
```

Rules:

- `<iterations>` must be at least `600000`.
- `<salt>` must be 16 to 128 characters and limited to safe ASCII characters.
- `<digest_hex>` must be a 64-character SHA-256 hex digest derived from PBKDF2-HMAC-SHA256.
- Any other format is unsupported and fails closed.

No helper currently generates hashes for operators. Password setup/generation guidance remains future work.

## Implemented Helper

New backend module:

```text
backend/app/auth.py
```

Implemented functions:

```text
verify_admin_password(password, password_hash) -> bool
is_supported_admin_password_hash(password_hash) -> bool
```

Behavior:

- Correct password and supported hash returns `True`.
- Wrong password returns `False`.
- Missing or blank password returns `False`.
- Missing or blank hash returns `False`.
- Unsupported hash format returns `False`.
- Malformed hash returns `False`.
- Too-low PBKDF2 iteration count returns `False`.
- Verification exceptions return `False`.
- The helper does not log passwords or hashes.
- The helper does not return detailed public failure reasons.

## Auth Status

`GET /auth/status` behavior is unchanged:

- `INSPECTRA_ADMIN_PASSWORD_HASH` still acts as a configuration-presence signal.
- A configured hash is not returned.
- `login_available` remains `false`.
- No password, hash, verifier detail, session id, cookie, or CSRF value is returned.

Runtime-13 or a later scoped slice should decide when `login_available` can become `true`.

## What Was Not Implemented

- No `POST /auth/login`.
- No `POST /auth/logout`.
- No session store.
- No cookies.
- No CSRF protection.
- No frontend login.
- No frontend auth-state handling.
- No rate limiting or lockout.
- No password generation/setup CLI.
- No hash migration.
- No OAuth/OIDC.
- No reverse-proxy trusted-header auth.
- No multi-user runtime.
- No public/community runtime.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No Active expansion.
- No Nmap.
- No target policy relaxation.

## Tests

Focused backend tests cover:

- correct password returns true;
- wrong password returns false;
- missing password returns false;
- missing hash returns false;
- unsupported hash format returns false;
- malformed hash returns false;
- too-low iteration count returns false;
- helper logs do not contain password or hash material;
- supported hash detection;
- `/auth/status` remains hash-redacted and `login_available=false`;
- existing auth-status/auth-mode/anonymous/health behavior remains compatible.

Reference validation commands:

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "password or auth_status or auth_mode or anonymous or health"
.venv/bin/python -m pytest backend/tests/test_backend.py
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend code.

## Residual Risks

- PBKDF2 is not memory-hard like Argon2.
- There is still no login endpoint or session runtime.
- `self_hosted_single_admin` remains fail-closed for anonymous sensitive routes but not usable for authenticated workflows.
- Operators still need future setup guidance for generating and storing hashes.
- Rate limiting, backoff, lockout, CSRF, cookie security, and frontend auth handling remain future slices.

## No-Scope Preserved

- No `.env`, `.env.*`, or `.envrc` reads.
- No runtime login behavior.
- No sessions or cookies.
- No CSRF implementation.
- No frontend changes.
- No guard changes.
- No sensitive endpoint changes.
- No Docker execution.
- No probes, DNS, external HTTP, Nmap, port scanning, or live target traffic.
- No Active expansion.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-12-SESSION-COOKIE-SKELETON
```

Next runtime work should design and implement the minimal session/cookie skeleton separately from login endpoint behavior, preserving fail-closed auth-required routes until a valid session principal is explicitly integrated.

Runtime-12 now accepts the internal session/cookie skeleton and recommends `PASSIVE-ALPHA-RUNTIME-13-LOGIN-LOGOUT-ENDPOINTS` next. Runtime-11 remains the historical password-verifier slice.

Runtime-13 now wires the password verifier and session/cookie skeleton into minimal backend login/logout endpoints and recommends `PASSIVE-ALPHA-RUNTIME-14-CSRF-MUTATING-ROUTES` next.
