# Passive Alpha Runtime 10 Single Admin Login Session Plan

Status: `PASSIVE_ALPHA_SINGLE_ADMIN_LOGIN_SESSION_PLAN_ACCEPTED`.

Base Runtime-09 closeout: `docs/future/passive-alpha-runtime-09-runtime-p0-closeout.md`

Base Runtime-02 auth-status skeleton: `docs/future/passive-alpha-runtime-02-single-admin-auth-skeleton.md`

Base Runtime-03 deny-anonymous guard: `docs/future/passive-alpha-runtime-03-deny-anonymous-sensitive-routes.md`

Base auth-boundary runtime plan: `docs/future/passive-alpha-p0-01-auth-boundary-design-to-runtime-plan.md`

Base deployment hardening checklist: `docs/future/passive-alpha-p0-06-deployment-hardening-checklist.md`

Successor Runtime-11 password verifier: `docs/future/passive-alpha-runtime-11-password-verify-helper.md`

Commit scope: docs-only login/session plan for future `self_hosted_single_admin` runtime. This block defines password verification, session/cookie behavior, logout, CSRF implications, frontend auth-state handling, future tests, and implementation slices. It does not change backend, frontend, runner, tests, fixtures, guards, sessions, cookies, target policy, Active behavior, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_SINGLE_ADMIN_LOGIN_SESSION_PLAN_ACCEPTED
```

Inspectra should make `self_hosted_single_admin` usable through a minimal local password plus browser session model, implemented in small future slices.

The current microphase is docs-first only. It does not implement login, password verification, sessions, cookies, CSRF, frontend login, rate limiting, or any new runtime capability.

## Objective

Runtime P0 is closed as trusted-local hardened, but auth-required modes still fail closed for anonymous sensitive routes without an authenticated path. This plan defines the smallest future shape that can turn `self_hosted_single_admin` from fail-closed-only into a usable self-hosted mode.

The plan keeps Inspectra open-source, altruistic, local-first, and self-hosted-first. Auth/session work exists for safety in local, self-hosted, private/internal, and optional community deployments. It is not SaaS, billing, tenant billing, subscription, quota, paid-plan, or enterprise multi-tenant work.

## Target Mode

This plan applies only to:

- `self_hosted_single_admin`

It does not apply yet to:

- `trusted_local_no_auth`, which remains the default for localhost/dev/local trusted use;
- `private_team_lightweight_users`;
- `public_community_limited_instance`;
- OAuth/OIDC;
- reverse-proxy trusted-header auth;
- multi-user login;
- SaaS, billing, tenant billing, paid plans, quotas, or enterprise tenancy.

## Current Runtime Baseline

The current backend already has:

- `INSPECTRA_AUTH_MODE`;
- `INSPECTRA_ADMIN_PASSWORD_HASH` as a configuration-presence signal only;
- `GET /auth/status`;
- deny-anonymous behavior for sensitive routes when auth mode requires auth;
- owner metadata for new files/jobs;
- trusted-local legacy owner mapping to `local-admin`;
- owner-scoped reads, exports, SBOMs, Raw JSON, and delete behavior.

The current backend does not have:

- password verification;
- login;
- session creation;
- cookie handling;
- logout;
- CSRF protection;
- frontend login/auth status UX.

The current frontend uses ordinary `fetch` calls without credentialed cookie handling, a login API helper, or global 401/auth-state behavior.

## Password And Hash Model

### Configuration

Future login should continue to use:

```text
INSPECTRA_ADMIN_PASSWORD_HASH
```

Rules:

- Never store a plaintext admin password in code, docs examples, tests, frontend state, job JSON, reports, Raw JSON, or logs.
- Never return the configured hash through `/auth/status`, login responses, errors, exports, or frontend state.
- Treat `configured=true` as "a future login credential is configured", not proof that the deployment is safe.
- Keep `trusted_local_no_auth` behavior unchanged when auth mode does not require login.
- In `self_hosted_single_admin`, future login should fail closed if the hash is missing or unsupported.

### Algorithm Recommendation

The current backend dependency set is intentionally small:

- `fastapi`
- `httpx`
- `python-multipart`
- `uvicorn`

There is no current password hashing dependency such as `passlib`, `bcrypt`, `argon2`, or `werkzeug`.

Preferred future implementation path:

1. Add an isolated password verification helper first.
2. Support one explicit modern hash family before adding login endpoints.
3. Keep unsupported hash formats as controlled failures, not silent accepts.

Recommended options:

- `argon2`: strong modern password hashing, good long-term default if the dependency footprint is accepted.
- `passlib` with bcrypt: familiar and well-supported, but adds dependency surface.
- Werkzeug password hashing: practical if Werkzeug is already introduced later for another reason, but it is not present now.

Avoid as a default:

- raw SHA hashes;
- unsalted hashes;
- reversible encoding;
- comparing plaintext passwords;
- a bare HMAC/constant-time compare unless the input is already an externally generated, high-entropy verifier format with clear operator documentation.

For Runtime-11, the recommended decision is to add a dedicated helper that validates hash prefixes and performs constant-time result handling through the chosen library. The helper should not log passwords, hashes, hash prefixes, salts, or verification exceptions containing sensitive material.

## Login Endpoint Design

Future endpoint:

```text
POST /auth/login
```

Candidate request body:

```json
{
  "password": "operator supplied password"
}
```

Optional future request body if the UI wants a visible account label:

```json
{
  "username": "admin",
  "password": "operator supplied password"
}
```

Initial recommendation:

- Do not require username for `self_hosted_single_admin`.
- If a username is accepted, allow only a fixed value such as `admin` and keep failures generic.
- Accept only JSON.
- Reject missing, empty, oversized, or malformed credentials with controlled errors.
- Return generic failure for wrong password, missing hash, unsupported hash, or inactive login.
- Do not echo submitted values.
- Do not reveal whether the admin hash exists through login failures.
- Do not create jobs or file records.
- Do not include password, hash, token, session id, or secret material in response JSON.

Candidate success response:

```json
{
  "authenticated": true,
  "operator_id": "local-admin",
  "auth_mode": "self_hosted_single_admin"
}
```

Candidate failure response:

```json
{"detail": "Invalid credentials."}
```

Future rate limiting, delay/backoff, and lockout behavior should be separately scoped if it grows beyond a small helper.

## Session Model

### Preferred Initial Shape

Preferred initial model:

- server-side sessions;
- opaque random session id in an `HttpOnly` cookie;
- session metadata stored in backend local storage or in-memory only for the first narrow implementation, with explicit limits;
- authenticated principal fixed to `local-admin` for `self_hosted_single_admin`;
- no bearer token returned to JavaScript;
- no token stored in localStorage/sessionStorage.

Rationale:

- Browser cookie sessions fit the local self-hosted UI.
- Opaque session ids reduce accidental frontend token exposure.
- Server-side session invalidation makes logout and expiry easier to reason about.
- The current owner model already has a single operator id, `local-admin`.

Signed-cookie-only sessions are an acceptable future alternative only if the signing key, expiry, rotation, revocation limitations, and logout behavior are explicitly designed first.

### Expiry And Logout

Future session fields should include:

- created timestamp;
- last-used or expiry timestamp;
- operator id;
- auth mode;
- session version or revocation marker if needed.

Initial expiry recommendation:

- short enough for self-hosted safety;
- configurable later if needed;
- absolute expiry before idle timeout complexity unless the implementation remains small.

Future logout endpoint:

```text
POST /auth/logout
```

Logout should:

- require a valid session when possible;
- delete or invalidate the server-side session;
- clear the session cookie;
- return a small generic success response;
- not leak whether a previous session existed.

## Cookie Rules

Future session cookie should be:

- `HttpOnly`;
- `SameSite=Lax` as the initial default unless the deployment requires stricter behavior;
- `Secure` outside localhost;
- path scoped to the app;
- bounded by explicit `Max-Age` or `Expires`;
- never written into Raw JSON, reports, job results, logs, or frontend local storage.

Localhost/dev may allow an insecure cookie only for explicitly trusted local development. Any non-local exposure should require TLS or a trusted TLS-terminating reverse proxy before using secure cookie auth.

## CSRF Implications

If browser cookie auth is used, mutating routes need CSRF protection before authenticated browser use is considered complete.

Mutating route families include:

- file uploads;
- file deletes;
- file-based audit creation;
- target-based baseline job creation;
- Active dry-run and one-HEAD job creation;
- job/result delete;
- future reset, cleanup, admin, or config mutations;
- `POST /auth/logout`, depending on implementation details.

Candidate CSRF approaches:

- synchronizer token stored server-side and returned through a safe endpoint;
- double-submit cookie with a non-HttpOnly CSRF token and an explicit request header;
- framework middleware if a suitable dependency is accepted later.

Rules:

- Do not weaken CORS to make CSRF easier.
- Do not use wildcard credentialed CORS.
- Keep allowed origins explicit for deployed frontends.
- Treat CORS as a browser boundary only, not backend authorization.
- Keep CSRF tokens out of reports, exports, Raw JSON, logs, and job results.

Recommended sequencing: login/session can be sketched first, but broad authenticated mutating UI should not be considered complete until CSRF protection is implemented and tested.

## Auth Status Evolution

Current `/auth/status` shape remains safe:

```json
{
  "auth_mode": "self_hosted_single_admin",
  "auth_required": true,
  "configured": true,
  "trusted_local": false,
  "default_operator_id": "local-admin",
  "login_available": false
}
```

Future authenticated shape should remain safe and may add:

```json
{
  "auth_mode": "self_hosted_single_admin",
  "auth_required": true,
  "configured": true,
  "trusted_local": false,
  "default_operator_id": "local-admin",
  "login_available": true,
  "authenticated": true,
  "operator_id": "local-admin"
}
```

Rules:

- `login_available=true` only after login/session runtime exists and a supported credential hash is configured.
- `authenticated=false` for anonymous callers.
- `operator_id` is safe to expose for the current single-admin model, but it is not a billing tenant, SaaS tenant, paid-plan id, or enterprise account id.
- Do not return password hashes, session ids, CSRF secrets, cookie values, feature flag internals, storage paths, file/job IDs, target histories, or bypass guidance.

## Guard Integration

Runtime-03 already denies anonymous sensitive requests in auth-required modes before handlers can look up resources.

Future login/session work should change only the principal resolution path:

1. Public-safe routes remain narrow:
   - `GET /health`
   - `GET /auth/status`
   - future login assets or login endpoint as explicitly scoped
   - `OPTIONS` preflight
2. `POST /auth/login` is public in the limited sense that it accepts credentials, but it must not expose sensitive app data.
3. When a valid session exists, current-owner resolution returns `local-admin`.
4. Sensitive routes remain denied until the session is valid.
5. Owner checks continue to use existing owner metadata and the single-admin/local-admin principal initially.
6. Wrong-owner or unresolved-owner behavior should remain generic.

Future multi-user or admin-read-all behavior must not be smuggled into single-admin login/session work.

## Frontend UX Plan

Docs-only future UX:

- Load `/auth/status` on startup.
- If `auth_required=false`, preserve current trusted-local UX.
- If `auth_required=true` and `login_available=false`, show a controlled not-ready/misconfigured state.
- If `auth_required=true`, `login_available=true`, and `authenticated=false`, show a login screen or modal before sensitive app workflows.
- Handle global `401` responses by refreshing auth status and showing login/session-expired state.
- Use credentialed `fetch` only after cookie-session behavior is intentionally implemented.
- Never store passwords, session ids, or hashes in localStorage/sessionStorage.
- Provide a logout button when authenticated.
- Avoid displaying admin hash configuration details beyond safe status copy.
- Keep Active panels gated by their existing feature flags and authorization confirmations after login.

The frontend must continue to present findings as heuristic indicators and must not imply production readiness, public/community readiness, Nmap readiness, credential validity, or exploitability confirmation.

## Failure, Lockout, And Logging

Future behavior should include:

- generic invalid credential responses;
- no username enumeration;
- no distinction between missing hash, wrong password, unsupported hash, or disabled login in public login failure copy;
- redacted logs for login failures;
- no password/hash/session/cookie/CSRF values in logs;
- optional fixed delay or backoff after failed attempts;
- future bounded rate limiting for exposed self-hosted installs;
- no permanent lockout without a clear operator recovery path.

Rate limiting and lockout may be separate slices if implementing them safely would enlarge the initial login/session work.

## Deployment Considerations

- `trusted_local_no_auth` remains localhost/dev/local trusted only.
- `self_hosted_single_admin` should not be exposed until a supported admin hash, login/session runtime, cookie flags, CSRF, and deployment guidance are implemented.
- TLS is required outside localhost for secure cookies.
- A TLS-terminating reverse proxy is acceptable if direct backend access cannot bypass the proxy.
- Trusted proxy headers must be accepted only from trusted proxy paths if they are used later.
- CORS origins must be explicit for deployed frontends.
- Credentialed wildcard CORS must remain disallowed.
- Logs, backups, storage directories, job JSON, exports, and Raw JSON remain sensitive.
- Direct static serving of uploads/results/storage remains out of scope.

## Minimum Future Tests

Backend tests:

- current `/auth/status` remains `login_available=false` before implementation;
- `trusted_local_no_auth` remains unaffected;
- `self_hosted_single_admin` without a hash remains fail-closed and login unavailable;
- unsupported hash format fails closed;
- correct password creates a session;
- wrong password returns a generic failure;
- login response does not expose password, hash, session id, or cookie value in JSON;
- session cookie has expected `HttpOnly`, `SameSite`, expiry, and environment-appropriate `Secure` flags;
- sensitive route is accessible after valid session;
- sensitive route is denied after logout or expiry;
- `/auth/status` reports safe authenticated state without leaking secrets;
- CSRF protects mutating routes when cookie auth is used;
- anonymous auth-required requests still receive generic `401`;
- owner-scoped reads/exports/delete continue to use `local-admin`;
- redaction regressions continue to pass.

Frontend tests:

- startup reads auth status;
- trusted-local mode preserves current UX;
- auth-required unauthenticated state shows login UI;
- disabled/unavailable login state is controlled and does not expose `.env` or bypass guidance;
- successful login transitions to app view;
- global `401` transitions to login/session-expired state;
- logout clears authenticated UI state;
- password is not rendered after submission;
- no hash/session/cookie/CSRF values appear in DOM or Raw JSON-like debug output.

## Implementation Slice Recommendation

Recommended future slices:

1. `PASSIVE-ALPHA-RUNTIME-11-PASSWORD-VERIFY-HELPER`
   - Choose and isolate password hash verification.
   - Add dependency only if accepted.
   - Keep login/session endpoints out of scope.
2. `PASSIVE-ALPHA-RUNTIME-12-SESSION-COOKIE-SKELETON`
   - Define server-side session store and cookie flags.
   - Keep login endpoint minimal or still deferred, depending on slice size.
3. `PASSIVE-ALPHA-RUNTIME-13-LOGIN-LOGOUT-ENDPOINTS`
   - Add `POST /auth/login` and `POST /auth/logout`.
   - Integrate valid session principal with the existing guard.
4. `PASSIVE-ALPHA-RUNTIME-14-CSRF-MUTATING-ROUTES`
   - Add CSRF mechanism for browser cookie auth and mutating routes.
5. `PASSIVE-ALPHA-RUNTIME-15-FRONTEND-AUTH-STATUS-LOGIN-UX`
   - Add frontend auth status, login, logout, and global 401 handling.

Recommended next microphase:

```text
PASSIVE-ALPHA-RUNTIME-11-PASSWORD-VERIFY-HELPER
```

Runtime-11 now accepts the isolated password verifier helper with explicit `pbkdf2_sha256$iterations$salt$digest` support and recommends `PASSIVE-ALPHA-RUNTIME-12-SESSION-COOKIE-SKELETON` next. Runtime-10 remains the historical login/session plan and does not itself implement runtime behavior.

Runtime-12 now accepts the internal session/cookie skeleton and recommends `PASSIVE-ALPHA-RUNTIME-13-LOGIN-LOGOUT-ENDPOINTS` next.

Runtime-13 now accepts minimal backend login/logout endpoints, session cookie issuance/clearing, and valid-session guard integration for `self_hosted_single_admin`; it recommends `PASSIVE-ALPHA-RUNTIME-14-CSRF-MUTATING-ROUTES` next.

## No-Scope

- No code changes.
- No runtime changes.
- No backend, frontend, runner, tests, or fixture changes.
- No login implementation.
- No password verification implementation.
- No session or cookie implementation.
- No CSRF implementation.
- No frontend login implementation.
- No rate limiting implementation.
- No OAuth/OIDC.
- No reverse-proxy trusted-header auth implementation.
- No multi-user runtime.
- No public/community runtime.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No Docker execution.
- No probes, DNS, external HTTP, Nmap, port scanning, or live target traffic.
- No Active expansion.
- No target policy relaxation.
- No push, tag, or release.
- No `.env`, `.env.*`, or `.envrc` reads.

## Acceptance Criteria

- Single-admin login/session plan is defined.
- Target mode is limited to `self_hosted_single_admin`.
- Password/hash model is defined.
- Login endpoint shape is defined without implementation.
- Session/cookie model is defined.
- Logout behavior is defined.
- CSRF implications are defined.
- `/auth/status` evolution is defined.
- Guard integration is defined.
- Frontend auth-state plan is defined.
- Minimum tests are defined.
- Implementation slices are defined.
- No runtime or capability changes are made.
