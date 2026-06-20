# App-Level Auth Staging Decision

Decision: `APP_LEVEL_AUTH_STAGING_DECISION_01_ACCEPTED`

Status: staging should keep Caddy Basic Auth for the current operator-only
alpha, but app-level auth should be enabled and smoke checked before access is
given to anyone else.

## Current State

Staging is currently protected by Caddy Basic Auth at:

```text
https://inspectra-alpha.urlbreve.es
```

Observed app auth mode during the staging smoke was:

```text
trusted_local_no_auth
```

Current posture:

- the staging URL is not promoted broadly;
- current operator-only use is acceptable with Caddy Basic Auth;
- passive upload, analysis, Raw JSON, and exports have been dogfooded;
- Active capabilities remained disabled in staging checks;
- Caddy returned `401` for unauthenticated access after cleanup;
- Caddy-only access should not be treated as enough for wider private sharing.

## Risk Comparison

| Option | Sharing risk | Job/archive privacy | Raw JSON/export privacy | Owner-scope expectation | Operations | UX | Wider private sharing fit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Caddy-only Basic Auth | Acceptable for one operator, weaker if access is forwarded or reused | Relies on one outer gate for all uploaded material | Relies on one outer gate for all reports | App remains in trusted-local mode, so every action maps to the local operator | Simple and already deployed | One browser prompt, no app login | Not preferred |
| App-level auth only | Better in-app route protection, but leaves the subdomain directly exposed to the app | Sensitive routes require app session | Reports/exports require app session | Matches existing owner-scoped route model | Needs deploy config, access material setup, smoke, and rollback plan | Normal login flow | Better than Caddy-only, but less conservative |
| Caddy Basic Auth plus app-level auth | Strongest near-term private-alpha posture | Outer gate plus app session for uploaded material | Outer gate plus app session for Raw JSON and exports | App owner model is exercised while Caddy still limits reachability | More setup and support burden | Two gates, acceptable for small private alpha | Recommended |
| IP allowlisting supplement | Reduces accidental reach if operators have stable IPs | Supplements either auth layer, but does not replace app auth | Supplements either auth layer, but does not replace app auth | Does not change app owner semantics | Can be brittle for mobile or changing networks | Usually invisible until it blocks access | Optional supplement only |

## Existing App Auth Capability

Local inspection of documented auth code shows app-level auth already exists for
the private self-hosted alpha path:

- `INSPECTRA_AUTH_MODE` supports `self_hosted_single_admin`.
- `INSPECTRA_ADMIN_PASSWORD_HASH` is the required admin verifier input for
  that mode.
- `/auth/status`, `/auth/login`, and `/auth/logout` are implemented.
- A supported admin hash makes login available.
- Sensitive routes require auth in modes other than `trusted_local_no_auth`.
- The app uses an `HttpOnly` session cookie and CSRF checks on mutating
  cookie-auth routes.
- Existing owner-scoped routes use the single admin operator.
- Login rate limiting and generic `429` handling exist.
- `INSPECTRA_AUTH_STATE_STORE=sqlite` is available for persistent session and
  login-attempt state; memory remains the default.
- The frontend has login/status/logout UX and keeps CSRF state in memory.

Decision: enabling app-level auth on staging should not need new application
runtime implementation. It should be planned as a config/deploy/smoke phase
that supplies staging-only auth settings outside git, preserves Caddy, keeps
Active disabled, validates uploads/reports/exports, and documents rollback.

Known remaining gaps still matter:

- secure-cookie and trusted-proxy hardening are documented as future exposed-use
  work;
- admin recovery/setup guidance is not a substitute for careful operator
  handling;
- this is private-alpha single-admin auth, not a multi-user sharing model.

## Recommended Staging Posture

Use this posture by stage:

1. Current operator-only alpha: keep Caddy Basic Auth and keep the app in
   `trusted_local_no_auth`.
2. Any wider private sharing: layer Caddy Basic Auth with
   `self_hosted_single_admin`.
3. Optional supplement: add IP allowlisting only when the operator set has
   stable access locations and the operational friction is acceptable.
4. Always: keep Active disabled by default regardless of the auth layer.

This preserves the working staging setup while making the next sharing step use
the app's route guards, owner-scoped reads/exports, login flow, and CSRF
protection.

## Future Implementation Options

Because app-level auth already exists, the next phase should be a staging enable
plan rather than an auth design phase.

That plan should cover:

- staging config changes needed for `self_hosted_single_admin`;
- creation and handling of staging-only admin access material outside repo
  records;
- whether to use memory or SQLite auth state for staging;
- Caddy Basic Auth retention during app-auth verification;
- expected `/auth/status` states before and after login;
- upload, job, Raw JSON, export, delete, logout, and retry smoke checks;
- Active-disabled verification;
- Caddy and app rollback;
- redacted logging expectations.

If that plan finds an implementation gap, then a focused hardening design phase
can follow. The current code/documentation inspection does not show that as the
first necessary step.

## No-Go Boundaries

Do not:

- add public signup;
- add open target intake;
- allow anonymous uploads;
- share the staging URL without access controls;
- enable Active broadly;
- write operator access material into git or docs;
- remove or weaken Caddy before app auth is verified;
- add version-to-CVE mapping in this line of work;
- make exploitability or safety assurance claims;
- route this through `archive/run-all` or `tools/runner/main.py`.

## Suggested Next Microphase

Recommended next microphase:

```text
APP_LEVEL_AUTH_STAGING_ENABLE_PLAN_02
```

Use `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_01` instead only if staging stays
strictly operator-only and the product priority remains report-quality dogfood
rather than sharing-readiness.

## Decision

```text
APP_LEVEL_AUTH_STAGING_DECISION_01_ACCEPTED
```
