# App-Level Auth Staging Enablement Plan

Decision: `APP_LEVEL_AUTH_STAGING_ENABLE_PLAN_02_ACCEPTED`

Status: plan accepted for a later staging execution phase. This phase does not
enable app-level auth, edit VPS or Caddy configuration, run the app, deploy, or
change runtime behavior.

## Objective

Enable existing app-level auth on staging before wider private sharing while
preserving the current outer Caddy Basic Auth layer and keeping Active
capabilities disabled by default.

The target auth mode is the existing private-alpha single-admin mode:

```text
self_hosted_single_admin
```

This is not a public signup, multi-user, or open intake plan.

## Current State

Current staging state from the accepted decision and dogfood records:

- staging URL: `https://inspectra-alpha.urlbreve.es`;
- Caddy Basic Auth protects the whole subdomain;
- app mode previously observed: `trusted_local_no_auth`;
- passive archive upload, project analysis, Raw JSON review, and exports have
  been validated on staging;
- report readability improvements are validated for categories, ecosystem
  grouping, and dependency pinning summaries;
- Active gates were checked as disabled;
- Caddy returned unauthenticated `401` after dogfood cleanup.

Current operator-only use can continue with Caddy Basic Auth. Any broader
private sharing should wait for the layered app-auth posture below.

## Target State

Target staging posture:

- Caddy Basic Auth remains enabled as the outer access layer.
- Backend app auth mode becomes `self_hosted_single_admin`.
- `INSPECTRA_ADMIN_PASSWORD_HASH` is supplied only through VPS-private config
  or an equivalent private mechanism.
- `INSPECTRA_AUTH_STATE_STORE=sqlite` is preferred for staging persistence if
  the data path and permissions are safe.
- If SQLite auth state is not used, the memory store is acceptable only with a
  clear note that sessions and login-attempt state reset on backend restart.
- `/auth/status` shows app auth required before login.
- Login and logout work through the frontend while still behind Caddy.
- Sensitive app routes require a valid app session.
- Active flags remain disabled regardless of auth mode.

## Secret Handling Plan

The later execution phase must treat staging auth material as operator-private:

- generate the staging admin passphrase outside git and docs;
- generate the verifier on the VPS or a trusted local shell without writing the
  plaintext to shell history;
- do not paste the passphrase or verifier into docs, chat, commits, logs, or
  terminal transcripts;
- store the verifier only in a VPS-private env/config location or a private
  secret mechanism;
- record only categories of changes, never values;
- verify logs do not include submitted auth material;
- define a rollback before editing any config;
- keep Caddy Basic Auth active throughout the auth enablement smoke.

Acceptable documentation wording is category-level, for example:

```text
INSPECTRA_AUTH_MODE set to self_hosted_single_admin.
INSPECTRA_ADMIN_PASSWORD_HASH set through VPS-private config.
INSPECTRA_AUTH_STATE_STORE set to sqlite.
```

Do not record the actual value of any private setting.

## Deployment Plan For Later Execution

The later execution phase should use the existing staging VPS runbook style and
avoid repository runtime changes unless a blocker is separately approved.

Planned steps:

1. Record local and VPS preflight state.
2. Confirm working tree and staging checkout are clean enough for config-only
   work.
3. Back up current VPS-local env/config and Compose override files.
4. Confirm Caddy Basic Auth is still the outer layer.
5. Add or update only VPS-private config categories:
   - `INSPECTRA_AUTH_MODE=self_hosted_single_admin`
   - `INSPECTRA_ADMIN_PASSWORD_HASH=<private>`
   - `INSPECTRA_AUTH_STATE_STORE=sqlite`, if chosen
   - `INSPECTRA_AUTH_STATE_DB_PATH`, only if a non-default path is needed
6. Preserve all Active-disabled settings.
7. Recreate the backend container so it reads the updated auth config.
8. Keep frontend and Caddy route unchanged unless a later smoke reveals a
   documented deploy blocker.
9. Do not create a release or tag.
10. Do not change `archive/run-all` or `tools/runner/main.py`.

SQLite auth-state preference:

- choose SQLite if the existing app data mount can hold the auth-state database
  with safe permissions;
- use the default auth-state DB path unless there is a clear staging reason to
  override it;
- document only the path category, not private values.

Memory-store tradeoff:

- easier to enable;
- sessions and login-attempt state reset on backend restart;
- acceptable only for a short smoke or very narrow operator-only period.

## Smoke Checklist For Later Execution

The execution phase should run this checklist after enabling app auth:

- unauthenticated request through Caddy still returns `401`;
- authenticated through Caddy but logged out of the app:
  - frontend renders the app-auth login or protected state correctly;
  - `/api/auth/status` reports auth required and unauthenticated;
- login with the staging admin passphrase succeeds;
- authenticated `/api/auth/status` reports authenticated state and CSRF
  requirement as expected;
- CSRF/session behavior works on mutating routes;
- passive archive upload works after login;
- `project_archive_basic` analysis works after login;
- Raw JSON, Markdown, HTML, XML, PDF, and delete routes require app auth;
- logout works;
- after logout, sensitive API routes deny access;
- failed login behavior remains generic and rate limited;
- Active flags remain disabled;
- no Nmap or live Active jobs are submitted.

Suggested passive smoke fixture:

- use a small sanitized archive or the already-approved synthetic passive
  fixture style;
- do not upload broad source snapshots in this auth enablement phase unless the
  sanitizer review is separately in scope.

## Rollback Plan

Rollback should be prepared before any staging config edit:

1. Restore the prior VPS-private auth config.
2. Restart or recreate the backend so the previous config is active.
3. Confirm `trusted_local_no_auth` only if rollback intentionally returns to
   the current operator-only app posture.
4. Keep Caddy Basic Auth active throughout rollback.
5. Remove any temporary local files that held staging auth material.
6. Confirm logs and docs contain no private auth values.
7. Record rollback result without values.

If login access is lost but Caddy remains active, rollback to the backed-up
config and repeat the app-auth smoke only after the cause is understood.

## Risk And Acceptance Criteria

Accept the later enablement only if:

- Caddy remains enabled;
- app auth required state is visible before login;
- login and logout work;
- uploads, project analysis, Raw JSON, and exports work after login;
- sensitive routes deny app-unauthenticated access;
- Active remains disabled;
- auth material is not recorded.

Block the later enablement if:

- app auth breaks the frontend completely;
- auth state cannot persist acceptably for the intended sharing period;
- Raw JSON or exports bypass app auth;
- auth material appears in logs, docs, or commits;
- Caddy is weakened or removed;
- Active flags drift from disabled.

## Suggested Next Microphase

Recommended next microphase:

```text
APP_LEVEL_AUTH_STAGING_ENABLE_SMOKE_03
```

Scope: execute staging config/deploy/smoke for `self_hosted_single_admin`
behind Caddy Basic Auth, with no release, tag, Active enablement, Nmap, or
outside target use.

## Decision

```text
APP_LEVEL_AUTH_STAGING_ENABLE_PLAN_02_ACCEPTED
```
