# App-Level Auth Staging Enable Smoke

Decision: `APP_LEVEL_AUTH_STAGING_ENABLE_SMOKE_03_ACCEPTED`

Status: staging app-level auth was enabled with the existing
`self_hosted_single_admin` mode behind Caddy Basic Auth, then smoke checked
with Active capabilities disabled.

## Scope

This phase changed VPS-private staging config and recreated the backend
container so the existing app-level auth mode could be smoke checked. It did
not create a release, create a tag, push, enable Active capabilities, run Nmap,
submit live Active jobs, use outside targets, take screenshots, publish the
staging URL, modify runtime code, modify `archive/run-all`, or modify
`tools/runner/main.py`.

## Staging Target

- Staging URL: `https://inspectra-alpha.urlbreve.es`
- Target posture: Caddy Basic Auth plus app-level
  `self_hosted_single_admin`
- Auth state store: SQLite selected for staging persistence
- Caddy Basic Auth: preserved as the outer layer
- Active posture: disabled by default and rechecked after smoke

## Preflight

Local preflight:

- initial local status: `## main...origin/main`
- latest local commit before this record:
  `d039343 docs(auth): plan staging app auth enablement`
- `git diff --check`: passed
- `git diff --cached --check`: passed
- no uncommitted runtime changes were present

VPS preflight:

- `/opt/apps/inspectra` checkout: `main`
- deployed commit before auth config:
  `94c63781998eca12c3da831c1736566762207f0a`
- deployed description: `v0.2.0-alpha.1-11-g94c6378`
- current app auth mode before config: `trusted_local_no_auth`
- Caddy unauthenticated `/`: `401`
- backend data/runtime directory: writable
- backend: healthy
- audit-tools: healthy
- frontend: up
- Inspectra services had no public host port bindings
- Docker socket mount was absent for backend, frontend, and audit-tools

## Backup And Config Categories

Backups created:

- `data/backups/auth-enable-smoke-20260620T125714Z`
- `data/backups/app-auth-smoke-20260620T130003Z`
- `data/backups/app-auth-smoke-retry-20260620T130438Z`

Backed up categories:

- VPS-local Compose override
- Caddyfile before temporary smoke access
- `.env` backup was absent because no `.env` file was present

VPS-private config categories changed:

- `INSPECTRA_AUTH_MODE`
- `INSPECTRA_ADMIN_PASSWORD_HASH`
- `INSPECTRA_AUTH_STATE_STORE`

No private auth values are recorded in this document.

## Enablement

The backend Compose config was updated with category-only app-auth settings and
validated successfully. The backend container was recreated and returned
healthy.

The selected auth state store was SQLite. The default runtime data path was
usable, so no additional path override was needed.

Caddy Basic Auth was not weakened or removed. A temporary Caddy smoke principal
was added to the existing Basic Auth block so the app smoke could run through
the protected public route. It was removed after smoke, and Caddy again returned
`401` unauthenticated.

## App Auth Smoke

Through Caddy Basic Auth:

| Check | Result |
| --- | --- |
| Caddy unauthenticated `/` | `401` |
| Caddy authenticated `/` | `200`, frontend title present |
| `/api/auth/status` before app login | `200`, `self_hosted_single_admin`, auth required, unauthenticated, login available |
| failed app login | `401`, generic invalid response, no retry header |
| app login | `200`, authenticated as `local-admin` |
| `/api/auth/status` after login | `200`, authenticated, CSRF required, CSRF value present |
| app logout | `200`, authenticated false |

The first smoke attempt failed before login because the generated app passphrase
was written to the wrong temporary path. Caddy was already restored and the app
auth config remained enabled. The retry consumed that temporary file, completed
the smoke, then deleted the file. No repository or runtime-code fix was needed.

## Passive Smoke

Smoke fixture:

- small synthetic archive only;
- included `package.json` and `requirements.txt`;
- no broad project source upload was used.

Results:

| Check | Result |
| --- | --- |
| archive upload after login | `201`, archive accepted |
| project archive launch | `202`, job `e81468b7062c47808fed562bdbd86345` |
| job result | `200`, `completed`, 4 findings |
| Markdown export | `200`, 10077 bytes |
| HTML export | `200`, 17990 bytes |
| XML export | `200`, 17589 bytes |
| PDF export | `200`, 12747 bytes |
| source delete after review | `200` |

Raw JSON and export marker scan returned zero hits for the checked private-value
markers.

## Denied After Logout

After app logout, a fresh session attempted sensitive routes through Caddy:

| Route class | Result |
| --- | --- |
| Raw job JSON | `401` |
| Markdown export | `401` |
| source delete | `401` |

This confirms app-level auth is enforced beyond the outer Caddy layer.

## Active Disabled

Checked after smoke:

- `INSPECTRA_ACTIVE_DRY_RUN_ENABLED`: disabled
- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED`: disabled
- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED`: disabled
- `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED`: disabled
- `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED`: disabled
- `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED`: disabled
- `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED`: disabled
- `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED`: disabled

No Active jobs were submitted.

## Logs And Exposure Review

Log review:

- traceback/error lines: 0
- generic private-value marker lines: 0
- value-specific hits for generated app and temporary Caddy smoke material: 0

Exposure review:

- temporary Caddy smoke principal was absent after restore;
- Caddy unauthenticated `/` returned `401` after restore;
- backend and audit-tools remained healthy;
- frontend remained up;
- backend, frontend, and audit-tools had no public host port bindings;
- Docker socket mount remained absent for Inspectra services;
- unrelated containers remained present.

Temporary private material cleanup:

- temporary app passphrase file: absent after smoke
- temporary smoke workspace: removed

## Rollback

Rollback was prepared by backing up the VPS-local config before edits. Rollback
was not needed because app auth enablement and smoke passed.

Available rollback remains:

1. restore the backed-up VPS-local Compose override;
2. recreate the backend container;
3. verify Caddy still returns unauthenticated `401`;
4. confirm the app returns to the intended rollback auth mode.

## Operational Note

Because no operator-provided passphrase was available in the execution
environment, the smoke used a generated private passphrase and then deleted it.
Staging app auth is enabled, but regular human access now requires an
operator-held verifier rotation through VPS-private config before broader
sharing.

Recommended follow-up:

```text
APP_LEVEL_AUTH_STAGING_OPERATOR_ACCESS_ROTATION_04
```

Goal: set an operator-held staging verifier through a private process, recreate
backend, and run a short login/logout-only smoke without recording private
values.

## Avoided Actions

This phase did not:

- create a release;
- create a tag;
- push;
- enable Active capabilities;
- run Nmap;
- submit live Active jobs;
- use outside targets;
- take screenshots;
- publish the staging URL;
- modify backend runtime code;
- modify frontend runtime code;
- modify tools runtime code;
- modify `archive/run-all`;
- modify `tools/runner/main.py`.

## Decision

```text
APP_LEVEL_AUTH_STAGING_ENABLE_SMOKE_03_ACCEPTED
```
