# App-Level Auth Staging Operator Access Rotation

Decision: `APP_LEVEL_AUTH_STAGING_OPERATOR_ACCESS_ROTATION_04_ACCEPTED`

Status: staging app-level auth was rotated to an operator-held verifier and
login/logout smoke passed behind the existing Caddy Basic Auth layer.

## Scope

This phase changed only VPS-private staging auth configuration and recreated
the backend container so the existing `self_hosted_single_admin` mode could use
the operator-held verifier. It did not create a release, create a tag, push,
enable Active capabilities, run Nmap, submit live Active jobs, use outside
targets, take screenshots, modify backend/frontend/tools runtime code, modify
`archive/run-all`, or modify `tools/runner/main.py`.

## Staging Target

- Staging URL: `https://inspectra-alpha.urlbreve.es`
- Target posture: Caddy Basic Auth plus app-level
  `self_hosted_single_admin`
- Auth state store: SQLite
- Caddy Basic Auth: preserved as the outer layer
- Active posture: disabled before and after smoke

## Local Preflight

- initial local status: `## main...origin/main`
- `git diff --check`: passed
- `git diff --cached --check`: passed
- no uncommitted runtime changes were present

## VPS Preflight

- `/opt/apps/inspectra` checkout: `main`
- deployed commit: `94c6378`
- Caddy unauthenticated `/`: `401`
- backend: running and healthy
- audit-tools: running and healthy
- frontend: running
- app auth mode: `self_hosted_single_admin`
- auth state store: `sqlite`
- app auth configured: true
- configured verifier format: supported
- Inspectra backend, frontend, and audit-tools had no public host port bindings
- Docker socket mount was absent for backend, frontend, and audit-tools

## Backup And Config Categories

Backups created during the rotation attempts:

- `/opt/apps/inspectra/data/backups/operator-access-rotation-20260621T102733Z`
- `/opt/apps/inspectra/data/backups/operator-access-rotation-20260621T103054Z`
- `/opt/apps/inspectra/data/backups/operator-access-rotation-20260621T105422Z`

Backed up categories:

- VPS-local Compose override
- Caddyfile before temporary smoke access
- `.env` backup was absent because no `.env` file was present

VPS-private config category changed in the accepted attempt:

- `INSPECTRA_ADMIN_PASSWORD_HASH`

Preserved categories:

- `INSPECTRA_AUTH_MODE=self_hosted_single_admin`
- `INSPECTRA_AUTH_STATE_STORE=sqlite`
- all checked Active feature flags remained disabled

No private auth values are recorded in this document.

## Rotation

The operator-held passphrase was supplied through a local FIFO handoff. It was
not pasted into chat, passed as a command argument, committed, or retained after
the smoke command completed.

The VPS generated the supported app verifier privately and updated only the
existing verifier category in the VPS-local Compose override. The backend
Compose config validated successfully, the backend container was recreated, and
the backend returned healthy.

## Caddy Smoke Access

Caddy Basic Auth was not weakened or removed. A temporary Caddy smoke principal
was added only to the `inspectra-alpha.urlbreve.es` site block so the bounded
smoke could run through the same public route as an operator.

Results:

| Check | Result |
| --- | --- |
| Caddy unauthenticated `/` before rotation | `401` |
| Caddy unauthenticated `/` during smoke | `401` |
| Caddy authenticated `/` during smoke | `200` |
| Caddy unauthenticated `/` after restore | `401` |
| temporary Caddy smoke principal after restore | absent |

## Login/Logout Smoke

Through Caddy Basic Auth:

| Check | Result |
| --- | --- |
| `/api/auth/status` before app login | `200`, auth required, unauthenticated, configured |
| app login | `200`, authenticated as `local-admin` |
| `/api/auth/status` after login | `200`, authenticated, CSRF value present |
| app logout | `200`, authenticated false |

No app secret material, Caddy verifier material, session values, CSRF values,
or private config values were recorded.

## Denied After Logout

After logout, a fresh session attempted a Markdown export route through Caddy.

| Route class | Result |
| --- | --- |
| Markdown export | `401` |

This confirms app-level auth remained enforced after logout.

## Active Disabled

Checked before and after smoke:

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

- traceback lines: 0
- private-value marker lines: 0
- value-specific hits for the operator-held app material and temporary Caddy
  smoke material: 0

Exposure review:

- backend host ports: absent
- frontend host ports: absent
- audit-tools host ports: absent
- backend Docker socket mount: absent
- frontend Docker socket mount: absent
- audit-tools Docker socket mount: absent

Final app auth state:

- auth mode: `self_hosted_single_admin`
- auth state store: `sqlite`
- configured: true

## Blockers, Fixes, And Rollback

Two pre-acceptance attempts updated the verifier category and recreated the
backend, but failed before app login smoke completed. Both attempts restored the
previous VPS-local Compose override and recreated the backend as planned.

The useful diagnosis was Caddyfile structure: more than one `basic_auth` block
exists, and the initial temporary-principal insertion targeted the first block
instead of the `inspectra-alpha.urlbreve.es` site block. The accepted attempt
limited the temporary insertion to the Inspectra site block, then restored the
original Caddyfile after smoke.

Rollback remains available from the accepted backup path:

```text
/opt/apps/inspectra/data/backups/operator-access-rotation-20260621T105422Z
```

Rollback was not used after the accepted attempt because the smoke passed.

## Recommendation

Recommended next product step:

```text
APP_LEVEL_AUTH_STAGING_PRIVATE_OPERATOR_SIGNOFF_05
```

Suggested scope: have the operator log in through the normal browser flow behind
Caddy, verify the Passive Alpha dashboard and exports are reachable with the new
operator-held access material, and keep Active disabled unless a separate phase
explicitly enables it.

## Decision

```text
APP_LEVEL_AUTH_STAGING_OPERATOR_ACCESS_ROTATION_04_ACCEPTED
```
