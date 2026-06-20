# Active Pre-Alpha Authed UI Passive Smoke

Decision: `ACTIVE_PRE_ALPHA_AUTHED_UI_PASSIVE_SMOKE_11_ACCEPTED`

Status: authenticated operator smoke completed through the protected staging
subdomain with Active capabilities left disabled.

## Scope

This phase performed only authenticated UI/API smoke and a minimal passive
project analysis smoke. It did not deploy a new app version, create a tag,
create a release, enable live Active features, run Nmap, submit live Active
jobs, use third-party targets, take screenshots, publish the staging URL, or
modify `archive/run-all` or `tools/runner/main.py`.

## Local Preflight

Initial local status:

```text
## main...origin/main [ahead 1]
```

Recent commits included:

```text
29b362e docs(active): record pre-alpha vps deploy smoke
a5aaede docs(active): plan pre-alpha vps deploy
38ff4fc docs(active): record pre-alpha release publication
45a50b8 docs(active): finalize pre-alpha release notes
7d6ee46 fix(active): validate pre-alpha docker packaging
```

Validation:

- `git diff --check`: passed.
- `git diff --cached --check`: passed.
- no uncommitted runtime changes were present.

The phase 10 docs commit was the only ahead commit. A push was attempted
because the phase plan allowed it, but the execution safety reviewer blocked
the remote write. The smoke continued without relying on that push.

## Environment

- Staging URL: `https://inspectra-alpha.urlbreve.es`
- Release/tag deployed: `v0.2.0-alpha.1`
- Source commit deployed:
  `45a50b8738dd54e43973d6a7568620095cf7f0aa`
- VPS app path: `/opt/apps/inspectra`
- Caddy route: existing Basic Auth pattern for the staging subdomain.

The authenticated smoke used a temporary smoke-only Basic Auth principal so the
existing access value did not need to be printed or stored. The temporary
principal was removed and Caddy was reloaded back to the prior file after the
smoke. A final grep for that temporary principal returned no matches.

Unauthenticated access before and after the smoke returned `401` with the
Caddy Basic Auth challenge.

## UI And API Smoke

Authenticated checks through the staging subdomain:

- frontend `/`: `200`
- frontend title present: true
- frontend asset references present: true
- JavaScript asset: `200`
- CSS asset: `200`
- `/api/health`: `200`
- health status: `ok`
- `/api/auth/status`: `200`
- app auth mode: `trusted_local_no_auth`
- app authenticated flag: false

Active status from the deployed backend remained disabled:

- Active Nmap basic: false
- Active TLS basic: false
- Active DNS inventory: false
- Active DNS OSINT: false

No browser screenshot was taken. Browser-console inspection was not performed in
this phase; the smoke verified the protected frontend document, static assets,
and API routes over HTTPS.

## Passive Project Smoke

Fixture:

- a temporary synthetic owned archive was generated on the VPS for this smoke;
- file count: 5;
- no forbidden fixture file names or fixture marker text were present;
- no repo demo archive was uploaded because those demo packs intentionally
  include redaction-test material outside this phase's upload constraints.

Smoke results:

- archive upload: `201`
- uploaded kind: `archive`
- project-archive launch: `202`
- project job ID: `d4cc81c4f46848f6ba9b6a1b484e9827`
- final job status: `completed`
- audit type: `project_archive_basic`
- result keys included `analyzer`, `archive_type`, `completed_at`, `errors`,
  `file_id`, `file_identification`, `findings`, `hashes`, `limits`,
  `parsed_manifests`, `summary`, and `supported_manifests`
- findings count: 2
- uploaded source file delete was attempted after report/export review

## Report And Redaction Review

Exports completed:

- Markdown export: `200`, 4900 bytes
- HTML export: `200`, 10073 bytes
- XML export: `200`, 8157 bytes
- PDF export: `200`, 6585 bytes

Raw JSON review:

- did not contain the checked sensitive marker terms;
- result shape was useful for a small project archive smoke;
- output produced review indicators rather than proof-style claims;
- UX/report readability was acceptable for alpha smoke;
- noise was low for the tiny fixture, with two findings to inspect.

## Logs And Exposure Review

Recent logs after smoke:

- backend: expected health, upload, project-archive, job, export, and delete
  routes; no tracebacks observed;
- audit-tools: expected project-archive analyzer call; no tracebacks observed;
- frontend: no error output observed.

Exposure checks:

- final Caddy validation passed;
- temporary smoke access principal was absent after rollback;
- unauthenticated staging access returned `401`;
- Inspectra backend, frontend, and audit-tools had no direct host port
  bindings;
- Inspectra containers did not mount the Docker socket;
- unrelated VPS containers remained running.

## Access-Control Decision

Caddy Basic Auth is acceptable for this tightly controlled staging alpha while
the URL is not promoted and operator access remains narrow.

Before broader sharing, add or enable app-level auth for the Inspectra
deployment so Caddy is not the only access-control layer. The deployed app
reported `trusted_local_no_auth`, which is fine for this private smoke but
should not be treated as the long-term staging posture.

## Blockers And Fixes

Blockers:

- Push of the phase 10 docs commit was blocked by execution safety review.

Fixes:

- no repository runtime fix was required;
- temporary Caddy access used for smoke was rolled back.

Rollback actions performed:

- Caddyfile restored from the smoke backup;
- Caddy reloaded after restore;
- temporary smoke files were removed from `/tmp`.

## Next Step

Recommended next microphase:

```text
ACTIVE_PRE_ALPHA_APP_AUTH_STAGING_DECISION_12
```

Goal: decide whether to enable existing app-level auth for staging before any
wider private sharing or additional operator testing.

## Decision

```text
ACTIVE_PRE_ALPHA_AUTHED_UI_PASSIVE_SMOKE_11_ACCEPTED
```
