# Passive Report Readability Staging Redeploy Dogfood

Decision: `PASSIVE_REPORT_READABILITY_STAGING_REDEPLOY_DOGFOOD_01_ACCEPTED`

Status: current `main` was redeployed to the existing protected staging VPS,
then passive `project_archive_basic` dogfood was repeated on sanitized
operator-owned snapshots. Active capabilities stayed disabled.

## Scope

This phase only redeployed staging and ran passive report-readability dogfood.
It did not create a release, create a tag, promote the staging URL, enable
Active capabilities, run Nmap, submit live Active jobs, use outside targets,
take screenshots, modify `archive/run-all`, or modify `tools/runner/main.py`.

## Local Preflight

Initial local status:

```text
## main...origin/main
```

Recent commits included:

```text
94c6378 fix(passive): harden dependency pinning summaries
5a08a37 feat(passive): summarize dependency pinning findings
8db0db3 fix(passive): harden project ecosystem grouping
400bc1f feat(passive): group project findings by ecosystem
8b39a1c feat(passive): categorize project archive findings
1375c6e docs(active): triage passive dogfood findings
17f3ac0 docs(active): dogfood passive analysis on owned projects
940e31f docs(active): record authed ui passive smoke
```

Validation before the redeploy:

- `git diff --check`: passed.
- `git diff --cached --check`: passed.
- local `HEAD` and `origin/main` both pointed to
  `94c63781998eca12c3da831c1736566762207f0a`.
- no local push was needed.

## Redeploy

Staging URL: `https://inspectra-alpha.urlbreve.es`

Before update:

- VPS app path: `/opt/apps/inspectra`
- deployed commit: `45a50b8738dd54e43973d6a7568620095cf7f0aa`
- deployed description: `v0.2.0-alpha.1`
- checkout state: detached

After update:

- deployed commit: `94c63781998eca12c3da831c1736566762207f0a`
- deployed description: `v0.2.0-alpha.1-11-g94c6378`
- checkout state: local `main`
- latest deployed commits: `94c6378`, `5a08a37`, `8db0db3`,
  `400bc1f`, and `8b39a1c`
- VPS-local `docker-compose.vps.yml` was preserved.

The remote checkout initially did not have a local `main` branch or
remote-tracking `origin/main`. The redeploy fetched
`main:refs/remotes/origin/main` and switched the staging checkout to a local
`main` branch at that ref.

## Compose And Caddy

Compose validation and rebuild:

- combined Compose config with the VPS override: passed.
- backend image: rebuilt.
- frontend image: rebuilt.
- audit-tools image: rebuilt.
- frontend build completed with the existing large-chunk warning.
- Compose recreate completed.

Final service status:

| Service | Status | Public host port binding |
| --- | --- | --- |
| `inspectra-audit-tools` | up and healthy | none |
| `inspectra-backend` | up and healthy | none |
| `inspectra-frontend` | up | none |

Exposure checks:

- Docker socket mount: absent for backend, frontend, and audit-tools.
- backend health: `{"service": "inspectra-backend", "status": "ok"}`.
- Caddy unauthenticated `/`: `401` before and after dogfood.
- authenticated `/`: `200`.
- authenticated JS asset: `200`, 630788 bytes.
- authenticated CSS asset: `200`, 10123 bytes.
- authenticated `/api/health`: `200`, status `ok`.
- app auth status after dogfood: `trusted_local_no_auth`,
  `auth_required=false`, `trusted_local=true`.

The temporary Caddy access principal could not be applied through `caddy reload`
after a host-file replacement because the running proxy kept the original
bind-mounted file inode. The dogfood used a temporary replacement of only the
Inspectra Basic Auth block plus a Caddy proxy restart, then restored the
original Caddyfile and restarted the proxy again. No app runtime file changed.

## Active Disabled

Checked backend Active gates after redeploy:

- `INSPECTRA_ACTIVE_DRY_RUN_ENABLED`: disabled.
- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED`: disabled.
- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED`: disabled.
- `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED`: disabled.
- `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED`: disabled.
- `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED`: disabled.
- `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED`: disabled.
- `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED`: disabled.

## Sanitized Snapshots

Each snapshot was created under `/tmp`, scanned by filename pattern and
conservative sensitive-marker checks, uploaded only after zero hits, then
removed from the VPS temp workspace.

| Project | Shape | Files | Snapshot bytes | Archive bytes | Top level | Guardrail hits |
| --- | --- | ---: | ---: | ---: | --- | --- |
| `urlbreve` | manifest/config-focused source snapshot | 53 | 264055 | 152245 | `app` | 0 |
| `vildek` | heavily sanitized source/config snapshot | 77 | 447502 | 111885 | `app` | 0 |
| `inspectra` | manifest/config-focused self-analysis snapshot | 11 | 119378 | 29911 | `backend`, `docker`, `docker-compose.yml`, `frontend`, `tools` | 0 |

Snapshot notes:

- `urlbreve` was narrowed after a dry-run marker scan flagged three source
  files by path only. Those source paths were omitted before upload.
- `vildek` excluded business-document areas, generated/media areas, runtime
  data, docs, and deployment-only local overrides.
- `inspectra` used a manifest/config-focused self-analysis snapshot rather
  than broad source, test, docs, data, or demo-archive content.

## Dogfood Results

| Project | Job ID | Status | Findings | Categories visible | Ecosystems visible | Pinning summary |
| --- | --- | --- | ---: | --- | --- | --- |
| `urlbreve` | `ff62c48933c84a44acb7f6e9f9c0cb50` | completed | 4 | Dependency hygiene 3; Ecosystem inventory 1 | Python / requirements 3; Generic project metadata 1 | 1 summary |
| `vildek` | `c087d1145b3841cc8f7b279ae77b3c58` | completed | 9 | Dependency hygiene 8; Ecosystem inventory 1 | Python / requirements 8; Generic project metadata 1 | 1 summary |
| `inspectra` | `d2e34a7e3384453588e54c5bc410a5e2` | completed | 23 | Dependency hygiene 21; Package script review 1; Ecosystem inventory 1 | Node / package.json 14; Python / requirements 8; Generic project metadata 1 | 2 summaries |

Severity counts:

| Project | Info | Low |
| --- | ---: | ---: |
| `urlbreve` | 1 | 3 |
| `vildek` | 4 | 5 |
| `inspectra` | 15 | 8 |

Pinning summary examples observed:

- `urlbreve`: Python / requirements summarized 3 dependency pinning review
  indicators across 1 manifest.
- `vildek`: Python / requirements summarized 8 dependency pinning review
  indicators across 2 manifests.
- `inspectra`: Node / package.json summarized 13 dependency pinning review
  indicators across 1 manifest; Python / requirements summarized 8 across
  3 manifests.

Uploaded source delete calls returned `200` for all three uploaded archives
after report/export review.

## Export Results

| Project | Markdown | HTML | XML | PDF |
| --- | --- | --- | --- | --- |
| `urlbreve` | `200/9550` | `200/17049` | `200/16302` | `200/12191` |
| `vildek` | `200/18416` | `200/30607` | `200/29446` | `200/22689` |
| `inspectra` | `200/40907` | `200/64022` | `200/64723` | `200/49029` |

## Readability Comparison

| Project | Previous state | Current state | Result |
| --- | --- | --- | --- |
| `urlbreve` | 4 findings in a flatter report | 4 findings with category, ecosystem, and one pinning summary | clearer small-app triage |
| `vildek` | 9 findings with dependency pinning dominating the list | 9 findings grouped by dependency hygiene and Python requirements summary | easier to scan repeated hygiene items |
| `inspectra` | 21 findings in manifest/config self-analysis | 23 findings with Node and Python ecosystem grouping plus two pinning summaries | clearer mixed-ecosystem self-review |

The readability improvements are visible in both API result shape and exports:

- category labels no longer collapse to an unspecified bucket for these jobs;
- ecosystem summaries separate Python, Node, and generic project metadata;
- dependency pinning summaries preserve individual findings while giving a
  compact count by ecosystem and manifest count;
- individual findings and detailed export sections remain available.

Remaining product notes:

- the dependency hygiene category can still dominate large manifest-heavy
  snapshots, but the summary makes the pattern easier to understand;
- the app-level auth decision remains separate from this staging-only Basic
  Auth posture;
- keep broad source snapshot tuning conservative and continue narrowing rather
  than weakening pre-upload checks.

## Review And Cleanup

Review results:

- Raw JSON and exported report marker review: 0 hits for all completed jobs.
- backend/audit-tools/frontend log review: 0 traceback/error lines and
  0 sensitive-marker lines in the checked window.
- Caddy temporary principal: absent after restore.
- Caddy unauthenticated `/` after restore: `401`.
- unrelated container name-set delta: 0.
- temporary `/tmp` workspace: removed.

No backend, frontend, tools, `archive/run-all`, or `tools/runner/main.py`
repository files were changed during this phase.

## Final VPS Status

Final staging state:

- checkout: `main`
- deployed commit: `94c63781998eca12c3da831c1736566762207f0a`
- description: `v0.2.0-alpha.1-11-g94c6378`
- VPS git status: local untracked `data/.locks/` and
  `docker-compose.vps.yml`, both VPS-local deployment artifacts.
- Inspectra containers: backend and audit-tools healthy; frontend up.
- Caddy route: protected with unauthenticated `401`.

## Recommendation

The passive report readability work is validated on staging for the controlled
owned-project dogfood set. The next product step should be a short docs/product
decision on whether to keep iterating report UX polish or move to app-level
auth hardening for wider private sharing.

Suggested next microphase:

```text
PASSIVE_REPORT_READABILITY_STAGING_CLOSEOUT_02
```

## Decision

```text
PASSIVE_REPORT_READABILITY_STAGING_REDEPLOY_DOGFOOD_01_ACCEPTED
```
