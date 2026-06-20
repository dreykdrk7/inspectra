# Active Pre-Alpha Owned Projects Passive Dogfood

Decision: `ACTIVE_PRE_ALPHA_OWNED_PROJECTS_PASSIVE_DOGFOOD_12_ACCEPTED`

Status: passive project/archive dogfood completed against sanitized snapshots of
three operator-owned projects on the deployed Inspectra alpha. Active
capabilities remained disabled.

## Scope

This phase used only passive `project_archive_basic` analysis on sanitized
project snapshots. It did not deploy a new version, create a tag, create a
release, enable Active capabilities, run Nmap, submit live Active jobs, use
outside targets, take screenshots, publish the staging URL, or modify
`archive/run-all` or `tools/runner/main.py`.

## Local Preflight

Initial local status:

```text
## main...origin/main [ahead 2]
```

Recent commits included:

```text
940e31f docs(active): record authed ui passive smoke
29b362e docs(active): record pre-alpha vps deploy smoke
a5aaede docs(active): plan pre-alpha vps deploy
38ff4fc docs(active): record pre-alpha release publication
45a50b8 docs(active): finalize pre-alpha release notes
```

Validation before the record:

- `git diff --check`: passed.
- `git diff --cached --check`: passed.
- no uncommitted runtime changes were present.

No push was attempted in this phase.

## Environment

- Staging URL: `https://inspectra-alpha.urlbreve.es`
- Release/tag deployed: `v0.2.0-alpha.1`
- VPS app path: `/opt/apps/inspectra`
- App auth mode observed in the prior smoke: `trusted_local_no_auth`
- Staging access: existing Caddy Basic Auth pattern

A temporary dogfood-only Caddy Basic Auth principal was used so the existing
access value did not need to be printed or stored. The temporary principal was
removed after the run; a final search for the dogfood principal name returned
no matches, and Caddy validation passed with only the known formatting warning.

Unauthenticated access to the staging URL returned `401` with a Caddy Basic
Auth challenge after the dogfood run.

## VPS Preflight

Final Compose status:

- `inspectra-audit-tools`: up and healthy.
- `inspectra-backend`: up and healthy.
- `inspectra-frontend`: up.

Checked Active flags were all `false`:

- `INSPECTRA_ACTIVE_DRY_RUN_ENABLED`
- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED`
- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED`
- `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED`
- `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED`
- `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED`
- `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED`

Exposure checks:

- backend, frontend, and audit-tools had no direct host port bindings;
- backend and audit-tools mounted only `/app/data`;
- frontend had no data mount;
- the Docker socket was not mounted into Inspectra containers;
- unrelated VPS containers remained running.

## Sanitization

Snapshots were built under `/tmp` and uploaded only after a manifest check,
forbidden filename scan, and conservative marker-term scan. Live project
directories were not uploaded directly.

Common high-risk categories were excluded, including repository metadata,
environment-value files, key/certificate material, database dumps, backups,
runtime data, generated output, logs, cache directories, dependency installs,
and VPS-local override files.

Project-specific handling:

- `urlbreve`: source-focused snapshot, excluding runtime data and deployment
  material.
- `vildek`: heavily narrowed snapshot, excluding media, generated documents,
  quote/invoice/order/payment areas, private storage, backups, runtime data,
  and generated output.
- `inspectra`: broad and narrowed source snapshots were not uploaded after the
  marker-term scan still reported hits in source/tests. A final
  manifest/config-focused self-analysis snapshot was used instead.

All final uploaded snapshots had zero forbidden filename hits and zero
marker-term hits.

## Archive Manifest Summary

| Project | Snapshot shape | Files | Snapshot bytes | Archive bytes | Included top level | Excluded category summary |
| --- | --- | ---: | ---: | ---: | --- | --- |
| `urlbreve` | source-focused | 46 | 107801 | 38571 | `app` | repository metadata, docs, forbidden filename patterns, project-specific high-risk surfaces, unsupported file types |
| `vildek` | heavily sanitized source/config | 65 | 388782 | 98037 | `app`, `env` | repository metadata, CI metadata, deploy backup path, backups, runtime data, docs, forbidden filename patterns, quote/business-document areas, unsupported file types |
| `inspectra` | manifest/config-focused self-analysis | 13 | 121431 | 31261 | `backend`, `docker`, `frontend`, `tools`, root manifests | broad source/tests, docs, archives, data, demo archive fixtures, large files, project-specific high-risk surfaces, unsupported file types |

## Upload, Analyze, Export

| Project | Audit type | Job ID | Job status | Findings | Severity counts | Finding code themes | Export results | Source delete |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- |
| `urlbreve` | `project_archive_basic` | `3da9719e49774f25a8363de3fba632f3` | `completed` | 4 | info 1, low 3 | `requirements_dependency_not_exactly_pinned`, `project_archive_multiple_ecosystems` | Markdown `200/6555`, HTML `200/12306`, XML `200/10909`, PDF `200/8677` | `200` |
| `vildek` | `project_archive_basic` | `92f2146bf73f45fdb44286f98555ab1d` | `completed` | 9 | info 4, low 5 | `dependency_not_exactly_pinned`, `requirements_dependency_not_exactly_pinned`, `project_archive_multiple_ecosystems` | Markdown `200/13514`, HTML `200/22897`, XML `200/20692`, PDF `200/16843` | `200` |
| `inspectra` | `project_archive_basic` | `b417c7df586543cdbdde5e2b2ea9010e` | `completed` | 21 | info 15, low 6 | `requirements_dependency_not_exactly_pinned`, `package_scripts_present`, `dependency_not_exactly_pinned`, `project_archive_multiple_ecosystems` | Markdown `200/28491`, HTML `200/44904`, XML `200/42586`, PDF `200/34474` | `200` |

Raw result/export marker review for the completed jobs reported no marker hits.

## Comparison

| Project | Alpha usefulness | Noise | Notes | Follow-up ideas |
| --- | --- | --- | --- | --- |
| `urlbreve` | Good small-app sanity check | Low | Quickly surfaced dependency pinning and multi-ecosystem review indicators. | Keep as a small regression dogfood case. |
| `vildek` | Good larger owned-app check | Moderate | More findings because the app has more manifests and mixed ecosystem shape; sanitizer discipline was essential. | Add clearer grouping by ecosystem and finding code. |
| `inspectra` | Useful self-analysis, but constrained | Moderate | Manifest/config snapshot worked; broader source snapshots need better local sanitizer tuning before upload. | Add a manifest-only dogfood fixture and improve source/test marker classification. |

## Report Usefulness

The passive project archive report is useful as a first inventory and sanity
layer for alpha operators. It made dependency pinning, package script, and
multi-ecosystem indicators visible across very different owned projects without
needing runtime behavior.

The main product gaps are presentation rather than execution:

- categories still collapse to `unspecified`, which makes triage less helpful;
- dependency pinning findings can dominate larger projects;
- ecosystem grouping would make the report easier to scan;
- the report would benefit from clearer "review indicator" copy around
  low-severity dependency hygiene findings.

## Redaction Review

The final uploaded snapshots passed the pre-upload manifest and marker-term
checks. Raw JSON and exported report reviews for the final completed jobs
reported no marker hits. The generated reports stayed at finding/manifest
summary level and did not paste uploaded source contents into logs reviewed in
this phase.

Uploaded source files were deleted through the app after report/export review;
each delete returned `200`.

## Logs And Exposure Review

Recent logs after dogfood:

- backend: expected health, upload, project-archive, job, export, and source
  delete routes; no tracebacks observed;
- audit-tools: expected project-archive analyzer calls; no tracebacks observed;
- frontend: no error output observed.

Exposure after dogfood:

- Caddy validation passed;
- temporary dogfood access principal was absent after rollback;
- unauthenticated staging access returned `401`;
- Inspectra containers had no direct host port bindings;
- Inspectra containers did not mount the Docker socket;
- unrelated VPS containers remained running.

## Cleanup

Cleanup completed:

- temporary dogfood directories under `/tmp` were removed using the remote
  owning account;
- temporary archives and staging files were removed;
- uploaded source files were deleted through the app after export review;
- temporary Caddy access was removed;
- no repository runtime cleanup was needed.

## Blockers And Fixes

Resolved blockers:

- The first sanitizer pass over-blocked source/docs/auth-heavy paths. The
  final run used narrower snapshots.
- Inspectra source-focused snapshots were not uploaded after marker-term hits
  remained. The accepted self-analysis used a manifest/config-focused snapshot.
- Initial `/tmp` cleanup failed from the narrower SSH account because the files
  were owned by the remote deploy account. Cleanup succeeded after connecting
  as the owning account.

Fixes:

- no backend, frontend, tools, `archive/run-all`, or `tools/runner/main.py`
  changes were made;
- no deploy-only fix was required.

## Access-Control Note

Caddy Basic Auth remains acceptable for this private operator dogfood while the
staging URL is not promoted. Before broader private sharing, app-level auth
should be added or enabled so Caddy is not the only access-control layer.

## Avoided Actions

This phase did not:

- enable Active capabilities;
- run Nmap;
- submit live Active jobs;
- perform DNS/TLS/CT/HTTP live target actions;
- use outside targets;
- take screenshots;
- create a tag;
- create a release;
- deploy a new version;
- modify backend runtime;
- modify frontend runtime;
- modify tools runtime;
- modify `archive/run-all`;
- modify `tools/runner/main.py`;
- push commits.

## Recommendation

Recommended next microphase:

```text
ACTIVE_PRE_ALPHA_DOGFOOD_FINDINGS_TRIAGE_13
```

Goal: triage the dogfood findings and report UX gaps without expanding runtime
behavior. Focus on category grouping, ecosystem grouping, dependency pinning
noise, and sanitizer false-positive handling. Keep app-level auth staging
decision work separate unless the next phase is about broader private sharing.

## Decision

```text
ACTIVE_PRE_ALPHA_OWNED_PROJECTS_PASSIVE_DOGFOOD_12_ACCEPTED
```
