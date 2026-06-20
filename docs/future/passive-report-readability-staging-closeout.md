# Passive Report Readability Staging Closeout

Decision: `PASSIVE_REPORT_READABILITY_STAGING_CLOSEOUT_02_ACCEPTED`

Status: the passive project archive report-readability block is closed after
staging dogfood confirmed the category, ecosystem, and dependency pinning
summary improvements on three sanitized operator-owned snapshots.

## Scope

This phase closes the readability block and records the next product decision.
It does not add runtime behavior, redeploy staging, run dogfood again, enable
Active capabilities, run Nmap, use outside targets, take screenshots, create a
tag, create a release, or push.

No backend, frontend, tools, `archive/run-all`, or `tools/runner/main.py`
runtime files are changed by this closeout.

## Reviewed Lineage

Relevant accepted phases:

- `ACTIVE_PRE_ALPHA_DOGFOOD_FINDINGS_TRIAGE_13`
- `PASSIVE_PROJECT_FINDING_CATEGORIES_01`
- `PASSIVE_REPORT_ECOSYSTEM_GROUPING_01`
- `PASSIVE_REPORT_ECOSYSTEM_GROUPING_02_REVIEW`
- `PASSIVE_DEPENDENCY_PINNING_SUMMARY_01`
- `PASSIVE_DEPENDENCY_PINNING_SUMMARY_02_REVIEW`
- `PASSIVE_REPORT_READABILITY_STAGING_REDEPLOY_DOGFOOD_01`

Relevant commits:

- `1375c6e docs(active): triage passive dogfood findings`
- `8b39a1c feat(passive): categorize project archive findings`
- `400bc1f feat(passive): group project findings by ecosystem`
- `8db0db3 fix(passive): harden project ecosystem grouping`
- `5a08a37 feat(passive): summarize dependency pinning findings`
- `94c6378 fix(passive): harden dependency pinning summaries`
- `47a0b0a docs(passive): dogfood report readability on staging`

## Before And After

Before this block:

- project archive findings were useful, but presented mostly as a flat list;
- category information collapsed to an unspecified bucket;
- ecosystem context was weak for mixed Python, Node, Docker, and project
  metadata reports;
- dependency pinning findings could dominate larger reports, making it harder
  to see the pattern before reading individual rows.

After this block:

- category labels are visible for project archive findings;
- ecosystem labels and ecosystem summaries are visible;
- dependency pinning summaries are visible before the detailed findings;
- individual findings remain visible in the detailed result and exports;
- Markdown, HTML, XML, and PDF exports include the improved metadata and
  summaries;
- staging dogfood confirmed the improvements on `urlbreve`, `vildek`, and
  `inspectra`.

## Staging Evidence

Staging URL: `https://inspectra-alpha.urlbreve.es`

Redeploy evidence from the previous phase:

- before deploy: `45a50b8738dd54e43973d6a7568620095cf7f0aa`
- after deploy: `94c63781998eca12c3da831c1736566762207f0a`
- deployed description: `v0.2.0-alpha.1-11-g94c6378`
- Caddy unauthenticated `/`: `401` after dogfood cleanup
- Active gates checked in the deployed backend: disabled
- backend and audit-tools: healthy
- frontend: up
- no direct public host port bindings for Inspectra services
- Docker socket mount absent for Inspectra services

Dogfood jobs:

| Project | Job ID | Status | Findings |
| --- | --- | --- | ---: |
| `urlbreve` | `ff62c48933c84a44acb7f6e9f9c0cb50` | completed | 4 |
| `vildek` | `c087d1145b3841cc8f7b279ae77b3c58` | completed | 9 |
| `inspectra` | `d2e34a7e3384453588e54c5bc410a5e2` | completed | 23 |

Export results:

| Project | Markdown | HTML | XML | PDF |
| --- | --- | --- | --- | --- |
| `urlbreve` | `200/9550` | `200/17049` | `200/16302` | `200/12191` |
| `vildek` | `200/18416` | `200/30607` | `200/29446` | `200/22689` |
| `inspectra` | `200/40907` | `200/64022` | `200/64723` | `200/49029` |

Review and cleanup evidence:

- Raw JSON and exported report marker review: 0 hits.
- backend/audit-tools/frontend log review: 0 traceback/error lines and
  0 sensitive-marker lines in the checked window.
- uploaded source delete calls returned `200` for all three archives.
- temporary Caddy access principal was absent after restore.
- temporary `/tmp` workspace was removed.
- unrelated container name-set delta was 0.

## Product Assessment

The project archive report is now easier to scan for technical-alpha operator
use. Category labels turn the previous flat list into recognizable review
themes, and ecosystem labels make mixed manifests easier to reason about.

Dependency hygiene noise is reduced enough for alpha. Larger manifest snapshots
can still produce many individual hygiene findings, but the summary now shows
the pattern first and preserves detailed evidence for review.

Categories and ecosystems are understandable for the current dogfood cases:

- `urlbreve`: Dependency hygiene and ecosystem inventory are clear for a small
  Python-focused app snapshot.
- `vildek`: repeated Python dependency hygiene findings are easier to scan
  because they summarize across manifests.
- `inspectra`: Node and Python grouping makes the self-analysis report more
  legible than the previous mixed flat list.

Exports are ready for technical-alpha operator use for this report family. The
exported formats include the same improved grouping and remain detailed enough
for review.

Remaining rough edges:

- dependency hygiene can still visually dominate manifest-heavy snapshots;
- broad self-dogfood source snapshots still need conservative fixture/test
  classification before they should be uploaded;
- dashboard-level triage does not yet surface these project archive category
  and ecosystem summaries as first-class rollups;
- other audit families may need a future cleanup pass so category/ecosystem
  conventions feel consistent across the whole product.

## Remaining Backlog

Backlog items kept out of this closeout:

- sanitizer fixture/source-test classification for broader self-dogfood
  snapshot support;
- dashboard-wide category and ecosystem rollups;
- category and ecosystem convention cleanup across other audit families;
- optional hard caps for pinning findings if summaries prove insufficient;
- severity changes only after more dogfood evidence;
- app-level auth staging decision before sharing staging beyond the current
  operator posture.

## Next-Step Decision

Recommended next product step:

```text
APP_LEVEL_AUTH_STAGING_DECISION_01
```

Rationale: the report-readability block is validated enough for the current
technical-alpha staging posture. The next risk is not another report display
increment; it is deciding whether app-level auth should be enabled or hardened
before staging is shared beyond the current operator-only pattern.

If staging remains private/operator-only, the next report-quality item should
be:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_01
```

That path would improve source snapshot support without weakening the current
fail-closed sanitizer discipline.

## No-Go Boundaries

The next phase must not:

- expand Active runtime behavior;
- run Nmap or live Active jobs;
- use outside targets;
- position Inspectra as an internet scanning product;
- weaken sanitization to make uploads easier;
- add version-to-CVE mapping;
- make exploitability or safety assurance claims;
- route this work through `archive/run-all` or `tools/runner/main.py`.

## Decision

```text
PASSIVE_REPORT_READABILITY_STAGING_CLOSEOUT_02_ACCEPTED
```
