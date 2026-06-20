# Active Pre-Alpha Dogfood Findings Triage

Decision: `ACTIVE_PRE_ALPHA_DOGFOOD_FINDINGS_TRIAGE_13_ACCEPTED`

Status: passive dogfood findings were triaged as a product/report-readability
problem. No runtime implementation was changed in this phase.

## Scope

This phase reviewed the completed owned-project passive dogfood record and the
minimum report/analyzer code needed to understand current project archive
finding shape. It did not implement backend, frontend, tools, storage, parser,
endpoint, UI, export, test, deploy, release, tag, Docker, Nmap, network, or
Active behavior changes.

## Local Preflight

Initial local status:

```text
## main...origin/main
```

Recent commits included:

```text
17f3ac0 docs(active): dogfood passive analysis on owned projects
940e31f docs(active): record authed ui passive smoke
29b362e docs(active): record pre-alpha vps deploy smoke
a5aaede docs(active): plan pre-alpha vps deploy
38ff4fc docs(active): record pre-alpha release publication
```

Validation before the record:

- `git diff --check`: passed.
- `git diff --cached --check`: passed.
- no uncommitted runtime changes were present.

No push was attempted in this phase.

## Inputs Reviewed

Primary docs:

- `docs/future/active-pre-alpha-owned-projects-passive-dogfood.md`
- `docs/future/active-pre-alpha-operational-polish.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

Minimal code context:

- `tools/runner/main.py`: project archive finding creation and manifest parsing.
- `frontend/src/projectArchiveReport.ts`: project archive report normalizer.
- `frontend/src/ProjectArchiveJobReport.tsx`: current project archive report view.
- `backend/app/reporting.py`: export/report section generation.
- `frontend/src/auditCatalog.ts`: audit-type catalog grouping.

## Dogfood Pattern

The owned-project dogfood produced useful first-pass signals:

| Project | Findings | Main pattern | Noise |
| --- | ---: | --- | --- |
| `urlbreve` | 4 | dependency pinning plus multi-ecosystem inventory | low |
| `vildek` | 9 | dependency pinning across a larger sanitized app | moderate |
| `inspectra` | 21 | manifest/config self-analysis with dependency pinning, package scripts, and multi-ecosystem inventory | moderate |

The issue is not that the findings are useless. The issue is that they arrive
as a flat list with weak categorization, so the operator must infer which
ecosystem and review theme each item belongs to.

## Category Quality

Current cause:

- project archive findings are emitted with `id`, `title`, `level`,
  `description`, `evidence`, and `recommendation`;
- the runner helper that creates findings has no category or ecosystem field;
- the project archive frontend type also has no category or ecosystem field;
- backend exports can display a category when present, but the project archive
  findings do not provide one;
- dogfood summary scripts therefore counted all project archive categories as
  `unspecified`.

Decision: use a small finding catalog mapping first. The catalog should map
existing project archive finding IDs to stable category and ecosystem metadata
at report-shaping/export/UI boundaries. Analyzer-emitted category fields can be
added later for new analyzers, but the first implementation should not require
new analysis logic.

Minimal category taxonomy for current project archive findings:

| Category ID | Label | Example finding IDs |
| --- | --- | --- |
| `dependency_hygiene` | Dependency hygiene | `dependency_not_exactly_pinned`, `requirements_dependency_not_exactly_pinned`, `dependency_broad_range` |
| `dependency_source_review` | Dependency source review | `dependency_external_or_local_source`, `requirements_editable_install` |
| `package_script_review` | Package script review | `package_scripts_present`, `package_sensitive_lifecycle_script` |
| `ecosystem_inventory` | Ecosystem inventory | `project_archive_multiple_ecosystems` |
| `manifest_parse_limits` | Manifest parsing and limits | `project_archive_manifest_parse_error`, `project_archive_manifest_read_error`, `project_archive_manifest_decode_error`, limit and skip findings |
| `archive_safety_metadata` | Archive safety metadata | project archive path, entry, ZIP preflight, traversal, absolute-path, and non-regular-file findings |

Unknown future IDs should still render safely as `Uncategorized review
indicator`, but the accepted dogfood IDs should no longer collapse there.

## Ecosystem Grouping

Reports should group project archive findings by ecosystem as a second
dimension, separate from category. The first mapping can infer ecosystem from
manifest type, finding ID prefix, evidence path, or existing manifest records.

Recommended ecosystem labels:

- Python / requirements
- Node / package.json
- Docker / Compose
- CI/CD
- Framework/config
- Generic project metadata

Placement:

- dashboard summary: show compact counts by category and ecosystem when a job
  has those fields;
- frontend detail view: group project archive findings by ecosystem, then show
  category pills inside each group;
- report sections: add a "Finding Groups" section before the flat finding list
  or replace the flat list when groups are available;
- exports: include category and ecosystem rows for each finding, then add a
  small category/ecosystem summary table for Markdown, HTML, XML, and PDF.

For the first implementation, project archive detail view and exports matter
more than dashboard changes. Dashboard rollups can follow once the stored
result shape and export rendering are stable.

## Dependency Pinning Noise

Dogfood showed a predictable pattern: pinning findings scale with manifest size.
That signal is useful, but a larger app can make the report feel repetitive.

Decision: preserve individual evidence, but add summary grouping before any
cap or severity change.

Recommended behavior:

- keep individual dependency hygiene findings in Raw JSON and detailed report
  views;
- group repeated pinning findings by ecosystem, manifest path, and dependency
  group;
- show a compact summary such as "8 Python dependency hygiene indicators across
  2 manifests";
- keep severity unchanged for now because lowering it further would hide
  useful review context without fixing readability;
- defer caps until real report examples show that grouping is insufficient.

Deferred options:

- hard cap visible pinning entries per manifest;
- merge all pinning findings into one synthetic finding;
- change severity based only on count.

Those options may be useful later, but they risk hiding useful evidence too
early.

## Review-Indicator Wording

Low/info dependency hygiene findings should keep clear manual-review language.
Preferred wording shape:

- "Review indicator: dependency declaration is not exactly pinned."
- "This affects reproducibility and update review. It is not a confirmed
  security defect."
- "Use exact pins or a lockfile where deterministic installs matter."
- "Inspectra did not install, resolve, execute, or contact registries."

Avoid wording that sounds like an assurance, a target verdict, or a scanner
claim. Reports should keep saying that findings are review indicators and need
operator judgment.

## Sanitizer False-Positive Handling

Broader Inspectra source snapshots were not uploaded because the pre-upload
marker-term scan still reported hits in source/tests. That was the correct
choice for this dogfood: when unsure, narrow the snapshot rather than weakening
the scanner.

Safe approach:

- keep sensitive-value detection fail-closed for real uploads;
- add explicit classification for synthetic tests, fixtures, and intentionally
  redacted examples;
- record path-level classifications without printing sensitive values;
- require an allowlisted fixture/synthetic marker before a hit can be treated
  as safe;
- keep manifest/config-only self-dogfood as a supported snapshot style.

Deferred work:

- a manifest-only self-dogfood fixture that can be reused in local tests;
- separate sanitizer fixture triage after report grouping improves;
- clearer operator notes for "source snapshot skipped, manifest snapshot used."

## Product Impact Ranking

| Rank | Improvement | Product value | Complexity | Safety/redaction risk | Test burden | Alpha usefulness |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | Project finding categories | High | Low | Low | Focused | High |
| 2 | Ecosystem grouping in project reports | High | Medium | Low | Moderate | High |
| 3 | Dependency pinning grouped summaries | Medium | Medium | Low | Moderate | Medium |
| 4 | Review-indicator wording polish | Medium | Low | Low | Focused | Medium |
| 5 | Sanitizer fixture classification design | Medium | Medium | Medium | Moderate | Medium |
| 6 | Dashboard-wide category rollups | Medium | Medium | Low | Moderate | Later |

## Fix Now

Fix project archive finding categories first.

The next implementation should:

- add a small project archive finding metadata catalog keyed by finding ID;
- produce category and ecosystem metadata for current project archive findings;
- keep existing finding IDs stable;
- preserve existing evidence and Raw JSON;
- improve frontend detail view labels for project archive findings;
- include category and ecosystem in exports when present;
- add focused tests for current dogfood finding IDs.

## Defer

Defer:

- new analyzers;
- new active capability work;
- dashboard-wide rollups;
- hard pinning caps;
- sanitizer fixture classification;
- manifest-only reusable self-dogfood fixture;
- broad report redesign across every audit family.

## Never

Do not:

- weaken sensitive-value detection to make source uploads easier;
- hide redaction failures behind category labels;
- turn dependency hygiene into an assurance claim;
- imply complete assessment;
- add network, package manager, registry, code execution, or Active behavior to
  explain passive project archive findings;
- route this through `archive/run-all` or `tools/runner/main.py` orchestration
  changes.

## Recommended Next Phase

Recommended next implementation phase:

```text
PASSIVE_PROJECT_FINDING_CATEGORIES_01
```

Rationale: categories are the smallest useful fix. They reduce dogfood noise,
make exports clearer, and create the metadata foundation for ecosystem grouping
without adding analyzers, network behavior, or broader report redesign.

`PASSIVE_REPORT_ECOSYSTEM_GROUPING_01` should follow after categories exist,
because grouping needs stable metadata to avoid brittle path parsing.

## Acceptance Criteria For Next Phase

`PASSIVE_PROJECT_FINDING_CATEGORIES_01` should be accepted only if:

- project archive findings for the dogfood IDs map to non-empty category labels;
- category metadata is visible in the frontend project archive detail view;
- Markdown, HTML, XML, and PDF exports include category metadata when present;
- unknown finding IDs still render safely with a neutral fallback;
- existing finding IDs, evidence, severity, source delete behavior, owner
  scope, and redaction behavior are preserved;
- focused backend/frontend tests cover the mapping and fallback;
- no new analyzer, network, package install, code execution, Active runtime,
  storage migration, endpoint, deploy, release, or tag behavior is added.

## Decision

```text
ACTIVE_PRE_ALPHA_DOGFOOD_FINDINGS_TRIAGE_13_ACCEPTED
```
