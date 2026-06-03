# Passive Alpha Gap Fixes 06 Limits Messaging And Report Polish

Status: `PASSIVE_ALPHA_LIMITS_REPORT_POLISH_DESIGN_ACCEPTED`.

Base disclaimers and onboarding copy: `docs/future/passive-alpha-gap-fixes-05-disclaimers-and-onboarding-copy.md`

Base retention cleanup reset design: `docs/future/passive-alpha-gap-fixes-04-retention-cleanup-reset-design.md`

Gap fixes closeout: `docs/future/passive-alpha-gap-fixes-07-closeout.md`

Commit scope: docs-only limits messaging, truncation copy, no-read explanation, severity/confidence wording, report/export polish criteria, and future implementation candidates. This block does not change backend, frontend, runner, tests, fixtures, schemas, storage, reports, exports, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_LIMITS_REPORT_POLISH_DESIGN_ACCEPTED
```

Inspectra should make limits, partial results, no-read sensitive files, sparse payloads, failed jobs, severity, confidence, reports, exports, Raw JSON, SBOMs, and target-based outputs easier to understand without promising complete coverage or adding capabilities.

This decision does not implement UI changes, report/export changes, runtime behavior, new limits, auth, cleanup, or any new analyzer.

## Objective

This block designs safe copy and polish criteria for future UI/report/export work.

The copy should help users understand:

- uploads and analyzers are bounded;
- some files, entries, bytes, fields, and sections may not be reviewed;
- no-read sensitive file detection is intentional and still sensitive;
- severity and confidence are prioritization hints, not proof;
- empty reports do not prove absence of risk;
- failed, sparse, malformed, or legacy payloads need cautious interpretation;
- exports, SBOMs, Raw JSON, and target histories remain sensitive.

## Limit Surfaces

Limits should be visible or explainable across:

- upload screen and docs;
- archive analyzer limits;
- file-size, max-entry, max-file, max-byte, and total-byte messaging;
- no-read sensitive file sections;
- job queued, running, failed, blocked, sparse, malformed, and truncated states;
- report and export headers;
- Raw JSON panel;
- SBOM exports;
- authorized baseline result views;
- internal Active dry-run and one-HEAD result views.

## File-Size And Upload Limits Copy

Short upload-limit copy:

```text
Large files or archives may be rejected, fail, or produce partial results when limits are reached. Review limits, truncation notes, and controlled errors before relying on a report.
```

Trusted local upload caution:

```text
Upload only files you are authorized to inspect. Use synthetic fixtures for demos. Uploaded originals and job results are stored locally and may remain sensitive even when report values are redacted.
```

Future hosted upload caution:

```text
This deployment may enforce upload size, archive entry, file count, file byte, and total byte limits. Limits protect the service and may reduce analyzer coverage. Check the deployment policy before uploading sensitive or large archives.
```

Do not invent concrete values in UI/report copy unless they come from configured limits, stored job limits, or documented deployment policy.

## Truncation And Bounded Analysis Copy

General truncation copy:

```text
Analysis was bounded or truncated. Not all files, entries, bytes, fields, or sections may have been reviewed. Review the limits and controlled errors before acting on the result.
```

Archive truncation copy:

```text
Archive review stopped at configured limits. Listed entries and findings are a partial view of the archive, not a complete inventory.
```

Candidate-file truncation copy:

```text
Only bounded candidate files were reviewed. Additional files may exist outside the reviewed set or beyond byte limits.
```

Avoid:

- "complete scan";
- "full coverage";
- "all files checked";
- "no risk found";
- "safe to deploy".

## No-Read Sensitive File Copy

Reusable no-read copy:

```text
Sensitive adjacent files may be detected by name or path and intentionally not read. Presence is a review indicator, not confirmed exposure. Filenames and paths can still be sensitive.
```

Examples of no-read sensitive files:

- `.env`, `.env.*`, and `.envrc`;
- Terraform state files;
- database dumps, backups, data files, WAL/binlog/InnoDB files;
- Redis ACL, RDB, AOF, appendonly, dump, and backup files;
- credential files;
- private-key-like and certificate-like files;
- referenced env files, secret files, includes, and external paths when a module documents no-read behavior.

Report wording should distinguish:

- detected but not read;
- referenced but not resolved;
- present as sensitive context;
- not validated as exposed, active, or exploitable.

## Severity And Confidence Wording

Recommended severity helper:

```text
Severity estimates potential review priority or impact if the indicator applies in your environment. It is not proof of exploitability, compromise, live exposure, or credential validity.
```

Recommended confidence helper:

```text
Confidence describes how strongly the static pattern matched. It is not proof that the issue is present in production, and low confidence does not mean the indicator should be ignored.
```

No-severity copy:

```text
Missing severity means the payload did not provide a level or the report could not normalize it. It does not mean the item is safe.
```

High-severity caution:

```text
High severity means prioritize review. It does not confirm exploitability or live reachability.
```

Low-confidence caution:

```text
Low confidence means the static signal is weaker or context-dependent. Validate manually before dismissing or acting.
```

Until Inspectra has a formal cross-analyzer severity/confidence model, this wording is a future polish design, not a new scoring contract.

## Empty And No-Findings States

Reusable no-findings copy:

```text
No findings were reported in this bounded view. This is not a clean bill of health and does not prove absence of secrets, vulnerabilities, exposure, or configuration risk.
```

Reusable empty-section copy:

```text
No entries were reported for this section.
```

Reusable no-errors copy:

```text
No controlled errors were reported.
```

Reusable no-redaction-notes copy:

```text
No redaction notes were reported.
```

No-findings states should never say:

- safe;
- secure;
- clean;
- verified;
- no secrets;
- no vulnerabilities;
- production ready.

## Failed, Sparse, And Malformed States

Failed job copy:

```text
The job failed in a controlled state. Review errors below; uploaded content was not executed. The report may be incomplete.
```

Sparse payload copy:

```text
Some result fields are unavailable. Showing available redacted data only.
```

Malformed or legacy payload copy:

```text
This result uses a sparse, malformed, or legacy payload. Inspectra renders available fields best-effort and applies defensive redaction, but missing fields should not be interpreted as absence of risk.
```

Parser error copy:

```text
Parsing failed or was uncertain for part of the input. Review controlled errors and limits before relying on the output.
```

Redaction caveat for failed/sparse states:

```text
Redaction is still applied best-effort. Treat errors, Raw JSON, and exports as sensitive.
```

## Report And Export Polish Checklist

Future reports and exports should:

- include an alpha/trusted-local disclaimer where appropriate;
- include a sensitivity/export warning;
- include limits and truncation sections when relevant;
- include redaction caveats near Raw JSON and exports;
- use "review indicators" and "requires human validation" wording;
- avoid forbidden wording and clean-verdict language;
- show analyzer scope and no-scope where report length allows;
- show generated-at, job ID, analyzer, status, and source/target metadata carefully;
- avoid raw secrets in errors, logs, findings, evidence, headers, URLs, and legacy fields;
- render sparse, malformed, queued, running, failed, and empty states with clear controlled copy;
- make no-read sensitive-file sections visibly different from read/reviewed sections;
- explain whether exports are generated on demand or stored artifacts when that policy exists.

## Raw JSON Polish

Raw JSON should be treated as advanced and sensitive.

Future UI copy:

```text
Raw JSON is intended for debugging and may include metadata, sparse fields, legacy payloads, controlled errors, redaction notes, filenames, or target context. It is redacted best-effort but remains sensitive.
```

Future UI polish candidates:

- place Raw JSON after human-readable sections;
- label it `Redacted Raw JSON`;
- collapse it by default or place it behind an acknowledgement;
- repeat the redaction and local-storage caveat nearby;
- follow job result retention and ownership policy.

## SBOM Export Polish

SBOM export copy:

```text
SBOM exports are generated from available bounded manifest data. They may expose dependency names, versions, paths, URL/VCS declarations, and internal project structure. They are not a complete dependency security audit and do not include registry, CVE, advisory, or installed-version validation unless separately designed.
```

SBOM polish checklist:

- show source job ID and manifest/source context carefully;
- indicate the SBOM reflects declared dependencies only;
- keep omission reasons visible for unsupported or unresolved dependency forms;
- avoid vulnerability-scanner wording;
- warn before sharing externally.

## Authorized Baseline And Active Result Copy

Target-based result copy:

```text
Target-based results may reflect observable DNS or HTTP behavior for the authorized target. They do not prove target safety or complete exposure status.
```

Baseline caution:

```text
Run web, DNS, and subdomain baseline jobs only for targets you own or are explicitly authorized to assess. Results are bounded and may be visible in resolver, server, proxy, or target-side logs.
```

Active one-HEAD caution:

```text
Active HTTP header probe remains internal and limited. When enabled, it sends at most one authorized HTTP HEAD request, follows no redirects, reads no body, and is not a broad scan.
```

Dry-run result copy:

```text
Active dry-run is planning only. It must report network_requests_sent: 0 and must not include live DNS, HTTP, socket, Nmap, or target-response data.
```

## Forbidden Wording Review

Reuse the Block 05 forbidden list:

- `vulnerability confirmed`
- `exploitability confirmed`
- `credential valid`
- `safe target`
- `production ready`
- `Nmap ready`
- `scanner general`
- `bypass`
- `guaranteed redaction`
- `secure deletion guaranteed`
- `ownership proof`
- `clean bill of health`
- `complete scan`

These strings may appear in forbidden-wording lists, no-scope sections, or validation commands. They should not appear as positive product claims.

## Future Implementation Candidates

Docs-only candidates for later implementation:

- visible upload limits on the upload page;
- report cover note;
- truncation badges;
- limits summary cards;
- severity and confidence helper text;
- no-read sensitive-file explainer;
- Raw JSON warning or acknowledgement;
- export sensitivity footer;
- SBOM sensitivity footer;
- no-findings empty-state copy;
- failed/sparse/malformed report explainer;
- analyzer scope/no-scope collapsible sections;
- shared report-shell migration for remaining reports.

Do not implement these in this block.

## Acceptance Criteria

- Limits messaging is defined.
- File-size/upload copy is defined.
- Truncation copy is defined.
- No-read sensitive-file copy is defined.
- Severity and confidence wording is defined.
- Empty/no-findings copy is defined.
- Failed/sparse/malformed state copy is defined.
- Report/export polish checklist is defined.
- Raw JSON, SBOM, authorized baseline, and Active result copy are covered.
- Forbidden wording review criteria are defined.
- Future implementation candidates are listed without implementation.
- No runtime or capability changes are made.

## No-Scope

- No code.
- No runtime changes.
- No tests or fixture changes.
- No UI implementation.
- No report/export implementation.
- No auth implementation.
- No cleanup implementation.
- No DB migration.
- No storage schema change.
- No probes.
- No live traffic.
- No DNS or HTTP.
- No Docker.
- No Nmap.
- No port scanning.
- No crawling.
- No GET fallback.
- No redirects.
- No body reads.
- No custom headers.
- No auth or cookies implementation.
- No fuzzing.
- No exploitation.
- No credential validation.
- No new Active capability.
- No new Passive analyzer implementation.
- No target-policy relaxation.
- No local-lab mode.
- No `.env`, `.env.*`, or `.envrc` reads.
- No push.
- No real tag or release.

## Next Recommendation

```text
PASSIVE-ALPHA-GAP-FIXES-08-IMPLEMENTATION-READINESS-PLAN
```

The gap-fixes closeout is now accepted. The next step should order the P0/P1 implementation sequence, define safe implementation boundaries, identify minimum tests for each runtime control, and keep code changes out of the planning block.

Do not proceed directly to UI implementation, report/export implementation, runtime auth, cleanup runtime, storage migrations, Nmap, another Active capability, or a new passive analyzer implementation from this polish-design block.

## Validation Commands

Reference checks for this docs-only block:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
rg -n "vulnerability confirmed|exploitability confirmed|credential valid|safe target|production ready|Nmap ready|guaranteed redaction|secure deletion guaranteed|ownership proof|bypass|clean bill of health|complete scan" README.md docs/architecture.md docs/security-scope.md docs/future/passive-alpha-gap-fixes-0*.md
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
