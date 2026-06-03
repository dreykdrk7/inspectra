# Passive Alpha Gap Fixes 05 Disclaimers And Onboarding Copy

Status: `PASSIVE_ALPHA_DISCLAIMERS_ONBOARDING_COPY_ACCEPTED`.

Base retention cleanup reset design: `docs/future/passive-alpha-gap-fixes-04-retention-cleanup-reset-design.md`

Base auth and isolation design: `docs/future/passive-alpha-gap-fixes-03-auth-and-user-isolation-design.md`

Base threat model: `docs/future/passive-alpha-gap-fixes-02-deployment-threat-model.md`

Commit scope: docs-only disclaimer, onboarding, authorized-use, report/export, and forbidden-copy design for future README/docs/UI reuse. This block does not change backend, frontend, runner, tests, fixtures, schemas, storage, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_DISCLAIMERS_ONBOARDING_COPY_ACCEPTED
```

Inspectra should use consistent user-facing copy that sets expectations before upload, before target-based baseline/Active flows, and before report/export sharing. The copy must keep the product framed as a trusted local Passive Alpha with heuristic review indicators, local storage caveats, best-effort redaction, and explicit authorized-use boundaries.

This decision does not implement UI onboarding, terms acceptance, runtime auth, cleanup, storage changes, or any new capability.

## Objective

The copy exists to prevent misunderstandings about:

- trusted local alpha scope;
- local storage of uploaded originals and results;
- best-effort redaction;
- heuristic findings;
- no confirmed vulnerability, exploitability, compromise, or credential-validity claims;
- no execution of uploaded projects or passive config modules;
- explicit authorization required for baseline and internal Active target flows;
- no production, external-user, or multi-user readiness.

## Audiences

### Trusted Local Operator

Needs short, practical copy before uploading data and running local demos. The operator should understand that uploaded originals remain sensitive and stored locally until deleted or cleaned up.

### Internal Reviewer

Needs report and export caveats. The reviewer should treat reports, Raw JSON, SBOMs, and exports as sensitive artifacts even when values are redacted.

### Future Authenticated User

Needs upload, retention, ownership, and authorized-use explanations before using a private/internal or single-tenant hosted deployment.

### Admin / Operator

Needs copy for deployment boundaries, retention caveats, cleanup limitations, log redaction, feature-flagged Active behavior, and unsupported public/SaaS modes.

### External Report Recipient

Needs report-cover copy that explains findings are review indicators, require human validation, and are not proof of exploitation, compromise, breach, credential validity, or live exposure.

## Mandatory Messages

- Inspectra analyzes user-supplied files and archives locally in the trusted alpha posture.
- Uploaded originals may contain secrets and remain sensitive.
- Results, Raw JSON, reports, SBOMs, and exports remain sensitive even when redacted.
- Redaction is best-effort and uses `[REDACTED]`; it does not sanitize uploaded originals.
- Findings are heuristic review indicators and require human validation.
- Inspectra does not validate exploitation, credential validity, compromise, breach, or live reachability for passive modules.
- Passive modules do not execute uploaded projects, package managers, Docker, Docker Compose, Kubernetes, Terraform, OpenTofu, Terragrunt, Nginx, database tools, Redis/Sentinel tools, CI workflows, provider APIs, registries, or CVE/advisory lookups.
- Authorized baseline and internal Active flows require explicit authorization and can create observable DNS or HTTP traffic.
- The internal Active one-HEAD flow is limited, opt-in, feature-flagged, and separate from passive archive analysis.
- Nmap is out of scope.
- Do not upload regulated or highly sensitive customer data without additional controls.
- Trusted local use is not production readiness, public deployment readiness, or multi-user isolation.

## Upload Onboarding Copy

Short reusable upload copy:

```text
Upload only files you are authorized to inspect. Inspectra stores uploaded originals and job results locally. Results, exports, and Raw JSON use best-effort redaction with [REDACTED], but uploaded originals are not sanitized. Do not upload real secrets, regulated data, or production archives unless you accept the local storage and retention behavior.
```

Longer reusable upload copy:

```text
Inspectra Passive Alpha performs bounded local review of uploaded files and archives. It does not execute your project, install dependencies, run package managers, run Docker/Kubernetes/Terraform/Nginx/database/Redis tools, or query CVEs/advisories for passive config modules. Findings are review indicators for human validation, not confirmed vulnerabilities. Reports and exports may contain sensitive metadata; review them before sharing.
```

Pre-upload checklist copy:

- I own or am authorized to inspect this file/archive.
- I understand the original upload is stored locally and is not sanitized by redaction.
- I understand results, Raw JSON, reports, SBOMs, and exports can remain sensitive.
- I understand findings are heuristic review indicators, not confirmed vulnerabilities.
- I will not upload regulated or highly sensitive customer data without additional controls.

## Results And Report Copy

Short reusable report copy:

```text
Findings are heuristic review indicators and require human validation. This report is not proof of exploitation, compromise, breach, credential validity, or live exposure. Redaction is best-effort; exports and Raw JSON may still contain sensitive metadata.
```

Report/export caution:

```text
Treat this report as sensitive. It may include filenames, paths, target names, dependency metadata, configuration signals, errors, redaction notes, and other context useful to an attacker or internal reviewer. Review before sharing outside your trusted audience.
```

No-findings copy:

```text
No findings were reported for this view. This is not a clean bill of health; it only means Inspectra did not report indicators within the current passive, bounded scope.
```

Failed/truncated copy:

```text
This job may be incomplete because parsing failed, limits were reached, or the result is truncated. Review controlled errors, limits, and redaction notes before relying on the output.
```

## Retention And Deletion Copy

Short reusable storage copy:

```text
Uploaded originals and job results remain stored locally until deleted manually or by a future cleanup policy. Deleting data inside Inspectra does not remove reports, SBOMs, Raw JSON, screenshots, or files already downloaded or shared outside the app.
```

Future hosted/single-tenant copy:

```text
Retention and deletion depend on the deployment policy. Source uploads, results, reports, exports, Raw JSON, target history, logs, and backups may have separate retention windows. Review the deployment policy before uploading sensitive data.
```

Backup/snapshot caveat:

```text
App-side deletion may not remove data already captured in host backups, object-store versions, snapshots, browser downloads, email attachments, or external report repositories.
```

## Authorized-Use Copy

Baseline target copy:

```text
Run target-based checks only on domains, URLs, and candidates that you own or are explicitly authorized to assess. Baseline web, DNS, and subdomain jobs can create observable HTTP or DNS traffic.
```

Internal Active one-HEAD copy:

```text
Active HTTP header probe is internal and limited. When enabled, it requires explicit live authorization and sends at most one HTTP HEAD request with no redirects and no body read. That request may appear in target-side logs. Do not use third-party targets as demos.
```

No scan-as-a-service copy:

```text
Inspectra is not a public scanning service. Do not use it to test arbitrary third-party targets, offer scan-as-a-service behavior, bypass target policy, or run broad network activity.
```

Dry-run copy:

```text
Active dry-run is planning only and must report network_requests_sent: 0. It does not send DNS queries, HTTP requests, socket traffic, Nmap commands, or live checks.
```

## Forbidden Wording

Avoid copy that says or implies:

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
- `breach confirmed`
- `compromise confirmed`
- `live exposure confirmed`
- `credentials are active`
- `no secrets`
- `fully sanitized`

These phrases may appear in forbidden-wording lists or no-scope sections, but should not appear as positive product claims.

## Proposed README And Security-Scope Snippets

### README Alpha Disclaimer

```text
Inspectra Passive Alpha is a trusted local technical alpha. It is intended for files, archives, URLs, domains, and explicit candidates that you own or are authorized to review. It is not production-ready, public-user-ready, or multi-user-isolated.
```

### Upload Caution

```text
Uploaded originals are stored locally and may contain secrets. Results, exports, and Raw JSON are redacted best-effort with [REDACTED], but redaction does not sanitize uploaded originals. Use synthetic fixtures for demos and avoid real secrets or production archives.
```

### Report And Export Caution

```text
Reports, exports, SBOMs, and Raw JSON may contain sensitive metadata even after redaction. Findings are review indicators for human validation, not confirmed vulnerabilities, exploitability proof, credential validation, or breach evidence.
```

### Authorized Target Caution

```text
Target-based web, DNS, subdomain, and internal Active flows require explicit authorization. They can create observable DNS or HTTP traffic. Do not use third-party targets as demos or operate Inspectra as a public scan service.
```

### Security-Scope Disclaimer

```text
Passive config modules use bounded local parsing and do not execute uploaded projects, package managers, infrastructure tools, database/cache tools, CI workflows, provider APIs, registry lookups, or CVE/advisory queries. Nmap and broader Active behavior remain out of scope unless separately designed and accepted.
```

## Future Acceptance Model

Future UI may require acknowledgement before upload or target-based flows. This block only designs the acknowledgement content; it does not implement the UI.

Future upload acknowledgement should cover:

- user is authorized to upload and inspect the file;
- uploaded originals are stored and not sanitized by redaction;
- results, exports, Raw JSON, and SBOMs remain sensitive;
- redaction is best-effort;
- findings are heuristic indicators, not confirmed vulnerabilities;
- retention and deletion follow deployment policy.

Future target-flow acknowledgement should cover:

- user owns or is authorized to assess the target;
- baseline/Active flows can create observable DNS or HTTP traffic;
- Active one-HEAD is limited and feature-flagged;
- target policy cannot be bypassed;
- Nmap and broad scans are not included.

Future export acknowledgement should cover:

- reports, SBOMs, and Raw JSON can remain sensitive;
- manual downloads and shared reports are outside app deletion control;
- exported content should be reviewed before sharing.

## Open Questions

- Should the disclaimer appear on home, upload, report, export, and target-flow screens?
- Should upload require a mandatory checkbox?
- Should acknowledgement be stored per user, per session, per upload, or per deployment?
- What minimum legal language is required before external users?
- What copy changes between trusted local mode and hosted single-tenant mode?
- Should every disclaimer have short and long variants?
- Should admin/operator views have separate retention and privileged-access disclaimers?
- Should report exports include a cover note by default?

## Out Of Scope

- No legal final review.
- No UI implementation.
- No terms acceptance implementation.
- No runtime changes.
- No auth runtime.
- No cleanup implementation.
- No database migration.
- No storage schema change.
- No new analyzer.
- No Nmap.
- No Active expansion.
- No production deployment approval.
- No public SaaS approval.
- No target-policy relaxation.
- No local-lab mode.

## Design Implications For Next Block

Next block:

```text
PASSIVE-ALPHA-GAP-FIXES-06-LIMITS-MESSAGING-AND-REPORT-POLISH
```

Limits, file-size messaging, truncation explanations, severity/confidence copy, report empty states, and export polish should reuse this safe copy model:

- use "review indicators" instead of confirmed-vulnerability language;
- explain bounded reads and truncation without implying completeness;
- keep redaction caveats near Raw JSON and exports;
- keep no-findings states away from "safe" or "secure" language;
- make failed/sparse/malformed reports understandable without overclaiming.

## Acceptance Criteria

- Disclaimers are defined.
- Onboarding copy is defined.
- Report/export copy is defined.
- Retention/deletion copy is defined.
- Authorized-use copy is defined.
- Forbidden wording is defined.
- Reusable snippets are defined.
- Future acknowledgement model is defined.
- Limits/report polish block is informed.
- No runtime or capability changes are made.

## No-Scope

- No code.
- No runtime changes.
- No tests or fixture changes.
- No UI implementation.
- No terms acceptance implementation.
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
PASSIVE-ALPHA-GAP-FIXES-06-LIMITS-MESSAGING-AND-REPORT-POLISH
```

Do not proceed directly to UI implementation, terms acceptance, runtime auth, cleanup runtime, storage migrations, Nmap, another Active capability, or a new passive analyzer implementation from this copy-design block.

## Validation Commands

Reference checks for this docs-only block:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
rg -n "vulnerability confirmed|exploitability confirmed|credential valid|safe target|production ready|Nmap ready|guaranteed redaction|secure deletion guaranteed|ownership proof|bypass" README.md docs/architecture.md docs/security-scope.md docs/future/passive-alpha-gap-fixes-0*.md
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
