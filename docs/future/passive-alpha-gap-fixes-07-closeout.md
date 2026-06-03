# Passive Alpha Gap Fixes 07 Closeout

Status: `PASSIVE_ALPHA_GAP_FIXES_DESIGN_LINE_CLOSED`.

Base limits messaging and report polish: `docs/future/passive-alpha-gap-fixes-06-limits-messaging-and-report-polish.md`

Base gap-fixes plan: `docs/future/passive-alpha-gap-fixes-01-plan.md`

Implementation readiness plan: `docs/future/passive-alpha-gap-fixes-08-implementation-readiness-plan.md`

Commit scope: docs-only closeout for the Passive Alpha public/external readiness gap-fixes design line. This block summarizes accepted decisions, design-level gaps, implementation candidates, remaining blockers, residual risks, and the recommended next product path. It does not change backend, frontend, runner, tests, fixtures, schemas, storage, reports, exports, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_GAP_FIXES_DESIGN_LINE_CLOSED
```

The Passive Alpha gap-fixes line is closed at the docs-first design level.

The trusted local Passive Alpha/release-candidate package remains accepted. The public/external should-fix gaps identified after that package are now documented as design decisions, implementation candidates, and remaining runtime blockers. This closeout does not implement those controls.

## Closeout Summary

The gap-fixes line covered the product and deployment hardening work needed before Inspectra can responsibly move beyond trusted local use.

The work closed the gaps as design inputs only:

- deployment threat model;
- auth and user isolation design;
- retention, cleanup, reset, and deletion semantics;
- disclaimers and onboarding copy;
- limits messaging and report/export polish.

No runtime auth, storage isolation, cleanup scheduler, UI acknowledgement, upload-limit UI, report/export implementation, or production deployment hardening was added by this line.

## Accepted Decisions

| Block | Decision | Document |
| --- | --- | --- |
| Gap Fixes 01 | `PASSIVE_ALPHA_GAP_FIXES_01_PLAN_ACCEPTED` | `docs/future/passive-alpha-gap-fixes-01-plan.md` |
| Gap Fixes 02 | `PASSIVE_ALPHA_DEPLOYMENT_THREAT_MODEL_ACCEPTED` | `docs/future/passive-alpha-gap-fixes-02-deployment-threat-model.md` |
| Gap Fixes 03 | `PASSIVE_ALPHA_AUTH_USER_ISOLATION_DESIGN_ACCEPTED` | `docs/future/passive-alpha-gap-fixes-03-auth-and-user-isolation-design.md` |
| Gap Fixes 04 | `PASSIVE_ALPHA_RETENTION_CLEANUP_RESET_DESIGN_ACCEPTED` | `docs/future/passive-alpha-gap-fixes-04-retention-cleanup-reset-design.md` |
| Gap Fixes 05 | `PASSIVE_ALPHA_DISCLAIMERS_ONBOARDING_COPY_ACCEPTED` | `docs/future/passive-alpha-gap-fixes-05-disclaimers-and-onboarding-copy.md` |
| Gap Fixes 06 | `PASSIVE_ALPHA_LIMITS_REPORT_POLISH_DESIGN_ACCEPTED` | `docs/future/passive-alpha-gap-fixes-06-limits-messaging-and-report-polish.md` |

## Gaps Treated

The docs-first line treated these gap categories:

- deployment threat model;
- deployment hardening boundaries;
- auth and authorization;
- single-tenant and future private/internal ownership;
- multi-user isolation boundaries;
- retention, cleanup, reset, and deletion semantics;
- local storage and manual-download caveats;
- legal/security disclaimers;
- onboarding and authorized-use copy;
- forbidden wording;
- visible limits and file-size messaging;
- truncation, no-read, failed, sparse, and malformed result copy;
- severity and confidence wording;
- report, export, SBOM, and Raw JSON polish.

## Resolved At Design Level

The following are now defined as docs-first design inputs:

- supported and unsupported deployment modes;
- actor model, assets, trust boundaries, and threats;
- recommended single-tenant auth/session boundary;
- role concepts and operator/admin boundaries;
- ownership model for uploads, jobs, results, exports, Raw JSON, and target histories;
- authorization matrix;
- service/background-job isolation expectations;
- retention classes;
- deletion semantics and caveats;
- trusted local reset workflows;
- disclaimers and onboarding copy;
- authorized-use copy for file, archive, baseline, and Active flows;
- forbidden wording list;
- upload limits, truncation, and no-read sensitive-file copy;
- severity and confidence helper wording;
- no-findings, failed, sparse, and malformed result copy;
- report/export polish checklist;
- Raw JSON, SBOM, and target-output sensitivity copy.

## Not Implemented

This line does not implement:

- auth runtime;
- login UI;
- sessions, cookies, CSRF, CORS, TLS, or reverse-proxy hardening;
- DB migrations;
- `owner_id`, `workspace_id`, or tenant-aware storage;
- owner-scoped API authorization;
- anonymous-read denial in runtime;
- delete/reset UI;
- cleanup scheduler;
- admin cleanup tooling;
- storage schema changes;
- report/export runtime polish;
- UI acknowledgement;
- visible upload-limit UI;
- Raw JSON warning UI;
- production deployment hardening.

## Implementation Candidates

### P0 Implementation Candidates

These block public/external runtime use:

- single-tenant auth/session boundary;
- no anonymous reads for uploads, jobs, results, reports, exports, Raw JSON, and target histories;
- owner-scoped uploads, jobs, results, reports, exports, and Raw JSON;
- service/background jobs processing only authorized jobs;
- delete source/job/result semantics;
- basic retention and local cleanup controls;
- deployment hardening checklist for host binding, TLS/reverse proxy, cookies/sessions, CORS/CSRF, logs, secrets, backups, and admin access.

### P1 Implementation Candidates

These improve trust and first-use clarity:

- onboarding/disclaimer UI;
- upload acknowledgement;
- target-flow authorization acknowledgement;
- visible upload limits and file-size messaging;
- truncation and partial-result messaging;
- no-read sensitive-file explainer;
- Raw JSON and export warnings.

### P2 Implementation Candidates

These are report and workflow polish:

- report/export polish;
- severity and confidence helper text;
- no-findings, failed, sparse, and malformed state polish;
- PassiveReportShell migration for remaining reports;
- SBOM export sensitivity footer;
- fixture-driven smoke script for trusted local demos.

## Remaining Blockers Before Public Or External Runtime

The design line is closed, but public or external runtime use remains blocked until implementation and review cover:

- auth and authorization;
- ownership enforcement;
- anonymous-read denial;
- owner-scoped reports, exports, Raw JSON, and target histories;
- retention and deletion controls;
- deployment hardening;
- onboarding and disclaimers surfaced in UI/docs;
- visible upload and analyzer limits;
- log/error/export redaction review;
- security review of the deployed shape.

## Product Readiness Statement

- Trusted local Passive Alpha: accepted.
- Public/external runtime: not ready.
- Private/internal or single-tenant hosted use: design path exists; implementation is pending.
- Multi-tenant SaaS: out of scope.
- Active Alpha: internal and limited only.
- Nmap: out of scope unless a separate docs-first decision explicitly scopes it.

## Residual Risks

- Docs are accepted, but runtime controls are absent.
- Trusted local users can still retain, copy, export, or share sensitive files and reports manually.
- Uploaded originals remain sensitive even when reports are redacted.
- Redaction is best-effort and may miss uncommon secret formats.
- Reports and exports may still be over-interpreted as stronger evidence than heuristic review indicators.
- External deployment without the P0 controls would be unsafe for untrusted users.
- Manual downloads, host backups, snapshots, browser caches, and external report repositories remain outside app cleanup control.

## Recommended Next Path

Recommended next microphase:

```text
PASSIVE-ALPHA-P0-01-AUTH-BOUNDARY-DESIGN-TO-RUNTIME-PLAN
```

The implementation readiness plan is now accepted. The next step should define the auth/session boundary and trusted local default-operator compatibility before storage ownership, API guards, delete semantics, or public/external runtime claims.

Alternative future paths:

- `PASSIVE-ALPHA-TRUSTED-LOCAL-RELEASE-NOTES` if the product wants to prepare local/trusted release copy before P0 implementation planning.

Do not proceed directly to runtime auth, migrations, cleanup runtime, report/export implementation, Nmap, another Active capability, or a new passive analyzer from this closeout.

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

## Acceptance Criteria

- All gap-fix decisions are summarized.
- The difference between implemented runtime and docs-first design is clear.
- Treated gaps are consolidated.
- Design-level resolutions are listed.
- Not-implemented runtime controls are explicit.
- Implementation candidates are prioritized as P0/P1/P2.
- Public/external runtime blockers are clear.
- Product readiness statement is explicit.
- Residual risks are documented.
- Next path is recommended.
- No runtime or capability changes are made.

## Validation Commands

Reference checks for this docs-only closeout:

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
