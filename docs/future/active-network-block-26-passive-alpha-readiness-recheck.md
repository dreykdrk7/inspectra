# Active Network Block 26 Passive Alpha Readiness Recheck

Status: `PASSIVE_ALPHA_READINESS_RECHECK_COMPLETED_AFTER_ACTIVE_CLOSEOUT`.

Active Alpha closeout: `docs/future/active-network-block-25-active-alpha-closeout.md`

Passive Alpha closeout/release candidate: `docs/future/passive-alpha-closeout-or-release-candidate.md`

Passive suite closeout: `docs/future/passive-suite-alpha-transversal-closeout.md`

Passive packaging readiness: `docs/future/passive-alpha-packaging-readiness.md`

Passive alpha post-tag handoff: `docs/future/passive-alpha-post-tag-verification-handoff.md`

Post-alpha backlog triage: `docs/future/post-alpha-readiness-backlog-triage.md`

Commit scope: docs-only product/readiness recheck after Active Alpha v0 closeout. This block does not change backend, frontend, runner, tests, fixtures, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_READINESS_RECHECK_COMPLETED_AFTER_ACTIVE_CLOSEOUT
```

No blocker was found that requires reopening Passive module expansion or broadening Active. The current product posture is:

- Passive Alpha remains the main release/readiness line.
- Active Alpha v0 is closed as internal and limited.
- New Active work, Nmap, local-lab mode, or broader live behavior still require a separate explicit product decision.

## Reason For This Recheck

Active Alpha v0 was closed in Block 25 as an internal limited package. That closeout deliberately did not approve production readiness, external-user readiness, Nmap, broader live checks, local-lab mode, policy relaxation, or any additional Active capability.

This recheck returns attention to the overall product alpha posture before any new Active line is opened. It verifies that Passive Alpha documentation, security scope, known gaps, and release wording remain coherent after Active was documented.

## Active State After Closeout

Active is closed only for internal limited use:

- `active_network_dry_run` remains no-network planning.
- `active_http_header_probe` remains the only limited live capability.
- The live capability remains opt-in, disabled by default, explicitly authorized, double-confirmed, target-based, and capped to one HTTP `HEAD` request.
- The accepted smoke evidence is test-double based and does not prove live target truth.
- Active is not production ready.
- Active is not external-user ready.
- Nmap, port scanning, crawling, broader scanning, local-lab mode, and new live capabilities remain out of scope.

This block adds no Active capability and does not relax target policy.

## Passive And Alpha Inventory

Current passive/alpha-visible surfaces from README, architecture, security scope, and recent closeouts:

| Area | Status | Scope summary |
| --- | --- | --- |
| File uploads and file metadata | Implemented / alpha-visible | Local PDF, image, manifest, and archive uploads with local storage and job results. |
| Archive and project-archive analysis | Implemented / alpha-visible | Passive archive metadata and bounded manifest parsing inside archives. |
| SBOM export | Implemented / alpha-visible | Offline SBOMs from completed manifest and project-archive jobs, without package-manager execution or registry lookup. |
| `django_config_basic` | Closed / ready | Archive-only bounded Django config review. |
| `docker_config_basic` | Closed / ready | Archive-only bounded Dockerfile and Docker/Compose review. |
| `secrets_review_basic` | Closed / ready | Archive-only redaction-first secret exposure indicators. |
| `node_package_config_basic` | Closed / ready | Archive-only Node package/config posture review. |
| `ci_cd_config_basic` | Closed / ready | Archive-only CI/CD workflow/config review. |
| `k8s_config_basic` | Closed / ready | Archive-only Kubernetes manifest review. |
| `terraform_config_basic` | Closed / ready | Archive-only Terraform/OpenTofu/Terragrunt review; state files detected but not read. |
| `nginx_config_basic` | Closed / ready | Archive-only Nginx/reverse-proxy review; includes detected but not resolved. |
| `compose_config_basic` | Closed / ready | Archive-only Docker Compose service-wiring review; `.env` and secret files detected but not read. |
| `database_config_basic` | Closed / ready | Archive-only PostgreSQL/MySQL/MariaDB config review. |
| `sql_database_config_basic` | Closed / ready | Archive-only SQL DB config review with data/dump/key/cert no-read context. |
| `redis_config_basic` | Closed / ready | Archive-only Redis/Sentinel config review; ACL/RDB/AOF/backup files detected but not read. |
| `web_basic` | Implemented / authorized baseline | Single authorized URL baseline with bounded HTTP behavior. |
| `domain_basic` | Implemented / authorized baseline | Single authorized domain DNS baseline. |
| `subdomain_inventory_basic` | Implemented / authorized baseline | Explicit candidate-only subdomain inventory. |
| `active_network_dry_run` | Closed / internal Active alpha | No-network planning only. |
| `active_http_header_probe` | Closed / internal limited Active alpha | One authorized HTTP `HEAD` request only when enabled and double-confirmed. |

Passive config modules remain archive-only, bounded, local, heuristic, redaction-first, and no-network. The web/DNS/subdomain families are separate authorized baseline flows with their own documented network/DNS limits.

## Readiness Checklist

Current assessment:

- README is coherent about Passive Alpha scope, local demo limitations, and Active Alpha boundaries.
- Architecture documents the passive archive flow, layered redaction, exports, frontend reports, and Active separation.
- Security scope documents allowed behavior, no-scope, no-read sensitive files, local retention, and Active limitations.
- Passive no-network behavior is clear for archive-based config modules.
- Active is separated and limited.
- No-scope wording is visible for exploitation, credential validation, CVE/advisory lookup, Nmap, port scanning, runtime execution, and broader Active scanning.
- Redaction is documented as best-effort and layered.
- Reports and Markdown/HTML/XML/PDF exports are documented.
- Trusted local demo guidance and synthetic fixture guidance exist.
- Passive release/tag/publish handoff exists.
- Known gaps are already classified for external-user and production readiness.
- Release wording stays prudent: trusted local/passive alpha, not production or external-user readiness.

## Gaps And Blockers

### Blockers Before Alpha General

No blocker was found for the current trusted local/passive alpha posture already documented and published.

This does not mean production readiness or external-user readiness.

### Should-Fix Before Public Technical Alpha Or Wider External Use

- Authentication and deployment hardening.
- Storage retention and cleanup/reset controls.
- Clearer onboarding and local-data deletion guidance.
- Legal/security disclaimer for uploaded content and local storage.
- Multi-user isolation and authorization model.
- Operational deployment threat model.
- More visible limits and file-size messaging.
- Continued report/export readability polish.

### Backlog

- Broader `PassiveReportShell` migration.
- Fixture-driven smoke script.
- Demo reset instructions.
- Cross-analyzer dashboard/summary polish.
- Severity and confidence explanation polish.
- Future passive modules only after explicit re-scope, such as MongoDB, RabbitMQ, Elasticsearch/OpenSearch, or Apache.
- Future Active/Nmap work only through a separate docs-first product decision.

## Residual Risks

- Redaction is best-effort and may miss unusual secret formats or field names.
- Users may over-interpret heuristic findings as confirmed vulnerabilities if copy is not kept careful.
- Active may be mistaken for a general scanner unless it remains clearly described as internal and limited.
- Passive modules do not replace professional review or live validation.
- Malicious or malformed uploaded archives still require sandboxing, limits, and careful local handling.
- Uploaded originals and job results are retained locally according to the MVP data model.
- Synthetic fixtures demonstrate product behavior, not real-world completeness.
- Authorized web/DNS/subdomain flows and Active one-HEAD behavior can create observable target traffic when intentionally used.

## Recommended Product Decision

Recommended next product path:

```text
PASSIVE-ALPHA-CLOSEOUT-OR-RELEASE-CANDIDATE-DOCS-FIRST
```

Rationale:

- Passive Alpha already has a trusted local release record and published prerelease handoff.
- Active Alpha v0 is now closed as internal and limited.
- No blocker was found that requires opening new analyzers or new Active behavior.
- A final product-level closeout/release-candidate pass can reconcile Passive release state, Active internal-alpha boundaries, and remaining external-user blockers before any new line begins.

If product wants hardening before any public-facing step, use:

```text
PASSIVE-ALPHA-GAP-FIXES-01
```

That should focus on external-user blockers, not new analyzers and not Active expansion.

## Relationship With Nmap

Nmap remains out of scope.

This block does not design, implement, enable, test, or approve Nmap. If product wants to discuss Nmap, it must be a separate docs-first decision covering product need, target authorization, safety, threat model, rate limits, redaction, operator copy, testing, no-external-demo-target rules, and explicit acceptance before implementation.

Recommended Nmap path only if product explicitly chooses it:

```text
NMAP-SCOPE-DECISION-DOCS-FIRST
```

## No-Scope

- No code.
- No runtime changes.
- No tests or fixture changes.
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
- No auth or cookies.
- No fuzzing.
- No exploitation.
- No credential validation.
- No new Active capability.
- No new Passive analyzer implementation.
- No target-policy relaxation.
- No local-lab mode.
- No `.env`, `.env.*`, or `.envrc` reads.
- No push.
- No tag or release.

## Next Recommendation

Completed next microphase:

```text
PASSIVE-ALPHA-CLOSEOUT-OR-RELEASE-CANDIDATE-DOCS-FIRST
```

Alternative paths:

- `PASSIVE-ALPHA-GAP-FIXES-01` if product wants to start external-user blockers immediately.
- `NMAP-SCOPE-DECISION-DOCS-FIRST` only if product explicitly chooses to discuss Nmap scope, without implementation.
- `NEXT-LIVE-CAPABILITY-DESIGN-DOCS-FIRST` only if product explicitly chooses to broaden Active after this recheck.

Do not proceed directly from this recheck to runtime implementation of Nmap, another Active capability, or a new passive analyzer.

## Validation Commands

Reference checks for this docs-only block:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
