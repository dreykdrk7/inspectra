# Passive Alpha Gap Fixes 02 Deployment Threat Model

Status: `PASSIVE_ALPHA_DEPLOYMENT_THREAT_MODEL_ACCEPTED`.

Base plan: `docs/future/passive-alpha-gap-fixes-01-plan.md`

Trusted local closeout: `docs/future/passive-alpha-closeout-or-release-candidate.md`

Auth and user isolation design: `docs/future/passive-alpha-gap-fixes-03-auth-and-user-isolation-design.md`

Open-source/self-hosted framing: `docs/future/passive-alpha-p0-00-open-source-self-hosted-product-framing.md`

Commit scope: docs-only deployment threat model for public/external readiness gap fixes. This block does not change backend, frontend, runner, tests, fixtures, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_DEPLOYMENT_THREAT_MODEL_ACCEPTED
```

Inspectra Passive Alpha remains accepted for trusted local use only. The deployment threat model is now the guiding boundary for the next public/external readiness design blocks: authentication and user isolation, retention/cleanup/reset, disclaimers/onboarding, and limits/report polish.

This decision does not approve production deployment, public external-user access, commercial SaaS, subscription plans, multi-tenant SaaS, Nmap, broader Active behavior, new passive analyzers, or any runtime implementation.

## Deployment Modes

### Supported Now

- Trusted local single-operator or developer workstation.
- Local demo using only fixtures and synthetic data.

These modes assume the operator controls the local machine, understands that uploads and job results are stored locally, and does not upload production secrets or regulated customer archives.

### Conditionally Future

- Private team or internal network deployment.
- Self-hosted single-instance server.
- Dedicated single-instance hosted deployment controlled by the operator.
- Optional public/community hosted instance with strict limits and disclaimers.

These modes are possible only after explicit controls are designed and implemented for authentication, authorization, file/job ownership, user isolation, retention, cleanup, deployment hardening, audit/log redaction, and secure export handling.

In this document, "hosted" and "public/external" do not mean commercial SaaS. They mean usage beyond a trusted local operator boundary, such as an operator-run self-hosted server, a private/internal install, or an optional public/community convenience instance.

### Unsupported Now

- Public unauthenticated internet deployment.
- Commercial SaaS by subscription.
- Multi-tenant SaaS.
- Broad enterprise tenant platform.
- Untrusted arbitrary external users.
- Processing regulated or highly sensitive customer data without additional controls.
- Public Active, Nmap, network-scan, or scan-as-a-service deployment.

## Actors

- Trusted local operator: runs Inspectra locally and owns the uploaded test data.
- Internal reviewer: reviews reports or exports shared inside a trusted team.
- Future authenticated user: may upload files and create jobs after auth/isolation is implemented.
- Unauthenticated visitor: can reach the app if it is accidentally exposed without auth.
- Malicious uploader: submits hostile archives, oversized files, parser edge cases, or secret-bearing content.
- Curious or overprivileged operator: can inspect local storage, reports, exports, or logs beyond the intended review path.
- External target owner: may be affected by authorized baseline web/DNS/subdomain flows or internal Active one-HEAD flows.
- Attacker with local filesystem or export access: reads uploaded files, results, reports, Raw JSON, or generated exports from disk or shared artifacts.

## Assets And Sensitive Data

- Uploaded archives and files under local storage.
- Extracted metadata and bounded parser summaries.
- Job records and stored JSON results.
- Markdown, HTML, XML, and PDF reports/exports.
- Raw JSON shown in the UI or returned by API endpoints.
- Detected secrets, secret-like strings, credentials, tokens, key material, and redaction notes.
- Target URLs and domains for authorized baseline flows and internal Active flows.
- Local storage paths, filenames, source-file metadata, and deletion markers.
- Logs or audit entries when present.

Uploaded originals remain sensitive even when results and exports are redacted. Redaction reduces exposure in derived surfaces; it does not sanitize stored source files.

## Trust Boundaries

- Browser/frontend boundary: user input, report rendering, Raw JSON display, and export links cross from local browser UI into backend API calls.
- Backend API boundary: upload, audit creation, job reads, deletion, and export endpoints receive untrusted user input.
- Local filesystem/storage boundary: uploaded originals and job results are stored on disk and can be accessed by local operators or processes with filesystem access.
- Analyzer/parser boundary: untrusted archives and files enter bounded local parsers and tool-runner workflows.
- Report/export boundary: stored job JSON is transformed into Markdown, HTML, XML, and PDF artifacts that may be shared outside the app.
- Optional authorized network baseline boundary: `web_basic`, `domain_basic`, and `subdomain_inventory_basic` can create observable HTTP/DNS traffic for explicitly authorized targets.
- Internal Active boundary: `active_network_dry_run` is no-network; `active_http_header_probe` is a separate internal one-HEAD capability gated by feature flag and explicit live authorization.
- Future auth/session boundary: any external-user deployment must define session identity, ownership, permissions, and administrative access.

## Data Flows

### Passive Upload And Reporting

1. User uploads a local file or archive.
2. Backend validates and stores the source file locally.
3. User starts a matching audit job.
4. Backend calls the internal runner with a relative path and configured limits.
5. Runner performs bounded passive analysis without executing archive contents.
6. Runner returns redaction-first structured JSON.
7. Backend stores the job result and applies defensive redaction for sensitive modules and legacy payloads.
8. API, frontend reports, Raw JSON, and Markdown/HTML/XML/PDF exports render from stored job data.

### Archive Parsing

Archive-based config modules inspect metadata and bounded candidate text. They do not extract archives broadly, follow symlinks or hardlinks, execute project code, install dependencies, run package managers, run Docker/Kubernetes/Terraform/Nginx/database/Redis tools, or call registries/CVEs/advisories.

### No-Read Sensitive Detection

Some modules detect sensitive adjacent files such as `.env`, state files, database dumps, ACL/RDB/AOF files, backups, data files, credential files, and referenced secret/env files. Those files are recorded as present with safe context and are not read by the analyzer.

### Redaction Pipeline

Sensitive-looking values should be redacted as early as practical in runner output and again across backend storage/reporting, public API payloads, exports, frontend reports, and frontend Raw JSON. The fixed placeholder remains `[REDACTED]`. The system should not intentionally emit secret prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

### Authorized Baseline And Active Flows

`web_basic`, `domain_basic`, and `subdomain_inventory_basic` are authorized baseline flows that can create bounded, observable DNS or HTTP traffic. They are not passive archive analyzers.

`active_http_header_probe` is a separate internal limited Active alpha flow: feature-flagged, double-confirmed, target-based, and capped to one HTTP `HEAD` request with no redirects and no body read. `active_network_dry_run` remains no-network and must preserve `network_requests_sent: 0`.

## Threats

- Malicious archive or file causes parser errors, excessive memory use, high CPU use, or resource exhaustion.
- Zip-slip, path traversal, absolute paths, symlinks, or hardlinks attempt to escape intended archive handling.
- Decompression bombs, huge files, or many-entry archives exceed reasonable local processing limits.
- Secrets leak through UI, reports, exports, Raw JSON, controlled errors, job summaries, logs, or legacy/malformed payloads.
- Unauthorized users access uploaded files, job results, reports, or exports when the app is exposed beyond a trusted local operator.
- Future multi-user deployments leak files/jobs/results across users or teams.
- Stale sensitive data remains in local uploads, results, exports, browser downloads, or shared reports longer than intended.
- Operators overclaim heuristic findings as confirmed vulnerabilities, proof of exploitation, credential validity, breach evidence, or live reachability.
- Local app is accidentally exposed on a network without auth or deployment hardening.
- Authorized baseline or Active target fields are misused for SSRF-like requests, private-target probing, or unwanted traffic.
- Future Active or Nmap work is abused if added without separate authorization, target policy, rate limits, dry-run behavior, and operator controls.
- Shared reports or exports leak target names, internal paths, metadata, secret-like evidence, or redaction gaps outside the intended audience.

## Existing Controls

- Passive archive/file modules are archive-only or local-file-only and do not make network calls.
- Archive/config analyzers use bounded parsing, max-file limits, max-byte limits, truncation, and controlled errors.
- Passive modules do not execute uploaded projects, package managers, CI workflows, Docker, Kubernetes, Terraform, Nginx, database tools, Redis/Sentinel, provider APIs, registries, or CVE/advisory lookups.
- Sensitive adjacent files are detected as no-read where documented.
- Redaction is best-effort and layered across runner, backend, API/reporting/export, frontend, and Raw JSON for sensitive modules.
- Findings are documented as heuristic review indicators requiring human validation.
- Current accepted posture is trusted local alpha, not production or external-user readiness.
- Active is separated from passive modules. The implemented live path is internal, limited, opt-in, and capped to one authorized HTTP `HEAD` request.
- Nmap, port scanning, crawling, fuzzing, exploitation, credential validation, and broader Active behavior remain out of scope.

## Required Controls Before External/Public Use

- Authentication for every non-local deployment.
- Authorization for file upload, job creation, job viewing, deletion, and export operations.
- File/job ownership and access checks across API, frontend, exports, and background jobs.
- Multi-user isolation for storage, job records, result reads, report exports, and admin/operator views.
- Retention, cleanup, reset, and deletion semantics for uploads, results, generated exports, logs, and demo data.
- Deployment hardening for host binding, CORS, reverse proxy, TLS, data mounts, backups, secrets, and operator access.
- Visible upload size/type limits and clear truncation/error messaging before upload and in reports.
- Legal/security disclaimers for user-uploaded content, authorized-use requirements, local storage, redaction limits, and heuristic findings.
- Audit/log redaction and careful error handling so logs do not become a secondary secret store.
- Secure export handling guidance, including report sensitivity, sharing expectations, and deletion guidance.
- Threat-informed onboarding that tells users what Inspectra does, what it stores, what it does not validate, and what deployment modes are unsupported.

## Design Implications For Next Blocks

### `PASSIVE-ALPHA-GAP-FIXES-03-AUTH-AND-USER-ISOLATION-DESIGN`

Design identity, sessions, roles, file/job ownership, export authorization, admin/operator boundaries, and cross-user data isolation before any multi-user or external deployment is approved.

### `PASSIVE-ALPHA-GAP-FIXES-04-RETENTION-CLEANUP-RESET-DESIGN`

Define how long uploads, job results, generated exports, logs, and demo data are retained. Specify deletion behavior, cleanup triggers, reset workflow, and residual local-file caveats.

### `PASSIVE-ALPHA-GAP-FIXES-05-DISCLAIMERS-AND-ONBOARDING-COPY`

Create user-facing copy for authorized use, upload sensitivity, local storage, redaction limits, heuristic findings, unsupported deployment modes, and the split between passive, baseline, and Active flows.

### `PASSIVE-ALPHA-GAP-FIXES-06-LIMITS-MESSAGING-AND-REPORT-POLISH`

Make limits, truncation, no-read behavior, redaction notes, confidence/severity meaning, sparse reports, failed jobs, and export sensitivity clearer in UI and docs.

## Non-Goals

- No implementation.
- No new analyzer.
- No Nmap.
- No Active expansion.
- No production deployment approval.
- No public SaaS approval.
- No public unauthenticated deployment approval.
- No target-policy relaxation.
- No local-lab mode.

## Open Questions

- Should the next auth model be single-user with simple authentication or real multi-user from the start?
- Should future deployment support be self-hosted only, dedicated single-instance hosting, optional public/community hosting, or a staged combination?
- How long should uploads, job results, generated exports, logs, and deleted-file records be retained?
- Who can see, delete, rerun, or export jobs?
- Should report sharing be supported, and if so should it use authenticated links, expiring links, or manual file exports only?
- What public upload size, archive entry, and file-type limits should be shown before upload?
- What disclaimer should users accept before uploading files or running authorized baseline/Active target flows?
- What operator logs are necessary, and which fields must always be redacted?

## Acceptance Criteria

- Deployment modes are defined.
- Actors are defined.
- Assets and sensitive data are defined.
- Trust boundaries are defined.
- Core data flows are defined.
- Threats and existing controls are defined.
- Required controls for public/external use are defined.
- Next auth, isolation, retention, onboarding, limits, and report polish blocks are informed.
- No capabilities are added.
- Nmap and Active expansion remain out of scope.

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
PASSIVE-ALPHA-GAP-FIXES-04-RETENTION-CLEANUP-RESET-DESIGN
```

Auth and user isolation design is now accepted as the next boundary. Proceed to docs-first retention, cleanup, and reset design. Do not proceed directly to runtime auth, storage migrations, Nmap, another Active capability, or a new passive analyzer implementation from this threat-model block.

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
