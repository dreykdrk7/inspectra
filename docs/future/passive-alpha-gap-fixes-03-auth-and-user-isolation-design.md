# Passive Alpha Gap Fixes 03 Auth And User Isolation Design

Status: `PASSIVE_ALPHA_AUTH_USER_ISOLATION_DESIGN_ACCEPTED`.

Base threat model: `docs/future/passive-alpha-gap-fixes-02-deployment-threat-model.md`

Base plan: `docs/future/passive-alpha-gap-fixes-01-plan.md`

Commit scope: docs-only authentication, authorization, ownership, and user-isolation design for future private/internal or single-tenant hosted deployment. This block does not change backend, frontend, runner, tests, fixtures, schemas, storage, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_AUTH_USER_ISOLATION_DESIGN_ACCEPTED
```

Inspectra should not move beyond trusted local use until every uploaded file, audit job, job result, report/export, Raw JSON view, and target-based job has an explicit ownership and authorization model.

The recommended first non-local auth shape is a single-tenant authenticated deployment with explicit users, authenticated sessions, no anonymous access to sensitive resources, and a separate operator/admin role. Multi-tenant SaaS remains outside the current design.

## Objective

This block does not implement authentication. It defines the boundaries that future runtime work must satisfy before Inspectra can support private/internal team use or single-tenant hosted use.

The design answers:

- who may access Inspectra;
- who owns uploaded files and jobs;
- who can read, export, delete, or reset stored results;
- how target-based baseline and internal Active jobs inherit ownership;
- what must remain impossible for anonymous visitors and ordinary users.

## Deployment Assumptions

Supported now:

- trusted local single-operator or developer workstation;
- local demo with fixtures and synthetic data.

Future target:

- private/internal team deployment;
- single-tenant hosted deployment.

Still unsupported:

- public unauthenticated deployment;
- multi-tenant SaaS;
- arbitrary untrusted external users;
- processing regulated or highly sensitive customer data without additional controls;
- public Active, Nmap, network-scan, or scan-as-a-service deployment.

## Recommended Auth Model

The first auth model should be:

- single-tenant authenticated users;
- authenticated browser sessions;
- no anonymous access to uploads, files, jobs, results, reports, exports, Raw JSON, baseline target history, or internal Active target history;
- an authenticated user/reviewer role for normal upload/review work;
- a separate operator/admin role for system-wide operational tasks;
- a service/background-job context that can process only jobs created by authenticated principals or trusted local defaults;
- an optional local single-user mode mapped to one default local operator for trusted/dev use only.

The local single-user mode must not be described as public, production, or internet-safe. It is a compatibility bridge for trusted local development and demos, not an auth substitute for deployed use.

Do not design full multi-tenant SaaS in this block. If team/workspace concepts are added later, they should serve single-tenant or private-team isolation first.

## Roles

### Unauthenticated Visitor

Can:

- reach public health or static frontend shell only if deployment chooses to expose those surfaces;
- see only unauthenticated-safe onboarding or login copy.

Cannot:

- upload files;
- list files;
- read file metadata;
- create jobs;
- list jobs;
- read job results;
- export reports;
- view Raw JSON;
- run authorized baseline flows;
- run internal Active flows;
- reset data;
- access admin operations.

### Authenticated User / Reviewer

Can:

- upload files into their owned scope;
- list and read metadata for their own files;
- create jobs for their own files;
- create authorized baseline target jobs in their own scope after explicit authorization;
- create internal Active one-HEAD jobs only if the feature is enabled and the user passes the same explicit authorization requirements;
- list their own jobs;
- read their own job results and redacted Raw JSON;
- export their own reports;
- delete their own uploaded source files or request deletion semantics defined by the retention block.

Cannot:

- read another user's files, jobs, results, reports, Raw JSON, target history, or exports;
- view system-wide storage paths;
- bypass target policy;
- enable Active features;
- manage other users;
- perform cleanup outside their own owned scope unless an admin grants that separately.

### Operator / Admin

Can:

- manage deployment configuration and feature flags;
- view system health and operational status;
- perform system cleanup/reset according to documented retention policy;
- investigate failures with redacted logs and controlled access;
- optionally view all tenant resources if the product explicitly accepts that admin boundary.

Cannot:

- bypass redaction requirements in reports/logs/errors;
- bypass target policy for baseline or Active jobs;
- use admin access to convert heuristic findings into confirmed vulnerability claims;
- expose the deployment publicly without the required external-use controls;
- enable Nmap or broader Active behavior from this design.

Admin read-all access is an open product/security decision. If allowed, it must be explicit in onboarding and deployment documentation because it makes operators privileged data processors.

### Service / Background Job Context

Can:

- run a queued job that already has an owner or trusted local default owner;
- read the specific source file or target metadata needed for that job;
- write the result for that same job;
- apply redaction and controlled errors.

Cannot:

- create user-facing jobs on its own;
- read unrelated users' files/results;
- export reports without an authenticated request;
- make target-based network requests outside the job's accepted contract;
- bypass archive, parser, target, or Active policy limits.

## Resource Ownership

Every sensitive resource must be owned before Inspectra supports more than one user.

### Uploaded Files

- Each uploaded file should have an `owner_id` or belong to a workspace/single-tenant boundary.
- File listing and metadata reads must filter by owner unless admin access is explicitly designed.
- Source-file deletion must verify ownership and preserve any documented historical job behavior.

### Audit Jobs

- Each job should have an owner derived from the user who created it.
- Jobs created from uploaded files must require ownership of the source file.
- Target-based jobs must store the user who confirmed authorization.

### Job Results

- Stored results inherit ownership from their job.
- `GET /jobs/{job_id}` must authorize against the job owner or accepted admin boundary.
- Compact job lists must not reveal other users' filenames, target names, statuses, summaries, errors, or redaction notes.

### Reports And Exports

- Markdown, HTML, XML, and PDF exports inherit job ownership.
- Export endpoints must check authorization at request time.
- Generated export artifacts, if stored later, need ownership metadata and retention semantics.
- Manual report sharing remains an operator/user responsibility unless authenticated sharing is designed later.

### Raw JSON

- Raw JSON is sensitive because legacy, malformed, sparse, or unexpected payloads can contain metadata or secret-like values.
- Raw JSON must follow the same ownership checks as job results and reports.
- Redaction remains required even after authorization succeeds.

### Deletion And Reset Operations

- User deletion applies only to owned files, owned jobs, or owned exports unless retention semantics say otherwise.
- Admin reset applies only within documented deployment and retention policy.
- Demo reset must avoid deleting unrelated user data in any non-local mode.

### Authorized Baseline Target Jobs

- `web_basic`, `domain_basic`, and `subdomain_inventory_basic` jobs are target-based and must have an owner even though they may not have a `file_id`.
- Authorization confirmation is not transferable between users.
- Target history and results are visible only to the owner or accepted admin boundary.

### Internal Active Target Jobs

- `active_network_dry_run` and `active_http_header_probe` jobs are target-based and must have an owner.
- Active enablement remains feature-flagged and internal/limited.
- The one-HEAD contract, target policy, double confirmation, and redaction requirements do not change.
- Nmap is not designed here.

## Authorization Matrix

| Action | Unauthenticated | Authenticated user / reviewer | Operator / admin | System / background |
| --- | --- | --- | --- | --- |
| Upload file | Deny | Own scope only | Optional admin-assisted upload if designed | Deny |
| List own files | Deny | Own files only | All files only if admin read-all is accepted | Deny |
| Read file metadata | Deny | Own files only | All files only if admin read-all is accepted | Job source only |
| Delete file | Deny | Own files only | Per retention/reset policy | Deny except cleanup task |
| Create job | Deny | Own files or owned target flow only | Admin-created jobs only if designed | Deny |
| List jobs | Deny | Own jobs only | All jobs only if admin read-all is accepted | Deny |
| Read job result | Deny | Own jobs only | All jobs only if admin read-all is accepted | Current job only |
| Export report | Deny | Own jobs only | All jobs only if admin read-all is accepted | Deny |
| Delete job/result | Deny | Own jobs if policy allows | Per retention/reset policy | Deny except cleanup task |
| Reset demo data | Deny | Local trusted/demo scope only if designed | Per reset policy | Scheduled cleanup only |
| Run authorized baseline | Deny | Owned target job with explicit authorization | Same policy as user unless admin tooling is designed | Deny |
| Run Active internal one-HEAD | Deny | Only if enabled, authorized, and owned | Same policy plus operator controls | Execute accepted job only |
| Admin view all | Deny | Deny | Allow only if product accepts admin read-all | Deny |
| System cleanup | Deny | Deny | Configure/trigger according to policy | Execute scoped cleanup only |

Default rule: deny unless ownership, role, action, feature flag, and target/file policy all allow the request.

## Isolation Boundaries

### API Access Checks

Every endpoint that returns sensitive data must check authenticated identity and ownership before reading from storage or rendering reports. This includes file listing, file metadata, job listing, job detail, report export, SBOM export, delete operations, baseline target results, and Active job results.

### Storage Path Isolation

Storage should not rely on user-controlled filenames or public paths for authorization. Future storage design may use owner-scoped directories, opaque IDs, or both, but API authorization must not depend only on path layout.

### Job Result Isolation

Job records should carry owner metadata. Background jobs should preserve owner context from queue creation through result persistence.

### Export Access Isolation

Export endpoints should authorize the job before rendering. If exports become stored artifacts, they must not be placed in unauthenticated public paths.

### Background Job Context Isolation

Background execution should receive only the file path or target metadata required for the accepted job. It should not scan storage globally or infer work from unowned files.

### Frontend Route Guarding

Frontend routes and panels must assume the backend is authoritative. Client-side guarding improves UX, but backend ownership checks are mandatory.

### Raw JSON And Report Rendering Checks

Raw JSON and report sections must use the same authorized job read path. Failed, queued, running, sparse, malformed, and legacy jobs must not expose data across users.

### Logs And Audit Entries

Logs and audit entries should avoid raw secrets, credential-bearing URLs, raw Authorization headers, private key text, uploaded source content, and cross-user metadata. Operational logs should be redacted and scoped to admin/operator roles.

## Storage Implications

Future runtime design should consider explicit fields or concepts such as:

- `owner_id`;
- `workspace_id` if private-team workspaces are accepted;
- `created_by`;
- `visibility`;
- `deleted_at`;
- `retention_policy`;
- export ownership metadata;
- target authorization metadata for baseline and Active jobs;
- audit log actor metadata.

These are design inputs only. No schema, storage, migration, or runtime behavior changes are made by this block.

## Local Trusted Compatibility

Trusted local mode can map all resources to one default local operator. That keeps current demos and development flows conceptually compatible with future ownership without claiming public readiness.

Local trusted mode must remain documented as:

- single-operator;
- not anonymous internet-safe;
- not production-ready;
- not multi-user isolation;
- not a substitute for auth in private/internal or hosted deployment.

If a future runtime adds auth, local trusted mode should still make the storage caveat visible: uploaded originals and job results remain locally stored and are not sanitized by report redaction.

## Active And Baseline Implications

- Authorized baseline flows require both user ownership and explicit target authorization.
- Target-based jobs without `file_id` still need `owner_id` or equivalent ownership.
- Active dry-run remains no-network and must keep `network_requests_sent: 0`.
- Active one-HEAD remains internal, limited, feature-flagged, double-confirmed, and target-policy-bound.
- Any future target-based execution must associate target, authorization, result, export, and errors with the creating user or accepted workspace boundary.
- Nmap is not designed, implemented, enabled, or approved here.

## Security Requirements

- Deny by default.
- No anonymous reads of uploaded files, file metadata, jobs, results, reports, exports, target history, or Raw JSON.
- No cross-user job, result, export, target, or Raw JSON reads.
- Explicit admin/operator boundaries.
- Redaction in logs, errors, summaries, reports, exports, API payloads, and Raw JSON.
- Careful session and cookie handling in future implementation.
- CSRF, CORS, secure cookie, TLS, reverse-proxy, host-binding, and session-hardening decisions belong in deployment hardening before external use.
- No credentials in reports, logs, job summaries, controlled errors, or audit entries.
- Feature flags and target policy remain independent authorization gates for Active flows.

## Open Questions

- Should the first runtime auth be simple single-user auth or real multi-user from the start?
- Should Inspectra introduce workspace/team ownership, or only individual owner ownership?
- Can admins read all uploaded files/results, or should admin tools operate the system without content access where possible?
- Should exports be generated on demand behind authenticated endpoints, stored as owned artifacts, or both?
- Are shareable report links allowed, and if so must they be authenticated, expiring, scoped, or disabled?
- How should demo data be marked so reset workflows do not delete real user data?
- Which auth mechanism should a future implementation use: local password, reverse-proxy auth, OAuth/OIDC, SSO, or a staged approach?
- What audit logs are necessary for private/internal deployment without creating a secondary sensitive-data store?

## Out Of Scope

- No auth implementation.
- No database migration.
- No storage schema change.
- No API change.
- No login UI.
- No password reset.
- No OAuth implementation.
- No SSO implementation.
- No multi-tenant SaaS design.
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
PASSIVE-ALPHA-GAP-FIXES-04-RETENTION-CLEANUP-RESET-DESIGN
```

Retention and cleanup must respect the ownership model defined here:

- uploaded-file retention must be owner-scoped;
- job/result retention must inherit job ownership;
- export cleanup must account for generated artifacts and manual downloads;
- demo reset must be separable from real user data;
- admin cleanup must be explicit about whether content access is allowed;
- deletion semantics must define what happens to historical jobs when source files are deleted.

## Acceptance Criteria

- Roles are defined.
- Resource ownership is defined.
- Authorization matrix is defined.
- Isolation boundaries are defined.
- Storage implications are documented without implementation.
- Local trusted compatibility is defined.
- Active and baseline implications are defined.
- Security requirements are defined.
- Retention/cleanup/reset design is informed.
- No runtime or capability changes are made.

## No-Scope

- No code.
- No runtime changes.
- No tests or fixture changes.
- No auth implementation.
- No DB migration.
- No login UI.
- No password reset, OAuth, or SSO implementation.
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

Do not proceed directly to runtime auth, migrations, login UI, Nmap, another Active capability, or a new passive analyzer implementation from this design block.

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
