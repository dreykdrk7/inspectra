# Passive Alpha Gap Fixes 04 Retention Cleanup Reset Design

Status: `PASSIVE_ALPHA_RETENTION_CLEANUP_RESET_DESIGN_ACCEPTED`.

Base auth and isolation design: `docs/future/passive-alpha-gap-fixes-03-auth-and-user-isolation-design.md`

Base threat model: `docs/future/passive-alpha-gap-fixes-02-deployment-threat-model.md`

Commit scope: docs-only retention, cleanup, reset, and deletion-semantics design for future private/internal or single-tenant hosted deployment. This block does not change backend, frontend, runner, tests, fixtures, schemas, storage, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_RETENTION_CLEANUP_RESET_DESIGN_ACCEPTED
```

Inspectra should treat uploaded source files, derived job results, reports/exports, Raw JSON, target histories, logs, and demo data as sensitive retained data. Future non-local deployments must provide explicit owner-scoped deletion, retention windows, cleanup/reset boundaries, and user-facing storage caveats before accepting real external users.

This decision does not implement cleanup, schedulers, deletion behavior, storage changes, auth, UI controls, or any runtime capability.

## Objective

This block defines future retention, cleanup, reset, and deletion rules. It does not implement them.

The goal is to reduce sensitive-data retention, clarify what is stored, and prepare private/internal or single-tenant hosted deployments without weakening the current trusted local alpha posture.

## Resource Inventory

- Uploaded source files.
- Extracted file metadata.
- Audit jobs.
- Job results and stored JSON.
- Raw JSON exposed in the UI/API.
- Markdown, HTML, XML, and PDF reports/exports.
- SBOM exports for supported completed jobs.
- Logs and audit entries where applicable.
- Generated temporary files and cache data.
- Demo fixtures and demo-generated data.
- Authorized baseline target history.
- Internal Active target history.

## Ownership Inheritance

The retention model inherits the Block 03 ownership rules:

- uploaded files have an owner or trusted local default operator;
- jobs inherit ownership from the creating user and, for file-based jobs, must also require ownership of the source file;
- job results inherit ownership from the job;
- reports and exports inherit ownership from the job;
- Raw JSON inherits ownership from the job result;
- target-based jobs have an owner even when `file_id: null`;
- cleanup and admin operations must respect owner/admin boundaries;
- service/background cleanup can operate only inside scoped, accepted retention policy.

## Retention Classes

### Source Uploads

- Sensitivity: highest, because originals can contain secrets, customer data, internal paths, code, archives, metadata, credentials, or regulated content.
- Owner: uploader or trusted local default operator.
- Trusted local retention: remain on disk until the operator deletes them manually or uses a future reset workflow.
- Future single-tenant retention: configurable retention window plus explicit "delete source upload" and "delete all my data" flows.
- Deletion behavior: remove stored source bytes and mark metadata as deleted if historical jobs are preserved.
- Caveats: deleting a source file does not delete manually downloaded copies or reports already shared outside the app.

### Derived Results

- Sensitivity: high, because stored JSON can include extracted metadata, filenames, target names, findings, redaction notes, controlled errors, and legacy/malformed values.
- Owner: job owner.
- Trusted local retention: remain on disk until manual cleanup or future reset.
- Future single-tenant retention: configurable job/result retention window with owner-scoped deletion.
- Deletion behavior: delete or tombstone job result JSON according to product policy; if source metadata remains, it must remain redacted and minimal.
- Caveats: redacted derived results are still sensitive because metadata and target context can be identifying.

### Generated Exports

- Sensitivity: high, even when redacted, because exports are designed to be readable and shareable.
- Owner: job owner.
- Trusted local retention: preferably generated on demand; if saved manually by the user, the app cannot delete the downloaded copy.
- Future single-tenant retention: prefer on-demand rendering behind authenticated endpoints; if stored as artifacts, store with owner, creation time, format, and TTL.
- Deletion behavior: delete stored export artifacts when the owning job/result is deleted or when export TTL expires.
- Caveats: manual downloads, email attachments, screenshots, and shared files remain outside app control.

### SBOM Exports

- Sensitivity: medium to high, because package names, versions, paths, VCS/URL declarations, and internal project structure can be sensitive.
- Owner: source job owner.
- Trusted local retention: generated on demand from stored results.
- Future single-tenant retention: same policy as reports/exports.
- Deletion behavior: no separate retention if generated on demand; stored artifacts require owner and TTL.
- Caveats: SBOMs can expose dependency and repository structure even without secrets.

### Logs And Audit Entries

- Sensitivity: medium to high, depending on fields captured.
- Owner: system/operator scope, with actor metadata where future auth exists.
- Trusted local retention: operator-managed local logs only.
- Future single-tenant retention: short, configurable retention; redacted by design; accessible only to operator/admin roles.
- Deletion behavior: rotate and expire according to deployment policy; avoid using logs as the only audit evidence for user deletion.
- Caveats: logs must not become a secondary secret store.

### Demo And Synthetic Data

- Sensitivity: low by design, but still should be separated from real user data.
- Owner: local demo operator or explicit demo workspace/user if future auth exists.
- Trusted local retention: can be reset manually between demos.
- Future single-tenant retention: demo data must be marked and isolated before any reset tooling exists.
- Deletion behavior: demo reset deletes only known demo uploads, jobs, results, and generated artifacts.
- Caveats: never infer demo data only from filenames in a non-local deployment.

### Temporary And Cache Data

- Sensitivity: same as the source/result that generated it.
- Owner: owning job/user or system cleanup scope.
- Trusted local retention: should be short-lived where possible.
- Future single-tenant retention: short TTL, owner/job association, and automatic cleanup.
- Deletion behavior: safe to delete after job completion or failure unless needed for controlled error handling.
- Caveats: temporary files must not contain unredacted secrets longer than necessary.

### Authorized Baseline And Active Target History

- Sensitivity: high, because target URLs, domains, request errors, response metadata, and timing can identify internal or external systems.
- Owner: creating user or trusted local default operator.
- Trusted local retention: stored with job results until manual cleanup.
- Future single-tenant retention: configurable target-history/result retention with owner-scoped deletion.
- Deletion behavior: deleting the target job/result deletes stored target inputs, errors, summaries, and exports under app control.
- Caveats: DNS/HTTP traffic may be observable by target owners, resolvers, logs, or infrastructure outside Inspectra.

## Deletion Semantics

### Delete Source Upload

Deleting a source upload should remove source bytes from local storage. Historical jobs may remain if the product keeps derived results, but those jobs must clearly show that the source file was deleted.

If future policy chooses cascading deletion, deleting a source upload should also delete related queued jobs, stored results, generated export artifacts, and Raw JSON for that source. This should be an explicit product decision because it changes historical reporting behavior.

### Delete Job Or Result

Deleting a job/result should remove stored result JSON, report/export availability, Raw JSON access, and job details except for any minimal tombstone required for auditability.

Queued or running jobs need controlled behavior: either deny deletion until completion/cancel support exists, or mark deletion requested and prevent result exposure after completion.

### Delete Export Artifact

If exports are stored, deleting an export artifact removes the stored file but not manually downloaded copies. Export deletion should not delete the underlying job unless explicitly requested.

If exports are generated on demand, no app-side artifact deletion is needed beyond controlling job/result retention.

### Delete All Owned Data

A future "delete all my data" flow should delete or tombstone:

- owned uploads;
- owned jobs;
- owned job results;
- owned stored export artifacts;
- owned Raw JSON access;
- owned baseline and Active target histories;
- owned demo data if it belongs to that user.

It must not delete unrelated users' data or shared system logs outside the defined retention/audit policy.

### Admin Cleanup

Admin cleanup should be explicit, logged with redacted metadata, scoped by retention policy, and careful about whether the admin is allowed to inspect content. Admin cleanup must not bypass target policy or redaction rules.

### Demo Reset

Demo reset deletes only known demo/synthetic uploads, jobs, results, exports, and temporary data. In non-local modes, demo data must be tagged by owner/workspace/fixture marker before automated reset is safe.

### Historical Jobs When Source Is Deleted

Two acceptable future policies exist:

- Preserve redacted historical results while marking source as deleted.
- Cascade-delete jobs/results when source is deleted.

The first preserves audit history but retains metadata. The second minimizes retention but removes report history. Product must choose before implementation.

### Manual Downloads

Manual report, SBOM, or Raw JSON downloads are outside app deletion control. Onboarding and disclaimers must say that deleting data inside Inspectra does not remove files already downloaded, copied, emailed, screenshotted, backed up, or shared.

### Logs And Audit Entries

Logs and audit entries should use redacted, minimal fields. Deleting user data may leave minimal operational tombstones if required, but those tombstones should avoid sensitive filenames, targets, secret-like values, and raw error content.

### Deletion Markers And Tombstones

Tombstones can help prevent confusing historical state and support auditability. They should be minimal, owner-scoped, and avoid sensitive metadata unless a deployment explicitly accepts that retention.

## Reset Workflows

### Local Demo Reset

Purpose: return a trusted local demo environment to a clean state.

Rules:

- May remove demo uploads, demo jobs, demo results, and demo generated artifacts.
- Should be clearly documented as local/trusted only.
- Should not be used on real customer data.
- Should not imply production-safe deletion guarantees.

### User-Owned Reset

Purpose: allow an authenticated user to remove their own uploaded files, jobs, results, exports, and target histories.

Rules:

- Must enforce ownership.
- Must clearly show what will be deleted and what may remain.
- Should handle target-based jobs without `file_id`.
- Should explain that manual downloads and external logs remain outside app control.

### Admin Full Cleanup

Purpose: let an operator clean a single-tenant deployment according to documented policy.

Rules:

- Must be admin-only.
- Must be auditable with redacted metadata.
- Must distinguish demo/synthetic, user-owned, and system data.
- Must avoid accidental cross-user deletion if private-team ownership exists.

### Scheduled Cleanup

Purpose: enforce configured retention windows.

Rules:

- Should run as a service/background context with scoped permissions.
- Should delete or tombstone expired data according to class-specific policy.
- Should record controlled, redacted cleanup outcomes.
- Should never process `.env`, backups, state files, dumps, or sensitive source content beyond deleting stored bytes/artifacts.

### Safe Reset Boundaries

Reset must distinguish:

- demo/synthetic data;
- real user-owned data;
- system logs/audit data;
- temporary/cache data;
- manually downloaded artifacts outside the app.

Demo reset must never delete real data in private/internal or hosted modes.

## Recommended Default Policies

### Trusted Local

- Keep current local storage posture explicit.
- Provide manual cleanup/reset guidance.
- Warn that uploads and results remain on disk until the operator removes them or future cleanup tooling exists.
- Use only synthetic fixtures for demos.
- Do not claim secure deletion, production retention, or multi-user isolation.

### Future Single-Tenant

- Provide configurable retention windows for uploads, results, exports, logs, and temporary data.
- Provide owner-scoped "delete source upload".
- Provide owner-scoped "delete job/result" or "delete all my data".
- Prefer on-demand exports behind authenticated endpoints.
- If storing exports, require owner metadata, created timestamp, format, and TTL.
- Keep admin cleanup separate from user deletion.
- Record redacted cleanup outcomes.

### Logs

- Avoid sensitive fields by design.
- Use shorter retention than user-owned results where possible.
- Redact target URLs, credential-bearing values, private key text, raw headers, secret-like fields, and raw parser errors.
- Do not rely on logs to reconstruct deleted sensitive content.

## Export Handling

Exports are sensitive even when redacted.

Requirements:

- authorize ownership before rendering;
- keep export rendering behind authenticated endpoints for non-local modes;
- prefer generating exports on demand from authorized job results;
- if exports are stored, attach owner, job ID, format, creation time, and TTL;
- delete stored export artifacts when the job/result is deleted or the export TTL expires;
- document that manual downloads are outside app control;
- include sharing guidance in onboarding and disclaimers.

## Raw JSON Handling

Raw JSON is sensitive because it can expose:

- legacy or malformed payload fields;
- parser errors;
- source filenames and paths;
- target URLs/domains;
- redaction notes;
- sparse or unexpected metadata.

Rules:

- Raw JSON must respect job ownership.
- Raw JSON must be redacted defensively.
- Raw JSON retention follows the job result policy.
- Raw JSON access disappears when the job/result is deleted, unless a minimal tombstone policy is explicitly chosen.

## Baseline And Active Target History

Target URLs, domains, candidates, target errors, and target report outputs are sensitive.

Rules:

- target-based jobs without `file_id` must have an owner;
- target inputs, results, errors, exports, and Raw JSON follow job result retention;
- target authorization confirmations are not transferable between users;
- deletion must cover target input history under app control;
- one-HEAD or baseline traffic can remain visible in target-side logs, DNS resolver logs, HTTP server logs, proxies, or infrastructure outside Inspectra.

Active remains internal and limited. Nmap is not part of this design.

## Security And Privacy Requirements

- No anonymous cleanup, read, delete, export, or reset operations.
- Owner-scoped deletion for user-controlled actions.
- Admin cleanup must be explicit, auditable, redacted, and bounded.
- Logs must avoid becoming a secondary secret store.
- Deletion behavior must be understandable before a user uploads data.
- Redacted derived results are still sensitive and need retention policy.
- Manual exports/downloads are not deleted by app-side cleanup.
- Future backups, snapshots, object-store versions, or host backups can retain data after app deletion and must be disclosed if used.
- Cleanup code, when later implemented, must not read no-read sensitive files to delete or classify them.

## Open Questions

- What default TTL should apply to source uploads?
- What default TTL should apply to job results and Raw JSON?
- Should exports be on-demand only or stored artifacts with TTL?
- Should deletion be hard delete, soft delete, or configurable by deployment mode?
- How can deletes be audited without retaining sensitive filenames, targets, or metadata?
- How should backups, snapshots, and object-store versions be handled?
- Should a future "delete all my data" operation exist before private/internal deployment?
- How should demo data be marked safely?
- Who can execute full reset in a single-tenant deployment?
- Should source deletion cascade to historical results or preserve redacted audit history?

## Out Of Scope

- No cleanup implementation.
- No scheduler or cron implementation.
- No database migration.
- No storage schema change.
- No delete/reset UI.
- No auth runtime.
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
PASSIVE-ALPHA-GAP-FIXES-05-DISCLAIMERS-AND-ONBOARDING-COPY
```

Onboarding and disclaimers must clearly explain:

- what Inspectra stores;
- what can be deleted;
- what is not deleted by app-side cleanup;
- the sensitivity of reports, exports, SBOMs, and Raw JSON;
- redaction limits and the fact that uploaded originals are not sanitized;
- manual download and report-sharing responsibility;
- authorized-use boundaries for baseline and Active target flows;
- trusted local mode versus future non-local deployment modes.

## Acceptance Criteria

- Resource inventory is defined.
- Ownership inheritance is defined.
- Retention classes are defined.
- Deletion semantics are defined.
- Reset workflows are defined.
- Recommended default policies are defined.
- Export and Raw JSON handling are defined.
- Baseline and Active target history is covered.
- Security and privacy requirements are defined.
- Disclaimers/onboarding design is informed.
- No runtime or capability changes are made.

## No-Scope

- No code.
- No runtime changes.
- No tests or fixture changes.
- No cleanup implementation.
- No scheduler or cron implementation.
- No DB migration.
- No storage schema change.
- No delete/reset UI.
- No auth implementation.
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
PASSIVE-ALPHA-GAP-FIXES-05-DISCLAIMERS-AND-ONBOARDING-COPY
```

Do not proceed directly to cleanup runtime, schedulers, storage migrations, delete/reset UI, Nmap, another Active capability, or a new passive analyzer implementation from this design block.

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
