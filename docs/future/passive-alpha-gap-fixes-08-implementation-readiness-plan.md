# Passive Alpha Gap Fixes 08 Implementation Readiness Plan

Status: `PASSIVE_ALPHA_IMPLEMENTATION_READINESS_PLAN_ACCEPTED`.

Base gap-fixes closeout: `docs/future/passive-alpha-gap-fixes-07-closeout.md`

Base auth and user-isolation design: `docs/future/passive-alpha-gap-fixes-03-auth-and-user-isolation-design.md`

Base retention cleanup reset design: `docs/future/passive-alpha-gap-fixes-04-retention-cleanup-reset-design.md`

Commit scope: docs-only implementation readiness plan for future Passive Alpha P0/P1/P2 runtime work. This block orders future microphases, names dependencies, defines minimum test expectations, and keeps runtime work separate. It does not change backend, frontend, runner, tests, fixtures, schemas, storage, reports, exports, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_IMPLEMENTATION_READINESS_PLAN_ACCEPTED
```

The Passive Alpha gap-fixes design line is ready to move into an implementation planning sequence.

This block does not implement auth, ownership, cleanup, UI, reports, exports, or deployment controls. It defines the order and acceptance boundaries for future runtime microphases.

## Objective

Convert the accepted docs-first designs into a safe implementation roadmap.

The plan should:

- order P0/P1/P2 implementation candidates;
- identify dependencies before code work begins;
- define minimum test expectations for each runtime boundary;
- preserve the current trusted local compatibility path;
- keep public/external runtime blocked until P0 controls are implemented and reviewed.

## Implementation Principles

Future runtime work should follow these principles:

- Deny by default.
- Auth before external use.
- Ownership before multi-user behavior.
- No anonymous reads for sensitive resources.
- Preserve trusted local compatibility through an explicit default local operator model.
- Do not add broad Active, Nmap, new analyzers, or scan-as-a-service behavior.
- Keep redaction layered across runner output, backend storage/reporting, API payloads, exports, frontend reports, and Raw JSON.
- Keep migrations small and reversible where practical.
- Test controls before claiming readiness.
- Treat legacy local data explicitly instead of assuming it is safe for hosted use.
- Keep backend authorization authoritative; frontend guards are UX only.

## Recommended Implementation Sequence

### P0 Runtime Sequence

1. `PASSIVE-ALPHA-P0-01-AUTH-BOUNDARY-DESIGN-TO-RUNTIME-PLAN`
   - Choose the first auth/session mechanism.
   - Define trusted local default operator compatibility.
   - Decide admin/operator shape.
   - Keep code changes out of this planning block unless separately scoped later.

2. `PASSIVE-ALPHA-P0-02-OWNER-MODEL-AND-STORAGE-MIGRATION-PLAN`
   - Define owner fields for uploads, jobs, results, exports, Raw JSON, and target histories.
   - Define legacy local data mapping.
   - Define migration and rollback expectations.

3. `PASSIVE-ALPHA-P0-03-DENY-ANONYMOUS-READS-API-GUARDS`
   - Add backend guards for list/read/upload/job/export/Raw JSON/delete surfaces.
   - Deny unauthenticated access to sensitive resources.
   - Keep trusted local default operator path explicit.

4. `PASSIVE-ALPHA-P0-04-OWNER-SCOPED-JOBS-RESULTS-EXPORTS`
   - Enforce owner checks for jobs, results, report rendering, exports, SBOMs, Raw JSON, and target histories.
   - Ensure background jobs process only owned and accepted jobs.

5. `PASSIVE-ALPHA-P0-05-RETENTION-DELETE-SEMANTICS-RUNTIME-PLAN`
   - Decide delete source versus delete source plus derived results behavior.
   - Define user deletion, admin cleanup, trusted local reset, and retention windows.
   - Defer scheduler implementation until policy is accepted.

6. `PASSIVE-ALPHA-P0-06-DEPLOYMENT-HARDENING-CHECKLIST`
   - Document deployment controls for host binding, TLS/reverse proxy, secure cookies/sessions, CORS/CSRF, secrets, logs, backups, storage permissions, and admin access.
   - Require review before any public/external runtime.

### P1 Sequence

1. `PASSIVE-ALPHA-P1-01-ONBOARDING-DISCLAIMER-UI`
   - Surface trusted-local and future hosted disclaimers.
   - Keep wording aligned with Block 05.

2. `PASSIVE-ALPHA-P1-02-UPLOAD-ACKNOWLEDGEMENT`
   - Add upload acknowledgement for sensitive local storage, authorization, and redaction caveats.

3. `PASSIVE-ALPHA-P1-03-TARGET-FLOW-ACKNOWLEDGEMENT`
   - Add target-flow acknowledgement for web, DNS, subdomain, and internal Active flows.

4. `PASSIVE-ALPHA-P1-04-VISIBLE-LIMITS-MESSAGING`
   - Surface upload, archive, file, byte, truncation, and no-read messaging.

5. `PASSIVE-ALPHA-P1-05-RAW-JSON-EXPORT-WARNINGS`
   - Add Raw JSON and export sensitivity warnings.

### P2 Sequence

1. `PASSIVE-ALPHA-P2-01-REPORT-EXPORT-POLISH`
   - Add report/export cover notes, sensitivity footers, and scope/no-scope copy.

2. `PASSIVE-ALPHA-P2-02-SEVERITY-CONFIDENCE-HELPERS`
   - Surface severity and confidence helper text without changing scoring contracts.

3. `PASSIVE-ALPHA-P2-03-STATE-POLISH`
   - Improve no-findings, failed, sparse, malformed, queued, running, and empty-state copy.

4. `PASSIVE-ALPHA-P2-04-PASSIVE-REPORT-SHELL-MIGRATION`
   - Migrate remaining reports to the shared report shell where practical.

5. `PASSIVE-ALPHA-P2-05-FIXTURE-DRIVEN-SMOKE-SCRIPT`
   - Add a trusted local smoke script around synthetic fixtures and documented no-network/no-secret constraints.

## First Runtime Candidate

Recommended first future block:

```text
PASSIVE-ALPHA-P0-01-AUTH-BOUNDARY-DESIGN-TO-RUNTIME-PLAN
```

Rationale:

- The auth/session boundary must be decided before owner fields, owner-scoped API guards, or delete semantics can be implemented safely.
- Trusted local default operator behavior must be explicit before migrating existing local data.
- Admin/operator boundaries affect cleanup, logs, exports, target histories, and Active internal controls.
- Starting with storage ownership before auth would risk inventing fields without a clear principal model.

## Dependencies

- Auth boundary before owner-scoped API guards.
- Auth boundary before owner-scoped exports and Raw JSON.
- Owner model before delete all my data.
- Owner model before target-history ownership.
- Ownership before stored export artifacts.
- Retention semantics before cleanup scheduler.
- Disclaimers before UI acknowledgements.
- Visible limits copy before upload/report polish implementation.
- Deployment hardening before external users.
- Security review before public/external runtime.

## Minimum Test Expectations

Future runtime implementation should include tests for:

- unauthenticated users cannot upload, list, read, export, view Raw JSON, or delete;
- authenticated users can see only their own files, jobs, results, reports, exports, Raw JSON, and target histories;
- admin/operator boundaries are explicit and tested;
- background jobs cannot process unowned, unauthenticated, or unapproved jobs;
- target-based jobs require an owner and explicit authorization metadata;
- Raw JSON follows job ownership;
- Markdown, HTML, XML, PDF, and SBOM exports require ownership;
- delete source/job/result semantics match the accepted retention policy;
- trusted local default operator compatibility remains tested;
- legacy local data is mapped or blocked according to migration policy;
- failed, sparse, malformed, queued, and running jobs do not leak across owners;
- redaction regression tests remain passing after auth and ownership changes;
- logs and controlled errors avoid cross-user data exposure.

## Migration And Readiness Risks

Future implementation must handle:

- existing local files and jobs without an owner;
- default local operator mapping;
- backward compatibility of job records and summaries;
- exports generated from legacy jobs;
- Raw JSON generated from legacy payloads;
- target histories and target authorization confirmations without owner metadata;
- demo fixtures and trusted local smoke flows;
- migration rollback;
- accidental anonymous public exposure during partial implementation;
- logs, errors, browser state, and downloaded exports retaining sensitive data outside app cleanup.

## Runtime Blockers Before Public Or External Use

Public/external runtime remains blocked until:

- auth and authorization are implemented;
- ownership is enforced across sensitive resources;
- anonymous reads are denied;
- retention and deletion controls are implemented;
- deployment hardening is documented, tested, and reviewed;
- onboarding and disclaimers are surfaced;
- visible limits are surfaced;
- report/export/Raw JSON warnings are surfaced;
- security review is completed.

## Explicitly Deferred

These remain deferred:

- multi-tenant SaaS;
- Nmap;
- broader Active behavior;
- new Passive analyzers;
- local-lab mode;
- public scan-as-a-service;
- regulated or highly sensitive data support;
- anonymous public deployment;
- third-party target testing without explicit authorization.

## Acceptance Criteria

- Implementation sequence is clear.
- First runtime candidate is chosen.
- P0/P1/P2 boundaries are clear.
- Dependencies are clear.
- Minimum tests are clear.
- Migration/readiness risks are documented.
- Public/external blockers are clear.
- Deferred work is explicit.
- No runtime or capability changes are made.

## Next Recommendation

```text
PASSIVE-ALPHA-P0-01-AUTH-BOUNDARY-DESIGN-TO-RUNTIME-PLAN
```

Choose this if the product wants to move toward private/internal or single-tenant hosted use.

Alternative:

```text
PASSIVE-ALPHA-TRUSTED-LOCAL-RELEASE-NOTES
```

Choose this if the product wants to publish or polish trusted local release copy before any P0 planning.

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

## Validation Commands

Reference checks for this docs-only plan:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
