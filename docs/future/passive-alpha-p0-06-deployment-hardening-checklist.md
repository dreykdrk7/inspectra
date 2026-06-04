# Passive Alpha P0 06 Deployment Hardening Checklist

Status: `PASSIVE_ALPHA_DEPLOYMENT_HARDENING_CHECKLIST_ACCEPTED`.

Base retention/delete runtime plan: `docs/future/passive-alpha-p0-05-retention-delete-semantics-runtime-plan.md`

Base owner-scoped resources plan: `docs/future/passive-alpha-p0-04-owner-scoped-jobs-results-exports.md`

Base deny-anonymous API guards plan: `docs/future/passive-alpha-p0-03-deny-anonymous-reads-api-guards.md`

Base owner model and storage migration plan: `docs/future/passive-alpha-p0-02-owner-model-and-storage-migration-plan.md`

Base auth-boundary runtime plan: `docs/future/passive-alpha-p0-01-auth-boundary-design-to-runtime-plan.md`

Base open-source/self-hosted framing: `docs/future/passive-alpha-p0-00-open-source-self-hosted-product-framing.md`

Base implementation readiness plan: `docs/future/passive-alpha-gap-fixes-08-implementation-readiness-plan.md`

P0 runtime planning closeout: `docs/future/passive-alpha-p0-07-p0-runtime-planning-closeout.md`

Commit scope: docs-only deployment hardening checklist for future Passive Alpha P0 work. This block defines deployment modes, controls, no-go conditions, and future tests/checks before exposing an Inspectra installation outside localhost/trusted local use. It does not change backend, frontend, runner, tests, fixtures, Compose configuration, schemas, storage, auth, CORS, CSRF, TLS, reverse proxy behavior, reports, exports, cleanup, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_DEPLOYMENT_HARDENING_CHECKLIST_ACCEPTED
```

Inspectra should use a deployment hardening checklist before any non-local, self-hosted exposed, private-team, or optional public/community use.

This checklist exists for safety in open-source, local-first, self-hosted-first deployments. It is not a SaaS, billing, paid-plan, quota monetization, tenant billing, or enterprise multi-tenant model.

## Objective

Define the deployment hardening controls that must be reviewed before exposing Inspectra beyond localhost/trusted local use.

This block does not implement hardening. It defines what future runtime, docs, operator guides, and deployment reviews must cover:

- host binding and exposure;
- reverse proxy and TLS;
- auth mode;
- future sessions and cookies;
- CORS and CSRF;
- storage permissions;
- logs and audit;
- backups and snapshots;
- retention and cleanup config;
- admin/operator access;
- no-auth exposure checks;
- public/community limits;
- target-based flows and Active boundaries.

Current local development remains trusted local only. Public/external runtime remains blocked until auth, ownership, retention/delete controls, deployment hardening, visible disclaimers, limits, and security review are implemented and accepted.

## Deployment Modes Covered

### `trusted_local_no_auth`

Objective:

- Preserve localhost/dev/local trusted workflows.
- Support synthetic fixture demos.
- Keep the current no-auth posture only inside a local operator boundary.

Minimum controls:

- Bind only to localhost or an equivalent trusted local interface.
- Do not expose backend or frontend to LAN/public internet.
- Use synthetic fixtures for demos.
- Keep uploads/results under local operator control.
- Document that uploads, results, exports, SBOMs, and Raw JSON remain locally sensitive.
- Keep Active dry-run disabled unless intentionally used.
- Keep Active one-HEAD disabled unless intentionally used by a trusted operator.

No-go conditions:

- no-auth service bound to `0.0.0.0`, LAN, or public interfaces;
- real external users;
- real customer/regulated/highly sensitive data;
- public uploads;
- public exports or Raw JSON;
- public Active behavior;
- Nmap or broad live scanning.

### `self_hosted_single_admin`

Objective:

- First recommended runtime shape.
- One authenticated admin/operator owns all resources.
- Protect an instance exposed beyond localhost.

Minimum controls:

- Auth enabled before exposure.
- Deny anonymous sensitive endpoints.
- Admin principal created through an explicit setup flow.
- TLS or trusted TLS-terminating reverse proxy outside localhost.
- Restrictive CORS for the deployed frontend origin.
- CSRF protection if browser session cookies are used.
- Source upload, result, export, Raw JSON, and target history retention documented.
- Storage directory permissions reviewed.
- Backups and logs treated as sensitive.
- Active remains opt-in and limited.

No-go conditions:

- anonymous upload/read/export/delete allowed;
- no owner/default-admin mapping for existing data;
- direct backend access allowed around a reverse-proxy auth layer;
- storage paths web-served directly;
- logs store source contents, Raw JSON, secrets, or target secrets;
- no retention/delete policy;
- public Active one-HEAD enabled by default.

### `private_team_lightweight_users`

Objective:

- Support a controlled private/internal team install without commercial SaaS or enterprise tenant framing.
- Keep each user's files, jobs, results, exports, Raw JSON, and target histories owner-scoped.

Minimum controls:

- Auth for every real user.
- Owner-scoped list/read/create/export/delete behavior.
- Admin read-all policy explicitly accepted or disabled.
- Stronger audit logging for admin actions, redacted by design.
- Retention and cleanup scoped by owner.
- Rate and upload limits reviewed.
- Team onboarding/disclaimer copy surfaced.
- Reverse proxy, TLS, CORS, CSRF, storage, logs, and backups reviewed.

No-go conditions:

- user A can list/read/export/delete user B resources;
- admin read-all exists accidentally or without documentation;
- shared Raw JSON URLs;
- unauthenticated sensitive endpoints;
- no migration/claim plan for legacy ownerless records;
- public Active/Nmap behavior.

### `public_community_limited_instance`

Objective:

- Optional non-commercial community convenience instance for users outside the trusted local operator boundary.
- Strictly limited, short-retention, abuse-aware, and easy to disable.

Minimum controls:

- Auth or equivalent anti-abuse gate before real uploads.
- Strict upload, archive, job, export, and retention limits.
- Short retention for uploads, results, target histories, logs, temp/cache, and stored artifacts if any.
- Clear onboarding/disclaimer acknowledgement.
- No regulated or highly sensitive data support.
- No anonymous real uploads.
- No anonymous reads/exports/Raw JSON.
- No public Active one-HEAD by default.
- No Nmap.
- Abuse monitoring and rate limits as future requirements.
- Operator ability to restrict or disable the instance.

No-go conditions:

- anonymous public upload;
- anonymous public job/result/export/Raw JSON access;
- broad target checks;
- public Active/Nmap;
- no retention/delete controls;
- no abuse limits;
- no TLS;
- unclear admin/operator data access.

## Host Binding And Exposure

Checklist:

- Keep `trusted_local_no_auth` bound to localhost/dev/trusted local interfaces only.
- Treat any LAN, VPN, reverse proxy, container host, or public internet exposure as non-local unless explicitly reviewed.
- Require auth before non-local exposure.
- Add future warning or fail-closed behavior for no-auth plus non-local bind.
- Deny public unauthenticated uploads.
- Deny anonymous reads, exports, Raw JSON, delete/reset, and target flows outside trusted local mode.
- Keep health/static/login/onboarding/docs public only if they expose no sensitive data.
- Health must not reveal filenames, job IDs, counts, target strings, storage paths, feature flag details, secrets, or internal config.
- Avoid publishing direct storage paths.

Current implementation note:

- The current Compose dev setup publishes backend `8000` and frontend `5173` for local use and documents localhost URLs. This is not an approval for non-local no-auth exposure.

Future checks:

- no-auth plus non-local bind warns or fails closed;
- health leaks no sensitive data;
- sensitive routes require auth outside trusted local;
- direct ID access does not reveal resource existence before auth/owner checks.

## Reverse Proxy And TLS

Checklist:

- Use TLS outside localhost.
- Put the app behind a carefully configured reverse proxy if exposed.
- Do not trust proxy auth headers unless the backend is unreachable directly except through the trusted proxy.
- Strip or normalize untrusted forwarding headers at the edge.
- Configure `X-Forwarded-Proto`, `X-Forwarded-Host`, and client IP headers only from trusted proxy paths if the app later uses them.
- Set upload/body size limits at the proxy and backend.
- Set request, response, upload, and idle timeout limits.
- Disable directory listing.
- Do not serve `data/`, uploads, results, temp/cache, generated exports, backups, or logs as static files.
- Keep backend docs/OpenAPI exposure reviewed for non-local deployments.
- Prefer documented examples for Caddy, Nginx, or Traefik later, but do not choose one in this block.

Future checks:

- TLS is present outside localhost;
- direct backend access cannot sidestep proxy auth;
- proxy upload limits align with backend upload limits;
- storage paths are not reachable as static files;
- headers used for auth or scheme are accepted only from trusted proxy paths.

## Auth, Session, And Cookie Hardening

Checklist for future runtime:

- Prefer `self_hosted_single_admin` / `single_user_auth` as the first runtime shape.
- Create initial admin through an explicit setup flow.
- Store passwords with a modern password hashing scheme if local password auth is chosen.
- Require strong setup/reset handling for the admin account.
- Use secure cookies outside localhost.
- Use `HttpOnly` cookies for session tokens.
- Use `SameSite` appropriate to the deployment.
- Set session expiry and idle timeout.
- Provide logout behavior.
- Consider browser cache and local storage behavior after logout.
- Protect all mutating requests with CSRF defenses if cookie sessions are used.
- Deny anonymous sensitive endpoints.
- Keep reverse-proxy auth as an alternative integration mode, with trusted-header boundaries documented.

Future checks:

- unauthenticated upload/list/read/export/Raw JSON/delete/reset/target flows fail outside trusted local;
- session cookies are `Secure`, `HttpOnly`, and have appropriate `SameSite`;
- session expiry works;
- logout prevents continued API access;
- reverse-proxy auth cannot be skipped by direct backend access.

## CORS And CSRF

Checklist:

- Keep CORS restrictive.
- Avoid wildcard CORS for credentialed browser requests.
- Configure allowed origins explicitly for self-hosted custom domains.
- Treat CORS as browser boundary only, not backend auth.
- Add CSRF protection for mutating requests if browser session cookies are used.
- Review API usage guidance for token or non-cookie auth if introduced later.
- Document proxy/custom-domain origin changes for self-hosted operators.
- Do not expose admin or sensitive APIs through broad cross-origin allowances.

Current implementation note:

- The current default CORS origin is local development (`http://localhost:5173`). Future deployed origins must be explicit.

Future checks:

- CORS allows only configured origins;
- credentialed wildcard CORS is rejected;
- mutating browser requests require CSRF protection when cookie auth is used;
- custom-domain docs warn operators to update CORS intentionally.

## Storage Permissions

Checklist:

- Store uploads, results, temp/cache, logs, and future artifact data outside web-served directories.
- Use a dedicated app data directory.
- Apply least-privilege filesystem permissions.
- Ensure containers/processes can read/write only what they need.
- Keep runner access to uploads/results bounded by job-specific paths.
- Keep local paths sensitive and avoid returning host paths through APIs.
- Do not serve generated exports publicly unless behind auth and owner checks.
- Prefer on-demand exports; stored artifacts require owner, TTL, and delete state.
- Keep temp/cache short-lived and associated with a job/system cleanup scope.
- Document backup and snapshot caveats.

Current implementation note:

- The current local MVP stores uploads under `data/uploads` and job/result JSON under `data/results/jobs`, with local JSON persistence and a storage lock. The Compose setup bind-mounts `./data` into backend and runner services. This is acceptable for trusted local MVP use, not a substitute for future database/storage hardening in multi-user/high-volume deployments.

Future checks:

- `data/` is not web-served;
- file/job APIs authorize by metadata, not path layout;
- exports require job owner authorization;
- temp/cache cleanup does not inspect no-read sensitive files;
- permissions prevent accidental public reads.

## Logs And Audit

Checklist:

- Logs should be redacted by design.
- Do not log source contents.
- Do not log Raw JSON.
- Do not log secret-like values.
- Do not log Authorization headers, cookies, bearer tokens, API keys, passwords, private keys, credential URLs, or target secrets.
- Avoid storing full target URLs with sensitive query strings.
- Avoid stack traces in user-facing errors.
- Keep controlled errors generic and redacted.
- Use short log retention compared with job result retention.
- Restrict log access to the operator/admin.
- Treat logs as sensitive artifacts.
- Avoid logs becoming a secondary secret store.

Future checks:

- representative errors redact secrets;
- target strings in logs are redacted or minimized;
- admin cleanup logs contain counts and IDs only where safe;
- logs rotate or expire according to policy;
- public-safe endpoints do not reveal operational internals.

## Backups And Snapshots

Checklist:

- Document that backups and snapshots may retain deleted data.
- Protect backup storage at least as strongly as app data.
- Avoid promising secure deletion when backups exist.
- Define backup retention separately from app retention.
- Include uploads, results, logs, and any stored artifacts in sensitivity classification.
- Avoid backing up temp/cache unless operationally necessary.
- For public/community instances, publish a clear backup policy before real use.
- Consider restore testing only with synthetic data unless a future private policy accepts real data handling.

Future checks:

- docs mention that app-side deletion may not remove backups/snapshots;
- backup retention is configured and reviewed;
- backups are not publicly served;
- restore procedures preserve owner and delete state if implemented.

## Retention And Cleanup Config

Checklist based on P0-05:

- Trusted local can start with manual cleanup guidance.
- Self-hosted single-admin can add optional configurable retention after auth/ownership exist.
- Public/community requires short retention before real use.
- Temp/cache should use the shortest practical TTL.
- Logs should have short redacted retention.
- Exports/SBOMs should be on-demand or have a short TTL if stored.
- Cleanup logs must be redacted and minimal.
- Cleanup must be owner-aware after owner model exists.
- Cleanup must not read `.env`, credential files, state files, dumps, backups, or no-read sensitive adjacent files to classify them.
- Deleting a source upload should remove source bytes while preserving redacted historical results with a source-deleted marker by default.
- Deleting a job/result should remove report/export/SBOM availability and Raw JSON access.

Future checks:

- configured retention applies by resource class;
- cleanup respects owner boundaries;
- cleanup handles partial failures with controlled errors;
- cleanup does not remove another owner's data;
- manual download and backup caveats are visible.

## Admin And Operator Access

Checklist:

- Protect the admin principal.
- Keep admin setup explicit.
- Keep admin read-all separate from admin cleanup.
- In `self_hosted_single_admin`, the admin owns all resources by default.
- In private/community modes, admin read-all must be an explicit product/security decision.
- Admin cleanup must be scoped, redacted, and logged.
- Admin operations must not override redaction, target policy, Active feature flags, no-read sensitive-file boundaries, or owner checks unless an explicit cleanup policy allows a specific action.
- Do not frame admin/operator controls as billing, SaaS, paid tenant, or enterprise customer controls.

Future checks:

- admin-only operations reject regular users;
- admin cleanup logs are redacted;
- admin read-all, if accepted, is tested and documented;
- admin cannot use cleanup paths to access raw sensitive contents.

## Target-Based Flows And Active

Checklist:

- Target-based flows require explicit authorization.
- Target jobs require owner metadata even with `file_id: null`.
- Target histories are owner-scoped.
- Target strings, errors, reports, exports, and Raw JSON remain sensitive.
- Public/community instances should not expose Active one-HEAD by default.
- Active dry-run remains no-network and independent.
- Active one-HEAD remains internal/limited, opt-in, feature-flagged, authorized, double-confirmed, and capped to one `HEAD` request.
- Nmap remains out of scope.
- No broad scan, crawling, port scanning, fuzzing, exploitation, or credential validation.
- Rate limits and abuse controls are required before public target flows.
- Target history retention follows P0-05.

Future checks:

- target flows reject anonymous users outside trusted local;
- target authorization metadata is tied to the owner/job;
- dry-run reports `network_requests_sent: 0`;
- Active one-HEAD remains disabled by default;
- target results and exports require owner authorization.

## Public/Community Additional Controls

Checklist:

- Auth or anti-abuse gate before real uploads.
- Strict upload, file, archive, job, export, and API limits.
- Short retention for uploads, results, Raw JSON, target histories, logs, temp/cache, and stored artifacts if any.
- Visible onboarding/disclaimer acknowledgement.
- No regulated or highly sensitive data support.
- No anonymous public upload.
- No public Active/Nmap.
- No scan-as-a-service posture.
- Rate limits, fair-use controls, and abuse monitoring as future concerns.
- Operator ability to disable or restrict the instance.
- Clear statement that availability is a community convenience, not a commercial service guarantee.

Future checks:

- public/community mode blocks anonymous real uploads;
- limits are enforced;
- retention is short and visible;
- abuse controls exist before external users;
- Active/Nmap remain unavailable publicly unless separately designed and accepted.

## Deployment No-Go Checklist

Public/external deployment is no-go if any of these are true:

- anonymous upload is possible;
- anonymous file/job/result/export/Raw JSON read is possible;
- no owner model exists for real users;
- storage paths are public;
- TLS is absent outside localhost;
- reverse-proxy auth can be skipped by direct backend access;
- wildcard CORS is used with credentials;
- no CSRF protection exists for cookie-auth mutating routes;
- no retention/delete policy exists;
- logs capture secrets, Raw JSON, source contents, or target secrets;
- backups are public or undocumented;
- exports/SBOMs/Raw JSON are shared without auth;
- Active/Nmap is public without a separate accepted decision;
- no onboarding/disclaimer/limits messaging exists;
- no abuse controls exist for public/community use;
- `.env`, credential, dump, state, backup, or no-read sensitive files are processed beyond the accepted no-read context rules.

## Minimum Future Tests And Checks

Some items are automated runtime tests; others are deployment checklist/manual review items.

Runtime tests:

- no-auth plus non-local bind warns or fails when implemented;
- health leaks no sensitive data;
- sensitive routes require auth outside trusted local mode;
- direct ID access does not reveal resource existence before auth/owner checks;
- CORS is restrictive;
- credentialed wildcard CORS is rejected;
- CSRF is required for mutating routes if cookie auth is used;
- uploads, jobs, exports, SBOMs, and Raw JSON require auth/owner checks;
- storage paths are not served directly;
- exports require auth and owner authorization;
- logs redact sensitive values;
- cleanup respects configured retention and owner boundaries;
- target flows remain gated;
- Active dry-run remains no-network;
- Active one-HEAD remains disabled by default.

Manual/deployment review checks:

- TLS and reverse proxy are configured outside localhost;
- backend is not directly reachable around proxy auth;
- upload/body/timeouts are set at the proxy;
- storage directory permissions are least-privilege;
- backups are protected and retention is documented;
- logs have short retention and admin-only access;
- public/community limits and abuse controls are reviewed;
- no public Active/Nmap surface exists;
- disclaimers and upload/export warnings are visible.

## Relationship To P0 Runtime Work

This checklist depends on P0-01 through P0-05:

- P0-01 defines auth/session boundary and deployment modes.
- P0-02 defines the owner model and legacy migration posture.
- P0-03 defines deny-anonymous sensitive API guards.
- P0-04 defines owner-scoped jobs, results, reports, exports, SBOMs, Raw JSON, and target histories.
- P0-05 defines retention/delete semantics and cleanup boundaries.
- P0-06 defines deployment hardening gates before external exposure.

The P0 runtime planning closeout is now accepted:

```text
PASSIVE_ALPHA_P0_RUNTIME_PLANNING_CLOSED
```

The preferred next step is the first small runtime slice:

```text
PASSIVE-ALPHA-RUNTIME-01-AUTH-MODE-FLAG-AND-LOCAL-OPERATOR
```

Preference: keep runtime implementation in small, testable slices and do not combine auth, ownership, retention/delete, UI, and deployment hardening in one large diff.

## Open Questions

- Which reverse proxy should future docs recommend first: Caddy, Nginx, or Traefik?
- Should the first auth runtime use simple local password/session or reverse-proxy auth?
- How should no-auth localhost-only mode be configured and enforced?
- What initial public/community limits should apply if that optional mode is ever accepted?
- What minimum logs does Inspectra need for operator support without retaining sensitive context?
- What backup guidance should self-hosted operators receive?
- How should a community instance be documented without commercial availability guarantees?
- Should OpenAPI docs remain reachable in non-local modes, or require auth?
- Should stored export artifacts remain deferred in favor of on-demand rendering?
- How much deployment hardening should be automated versus operator checklist?

## Out Of Scope

- Runtime implementation.
- Tests or fixture changes.
- Auth implementation.
- Session or cookie implementation.
- Owner checks implementation.
- API guard implementation.
- DB/storage migration.
- Delete/reset implementation.
- Scheduler or cron implementation.
- UI implementation.
- Cleanup implementation.
- Report/export implementation.
- Reverse proxy implementation.
- TLS implementation.
- CORS/CSRF implementation.
- Billing.
- SaaS plans.
- Tenant billing model.
- Enterprise RBAC.
- Nmap.
- New Active behavior.
- New Passive analyzers.
- Target-policy relaxation.
- Public/community runtime approval.

## No-Scope

- No code.
- No runtime changes.
- No tests or fixture changes.
- No backend changes.
- No frontend changes.
- No runner changes.
- No auth implementation.
- No session or cookie implementation.
- No owner checks implementation.
- No API guard implementation.
- No DB/storage migration.
- No delete/reset implementation.
- No scheduler or cron implementation.
- No UI implementation.
- No cleanup implementation.
- No report/export implementation.
- No reverse-proxy implementation.
- No TLS implementation.
- No CORS/CSRF implementation.
- No probes.
- No live traffic.
- No DNS or HTTP.
- No Docker command execution.
- No Nmap.
- No port scanning.
- No crawling.
- No exploitation.
- No credential validation.
- No new Active capability.
- No new Passive analyzer.
- No billing.
- No SaaS plans.
- No tenant billing model.
- No target-policy relaxation.
- No local-lab mode.
- No `.env`, `.env.*`, or `.envrc` reads.
- No push.
- No real tag or release.

## Acceptance Criteria

- Final decision is recorded.
- Deployment modes are covered.
- Host binding and exposure checklist is defined.
- Reverse proxy and TLS checklist is defined.
- Auth/session/cookie hardening checklist is defined.
- CORS/CSRF checklist is defined.
- Storage permissions checklist is defined.
- Logs/audit checklist is defined.
- Backups/snapshots checklist is defined.
- Retention/cleanup config checklist is defined.
- Admin/operator access checklist is defined.
- Target-based and Active boundaries are covered.
- Public/community additional controls are covered.
- Deployment no-go checklist is defined.
- Minimum future tests/checks are listed.
- Relationship to auth, owner, retention, and next step is clear.
- No runtime or capability changes are made.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-01-AUTH-MODE-FLAG-AND-LOCAL-OPERATOR
```

Start runtime work by making the auth mode and default local/admin operator explicit before full login, owner metadata, API guards, owner checks, delete/cleanup, or deployment hardening implementation.

## Validation Commands

Reference checks for this docs-only deployment hardening checklist:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
