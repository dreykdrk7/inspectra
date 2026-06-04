# Passive Alpha Runtime 09 Runtime P0 Closeout

Status: `PASSIVE_ALPHA_RUNTIME_P0_CLOSED_TRUSTED_LOCAL_HARDENED`.

Base Runtime-08 deployment hardening smoke: `docs/future/passive-alpha-runtime-08-deployment-hardening-smoke.md`

Base Runtime-07 delete source/job-results: `docs/future/passive-alpha-runtime-07-delete-source-and-job-results.md`

Base Runtime-06 owner-scoped reads/exports: `docs/future/passive-alpha-runtime-06-owner-scoped-reads-and-exports.md`

Base Runtime-05 legacy local data mapping: `docs/future/passive-alpha-runtime-05-legacy-local-data-mapping.md`

Base Runtime-04 owner metadata writes: `docs/future/passive-alpha-runtime-04-owner-metadata-write-path.md`

Base Runtime-03 deny anonymous sensitive routes: `docs/future/passive-alpha-runtime-03-deny-anonymous-sensitive-routes.md`

Base Runtime-02 single-admin auth skeleton: `docs/future/passive-alpha-runtime-02-single-admin-auth-skeleton.md`

Base Runtime-01 auth mode/local operator: `docs/future/passive-alpha-runtime-01-auth-mode-flag-and-local-operator.md`

P0 runtime planning closeout: `docs/future/passive-alpha-p0-07-p0-runtime-planning-closeout.md`

Successor Runtime-10 single-admin login/session plan: `docs/future/passive-alpha-runtime-10-single-admin-login-session-plan.md`

Commit scope: docs-only Runtime P0 closeout. This block summarizes accepted runtime decisions, current backend posture, Runtime-08 test evidence, preserved no-scope boundaries, residual gaps, and recommended next lines. It does not change backend, frontend, runner, tests, fixtures, storage, auth logic, sessions, cookies, target policy, Active behavior, reports, exports, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_P0_CLOSED_TRUSTED_LOCAL_HARDENED
```

The current Passive Alpha Runtime P0 line is closed.

Runtime P0 is accepted as hardened for the current trusted-local scope:

- `trusted_local_no_auth` remains the default and stays compatible with current local workflows;
- auth-required modes fail closed for anonymous sensitive routes;
- new files and jobs write owner metadata;
- trusted-local legacy ownerless records map to `local-admin`;
- file/job reads, reports, exports, SBOMs, and Raw JSON surfaces are owner-scoped;
- source upload and terminal job/result deletion are owner-scoped;
- queued/running job deletion returns a controlled conflict;
- backend smoke and full backend suite pass.

This closeout does not approve production/public/community readiness. It does not make `self_hosted_single_admin` usable for authenticated workflows yet because login, password verification, sessions, and cookies remain unimplemented.

## Runtime Decisions Accepted

| Runtime block | Decision | Summary |
| --- | --- | --- |
| Runtime-01 | `PASSIVE_ALPHA_RUNTIME_AUTH_MODE_LOCAL_OPERATOR_ACCEPTED` | Added `INSPECTRA_AUTH_MODE` and the stable default local/admin operator concept. |
| Runtime-02 | `PASSIVE_ALPHA_RUNTIME_SINGLE_ADMIN_AUTH_SKELETON_ACCEPTED` | Added `GET /auth/status` and safe configured/unconfigured auth status without login/session behavior. |
| Runtime-03 | `PASSIVE_ALPHA_RUNTIME_DENY_ANONYMOUS_ROUTES_ACCEPTED` | Denies anonymous sensitive backend routes in auth-required modes while keeping health/auth-status public. |
| Runtime-04 | `PASSIVE_ALPHA_RUNTIME_OWNER_METADATA_WRITE_PATH_ACCEPTED` | Writes `owner_id` metadata for uploads, file-based jobs, target jobs, and Active jobs. |
| Runtime-05 | `PASSIVE_ALPHA_RUNTIME_LEGACY_LOCAL_DATA_MAPPING_ACCEPTED` | Maps trusted-local ownerless legacy files/jobs to `local-admin` with lazy job persistence. |
| Runtime-06 | `PASSIVE_ALPHA_RUNTIME_OWNER_SCOPED_READS_EXPORTS_ACCEPTED` | Owner-scopes file/job reads, file-based job creation, reports, exports, SBOMs, Raw JSON, and target histories. |
| Runtime-07 | `PASSIVE_ALPHA_RUNTIME_DELETE_SOURCE_JOB_RESULTS_ACCEPTED` | Owner-scopes source upload deletion and completed/failed job/result deletion. |
| Runtime-08 | `PASSIVE_ALPHA_RUNTIME_DEPLOYMENT_HARDENING_SMOKE_PASSED` | Validates the current backend hardening state with focused and full backend tests. |

## Implemented Runtime State

### Auth And Public Status

- `INSPECTRA_AUTH_MODE` is parsed by backend settings.
- Default mode remains `trusted_local_no_auth`.
- Planned mode names remain accepted for future work:
  - `trusted_local_no_auth`
  - `self_hosted_single_admin`
  - `private_team_lightweight_users`
  - `public_community_limited_instance`
- `INSPECTRA_ADMIN_PASSWORD_HASH` is read only as a future credential-presence signal.
- `GET /auth/status` reports safe auth status and does not return password hashes, tokens, sessions, cookies, file/job data, target history, storage paths, or bypass guidance.

### Public Routes

The public-safe backend route set remains narrow:

- `GET /health`
- `GET /auth/status`
- `OPTIONS` preflight

### Auth-Required Fail-Closed Behavior

When auth is required, anonymous requests to sensitive routes receive a generic `401` before route handlers look up resources.

Covered sensitive route families include:

- uploads;
- file list/detail/delete;
- file-based audit creation;
- target-based baseline jobs;
- Active dry-run and one-HEAD jobs;
- job list/detail/Raw JSON;
- Markdown/HTML/XML/PDF exports;
- CycloneDX/SPDX SBOM exports;
- source upload delete;
- job/result delete.

### Owner Metadata And Legacy Mapping

- New uploads write `owner_id`.
- File-based jobs inherit source ownership where available.
- Target-based jobs carry owner metadata with `file_id: null`.
- Active dry-run and one-HEAD jobs carry owner metadata without expanding Active behavior.
- In `trusted_local_no_auth`, ownerless legacy files and jobs resolve to `local-admin`.
- Auth-required modes do not silently claim unresolved ownerless records for anonymous callers.

### Owner-Scoped Reads, Exports, SBOMs, And Raw JSON

- File lists are owner-filtered.
- File detail is owner-scoped.
- File-based job creation requires ownership of the source file.
- Job lists are owner-filtered.
- Job detail and Raw JSON payloads are owner-scoped.
- Markdown/HTML/XML/PDF exports require job-owner authorization before rendering.
- CycloneDX and SPDX SBOM exports require job-owner authorization before generation.
- Wrong-owner direct access returns generic not-found responses.

### Owner-Scoped Deletion

- `DELETE /files/{file_id}` requires current/effective file owner.
- Source upload deletion removes source bytes and file metadata.
- Source upload deletion preserves historical job results by default.
- Related owned jobs are marked with `source_file_deleted_at`.
- `DELETE /jobs/{job_id}` requires current/effective job owner.
- Completed and failed job/result deletion removes stored job JSON.
- Deleted jobs make job detail, Raw JSON, reports, exports, and SBOM exports unavailable.
- Queued and running job deletion returns a controlled conflict.
- Target-based job deletion removes app-side target history stored in the job record.

## Runtime-08 Evidence

Runtime-08 recorded the following validation evidence:

| Evidence | Result |
| --- | --- |
| `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend` | passed |
| Focused backend smoke | `120 passed, 111 deselected` |
| Full backend suite | `231 passed` |
| Forbidden/no-scope text review | expected no-scope/framing/test-negative hits only |
| `git diff --check` | passed |
| `git diff --cached --check` | passed |

The focused smoke covered auth mode, auth status, anonymous denial, owner behavior, legacy mapping, delete behavior, health, files, jobs, exports, SBOMs, and Active route families.

## Product And Security Posture

### Trusted Local

Trusted local use is accepted and hardened for the current scope.

`trusted_local_no_auth` remains suitable only for localhost/dev/local trusted operator workflows and synthetic fixture demos. It is not approval for LAN, public internet, shared external users, commercial service exposure, or untrusted uploads.

### Self-Hosted Single Admin

`self_hosted_single_admin` fails closed for anonymous sensitive routes, and `/auth/status` can report whether a future admin credential hash is configured.

It is not usable yet for authenticated workflows because login, password verification, sessions, cookies, and frontend login handling do not exist.

### Private Team And Public/Community

Private team and optional public/community modes remain not ready.

They require login/session runtime, user/owner identity, frontend auth handling, anti-abuse/limits review, visible disclaimers, retention controls, deployment hardening, and security review before use outside a trusted local operator boundary.

### SaaS, Billing, And Tenancy

Inspectra remains open-source, altruistic, local-first, and self-hosted-first.

The auth, ownership, retention, and hardening work exists for safety in local, self-hosted, private/internal, and optional community deployments. It is not a commercial SaaS, billing, quota, paid-plan, tenant billing, subscription, or enterprise multi-tenant model.

### Active And Nmap

Active Alpha remains internal, limited, feature-flag gated, and separately scoped.

Nmap remains unimplemented and out of scope. Runtime P0 does not add broad scanning, crawling, port scanning, target expansion, policy relaxation, credential validation, exploitation, or new Active capabilities.

## Remaining Gaps

- Login runtime.
- Password verification.
- Session and cookie runtime.
- Frontend login/status handling.
- Cookie and CSRF hardening.
- Deployment TLS/reverse-proxy implementation and operator docs.
- Delete-all-owned-data.
- Scheduler cleanup and retention TTL.
- Admin cleanup.
- Public/community anti-abuse and rate limits.
- UI disclaimers and acknowledgements.
- Frontend owner/permission state.
- Authenticated user A/user B runtime.
- Admin read-all policy, if ever accepted.
- Visible retention/delete UX.

## Risk Register

- Auth-required modes are intentionally fail-closed but not usable until login/session runtime exists.
- `trusted_local_no_auth` must remain localhost/dev/local trusted only.
- Manual downloads, browser caches, screenshots, shared exports, host backups, snapshots, object-store versions, and target-side logs remain outside app-side deletion control.
- Inspectra does not make a secure deletion guarantee.
- Future frontend code must handle `401` and permission states cleanly.
- Future route additions must be protected by default unless explicitly documented as public-safe.
- Legacy ownerless records must not become exposed in auth-required or future multi-user modes.
- Active target flows must remain feature-flag gated, authorization gated, and separately reviewed.
- Future public/community use needs anti-abuse, retention, deployment, and security review before exposure.

## No-Scope Preserved

- No code changes beyond documentation.
- No runtime changes.
- No backend, frontend, runner, tests, or fixture changes.
- No login.
- No password verification.
- No sessions.
- No cookies.
- No frontend login.
- No cleanup scheduler.
- No delete-all-owned-data.
- No admin cleanup.
- No Docker execution.
- No probes, DNS, external HTTP, Nmap, or live target traffic.
- No Active expansion.
- No target policy relaxation.
- No billing, SaaS, tenant billing, subscription, quota, paid-plan, or enterprise tenancy model.
- No push, tag, or release.
- No `.env`, `.env.*`, or `.envrc` reads.

## Acceptance Criteria

- Runtime-01 through Runtime-08 decisions are summarized.
- Current implemented runtime state is explicit.
- Runtime-08 evidence is preserved.
- Trusted-local, auth-required, self-hosted, private-team, public/community, Active, Nmap, and SaaS postures are explicit.
- Remaining gaps are explicit.
- Risk register is consolidated.
- Next path is recommended.
- No runtime or capability changes are made.

## Recommended Next Paths

Primary technical recommendation:

```text
PASSIVE-ALPHA-RUNTIME-10-SINGLE-ADMIN-LOGIN-SESSION-PLAN
```

Rationale: this is the next necessary docs-first line if Inspectra should become usable in `self_hosted_single_admin` mode beyond fail-closed anonymous protection. It should design login, password verification, session/cookie behavior, CSRF implications, frontend 401/session state, logout, and auth-status UX before runtime implementation.

Product/publication alternative:

```text
PASSIVE-ALPHA-TRUSTED-LOCAL-RELEASE-NOTES
```

Rationale: this is appropriate if the goal is to publish or explain the current trusted-local hardened state before starting login/session work.

Recommended order:

1. `PASSIVE-ALPHA-RUNTIME-10-SINGLE-ADMIN-LOGIN-SESSION-PLAN`
2. `PASSIVE-ALPHA-TRUSTED-LOCAL-RELEASE-NOTES`

Keep runtime implementation separate from release notes unless explicitly scoped.

Runtime-10 now accepts the single-admin login/session plan at docs-first level and recommends `PASSIVE-ALPHA-RUNTIME-11-PASSWORD-VERIFY-HELPER` as the next runtime slice. Runtime-09 remains the historical closeout for the trusted-local hardened P0 line.
