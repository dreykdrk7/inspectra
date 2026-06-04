# Passive Alpha Runtime 06 Owner Scoped Reads And Exports

Status: `PASSIVE_ALPHA_RUNTIME_OWNER_SCOPED_READS_EXPORTS_ACCEPTED`.

Base runtime 05 legacy local data mapping: `docs/future/passive-alpha-runtime-05-legacy-local-data-mapping.md`

Base runtime 04 owner metadata write path: `docs/future/passive-alpha-runtime-04-owner-metadata-write-path.md`

Base runtime 03 deny-anonymous sensitive routes: `docs/future/passive-alpha-runtime-03-deny-anonymous-sensitive-routes.md`

Base owner-scoped resources plan: `docs/future/passive-alpha-p0-04-owner-scoped-jobs-results-exports.md`

Base owner model and storage migration plan: `docs/future/passive-alpha-p0-02-owner-model-and-storage-migration-plan.md`

Commit scope: minimal backend owner-scoped read/export enforcement using the existing current/effective owner. This block does not implement login, password verification, sessions, cookies, frontend login UI, multi-user runtime, DB users, delete/retention runtime, broad storage migration, billing, SaaS tenants, Nmap, new Active behavior, or new analyzers.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_OWNER_SCOPED_READS_EXPORTS_ACCEPTED
```

Inspectra now checks ownership before returning sensitive file/job metadata or rendering job-derived outputs.

In `trusted_local_no_auth`, the current owner is still the default local/admin operator:

```text
local-admin
```

In auth-required modes, Runtime-03 continues to deny anonymous sensitive routes before resource lookup. Runtime-06 does not add a real authenticated principal yet.

## What Was Implemented

- Added central backend helpers for current-owner comparisons.
- File lists now return only files owned by the current owner.
- File detail now checks owner before returning metadata.
- File-based audit creation now checks source-file owner before kind-specific validation or job creation.
- Job lists now return only jobs owned by the current owner.
- Job detail and Raw JSON payloads now check job owner before returning data.
- Markdown/HTML/XML/PDF exports now check job owner before rendering.
- CycloneDX and SPDX SBOM exports now check job owner before generation.
- Target-based jobs remain owner-scoped even when `file_id` is `null`.
- Failed, sparse, malformed, queued, running, and completed jobs all use the same owner check.
- Job list filtering happens before building job summaries for the response.

## Protected Surfaces

- `GET /files`
- `GET /files/{file_id}`
- `POST /audits/*/{file_id}` for file-based jobs
- `GET /jobs`
- `GET /jobs/{job_id}`
- `GET /jobs/{job_id}/export/markdown`
- `GET /jobs/{job_id}/export/html`
- `GET /jobs/{job_id}/export/xml`
- `GET /jobs/{job_id}/export/pdf`
- `GET /jobs/{job_id}/sbom/cyclonedx-json`
- `GET /jobs/{job_id}/sbom/spdx-json`
- target-based job history through the job list/detail surfaces

## Trusted Local Behavior

`trusted_local_no_auth` remains compatible.

- New local files and jobs owned by `local-admin` remain visible.
- Runtime-05 legacy ownerless files and jobs resolved to `local-admin` remain visible.
- Archive-only passive analyzers, target-based baseline jobs, Active dry-run jobs, and Active one-HEAD jobs keep existing trusted-local behavior.
- Existing report/export/SBOM routes keep working for current-owner jobs.

## Legacy Ownerless Behavior

Runtime-05 effective-owner mapping is reused.

- Legacy ownerless files map to `local-admin` in trusted local mode before the Runtime-06 owner check.
- Legacy ownerless jobs map to `local-admin` in trusted local mode before the Runtime-06 owner check.
- Legacy target jobs with `file_id: null` map to `local-admin`.
- Auth-required modes do not silently map missing owner metadata.

## Wrong-Owner And Missing-Owner Behavior

Wrong-owner direct reads and exports return generic not-found responses:

```json
{"detail": "File not found."}
```

or:

```json
{"detail": "Job not found."}
```

The chosen behavior is generic `404`, not `403`, so direct ID access does not reveal whether the resource exists. Export and SBOM routes deny before report rendering or SBOM generation.

In auth-required modes, anonymous requests still receive the Runtime-03 generic `401` before owner lookup:

```json
{"detail": "Authentication required."}
```

## What Was Not Implemented

- Login.
- Password verification.
- Session creation.
- Cookies.
- CSRF changes.
- Frontend login UI.
- Multi-user UI.
- DB users.
- User A/user B authenticated runtime.
- Admin read-all policy.
- Delete or retention runtime.
- Job/result deletion.
- Full storage migration.
- Public/community runtime.
- Billing, SaaS, tenant billing, paid plans, quotas, or enterprise multi-tenant behavior.
- Nmap.
- New Active behavior.
- New Passive analyzers.

## Security Notes

- Backend ownership is authoritative; frontend filtering remains UX only.
- Redaction remains required after owner checks pass.
- Storage paths and user-controlled filenames are not authorization.
- Wrong-owner exports and SBOMs deny before rendering/generation.
- Auth-required modes still lack login/session runtime and are intentionally blocked for anonymous sensitive flows.

## Residual Risks

- No authenticated login/session path exists yet.
- `self_hosted_single_admin` still cannot run protected workflows through an authenticated session.
- There is no real user A/user B runtime yet, only owner checks using the current/effective owner.
- Delete/retention runtime remains future work.
- Frontend does not yet surface a dedicated owner/permission state.
- Full migration and missing-owner claiming remain future work.

## Acceptance Criteria

- Trusted-local file lists include current-owner and mapped legacy records.
- Trusted-local job lists include current-owner and mapped legacy records.
- Direct file/job reads work for `local-admin`.
- Direct file/job reads deny wrong-owner records with generic not-found responses.
- File-based audit creation denies wrong-owner source files before job creation.
- Target jobs with `file_id: null` are owner-scoped.
- Failed, sparse, malformed, queued, running, and completed jobs are owner-scoped.
- Markdown/HTML/XML/PDF exports deny wrong-owner jobs before rendering.
- CycloneDX/SPDX SBOM exports deny wrong-owner jobs before generation.
- Anonymous auth-required requests still deny before owner lookup.
- No login, sessions, cookies, multi-user runtime, frontend login UI, delete/retention runtime, runner changes, Active expansion, Nmap, or new capabilities are added.

## Reference Validation Commands

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "owner or legacy or anonymous or files or jobs or export or sbom or active"
.venv/bin/python -m pytest backend/tests/test_backend.py
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend code.

No `.env`, `.env.*`, or `.envrc` files are read by this work. No external network traffic is required.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-07-DELETE-SOURCE-AND-JOB-RESULTS
```

Next runtime work should define and implement owner-scoped source delete and job/result delete behavior. Keep login/session runtime, UI login/status work, broader migration, deployment hardening, public/community support, billing/SaaS concepts, Nmap, new Active behavior, and new analyzers separately scoped.
