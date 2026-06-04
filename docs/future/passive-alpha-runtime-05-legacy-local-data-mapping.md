# Passive Alpha Runtime 05 Legacy Local Data Mapping

Status: `PASSIVE_ALPHA_RUNTIME_LEGACY_LOCAL_DATA_MAPPING_ACCEPTED`.

Base runtime 04 owner metadata write path: `docs/future/passive-alpha-runtime-04-owner-metadata-write-path.md`

Base owner model and storage migration plan: `docs/future/passive-alpha-p0-02-owner-model-and-storage-migration-plan.md`

Base owner-scoped resources plan: `docs/future/passive-alpha-p0-04-owner-scoped-jobs-results-exports.md`

Base P0 runtime planning closeout: `docs/future/passive-alpha-p0-07-p0-runtime-planning-closeout.md`

Successor runtime 06 owner-scoped reads and exports: `docs/future/passive-alpha-runtime-06-owner-scoped-reads-and-exports.md`

Commit scope: minimal backend storage mapping for trusted-local legacy ownerless data. This block does not implement login, password verification, sessions, cookies, frontend login UI, multi-user runtime, owner-scoped reads, cross-owner denial, broad storage migration, delete/retention runtime, billing, SaaS tenants, Nmap, new Active behavior, or new analyzers.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_LEGACY_LOCAL_DATA_MAPPING_ACCEPTED
```

Inspectra now maps existing ownerless local file and job records to the default local/admin operator when running in `trusted_local_no_auth`.

The effective owner is:

```text
local-admin
```

This mapping is trusted-local compatibility only. It is not a production multi-user identity model, billing tenant, SaaS tenant, quota, commercial customer, or enterprise tenancy concept.

## Strategy Chosen

Runtime-05 uses on-read normalization with lazy persistence for touched jobs.

- `FileStore` normalizes ownerless legacy file records to `local-admin` on list/detail reads in `trusted_local_no_auth`.
- `JobStore` normalizes ownerless legacy job records to `local-admin` on list/detail/export/SBOM reads in `trusted_local_no_auth`.
- Job status/result updates preserve the effective owner and lazily write `owner_id=local-admin` back to the updated job record.
- The implementation does not walk storage, rewrite every historical record, or create a migration marker.

This keeps legacy trusted-local data compatible while avoiding a broad storage mutation before owner-scoped reads and retention/delete runtime exist.

## Trusted Local Behavior

In `trusted_local_no_auth`:

- legacy file detail responses expose `owner_id=local-admin`;
- legacy file list responses expose `owner_id=local-admin`;
- legacy file-based jobs expose `owner_id=local-admin`;
- legacy target-based jobs with `file_id: null` expose `owner_id=local-admin`;
- legacy job lists expose `owner_id=local-admin`;
- legacy Markdown/HTML/XML/PDF exports and SBOM routes continue using the existing job storage path and see the normalized owner;
- new jobs created from legacy source files keep using `local-admin`;
- job updates on legacy records persist the effective owner on that job only.

## Auth-Required Behavior

In auth-required modes, missing owner metadata remains unresolved.

Runtime-03 still denies anonymous sensitive routes before upload, file, job, export, SBOM, target, or Active handlers can reveal resource existence. Because login, sessions, and authenticated principals do not exist yet, Runtime-05 does not map ownerless data for auth-required modes.

Runtime-06 now applies generic not-found denials for wrong-owner or unresolved-owner reads/exports while keeping auth-required anonymous routes blocked before lookup.

## API Shape

`owner_id` remains visible on `StoredFile`, `JobRecord`, and `JobListItem` API shapes.

For trusted-local legacy records without stored owner metadata, API responses return:

```text
owner_id: local-admin
```

This is an effective owner mapping. It does not mean the original legacy file necessarily had an `owner_id` field on disk before Runtime-05.

## What Was Implemented

- Added a centralized storage helper for resolving effective record owners.
- Normalized `StoredFile` load/list paths.
- Normalized `JobRecord` load/list paths.
- Preserved existing owner metadata on new records.
- Preserved owner metadata through job result/status updates.
- Added backend tests for trusted-local legacy file/job/target-job mapping.
- Added backend tests for legacy export and SBOM compatibility.
- Added backend tests that a touched legacy job is lazily written back with `owner_id=local-admin`.
- Kept auth-required anonymous route denial unchanged.

## What Was Not Implemented

- Login.
- Password verification.
- Session creation.
- Cookies.
- CSRF changes.
- Frontend login UI.
- Multi-user runtime.
- Owner-scoped reads.
- Owner-filtered lists.
- Cross-owner denial.
- Full migration over all stored files.
- Migration status fields.
- Delete or retention runtime.
- Deployment hardening runtime.
- Public/community runtime.
- Billing, SaaS tenants, tenant billing, commercial plans, or enterprise multi-tenant behavior.
- Nmap.
- New Active behavior.
- New Passive analyzers.

## Security Notes

- This is a compatibility bridge for trusted local data, not a complete authorization layer.
- Auth-required anonymous routes remain blocked before owner mapping matters.
- Ownerless records are not silently mapped in auth-required modes.
- Redaction remains required after any future owner check succeeds.
- Storage paths and user-controlled filenames remain non-authoritative.
- Future owner-scoped reads must still authorize every sensitive file, job, report, export, SBOM, Raw JSON, and target history.

## Residual Risks

- Owner-scoped reads and exports are now enforced by Runtime-06 for the implemented read/export surfaces.
- There is still no user A/user B isolation.
- Trusted-local mapping assumes legacy local data belongs to the local operator.
- Legacy files are not mass-rewritten, so on-disk metadata may still omit `owner_id` until touched by a later operation.
- Auth-required modes still need login/session runtime before protected workflows can proceed.
- Future delete/retention behavior depends on owner-scoped reads and missing-owner policy.

## Acceptance Criteria

- Legacy ownerless files map to `local-admin` in trusted-local list/detail reads.
- Legacy ownerless jobs map to `local-admin` in trusted-local list/detail reads.
- Legacy target-based jobs with `file_id: null` map to `local-admin`.
- Exports and SBOM routes remain compatible for legacy jobs.
- Updating a legacy ownerless job persists the effective owner on that job.
- Auth-required anonymous routes still deny before owner mapping can reveal sensitive data.
- No login, sessions, cookies, multi-user runtime, owner-scoped reads, cross-owner denial, full migration, frontend UI, runner changes, Active expansion, Nmap, or new capabilities are added.

## Reference Validation Commands

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "legacy or owner or auth_mode or anonymous or health or files or jobs or export or sbom"
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

Runtime-06 now implements owner-scoped reads and exports for files, jobs, reports, SBOMs, Raw JSON/job detail, and target histories through job surfaces. Next runtime work should define owner-scoped source delete and job/result delete behavior. Keep broader retention runtime, cleanup, deployment hardening, UI login/status work, public/community support, billing/SaaS concepts, Nmap, new Active behavior, and new analyzers separately scoped.
