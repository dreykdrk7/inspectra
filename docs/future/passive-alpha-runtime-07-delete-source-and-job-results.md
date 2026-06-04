# Passive Alpha Runtime 07 Delete Source And Job Results

Status: `PASSIVE_ALPHA_RUNTIME_DELETE_SOURCE_JOB_RESULTS_ACCEPTED`.

Base Runtime-06 owner-scoped reads/exports: `docs/future/passive-alpha-runtime-06-owner-scoped-reads-and-exports.md`

Base retention/delete semantics plan: `docs/future/passive-alpha-p0-05-retention-delete-semantics-runtime-plan.md`

Base owner-scoped resources plan: `docs/future/passive-alpha-p0-04-owner-scoped-jobs-results-exports.md`

Commit scope: minimal backend owner-scoped delete runtime for source uploads and terminal job/result records. This block does not implement login, sessions, UI delete controls, delete-all-owned-data, scheduler cleanup, admin cleanup, demo reset, storage migration beyond existing JSON records, runner changes, frontend changes, Active expansion, Nmap, billing, SaaS tenants, or new analyzers.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_DELETE_SOURCE_JOB_RESULTS_ACCEPTED
```

Inspectra now has owner-scoped delete behavior for the two P0 resource classes that already exist in storage:

- source upload records and bytes;
- completed or failed job/result records.

The implementation preserves the accepted separation between source deletion and result deletion. Deleting a source upload removes the source bytes and file metadata, then marks related owned jobs with `source_file_deleted_at`. Deleting a job removes the stored job JSON, which makes job detail, Raw JSON, reports, exports, and SBOM generation unavailable because those surfaces are derived from the stored job record.

## Implemented Surfaces

- `DELETE /files/{file_id}`
- `DELETE /jobs/{job_id}`

Both routes are protected by Runtime-03 anonymous-route denial before handler execution in auth-required modes. Both routes use Runtime-06 owner checks through the current/effective owner before deleting anything.

Wrong-owner source/job delete attempts return generic not-found responses:

```json
{"detail": "File not found."}
```

or:

```json
{"detail": "Job not found."}
```

This avoids confirming whether another owner's resource exists.

## Source Upload Delete

`DELETE /files/{file_id}` now:

- requires the current/effective owner of the file;
- deletes the stored upload bytes;
- deletes the file metadata JSON;
- marks related owned jobs with `source_file_deleted_at`;
- preserves owned historical job results and report/export availability;
- does not cascade to job/result deletion.

Related wrong-owner jobs with the same `file_id` are not marked. Legacy ownerless records continue to map to `local-admin` only in `trusted_local_no_auth`, following Runtime-05.

## Job And Result Delete

`DELETE /jobs/{job_id}` now:

- requires the current/effective job owner;
- allows deletion only when the job is `completed` or `failed`;
- returns `409` for `queued` and `running` jobs until a separate cancellation policy exists;
- deletes the stored job JSON record;
- makes `GET /jobs/{job_id}` unavailable;
- makes Raw JSON unavailable through the job detail surface;
- makes Markdown, HTML, XML, and PDF report exports unavailable;
- makes CycloneDX and SPDX SBOM exports unavailable when applicable;
- applies equally to file-based jobs and target-based jobs with `file_id: null`.

No tombstone is retained in this slice. Repeated delete therefore returns the existing generic missing-job behavior.

## Redaction And Sensitivity

Delete responses intentionally return only minimal metadata:

- deleted source responses reuse the existing deleted file response and owner-scoped marker count;
- deleted job responses return only the job id and `deleted: true`.

Reports, exports, SBOMs, and Raw JSON remain redacted while the job exists. After job deletion, those surfaces are unavailable. This work does not make a secure deletion guarantee. Manual downloads, browser caches, screenshots, shared exports, backups, snapshots, object-store versions, host logs, and target-side infrastructure logs remain outside app-side deletion control.

## What Was Not Implemented

- Login.
- Password verification.
- Sessions.
- Cookies.
- Frontend delete controls.
- Multi-user runtime.
- DB users.
- Delete all owned data.
- Source-plus-derived cascade delete.
- Scheduled cleanup.
- Admin cleanup.
- Demo reset.
- Stored export artifact cleanup beyond on-demand availability.
- Background job cancellation.
- Queued/running job deletion.
- Runner changes.
- Frontend changes.
- Active expansion.
- Nmap.
- Billing, SaaS tenants, quotas, plans, or enterprise multi-tenancy.

## Acceptance Criteria

- Owner can delete an owned source upload.
- Wrong owner cannot delete source upload or learn whether it exists.
- Anonymous auth-required requests cannot delete source uploads.
- Source upload deletion removes source bytes and file metadata.
- Source upload deletion marks only related owned jobs with `source_file_deleted_at`.
- Source upload deletion does not remove historical job results by default.
- Owner can delete own completed job/result.
- Owner can delete own failed job/result.
- Wrong owner cannot delete job/result or learn whether it exists.
- Anonymous auth-required requests cannot delete jobs/results.
- Queued and running job deletion returns a controlled `409`.
- Deleted jobs make job detail, Raw JSON, report exports, and SBOM exports unavailable.
- Target-based job deletion removes app-side target history stored in the job record.
- Sparse, malformed, failed, and legacy-compatible jobs follow the same owner/delete rules.
- No frontend, runner, Active, Nmap, scheduler, delete-all, admin cleanup, demo reset, billing, SaaS, or new analyzer behavior is added.

## Reference Validation Commands

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "delete or owner or legacy or anonymous or files or jobs or export or sbom or active"
.venv/bin/python -m pytest backend/tests/test_backend.py
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend code.

No `.env`, `.env.*`, or `.envrc` files are read by this work. No Docker, runner, Nmap, Redis, Nginx, Terraform, Kubernetes, or external network command is required.

## Residual Risks

- There is still no login/session runtime, so `self_hosted_single_admin` remains blocked for anonymous sensitive routes.
- There is no real user A/user B authenticated runtime yet; owner checks use the current/effective local owner.
- Queued/running job cancellation remains future work.
- There is no delete-all-owned-data operation.
- There is no scheduler cleanup or retention TTL runtime.
- There is no admin cleanup policy.
- Source deletion keeps derived job results by default, so users must delete jobs separately when they want report/Raw JSON/export/SBOM availability removed.
- App-side deletion does not control external copies, host backups, snapshots, manual downloads, or target-side logs.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-08-DEPLOYMENT-HARDENING-SMOKE
```

Next runtime work should smoke the current trusted-local and auth-required behavior from a deployment-hardening angle, without adding login/session runtime, frontend controls, public/community support, billing/SaaS concepts, Nmap, new Active behavior, or new analyzers.
