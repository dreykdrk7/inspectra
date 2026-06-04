# Passive Alpha Runtime 04 Owner Metadata Write Path

Status: `PASSIVE_ALPHA_RUNTIME_OWNER_METADATA_WRITE_PATH_ACCEPTED`.

Base runtime 03 deny-anonymous sensitive routes: `docs/future/passive-alpha-runtime-03-deny-anonymous-sensitive-routes.md`

Base owner model and storage migration plan: `docs/future/passive-alpha-p0-02-owner-model-and-storage-migration-plan.md`

Base owner-scoped resources plan: `docs/future/passive-alpha-p0-04-owner-scoped-jobs-results-exports.md`

Base P0 runtime planning closeout: `docs/future/passive-alpha-p0-07-p0-runtime-planning-closeout.md`

Commit scope: minimal backend owner metadata write path for new files and jobs. This block does not implement login, password verification, sessions, cookies, frontend login UI, multi-user runtime, owner-scoped reads, owner-scoped exports, legacy migration, delete/retention runtime, billing, SaaS tenants, Nmap, new Active behavior, or new analyzers.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_OWNER_METADATA_WRITE_PATH_ACCEPTED
```

Inspectra now writes owner metadata for new sensitive resources created through the backend write paths.

`trusted_local_no_auth` remains the default. In that mode, new uploads and jobs are owned by the default local/admin operator:

```text
local-admin
```

Auth-required modes still deny anonymous sensitive writes through Runtime-03, so no anonymous owner is minted for protected deployments before login/session work exists.

## What Was Implemented

- Added optional `owner_id` metadata to stored file records.
- Added optional `owner_id` metadata to job records.
- Added optional `owner_id` metadata to job list items.
- New uploads write `owner_id=local-admin` in `trusted_local_no_auth`.
- New file-based audit jobs write an owner derived from the source file owner when present, falling back to the current local operator.
- New target-based baseline jobs write `owner_id=local-admin` with `file_id: null`.
- New Active dry-run and one-HEAD jobs write `owner_id=local-admin` with `file_id: null`.
- Job status/result updates preserve the existing job owner.
- Legacy ownerless file and job records remain readable in trusted local mode.
- Backend tests cover owner writes, update preservation, target jobs, Active jobs, legacy ownerless compatibility, and auth-required anonymous write denial.

## Write Paths Covered

### Uploads

These routes now create file metadata with `owner_id=local-admin` in trusted local mode:

- `POST /files/pdf`
- `POST /files/image`
- `POST /files/manifest`
- `POST /files/archive`

### File-Based Jobs

These routes now create job metadata with an owner:

- `POST /audits/pdf/{file_id}`
- `POST /audits/image/{file_id}`
- `POST /audits/manifest/{file_id}`
- `POST /audits/archive/{file_id}`
- `POST /audits/project-archive/{file_id}`
- passive archive config audits, including Django, Docker, secrets review, Node package config, CI/CD, Kubernetes, Terraform, Nginx, Compose, Database, SQL DB, and Redis.

If the source file already has an owner, the job uses that owner. If the source file is legacy ownerless, trusted local job creation maps the new job to `local-admin`.

### Target-Based Jobs

These target jobs now carry owner metadata even though `file_id` is `null`:

- `POST /audits/web/basic`
- `POST /audits/domain/basic`
- `POST /audits/subdomains/basic`

### Active Jobs

These Active jobs now carry owner metadata even though `file_id` is `null`:

- `POST /active/network/dry-run`
- `POST /active/network/http-header-probe`

This does not expand Active behavior. Feature flags, target policy, authorization payloads, double confirmation, private/loopback blocking, redaction, no-Nmap boundaries, and no-network dry-run semantics remain unchanged.

## Current Principal Behavior

This slice introduces a small backend current-owner helper for existing local behavior.

In `trusted_local_no_auth`, the current owner is the default local/admin operator:

```text
local-admin
```

In auth-required modes, Runtime-03 blocks anonymous sensitive routes before writes occur. Because login, sessions, and authenticated principals do not exist yet, this slice does not mint a synthetic authenticated user for those modes.

## Legacy Data

Ownerless legacy records remain compatible in trusted local mode.

- Legacy file metadata without `owner_id` still validates.
- Legacy job metadata without `owner_id` still validates.
- Reads/lists still return legacy records.
- New jobs created from legacy ownerless source files in trusted local mode get `owner_id=local-admin`.
- Formal mapping or migration of legacy ownerless data remains deferred to Runtime-05.

## API Shape

`owner_id` is present on backend `StoredFile`, `JobRecord`, and `JobListItem` records. The value is not a secret. In this slice it is used as explicit local safety/accountability metadata, not as a billing tenant, SaaS tenant, subscription, quota, or enterprise customer identifier.

Future UI or API polish may decide whether to hide owner metadata from some response shapes, but this slice keeps it visible for transparency and tests.

## What Was Not Implemented

- Login.
- Password verification.
- Session creation.
- Cookies.
- CSRF changes.
- Frontend login UI.
- Multi-user runtime.
- User A/user B isolation.
- Owner-scoped reads.
- Owner-scoped job lists.
- Owner-scoped file lists.
- Owner-scoped reports, exports, SBOMs, or Raw JSON.
- Cross-owner denial.
- Full legacy migration.
- Storage layout migration.
- Delete or retention runtime.
- Deployment hardening runtime.
- Public/community runtime.
- Billing, SaaS, tenant billing, commercial plans, or enterprise multi-tenant behavior.
- Nmap.
- New Active behavior.
- New Passive analyzers.

## Security Notes

- Owner metadata is written before future owner enforcement exists.
- This is a foundation for later checks, not an access-control completion.
- Anonymous sensitive writes remain blocked in auth-required modes.
- `trusted_local_no_auth` remains localhost/dev/local trusted only.
- Redaction remains required after future owner checks succeed.
- Reports, exports, SBOMs, and Raw JSON still require owner-scoped authorization in a later runtime slice.

## Residual Risks

- New records have owner metadata, but owner-scoped reads are not enforced yet.
- Legacy ownerless records remain unmigrated.
- There is no user A/user B isolation yet.
- Auth-required modes still have no login/session path, so protected workflows are blocked until later auth runtime.
- `owner_id=local-admin` is a local compatibility marker, not a production multi-user identity model.
- Future route additions must assign owner metadata on writes before they become non-local ready.

## Acceptance Criteria

- New uploads receive `owner_id=local-admin` in trusted local mode.
- New file-based jobs receive owner metadata.
- New target-based jobs receive owner metadata with `file_id: null`.
- New Active dry-run and one-HEAD jobs receive owner metadata with `file_id: null`.
- Job result/status updates preserve owner metadata.
- Ownerless legacy records remain readable in trusted local mode.
- Auth-required modes continue denying anonymous writes before owner assignment.
- No login, sessions, cookies, multi-user runtime, owner-scoped reads, migrations, frontend UI, runner changes, Active expansion, Nmap, or new capabilities are added.

## Reference Validation Commands

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "owner or auth_mode or anonymous or health or files or jobs or active"
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend code.

No `.env`, `.env.*`, or `.envrc` files are read by this work. No external network traffic is required.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-05-LEGACY-LOCAL-DATA-MAPPING
```

Next runtime work should define and implement the trusted local mapping behavior for existing ownerless records before enforcing owner-scoped reads. Keep owner-scoped reads, delete/retention runtime, deployment hardening, UI login/status work, public/community support, billing/SaaS concepts, Nmap, new Active behavior, and new analyzers separately scoped.
