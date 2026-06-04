# Passive Alpha Runtime 03 Deny Anonymous Sensitive Routes

Status: `PASSIVE_ALPHA_RUNTIME_DENY_ANONYMOUS_ROUTES_ACCEPTED`.

Base runtime 02 single-admin auth skeleton: `docs/future/passive-alpha-runtime-02-single-admin-auth-skeleton.md`

Base deny-anonymous guard plan: `docs/future/passive-alpha-p0-03-deny-anonymous-reads-api-guards.md`

Base P0 runtime planning closeout: `docs/future/passive-alpha-p0-07-p0-runtime-planning-closeout.md`

Commit scope: minimal backend guard for anonymous requests in auth-required modes. This block does not implement login, password verification, sessions, cookies, CSRF, frontend login UI, DB users, owner metadata, storage migrations, owner-scoped reads, owner-scoped writes, delete/retention runtime, deployment hardening, billing, SaaS tenants, Nmap, new Active behavior, or new analyzers.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_DENY_ANONYMOUS_ROUTES_ACCEPTED
```

Inspectra now denies anonymous requests to sensitive backend routes whenever `is_auth_required(settings)` is true.

`trusted_local_no_auth` remains the default and keeps existing local behavior unchanged.

## What Was Implemented

- Added a centralized backend HTTP guard.
- The guard uses the existing auth-mode helpers instead of route-specific ad hoc checks.
- In auth-required modes, anonymous requests to non-public routes return a generic `401`.
- The generic response is:

```json
{"detail": "Authentication required."}
```

- The denial happens before route handlers look up files, jobs, exports, SBOMs, targets, or Active request details.
- `GET /health` remains public.
- `GET /auth/status` remains public and continues to expose only safe auth-mode status.
- `OPTIONS` preflight is allowed because it does not expose application data.
- Existing `trusted_local_no_auth` uploads, jobs, reports, exports, Raw JSON, target flows, and feature-flag behavior remain compatible.
- Backend tests cover public routes and anonymous denial for files, uploads, audits, target-based jobs, Active dry-run/live-header routes, jobs, exports, and SBOM exports.

## Protected Route Families

The guard applies to all backend paths except the public-safe routes listed below when auth is required. This includes:

- file uploads: `POST /files/pdf`, `/files/image`, `/files/manifest`, `/files/archive`;
- file list, detail, and delete: `GET /files`, `GET /files/{file_id}`, `DELETE /files/{file_id}`;
- file-based audit creation: `POST /audits/*/{file_id}`;
- target-based baseline jobs: `POST /audits/web/basic`, `/audits/domain/basic`, `/audits/subdomains/basic`;
- Active dry-run and live-header jobs: `POST /active/network/dry-run`, `/active/network/http-header-probe`;
- job list and detail: `GET /jobs`, `GET /jobs/{job_id}`;
- report exports: `GET /jobs/{job_id}/export/markdown`, `/html`, `/xml`, `/pdf`;
- SBOM exports: `GET /jobs/{job_id}/sbom/cyclonedx-json`, `/spdx-json`;
- any future backend route unless it is explicitly made public-safe in a later scoped change.

## Public Routes

Only these routes are intentionally public in this slice:

- `GET /health`
- `GET /auth/status`
- `OPTIONS` preflight

`GET /auth/status` does not authenticate users, create sessions, set cookies, return tokens, return password hashes, or expose file/job/target data.

## Trusted Local Compatibility

`trusted_local_no_auth` remains the default for localhost/dev/local trusted workflows. In that mode, the guard does not change existing endpoint behavior.

Auth-required modes now fail closed for anonymous sensitive routes. This is intentional even though login and session support are not implemented yet; those modes are not fully usable for protected workflows until later runtime slices add authenticated identity.

## What Was Not Implemented

- Login.
- Password verification.
- Session creation.
- Cookies.
- CSRF changes.
- Frontend login UI.
- DB users.
- `owner_id`.
- Storage migrations.
- Owner metadata writes.
- Owner-scoped reads.
- Owner-scoped exports.
- Owner-scoped target histories.
- Delete or retention runtime.
- Deployment hardening runtime.
- Public/community runtime.
- Billing, SaaS, tenant billing, commercial plans, or enterprise multi-tenant behavior.
- Nmap.
- New Active behavior.
- New Passive analyzers.

## Security Notes

- Denials are intentionally generic and do not reveal whether a file, job, export, SBOM, or target exists.
- The guard does not weaken Active target policy, feature flags, authorization payloads, double-confirmation requirements, or redaction.
- Redaction remains required after future authentication succeeds.
- Auth-required modes are still incomplete until login/session and owner metadata slices land.

## Residual Risks

- Auth-required modes now block anonymous sensitive access but do not yet provide an authenticated use path.
- Owner metadata is not written yet.
- Owner-scoped reads, reports, exports, SBOMs, Raw JSON, and target histories are not enforced yet.
- `trusted_local_no_auth` remains appropriate only for localhost/dev/local trusted use.
- Future route additions must either remain protected by default or document a narrow public-safe exception.

## Acceptance Criteria

- `trusted_local_no_auth` remains compatible.
- `self_hosted_single_admin` denies anonymous sensitive routes.
- Public-safe health and auth-status routes continue to work.
- Sensitive route denial is generic and does not expose resource existence.
- Upload, file, audit, target, Active, job, export, and SBOM route families are covered.
- No login, sessions, cookies, owner metadata, migrations, frontend UI, runner changes, Active expansion, Nmap, or new capabilities are added.

## Reference Validation Commands

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "auth_mode or auth_status or anonymous or health or files or jobs or active"
git diff --check
git diff --cached --check
git status --short
```

No npm suite is required because this slice does not touch frontend code.

No `.env`, `.env.*`, or `.envrc` files are read by this work. No external network traffic is required.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-04-OWNER-METADATA-WRITE-PATH
```

Next runtime work should write owner metadata on new uploads and target-based jobs, while preserving trusted-local compatibility and keeping owner-scoped reads, migrations, retention/delete runtime, deployment hardening, UI polish, public/community support, billing/SaaS concepts, Nmap, new Active behavior, and new analyzers separately scoped.
