# Passive Alpha Runtime 08 Deployment Hardening Smoke

Status: `PASSIVE_ALPHA_RUNTIME_DEPLOYMENT_HARDENING_SMOKE_PASSED`.

Base Runtime-07 delete source/job-results: `docs/future/passive-alpha-runtime-07-delete-source-and-job-results.md`

Base Runtime-06 owner-scoped reads/exports: `docs/future/passive-alpha-runtime-06-owner-scoped-reads-and-exports.md`

Base Runtime-05 legacy local data mapping: `docs/future/passive-alpha-runtime-05-legacy-local-data-mapping.md`

Base Runtime-04 owner metadata writes: `docs/future/passive-alpha-runtime-04-owner-metadata-write-path.md`

Base Runtime-03 deny anonymous sensitive routes: `docs/future/passive-alpha-runtime-03-deny-anonymous-sensitive-routes.md`

Base Runtime-02 single-admin auth skeleton: `docs/future/passive-alpha-runtime-02-single-admin-auth-skeleton.md`

Base Runtime-01 auth mode/local operator: `docs/future/passive-alpha-runtime-01-auth-mode-flag-and-local-operator.md`

Base deployment hardening checklist: `docs/future/passive-alpha-p0-06-deployment-hardening-checklist.md`

Commit scope: backend smoke validation and documentation for the current Passive Alpha runtime hardening state. This block does not implement login, password verification, sessions, cookies, frontend login UI, cleanup scheduler, delete-all-owned-data, admin cleanup, runtime TLS/proxy configuration, Docker execution, runner changes, Active expansion, Nmap, billing, SaaS tenants, or new analyzers.

## Final Decision

```text
PASSIVE_ALPHA_RUNTIME_DEPLOYMENT_HARDENING_SMOKE_PASSED
```

The current backend Runtime-01 through Runtime-07 state passes the deployment-hardening smoke for trusted local and auth-required fail-closed behavior.

This smoke is not production readiness, public/community readiness, SaaS readiness, billing readiness, or approval for broader Active/Nmap behavior. It confirms that the implemented backend guardrails remain coherent before closing the P0 runtime line.

## Commands Executed

```text
git status --short
git status --branch --short
git log --oneline -12
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "auth_mode or auth_status or anonymous or owner or legacy or delete or health or files or jobs or export or sbom or active"
.venv/bin/python -m pytest backend/tests/test_backend.py
rg -n "Nmap|port scan|crawler|credential valid|vulnerability confirmed|exploitability confirmed|safe target|production ready|SaaS|billing|tenant billing|subscription" README.md docs/architecture.md docs/security-scope.md docs/future/passive-alpha-runtime-0*.md backend/app backend/tests
git diff --check
git diff --cached --check
git status --short
```

## Results

| Check | Result |
| --- | --- |
| Initial `git status --short` | clean |
| Initial branch status | `main...origin/main [ahead 52]` |
| Initial top commit | `3377678 feat(alpha): delete owned source and results` |
| `compileall backend` | passed |
| Focused backend smoke | `120 passed, 111 deselected` |
| Full backend suite | `231 passed` |
| Forbidden/no-scope text review | expected no-scope/framing/test-negative hits only |
| `git diff --check` | passed |
| `git diff --cached --check` | passed |

## Coverage Confirmed

### Trusted Local Default

- `trusted_local_no_auth` remains the default auth mode.
- Trusted-local health, upload/file/job flows remain compatible.
- New local uploads and jobs use the default local/admin operator.
- Legacy local ownerless files and jobs still map to `local-admin`.

### Public Routes

The public-safe backend route set remains narrow:

- `GET /health`
- `GET /auth/status`
- `OPTIONS` preflight

`GET /auth/status` reports auth mode/configuration status without returning password hashes, tokens, sessions, file/job metadata, target history, storage paths, or feature-bypass guidance.

### Auth-Required Anonymous Denial

`self_hosted_single_admin` and other auth-required modes still deny anonymous sensitive routes before route handlers perform resource lookup.

Sensitive route families covered by the smoke include:

- uploads;
- file list/detail/delete;
- file-based audit creation;
- target-based baseline job creation;
- Active dry-run and one-HEAD route families;
- job list/detail;
- Raw JSON/job payload surfaces;
- Markdown/HTML/XML/PDF report exports;
- CycloneDX/SPDX SBOM exports;
- source upload delete;
- job/result delete.

### Owner Metadata And Owner Scope

- New uploads write owner metadata.
- File-based jobs inherit source owner where available.
- Target-based jobs carry owner metadata even when `file_id` is `null`.
- Active dry-run and one-HEAD jobs carry owner metadata without expanding Active behavior.
- File/job lists are owner-filtered.
- File/job direct reads are owner-scoped.
- Report exports and SBOM exports check job owner before rendering/generation.
- Wrong-owner reads and deletes return generic not-found responses.

### Delete Semantics

- Source upload deletion is owner-scoped.
- Source upload deletion removes source bytes and file metadata.
- Source upload deletion preserves historical job results by default.
- Related owned jobs are marked with `source_file_deleted_at`.
- Completed and failed job/result deletion is owner-scoped.
- Deleted jobs make job detail, Raw JSON, report exports, and SBOM exports unavailable.
- Queued and running job deletion returns a controlled conflict.

### Active State

- Active dry-run remains separate and no-network.
- Active one-HEAD remains feature-flag gated, authorization-gated, and limited.
- The smoke did not add Active behavior.
- The smoke did not run live probes or external target traffic.
- Nmap remains out of scope.

## Forbidden/No-Scope Review

The no-scope text search found expected references only:

- explicit no-scope statements for Nmap, port scanning, crawling, SaaS, billing, tenant billing, subscription, production readiness, and exploitability claims;
- security-scope framing that Inspectra is open-source, local-first, self-hosted-first, and not commercial SaaS;
- backend/reporting copy that says Active dry-run/limited header probe do not include Nmap or broad scanning;
- backend tests that assert forbidden phrases such as `vulnerability confirmed` and `credential valid` are absent.

No positive promise was found that would make Inspectra production-ready, SaaS/commercial, Nmap-enabled, crawler-enabled, port-scanning, exploitability-confirming, or credential-validating.

## Gaps Remaining

- No login runtime.
- No password verification.
- No sessions or cookies.
- No frontend login UI.
- No public/community readiness.
- No private-team multi-user runtime.
- No admin read-all or admin cleanup policy.
- No delete-all-owned-data operation.
- No cleanup scheduler or retention TTL runtime.
- No deployment TLS/reverse-proxy implementation.
- No runtime CORS/CSRF hardening beyond current configured CORS behavior.
- No secure deletion guarantee.
- No frontend owner/permission state.
- No Nmap.
- No new Active capability.

## No-Scope Preserved

- No `.env`, `.env.*`, or `.envrc` files were read.
- No Docker command was executed.
- No runner command was executed.
- No external HTTP/DNS/probe traffic was executed.
- No Nmap command was executed.
- No push, tag, or release was created.
- No login/session/password/cookie runtime was added.
- No frontend code was changed.
- No cleanup scheduler, delete-all, admin cleanup, demo reset, billing/SaaS tenant model, or new analyzer was added.

## Acceptance Criteria

- Trusted local default behavior passes.
- Auth-required anonymous behavior fails closed for sensitive routes.
- Public-safe routes remain narrow and do not expose sensitive data.
- Owner metadata write path passes.
- Legacy local owner mapping passes.
- Owner-scoped reads, exports, SBOMs, and Raw JSON surfaces pass.
- Owner-scoped source and job/result deletion pass.
- Active route families remain gated.
- No forbidden no-scope copy or behavior is introduced.
- Backend full suite passes.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-10-SINGLE-ADMIN-LOGIN-SESSION-PLAN
```

Runtime-09 has closed the Runtime-01 through Runtime-08 P0 line. Next technical work should be a docs-first single-admin login/session plan if Inspectra should become usable in `self_hosted_single_admin` mode. Product publication work may instead proceed with trusted-local release notes. Keep runtime implementation separate unless explicitly scoped.
