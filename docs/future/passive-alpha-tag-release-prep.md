# Passive Alpha Tag Release Prep

Status: `PASSIVE_ALPHA_TAG_RELEASE_PREP_READY`

Final publication decision: `NOT_PUBLISHED_YET`

This document prepares the Inspectra Passive Alpha tag and release publication path. It is docs/checklist-only: it does not create a tag, push commits, publish a GitHub release, or change runtime behavior.

## Scope

This preparation block freezes the candidate version, release title, release body draft, final pre-tag checklist, planned commands, and blockers before a separate publication microphase.

It does not:

- change backend runtime behavior;
- change frontend runtime behavior;
- change backend features;
- change API, cookie, session, CSRF, `401`, `403`, `429`, or `Retry-After` contracts;
- execute Docker;
- execute Nmap;
- expand Active behavior;
- run probes, DNS checks, or external HTTP;
- push commits;
- create a tag;
- create a GitHub release;
- approve production-ready use;
- approve public/community hosting;
- add SaaS, billing, tenant billing, subscription, quota, paid-plan, or enterprise behavior.

## Version Decision

Recommended final candidate version:

```text
v0.1.0-alpha.1
```

Rationale:

- This is the first technical alpha publication candidate after the private/self-hosted Passive Alpha hardening line.
- The project remains local-first and self-hosted-first.
- The release is positioned as a private/local/self-hosted Passive Alpha, not production, public/community, or SaaS readiness.
- The suffix leaves room for later `alpha.2`, beta, and stable versions without overclaiming maturity.
- The existing frontend package version is `0.1.0`, so `v0.1.0-alpha.1` aligns with the current project version family.

Alternative if product wants to continue the older local passive-alpha tag naming:

```text
v0.1.0-passive-alpha.1
```

No conflict was found that would require preferring the alternative.

## Release Title

```text
Inspectra Passive Alpha v0.1.0-alpha.1
```

## Release Body Draft

The following body is ready to copy into a future GitHub release after the separate publication decision.

### Summary

Inspectra Passive Alpha is a technical alpha for private local and self-hosted defensive security review. It focuses on passive analysis of projects, uploaded artifacts, configuration files, dependency metadata, local reports, exports, SBOMs, Raw JSON, and redacted evidence.

Inspectra is open-source, altruistic, local-first, and self-hosted-first. This release candidate is not a public production launch, hosted SaaS offering, billing platform, tenant system, or broad active scanner.

### Included

- Passive local project and artifact analysis as documented in `README.md`.
- Local reports, Markdown/HTML/XML/PDF exports, SBOM exports, and Raw JSON views.
- Redaction-first handling across runner/backend/API/reporting/export/frontend surfaces where implemented.
- `trusted_local_no_auth` for localhost/dev/local trusted use.
- `self_hosted_single_admin` for private self-hosted alpha use.
- Login and logout.
- `HttpOnly` session cookie.
- CSRF checks on mutating cookie-auth routes.
- Owner-scoped sensitive routes for files, jobs, reports, exports, SBOMs, Raw JSON, target jobs, and delete flows.
- Generic `401` behavior.
- Controlled `403` behavior.
- Controlled login `429` with safe `Retry-After`.
- Controlled frontend `401`/`429` copy.
- No browser `localStorage` or `sessionStorage` auth state.
- Optional SQLite persistent auth state for `self_hosted_single_admin`:
  - `INSPECTRA_AUTH_STATE_STORE=sqlite`;
  - `INSPECTRA_AUTH_STATE_DB_PATH`;
  - persistent sessions;
  - persistent CSRF hash/session binding;
  - persistent login attempts and soft lockouts;
  - cleanup, pruning, revocation, expiration, and restart smoke coverage.
- Deployment hardening documentation and operator runbook for private self-hosted review.

### Validation

- Backend compile: passed.
- Backend full suite: `308 passed`.
- Frontend full suite: `127 passed`.
- Frontend build: passed.
- Final persistent-auth focused smoke: `67 passed, 241 deselected`.
- Browser storage search: no `localStorage` or `sessionStorage` matches in `frontend/src`, `backend/app`, or `backend/tests`.
- Broad no-scope search: expected docs/test/copy hits only.

### Explicit No-Scope

This release candidate does not include or approve:

- production-ready use;
- public/community hosting;
- SaaS;
- billing;
- tenant billing;
- subscriptions;
- quotas;
- paid plans;
- enterprise tenancy;
- OAuth/OIDC;
- multi-user runtime;
- admin recovery/setup flow;
- trusted proxy runtime enforcement;
- secure-cookie runtime enforcement;
- public/community anti-abuse controls;
- Nmap;
- port scanning;
- crawling;
- probes;
- DNS expansion;
- external HTTP or live target expansion beyond separately documented authorized target flows;
- confirmed-vulnerability claims;
- exploitability-confirmed claims;
- credential-validity claims.

### Known Gaps

- Admin recovery/setup guidance remains pending.
- Secure-cookie runtime enforcement remains pending.
- Trusted proxy runtime behavior remains pending.
- Public/community anti-abuse remains pending.
- Full session/key rotation remains pending.
- Local/offline operator tooling remains pending.
- Real deployment and reverse proxy behavior are not validated by this prep block.
- Active/Nmap/CVE work is deferred to separate docs-first design.

### Next

- Push/tag/release publication decision.
- Product technical pause after publication.
- Active/Nmap basic design only through a separate docs-first, opt-in, bounded process.
- CVE version matching design only through a separate docs-first process.

## Pre-Tag Checklist

- Git status is clean.
- Branch/ahead state has been reviewed.
- Final prep commit exists.
- Backend compile passed.
- Backend full suite passed.
- Frontend full suite passed.
- Frontend build passed.
- Browser auth state search found no `localStorage` or `sessionStorage`.
- Broad no-scope search was reviewed and contains only expected docs/test/copy hits.
- No generated auth DB is staged.
- No `.env`, `.env.*`, or `.envrc` file is staged or read.
- No uploads, reports, Raw JSON, SBOMs, runtime DBs, or generated artifacts are staged.
- `README.md`, `docs/security-scope.md`, and `docs/architecture.md` are aligned.
- Release body has been reviewed for overclaims.

## Commands To Run Later, Not Now

Future publication microphase commands:

```bash
git status --short
git status --branch --short
git log --oneline -10
git tag -a v0.1.0-alpha.1 -m "Inspectra Passive Alpha v0.1.0-alpha.1"
git push origin main
git push origin v0.1.0-alpha.1
```

If the GitHub CLI path is explicitly chosen later:

```bash
gh release create v0.1.0-alpha.1 --title "Inspectra Passive Alpha v0.1.0-alpha.1" --notes-file <release-notes-file>
```

Do not run these commands in this prep block. If a release notes file is created later, keep it under `docs/future/` or another tracked docs path and verify it contains no secrets.

## Release Blockers

Block publication if any of these are true:

- Tests fail.
- Frontend build fails.
- Git working tree is dirty.
- Documentation overclaims production/public/community/SaaS/billing readiness.
- Secrets, auth DBs, uploads, reports, Raw JSON, SBOMs, or runtime artifacts are staged.
- Browser auth state uses `localStorage` or `sessionStorage`.
- Nmap, Active expansion, probes, DNS expansion, port scanning, crawling, or external HTTP behavior is introduced.
- Production/public/community/SaaS/billing claims appear.
- Runtime changes are present but not separately designed and validated.
- `.env`, `.env.*`, or `.envrc` contents are read or leaked.

## Recommended Next Path

1. `PASSIVE-ALPHA-PUBLISH-GITHUB-RELEASE`
2. Product technical pause.
3. `ACTIVE-NMAP-BASIC-DESIGN`
4. `CVE-VERSION-MATCHING-DESIGN`

## Final Decision

```text
PASSIVE_ALPHA_TAG_RELEASE_PREP_READY
```

Publication remains pending:

```text
NOT_PUBLISHED_YET
```
