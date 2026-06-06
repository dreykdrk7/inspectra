# Passive Alpha Release Candidate Checklist

Status: `PASSIVE_ALPHA_RELEASE_CANDIDATE_CHECKLIST_READY`

This document prepares Inspectra Passive Alpha for a release-candidate decision. It is a docs-first checklist only: it does not change backend runtime, frontend runtime, API contracts, cookies, sessions, CSRF, analyzers, Active behavior, tags, releases, or push state.

## Release Candidate Target

The release candidate target is a private, local-first, self-hosted-first Passive Alpha for defensive review of projects and artifacts the operator owns or is explicitly authorized to assess.

Supported RC shape:

- `trusted_local_no_auth` remains the default localhost/dev/local trusted mode.
- `self_hosted_single_admin` is available for private self-hosted alpha use.
- Login/logout, an `HttpOnly` session cookie, CSRF checks on mutating cookie-auth routes, owner-scoped sensitive routes, generic `401`, controlled `403`, login `429` with safe `Retry-After`, and controlled frontend `429` copy are in scope.
- SQLite-backed persistent auth state is opt-in for `self_hosted_single_admin` through `INSPECTRA_AUTH_STATE_STORE=sqlite`.
- Memory-backed auth state remains the default.
- The RC is technical and private/self-hosted. It is not a mass public launch, hosted SaaS launch, production approval, or community-hosting approval.

## Included Capability Checklist

Passive analysis and reporting:

- Local file and archive upload flows remain the supported input model.
- Passive project/artifact analyzers, reports, exports, SBOM output, and Raw JSON remain bounded and redaction-first.
- Owner-scoped sensitive routes protect uploads, jobs, stored results, exports, SBOMs, and Raw JSON in auth-required mode.
- Findings remain heuristic review indicators, not confirmed vulnerabilities or exploitability claims.
- Active expansion is not included in this RC checklist.

Self-hosted auth:

- `trusted_local_no_auth` remains unchanged for localhost/dev/local trusted use.
- `self_hosted_single_admin` has password-hash verification, login, logout, session cookie, authenticated status, and in-memory CSRF token handling.
- Mutating cookie-auth routes require CSRF.
- Sensitive routes are owner-scoped.
- Wrong-owner and unresolved-owner reads remain generic.
- Login failure is generic.
- Login rate-limit/backoff returns controlled `429` with safe `Retry-After`.
- Frontend login `429` copy is controlled and does not expose counters, thresholds, client keys, hash/config state, recovery, or bypass guidance.
- Browser auth state is kept out of `localStorage` and `sessionStorage`.

Persistent auth state:

- `INSPECTRA_AUTH_STATE_STORE=memory` remains the default.
- `INSPECTRA_AUTH_STATE_STORE=sqlite` can persist sessions and login-attempt lockout state for `self_hosted_single_admin`.
- The optional DB path is controlled by `INSPECTRA_AUTH_STATE_DB_PATH`.
- Stored session ids, CSRF tokens, and login client keys are hashed before persistence.
- Session cleanup, revocation, expiration, store recreation, login-attempt cleanup, pruning, and lockout behavior have focused smoke coverage.
- Raw tokens, client keys, passwords, and admin hashes are not intentionally stored in the SQLite auth-state DB.
- Forwarded headers remain ignored until a separate trusted-proxy policy exists.

Deployment hardening docs:

- Private self-hosted release notes exist.
- Deployment hardening design exists.
- Deployment hardening runbook exists.
- README launch copy has been polished for private alpha use.
- Deployment hardening closeout documents residual exposed-use gaps.

## Validation Checklist

Reference validation evidence from the final persistent-auth regression smoke:

- Backend compile passed.
- Focused backend persistent-auth smoke passed: 67 passed, 241 deselected.
- Full backend suite passed: 308 passed.
- Frontend App suite passed: 37 passed.
- Full frontend suite passed: 127 passed.
- Frontend build passed.
- Browser-storage search found no `localStorage` or `sessionStorage` auth-state use.
- Broad no-scope search produced only expected docs/test/copy hits.
- `git diff --check` and `git diff --cached --check` passed.

Required final pre-tag validation:

- Confirm `git status --short` is clean.
- Confirm branch/ahead state with `git status --branch --short`.
- Review the recent commit line with `git log --oneline`.
- Rerun backend compile.
- Rerun the full backend test suite.
- Rerun the full frontend test suite.
- Rerun frontend build.
- Rerun browser-storage search.
- Rerun no-scope search.
- Rerun `git diff --check`.
- Rerun `git diff --cached --check` after staging release-note or checklist changes.
- Confirm no generated auth DB, runtime DB, uploaded source, result JSON, report output, or secret-bearing artifact is staged.

## Release Blockers

Block the RC if any of these are true:

- Git working tree is not clean before tag/release preparation.
- Backend compile fails.
- Backend tests fail.
- Frontend tests fail.
- Frontend build fails.
- Browser auth state uses `localStorage` or `sessionStorage`.
- API, cookie, session, or CSRF contracts changed without a dedicated design block.
- `.env`, `.env.*`, or `.envrc` contents are read, printed, staged, or referenced with real values.
- A runtime auth DB, uploaded source, stored result, export, or Raw JSON artifact is staged.
- README, architecture, security-scope, or release notes overclaim production, public/community, SaaS, billing, tenant, quota, or paid-plan readiness.
- Docs or UI copy present findings as confirmed vulnerabilities, confirmed exploitability, proof of compromise, or credential validity.
- Active/Nmap/probe/DNS/port-scan/crawl behavior is introduced or implied.
- Docker deployment execution or reverse-proxy runtime enforcement is introduced in this RC checklist.
- Security scope, architecture, README, self-hosted release notes, deployment hardening closeout, and persistent auth closeout disagree on supported state.

## Explicit No-Scope

This RC checklist does not approve or implement:

- Public/community hosting.
- Production approval.
- Hosted SaaS.
- Billing, tenant billing, subscriptions, quotas, paid plans, or enterprise tenancy.
- OAuth/OIDC.
- Multi-user runtime.
- Admin recovery/setup flow.
- Trusted proxy runtime behavior.
- Secure-cookie runtime enforcement.
- Public/community anti-abuse controls.
- New analyzers.
- Active expansion.
- Nmap.
- Port scanning.
- Crawling.
- DNS expansion.
- External HTTP probes or live target expansion.
- Docker execution.
- Tag creation.
- Release creation.
- Push to a remote.

## Residual Gaps Accepted For RC

Known residual gaps that do not block the private/self-hosted technical RC:

- Admin recovery/setup guidance remains pending.
- Secure-cookie runtime enforcement remains pending.
- Trusted-proxy runtime behavior remains pending.
- Public/community anti-abuse remains pending.
- Full session/key rotation remains pending.
- Local/offline operator tooling remains pending.
- Active/Nmap/CVE work remains separate.
- Real deployment and reverse-proxy behavior are not validated by this checklist.
- The RC remains a private/self-hosted alpha, not production/public/community readiness.

## Tag And Release Prep Notes

Recommended new RC tag candidate:

- `v0.1.0-alpha.1`

Alternative if the product wants to continue the older local passive-alpha tag naming:

- `v0.1.0-passive-alpha.1`

Suggested release title:

- `Inspectra Passive Alpha v0.1.0-alpha.1`

The release body should derive from:

- `README.md`
- `docs/future/passive-alpha-self-hosted-release-notes.md`
- `docs/future/passive-alpha-deployment-hardening-closeout.md`
- `docs/future/passive-alpha-persistent-auth-closeout.md`
- `docs/future/passive-alpha-persistent-auth-final-regression-smoke.md`

Release copy must avoid claiming production readiness, public/community readiness, SaaS/billing support, Nmap readiness, broad Active scanning, confirmed vulnerabilities, confirmed exploitability, or credential validity.

## Recommended Next Path

1. `PASSIVE-ALPHA-TAG-RELEASE-PREP`
2. Push/tag/release decision.
3. Product technical pause after Passive Alpha publication.
4. `ACTIVE-NMAP-BASIC-DESIGN` as a separate docs-first, opt-in, bounded design.
5. `CVE-VERSION-MATCHING-DESIGN` as a separate docs-first design.

Final decision: `PASSIVE_ALPHA_RELEASE_CANDIDATE_CHECKLIST_READY`.
