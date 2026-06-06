# Passive Alpha Post-Release Technical Pause

Status: `PASSIVE_ALPHA_POST_RELEASE_TECHNICAL_PAUSE_RECORDED`

This document records the product and technical pause after publishing Inspectra Passive Alpha `v0.1.0-alpha.1`. It summarizes what was actually shipped, what remains out of scope, the accepted debt, and the recommended next path before opening Active/Nmap, CVE/version matching, or deeper passive audit work.

## Scope

This block is documentation-only. It does not change backend runtime, frontend runtime, runner behavior, API contracts, cookie/session/CSRF contracts, `401`/`403`/`429` behavior, report/export behavior, analyzers, Active behavior, CVE behavior, release state, or tag state.

It also does not execute Docker, Nmap, probes, DNS checks, external HTTP checks, deployment commands, or live-target validation. No `.env`, `.env.*`, or `.envrc` contents are read or printed.

The only permitted push for this block is the final docs commit recording this pause.

## Published State Recap

- Release: `v0.1.0-alpha.1`
- Release title: `Inspectra Passive Alpha v0.1.0-alpha.1`
- Tag state: published.
- Tag target commit: `4d4a5a0 docs(alpha): add v0.1.0 alpha release notes`
- Latest `main` commit before this pause: `272dc83 docs(alpha): record github release publication`
- Release notes: `docs/future/passive-alpha-v0.1.0-alpha.1-release-notes.md`
- Publication closeout: `docs/future/passive-alpha-publish-github-release.md`

Reference validation from the publication block:

- Backend compile: passed.
- Backend full suite: `308 passed in 12.27s`.
- Frontend full suite: `127 passed`.
- Frontend build: passed, `1626 modules transformed`.
- Browser auth-state search: no `localStorage` or `sessionStorage` matches in `frontend/src`, `backend/app`, or `backend/tests`.
- Broad no-scope search: expected docs/test/copy hits only.
- `git diff --check`: passed.
- `git diff --cached --check`: passed.

## What Shipped

Passive Alpha shipped as a local-first and self-hosted-first technical alpha for defensive review of projects, uploaded artifacts, configuration files, dependency metadata, reports, exports, SBOMs, Raw JSON, and redacted evidence. It includes the passive analyzer suite described in `README.md`, local job/result storage, Markdown/HTML/XML/PDF reports, SBOM exports for supported manifest jobs, and redaction-first behavior where implemented.

The supported auth state includes:

- `trusted_local_no_auth` for localhost/dev/local trusted use.
- `self_hosted_single_admin` for private self-hosted alpha use.
- Login/logout.
- `HttpOnly` session cookie.
- CSRF checks on mutating cookie-auth routes.
- Owner-scoped sensitive routes for files, jobs, reports, exports, SBOMs, Raw JSON, target jobs, and delete flows.
- Generic `401` behavior.
- Controlled `403` behavior.
- Controlled login `429` with safe `Retry-After`.
- Controlled frontend `401`/`429` copy.
- No frontend `localStorage` or `sessionStorage` auth state.

The optional persistent auth state includes:

- `INSPECTRA_AUTH_STATE_STORE=memory` as the default.
- `INSPECTRA_AUTH_STATE_STORE=sqlite` as an opt-in for `self_hosted_single_admin`.
- `INSPECTRA_AUTH_STATE_DB_PATH` for the local auth-state DB path.
- Persistent sessions.
- Persistent CSRF hash/session binding.
- Persistent login attempts and soft lockouts.
- Cleanup, pruning, revocation, expiration, restart/store recreation, and DB-byte redaction smoke evidence.
- No intentional raw session ids, CSRF tokens, client keys, passwords, or admin hashes in SQLite auth state.

Deployment/product documentation shipped:

- Self-hosted alpha release notes.
- Deployment hardening design.
- Deployment hardening runbook.
- README launch copy.
- Release candidate checklist.
- Tag/release prep.
- GitHub release publication closeout.

## What Did Not Ship

The release does not include or approve:

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
- CVE/version matching;
- confirmed-vulnerability claims;
- exploitability-confirmed claims;
- credential-validity claims.

## Residual Debt Inventory

Security and deployment debt:

- Secure-cookie runtime enforcement is still pending.
- Trusted proxy runtime behavior is still pending.
- Real reverse proxy/TLS deployment has not been validated by this release.
- Public/community anti-abuse has not been designed.
- Admin recovery/setup guidance is still pending.
- Local/offline operator tooling is still pending.
- Full session/key rotation is still pending.

Product and capability debt:

- Active/Nmap is not designed yet.
- CVE/version matching is not designed yet.
- Deep passive audits remain future work.
- Report/UX/docs improvements should be driven by alpha feedback.

Operational debt:

- Release automation is not implemented.
- The GitHub release checklist remains manual.
- No real deployment smoke is recorded for the release.
- Tag/release publication was manual.

## Path A: Active/Nmap Bounded Design

Objective: design a strictly opt-in, bounded, local/private/self-hosted Nmap capability before any implementation.

Advantages:

- Moves toward the next obvious security analyst workflow.
- Reuses the Active docs-first discipline already established by dry-run and one-HEAD probe work.
- Can define narrow authorization, target, rate-limit, timeout, output, and redaction boundaries before runtime exists.

Risks:

- Higher misuse and overclaim risk than passive modules.
- Requires careful policy, copy, tests, and operator guidance.
- Must avoid becoming arbitrary internet scanning or a public scanner.

Recommended next microphase if this path is chosen:

```text
ACTIVE-NMAP-BASIC-DESIGN
```

Guardrails:

- Disabled by default.
- Explicit opt-in and explicit authorized targets.
- Local/private/self-hosted framing only.
- No arbitrary internet scanning.
- No wide ranges.
- No stealth, evasion, aggressive NSE defaults, brute force, exploit scripts, credential validation, crawling, or DNS expansion unless separately designed.
- Bounded timeouts, target count, output size, and storage.
- Redacted logs, API responses, reports, exports, and Raw JSON.
- Report wording must say observed exposure or review indicator, not confirmed vulnerability.

## Path B: CVE/Version Matching Design

Objective: design passive-first CVE/version matching for already-collected version signals without claiming exploitability.

Advantages:

- Lower live-traffic risk than Active/Nmap.
- Fits the existing passive analyzer/reporting posture.
- Can improve value of manifest/config/version findings without broadening target behavior.

Risks:

- Version-only matching can create noisy false positives.
- Requires a data-source/update strategy and careful stale-data handling.
- Requires strong wording to avoid confirmed-vulnerability or exploitability claims.

Recommended next microphase if this path is chosen:

```text
CVE-VERSION-MATCHING-DESIGN
```

Guardrails:

- Passive-first.
- No exploitability or confirmed-vulnerability claims.
- Version-based candidates only.
- Manual validation required.
- Data model, update source, freshness, offline behavior, and redaction strategy designed before runtime.

## Path C: Deep Passive Audits

Objective: deepen existing passive modules before opening a new major capability family.

Examples:

- Deeper secrets review posture.
- Dependency policy and lockfile quality.
- Docker/Kubernetes/CI hardening depth.
- Report quality, severity explanations, and UX polish.

Advantages:

- Lowest misuse risk.
- Builds on existing architecture.
- Improves alpha quality from user feedback.

Risks:

- Less visible than Active/Nmap.
- Can keep the product in refinement mode too long.

## Path D: Remaining Deployment/Security Hardening

Objective: close more deployment/auth gaps before capability expansion.

Candidates:

- Secure-cookie runtime enforcement.
- Trusted proxy runtime behavior.
- Admin setup/recovery guidance.
- Local/offline operator tooling.
- Release automation.

Advantages:

- Improves safety before broader use.
- Reduces operational ambiguity for private self-hosted operators.

Risks:

- Slower feature momentum.
- Some work depends on deployment assumptions that are still intentionally private-alpha.

## Recommended Decision

Prefer:

```text
ACTIVE-NMAP-BASIC-DESIGN
```

Rationale: after Passive Alpha publication and the already separated Active dry-run/one-HEAD work, the most valuable next product question is whether Nmap can be designed safely as a bounded, disabled-by-default, opt-in, local/private/self-hosted capability. This should be design-only first.

Risk-minimizing alternative:

```text
CVE-VERSION-MATCHING-DESIGN
```

Choose this first if the product wants to avoid any new live/network capability until another passive-first value layer is designed.

## Acceptance Criteria

- Release state is summarized accurately.
- No runtime, frontend, backend, runner, API, cookie, session, CSRF, report/export, Active, Nmap, or CVE behavior changes.
- No new tag or release is created.
- No Docker, Nmap, probes, DNS checks, or external HTTP checks are executed.
- No `.env`, `.env.*`, or `.envrc` contents are read or printed.
- Residual debt remains explicit.
- Next pathing is documented with guardrails.

## Final Decision

```text
PASSIVE_ALPHA_POST_RELEASE_TECHNICAL_PAUSE_RECORDED
```

Recommended next microphase:

```text
ACTIVE-NMAP-BASIC-DESIGN
```

Alternative:

```text
CVE-VERSION-MATCHING-DESIGN
```
