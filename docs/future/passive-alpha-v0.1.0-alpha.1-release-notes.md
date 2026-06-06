# Inspectra Passive Alpha v0.1.0-alpha.1

## Summary

Inspectra Passive Alpha is a technical alpha for private local and self-hosted defensive security review. It focuses on passive analysis of projects, uploaded artifacts, configuration files, dependency metadata, local reports, exports, SBOMs, Raw JSON, and redacted evidence.

Inspectra is open-source, altruistic, local-first, and self-hosted-first. This release candidate is not a public production launch, hosted SaaS offering, billing platform, tenant system, or broad active scanner.

## Included

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

## Validation

- Backend compile: passed.
- Backend full suite: `308 passed`.
- Frontend full suite: `127 passed`.
- Frontend build: passed.
- Final persistent-auth focused smoke: `67 passed, 241 deselected`.
- Browser storage search: no `localStorage` or `sessionStorage` matches in `frontend/src`, `backend/app`, or `backend/tests`.
- Broad no-scope search: expected docs/test/copy hits only.

## Explicit No-Scope

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

## Known Gaps

- Admin recovery/setup guidance remains pending.
- Secure-cookie runtime enforcement remains pending.
- Trusted proxy runtime behavior remains pending.
- Public/community anti-abuse remains pending.
- Full session/key rotation remains pending.
- Local/offline operator tooling remains pending.
- Real deployment and reverse proxy behavior are not validated by this release.
- Active/Nmap/CVE work is deferred to separate docs-first design.

## Next

- Push/tag/release publication decision.
- Product technical pause after publication.
- Active/Nmap basic design only through a separate docs-first, opt-in, bounded process.
- CVE version matching design only through a separate docs-first process.
