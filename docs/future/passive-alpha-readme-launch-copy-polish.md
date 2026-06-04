# Passive Alpha README Launch Copy Polish

Status: `PASSIVE_ALPHA_README_LAUNCH_COPY_POLISH_ACCEPTED`.

Base release notes: `docs/future/passive-alpha-self-hosted-release-notes.md`

Base deployment hardening design: `docs/future/passive-alpha-deployment-hardening-design.md`

Base deployment hardening runbook: `docs/future/passive-alpha-deployment-hardening-runbook.md`

Commit scope: documentation-only README and launch-copy polish for the current private/self-hosted Passive Alpha posture. This block does not add runtime behavior, backend changes, frontend changes, tests, Docker execution, deployment execution, public/community readiness, production-ready claims, SaaS/billing/tenant/quota/paid-plan behavior, Nmap behavior, Active expansion, push, tag, or release state.

## Status

```text
PASSIVE_ALPHA_README_LAUNCH_COPY_POLISH_ACCEPTED
```

The README now has a clearer Passive Alpha entry point for private alpha review: what Inspectra is, how the two current auth/deployment modes should be understood, what hardening is required before exposure, what the alpha does not promise, and the immediate roadmap before deeper Active/Nmap/CVE work.

## Scope

This microfase is docs-only.

It does not:

- change backend runtime behavior;
- change frontend runtime behavior;
- change Docker or Compose configuration;
- execute Docker;
- execute deployment commands;
- run tests;
- approve public/community hosting;
- claim production readiness;
- add SaaS, billing, tenant billing, subscriptions, quotas, paid plans, or enterprise tenancy;
- add OAuth/OIDC, multi-user runtime, persistent sessions, persistent rate-limit storage, or admin recovery;
- add Nmap, port scanning, crawling, probes, DNS expansion, or external HTTP/live target expansion;
- push, tag, or publish a release.

## README Changes

The README launch copy now summarizes:

- Inspectra Passive Alpha as open-source, altruistic, local-first, and self-hosted-first.
- Passive analysis scope for local projects, uploaded artifacts, config review, dependency review, reports, SBOM/exports, and local evidence.
- The distinction between `trusted_local_no_auth` and `self_hosted_single_admin`.
- Current `self_hosted_single_admin` support: password hash, login/logout, `HttpOnly` cookie, CSRF, owner-scoped sensitive routes, generic `401`, controlled `429`, and no browser `localStorage`/`sessionStorage` auth state.
- Deployment hardening expectations: HTTPS/TLS outside localhost, reverse proxy, backend not directly exposed, explicit origins, no wildcard credentialed CORS, sensitive-log avoidance, and known secure-cookie/trusted-proxy/persistent-state gaps.
- Explicit no-scope for production/public/community/SaaS/billing/Nmap/general-active-scanner claims.
- Immediate roadmap toward deployment hardening closeout, persistent auth-state design, release-candidate checklist, tag/release/push, and separately scoped deeper Active/Nmap/CVE work.

## No-Scope Preserved

- No runtime behavior changes.
- No backend changes.
- No frontend changes.
- No tests or fixtures.
- No Docker execution.
- No Nmap.
- No probes, DNS, external HTTP, port scanning, crawling, or live target expansion.
- No public/community runtime.
- No exposed production approval.
- No SaaS, billing, tenant billing, subscription, quota, paid-plan, or enterprise tenancy behavior.
- No OAuth/OIDC or multi-user runtime.
- No push, tag, or release.
- No `.env`, `.env.*`, or `.envrc` reads.

## Final Decision

```text
PASSIVE_ALPHA_README_LAUNCH_COPY_POLISH_ACCEPTED
```

The Passive Alpha README launch copy is accepted as ready for private alpha presentation while preserving local-first, self-hosted-first, passive-analysis framing and explicit non-production boundaries.

## Next Recommendation

```text
PASSIVE-ALPHA-DEPLOYMENT-HARDENING-CLOSEOUT
```

That follow-up should close the deployment hardening design and runbook line as docs-only before moving to persistent auth-state planning, release-candidate checklist work, or separately scoped Active/Nmap/CVE design.
