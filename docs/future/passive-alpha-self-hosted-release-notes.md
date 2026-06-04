# Passive Alpha Self-Hosted Release Notes

Status: `PASSIVE_ALPHA_SELF_HOSTED_RELEASE_NOTES_READY`.

These notes summarize the current private/self-hosted Passive Alpha state after the self-hosted auth hardening closeout. They are product-facing alpha notes, not a runtime design and not a public launch announcement.

## Audience

These notes are for:

- local use;
- private self-hosted use;
- technical review of the Passive Alpha;
- operators evaluating the current self-hosted single-admin alpha boundary.

These notes are not for public launch, production rollout, public/community hosting, or external-user readiness claims.

## What Is Included

- Inspectra Passive Alpha remains open-source, altruistic, local-first, and self-hosted-first.
- `trusted_local_no_auth` remains the default localhost/dev/local trusted mode.
- `self_hosted_single_admin` is available as a private/self-hosted mode when configured correctly with a supported admin password hash.
- Login and logout are available.
- Successful login issues an `HttpOnly` session cookie.
- CSRF is required on mutating cookie-auth routes through `X-CSRF-Token`.
- Sensitive routes are owner-scoped for files, jobs, reports, Raw JSON, exports, SBOM, target jobs, Active job creation, and delete flows.
- Login `401` remains generic.
- Login `429` is controlled and can include safe backend `Retry-After`.
- Frontend login `429` copy is controlled:

```text
Too many attempts. Try again later.
```

- Logout clears session state and returns to controlled unauthenticated behavior.
- Global `401` and `403` handling is controlled in the frontend.
- Configured-origin CORS credential behavior is covered.
- No frontend `localStorage` or `sessionStorage` is used for auth state.
- Runtime-22 validated backend/frontend suites and frontend build for this auth hardening line.

## Validation Evidence

Runtime-22 recorded the current smoke evidence:

- `compileall backend`: passed.
- Backend focused smoke: `148 passed, 134 deselected`.
- Backend full suite: `282 passed`.
- Frontend App suite: `37 passed`.
- Frontend full suite: `127 passed`.
- `npm run build`: passed.
- `rg localStorage/sessionStorage`: no matches in `frontend/src`, `backend/app`, or `backend/tests`.
- Broad no-scope `rg`: expected hits only.
- `git diff --check`: passed.
- `git diff --cached --check`: passed.

This release-notes slice is docs-only and does not re-run the full backend/frontend suites.

## Explicit Not Included / No-Scope

This Passive Alpha self-hosted release-note state does not include:

- exposed production deployment approval;
- public/community runtime;
- SaaS;
- billing;
- tenant billing;
- subscriptions;
- quotas;
- paid plans;
- enterprise tenancy;
- OAuth/OIDC;
- multi-user runtime;
- persistent sessions;
- persistent rate-limit store;
- admin recovery;
- Docker execution as part of this release-note slice;
- Nmap;
- port scanning;
- crawling;
- probes;
- DNS expansion;
- external HTTP or live target traffic expansion;
- release, tag, or push.

Existing Passive Alpha capabilities and historical docs retain their own scoped behavior. These notes do not add new runtime behavior or broaden any target-facing capability.

## Known Gaps Before Exposed Use

- Sessions remain in memory.
- Login attempt and rate-limit state remain in memory.
- Multiple backend processes do not share session or attempt state.
- TLS, reverse proxy, and secure-cookie hardening remain pending.
- Trusted proxy header handling remains pending.
- Session rotation and key rotation remain pending.
- Admin recovery and setup guidance remain pending.
- Public/community anti-abuse requires separate design and controls.

## Safe Positioning

Passive Alpha is useful for local and private self-hosted passive analysis. The current auth hardening reduces accidental exposure risk in private/self-hosted use, but it is not a production-ready platform boundary.

Do not present this state as:

- a commercial SaaS platform;
- a billing, quota, paid-plan, or tenant product;
- a general active scanner;
- a production-ready deployment package;
- a public/community hosting package;
- a multi-tenant security platform.

Active remains limited by previous Active Alpha decisions and is not expanded by these notes.

## Recommended Next Path

```text
PASSIVE-ALPHA-README-LAUNCH-COPY-POLISH
```

The next step should polish README and launch-facing copy for a private alpha presentation while preserving the current boundaries: local/private self-hosted framing, no public/community readiness, no SaaS/billing language, no new Active/Nmap behavior, and no runtime changes.

Alternative follow-up:

```text
PASSIVE-ALPHA-DEPLOYMENT-HARDENING-DESIGN
```

That path should cover TLS, reverse proxy, secure-cookie behavior, and trusted proxy headers before any exposed self-hosted use is considered.
