# Passive Alpha Deployment Hardening Design

Status: `PASSIVE_ALPHA_DEPLOYMENT_HARDENING_DESIGN_ACCEPTED`.

Base release notes: `docs/future/passive-alpha-self-hosted-release-notes.md`

Base auth hardening closeout: `docs/future/passive-alpha-runtime-23-self-hosted-auth-hardening-closeout.md`

Commit scope: documentation-only deployment hardening design for private self-hosted Passive Alpha use. This block does not add runtime behavior, backend changes, frontend changes, tests, Docker execution, deployment execution, exposed deployment approval, public/community readiness, production-ready claims, Nmap behavior, new Active behavior, or new analyzers.

## Status

```text
PASSIVE_ALPHA_DEPLOYMENT_HARDENING_DESIGN_ACCEPTED
```

This design accepts the minimum deployment-hardening direction needed before any private self-hosted Passive Alpha use is exposed beyond a trusted local workstation. It closes the immediate design gap called out by the self-hosted release notes: TLS, reverse proxy posture, secure-cookie expectations, and trusted proxy header handling.

## Scope

This is docs-only design for private, self-hosted deployment planning.

It does not:

- change backend runtime behavior;
- change frontend runtime behavior;
- change Docker or Compose configuration;
- execute Docker;
- execute deployment commands;
- approve an exposed deployment;
- approve public/community readiness;
- claim production readiness;
- add Nmap, port scanning, crawling, probes, DNS expansion, or external HTTP behavior;
- add SaaS, billing, tenant billing, subscription, quota, paid-plan, or enterprise tenancy behavior.

## Deployment Positioning

### `trusted_local_no_auth`

- Default localhost/dev/local trusted mode.
- Appropriate for a single operator on a controlled local machine.
- Not recommended for exposure on a network.
- Must not be used behind a public reverse proxy.
- Must not be presented as private, public, community, or production-ready deployment protection.

### `self_hosted_single_admin`

- Private/self-hosted single-admin mode.
- Requires `INSPECTRA_ADMIN_PASSWORD_HASH` with a supported admin password hash.
- Uses login/logout, `HttpOnly` session cookie, CSRF on mutating cookie-auth routes, owner-scoped sensitive routes, generic login `401`, and controlled login `429`.
- May be placed behind a reverse proxy only when the operator applies the deployment controls in this design.
- Still is not public/community, multi-user, SaaS, enterprise, or production-ready runtime.

## TLS / HTTPS Expectations

- Any exposure outside localhost should use HTTPS.
- TLS should terminate at a reverse proxy such as Caddy, Nginx, Traefik, or an equivalent operator-controlled edge component.
- Plain HTTP is acceptable only for localhost or a tightly controlled private network used by a trusted operator.
- The backend should not be exposed directly to the internet.
- This design does not validate certificates, configure TLS, run a server, or declare the current alpha production-ready.

## Reverse Proxy Expectations

A private self-hosted deployment should place a reverse proxy in front of the backend and frontend rather than exposing backend ports directly.

Recommended controls:

- Bind backend services to an internal interface or private network where possible.
- Restrict allowed hostnames and browser origins to the intended operator URL.
- Use reasonable request body limits that match Inspectra upload limits and deployment capacity.
- Use reasonable connect, read, write, and idle timeouts.
- Avoid logging request bodies, cookies, authorization headers, CSRF tokens, session ids, upload contents, Raw JSON payloads, or exported report contents.
- Forward only the headers required by the app and the deployment.
- Treat `X-Forwarded-For`, `X-Forwarded-Proto`, and `Forwarded` as untrusted unless future trusted-proxy runtime configuration explicitly allows the proxy source.
- Keep public static assets and backend API routes separated clearly enough that authentication and CORS expectations remain auditable.

This design does not choose a mandatory proxy implementation and does not provide a production deployment recipe.

## Secure Cookie Behavior

Current state:

- The session cookie is `HttpOnly`.
- The cookie uses conservative SameSite behavior for the current alpha flow.
- The current implementation remains localhost/dev oriented.

Expected future behavior:

- HTTPS/exposed use should require a Secure session cookie.
- Localhost/dev may need a controlled non-Secure cookie mode for development.
- SameSite should remain strict or conservative unless a future documented browser-flow need justifies changing it.
- Cookie settings should not depend on untrusted proxy headers.

Future runtime work should add explicit secure-cookie configuration and tests for localhost versus HTTPS self-hosted behavior. This microfase does not implement that behavior.

## Trusted Proxy Headers

The backend should not blindly trust:

- `X-Forwarded-For`;
- `X-Forwarded-Proto`;
- `Forwarded`;
- equivalent proxy-supplied client or scheme headers.

Policy direction:

- Accept proxy headers only from explicitly trusted proxy addresses or networks.
- Avoid deriving security-critical decisions from proxy headers when the request source is not trusted.
- Keep login rate-limit client-key behavior conservative; the current backend-observed client address is safer than trusting arbitrary forwarded headers by default.
- Future trusted-proxy configuration should be an allowlist, not a broad enable flag.
- Future tests should cover scheme/origin/cookie behavior, spoofed forwarded headers, and trusted versus untrusted proxy sources.

This design does not add trusted proxy runtime enforcement.

## CORS / Origin

- Configured-origin CORS credential support is already covered by the auth hardening line.
- Credentialed CORS must not use wildcard origins.
- Exposed self-hosted use should configure allowed origins explicitly for the operator-controlled frontend origin.
- This design does not broaden current CORS behavior.

## Admin Setup / Recovery Boundary

- Admin recovery/setup guidance remains pending.
- This microfase does not create recovery flows, reset flows, backup flows, or password-hash generation tooling.
- For private alpha use, the operator is responsible for preserving credentials and configuration securely.
- Lost admin credentials may require manual operator intervention until a separate recovery/setup design exists.

## Residual Risks After This Design

- Sessions remain in memory.
- Login attempts and rate-limit state remain in memory.
- Multiple backend processes do not share session or attempt state.
- There is no persistent session store.
- There is no persistent rate-limit store.
- Admin recovery remains unavailable.
- Trusted proxy runtime enforcement is not implemented yet.
- Secure-cookie HTTPS/exposed behavior is not implemented yet if the current runtime lacks explicit configuration.
- Public/community anti-abuse remains blocked until separate design and controls exist.

## Recommended Implementation Sequence

1. `PASSIVE-ALPHA-DEPLOYMENT-HARDENING-RUNBOOK`
2. `PASSIVE-ALPHA-README-LAUNCH-COPY-POLISH`
3. `ACTIVE-NMAP-BASIC-DESIGN`

Optional later follow-up:

4. `PASSIVE-ALPHA-PERSISTENT-AUTH-STATE-DESIGN`

The runbook should remain documentation-first and should not run deployment commands. Any runtime work for secure cookies, trusted proxy allowlists, persistent auth state, or admin recovery should be separately scoped and tested.

## Acceptance Criteria

- The design distinguishes `trusted_local_no_auth` from `self_hosted_single_admin`.
- HTTPS and reverse proxy expectations are documented without approving exposed production use.
- Secure-cookie behavior is identified as a future runtime gap.
- Trusted proxy header handling is defined as deny-by-default until configured.
- CORS/origin expectations remain explicit-origin and credential-safe.
- Admin setup/recovery remains a known gap.
- No runtime, backend, frontend, Docker, Nmap, Active, push, tag, or release behavior is added.

## Final Decision

```text
PASSIVE_ALPHA_DEPLOYMENT_HARDENING_DESIGN_ACCEPTED
```

The deployment hardening design is accepted as the next docs/product guardrail for private self-hosted Passive Alpha. It prepares the path for a runbook and launch-copy polish without weakening the current no-production, no-public/community, no-SaaS, and no-new-runtime boundaries.
