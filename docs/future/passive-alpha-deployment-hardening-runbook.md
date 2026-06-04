# Passive Alpha Deployment Hardening Runbook

Status: `PASSIVE_ALPHA_DEPLOYMENT_HARDENING_RUNBOOK_READY`.

Base design: `docs/future/passive-alpha-deployment-hardening-design.md`

Base release notes: `docs/future/passive-alpha-self-hosted-release-notes.md`

Commit scope: documentation-only operator runbook for private self-hosted Passive Alpha deployment review. This block does not add runtime behavior, backend changes, frontend changes, tests, Docker execution, deployment execution, exposed deployment approval, production-ready claims, public/community readiness, SaaS/billing/tenant/quota/paid-plan behavior, Nmap behavior, or Active expansion.

## Status

```text
PASSIVE_ALPHA_DEPLOYMENT_HARDENING_RUNBOOK_READY
```

This runbook turns the accepted deployment hardening design into a practical pre-exposure checklist for a technical operator. It is not a production guide and does not make exposed use safe by itself.

## Scope

This is docs-only guidance for private self-hosted Passive Alpha review.

It does not:

- change backend runtime behavior;
- change frontend runtime behavior;
- change Docker or Compose configuration;
- execute Docker;
- execute deployment commands;
- approve exposed deployment;
- claim production readiness;
- approve public/community readiness;
- add SaaS, billing, tenant, quota, subscription, paid-plan, or enterprise behavior;
- add Nmap behavior or Active expansion.

## Who This Runbook Is For

Use this runbook for:

- a technical local operator;
- private self-hosted review;
- controlled alpha evaluation;
- deciding whether the current deployment posture is blocked before exposure.

Do not use this runbook as:

- public/community hosting approval;
- external-user readiness approval;
- multi-tenant deployment approval;
- production readiness evidence;
- a replacement for a real deployment security review.

## Mode Selection Checklist

### Use `trusted_local_no_auth` only when:

- Inspectra is running on localhost, dev, or a trusted local workstation.
- There is no network exposure.
- There is no public reverse proxy.
- Third parties cannot access the instance.
- The operator accepts local-only alpha behavior.

### Use `self_hosted_single_admin` only when:

- A supported admin password hash is configured.
- The deployment is private and controlled.
- Access is restricted to intended operators.
- The frontend origin is explicit and known.
- The operator understands this remains alpha, private, and not production-ready.
- The operator accepts the residual in-memory session and login-attempt limits.

## Pre-Exposure Checklist

Before exposing Inspectra outside localhost, confirm:

- `self_hosted_single_admin` is enabled.
- A supported admin password hash is configured.
- `trusted_local_no_auth` is not used behind a public reverse proxy.
- A reverse proxy is placed in front of the app.
- The backend is not exposed directly to the internet.
- HTTPS/TLS is used for exposed access.
- The allowed browser origin is explicit.
- Credentialed CORS does not use wildcard origins.
- Upload and request body limits are reviewed.
- Proxy timeouts are reviewed.
- Logs are configured not to capture secrets, cookies, tokens, upload bodies, Raw JSON, report contents, or SBOM contents.
- Network access is restricted by VPN, firewall, private network, or equivalent controls where possible.
- Operator credentials and configuration are stored securely.
- The operator accepts that sessions and login-attempt state are in memory.
- The operator accepts that admin recovery is not available yet.

## Reverse Proxy Checklist

For Caddy, Nginx, Traefik, or another operator-managed proxy, confirm:

- TLS terminates at the proxy.
- Backend service ports are reachable only internally.
- The expected frontend/origin URL is defined.
- Only required headers are forwarded.
- Cookies, authorization headers, CSRF tokens, session ids, request bodies, and sensitive response bodies are not logged.
- Request body limits are reasonable for the deployment and Inspectra upload limits.
- Connect, read, write, and idle timeouts are reasonable.
- `X-Forwarded-For`, `X-Forwarded-Proto`, and `Forwarded` are not treated as trusted until trusted proxy runtime enforcement exists.
- Unexpected hosts and origins are blocked when the proxy supports it.

This runbook does not choose a mandatory proxy and does not provide deployment commands.

## Cookie / Session Checklist

Current state:

- The session cookie is `HttpOnly`.
- SameSite behavior is conservative for the current alpha flow.
- Logout clears current session state.
- Sessions are stored in memory.
- Backend restart invalidates in-memory sessions.
- Multiple backend processes do not share sessions.
- There is no persistent session store yet.

Gap before exposed use:

- HTTPS/exposed use should require a Secure session cookie.
- Localhost/dev may need a controlled non-Secure cookie mode.
- Secure-cookie runtime behavior should be implemented and tested separately before treating exposed use as hardened.

## Rate-Limit Checklist

Current state:

- Controlled login `429` exists.
- Safe `Retry-After` exists.
- Frontend login `429` copy is controlled.
- Login attempt state is stored in memory.
- Backend restart clears login attempt state.
- Multiple backend processes do not share login attempt state.
- There is no persistent rate-limit store yet.
- Public/community anti-abuse is not implemented.

## CORS / Origin Checklist

Confirm:

- Allowed origins are explicit.
- Credentials are allowed only for intended origins.
- Wildcard origins are not used with credentials.
- The operator documents the expected frontend URL and backend API URL.
- No current CORS behavior is broadened for convenience.

## Logging Checklist

Do not log:

- cookies;
- session ids;
- CSRF tokens;
- authorization headers;
- admin passwords or password hashes;
- upload contents;
- Raw JSON contents;
- exported report contents;
- SBOM contents when they may reveal sensitive dependency or project information;
- secrets found during analysis.

Prefer short operational events, status codes, request ids, and redacted error messages over full payload logging.

## Operator Smoke Checklist

This is a manual/documental checklist. It does not require Nmap, probes, DNS, external traffic, or destructive commands.

- Open the private frontend URL.
- Confirm the login gate appears in `self_hosted_single_admin`.
- Confirm a correct login succeeds.
- Confirm logout returns to controlled unauthenticated behavior.
- Confirm anonymous access to sensitive routes is blocked.
- Optionally upload and analyze a small synthetic local test file if the operator chooses to test the full local flow.
- Confirm prior validations still show no `localStorage` or `sessionStorage` auth state in code.
- Confirm backend ports are not directly exposed.
- Confirm the proxy does not log cookies, tokens, request bodies, Raw JSON, exported reports, or secrets.
- Confirm dry-run and limited Active behaviors remain separately gated by their own decisions and flags.

Do not run Nmap, port scans, crawlers, DNS probes, external HTTP probes, fuzzing, credential validation, or target expansion as part of this runbook.

## Red Flags / Do Not Proceed

Do not expose the instance if any of these are true:

- `trusted_local_no_auth` is reachable on a network.
- The backend is directly reachable from the internet.
- Plain HTTP is used outside localhost or a tightly controlled private network.
- Credentialed CORS uses wildcard origins.
- The proxy logs cookies, tokens, authorization headers, request bodies, upload contents, Raw JSON, or report contents.
- The admin password or hash is weak, lost, shared carelessly, or not configured.
- HTTPS is absent for real exposure.
- The intended use is public/community hosting.
- Several unrelated external users need access.
- The operator needs a production-ready guarantee.
- Persistent sessions or persistent rate-limit state are required.
- Admin recovery is required.

## Residual Risks

- Sessions remain in memory.
- Login attempts remain in memory.
- Multiple backend processes do not share session or attempt state.
- Secure-cookie runtime enforcement remains pending if not yet implemented.
- Trusted proxy runtime enforcement remains pending.
- Admin recovery remains pending.
- Persistent auth state remains pending.
- Public/community anti-abuse remains pending.

## Recommended Next Path

1. `PASSIVE-ALPHA-README-LAUNCH-COPY-POLISH`
2. `PASSIVE-ALPHA-DEPLOYMENT-HARDENING-CLOSEOUT`
3. `PASSIVE-ALPHA-PERSISTENT-AUTH-STATE-DESIGN`

After those:

4. `PASSIVE-ALPHA-RELEASE-CANDIDATE-CHECKLIST`
5. `ACTIVE-NMAP-BASIC-DESIGN`

## Final Decision

```text
PASSIVE_ALPHA_DEPLOYMENT_HARDENING_RUNBOOK_READY
```

The private self-hosted deployment hardening runbook is ready as documentation-only operator guidance. It does not approve exposed production use, public/community hosting, runtime changes, Docker execution, Nmap, or Active expansion.
