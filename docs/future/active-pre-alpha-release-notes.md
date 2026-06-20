# Inspectra Active Technical Alpha - Release Notes

Decision: `ACTIVE_PRE_ALPHA_RELEASE_NOTES_FINALIZE_07_ACCEPTED`

Status: release-candidate-ready notes for the Inspectra Active technical alpha.
These notes are finalized for the next tag-planning step, but this phase did
not publish a release, create a version marker, deploy, upload commits, run the
app, run Docker, invoke Nmap, submit Active jobs, contact targets, or capture
images.

Inspectra Active technical alpha is positioned for local/private/self-hosted
security review by an operator with explicit authorization for each submitted
target, domain, or URL. Results are review indicators and require manual
validation.

## Included Active Capabilities

### Active / Nmap Basic v0

Purpose: bounded TCP exposure review through the accepted Nmap basic v0 path.

- Disabled unless the Active Nmap feature gate and supporting active-tools
  setup are configured.
- Uses the accepted one-authorized-target boundary for v0.
- Reports observed exposure review indicators.
- Requires manual validation.
- Uses redaction-first reporting and public-result shaping.
- Limitations: no broad port sweep, service/version expansion, script scans,
  credential checks, or automatic target expansion.

### Active / TLS Basic v0

Purpose: one-host TLS handshake and certificate metadata review.

- Disabled by default through its feature gate.
- Accepts one authorized host and one accepted TLS port.
- Performs the bounded TLS behavior only after operator confirmation and the
  feature gate.
- Reports TLS configuration review indicators.
- Requires manual validation.
- Uses redaction-first reporting for target and certificate material.
- Limitations: no HTTP request, content traversal, raw certificate material,
  client credentials, or alternate-port retry expansion.

### Active DNS Inventory v0

Purpose: bounded standard DNS record and configuration review for one domain.

- Disabled by default through its feature gate.
- Accepts one explicit authorized root domain.
- Reviews allowlisted record types, SPF/DMARC/CAA indicators, and bounded
  fixed-candidate subdomain context.
- Reports DNS configuration review indicators with best-effort or bounded
  inventory wording.
- Requires manual validation.
- Uses redaction-first reports, exports, Raw JSON, list, and detail surfaces.
- Limitations: no provider administration, passive DNS sources, broad wordlist,
  sibling-domain expansion, or automatic probing of observed names.

### Authorized AXFR Inside DNS Inventory

Purpose: separately confirmed zone-transfer review inside DNS inventory.

- Available only when DNS inventory is enabled and the request confirms AXFR
  authorization.
- Uses one explicit authorized root domain and authoritative-server context.
- Attempts AXFR only when the request option and separate confirmation are
  present.
- Reports high-risk configuration review indicators when an authoritative
  server accepts the transfer.
- Requires manual validation.
- Uses redaction-first reporting for domain, names, and values.
- Limitations: no AXFR attempt without explicit authorization, no provider
  import, and no complete-zone statement unless terminal checks pass.

### Active DNS OSINT CT v0

Purpose: bounded public-source observed-name review through the accepted CT
source shape.

- DNS OSINT and CT source gates are disabled by default.
- Accepts one explicit authorized domain.
- Uses the CT source only when both gates are enabled and confirmations pass.
- Reports DNS OSINT review indicators and public-source observed-name context.
- Requires manual validation.
- Uses redaction-first reporting with `[REDACTED_DNS_NAME]` samples.
- Limitations: no passive DNS sources, search scraping, recursive discovery,
  auto-scan of observed names, or provider credentials.

### Active HTTP Basic/Header Review v1

Purpose: one-root-URL HTTP header review through no-live storage or
backend-gated live HEAD.

- Capability gate is disabled by default.
- Live HEAD requires a second disabled-by-default live flag.
- Accepts one explicit authorized root `http://` or `https://` URL with no
  query, fragment, credentials, custom port, or non-root path.
- Default enabled behavior stores a no-live record; live HEAD requires both
  flags and all confirmations.
- Reports HTTP header review indicators.
- Requires manual validation.
- Uses redaction-first reporting with `[REDACTED_TARGET]`.
- Limitations: no GET fallback, body reads, redirects followed, custom headers,
  cookies as input, auth, forms, content traversal, or technology expansion.

## Disabled-By-Default Posture

Active features require explicit feature gates before use. Live actions also
require a valid one-target contract and operator confirmations.

Important gate notes:

- HTTP basic/header review live HEAD requires the capability gate and the
  second live-HEAD gate.
- DNS OSINT CT requires the DNS OSINT capability gate and the CT source gate.
- Authorized AXFR requires DNS inventory enablement, request selection, and a
  separate AXFR authorization confirmation.
- Browser-side target traffic is not part of the product flow; the frontend
  submits to Inspectra backend APIs.

## Safety And Redaction Note

Active results are review indicators for authorized local/private use. Reports
intentionally redact raw targets, domains, names, values, headers, cookies, CT
payload material, resolver context, exception text, credentials, tokens, and
secrets. Redaction is intentional and manual validation is required.

## Validation Evidence

Release-candidate validation:
`docs/future/active-pre-alpha-rc-validation.md`

- Python compile: passed.
- Focused Active backend slice: `352 passed, 338 deselected`.
- Full backend suite: `774 passed`.
- Full frontend suite: `196 tests across 28 files`.
- Focused Active frontend slice: `154 tests across 13 files`.
- Frontend production build: passed with the existing Vite large-chunk warning.
- Docs and guardrail review: passed.

Docker packaging validation:
`docs/future/active-pre-alpha-docker-packaging-validation.md`

- `docker compose config`: passed.
- `docker compose build`: passed for backend, frontend, and audit-tools.
- `docker compose up -d`: passed after packaging-only fixes.
- Backend health: `{"status":"ok","service":"inspectra-backend"}`.
- Frontend local check: `HTTP/1.1 200 OK`.
- Active tools example config-only validation: passed.
- Compose teardown completed and no Inspectra validation containers remained
  running.

Validation phases did not invoke Nmap, submit Active jobs, use real targets,
capture images, deploy to a remote server, publish a release, create a version
marker, or upload commits.

## Docker Package Notes

The root Compose package has been validated for local/private technical-alpha
packaging.

Packaging notes:

- backend image includes the `active_runner` package needed by backend imports;
- frontend image builds and serves static `dist/` output in Docker;
- backend and frontend have host-access Compose networking for the documented
  local ports;
- default host ports remain `8000` and `5173`, with local override hooks for
  occupied developer machines;
- audit-tools remains on the internal runner path;
- Active tools remains separate/example-only and is not part of normal root
  Compose startup;
- image tag naming and provenance move to the next release/tag phase.

## Known Limitations

- Results are bounded and source-specific.
- Redaction prevents raw-target inspection in shared reports by design.
- Live features require careful local/private operator configuration.
- Technology fingerprinting is deferred.
- HTTP policy grouping is deferred.
- TLS deeper review is deferred.
- Nmap deeper review is deferred.
- Passive sources, provider imports, and connector-style administration are
  deferred.
- Active tools remains separate/example-only for this alpha.
- Image tag/provenance recording remains pending until the tag phase.

## Dependency Audit Note

The uncached frontend Docker build reported npm audit warnings during install.
This finalization phase did not run an audit command, change dependencies, or
infer package names or severity beyond the existing packaging-validation log.

Recommended handling: track dependency audit triage as a separate
release-readiness or post-alpha issue unless product decides it must block the
alpha tag.

## Intentionally Not Included

This alpha does not present itself as including:

- open-target internet service intake;
- hosted multi-tenant target intake;
- broad target discovery;
- passive DNS sources or provider imports;
- provider credentials or admin connectors;
- archive/run-all Active orchestration;
- `tools/runner/main.py` Active orchestration;
- body reads, content traversal, browser script execution, or image capture;
- automatic matching from observed versions to vulnerability databases;
- exploit checks;
- automated remediation;
- binary pass/fail target verdicts;
- complete discovery or complete assessment claims.

## Upgrade And Deployment Note

This technical alpha candidate is for local/private/self-hosted use. Operators
must review feature flags before enabling Active capabilities and should enable
only the specific capability needed for an explicitly authorized target,
domain, or URL.

Do not place real secrets, API keys, provider credentials, cookies, tokens, or
private target examples in configuration snippets, screenshots, release notes,
or shared issue comments. These release notes do not add migration
instructions or invent a new deployment process.

## Suggested Next Step

Recommended next phase:

```text
ACTIVE_PRE_ALPHA_RELEASE_TAG_08
```

Scope: run final clean-state checks, record the exact commit hash, create the
alpha tag, and prepare the release from these finalized notes.

Keep VPS deploy/smoke as a separate later phase unless the operator explicitly
chooses a combined tag-and-deploy path.

Do not choose a new Active runtime feature before alpha publication.

## Decision

```text
ACTIVE_PRE_ALPHA_RELEASE_NOTES_FINALIZE_07_ACCEPTED
```
