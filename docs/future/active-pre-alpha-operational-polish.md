# Active Pre-Alpha Operational Polish

Decision: `ACTIVE_PRE_ALPHA_OPERATIONAL_POLISH_01_ACCEPTED`

This docs/checklist-only package consolidates operator guidance for the closed
Active capabilities. It adds no endpoint, flag, contract, storage, transport,
report, UI, test, backend behavior, frontend behavior, tools behavior,
archive/run-all handoff, `tools/runner/main.py` handoff, live target activity,
release, tag, or push state.

## Capability Map

| Capability | Purpose | Default posture | Target boundary | Live/no-live behavior | Report wording | Key not-approved scope |
| --- | --- | --- | --- | --- | --- | --- |
| Active / Nmap basic v0 | Bounded TCP exposure review using the accepted Nmap v0 path. | Disabled unless the Active Nmap flag and supporting active-tools path are configured. | One authorized target set within the accepted v0 policy. | Supports no-live lifecycle records and the reviewed minimal live path when explicitly configured. | Observed exposure review indicator; manual validation required. | No broad port sweep, service/version expansion, script scans, credential checks, or target expansion. |
| Active / TLS basic v0 | One-host TLS handshake and certificate metadata review. | Disabled by default through its feature flag. | One authorized host and one accepted TLS port. | Live TLS handshake only after operator confirmation and the flag gate. | TLS configuration review indicator; manual validation required. | No HTTP request, content traversal, raw certificate material, client credentials, or alternate-port retry expansion. |
| Active DNS inventory v0 | Standard DNS record and configuration review for one domain. | Disabled by default through its feature flag. | One explicit authorized root domain. | Live DNS inventory only after authorization and live-query confirmation. | DNS configuration review indicator; best-effort or bounded inventory wording; manual validation required. | No provider administration, passive DNS source, broad wordlist, sibling-domain expansion, or automatic probing of names. |
| Authorized AXFR | Separately confirmed zone-transfer review inside DNS inventory. | Disabled unless DNS inventory is enabled and the request confirms AXFR authorization. | One explicit authorized root domain and authoritative-server context. | Attempted only when the request sets the AXFR option and the separate confirmation. | High-risk configuration review indicator when accepted by an authoritative server; manual validation required. | No zone-transfer attempt without explicit authorization, no provider import, and no complete-zone claim unless terminal checks pass. |
| Active DNS OSINT CT v0 | Bounded public-source observed-name review through the accepted CT source shape. | DNS OSINT and CT source flags are disabled by default. | One explicit authorized domain. | CT source request only when both OSINT and CT source flags are enabled and confirmations pass. | DNS OSINT review indicator; public-source observed names; manual validation required. | No passive DNS source, search scraping, recursive discovery, auto-scan of observed names, or provider credentials. |
| Active HTTP basic/header review v1 | One-root-URL HTTP header review through no-live storage or backend-gated live HEAD. | Capability flag disabled by default; live HEAD has a second disabled-by-default flag. | One explicit authorized root `http://` or `https://` URL, no query, fragment, credentials, custom port, or path beyond `/`. | Default enabled behavior stores a no-live record; live HEAD requires both flags and all confirmations. | HTTP header review indicator; manual validation required. | No GET fallback, body reads, redirects followed, custom headers, cookies as input, auth, forms, content traversal, or technology expansion. |

## Operator Usage Story

Active capabilities are for trusted local, private, or self-hosted operation by
an operator who has explicit authorization for the submitted target, domain, or
URL. They are not intended as an open internet scanning service or hosted
multi-tenant target-intake product.

Every Active result is review context. It can help an operator decide what to
inspect next, but it does not prove that a vulnerability exists, does not prove
exploitability, does not establish that a target is safe, and does not promise
complete discovery. Manual validation is required.

Redaction is intentional. Placeholder values in reports, exports, Raw JSON,
lists, and frontend detail views mean the system is preserving the accepted
privacy and abuse boundaries, not failing to render data.

## Safe Enablement Guide

Use feature flags only in a controlled local/private deployment. Keep flags off
until the operator can explain the target authorization, expected live traffic,
and manual validation plan.

At a high level:

- Nmap basic v0 uses its own Active Nmap feature gate and active-tools setup.
- TLS basic v0 uses its TLS feature gate.
- DNS inventory v0 uses its DNS inventory feature gate.
- Authorized AXFR also requires the request-level AXFR option and separate
  confirmation.
- DNS OSINT CT v0 requires the DNS OSINT gate, the CT source gate, and the
  accepted CT source configuration.
- HTTP basic/header review v1 uses one capability gate for no-live records and
  a second live-HEAD gate before the backend may attempt one HEAD request.

Use placeholders in docs, checklists, and examples:

```text
example.com
https://example.com/
[AUTHORIZED_TARGET]
[AUTHORIZED_DOMAIN]
```

Do not place real targets, credentials, cookies, API keys, account IDs, or
tokens in screenshots, examples, issue comments, release notes, or shared
checklists.

When a live feature is enabled, live traffic may occur only after matching
feature flags, a valid one-target contract, and operator confirmations. The
browser-side product flow must continue to call only Inspectra backend APIs.

## Smoke Checklist

This checklist is for later operator use. This phase did not execute it.

Setup and disabled-state checks:

- Confirm the deployment is local/private/self-hosted.
- Confirm all Active flags are off by default in a fresh environment.
- Confirm disabled Active routes return controlled disabled responses or remain
  unavailable as designed.
- Confirm disabled submissions create no job and no live traffic.

No-live checks:

- Enable only the HTTP basic/header review capability gate.
- Submit the placeholder URL shape `https://example.com/` only in an authorized
  lab phase.
- Confirm a no-live `active_http_basic_header_review` job stores
  `[REDACTED_TARGET]`, method `HEAD`, zero requests, no redirect followed, no
  body read, and manual validation copy.
- Confirm completed lifecycle wording does not imply HTTP success.

Live-enabled placeholder checks:

- For each live capability, enable only the relevant feature gates in an
  explicitly authorized lab phase.
- Use one authorized target/domain/URL at a time.
- Confirm confirmations are required before a job is accepted.
- Confirm pre-request policy blocks create no job and do not call live
  transports.
- Confirm timeout/error states are controlled review context.

Report, export, and Raw JSON checks:

- Check Markdown, HTML, XML, PDF, Raw JSON, list, and detail views.
- Confirm redacted placeholders are present where expected.
- Confirm raw targets, cookies, header values, resolver data, CT payloads,
  response bodies, exception text, credentials, tokens, and secrets are absent.
- Confirm wrong-owner detail, delete, and export requests return generic not
  found behavior in auth-required deployments.

Frontend checks:

- Confirm the Active panels are visible only as product surfaces and do not add
  browser-side target traffic.
- Confirm each panel requires authorization confirmations.
- Confirm reports use review-indicator wording and manual validation copy.
- Confirm no panel exposes batch Active orchestration, provider credentials, or
  unsupported target expansion controls.

## Redaction And Reporting Guide

Common placeholders:

- `[REDACTED_TARGET]`: target URL, host, or active-tool target display is
  intentionally hidden.
- `[REDACTED_DOMAIN]`: raw domain value is intentionally hidden.
- `[REDACTED_DNS_NAME]`: observed or retained DNS name is intentionally hidden.
- `[REDACTED_DNS_VALUE]`: DNS record value is intentionally hidden or bounded.

Raw values are not rendered because they can contain credentials, tokens,
private hostnames, account identifiers, internal topology, resolver details,
response headers, cookies, redirect locations, CT payload material, exception
text, or other sensitive context. The public result shape should expose only
bounded indicators, counts, booleans, controlled status codes, and caveats.

Allowed wording:

- review indicator;
- observed exposure;
- manual validation required;
- best effort;
- bounded;
- controlled timeout/error;
- redaction-first.

Avoid wording that implies:

- a vulnerability has been proven;
- exploitability has been proven;
- the target has been established as safe;
- discovery or assessment is complete;
- every issue has been found;
- a binary pass/fail verdict for the target.

## Pre-Alpha Readiness Notes

Strong enough for a technical alpha:

- multiple Active capabilities are closed with explicit flags, owner-scoped
  jobs, redaction-first reports, and manual-validation wording;
- HTTP header review has both no-live and backend-gated live HEAD boundaries;
- DNS inventory, authorized AXFR, DNS OSINT CT, TLS basic, and Nmap basic have
  separate closeout documents;
- operational guidance now gives operators a single map and smoke checklist.

Intentionally deferred:

- technology fingerprint ultra-bounded summary layer;
- HTTP policy grouping beyond current header indicators;
- TLS deeper v1;
- Nmap deeper v1 unless a strong product reason appears;
- passive DNS and provider import;
- archive/run-all Active orchestration;
- `tools/runner/main.py` Active orchestration.

Do not advertise yet:

- hosted open-target intake;
- unattended broad scanning;
- connector-based provider administration;
- source-credential workflows;
- automated remediation;
- binary target verdicts;
- complete discovery or complete assessment.

Suggested next consolidation steps:

- add static screenshots or a demo script in a separate docs phase;
- prepare release notes for the closed Active capability set;
- prepare a tag/release-candidate checklist;
- optionally run local smoke checks on owned lab targets in a separate,
  explicitly authorized phase.

## Deferred Paths

Technology fingerprint ultra-bounded remains a later candidate only as a
conservative summary layer over already approved bounded signals.

HTTP policy grouping remains a later candidate if it only improves
interpretation, copy, and report grouping for already collected header
indicators.

TLS deeper v1 remains a later candidate if it preserves the one-host,
authorization-confirmed, disabled-by-default TLS boundary.

Nmap deeper v1 remains deferred unless a specific product need justifies the
larger review and test surface.

Passive DNS and provider import remain deferred because they introduce source
terms, credentials, retention, account identity, source failure, and abuse
boundary complexity.

`archive/run-all` and `tools/runner/main.py` remain outside Active until a
separate architecture decision freezes how explicit authorization, owner
scope, redaction, and per-capability intent would be preserved.

## Decision

```text
ACTIVE_PRE_ALPHA_OPERATIONAL_POLISH_01_ACCEPTED
```
