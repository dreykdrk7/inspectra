# Active DNS OSINT Frontend CT OSINT Product Flow

Decision: `ACTIVE_DNS_OSINT_07_FRONTEND_CT_OSINT_PRODUCT_FLOW_PASSED`

## Scope

This microphase connects the existing frontend to the backend
`active_dns_osint` job contract for bounded Certificate Transparency OSINT.
It adds the separate `Active / DNS OSINT` panel, sends the exact
`POST /active/network/dns-osint` request shape, accepts a `202 JobRecord`,
selects the returned job, refreshes the job list, and renders CT OSINT
results as public-source observed-name review indicators.

## Product Contract

The frontend sends:

- `mode: live_dns_osint`;
- `profile: ct_subdomain_discovery_bounded`;
- one explicit `domain`;
- `include_certificate_transparency: true`;
- `include_passive_dns: false`;
- bounded `max_names`;
- `authorization_confirmed: true`;
- `owned_or_authorized_domain_confirmed: true`;
- `public_osint_queries_confirmed: true`.

Passive DNS remains visible as unavailable and is not user-activatable in this
phase. The browser does not call CT sources, passive-DNS sources, provider APIs,
DNS resolvers, or observed names directly.

## UX Boundary

The panel requires three confirmations:

- authorization to query the domain;
- ownership or explicit authorization for the domain;
- acceptance that the backend may perform bounded public OSINT queries if
  configured and policy accepts the request.

The panel shows Certificate Transparency as the bounded source, `Passive DNS:
not_attempted`, `osint_best_effort` coverage, redacted domain display, and
manual-validation wording. Observed names are not auto-scanned.

## Report Rendering

The `Active / DNS OSINT report` renders:

- `coverage_level: osint_best_effort`;
- CT source status and counters;
- retained/observed/discarded name counts;
- truncation and controlled source error states;
- redacted observed-name samples;
- passive DNS `not_attempted`;
- execution counters for CT, passive DNS, DNS, HTTP, provider, crawling, and
  observed-name auto-scan boundaries;
- Raw JSON redacted-first.

Allowed wording remains:

- `DNS OSINT review indicator`;
- `OSINT best-effort`;
- `public-source observed-name review indicator`;
- `Manual validation required`.

The UI does not present OSINT output as exhaustive discovery, exploitability,
target safety, or vulnerability proof.

## Redaction Boundary

Frontend rendering defensively redacts:

- raw domain;
- raw observed names;
- raw CT payloads;
- certificate bodies;
- source exception text;
- provider secrets;
- credentials, headers, cookies, and tokens;
- email-like values and DNS value material.

Job list targets use `[REDACTED_DOMAIN]`, and Raw JSON uses placeholders such
as `[REDACTED_DOMAIN]` and `[REDACTED_DNS_NAME]`.

## No-Scope Confirmed

This microphase adds no passive DNS source, provider DNS/API integration,
frontend CT HTTP calls, DNS queries from the frontend, crawling, search-engine
scraping, wordlists, reverse-IP/ASN/range discovery, observed-name auto-scan,
archive/run-all integration, `tools/runner/main.py`, Nmap, Docker, subprocess
runtime, release, tag, or push behavior.

## Validation Notes

Expected validation set:

- backend focused `active_dns_osint`;
- focused frontend DNS OSINT/App/catalog/report tests;
- full frontend suite;
- frontend build;
- diff checks;
- guardrail searches for passive-DNS/provider/API boundaries, frontend CT
  direct calls, DNS queries, archive/run-all, tools runner, raw-domain/name/source
  leakage, and prohibited claim wording.

## Final State

`active_dns_osint` is now visible in the frontend as a bounded
Certificate-Transparency OSINT product flow. Jobs remain owner-scoped,
domain-redacted, source-limited, `osint_best_effort`, and manual-review only.
