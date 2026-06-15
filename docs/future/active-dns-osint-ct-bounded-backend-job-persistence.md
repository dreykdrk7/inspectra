# Active DNS OSINT CT Bounded Backend Job Persistence

Decision: `ACTIVE_DNS_OSINT_03_CT_BOUNDED_BACKEND_JOB_PERSISTENCE_PASSED`

This microphase implements the first backend persistence step for
`active_dns_osint`. The backend can now create owner-scoped redacted
`JobRecord`s from `POST /active/network/dns-osint` using an injectable
Certificate Transparency source adapter. The default adapter is disabled and
tests use fake sources only; this phase still performs no real CT, HTTP, DNS,
passive-DNS, provider, crawling, subprocess, Docker, Nmap, archive/run-all, or
`tools/runner/main.py` behavior.

## Accepted State

- Feature flag remains `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=false` by default.
- Endpoint remains `POST /active/network/dns-osint`.
- Enabled valid requests create at most one owner-scoped job:
  - `audit_type: active_dns_osint`;
  - `file_id: null`;
  - `target_url: [REDACTED_DOMAIN]`;
  - `target_domain: null`;
  - `coverage_level: osint_best_effort`.
- The backend validates the existing contract before source handoff:
  - `mode: live_dns_osint`;
  - `profile: ct_subdomain_discovery_bounded`;
  - one explicit authorized domain;
  - `include_certificate_transparency: true`;
  - `include_passive_dns: false`;
  - `max_names` bounded from 1 to 100;
  - `authorization_confirmed: true`;
  - `owned_or_authorized_domain_confirmed: true`;
  - `public_osint_queries_confirmed: true`.
- Anonymous callers in auth-required modes are rejected before validation
  details or source behavior.

## Source Adapter Boundary

The backend defines a CT source adapter contract that can be injected in tests.
The default source returns a controlled `disabled` state and sends no requests.
Fake test sources can return bounded names, source states, timeouts, or
controlled errors without leaving the process.

Allowed source statuses:

- `not_attempted`;
- `disabled`;
- `completed`;
- `partial`;
- `timed_out`;
- `rate_limited`;
- `source_unavailable`;
- `source_error_controlled`;
- `truncated`;
- `invalid_source_response`;
- `blocked_by_policy`.

No real CT source is selected in this phase. A future real source would require
a separate source-specific review for URL, rate limits, timeout behavior, ToS,
redaction, error handling, and product wording.

## Result Boundary

Persisted results are allowlisted and redacted:

- public domain is always `[REDACTED_DOMAIN]`;
- observed-name samples are placeholders only: `[REDACTED_DNS_NAME]`;
- raw CT payloads, certificates, source errors, provider secrets, DNS packets,
  resolver logs, and observed-name values are not public output;
- `manual_validation_required: true`;
- `result_interpretation: DNS OSINT review indicator`;
- passive DNS remains `not_attempted`;
- execution counters remain zero:
  - `external_requests_sent: 0`;
  - `ct_queries_sent: 0`;
  - `passive_dns_queries_sent: 0`;
  - `dns_queries_sent: 0`;
  - `http_requests_sent: 0`.

Observed names from the fake source are normalized, deduplicated, and retained
only when they are the exact authorized domain or subdomains of that domain.
Out-of-scope names are discarded. Wildcard CT names may be normalized by
removing the wildcard prefix, but they are never expanded. Retained names are
truncated by `max_names`.

## Public Surfaces

Detail, list, Raw JSON, and Markdown/HTML/XML/PDF exports are redaction-first:

- no raw domain;
- no raw observed names;
- no raw CT payload;
- no raw certificate body;
- no source payload or source exception text;
- no provider/API credential material;
- wrong-owner detail, export, and delete remain generic `Job not found.`;
- wording remains public-source observed-name review-indicator wording, never a
  vulnerability, exploitability, target-safety, scanner, or exhaustive-inventory
  claim.

## No-Scope Preserved

This phase does not add:

- real Certificate Transparency calls;
- real HTTP calls;
- passive DNS API calls;
- provider DNS/API import;
- API-key handling;
- DNS queries;
- crawling;
- broad scraping;
- search-engine scraping;
- wordlists;
- reverse-IP, ASN, or range discovery;
- automatic scanning of observed names;
- frontend runtime;
- archive/run-all;
- `tools/runner/main.py`;
- Nmap;
- Docker;
- subprocess execution;
- release, tag, or push behavior.

## Tests And Validation

Focused backend tests cover:

- disabled flag rejects without source calls or jobs;
- auth-required anonymous rejection before validation/source calls;
- invalid request, domain policy, and `max_names` rejection without source
  calls;
- fake CT source creates exactly one owner-scoped redacted job;
- normalization, deduplication, out-of-scope discard, wildcard handling, and
  `max_names` truncation;
- empty source output as `osint_best_effort`;
- timeout, rate-limit, unavailable, generic source error, and invalid source
  response as controlled statuses;
- passive DNS remains `not_attempted`;
- detail/list/Raw JSON/export redaction;
- wrong-owner generic not found;
- source guardrails against HTTP, DNS, passive DNS, provider API, subprocess,
  Nmap, Docker, frontend, archive/run-all, and `tools/runner/main.py`.

## Decision

`ACTIVE_DNS_OSINT_03_CT_BOUNDED_BACKEND_JOB_PERSISTENCE_PASSED`
