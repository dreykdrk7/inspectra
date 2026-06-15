# Active DNS OSINT Real CT Source Bounded

Decision: `ACTIVE_DNS_OSINT_05_REAL_CT_SOURCE_BOUNDED_PASSED`

This microphase adds the first real Certificate Transparency source for
`active_dns_osint`, behind explicit configuration and bounded runtime controls.
The capability remains attacker-equivalent, owner-scoped, redaction-first, and
`osint_best_effort`.

## Accepted State

- Core feature flag remains `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=false` by
  default.
- CT source flag is separate and remains disabled by default:
  `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED=false`.
- A request can reach the real CT source only after:
  - the backend feature flag is enabled;
  - the CT source flag is enabled;
  - the CT source URL is configured and accepted;
  - the `live_dns_osint` / `ct_subdomain_discovery_bounded` contract passes;
  - domain policy accepts one explicit authorized domain;
  - `include_certificate_transparency: true`;
  - `include_passive_dns: false`;
  - all authorization and public-OSINT confirmations are true.
- Disabled or missing CT source configuration returns controlled `disabled`
  source state and sends no request.
- Invalid CT source URL configuration returns controlled `blocked_by_policy`
  and sends no request.
- Tests use `httpx.MockTransport` or fake source adapters and do not depend on
  external network access.

## Source

Chosen source:

- Source: `crt.sh`
- Base URL: `https://crt.sh/`
- Request shape: `GET /?q=%.<authorized-domain>&output=json`
- Response format: JSON array of objects.
- Candidate fields parsed: `name_value` and `common_name`.
- Names may be newline-separated in `name_value`.

The configured URL is accepted only when it is exactly an HTTPS `crt.sh` base
URL with no credentials, custom path, query, or fragment. Other hosts, schemes,
paths, credentials, query strings, or fragments are blocked before any request.

## Runtime Limits

Defaults:

- `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_TIMEOUT_SECONDS=5.0`
- `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_RESPONSE_BYTES=262144`
- `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_NAMES_PARSED=500`
- retained names: request `max_names`, bounded from 1 to 100.

Hard config ceilings:

- timeout: 10 seconds;
- response bytes: 1048576;
- parsed candidate names: 1000.

Each accepted request performs at most one CT HTTP request. There are no
recursive CT requests, DNS queries, passive-DNS requests, provider requests,
crawling, search-engine scraping, wordlists, reverse-IP discovery, ASN/range
discovery, or automatic scans of observed names.

## Error And Rate Handling

Source states remain allowlisted:

- `completed`;
- `partial`;
- `timed_out`;
- `rate_limited`;
- `source_unavailable`;
- `source_error_controlled`;
- `truncated`;
- `invalid_source_response`;
- `blocked_by_policy`;
- `disabled`.

HTTP status handling:

- `429` becomes `rate_limited`;
- `408` or `504` becomes `timed_out`;
- `5xx` becomes `source_unavailable`;
- other non-`200` statuses become `source_error_controlled`;
- invalid JSON or unexpected response shape becomes `invalid_source_response`;
- over-limit response bytes become `truncated`.

Errors do not persist raw source payloads, raw exception strings, domain values,
observed-name values, certificate material, email/person strings, provider
credentials, or API-key material.

## Normalization

Candidate names from CT are normalized through the existing
`active_dns_osint` domain policy:

- lowercase;
- trailing dot removed;
- IDNA normalized;
- duplicate names deduplicated before retention;
- exact authorized domain and subdomains only;
- out-of-scope names discarded;
- leading wildcard labels may be stripped;
- wildcard values are never expanded;
- retained names are capped by request `max_names`;
- candidate parsing is capped by source `max_names_parsed`.

Observed names are never used as new targets.

## Storage And Public Surfaces

Jobs remain owner-scoped `active_dns_osint` records with:

- `file_id: null`;
- `target_url: [REDACTED_DOMAIN]`;
- `target_domain: null`;
- `coverage_level: osint_best_effort`;
- redacted observed-name counters and placeholder samples;
- manual validation required.

Detail, list, Raw JSON, and Markdown/HTML/XML/PDF export surfaces remain
redaction-first:

- domain is `[REDACTED_DOMAIN]`;
- observed names are `[REDACTED_DNS_NAME]`;
- raw CT payloads are not exposed;
- raw certificate bodies are not exposed;
- raw source errors are not exposed;
- provider/API credentials are not accepted or exposed;
- wrong-owner access remains generic `Job not found.`.

Wording remains `DNS OSINT review indicator`, `OSINT best-effort`, and
`Manual validation required`. Results do not claim subdomain completeness,
record completeness, exhaustive inventory, vulnerability, exploitability,
target safety, or scanner-service behavior.

## No-Scope Preserved

This phase does not add:

- passive DNS;
- provider DNS/API import;
- API-key handling;
- DNS queries;
- crawling;
- broad scraping;
- search-engine scraping;
- wordlists;
- reverse-IP discovery;
- ASN/range discovery;
- frontend runtime;
- archive/run-all;
- `tools/runner/main.py`;
- Nmap;
- Docker;
- subprocess;
- release, tag, or push behavior.

## Validation Summary

Commands run:

- `git status --short --branch`
- `python3 -m py_compile backend/app/active_dns_osint.py backend/app/main.py backend/app/config.py`
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_osint`
- Active backend related tests
- full backend suite
- `git diff --check`
- `git diff --cached --check`
- guardrail searches for source/runtime boundaries and wording drift

Results:

- focused `active_dns_osint`: 78 passed;
- Active backend related tests: 298 passed;
- full backend suite: 720 passed;
- diff checks: clean;
- guardrails: no blocker.

## Decision

`ACTIVE_DNS_OSINT_05_REAL_CT_SOURCE_BOUNDED_PASSED`
