# Active DNS OSINT Backend Contract Gate

Decision: `ACTIVE_DNS_OSINT_02_BACKEND_CONTRACT_GATE_ACCEPTED`

This microphase adds the initial backend contract gate for future
`active_dns_osint` without implementing any source runtime. The endpoint exists
only to validate the request shape, authorization confirmations, source flags,
domain policy, and disabled-by-default behavior.

## Accepted State

- Feature flag: `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=false` by default.
- Endpoint: `POST /active/network/dns-osint`.
- Accepted identity:
  - `mode: live_dns_osint`;
  - `profile: ct_subdomain_discovery_bounded`;
  - `capability: active_dns_osint`;
  - `audit_type: active_dns_osint`.
- Accepted input:
  - one explicit domain string;
  - `include_certificate_transparency: true`;
  - `include_passive_dns: false`;
  - `max_names` as a bounded integer from 1 to 100;
  - `authorization_confirmed: true`;
  - `owned_or_authorized_domain_confirmed: true`;
  - `public_osint_queries_confirmed: true`.
- Disabled mode rejects before creating jobs, storage, source lookups, or any
  runtime side effects.
- Enabled valid requests return controlled `not_executed` metadata with:
  - `[REDACTED_DOMAIN]`;
  - `external_requests_sent: 0`;
  - `ct_queries_sent: 0`;
  - `passive_dns_queries_sent: 0`;
  - `job_created: false`;
  - `storage_persisted: false`;
  - empty observed-name samples;
  - `manual_validation_required: true`.

## Validation Boundary

The contract rejects unsupported or dangerous fields, including provider
credentials, API keys/tokens, passive-DNS source selection, Certificate
Transparency source override, search-engine fields, wordlists, crawling fields,
headers, cookies, credential material, target files, resolver or nameserver
override, reverse-IP/ASN/range inputs, and shell/command fields.

Domain validation accepts only a single explicit domain and rejects empty input,
lists, URL-shaped values, paths, query strings, fragments, userinfo, wildcards,
IP addresses, CIDR/range-like values, target files, metadata/control-plane
names, single-label names, overlong labels, and control characters.

In auth-required modes, anonymous callers are denied by the existing global
guard before validation details are disclosed.

## No Runtime Added

This phase does not add:

- Certificate Transparency queries;
- passive DNS queries;
- HTTP requests;
- DNS queries;
- provider DNS/API import;
- credentials or API-key handling;
- crawling, scraping, search-engine scraping, broad wordlists, reverse-IP, ASN,
  or range discovery;
- sockets, `ssl`, OpenSSL, subprocess, DNS CLI, Nmap, Docker, frontend runtime,
  persistent jobs, storage, reports/exports, archive/run-all, or
  `tools/runner/main.py` integration.

## Reporting Wording

The returned metadata preserves the future wording direction: OSINT output is a
public-source observed-name review indicator, not proof of vulnerability, not
proof of exploitability, not target-safety evidence, and not exhaustive
coverage.

## Validation Summary

Focused backend tests cover disabled behavior, enabled `not_executed` response,
required mode/profile, confirmations, CT/passive-DNS source flags, bounded
`max_names`, malformed domains, dangerous extra fields, target/payload
redaction in errors, auth-required anonymous behavior, feature-flag parsing, and
source guardrails confirming that the backend contract gate contains no source
runtime, no jobs, no storage, and no runner/archive/frontend integration.
