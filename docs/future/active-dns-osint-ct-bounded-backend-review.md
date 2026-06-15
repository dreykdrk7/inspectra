# Active DNS OSINT CT Bounded Backend Review

Decision: `ACTIVE_DNS_OSINT_04_CT_BOUNDED_BACKEND_REVIEW_PASSED`

This review covers `d233d51 feat(active): persist dns osint ct source results`
and the current tree after `ACTIVE_DNS_OSINT_03_CT_BOUNDED_BACKEND_JOB_PERSISTENCE_PASSED`.
The review found no blockers and applied no functional changes.

## Reviewed Change

Commit reviewed:

- `d233d51 feat(active): persist dns osint ct source results`

Files reviewed:

- `backend/app/active_dns_osint.py`
- `backend/app/main.py`
- `backend/app/models.py`
- `backend/app/storage.py`
- `backend/app/reporting.py`
- `backend/tests/test_backend.py`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`
- `docs/future/active-dns-osint-design.md`
- `docs/future/active-dns-osint-backend-contract-gate.md`
- `docs/future/active-dns-osint-ct-bounded-backend-job-persistence.md`

## Contract And Gate

The backend keeps `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=false` by default. Disabled
mode rejects before source calls or job creation. Auth-required anonymous
requests are blocked by the existing auth guard before validation details are
returned. Invalid request bodies, malformed domains, unsupported source flags,
dangerous extra fields, and out-of-range `max_names` fail before source handoff.

The accepted contract remains:

- `mode: live_dns_osint`;
- `profile: ct_subdomain_discovery_bounded`;
- one explicit authorized domain;
- `include_certificate_transparency: true`;
- `include_passive_dns: false`;
- `max_names` from 1 to 100;
- `authorization_confirmed: true`;
- `owned_or_authorized_domain_confirmed: true`;
- `public_osint_queries_confirmed: true`.

`include_passive_dns=true` remains blocked. Provider credentials, source
overrides, search-engine fields, wordlists, crawling flags, target files,
resolver/nameserver overrides, reverse-IP/ASN/range inputs, headers, cookies,
tokens, credentials, and shell/command fields remain unsupported.

## CT Source Adapter

The CT source boundary remains fakeable and disabled by default. The default
adapter returns `disabled` and sends no request. Tests inject fake sources only.
No real CT URL, HTTP client, DNS resolver, passive-DNS API, provider API, API-key
handling, subprocess, Nmap, or Docker behavior was added.

Allowed source statuses remain:

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

Timeouts, rate limits, source unavailability, unexpected exceptions, and invalid
source responses normalize to controlled status/error values without exposing raw
source payloads or exception text.

## Observed Names

Observed names are normalized and deduplicated before counting retained names.
Only the exact authorized domain or subdomains of that domain are retained.
Out-of-scope names are discarded. CT wildcard names may be normalized by removing
the leading wildcard label, but there is no wildcard expansion. Retention is
capped by `max_names`, and truncation is reported when eligible names exceed the
retained count.

The reviewed implementation does not auto-scan observed names, perform DNS
resolution, crawl HTTP, expand parent/sibling domains, perform reverse-IP/ASN
discovery, or feed observed names into any other Active capability.

## Storage, Reporting, And Redaction

Jobs are persisted as owner-scoped `active_dns_osint` records with:

- `file_id: null`;
- `target_url: [REDACTED_DOMAIN]`;
- `target_domain: null`;
- `coverage_level: osint_best_effort`;
- source status and bounded counters;
- placeholder observed-name samples only;
- manual validation required.

Public detail, list, Raw JSON, and Markdown/HTML/XML/PDF export surfaces are
redaction-first:

- domain is `[REDACTED_DOMAIN]`;
- observed names are `[REDACTED_DNS_NAME]` placeholders;
- raw CT payloads are not exposed;
- raw certificate material is not exposed;
- raw source exceptions are not exposed;
- emails/person names are redacted;
- provider/API credentials are redacted;
- wrong-owner detail, export, and delete return generic `Job not found.`;
- legacy malformed stored payloads are normalized back to safe public output.

## Wording Boundary

The accepted wording is:

- `DNS OSINT review indicator`;
- `osint_best_effort`;
- `Manual validation required`;
- public-source observed-name inventory.

The review confirmed that OSINT best-effort is not presented as exhaustive zone
inventory, provider import coverage, or exhaustive source inventory. It does not
claim subdomain completeness, record completeness, vulnerability, exploitability,
target safety, or scanner-service behavior.

## No-Scope Confirmed

Still not implemented or approved:

- real Certificate Transparency calls;
- real HTTP calls;
- passive DNS;
- provider DNS/API;
- DNS queries;
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
- `git show --stat --oneline d233d51`
- `git show --name-only --oneline d233d51`
- `python3 -m py_compile backend/app/active_dns_osint.py backend/app/main.py backend/app/storage.py backend/app/reporting.py backend/app/models.py`
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_osint`
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_dns_osint or active_dns_inventory or active_tls_basic or active_nmap_basic"`
- `.venv/bin/python -m pytest backend/tests`
- `git diff --check`
- `git diff --cached --check`
- focused guardrail searches for HTTP/CT runtime, passive DNS/provider API, DNS
  queries, subprocess/Nmap/Docker, frontend/archive/tools-runner integration,
  raw domain/observed-name/source-payload/certificate leakage, complete-coverage
  drift, and vulnerability/exploitability/target-safety wording.

Results:

- focused `active_dns_osint`: 70 passed;
- Active backend related tests: 290 passed;
- full backend suite: 712 passed;
- diff checks: clean;
- guardrails: no blocker.

## Decision

`ACTIVE_DNS_OSINT_04_CT_BOUNDED_BACKEND_REVIEW_PASSED`
