# Active DNS Inventory V0 Functional Closeout

Decision: `ACTIVE_DNS_INVENTORY_06_FUNCTIONAL_REVIEW_AND_CLOSEOUT_ACCEPTED`

This document closes `active_dns_inventory` v0 after the backend real-minimal
runtime, backend boundary review, and frontend product flow. It adds no new
runtime behavior, no new DNS execution, no AXFR, no provider API, no
Certificate Transparency lookup, no passive DNS lookup, no Docker execution,
no Nmap execution, no HTTP crawling, no archive/run-all behavior, no
`tools/runner/main.py` behavior, no release, no tag, and no push state.

Status note: this document remains the historical v0 closeout before the
separate authorized AXFR backend and frontend extension. The expanded v0
boundary with authorized AXFR is closed in
`docs/future/active-dns-inventory-with-authorized-axfr-functional-closeout.md`
with decision
`ACTIVE_DNS_INVENTORY_11_FUNCTIONAL_CLOSEOUT_WITH_AXFR_ACCEPTED`.

## Reviewed Commits

Reviewed as the functional v0 line:

- `d1ad2d9 feat(active): persist dns inventory standard records`;
- `cdbbcad fix(active): harden dns inventory backend runtime`;
- `5230fa6 feat(active): show dns inventory jobs in frontend`.

These commits establish the bounded backend runtime, harden the boundary, and
connect the frontend product flow without widening the capability into a
scanner or complete-zone inventory.

## Approved State

`active_dns_inventory` v0 is accepted as a functional minimum Active capability
with these boundaries:

- feature flag disabled by default through
  `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=false`;
- endpoint `POST /active/network/dns-inventory`;
- exact request contract `live_dns_inventory` /
  `dns_inventory_authorized`;
- one explicit authorized root domain;
- record types allowlisted to `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`,
  and `CAA`;
- SPF, DMARC, and CAA review indicators;
- fixed-candidate bounded subdomain discovery;
- DNS runtime isolated to `backend/app/active_dns_inventory.py`;
- owner-scoped `active_dns_inventory` jobs with `file_id: null`;
- public domain display as `[REDACTED_DOMAIN]`;
- record names and values redacted or bounded before storage and rendering;
- `best_effort_inventory` and `partial_inventory` coverage states only;
- reporting, exports, Raw JSON, and frontend rendering are redaction-first;
- frontend forces `attempt_zone_transfer: false`;
- manual validation required;
- wording limited to DNS configuration review indicators.

The backend remains the authority for auth, owner scope, contract validation,
domain policy, job creation, storage, report/export shaping, and redaction.

## Not Approved

The v0 closeout does not approve:

- complete-zone coverage without a separately authorized AXFR phase;
- AXFR runtime;
- provider DNS/API import;
- Certificate Transparency lookup;
- passive DNS lookup;
- broad wordlists;
- recursive discovery;
- wildcard discovery expansion;
- DKIM selector guessing;
- parent-domain or sibling-domain expansion;
- custom resolver or nameserver override from the request;
- target files or generated candidates;
- DNS CLI execution such as `dig`, `host`, or `nslookup`;
- subprocess execution;
- Nmap;
- Docker runtime;
- HTTP or crawling;
- credential validation;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- public scanner or SaaS-style inventory behavior;
- vulnerability, exploitability, target-safety, all-records-found, or
  complete-coverage claims.

## Boundary Review

Confirmed v0 boundaries:

- auth-required deployments deny anonymous requests before DNS validation
  details;
- disabled mode rejects without creating jobs and without calling the resolver;
- invalid requests reject before resolver invocation;
- `attempt_zone_transfer=true` rejects in the contract gate;
- query accounting is aligned with actual sends by using one configured
  nameserver per logical query;
- root record lookups use only the allowlisted record types;
- SPF derives from root TXT, DMARC derives from `_dmarc.<domain>`, and CAA
  derives from root CAA;
- bounded subdomain discovery uses only the fixed candidate list and
  `A`/`AAAA`/`CNAME` per candidate;
- no recursive discovery, broad wordlist, wildcard expansion, sibling
  expansion, parent expansion, target-file expansion, CT/passive DNS, provider
  API, or AXFR path is present;
- no raw domain, raw record values, raw resolver logs, raw DNS packets,
  provider tokens, provider account IDs, provider zone IDs, credentials,
  headers, cookies, tokens, commands, stdout, stderr, or packet captures appear
  in public surfaces;
- wrong-owner reads, exports, and deletes stay generic not found;
- frontend exposes no AXFR, provider, CT/passive DNS, resolver override, raw
  DNS packet, shell, credential, header, cookie, token, or archive/run-all
  controls.

## Reporting And UX

The accepted UX is a separate `Active / DNS inventory` panel and
`ActiveDnsInventoryJobReport` renderer. The product flow:

- sends the exact backend contract;
- requires authorization, local/private/owned scope, and live-DNS-query
  confirmations;
- opens the returned `202 JobRecord`;
- refreshes the jobs list;
- groups records by type;
- renders SPF, DMARC, and CAA as review indicators;
- renders bounded subdomain counts and redacted samples;
- renders zone transfer and provider import as `not_attempted`;
- keeps Raw JSON redaction-first;
- distinguishes `best_effort_inventory` and `partial_inventory` from any
  future authorized AXFR complete-zone source.

The UI must continue to avoid completed-scan, vulnerability, exploitability,
target-safety, all-records-found, public-scanner, and complete-coverage copy.

## Validation Record

Validation run during this closeout:

- `git status --short --branch`;
- `git show --stat --oneline d1ad2d9`: reviewed 10-file backend runtime
  integration commit;
- `git show --stat --oneline cdbbcad`: reviewed backend hardening commit;
- `git show --stat --oneline 5230fa6`: reviewed frontend product-flow commit;
- `python3 -m py_compile backend/app/active_dns_inventory.py backend/app/main.py backend/app/storage.py backend/app/reporting.py backend/app/models.py`:
  passed;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_inventory`:
  `60 passed, 490 deselected`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_dns_inventory or active_tls_basic or active_nmap_basic"`:
  `212 passed, 338 deselected`;
- `.venv/bin/python -m pytest backend/tests`: `634 passed`;
- `npm test -- --run ActiveDnsInventoryPanel ActiveDnsInventoryJobReport App dashboardFilters`:
  `60 passed`;
- `npm test -- --run`: `167 passed`;
- `npm run build`: passed with the existing Vite chunk-size warning only;
- `git diff --check`: passed;
- `git diff --cached --check`: passed;
- guardrail source and wording searches for AXFR/provider/CT/passive DNS
  runtime, DNS CLI/subprocess, Nmap, Docker, HTTP/crawling, archive/run-all,
  `tools/runner/main.py`, raw domain/record/provider-secret leakage, and
  complete-coverage wording drift found only no-scope documentation,
  historical references, controlled metadata, or redaction patterns.

## Roadmap

Recommended next decision point:

1. Stop for a technical pathing choice after this closeout.
2. Choose one separately scoped path: authorized AXFR design, a new small
   Active tool, Nmap polish, DNS operational polish, or release preparation.
3. Keep archive/run-all out of Active DNS inventory until a separate design
   freezes owner scope, authorization, redaction, and abuse boundaries.
4. Keep complete-zone states in core Active DNS reserved for future authorized
   AXFR. Provider import, if ever needed, belongs in a separate admin inventory
   connector rather than the attacker-equivalent Active DNS path.

## Decision

`ACTIVE_DNS_INVENTORY_06_FUNCTIONAL_REVIEW_AND_CLOSEOUT_ACCEPTED`
