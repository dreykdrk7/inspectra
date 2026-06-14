# Active DNS Inventory Standard Records And Bounded Discovery

Decision: `ACTIVE_DNS_INVENTORY_03_STANDARD_RECORDS_AND_BOUNDED_DISCOVERY_PASSED`

This microphase turns the existing `active_dns_inventory` backend contract into
a real-minimal, bounded DNS inventory job. The capability remains
disabled-by-default, explicit opt-in, local/private/self-hosted, authorized, and
redaction-first. It adds no frontend runtime, Nmap, Docker, HTTP crawling,
archive/run-all integration, `tools/runner/main.py` integration, release state,
tag state, or push state.

## Implemented Scope

`POST /active/network/dns-inventory` now returns `202 JobRecord` when all gates
pass:

- `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=true`;
- authenticated or trusted local owner context;
- exact `live_dns_inventory` / `dns_inventory_authorized` contract;
- one explicit root domain accepted by policy;
- allowlisted record types only: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`,
  and `CAA`;
- required confirmations set to `true`;
- `attempt_zone_transfer: false`.

The job is owner-scoped, uses `audit_type: active_dns_inventory`, has
`file_id: null`, stores `[REDACTED_DOMAIN]`, and persists only allowlisted
summary data.

## DNS Runtime Boundary

DNS runtime is isolated to `backend/app/active_dns_inventory.py`. The module
uses a structured UDP DNS resolver with bounded timeout and no shell execution.
Tests inject a fake resolver and do not perform real DNS queries.

The backend does not use:

- subprocess execution;
- `dig`, `host`, or `nslookup`;
- Nmap;
- Docker;
- HTTP requests;
- Certificate Transparency sources;
- passive DNS APIs;
- provider APIs;
- AXFR;
- recursive discovery;
- target expansion from files or lists.

## Result Shape

Persisted result fields are bounded and redacted:

- `status` / `result_status`;
- `coverage_level`: `best_effort_inventory` or `partial_inventory`;
- redacted `domain`;
- requested `record_types`;
- grouped standard records with counts, redacted sample names/values, TTL, and
  MX priority when present;
- `security_records` for SPF, DMARC, CAA, and explicit DKIM not-attempted state;
- bounded subdomain summary for the fixed candidate allowlist;
- `zone_transfer` and `provider_import` as not attempted;
- `dns_queries_sent` and `subdomain_queries_sent`;
- controlled error codes;
- execution flags showing no subprocess, no Nmap, no HTTP, no provider API, no
  recursive discovery, no crawling, and no credential validation;
- limits documenting timeout, record caps, candidate caps, and no packet/log
  persistence;
- `manual_validation_required: true`;
- `result_interpretation: DNS configuration review indicator`.

## Bounded Subdomain Discovery

When `include_subdomain_discovery=true`, the backend checks only this fixed
candidate allowlist:

```text
www mail smtp imap pop api app admin portal dev staging test
```

For each candidate it queries only:

```text
A AAAA CNAME
```

The job stores only candidate counts, redacted sample entries, queried record
types, and truncation flags. It does not store raw candidate names.

## Security Record Indicators

When `include_security_records=true`, the backend derives only review
indicators:

- SPF presence from root TXT;
- DMARC presence from `_dmarc.<domain>` TXT;
- CAA presence from root CAA;
- DKIM selector checks are not attempted.

Record values are not persisted publicly.

## Redaction Boundary

Public API detail, job list summaries, Markdown/HTML/XML/PDF exports, and Raw
JSON-style surfaces preserve:

- `[REDACTED_DOMAIN]`;
- `[REDACTED_DNS_NAME]`;
- `[REDACTED_DNS_VALUE]`;
- controlled counts and statuses;
- manual validation wording.

They must not expose raw domain, raw DNS values, raw resolver logs, DNS packets,
provider tokens, provider account identifiers, command lines, stdout/stderr,
credentials, headers, cookies, or tokens.

## Not Approved

This phase does not approve complete-zone coverage, AXFR, provider import,
Certificate Transparency lookup, passive DNS lookup, broad wordlists, DKIM
selector guessing, recursive discovery, sibling or parent expansion, arbitrary
nameserver override, shell commands, packet capture storage, Nmap, Docker,
frontend runtime, archive/run-all, `tools/runner/main.py`, release, tag, or
push state.

Reports must use DNS configuration review-indicator wording and require manual
validation. They must not claim exploitability, target safety, or complete
coverage.

## Tests And Validation

Implemented tests cover:

- disabled flag rejects without resolver call or job;
- auth-required anonymous rejects before validation details and resolver calls;
- invalid requests reject without resolver call or job;
- valid fake resolver creates an owner-scoped `active_dns_inventory` job;
- standard record grouping and public redaction;
- SPF, DMARC, and CAA indicators;
- subdomain discovery disabled and enabled paths;
- partial timeout/error handling as `partial_inventory`;
- empty DNS results as controlled best-effort inventory;
- unsupported AXFR remains blocked;
- detail/list/export redaction;
- wrong-owner detail/delete/export generic not found;
- source guardrails confirming DNS runtime isolation.

Validation run:

- `python3 -m py_compile backend/app/active_dns_inventory.py backend/app/main.py backend/app/storage.py backend/app/reporting.py backend/app/models.py`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_inventory`.
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_dns_inventory or active_tls_basic or active_nmap_basic"`;
- `.venv/bin/python -m pytest backend/tests`;
- `git diff --check`;
- `git diff --cached --check`.

## Decision

`ACTIVE_DNS_INVENTORY_03_STANDARD_RECORDS_AND_BOUNDED_DISCOVERY_PASSED`
