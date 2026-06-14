# Active DNS Inventory Backend Contract Gate

Decision: `ACTIVE_DNS_INVENTORY_02_BACKEND_CONTRACT_GATE_ACCEPTED`

This microphase implements the initial backend contract gate for the future
`active_dns_inventory` capability. It adds no DNS runtime, no sockets, no
subprocess calls, no `dig`, no `host`, no `nslookup`, no Nmap, no Docker, no
HTTP requests, no Certificate Transparency runtime, no passive DNS API runtime,
no AXFR execution, no provider API integration, no subdomain discovery runtime,
no jobs, no storage, no exports, no frontend runtime, no archive/run-all
integration, no `tools/runner/main.py` integration, no release state, no tag
state, and no push state.

## Implemented Scope

The backend now has a disabled-by-default feature flag:

```text
INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=false
```

The backend exposes the contract gate:

```text
POST /active/network/dns-inventory
```

When disabled, the endpoint rejects the request with a controlled response and
creates no job.

When enabled, the endpoint validates the exact contract, denies anonymous
auth-required requests before validation details, and returns a controlled
`not_executed` payload. The response records:

- `capability: active_dns_inventory`;
- `status: not_executed`;
- `coverage_level: not_executed`;
- `domain: [REDACTED_DOMAIN]`;
- `dns_queries_sent: 0`;
- `subdomain_queries_sent: 0`;
- `zone_transfer_attempted: false`;
- `provider_import_attempted: false`;
- `job_created: false`;
- `storage_persisted: false`;
- `execution_enabled: false`;
- `manual_validation_required: true`;
- `result_interpretation: dns_configuration_review_indicator`.

## Contract

Accepted request fields are:

- `mode`: exactly `live_dns_inventory`;
- `profile`: exactly `dns_inventory_authorized`;
- `domain`: one explicit root domain;
- `record_types`: non-empty list from the allowlist;
- `include_security_records`: boolean;
- `include_subdomain_discovery`: boolean;
- `attempt_zone_transfer`: optional boolean, default `false`;
- `authorization_confirmed`: exactly `true`;
- `local_private_or_owned_scope_confirmed`: exactly `true`;
- `live_dns_queries_confirmed`: exactly `true`.

The initial record-type allowlist is:

- `A`;
- `AAAA`;
- `CNAME`;
- `MX`;
- `TXT`;
- `NS`;
- `SOA`;
- `CAA`.

`attempt_zone_transfer: true` is rejected in this phase with a controlled
not-supported error. It does not attempt AXFR.

## Domain Policy

The new backend helper `backend/app/active_dns_inventory.py` performs pure local
shape validation. It accepts only one explicit domain and rejects:

- empty values;
- multiple values;
- non-string values;
- IP literals;
- URL/path/query/fragment/userinfo-shaped values;
- wildcards;
- CIDR/range-like values;
- pasted lists;
- control characters;
- metadata/control-plane domains;
- overlong domains and labels;
- labels with unsupported characters or hyphen boundary issues.

The helper does not resolve names and does not import DNS or network libraries.

## Rejected Fields

The endpoint rejects unsupported or dangerous fields before any execution path
can exist, including:

- resolver overrides;
- nameserver overrides;
- provider credentials;
- API tokens;
- Certificate Transparency or passive-DNS source selectors;
- wordlists;
- AXFR server overrides;
- shell command fields;
- headers;
- cookies;
- tokens;
- credentials;
- target files.

Error responses use controlled wording and do not reflect raw domain values or
payload secrets.

## No-Scope Preserved

This phase preserves these boundaries:

- no DNS queries;
- no sockets;
- no subprocess;
- no Nmap;
- no Docker;
- no HTTP requests;
- no CT lookup;
- no passive DNS API lookup;
- no AXFR;
- no provider API;
- no runtime subdomain discovery;
- no brute force;
- no wildcard discovery;
- no jobs;
- no storage;
- no exports;
- no frontend runtime;
- no archive/run-all;
- no `tools/runner/main.py`;
- no complete-zone result;
- no vulnerability, exploitability, target-safety, or coverage-completeness
  claims.

## Validation Evidence

Executed validations:

- `git status --short --branch`;
- `python3 -m py_compile backend/app/config.py backend/app/main.py backend/app/active_dns_inventory.py`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_inventory`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_dns_inventory or active_tls_basic or active_nmap_basic"`;
- `.venv/bin/python -m pytest backend/tests`;
- `git diff --check`;
- `git diff --cached --check`;
- source and wording guardrail searches for DNS runtime, subprocess, Nmap,
  Docker, HTTP, frontend, archive/run-all, `tools/runner/main.py`, and
  prohibited claims.

Observed test results:

- focused `active_dns_inventory`: 55 passed;
- related Active backend tests: 207 passed;
- full backend suite: 629 passed.

## Final Decision

```text
ACTIVE_DNS_INVENTORY_02_BACKEND_CONTRACT_GATE_ACCEPTED
```

The backend contract gate exists, is disabled by default, validates the bounded
future `active_dns_inventory` contract, and returns only controlled
`not_executed` metadata. No DNS runtime, jobs, storage, frontend behavior, or
external traffic is added by this phase.
