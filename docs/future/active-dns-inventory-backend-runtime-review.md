# Active DNS Inventory Backend Runtime Review

Decision: `ACTIVE_DNS_INVENTORY_04_BACKEND_RUNTIME_REVIEW_PASSED`

This microphase reviews commit `d1ad2d9 feat(active): persist dns inventory
standard records` and the current tree after a minimal hardening fix. The review
covers the 10 files changed by Microphase 03 and confirms that
`active_dns_inventory` remains a bounded, opt-in, owner-scoped, redaction-first
backend capability.

## Reviewed Commit

Reviewed:

- `d1ad2d9 feat(active): persist dns inventory standard records`
- 10 files changed;
- approximately `+1441/-55`.

Files reviewed:

- `README.md`;
- `backend/app/active_dns_inventory.py`;
- `backend/app/main.py`;
- `backend/app/models.py`;
- `backend/app/reporting.py`;
- `backend/app/storage.py`;
- `backend/tests/test_backend.py`;
- `docs/architecture.md`;
- `docs/future/active-dns-inventory-standard-records-bounded-discovery.md`;
- `docs/security-scope.md`.

## Review Findings

No release-blocking issue remains.

One boundary hardening was applied during review:

- The resolver previously allowed up to two configured nameservers per logical
  DNS query. The public `dns_queries_sent` counter represents the logical query
  plan, so fallback to a second nameserver could make actual UDP sends higher
  than that public count. The review hardened
  `ACTIVE_DNS_INVENTORY_MAX_NAMESERVERS` to `1`, keeping query accounting and
  actual network send caps aligned.
- Public limit metadata now uses `domain_value_persisted: false` instead of a
  public `raw_domain_*` key, avoiding raw-domain wording drift on API/report
  surfaces while preserving the same redaction guarantee.

## Backend Route

Confirmed:

- `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=false` remains the default;
- disabled mode rejects without creating jobs or calling the resolver;
- auth/owner resolution happens before validation details;
- invalid requests do not call the resolver and do not create jobs;
- `attempt_zone_transfer=true` is rejected in request validation;
- valid enabled requests create owner-scoped `JobRecord`s;
- jobs use `audit_type: active_dns_inventory` and `file_id: null`;
- wrong-owner detail, delete, and export paths return generic not found.

## DNS Runtime Boundary

Confirmed:

- DNS runtime is isolated to `backend/app/active_dns_inventory.py`;
- the route delegates to `run_active_dns_inventory(...)` only after gate,
  ownership, contract validation, and policy acceptance;
- no backend subprocess path is used;
- no `dig`, `host`, or `nslookup` command is used;
- no Nmap path is used;
- no Docker path is used;
- no HTTP client path is used;
- no Certificate Transparency, passive DNS, or provider API path exists;
- no AXFR path exists;
- timeout is bounded;
- nameserver fanout is capped to one resolver endpoint per query;
- maximum logical query count for the accepted full profile is bounded by the
  fixed root/security/subdomain plan.

## Record Scope

Confirmed allowed root record types are only:

```text
A AAAA CNAME MX TXT NS SOA CAA
```

Confirmed security indicators:

- SPF is derived from root TXT;
- DMARC is derived from `_dmarc.<domain>` TXT;
- CAA is derived from root CAA;
- DKIM selector checks are explicitly not attempted;
- MX targets are not recursively resolved beyond requested record data.

## Subdomain Discovery

Confirmed fixed candidate list:

```text
www mail smtp imap pop api app admin portal dev staging test
```

Confirmed per-candidate record types:

```text
A AAAA CNAME
```

The implementation does not perform recursive discovery, broad wordlists,
wildcard expansion, sibling expansion, parent expansion, target-file expansion,
or raw candidate-name persistence in public surfaces.

## Storage, Reporting, And Redaction

Confirmed public surfaces preserve only bounded/redacted data:

- `[REDACTED_DOMAIN]`;
- `[REDACTED_DNS_NAME]`;
- `[REDACTED_DNS_VALUE]`;
- record type, TTL, priority, counts, and truncation flags;
- SPF/DMARC/CAA presence indicators;
- bounded subdomain counts and redacted samples;
- controlled error codes;
- report caveats and manual validation wording.

Confirmed public surfaces do not expose raw resolver logs, raw DNS packets,
command lines, stdout/stderr, provider secrets, provider account IDs, provider
zone IDs, credentials, headers, cookies, or tokens.

## Wording Boundary

Confirmed reporting uses DNS review-indicator wording and does not present
best-effort inventory as complete-zone coverage.

Approved wording:

- `DNS configuration review indicator`;
- `best-effort DNS inventory`;
- `partial inventory`;
- `Manual validation required`.

Not approved:

- complete-zone result for this phase;
- all-records-found claims;
- vulnerability claims;
- exploitability claims;
- target-safety claims.

`zone_transfer_complete` and `provider_import_complete` remain future-only
states for separately authorized AXFR or provider-import phases.

## Validation

Validation run:

- `git status --short --branch`;
- `git show --stat --oneline d1ad2d9`;
- `git show --name-only --oneline d1ad2d9`;
- `python3 -m py_compile backend/app/active_dns_inventory.py backend/app/main.py backend/app/storage.py backend/app/reporting.py backend/app/models.py`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_inventory`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_dns_inventory or active_tls_basic or active_nmap_basic"`;
- `.venv/bin/python -m pytest backend/tests`;
- `git diff --check`;
- `git diff --cached --check`;
- guardrail searches for subprocess/DNS CLI/Nmap/Docker/HTTP/CT/passive DNS/provider API/AXFR/archive-run-all/`tools/runner/main.py` and complete-coverage wording drift.

## Decision

`ACTIVE_DNS_INVENTORY_04_BACKEND_RUNTIME_REVIEW_PASSED`
