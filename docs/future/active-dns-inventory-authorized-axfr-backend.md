# Active DNS Inventory Authorized AXFR Backend

Decision: `ACTIVE_DNS_INVENTORY_07_AUTHORIZED_AXFR_BACKEND_PASSED`

This microphase adds an authorized AXFR backend submodule to
`active_dns_inventory`. The feature remains disabled by default through
`INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=false`, stays backend-only, and does not
add frontend controls, provider DNS import, Certificate Transparency, passive
DNS, HTTP, Nmap, Docker, archive/run-all, or `tools/runner/main.py`
integration.

## Approved Scope

`POST /active/network/dns-inventory` may now accept:

```json
{
  "mode": "live_dns_inventory",
  "profile": "dns_inventory_authorized",
  "domain": "example.com",
  "record_types": ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"],
  "include_security_records": true,
  "include_subdomain_discovery": true,
  "attempt_zone_transfer": true,
  "zone_transfer_authorized_confirmed": true,
  "authorization_confirmed": true,
  "local_private_or_owned_scope_confirmed": true,
  "live_dns_queries_confirmed": true
}
```

AXFR is attempted only after:

- the backend feature flag is enabled;
- authentication/owner scope has been resolved;
- the normal DNS inventory contract and domain policy pass;
- `attempt_zone_transfer` is exactly `true`;
- `zone_transfer_authorized_confirmed` is exactly `true`;
- authoritative NS records have been resolved for the exact requested domain.

The runtime attempts zone transfer only against the bounded authoritative
nameserver set derived from the exact requested domain. It does not accept
nameserver overrides, domain expansion, parent or sibling domains, CNAME/MX
targets, broad wordlists, recursive discovery, or brute-force NS discovery.

## Runtime Boundary

AXFR runtime is isolated in `backend/app/active_dns_inventory.py`. It uses the
same structured DNS packet parser style as the existing DNS inventory module and
does not invoke `dig`, `host`, `nslookup`, shell commands, subprocesses, Nmap, or
Docker. Tests use fake resolver and fake AXFR transport objects; the validation
for this phase does not execute real DNS probes.

The route injects the optional AXFR transport from app state for tests. In normal
runtime, the transport is constructed inside the DNS inventory module only after
the route has accepted the feature gate, contract, domain policy, and
confirmations. The internal helper also fails closed with
`authorization_required` if a direct internal caller asks for AXFR without the
specific confirmation.

## Limits

The authorized AXFR path is bounded by:

- short per-NS timeout;
- maximum authoritative nameservers attempted, currently one;
- maximum retained records;
- maximum response bytes;
- standard record type allowlist only: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`,
  `SOA`, `CAA`;
- public sample limits per record type;
- no raw DNS messages, resolver logs, raw zone files, or command output.

If limits are exceeded or parsing becomes unsafe, the result becomes controlled
`partial_inventory` with `zone_transfer.status: record_limit_exceeded` or a
related controlled status.

## Result States

The public `zone_transfer` object may expose only bounded counters and controlled
state:

- `attempted`;
- `status`;
- `nameservers_considered`;
- `nameservers_attempted`;
- `records_received_count`;
- `records_retained_count`;
- `truncated`;
- `reason_code` for non-complete states;
- `interpretation` for accepted AXFR.

Allowed AXFR statuses are:

- `not_attempted`;
- `authorization_required`;
- `no_authoritative_nameservers`;
- `refused`;
- `unavailable`;
- `timed_out`;
- `malformed_response`;
- `record_limit_exceeded`;
- `zone_transfer_complete`.

If bounded AXFR succeeds, the job may use:

- `coverage_level: zone_transfer_complete`;
- `result_status: zone_transfer_complete`;
- interpretation: `zone transfer accepted by authoritative server / high-risk configuration review indicator`.

If AXFR is refused, unavailable, timed out, malformed, or exceeds limits, the job
stays controlled as `best_effort_inventory` or `partial_inventory`. Those states
remain review indicators and are not system failures.

## Storage And Reporting

Jobs remain owner-scoped with `audit_type: active_dns_inventory` and
`file_id: null`. Public surfaces continue to store and render:

- `[REDACTED_DOMAIN]`;
- `[REDACTED_DNS_NAME]`;
- `[REDACTED_DNS_VALUE]`;
- bounded counts/samples;
- manual validation required;
- DNS configuration review indicator wording.

The backend does not persist raw domains, raw nameserver hostnames, raw record
values, raw DNS packets, raw resolver logs, raw zone files, provider account
data, provider credentials, or tokens. Wrong-owner job access remains generic
not found.

## Not Approved

This phase does not approve:

- public scanner behavior;
- arbitrary or third-party zone transfer attempts;
- provider DNS/API import;
- Certificate Transparency or passive DNS lookups;
- broad subdomain enumeration;
- recursive discovery;
- wildcard expansion;
- DKIM selector guessing;
- parent, sibling, CNAME, MX, or resolver-derived domain expansion;
- custom resolver or nameserver override from user input;
- DNS CLI usage;
- subprocess execution;
- Nmap;
- Docker runtime behavior;
- HTTP/crawling;
- archive/run-all;
- `tools/runner/main.py`;
- complete-zone wording except the explicit `zone_transfer_complete` state after
  bounded authorized AXFR acceptance;
- vulnerability, exploitability, target-safety, public-scanner, or all-records
  found claims.

## Tests And Validation

Coverage added in `backend/tests/test_backend.py` confirms:

- disabled feature flag rejects without resolver or AXFR transport calls;
- AXFR request without `zone_transfer_authorized_confirmed` rejects before
  resolver or AXFR calls;
- the internal helper fails closed with `authorization_required` without AXFR
  transport calls if confirmation is missing;
- no authoritative NS becomes a controlled state;
- refused AXFR is controlled and redacted;
- timeout is controlled and partial;
- fake successful AXFR yields `zone_transfer_complete`;
- oversized fake AXFR is truncated and partial;
- detail, list, Raw JSON-style job output, and exports remain redaction-first.

Validation commands for this phase:

- `python3 -m py_compile backend/app/active_dns_inventory.py backend/app/main.py backend/app/storage.py backend/app/reporting.py backend/app/models.py`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_inventory`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_dns_inventory or active_tls_basic or active_nmap_basic"`;
- `.venv/bin/python -m pytest backend/tests`;
- `git diff --check`;
- `git diff --cached --check`;
- guardrail searches for DNS CLI/subprocess/Nmap/Docker/HTTP/provider/CT/passive
  DNS/archive-run-all/tools-runner usage and complete-coverage wording drift.
