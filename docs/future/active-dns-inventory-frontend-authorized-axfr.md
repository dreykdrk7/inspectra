# Active DNS Inventory Frontend Authorized AXFR

Decision: `ACTIVE_DNS_INVENTORY_09_FRONTEND_AUTHORIZED_AXFR_PASSED`

This microphase connects the existing `Active / DNS inventory` frontend flow to
the already implemented authorized AXFR backend submodule. It adds product UI
for explicitly requesting AXFR, keeps AXFR disabled by default, requires a
separate authorization confirmation, and renders AXFR states as controlled DNS
configuration review indicators.

No real AXFR, DNS lookup, provider API, Certificate Transparency lookup,
passive DNS lookup, Docker runtime, Nmap, HTTP crawling, DNS CLI command,
subprocess, archive/run-all, `tools/runner/main.py`, release, tag, or push
behavior is added by this phase.

## Scope

The frontend now supports:

- `attempt_zone_transfer: false` by default;
- optional `attempt_zone_transfer: true` only when the operator selects the AXFR
  checkbox;
- `zone_transfer_authorized_confirmed: true` only when AXFR is selected and the
  separate AXFR confirmation is checked;
- clear copy that AXFR is high impact and should be used only for domains owned
  by or explicitly authorized for the operator;
- copy that AXFR asks authoritative nameservers for the exact zone;
- copy that AXFR is not provider import;
- copy that refused, timed-out, malformed, unavailable, or failed AXFR does not
  guarantee coverage;
- report rendering for AXFR status, nameserver counters, record counters, and
  truncation state;
- redacted Raw JSON for AXFR-related payloads, nameservers, DNS names, DNS
  values, raw zone material, DNS packets, resolver logs, provider secrets, and
  credentials.

## Contract

The default request body remains bounded:

```json
{
  "mode": "live_dns_inventory",
  "profile": "dns_inventory_authorized",
  "domain": "example.internal",
  "record_types": ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"],
  "include_security_records": true,
  "include_subdomain_discovery": true,
  "attempt_zone_transfer": false,
  "authorization_confirmed": true,
  "local_private_or_owned_scope_confirmed": true,
  "live_dns_queries_confirmed": true
}
```

When AXFR is explicitly enabled and confirmed, the frontend may send:

```json
{
  "attempt_zone_transfer": true,
  "zone_transfer_authorized_confirmed": true
}
```

The frontend must not send `zone_transfer_authorized_confirmed: true` when AXFR
is not selected.

## Rendered States

The UI recognizes these AXFR statuses:

- `not_attempted`;
- `authorization_required`;
- `no_authoritative_nameservers`;
- `refused`;
- `unavailable`;
- `timed_out`;
- `malformed_response`;
- `record_limit_exceeded`;
- `zone_transfer_complete`.

`zone_transfer_complete` is rendered only as:

- `zone transfer accepted by authoritative server`;
- `high-risk configuration review indicator`;
- `Manual validation required`.

All other AXFR outcomes remain controlled best-effort or partial inventory
states and must not be presented as complete coverage.

## Redaction

Frontend report and Raw JSON surfaces keep:

- domain display as `[REDACTED_DOMAIN]`;
- DNS names as `[REDACTED_DNS_NAME]`;
- DNS values as `[REDACTED_DNS_VALUE]`;
- raw zone material omitted or redacted;
- raw DNS packets and resolver logs omitted or redacted;
- provider IDs, provider tokens, credentials, headers, cookies, and tokens
  omitted or redacted.

The UI does not show raw domain, raw nameserver, raw zone file, raw record
values, provider secrets, or raw DNS packets.

## No-Scope

This phase does not add:

- real AXFR execution;
- new DNS runtime or DNS lookups;
- provider DNS/API import;
- Certificate Transparency or passive DNS lookup;
- frontend DNS resolver behavior;
- DNS CLI commands such as `dig`, `host`, or `nslookup`;
- subprocess execution;
- Nmap;
- Docker or Compose runtime;
- HTTP crawling;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- public scanner behavior;
- all-records-found claims;
- vulnerability, exploitability, or target-safety claims.

## Tests And Validation

Frontend tests cover:

- default request sends `attempt_zone_transfer: false` and no AXFR-specific
  confirmation;
- AXFR checkbox alone keeps submit blocked;
- AXFR checkbox plus specific confirmation sends both `attempt_zone_transfer:
  true` and `zone_transfer_authorized_confirmed: true`;
- `zone_transfer_complete` renders as high-risk review indicator, not as an
  exploitability claim;
- refused, timed-out, malformed, and record-limit states render as controlled
  states;
- Raw JSON stays redaction-first.

The backend AXFR behavior remains covered by the existing focused backend DNS
tests from the previous phases. This phase adds no backend runtime changes.

## Acceptance

The product flow is accepted when:

- AXFR is off by default;
- AXFR requires a separate explicit confirmation;
- the request contract matches the backend contract;
- AXFR status/counters are visible without raw domain or raw zone leakage;
- `zone_transfer_complete` is worded only as a high-risk DNS configuration
  review indicator;
- failed/refused/unavailable AXFR stays best-effort or partial;
- frontend focused tests, backend focused DNS tests, full frontend tests,
  frontend build, diff checks, and guardrail searches pass.

`ACTIVE_DNS_INVENTORY_09_FRONTEND_AUTHORIZED_AXFR_PASSED`
