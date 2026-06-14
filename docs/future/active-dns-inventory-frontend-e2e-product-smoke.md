# Active DNS Inventory Frontend And Product Smoke

Decision: `ACTIVE_DNS_INVENTORY_05_FRONTEND_AND_E2E_PRODUCT_SMOKE_PASSED`

This microphase connects the frontend to the existing real-minimal backend
`active_dns_inventory` contract and validates the product flow with mocked,
controlled frontend tests and existing backend fake-resolver coverage. It adds
no new DNS runtime, no frontend-side resolver behavior, and no live DNS target
execution.

## Scope

Implemented frontend behavior:

- a separate `Active / DNS inventory` panel;
- exact `POST /active/network/dns-inventory` request body;
- allowlisted record-type selection for `A`, `AAAA`, `CNAME`, `MX`, `TXT`,
  `NS`, `SOA`, and `CAA`;
- `include_security_records` and `include_subdomain_discovery` controls;
- `attempt_zone_transfer: false` forced by the UI;
- three required confirmations for authorization, local/private/owned scope,
  and live DNS queries;
- `202 JobRecord` handling, job selection, and jobs refresh through the
  existing dashboard pattern;
- a dedicated `ActiveDnsInventoryJobReport` renderer;
- grouped DNS records, SPF/DMARC/CAA review indicators, bounded subdomain
  summary, zone-transfer/provider-import not-attempted states, caveats, limits,
  controlled errors, and redacted Raw JSON.

## Contract

The frontend sends only this bounded contract:

```json
{
  "mode": "live_dns_inventory",
  "profile": "dns_inventory_authorized",
  "domain": "operator-provided-domain",
  "record_types": ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"],
  "include_security_records": true,
  "include_subdomain_discovery": true,
  "attempt_zone_transfer": false,
  "authorization_confirmed": true,
  "local_private_or_owned_scope_confirmed": true,
  "live_dns_queries_confirmed": true
}
```

The UI does not expose provider credentials, resolver overrides, target files,
AXFR controls, CT/passive DNS controls, headers, cookies, tokens, credentials,
subprocess controls, or DNS CLI inputs.

## Rendering Boundary

Frontend rendering treats the job as a DNS configuration review indicator:

- domain display is `[REDACTED_DOMAIN]`;
- DNS names are `[REDACTED_DNS_NAME]`;
- DNS values are `[REDACTED_DNS_VALUE]`;
- Raw JSON is defensively redacted again in the browser;
- `best_effort_inventory` and `partial_inventory` remain distinct from any
  complete-zone state;
- zone transfer and provider import are rendered as `not_attempted`;
- manual validation is required.

The UI does not claim all records were found, a vulnerability was confirmed,
the target is safe, exploitability is present, or that Inspectra is a public
scanner.

## Validation

Validation for this microphase covers:

- focused frontend panel tests;
- focused frontend report tests;
- frontend App product-flow smoke with mocked backend responses;
- dashboard filter/catalog tests;
- backend `active_dns_inventory` fake-resolver tests;
- full backend suite when practical;
- full frontend suite;
- frontend build;
- whitespace checks;
- guardrail source searches for DNS runtime expansion, AXFR/provider/CT/passive
  DNS, subprocess/DNS CLI, Nmap, Docker, HTTP, archive/run-all,
  `tools/runner/main.py`, raw-domain/value leakage, provider secrets, and
  complete-coverage wording drift.

## Decision

`ACTIVE_DNS_INVENTORY_05_FRONTEND_AND_E2E_PRODUCT_SMOKE_PASSED`
