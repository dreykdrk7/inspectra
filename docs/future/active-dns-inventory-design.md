# Active DNS Inventory Design

Decision: `ACTIVE_DNS_INVENTORY_01_DESIGN_FROZEN`

This document freezes a docs-only design for a future
`active_dns_inventory` capability. It does not implement backend runtime,
frontend runtime, runner behavior, socket execution, DNS queries, `dig`,
`host`, `nslookup`, subprocess calls, Nmap behavior, Docker behavior, HTTP
requests, Certificate Transparency lookups, passive DNS API calls, AXFR
execution, archive/run-all integration, `tools/runner/main.py` integration,
release state, tag state, or push state.

Implementation status update: `active_dns_inventory` v0 was later implemented
and closed first as a bounded functional minimum in
`docs/future/active-dns-inventory-v0-functional-closeout.md` with decision
`ACTIVE_DNS_INVENTORY_06_FUNCTIONAL_REVIEW_AND_CLOSEOUT_ACCEPTED`. Authorized
AXFR was then added as a separate backend and frontend extension and closed in
`docs/future/active-dns-inventory-with-authorized-axfr-functional-closeout.md`
with decision
`ACTIVE_DNS_INVENTORY_11_FUNCTIONAL_CLOSEOUT_WITH_AXFR_ACCEPTED`. The accepted
expanded v0 direction is attacker-equivalent visibility: one domain,
allowlisted public-network DNS observation, optional authorized AXFR,
redaction-first reporting, and no privileged provider access in core Active
DNS. Certificate Transparency or passive DNS may be considered only as
separate public-OSINT phases; the first such design is
`docs/future/active-dns-osint-design.md` with decision
`ACTIVE_DNS_OSINT_01_DESIGN_FROZEN`. Provider DNS/API import is deprioritized
and out of core Active DNS; if it ever exists, it must be a separate admin
inventory connector rather than part of this attacker-equivalent path.
Complete-zone coverage in core Active DNS is limited to
`zone_transfer_complete` from authorized, bounded, terminal-SOA-validated AXFR.

## Objective

`active_dns_inventory` is intended to perform an authorized DNS inventory for
one explicit root domain. The capability should help a trusted operator review
the DNS surface that is published for a domain they own or are explicitly
authorized to assess:

- apex and base-domain DNS records;
- mail and security-related DNS records;
- authoritative nameserver metadata;
- bounded subdomain inventory from controlled sources;
- optional future zone-transfer checking only when specifically authorized;
- no provider-zone import in core Active DNS; privileged provider inventory, if
  ever needed, belongs in a separate admin inventory connector.

The capability must distinguish clearly between `zone_transfer_complete` from
authorized AXFR and best-effort inventory. Best-effort output must never be
presented as exhaustive coverage.

Results must be framed as DNS configuration review indicators requiring manual
validation. The capability must not claim vulnerability status,
exploitability, target safety, or complete coverage unless the result is
`zone_transfer_complete` from authorized, bounded, terminal-SOA-validated AXFR.

## Activation Model

Future implementation must be disabled by default and require explicit opt-in.
A suggested backend flag is:

```text
INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=false
```

Enabled mode must still require:

- authenticated/owner-scoped access when the deployment uses auth-required mode;
- explicit domain authorization confirmation;
- explicit local/private/owned scope confirmation;
- explicit live-DNS-query confirmation;
- backend domain policy acceptance before any network-capable path;
- short timeouts, rate limits, and bounded result limits;
- no integration with archive/run-all or the passive runner monolith.

Anonymous requests in auth-required deployments must be denied before validation
details are revealed.

## Future Contract Shape

Suggested future route:

```text
POST /active/network/dns-inventory
```

Suggested future request:

```json
{
  "mode": "live_dns_inventory",
  "profile": "dns_inventory_authorized",
  "domain": "example.com",
  "record_types": ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"],
  "include_security_records": true,
  "include_subdomain_discovery": true,
  "attempt_zone_transfer": false,
  "authorization_confirmed": true,
  "local_private_or_owned_scope_confirmed": true,
  "live_dns_queries_confirmed": true
}
```

Required future fields:

- `mode`: exactly `live_dns_inventory`;
- `profile`: exactly `dns_inventory_authorized`;
- `domain`: one explicit root domain only;
- `record_types`: list limited to the allowlisted record types for the active
  profile;
- `include_security_records`: boolean;
- `include_subdomain_discovery`: boolean;
- `attempt_zone_transfer`: default `false`;
- `authorization_confirmed`: exactly `true`;
- `local_private_or_owned_scope_confirmed`: exactly `true`;
- `live_dns_queries_confirmed`: exactly `true`.

If AXFR is implemented in a later phase, the request must also require:

- `zone_transfer_authorized_confirmed`: exactly `true`.

Persisted job identity, if implemented later:

- `audit_type: active_dns_inventory`;
- `file_id: null`;
- owner-scoped;
- target-based with public domain display redacted.

## Domain Policy

The domain policy must accept only one explicit root domain. It must reject:

- empty domains;
- multiple domains;
- URL-shaped input with scheme, path, query, fragment, or userinfo;
- CIDR blocks, dash ranges, wildcards, pasted lists, target files, and generated
  candidates;
- IP addresses when a domain is required;
- overly long values or values with control characters;
- metadata/control-plane names;
- arbitrary third-party domains without explicit authorization;
- parent-domain expansion and sibling-domain expansion.

The submitted domain is the authorization boundary. Future implementations must
not automatically turn discovered MX, NS, CNAME, SAN, CT, or passive-DNS names
into new scan targets outside that exact authorized domain.

## Coverage Model

Every result must include an explicit `coverage_level`. Allowed values:

- `zone_transfer_complete`;
- `best_effort_inventory`;
- `partial_inventory`;
- `failed_controlled`.

Complete-zone coverage in core Active DNS may be reported only when this source
succeeds:

- explicitly authorized AXFR against an authoritative nameserver for the exact
  domain.

Provider-zone import is no longer a core Active DNS complete-zone source. If it
is ever pursued, it must be a separate admin inventory connector and not an
attacker-equivalent Active DNS mode. A provider-specific connector may define
its own non-core coverage wording separately.

All other successful runtime modes must use `best_effort_inventory` or
`partial_inventory`, depending on errors and truncation.

## Phased Capability Plan

Future implementation should be split into small phases:

1. `standard_records`: query only the allowlisted apex/base-domain records and
   security-record locations.
2. `subdomain_discovery_bounded`: query a small controlled set of names and
   operator-provided candidates within the authorized domain.
3. `zone_transfer_check`: attempt AXFR only against authoritative nameservers
   for the exact domain and only with specific AXFR authorization.
4. `admin_inventory_connector`: if privileged provider import is ever needed,
   design it outside core Active DNS with credential handling,
   provider-specific redaction, and strict owner scope.

## Record Scope

Initial apex/base-domain record types:

- `A`;
- `AAAA`;
- `CNAME`;
- `MX`;
- `TXT`;
- `NS`;
- `SOA`;
- `CAA`.

Security and mail records:

- SPF via bounded TXT parsing on the root domain;
- DMARC at `_dmarc.<domain>`;
- DKIM only for selectors that are explicitly configured or operator-supplied;
- optional bounded MX target resolution only in a later design phase.

Additional future record types may be considered only when bounded and
justified:

- `SRV`;
- `TLSA`;
- `DS`;
- `DNSKEY`;
- `NAPTR`.

## Subdomain Discovery Boundaries

Subdomain discovery must be controlled, not open-ended enumeration. Initial
future candidates may include only a small fixed set such as:

- `www`;
- `mail`;
- `smtp`;
- `imap`;
- `pop`;
- `api`;
- `app`;
- `admin`;
- `portal`;
- `dev`;
- `staging`;
- `test`.

Additional sources require separate design or explicit operator input:

- operator-provided names;
- names discovered from already-consulted CNAME, MX, or NS records, retained
  only as bounded context unless still inside the authorized domain;
- Certificate Transparency or passive-DNS sources only through the separate
  `active_dns_osint` path with concrete source limits and rate limits;
- a minimal fixed wordlist only in a separate phase with a low cap;
- provider-zone import only as a separate future admin inventory connector,
  not as part of core Active DNS attacker-equivalent coverage.

The v0 design rejects broad wordlists, wildcard discovery runtime, DKIM selector
guessing, sibling-domain expansion, and recursive discovery loops.

## AXFR / Zone Transfer

AXFR was reserved as a future separate phase in the original design and is now
accepted only for the specifically confirmed Active DNS Inventory path
documented in
`docs/future/active-dns-inventory-with-authorized-axfr-functional-closeout.md`.
It must remain:

- disabled by default;
- attempted only against authoritative nameservers for the exact domain;
- attempted only when `zone_transfer_authorized_confirmed` is true;
- requested from the frontend only when the optional AXFR control is enabled
  and the specific AXFR confirmation is checked;
- bounded by timeout, response-size, and record-count limits;
- owner-scoped and redaction-first before storage or rendering.

If AXFR is refused or unavailable, the result uses controlled states such as
`unavailable`, `timed_out`, or `refused`. If bounded authorized AXFR succeeds,
the backend may set `zone_transfer_complete` only after terminal-SOA
validation for the exact domain. The report may say "zone transfer accepted by
authoritative server / high-risk configuration review indicator" and must
treat the returned zone as sensitive operator data, not as an exploit result.

## Provider Zone Import

Provider DNS/API import is out of core Active DNS because it uses
administrator-level provider privileges rather than attacker-equivalent public
or network observation. It is not the recommended next path from the
authorized-AXFR closeout.

If provider import is ever implemented, it must be designed as a separate admin
inventory connector with its own product surface, credential boundary, owner
scope, redaction, tests, and review. It must not be presented as part of core
Active DNS or as public-network OSINT coverage.

The provider phase must define:

- supported providers and exact API scopes;
- credential storage and redaction rules;
- token lifecycle and deletion behavior;
- provider rate limits and pagination limits;
- owner scope for imported zones;
- provider-error normalization;
- reporting language that distinguishes imported authoritative inventory from
  best-effort DNS observation.

No provider credentials or API integration are added by this design.

## Timeouts And Limits

Suggested future defaults:

- target domain count: 1;
- standard record type count: allowlisted set only;
- DNS query timeout: 2 seconds per query;
- total deadline: 15 seconds for standard records;
- total deadline: 30 seconds when bounded subdomain discovery is enabled;
- subdomain candidate cap: 25 for the first implementation;
- retained subdomain sample cap: 25;
- retained record cap per type: 50;
- total retained record cap: 250;
- TXT value length cap before storage/rendering;
- resolver error strings: controlled reason codes only.

Timeouts and partial failures must fail closed into controlled states without
leaking raw domain names or resolver payloads.

## Allowed Result Shape

Future stored result should be allowlisted and bounded. Suggested fields:

```json
{
  "audit_type": "active_dns_inventory",
  "capability": "active_dns_inventory",
  "status": "completed",
  "result_status": "best_effort_inventory",
  "domain": "[REDACTED_DOMAIN]",
  "coverage_level": "best_effort_inventory",
  "records": {
    "A": [{"name": "[REDACTED_NAME]", "value": "[REDACTED_VALUE]", "ttl": 300}],
    "AAAA": [],
    "CNAME": [],
    "MX": [],
    "TXT": [],
    "NS": [],
    "SOA": [],
    "CAA": []
  },
  "subdomains": {
    "count": 0,
    "sample": []
  },
  "security_records": {
    "spf_present": null,
    "dmarc_present": null,
    "caa_present": null
  },
  "zone_transfer": {
    "attempted": false,
    "status": "not_attempted"
  },
  "manual_validation_required": true,
  "result_interpretation": "dns_configuration_review_indicator"
}
```

Allowed future observations:

- record type;
- bounded record name placeholder or redacted display name;
- bounded record value placeholder or redacted display value;
- TTL;
- security-record booleans or controlled null values;
- subdomain count and bounded/redacted sample;
- coverage level;
- zone-transfer attempted flag and controlled status;
- provider-import status if a later provider phase is accepted;
- manual validation marker;
- review-indicator wording.

The result must not include provider credentials, raw resolver logs, complete
raw DNS message payloads, raw domain values in public surfaces, credentials,
headers, cookies, tokens, command lines, stdout/stderr, packet captures,
unbounded TXT values, or unbounded internal IP/name material.

## Redaction And Public Surfaces

Public API responses, job detail, job list summaries, Raw JSON views, reports,
and future exports must be redaction-first:

- domain shown only as `[REDACTED_DOMAIN]` or equivalent;
- record names and values redacted or bounded before storage/rendering;
- TTLs and record types may be preserved;
- SPF/DMARC/CAA indicators may be preserved as booleans or controlled states;
- provider credentials, tokens, account ids, zone ids, and API error payloads
  must not appear in public surfaces;
- resolver errors must use controlled reason codes;
- wrong-owner access remains generic not-found behavior.

Report wording should use phrases such as:

- "DNS configuration review indicator";
- "best-effort DNS inventory";
- "complete-zone source: authorized AXFR";
- "provider import requires a separate admin inventory connector";
- "manual validation required".

Reports must not present best-effort results as complete coverage or present
DNS observations as proof of compromise, exploitability, or target safety.

## UX Expectations

Future UI should be separate from Passive scans, Active / Nmap basic, and
Active / TLS basic. Expected controls:

- domain input for one explicit root domain;
- fixed profile display for `dns_inventory_authorized`;
- record-type display constrained to the backend allowlist;
- `include_security_records` toggle;
- `include_subdomain_discovery` toggle with visible candidate/result limits;
- authorization confirmation;
- owned-or-authorized domain confirmation;
- live-DNS-query confirmation;
- AXFR authorization confirmation only when that phase exists;
- disabled-state copy when the feature flag is off.

Expected result display:

- coverage level;
- grouped records by type;
- subdomain count and bounded sample;
- SPF, DMARC, and CAA review indicators;
- zone-transfer status if applicable;
- provider-import status only if a separate admin inventory connector ever
  exists;
- manual validation note;
- redacted Raw JSON.

The UI must not expose controls for broad wordlists, custom resolver payloads,
target files, wildcard expansion, CT/passive-DNS source selection, provider
tokens, raw DNS packets, shell commands, Nmap, crawling, credential validation,
or archive/run-all.

## Abuse Threats

Primary abuse risks:

- turning the feature into mass subdomain enumeration;
- using it against arbitrary third-party domains;
- attempting AXFR against domains without specific authorization;
- treating best-effort inventory as complete coverage;
- leaking internal infrastructure names or addresses in reports;
- expanding targets from CT or passive DNS without authorization;
- guessing DKIM selectors;
- importing provider zones without safe credential boundaries;
- routing execution through shell commands;
- merging Active DNS inventory into passive archive workflows.

Required mitigations:

- disabled-by-default feature gate;
- explicit confirmations;
- one-domain policy;
- query limits and total deadlines;
- rate limits;
- allowlisted record types;
- bounded subdomain candidates and retained results;
- no broad wordlists;
- no AXFR without specific confirmation;
- no provider API in core Active DNS; provider import requires a separate admin
  inventory connector;
- owner-scoped jobs;
- generic wrong-owner responses;
- redaction before storage and rendering;
- explicit `coverage_level`;
- manual validation marker;
- no archive/run-all integration.

## Future Tests

Future implementation should include tests for:

- disabled flag rejects without DNS queries;
- auth-required anonymous fails before validation details;
- exact request contract validation;
- invalid domain, URL, range, list, and wildcard rejection;
- record type outside the allowlist rejection;
- missing or false confirmations;
- best-effort inventory with a fake resolver;
- AXFR disabled by default;
- AXFR requires specific confirmation;
- AXFR refused maps to a controlled state;
- complete-zone coverage in core Active DNS only when fake AXFR returns an
  accepted, terminal-SOA-validated complete-zone payload;
- bounded subdomain discovery with fixtures;
- no raw domain, records, provider secrets, resolver payloads, or sensitive
  values in detail, list, Raw JSON, or exports;
- owner scope and generic wrong-owner behavior;
- no archive/run-all integration;
- no `tools/runner/main.py` integration;
- no subprocess, `dig`, `host`, `nslookup`, Nmap, Docker, HTTP, CT, or passive
  DNS runtime in the baseline phase.

Tests for this design phase are documentation checks only.

## Acceptance Criteria For Future Implementation

A future implementation can be considered for acceptance only when:

- it remains disabled by default and opt-in;
- it accepts exactly one authorized domain;
- it uses only allowlisted record types and bounded query plans;
- it keeps subdomain discovery bounded and source-limited;
- it reports `coverage_level` explicitly;
- it labels best-effort and partial results without complete-coverage language;
- it treats AXFR as the only core Active DNS complete-zone source and keeps
  provider import out of core unless separately designed as an admin connector;
- it stores only allowlisted, redacted, bounded result fields;
- it keeps backend authority over auth, owner scope, validation, storage,
  reporting, and redaction;
- it keeps Passive archive flows separate;
- it does not use shell commands, Nmap, Docker runtime, crawling, credential
  validation, broad enumeration, provider APIs inside core Active DNS, or
  archive/run-all;
- backend, frontend, report, Raw JSON, owner-scope, and source-boundary tests
  pass;
- docs continue to frame output as DNS review indicators requiring manual
  validation.

## Final Decision

```text
ACTIVE_DNS_INVENTORY_01_DESIGN_FROZEN
```

The `active_dns_inventory` capability is designed as a future bounded, opt-in,
owner-scoped DNS inventory review indicator for one explicit authorized domain.
No runtime implementation is added by this phase.
