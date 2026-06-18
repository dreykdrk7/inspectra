# Active DNS v0 Operational Guide

Decision: `ACTIVE_DNS_OPERATIONS_01_OPERATIONAL_GUIDE_ACCEPTED`

This guide documents operator use for the complete Active DNS v0 block. It is a
docs-only freeze document. It does not change runtime behavior, endpoint
contracts, feature flags, backend code, frontend code, tools code,
archive/run-all behavior, `tools/runner/main.py` behavior, Docker behavior,
Nmap behavior, DNS behavior, CT source behavior, release state, tag state, or
push state. No live request was performed while writing this guide.

## Included Capabilities

Active DNS v0 has two separate capabilities:

- `active_dns_inventory`: standard DNS inventory for one explicit authorized
  root domain.
- `active_dns_osint`: bounded CT-source OSINT for public-source observed names
  under one explicit authorized domain.

`active_dns_inventory` includes:

- allowlisted standard record review for `A`, `AAAA`, `CNAME`, `MX`, `TXT`,
  `NS`, `SOA`, and `CAA`;
- SPF, DMARC, and CAA configuration review indicators;
- bounded fixed-candidate subdomain discovery;
- optional authorized AXFR check when separately enabled and confirmed;
- owner-scoped `active_dns_inventory` jobs with redaction-first reports,
  exports, Raw JSON, and frontend rendering.

`active_dns_osint` includes:

- bounded Certificate Transparency source discovery through the accepted
  `crt.sh` source shape;
- retained observed-name counters and samples rendered as
  `[REDACTED_DNS_NAME]`;
- `osint_best_effort` coverage and public-source observed-name review
  indicators;
- owner-scoped `active_dns_osint` jobs with redaction-first reports, exports,
  Raw JSON, and frontend rendering.

## Feature Flags

Active DNS v0 remains disabled by default.

Inventory:

```text
INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=false
```

DNS OSINT:

```text
INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=false
INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED=false
INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_URL=https://crt.sh/
```

Enable these flags only in a trusted local, private, or self-hosted deployment
where the operator has explicit authorization for the submitted domain. The CT
source flag is separate from the DNS OSINT capability flag; both must be enabled
before the accepted `crt.sh` source can be used.

To disable Active DNS v0, set the inventory flag to `false`, set the OSINT flag
to `false`, or keep the CT source flag set to `false`.

## Operational Use

Use Active DNS only for one explicitly authorized domain at a time. The
operator must be able to confirm authorization, domain ownership or delegated
permission, and the requested live DNS or public-OSINT behavior before
submitting a job.

Use `active_dns_inventory` when the goal is DNS configuration review for the
authorized domain itself:

- standard record presence and bounded counts;
- SPF, DMARC, and CAA review indicators;
- fixed-candidate subdomain summaries;
- optional, separately confirmed AXFR review.

Use `active_dns_osint` when the goal is public-source observed-name review from
the accepted CT source:

- public-source names that appear to belong under the authorized domain;
- source status, retention, truncation, and rate-limit context;
- manual follow-up planning by the operator.

Do not treat OSINT observed names as automatic inventory input. The OSINT path
does not perform DNS queries for observed names and does not hand them to DNS
inventory, TLS, Nmap, archive/run-all, or `tools/runner/main.py`.

Use AXFR only when the operator has separate authorization to attempt a zone
transfer check. The inventory request must keep `attempt_zone_transfer: false`
unless that separate authorization is confirmed. When AXFR is selected, the
request must also send `zone_transfer_authorized_confirmed: true`.

The backend remains authoritative for feature gates, auth, owner scope, request
validation, domain policy, source selection, DNS and AXFR bounds, storage,
report/export shaping, and redaction.

## Safe Examples

The examples below use reserved placeholder domains only. They are request
shapes for operator education; this documentation phase did not execute them.

Inventory without AXFR:

```json
{
  "mode": "live_dns_inventory",
  "profile": "dns_inventory_authorized",
  "domain": "example.com",
  "record_types": ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"],
  "include_subdomains": true,
  "attempt_zone_transfer": false,
  "authorization_confirmed": true,
  "domain_control_confirmed": true,
  "live_dns_queries_confirmed": true
}
```

Inventory with separately confirmed AXFR:

```json
{
  "mode": "live_dns_inventory",
  "profile": "dns_inventory_authorized",
  "domain": "example.com",
  "record_types": ["NS", "SOA", "CAA", "TXT"],
  "include_subdomains": true,
  "attempt_zone_transfer": true,
  "zone_transfer_authorized_confirmed": true,
  "authorization_confirmed": true,
  "domain_control_confirmed": true,
  "live_dns_queries_confirmed": true
}
```

DNS OSINT through the accepted CT source:

```json
{
  "mode": "live_dns_osint",
  "profile": "ct_subdomain_discovery_bounded",
  "domain": "example.com",
  "include_certificate_transparency": true,
  "include_passive_dns": false,
  "max_names": 25,
  "authorization_confirmed": true,
  "domain_control_confirmed": true,
  "public_osint_confirmed": true
}
```

## Result Interpretation

Inventory coverage levels:

- `best_effort_inventory`: bounded inventory completed enough to provide
  review indicators, but it is not a complete-zone state.
- `partial_inventory`: bounded inventory produced controlled partial output or
  encountered a controlled refusal, timeout, malformed response, unavailable
  source, truncation, or similar limit.
- `zone_transfer_complete`: authorized AXFR was accepted by an authoritative
  server and passed terminal-SOA validation for the exact domain.

OSINT coverage:

- `osint_best_effort`: bounded public-source observed-name review. It requires
  manual validation and is not automatic inventory proof.

Common controlled states include refused, timed out, source unavailable, rate
limited, malformed, oversized, and truncated. These states should remain
operator review context, not system-error panic and not security conclusions.

Allowed wording is review-indicator wording only, for example:

- `DNS configuration review indicator`;
- `DNS OSINT review indicator`;
- `public-source observed names`;
- `zone transfer accepted by authoritative server`;
- `high-risk configuration review indicator`;
- `Manual validation required`.

## Redaction Boundary

Reports, exports, Raw JSON, list/detail responses, and frontend rendering must
preserve these boundaries:

- public domain display as `[REDACTED_DOMAIN]`;
- observed or retained names as `[REDACTED_DNS_NAME]`;
- bounded DNS values as redacted placeholders such as `[REDACTED_DNS_VALUE]`;
- no raw domain;
- no raw observed names;
- no raw CT payload;
- no certificate bodies;
- no raw source exceptions;
- no raw zone file, DNS packet, or resolver log;
- no provider credentials, API keys, account IDs, tokens, or secrets;
- wrong-owner reads, exports, deletes, and Raw JSON access as generic not found.

Redaction is intentional. A redacted report, Raw JSON view, or export is not a
rendering failure.

## Not Approved

Active DNS v0 does not approve:

- passive DNS;
- provider DNS/API import or privileged provider administration;
- search-engine scraping;
- crawling;
- broad wordlists;
- reverse-IP, ASN, or range discovery;
- automatic probing or scanning of observed names;
- DNS queries from `active_dns_osint`;
- browser-side CT or provider requests;
- Nmap expansion;
- Docker run/build/compose behavior;
- subprocess or shell execution;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- claims that discovery is complete or comprehensive;
- complete subdomain-set or DNS record-set assertions;
- vulnerability, exploitability, or target-safe conclusions;
- hosted or SaaS-style scanning product behavior.

Any future passive-DNS source, provider connector, broader discovery source,
runtime integration, or public deployment posture requires a separate
design/freeze/review path before implementation.

## Troubleshooting

- Feature disabled: confirm
  `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=true` for inventory or
  `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=true` for OSINT in the intended private
  deployment.
- Missing confirmations: resubmit only after the operator can truthfully
  confirm authorization, domain control/delegated permission, and the requested
  live-DNS or public-OSINT behavior.
- Unsupported domain shape: use one explicit domain such as `example.com`, not
  a URL, wildcard, range, pasted list, parent/sibling expansion, or source file.
- CT source disabled: set
  `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED=true` only when CT-source use is
  explicitly approved for the deployment.
- CT source URL rejected: use exactly
  `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_URL=https://crt.sh/`; alternate hosts,
  credentials, custom ports, paths, queries, and fragments fail closed.
- Timeout, rate limit, or source unavailable: treat the result as controlled
  public-source context and retry only when operationally appropriate.
- AXFR refused, malformed, partial, oversized, or timed out: treat it as a
  controlled DNS configuration review indicator. Only terminal-SOA-validated
  accepted AXFR can produce `zone_transfer_complete`.
- Raw JSON, report, or export hides names or values: this is the accepted
  redaction boundary for target-based DNS data.

## Final Decision

```text
ACTIVE_DNS_OPERATIONS_01_OPERATIONAL_GUIDE_ACCEPTED
```

Active DNS v0 now has operator guidance for local/private/self-hosted use. The
guide preserves disabled-by-default posture, one authorized domain, exact
inventory and OSINT contract boundaries, separate AXFR confirmation, CT-source
gating, redaction-first result surfaces, conservative review-indicator wording,
and manual validation.
