# Active DNS OSINT Design

Decision: `ACTIVE_DNS_OSINT_01_DESIGN_FROZEN`

Implementation status: the backend contract gate is accepted in
`docs/future/active-dns-osint-backend-contract-gate.md` with decision
`ACTIVE_DNS_OSINT_02_BACKEND_CONTRACT_GATE_ACCEPTED`. The first backend
persistence step is accepted in
`docs/future/active-dns-osint-ct-bounded-backend-job-persistence.md` with
decision
`ACTIVE_DNS_OSINT_03_CT_BOUNDED_BACKEND_JOB_PERSISTENCE_PASSED`. The backend
can now create owner-scoped redacted `active_dns_osint` jobs from an injectable
fakeable CT source adapter, but it still performs no real CT, passive DNS,
HTTP, DNS, provider, crawling, scraping, frontend, archive/run-all, or runner
behavior.

This document freezes a docs-only design for a future `active_dns_osint`
capability. It does not implement backend runtime, frontend runtime, runner
behavior, Certificate Transparency queries, passive DNS API calls, HTTP
requests, DNS queries, provider DNS/API import, credential handling, crawling,
scraping, subprocess calls, Nmap behavior, Docker behavior, archive/run-all
integration, `tools/runner/main.py` integration, release state, tag state, or
push state.

## Product Direction

`active_dns_osint` extends the Active DNS line with attacker-equivalent public
source visibility. It complements:

- `active_dns_inventory` standard records;
- bounded in-domain subdomain discovery;
- specifically authorized AXFR.

The capability should help a trusted operator review names and subdomains that
are observable in public OSINT sources, while avoiding mass enumeration,
aggressive scraping, crawling, public scanner behavior, and privileged
administrative inventory.

Provider DNS/API import remains out of core Active DNS. If provider import is
ever needed, it belongs in a separate admin inventory connector with its own
credential boundary, owner scope, redaction, tests, and review.

## Capability Shape

`active_dns_osint` should be a separate capability, not a submodule folded into
`active_dns_inventory` v0.

Reasons:

- public OSINT sources have different source policies, rate limits, ToS, and
  failure modes than live DNS record queries;
- passive DNS sources may require API keys or paid quota in a later phase;
- OSINT results are not complete-zone coverage and must never alter
  `active_dns_inventory` `zone_transfer_complete` semantics;
- a separate audit type keeps storage, reports, Raw JSON, and UX copy clearly
  scoped.

Future UI may cross-link DNS inventory and DNS OSINT jobs for the same redacted
domain, but the runtime contract and result should remain separate unless a
later design freezes a safe combined workflow.

Suggested identity:

- `audit_type: active_dns_osint`;
- `capability: active_dns_osint`;
- owner-scoped;
- `file_id: null`;
- domain display as `[REDACTED_DOMAIN]`;
- `coverage_level: osint_best_effort`.

## Activation Model

Future implementation must be disabled by default and require explicit opt-in.
A suggested backend flag is:

```text
INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=false
```

Enabled mode must still require:

- authenticated/owner-scoped access when the deployment uses auth-required mode;
- explicit authorization confirmation for the submitted domain;
- explicit owned-or-authorized domain confirmation;
- explicit public-OSINT-query confirmation;
- source-specific policy acceptance before any network-capable path;
- short timeouts, rate limits, source caps, and retained-name caps;
- no archive/run-all integration.

Anonymous requests in auth-required deployments must be denied before validation
details are revealed.

## Future Contract

Suggested future route:

```text
POST /active/network/dns-osint
```

Suggested first request shape:

```json
{
  "mode": "live_dns_osint",
  "profile": "ct_subdomain_discovery_bounded",
  "domain": "example.com",
  "include_certificate_transparency": true,
  "include_passive_dns": false,
  "max_names": 100,
  "authorization_confirmed": true,
  "owned_or_authorized_domain_confirmed": true,
  "public_osint_queries_confirmed": true
}
```

Required fields:

- `mode`: exactly `live_dns_osint`;
- `profile`: exactly `ct_subdomain_discovery_bounded` for the first phase;
- `domain`: one explicit authorized root domain only;
- `include_certificate_transparency`: boolean, initially the only enabled
  source flag;
- `include_passive_dns`: boolean, accepted only as `false` until a later
  passive-DNS phase freezes provider/source details;
- `max_names`: bounded integer, capped by backend policy;
- `authorization_confirmed`: exactly `true`;
- `owned_or_authorized_domain_confirmed`: exactly `true`;
- `public_osint_queries_confirmed`: exactly `true`.

If a later integration chooses to expose this as an optional DNS inventory
sub-flow, it must use separate fields and remain disabled by default:

```json
{
  "include_osint_discovery": true,
  "osint_sources": ["certificate_transparency"],
  "osint_max_names": 100,
  "public_osint_queries_confirmed": true
}
```

That combined shape is not approved by this design for runtime; it is only a
future compatibility note.

## Domain Policy

The domain policy must accept only one explicit root domain. It must reject:

- empty domains;
- multiple domains;
- URL-shaped input with scheme, path, query, fragment, or userinfo;
- CIDR blocks, dash ranges, wildcards, pasted lists, target files, and generated
  candidates;
- IP addresses when a domain is required;
- parent-domain or sibling-domain expansion;
- overly long values or values with control characters;
- arbitrary third-party domains without explicit authorization.

Observed names from CT or passive DNS must be retained only if they are the
submitted domain or subdomains of that exact domain. Names outside the boundary
must be discarded before storage and rendering. Wildcard labels from CT must be
normalized or discarded according to a future bounded policy; they must never
trigger wildcard expansion.

## Source Plan

Initial implementation recommendation:

1. Certificate Transparency bounded discovery only.
2. Passive DNS public/API source as a later phase with a concrete source,
   rate-limit policy, ToS review, error model, redaction rules, and API-key
   handling if needed.

Allowed future sources:

- Certificate Transparency logs or public CT aggregators, only after a source
  is specifically chosen and reviewed;
- passive DNS public/API sources, only in a later source-specific phase;
- names directly observed from accepted source payloads, retained only if they
  belong to the authorized domain;
- operator-provided candidate names, only if separately validated and bounded.

Not allowed in core `active_dns_osint`:

- provider DNS/API import;
- Cloudflare, Route53, or similar administrative credentials;
- unbounded scraping;
- crawling HTTP;
- search-engine scraping;
- broad wordlists;
- mass brute force;
- aggressive wildcard expansion;
- parent or sibling domain expansion;
- reverse-IP sweeping;
- ASN or IP range discovery;
- automatic scans of observed names.

## Coverage Model

Allowed coverage values:

- `osint_best_effort`;
- `failed_controlled`.

Disallowed coverage values:

- `zone_transfer_complete`;
- `provider_import_complete`;
- `complete_zone`;
- any wording that implies exhaustive inventory.

CT and passive DNS output must be presented as public-source observed names and
review indicators. It must never say that all subdomains, all records, or
complete coverage were found.

## Result Shape

Suggested future successful result:

```json
{
  "audit_type": "active_dns_osint",
  "capability": "active_dns_osint",
  "status": "completed",
  "result_status": "osint_best_effort",
  "domain": "[REDACTED_DOMAIN]",
  "coverage_level": "osint_best_effort",
  "sources": {
    "certificate_transparency": {
      "attempted": true,
      "status": "completed",
      "names_observed_count": 12,
      "names_retained_count": 12,
      "truncated": false
    },
    "passive_dns": {
      "attempted": false,
      "status": "not_attempted"
    }
  },
  "observed_names": {
    "count": 12,
    "sample": ["[REDACTED_DNS_NAME]"]
  },
  "manual_validation_required": true,
  "result_interpretation": "dns_osint_review_indicator"
}
```

Allowed source statuses:

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

The result must include enough limit metadata for review without exposing raw
source payloads.

## Limits

Future implementation must define hard backend caps for:

- total sources enabled per request;
- CT source requests;
- passive DNS source requests;
- total deadline;
- per-source timeout;
- maximum observed names parsed;
- maximum names retained;
- maximum sample size;
- maximum bytes read from source responses;
- maximum error text length;
- per-owner or per-instance rate limits.

Suggested first-phase defaults:

- CT source count: `1`;
- passive DNS: disabled;
- `max_names`: capped at `100`;
- retained sample: capped at `20`;
- per-source timeout: no more than a short interactive timeout;
- no recursive source queries from observed names.

## Redaction

Public API responses, job detail, job list summaries, Raw JSON views, reports,
and future exports must be redaction-first:

- domain shown only as `[REDACTED_DOMAIN]` or equivalent;
- observed names shown only as `[REDACTED_DNS_NAME]` or bounded/redacted
  samples;
- no raw CT payloads;
- no raw passive DNS API payloads;
- no source API keys;
- no provider tokens;
- no raw certificate bodies;
- no email addresses or personal names from certificates;
- no source account IDs;
- no raw errors that include the submitted domain, source payload, keys, or
  provider metadata;
- wrong-owner access remains generic not-found behavior.

## Report Wording

Allowed wording:

- "public-source observed names";
- "DNS OSINT review indicator";
- "OSINT best-effort";
- "manual validation required";
- "source response truncated by Inspectra limits".

Disallowed wording:

- "all subdomains found";
- "all records found";
- "complete coverage";
- "complete zone";
- "confirmed vulnerability";
- "exploitable";
- "target is safe";
- "public scanner".

## UX Expectations

Future UI should be separate from `Active / DNS inventory` unless a later
combined-flow design is accepted. Suggested surface:

- panel name: `Active / DNS OSINT`;
- domain input for one explicit authorized domain;
- Certificate Transparency toggle enabled only when the backend flag and source
  policy allow it;
- passive DNS shown as disabled/unavailable until a later source-specific
  phase;
- confirmation that the operator owns or is authorized to review the domain;
- confirmation that public OSINT queries are acceptable;
- confirmation that results are not complete coverage;
- source status display;
- observed and retained name counts;
- redacted sample display;
- truncation and rate-limit indicators;
- manual validation note;
- redacted Raw JSON.

The UI must not expose provider credentials, search-engine scraping controls,
wordlist uploads, resolver overrides, reverse-IP input, ASN/range input, HTTP
crawling controls, shell commands, Nmap controls, or archive/run-all actions.

## Abuse Threats

Primary abuse risks:

- turning the feature into mass subdomain enumeration;
- using CT or passive DNS to expand scope outside the authorized domain;
- treating OSINT best-effort as complete inventory;
- leaking internal or sensitive names in reports;
- violating source ToS, rate limits, or quota policies;
- introducing API keys or provider secrets into public surfaces;
- linking OSINT results to automatic scans;
- merging OSINT discovery into archive/run-all.

Required mitigations:

- disabled-by-default feature gate;
- explicit confirmations;
- one-domain policy;
- source allowlist;
- source-specific caps and rate limits;
- retained-name caps;
- no recursive discovery from observed names;
- no auto-scan of observed names;
- owner-scoped jobs;
- generic wrong-owner responses;
- redaction before storage and rendering;
- explicit `osint_best_effort` coverage;
- manual validation required.

## Future Tests

Future implementation should include tests for:

- disabled flag rejects without external calls;
- auth-required anonymous fails before validation details;
- invalid domain, URL, range, wildcard, and list rejection;
- CT source disabled does not call the source;
- CT fake source returns bounded and redacted names;
- names outside the authorized domain are discarded;
- wildcard names are normalized or discarded without expansion;
- duplicate names are normalized and deduplicated;
- `max_names` and truncation are applied;
- passive DNS remains disabled by default;
- passive DNS requires a separate source-specific phase;
- no raw source payloads in detail, list, Raw JSON, or exports;
- no source API keys, provider tokens, certificate bodies, email addresses, or
  personal names in public surfaces;
- wrong-owner access returns generic not found;
- no archive/run-all integration;
- no `tools/runner/main.py` integration;
- no provider DNS/API import;
- no crawling, search-engine scraping, broad wordlists, reverse-IP sweeping, or
  ASN/range discovery.

Tests for this design phase are documentation checks only.

## Acceptance Criteria For Future Implementation

A future implementation can be considered for acceptance only when:

- it remains disabled by default and opt-in;
- it accepts exactly one authorized domain;
- it uses a reviewed, allowlisted source plan;
- CT is bounded and source-specific;
- passive DNS remains disabled until a later phase freezes a concrete source;
- provider DNS/API import remains out of core Active DNS;
- observed names stay inside the authorized domain boundary;
- no observed name is auto-scanned;
- it reports only `osint_best_effort` or controlled failure;
- it stores only allowlisted, bounded, redacted result fields;
- backend, frontend, report, Raw JSON, owner-scope, source-boundary, and
  guardrail tests pass;
- docs continue to frame output as public-source observed names requiring
  manual validation.

## Decision

`ACTIVE_DNS_OSINT_01_DESIGN_FROZEN`
