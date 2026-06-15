# Active DNS Inventory Functional Closeout With Authorized AXFR

Decision: `ACTIVE_DNS_INVENTORY_11_FUNCTIONAL_CLOSEOUT_WITH_AXFR_ACCEPTED`

This document closes `active_dns_inventory` v0 after the standard-records
runtime, backend runtime review, frontend product flow, authorized AXFR backend
extension, authorized AXFR backend review, authorized AXFR frontend integration,
and authorized AXFR frontend review. It adds no new runtime behavior, no new
DNS execution, no provider API, no Certificate Transparency lookup, no passive
DNS lookup, no subprocess execution, no DNS CLI execution, no Nmap behavior, no
Docker behavior, no HTTP crawling, no archive/run-all behavior, no
`tools/runner/main.py` behavior, no release, no tag, and no push state.

## Reviewed Lineage

Reviewed as the final v0 line with authorized AXFR:

- `d1ad2d9 feat(active): persist dns inventory standard records`;
- `cdbbcad fix(active): harden dns inventory backend runtime`;
- `5230fa6 feat(active): show dns inventory jobs in frontend`;
- `30b1167 feat(active): add authorized dns zone transfer check`;
- `58a9faf fix(active): harden authorized dns zone transfer`;
- `fb01b7c feat(active): expose authorized axfr in dns inventory ui`;
- `bb1826e docs(active): review authorized axfr frontend`.

The important backend review correction is retained as part of the accepted
boundary: `zone_transfer_complete` requires a valid terminal SOA pair for the
exact authorized domain. Missing terminal SOA, malformed, oversized, refused,
timed-out, or unavailable AXFR results remain controlled non-complete
inventory states.

## Product Direction

The core Active DNS direction is attacker-equivalent visibility: Inspectra
models what an external operator could observe through authorized public-network
or public-OSINT techniques, without using privileged DNS-provider access.

Authorized AXFR fits this direction because it is an external check against
authoritative nameservers for the exact authorized domain. Certificate
Transparency or passive DNS may be considered later as separate public-OSINT
phases with their own caps and review. Provider DNS/API import is deliberately
out of core Active DNS because it depends on administrator privileges that an
external observer would not have.

If provider import is ever implemented, it must be designed as a separate admin
inventory connector, not as part of the attacker-equivalent Active DNS path and
not as the recommended next step from this closeout. Within current Active DNS,
complete-zone coverage can come only from `zone_transfer_complete` produced by
authorized, bounded, terminal-SOA-validated AXFR.

## Approved State

`active_dns_inventory` v0 is accepted as a bounded Active capability with:

- feature flag disabled by default through
  `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=false`;
- endpoint `POST /active/network/dns-inventory`;
- exact request contract `live_dns_inventory` /
  `dns_inventory_authorized`;
- one explicit authorized domain;
- record types allowlisted to `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`,
  and `CAA`;
- SPF, DMARC, and CAA configuration review indicators;
- fixed-candidate bounded subdomain discovery;
- optional authorized AXFR as a separate submodule;
- complete frontend product flow;
- reporting, export, Raw JSON, and frontend surfaces that are redaction-first;
- owner-scoped `active_dns_inventory` jobs with `file_id: null`;
- public domain display as `[REDACTED_DOMAIN]`;
- manual validation required.

Authorized AXFR is accepted only with these conditions:

- `attempt_zone_transfer: false` by default;
- `attempt_zone_transfer: true` only when
  `zone_transfer_authorized_confirmed: true`;
- AXFR only against authoritative nameservers derived for the exact submitted
  domain;
- no request-provided nameserver override;
- bounded nameserver attempts, timeout, response size, retained records, and
  grouped record output;
- `zone_transfer_complete` only when AXFR is explicitly authorized, bounded,
  accepted, and terminal-SOA validated for the exact domain;
- `best_effort_inventory` or `partial_inventory` for refused, timed-out,
  unavailable, malformed, oversized, or truncated outcomes.

The backend remains the authority for feature gates, auth, owner scope, request
validation, domain policy, DNS runtime handoff, AXFR authorization, storage,
report/export shaping, and redaction.

## Not Approved

This closeout does not approve:

- provider DNS/API import as part of core Active DNS;
- Certificate Transparency lookup in this block;
- passive DNS lookup in this block;
- broad wordlists;
- recursive discovery;
- broad wildcard discovery;
- DKIM selector guessing;
- parent-domain or sibling-domain expansion;
- custom resolver or nameserver override from the request;
- CNAME, MX, or NS-derived target expansion;
- DNS CLI execution such as `dig`, `host`, or `nslookup`;
- subprocess execution;
- Nmap;
- Docker runtime;
- HTTP or crawling;
- credential validation;
- provider secrets, tokens, account IDs, or zone IDs;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- public scanner or SaaS-style inventory behavior;
- all-records-found, vulnerability, exploitability, target-safety, or
  non-AXFR complete-coverage claims.

## Approved AXFR Wording

If the backend returns `zone_transfer_complete`, product and report surfaces may
use only conservative wording such as:

- `zone transfer accepted by authoritative server`;
- `high-risk configuration review indicator`;
- `Manual validation required`.

This wording describes a configuration review indicator. It is not an
exploitability claim, not a target-safety claim, and not approval for public or
third-party scanning.

## Redaction Boundary

Accepted storage, reporting, export, Raw JSON, and frontend surfaces must keep:

- no raw domain;
- no raw nameserver;
- no raw zone file;
- no raw DNS packets;
- no raw resolver logs;
- no raw DNS record values;
- no provider secrets, tokens, account IDs, or zone IDs;
- wrong-owner reads, exports, and deletes as generic not found.

Public and owner-visible surfaces may expose bounded counts, controlled status
codes, allowlisted record type group names, redacted samples, coverage level,
manual-validation copy, and review-indicator wording.

## Final Validation Scope

Final closeout validation covers:

- backend DNS inventory focused tests;
- backend Active regression tests for DNS, TLS, and Nmap;
- full backend test suite;
- frontend DNS inventory focused tests;
- full frontend test suite;
- frontend production build;
- Python compile checks for backend DNS/storage/reporting modules;
- Git whitespace checks;
- guardrail searches for provider/CT/passive DNS runtime, DNS CLI/subprocess,
  Nmap, Docker, HTTP, archive/run-all, `tools/runner/main.py`, raw
  zone/domain/record/provider leakage, complete-coverage wording drift, and
  vulnerability/exploitability/target-safety wording drift.

## Validation Results

Validation run during this closeout:

- `git status --short --branch`: docs-only working tree before commit, branch
  ahead of origin;
- `git show --stat --oneline 30b1167`: reviewed authorized AXFR backend
  commit, 11 files changed, +904/-39;
- `git show --stat --oneline 58a9faf`: reviewed authorized AXFR backend
  hardening commit, 7 files changed, +261/-11;
- `git show --stat --oneline fb01b7c`: reviewed authorized AXFR frontend
  integration commit, 10 files changed, +603/-28;
- `git show --stat --oneline bb1826e`: reviewed authorized AXFR frontend
  review commit, 4 files changed, +163;
- `python3 -m py_compile backend/app/active_dns_inventory.py backend/app/main.py backend/app/storage.py backend/app/reporting.py backend/app/models.py`:
  passed;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_inventory`:
  `68 passed, 490 deselected`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_dns_inventory or active_tls_basic or active_nmap_basic"`:
  `220 passed, 338 deselected`;
- `.venv/bin/python -m pytest backend/tests`: `642 passed`;
- `npm test -- --run ActiveDnsInventoryPanel ActiveDnsInventoryJobReport App dashboardFilters`
  from `frontend/`: `66 passed`;
- `npm test -- --run` from `frontend/`: `173 passed`;
- `npm run build` from `frontend/`: passed with the existing Vite chunk-size
  warning;
- `git diff --check`: passed;
- `git diff --cached --check`: passed;
- runtime diff guardrail for `backend`, `frontend`, and `tools`: no changed
  files;
- source and wording guardrails found matches only in no-scope wording,
  historical documentation, controlled review wording, or redaction
  requirements.

## Roadmap And Stop

This closeout triggers a mandatory technical stop before choosing the next
path. Future work must be separately designed and accepted before changing this
boundary.

Recommended next options:

1. push the accumulated commits when the operator decides;
2. choose CT/passive DNS OSINT as a separate public-source design, Nmap deep,
   a new small Active tool, operational polish, or release/pre-alpha work;
3. keep provider DNS/API import out of the recommended Active DNS path; if it
   is ever needed, design it as a separate admin inventory connector;
4. keep broad discovery, provider credentials, and archive/run-all out of
   Active DNS inventory until separate designs freeze authorization, redaction,
   abuse boundaries, and validation;
5. keep complete-zone states in core Active DNS limited to authorized,
   bounded, terminal-SOA-validated AXFR.

## Decision

`ACTIVE_DNS_INVENTORY_11_FUNCTIONAL_CLOSEOUT_WITH_AXFR_ACCEPTED`
