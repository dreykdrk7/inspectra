# Active DNS Inventory Authorized AXFR Backend Review

Decision: `ACTIVE_DNS_INVENTORY_08_AUTHORIZED_AXFR_BACKEND_REVIEW_PASSED`

This microphase reviews `30b1167 feat(active): add authorized dns zone transfer
check`, covering the backend AXFR submodule introduced for
`active_dns_inventory`. The review confirms the feature remains backend-only,
disabled by default, explicitly authorized, owner-scoped, bounded, and
redaction-first.

## Reviewed Commit

- `30b1167 feat(active): add authorized dns zone transfer check`

The reviewed commit touched:

- `README.md`;
- `backend/app/active_dns_inventory.py`;
- `backend/app/main.py`;
- `backend/app/reporting.py`;
- `backend/app/storage.py`;
- `backend/tests/test_backend.py`;
- `docs/architecture.md`;
- `docs/future/active-dns-inventory-authorized-axfr-backend.md`;
- `docs/future/active-dns-inventory-design.md`;
- `docs/future/active-dns-inventory-v0-functional-closeout.md`;
- `docs/security-scope.md`.

## Review Findings

One blocker was found and fixed in this microphase.

The original AXFR TCP path could return `zone_transfer_complete` after receiving
some records if the connection closed before the terminal SOA was observed. That
could make a partial zone-transfer response look complete. The fix now requires
a terminal SOA pair before success:

- real TCP AXFR responses without terminal SOA become `malformed_response` with
  `zone_transfer_missing_terminal_soa`;
- fake/injected AXFR results that claim `zone_transfer_complete` are also
  downgraded unless they contain the terminal SOA pair for the exact domain;
- tests cover this downgrade and confirm the response remains redacted and
  `partial_inventory`.

Two related hardening adjustments were also applied:

- `nameservers_attempted` now reflects valid bounded candidate NS values rather
  than raw NS record count;
- TXT values parsed from DNS packets are capped internally before any indicator
  logic sees them.

## Contract And Authorization

The route still requires:

- `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=true`;
- `mode: live_dns_inventory`;
- `profile: dns_inventory_authorized`;
- one accepted explicit root domain;
- allowlisted record types only;
- `authorization_confirmed: true`;
- `local_private_or_owned_scope_confirmed: true`;
- `live_dns_queries_confirmed: true`.

AXFR requires both:

- `attempt_zone_transfer: true`;
- `zone_transfer_authorized_confirmed: true`.

Without the specific AXFR confirmation, request validation rejects before
resolver or AXFR transport calls. The internal helper also fails closed with
`authorization_required` if invoked directly without that confirmation.
Disabled deployments reject before resolver or AXFR calls. Auth-required
anonymous requests are rejected by the existing anonymous-sensitive-route guard
before route validation details are exposed.

## Scope Boundary

AXFR remains scoped to the exact requested domain:

- authoritative NS records are resolved for that exact domain only;
- at most one valid authoritative NS candidate is attempted;
- no nameserver override is accepted from user input;
- no parent, sibling, CNAME, MX, provider, CT, passive DNS, recursive, or
  brute-force discovery expansion is added;
- frontend still does not expose AXFR controls.

## Runtime Boundary

AXFR runtime is isolated in `backend/app/active_dns_inventory.py`. The reviewed
tree does not add:

- `dig`, `host`, or `nslookup`;
- subprocess or shell execution;
- Nmap;
- Docker runtime behavior;
- HTTP requests;
- provider DNS/API access;
- Certificate Transparency lookup;
- passive DNS lookup;
- archive/run-all;
- `tools/runner/main.py` integration.

The backend route calls `run_active_dns_inventory(...)` only after feature gate,
owner resolution, request validation, and domain policy acceptance.

## Limits

The AXFR path remains bounded by:

- one authoritative NS candidate;
- short per-NS timeout;
- maximum response bytes;
- maximum received/retained records;
- record type allowlist: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `CAA`;
- public sample caps per type;
- internal TXT value cap;
- no raw DNS messages, resolver logs, raw zone files, command output, stdout, or
  stderr.

Oversized, truncated, missing-terminal-SOA, malformed, timed-out, unavailable,
or refused AXFR paths become controlled status values and do not become system
errors.

## Storage, Reporting, And Wording

Owner-scoped jobs keep `file_id: null` and public surfaces keep:

- `[REDACTED_DOMAIN]`;
- `[REDACTED_DNS_NAME]`;
- `[REDACTED_DNS_VALUE]`;
- bounded counts and samples;
- `manual_validation_required: true`;
- `dns_configuration_review_indicator`.

`zone_transfer_complete` is used only when bounded authorized AXFR succeeds and
passes terminal-SOA validation. The allowed success wording is:

`zone transfer accepted by authoritative server / high-risk configuration review indicator`

Refused, unavailable, timed-out, malformed, or oversized AXFR remains
`best_effort_inventory` or `partial_inventory`. The reviewed code does not add
`provider_import_complete`, complete-coverage claims outside
`zone_transfer_complete`, all-records-found claims, vulnerability claims,
exploitability claims, target-safety claims, or public-scanner claims.

Wrong-owner reads remain generic not found through the existing owner-scoped job
surfaces.

## Validation

Validation performed for this review:

- `git status --short --branch`;
- `git show --stat --oneline 30b1167`;
- `git show --name-only --oneline 30b1167`;
- `python3 -m py_compile backend/app/active_dns_inventory.py backend/app/main.py backend/app/storage.py backend/app/reporting.py backend/app/models.py`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_inventory`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_dns_inventory or active_tls_basic or active_nmap_basic"`;
- `.venv/bin/python -m pytest backend/tests`;
- `git diff --check`;
- `git diff --cached --check`;
- guardrail searches for DNS CLI/subprocess, Nmap/Docker/HTTP,
  provider/CT/passive DNS, archive-run-all/tools-runner, raw DNS/zone/domain
  leakage, complete-coverage wording drift, and vulnerability/exploitability or
  target-safety wording.

## Decision

Authorized AXFR backend review is accepted after the terminal-SOA hardening fix.
No frontend, provider API, CT/passive DNS, Docker, Nmap, HTTP, archive/run-all,
`tools/runner/main.py`, release, tag, or push behavior is added.
