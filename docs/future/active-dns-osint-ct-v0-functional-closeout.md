# Active DNS OSINT CT v0 Functional Closeout

Decision: `ACTIVE_DNS_OSINT_09_FUNCTIONAL_CLOSEOUT_ACCEPTED`

This document closes `active_dns_osint` v0 after the docs design, backend
contract gate, backend CT-bounded persistence, backend review, bounded real CT
source, source review, frontend product flow, and frontend review. This
closeout adds no new runtime behavior, no new CT request, no passive DNS, no
provider API, no DNS query, no crawling, no search scraping, no wordlist, no
reverse-IP, ASN, or range discovery, no auto-scan of observed names, no
archive/run-all behavior, no `tools/runner/main.py` behavior, no Nmap, no
Docker, no subprocess behavior, no release, no tag, and no push state.

## Reviewed Lineage

Reviewed as the final v0 CT OSINT line:

- `9f85130 docs(active): design dns osint discovery capability`;
- `df15636 feat(active): add dns osint backend contract gate`;
- `d233d51 feat(active): persist dns osint ct source results`;
- `1af47e4 docs(active): review dns osint ct backend`;
- `57bc31d feat(active): add bounded ct osint source`;
- `c2687f5 fix(active): harden bounded ct osint source`;
- `ea56384 feat(active): show dns osint ct jobs in frontend`;
- `3ef7ab5 docs(active): review dns osint frontend`.

The source review correction is retained as part of the accepted boundary:
`crt.sh` source configuration accepts only the HTTPS base URL for `crt.sh`, with
no alternate host, credentials, explicit custom port, custom path, query, or
fragment.

## Product Direction

`active_dns_osint` is accepted as a bounded public-source review capability for
one explicit authorized domain. It complements `active_dns_inventory` without
folding public OSINT sources into the standard DNS inventory path.

The capability is for self-hosted/local/private operation with explicit
operator authorization. It reports only public-source observed-name review
indicators and remains `osint_best_effort`; it does not promise exhaustive
discovery, automatic validation of observed names, or safety conclusions.

Passive DNS and provider DNS/API import remain out of v0. If either is ever
considered, it must be designed as a separate source-specific or admin-inventory
phase with its own authorization, source, retention, and redaction boundaries.

## Approved State

`active_dns_osint` v0 is accepted with:

- feature flag disabled by default through
  `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=false`;
- CT source disabled by default through
  `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED=false`;
- endpoint `POST /active/network/dns-osint`;
- exact request contract `live_dns_osint` /
  `ct_subdomain_discovery_bounded`;
- one explicit authorized domain;
- `include_certificate_transparency: true`;
- `include_passive_dns: false`;
- bounded `max_names` from `1` to `100`;
- explicit authorization, owned-or-authorized-domain, and public-OSINT
  confirmations;
- owner-scoped `active_dns_osint` jobs with `file_id: null`;
- public domain display as `[REDACTED_DOMAIN]`;
- retained observed names displayed as `[REDACTED_DNS_NAME]` placeholders;
- `coverage_level: osint_best_effort`;
- `DNS OSINT review indicator`;
- `public-source observed names`;
- `Manual validation required`;
- report, export, Raw JSON, list, detail, and frontend surfaces that are
  redaction-first.

The backend remains the authority for feature gates, auth, owner scope, request
validation, domain policy, source selection, CT-source caps, storage,
report/export shaping, and redaction.

## CT Source Boundary

The bounded `crt.sh` source is accepted only when all of these conditions hold:

- `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=true`;
- `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED=true`;
- `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_URL=https://crt.sh/`;
- the request passes the exact `active_dns_osint` contract;
- the domain passes policy for one explicit authorized domain.

Runtime source behavior is constrained to:

- at most one CT request per accepted job;
- timeout and response-size caps;
- parsed-name caps;
- retained-name caps;
- parsing only `name_value` and `common_name`;
- JSON array input only;
- lowercase, trailing-dot, and IDNA normalization;
- dedupe before retention;
- exact-domain or subdomain retention only;
- out-of-scope names discarded;
- wildcard source names normalized without expansion;
- controlled statuses for timeout, rate limit, source unavailability, source
  errors, invalid source response, truncation, disabled source, and
  policy-blocked outcomes.

No raw CT payload, certificate body, source exception text, API credential,
email/person material, or provider secret is persisted or rendered.

## Frontend Boundary

The v0 frontend is accepted with a separate `Active / DNS OSINT` panel. The UI:

- submits only to `POST /active/network/dns-osint`;
- sends the exact CT-bounded contract;
- requires all three confirmations;
- bounds `max_names`;
- always sends `include_passive_dns: false`;
- displays passive DNS as unavailable;
- receives a `202 JobRecord`;
- selects the returned job and refreshes the list;
- renders source status, counts, truncation/rate-limit/source-error states,
  passive DNS `not_attempted`, redacted samples, caveats, and Raw JSON;
- does not contact CT, passive DNS, provider APIs, DNS resolvers, Nmap, TLS, DNS
  inventory, archive/run-all, or `tools/runner/main.py` from the browser;
- does not auto-scan observed names.

## Not Approved

This closeout does not approve:

- passive DNS runtime;
- provider DNS/API import;
- provider API keys, account IDs, tokens, or secrets;
- search-engine scraping;
- crawling;
- broad wordlists;
- reverse-IP, ASN, or range discovery;
- automatic probing or scanning of observed names;
- custom source URLs beyond the accepted `crt.sh` base URL;
- DNS queries from this capability;
- browser-side CT or provider requests;
- Nmap;
- Docker runtime;
- subprocess execution;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- public-scanning or SaaS-inventory behavior;
- exhaustive-discovery assertions;
- all-subdomain or all-record assertions;
- vulnerability-proof, exploitability, or target-safety claims.

## Redaction Boundary

Accepted storage, reporting, export, Raw JSON, list, detail, and frontend
surfaces must keep:

- no raw domain;
- no raw observed names;
- no raw CT payload;
- no certificate bodies;
- no raw source exceptions;
- no emails or person names;
- no provider credentials, API keys, account IDs, tokens, or secrets;
- no credentials, headers, cookies, or tokens;
- wrong-owner reads, exports, deletes, and Raw JSON access as generic not found.

Public and owner-visible surfaces may expose bounded source status, counts,
truncation, redacted samples, coverage level, manual-validation copy, and
review-indicator wording.

## Final Validation Scope

Final closeout validation covers:

- recent CT OSINT backend, CT source, frontend, and review commits;
- Python compile checks for backend OSINT/config/storage/reporting/model
  modules;
- focused backend `active_dns_osint` tests;
- backend Active regression tests for DNS OSINT, DNS inventory, TLS, and Nmap;
- full backend test suite;
- focused frontend DNS OSINT/App/catalog/report tests;
- full frontend test suite;
- frontend production build;
- Git whitespace checks;
- guardrail searches for passive DNS/provider runtime, DNS queries,
  archive/run-all, `tools/runner/main.py`, raw domain/observed/source payload
  leakage, exhaustive-coverage wording drift, and vulnerability/target-safety
  wording drift.

## Validation Results

Validation run during this closeout:

- `git status --short --branch`: pending final commit, branch ahead of origin;
- `git show --stat --oneline d233d51`: reviewed CT bounded backend
  persistence commit, 12 files changed, +1218/-82;
- `git show --stat --oneline 57bc31d`: reviewed bounded real CT source
  commit, 9 files changed, +727/-17;
- `git show --stat --oneline ea56384`: reviewed frontend CT OSINT product
  flow commit, 15 files changed, +1604/-6;
- `git show --stat --oneline 3ef7ab5`: reviewed frontend CT OSINT review
  commit, 4 files changed, +153;
- `python3 -m py_compile backend/app/active_dns_osint.py backend/app/main.py backend/app/config.py backend/app/storage.py backend/app/reporting.py backend/app/models.py`:
  passed;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_osint`:
  `85 passed, 558 deselected`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_dns_osint or active_dns_inventory or active_tls_basic or active_nmap_basic"`:
  `305 passed, 338 deselected`;
- `.venv/bin/python -m pytest backend/tests`: `727 passed`;
- `npm test -- --run ActiveDnsOsintPanel ActiveDnsOsintJobReport App dashboardFilters`
  from `frontend/`: `62 passed`;
- `npm test -- --run` from `frontend/`: `183 passed`;
- `npm run build` from `frontend/`: passed with the existing Vite
  chunk-size warning;
- `git diff --check`: passed;
- `git diff --cached --check`: passed;
- runtime diff guardrail for `backend`, `frontend`, and `tools`: no changed
  tracked files;
- forbidden wording guardrail on the documentation diff: no matches for the
  blocked exhaustive-discovery, vulnerability, target-safety, or
  public-scanning phrases;
- frontend boundary guardrail: the only `fetch` match is the existing shared
  backend API client, with no direct `crt.sh`, browser DNS, archive/run-all, or
  `tools/runner/main.py` call;
- OSINT source guardrail: no DNS CLI, Docker, subprocess execution, or Nmap
  execution path was added; existing matches are false-valued safety counters
  and the bounded `crt.sh` host constant in `backend/app/active_dns_osint.py`.

## Roadmap And Stop

This closeout triggers a technical stop before choosing the next path. Future
work must be separately designed and accepted before changing this boundary.

Recommended next options:

1. push the accumulated commits when the operator decides;
2. choose a new small Active tool, operational polish, release/pre-alpha work,
   or a separately designed source-specific extension;
3. keep passive DNS and provider import outside v0;
4. keep archive/run-all and `tools/runner/main.py` outside Active OSINT until a
   separate design freezes authorization, redaction, abuse boundaries, and
   validation;
5. preserve OSINT CT v0 as bounded, self-hosted/local/private,
   redaction-first, and manual-review only.

## Decision

`ACTIVE_DNS_OSINT_09_FUNCTIONAL_CLOSEOUT_ACCEPTED`
