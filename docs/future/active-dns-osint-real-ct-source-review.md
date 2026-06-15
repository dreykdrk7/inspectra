# Active DNS OSINT Real CT Source Review

Decision: `ACTIVE_DNS_OSINT_06_REAL_CT_SOURCE_REVIEW_PASSED`

This review covers `57bc31d feat(active): add bounded ct osint source` and the
current tree after the review hardening. The review found one URL-boundary
blocker and fixed it in this microphase: explicit non-default ports on the
`crt.sh` source URL are now rejected before any request.

## Reviewed Change

Commit reviewed:

- `57bc31d feat(active): add bounded ct osint source`

Files reviewed:

- `backend/app/active_dns_osint.py`
- `backend/app/config.py`
- `backend/app/main.py`
- `backend/tests/test_backend.py`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`
- `docs/future/active-dns-osint-design.md`
- `docs/future/active-dns-osint-real-ct-source-bounded.md`

## Configuration Review

The CT source remains disabled by default through
`INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED=false`. The core capability flag
also remains disabled by default through `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=false`.

Without a configured source URL, the factory returns the disabled source and
sends no request. Non-empty invalid URLs return the blocked source and send no
request.

Accepted source URL shape after the review fix:

- scheme must be `https`;
- host must be exactly `crt.sh`;
- port must be absent or the default HTTPS port;
- path must be empty or `/`;
- username and password are rejected;
- query and fragment are rejected.

The config caps remain bounded:

- timeout default `5.0`, maximum `10.0` seconds;
- response bytes default `262144`, maximum `1048576`;
- parsed candidate names default `500`, maximum `1000`;
- retained names bounded by request `max_names`, from 1 to 100.

## Runtime HTTP Review

The only HTTP runtime added by this block is isolated in
`backend/app/active_dns_osint.py`. The backend route and config layer do not
perform HTTP calls themselves.

The real source performs at most one `GET /?q=%.<authorized-domain>&output=json`
request per accepted job. It disables redirects, applies a bounded timeout,
reads response bytes through a bounded stream before parsing, and maps source
failures into allowlisted states.

The reviewed implementation does not retry recursively, crawl, query passive
DNS, use provider APIs, perform DNS queries, scrape search engines, use
wordlists, perform reverse-IP/ASN/range discovery, or auto-scan observed names.
Tests use `httpx.MockTransport` or fake source adapters and do not depend on
external network access.

## Parsing And Scope Review

The parser accepts only the expected `crt.sh` JSON array response shape. It
extracts candidate names only from `name_value` and `common_name`; newline
separated names in `name_value` are split into individual candidates.

Candidate names flow through the existing domain policy:

- lowercase normalization;
- trailing-dot removal;
- IDNA normalization;
- duplicate names deduplicated before retention;
- only the exact authorized domain or its subdomains are retained;
- out-of-scope names are discarded;
- leading wildcard labels may be stripped;
- wildcard values are never expanded;
- `max_names_parsed` and request `max_names` are both applied.

Observed names are never used as follow-up targets.

## Error Handling Review

Source status mapping is controlled:

- `429` maps to `rate_limited`;
- `408` and `504` map to `timed_out`;
- `5xx` maps to `source_unavailable`;
- other non-`200` responses map to `source_error_controlled`;
- oversized responses map to `truncated`;
- invalid JSON or unexpected response shape maps to `invalid_source_response`;
- transport and timeout exceptions normalize without raw exception text.

Errors do not expose raw domain values, raw source payloads, observed-name
values, certificate material, source exceptions, provider credentials, or API
key material.

## Storage, Reporting, And Redaction

Jobs remain owner-scoped `active_dns_osint` records with `file_id: null`,
`target_url: [REDACTED_DOMAIN]`, `target_domain: null`, and
`coverage_level: osint_best_effort`.

Public detail, list, Raw JSON, and Markdown/HTML/XML/PDF exports remain
redaction-first:

- domain is `[REDACTED_DOMAIN]`;
- observed names are `[REDACTED_DNS_NAME]`;
- raw CT payloads are not exposed;
- certificate bodies are not exposed;
- email/person-like strings are redacted;
- raw source errors are not exposed;
- provider/API credentials are not accepted or exposed;
- wrong-owner access remains generic `Job not found.`.

Approved wording remains:

- `DNS OSINT review indicator`;
- `osint_best_effort`;
- `Manual validation required`.

The reviewed source remains best-effort public-source OSINT. It does not make
subdomain-completeness, record-completeness, exhaustive-inventory,
vulnerability, exploitability, target-safety, or scanner-service claims.

## Fix Applied

The review hardened `_normalize_crtsh_source_url` so explicit custom ports are
rejected before source construction. Tests now cover alternate schemes,
alternate hosts, custom ports, custom paths, query strings, fragments, and
credentials.

## Validation Summary

Commands run:

- `git status --short --branch`
- `git show --stat --oneline 57bc31d`
- `git show --name-only --oneline 57bc31d`
- `python3 -m py_compile backend/app/active_dns_osint.py backend/app/main.py backend/app/config.py backend/app/storage.py backend/app/reporting.py backend/app/models.py`
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_osint`
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_dns_osint or active_dns_inventory or active_tls_basic or active_nmap_basic"`
- `.venv/bin/python -m pytest backend/tests`
- `git diff --check`
- `git diff --cached --check`
- focused guardrail searches for HTTP outside the OSINT module, external CT in
  tests, passive DNS/provider/DNS behavior, subprocess/Nmap/Docker,
  frontend/archive/tools-runner changes, raw source leakage, and wording drift.

Results:

- focused `active_dns_osint`: 85 passed;
- Active backend related tests: 305 passed;
- full backend suite: 727 passed;
- diff checks: clean;
- guardrails: no blocker after custom-port fix.

## Decision

`ACTIVE_DNS_OSINT_06_REAL_CT_SOURCE_REVIEW_PASSED`
