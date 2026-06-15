# Active DNS OSINT Frontend CT OSINT Review

Decision: `ACTIVE_DNS_OSINT_08_FRONTEND_CT_OSINT_REVIEW_PASSED`

## Scope

This review covers `ea56384 feat(active): show dns osint ct jobs in frontend`
and the current tree after the Active DNS OSINT frontend product-flow
microphase. The reviewed change added the `Active / DNS OSINT` panel, frontend
API contract, report renderer, redaction helper, catalog/filter entries, App
selection/refresh flow, tests, and product-flow documentation.

No blocker was found. This review is docs-only and adds no runtime behavior.

## Files Reviewed

- `frontend/src/ActiveDnsOsintPanel.tsx`
- `frontend/src/ActiveDnsOsintJobReport.tsx`
- `frontend/src/activeDnsOsintReport.ts`
- `frontend/src/App.tsx`
- `frontend/src/api.ts`
- `frontend/src/types.ts`
- `frontend/src/auditCatalog.ts`
- `frontend/src/dashboardFilters.test.ts`
- `frontend/src/App.test.tsx`
- `frontend/src/ActiveDnsOsintPanel.test.tsx`
- `frontend/src/ActiveDnsOsintJobReport.test.tsx`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`
- `docs/future/active-dns-osint-frontend-ct-osint-product-flow.md`

## UI And Contract Review

The UI exposes a separate `Active / DNS OSINT` panel and submits only to the
backend route:

- `POST /active/network/dns-osint`;
- `mode: live_dns_osint`;
- `profile: ct_subdomain_discovery_bounded`;
- one explicit domain string;
- `include_certificate_transparency: true`;
- `include_passive_dns: false`;
- bounded `max_names` from `1` to `100`;
- `authorization_confirmed: true`;
- `owned_or_authorized_domain_confirmed: true`;
- `public_osint_queries_confirmed: true`.

The submit button remains disabled until the domain, bounded name cap, and all
three confirmations are present. The panel does not expose provider credentials,
passive DNS source selection, source override, wordlists, reverse-IP/ASN/range
inputs, target files, shell inputs, or archive/run-all controls.

## Browser Boundary

The frontend delegates source execution to the backend contract only. The review
confirmed:

- no direct browser call to CT sources;
- no browser DNS query path;
- no passive DNS call path;
- no provider API call path;
- no observed-name auto-scan behavior;
- no automatic handoff to Nmap, TLS, DNS inventory, archive/run-all, or
  `tools/runner/main.py`.

The only network primitive remains the existing shared API client, which calls
the configured Inspectra backend base URL.

## Reporting Review

The report renderer keeps OSINT output as:

- `coverage_level: osint_best_effort`;
- `DNS OSINT review indicator`;
- source-limited public-source observed names;
- manual-validation required.

It renders CT source status/counters, retained/observed/discarded counts,
truncation, rate-limit/source error states, passive DNS `not_attempted`,
execution-boundary counters, caveats, and Raw JSON.

Source states such as partial output, timeout, rate limit, source unavailable,
invalid response, truncation, disabled, and policy-blocked states are rendered
as controlled review states rather than proof of source completeness.

## Redaction Review

The frontend redaction helper defensively removes or replaces:

- raw domain values;
- raw observed names;
- raw CT payloads;
- certificate bodies;
- source exception text;
- provider secrets;
- credentials, headers, cookies, and tokens;
- email-like and DNS-value material.

Job-table target display, report sections, caveats/errors, and Raw JSON use
`[REDACTED_DOMAIN]`, `[REDACTED_DNS_NAME]`, `[REDACTED_DNS_VALUE]`, or generic
redaction placeholders. Tests include legacy/malformed payload fixtures to
ensure raw source material is not rendered.

## Wording Review

Approved wording remains:

- `DNS OSINT review indicator`;
- `OSINT best-effort`;
- `public-source observed names`;
- `Manual validation required`.

The frontend does not claim exhaustive discovery, source completeness,
vulnerability proof, exploitability, target safety, or public-scanning
capability. Observed names are explicitly not auto-scanned.

## Validations Run

- `git status --short --branch`
- `git show --stat --oneline ea56384`
- `git show --name-only --oneline ea56384`
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_osint`
  - Result: 85 passed, 558 deselected.
- `npm test -- --run ActiveDnsOsintPanel ActiveDnsOsintJobReport App dashboardFilters`
  - Result: 62 passed.
- `npm test -- --run`
  - Result: 183 passed.
- `npm run build`
  - Result: passed; Vite emitted the existing chunk-size warning.

Additional guardrail searches are expected before commit for:

- frontend CT direct calls;
- passive DNS/provider API paths;
- browser DNS query paths;
- archive/run-all and tools-runner references;
- raw domain/name/source payload leakage;
- exhaustive-coverage or vulnerability/target-safety wording drift.

## Final Assessment

`active_dns_osint` frontend CT OSINT is reviewed and accepted as a bounded
product flow. The UI sends the correct backend contract, keeps passive DNS out,
does not contact OSINT sources from the browser, renders `osint_best_effort`
review indicators, and remains redaction-first.
