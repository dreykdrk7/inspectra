# Inspectra subdomain_inventory_basic security review

## 1. Executive summary

The `subdomain_inventory_basic` module is integrated coherently with the current Inspectra MVP. The backend requires explicit authorization confirmation, validates the root domain with the same defensive policy used by `domain_basic`, rejects URL-shaped and out-of-scope candidates, creates jobs without `file_id`, and delegates bounded DNS work to the `audit-tools` runner. The runner keeps the inventory narrow: it normalizes and deduplicates submitted candidates, resolves only `A`, `AAAA`, and `CNAME`, optionally performs a small wildcard-DNS heuristic, and does not use wordlists, Certificate Transparency, AXFR, HTTP crawling, port scanning, Nmap, CVE lookup, or external reputation APIs.

Overall recommendation: continue after addressing the medium availability item before relying on large candidate lists in degraded DNS environments. No critical or high findings were observed. The module is suitable for MVP/local use with its current defensive scope, but a follow-up hardening microfase should cap or globally budget long DNS jobs and tighten a few contract and test edges.

Main strengths:

- Clear public endpoint and internal runner endpoint for `subdomain_inventory_basic`.
- Explicit authorization confirmation in API and UI.
- Root-domain validation rejects URLs, userinfo, paths, queries, fragments, IP literals, localhost-style names, and reserved/internal suffixes.
- Candidate validation rejects wildcards, URLs, paths, query strings, fragments, userinfo, IP literals, spaces, empty labels, invalid domains, root-domain self references, and out-of-root FQDNs.
- Jobs without `file_id` are compatible with listing, detail, summaries, and report exports.
- Runner scope is bounded to submitted candidates plus at most two wildcard-DNS probes.
- DNS answers are bounded per type and findings use prudent indicator language.
- Frontend, report helpers, dashboard filters, and exports recognize the new audit type.
- Tests cover core backend validation, runner DNS behavior, wildcard heuristic, frontend launch, filtering, report helper, and completed-job exports.

Main risks:

- Worst-case DNS timeout for 100 candidates can become very long because the backend timeout is calculated from sequential candidate, record-type, wildcard, nameserver, and DNS-timeout budgets.
- The public backend rejects the whole request when any candidate is invalid, while the runner/result model supports per-candidate rejected status; this is safe, but the contract is slightly split.
- Candidate count is bounded, but raw JSON body size and raw candidate string length are not constrained before request parsing.
- Export tests cover completed subdomain jobs, but not queued/running/failed or sparse-result subdomain jobs yet.

## 2. Scope reviewed

- Backend: `backend/app/main.py`, `backend/app/models.py`, `backend/app/services.py`, `backend/app/storage.py`, `backend/app/reporting.py`, `backend/app/config.py`, `backend/app/domain_security.py`, backend tests.
- Runner: `tools/runner/main.py`, DNS query helpers reused from `domain_basic`, subdomain normalization, wildcard heuristic, private/reserved IP detection, external CNAME detection, runner tests.
- Frontend: `frontend/src/App.tsx`, `frontend/src/api.ts`, `frontend/src/types.ts`, `frontend/src/SubdomainJobReport.tsx`, `frontend/src/subdomainReport.ts`, `frontend/src/dashboardFilters.ts`, frontend tests.
- Reporting/export: Markdown, HTML, XML, and PDF paths for `subdomain_inventory_basic`.
- Docker/config: `docker-compose.yml`, service networks, mounts, exposed ports, security options, new subdomain environment variables.
- Documentation: `README.md`, `docs/architecture.md`, `docs/security-scope.md`, previous web/domain audit notes.
- Tests and local risk-pattern searches.

## 3. Validations executed

| Command | Result | Observations |
| --- | --- | --- |
| `git status --short` initial | Passed | Working tree was clean. |
| `git log --oneline -10` | Passed | Includes `7395ab9 feat(audits): add controlled subdomain inventory`. |
| `git show --stat --oneline 7395ab9` | Passed | Commit touches 24 files with about 1549 insertions and 24 deletions. |
| `git show --name-only --oneline 7395ab9` | Passed | Reviewed changed backend, runner, frontend, tests, docs, and Compose files. |
| `docker compose config` | Passed | `INSPECTRA_SUBDOMAIN_MAX_CANDIDATES` and `INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS` are present for backend and `audit-tools`; runner remains unexposed and keeps the separate egress-capable network. |
| `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools` | Passed | Python sources compile. |
| `.venv/bin/python -m pytest` inside sandbox | Failed due sandbox | Existing web tests that bind local HTTP servers on `127.0.0.1` fail with `PermissionError` under sandbox socket restrictions. |
| `.venv/bin/python -m pytest` outside sandbox with approval | Passed | `156 passed`; no internet targets were used. |
| `npm run build` in `frontend` | Passed | TypeScript and Vite production build completed. |
| `npm run test -- --run` in `frontend` | Passed | `20 passed`. |
| Risk-pattern searches | Passed with expected hits | No dangerous implementation hits for shell execution, Docker socket, wildcard CORS, Nmap, CT lookup, AXFR, wordlists, brute force, crawling, or CVE lookup. Hits were docs, tests, local healthchecks, dependency lock metadata, or passive parser/reporting strings. |
| `git diff --check` | Passed | No whitespace errors. |
| `git diff --cached --check` | Passed | No staged whitespace errors before commit. |

## 4. Findings

### INSPECTRA-SUBDOMAIN-REVIEW-001

- Severity: medium
- Area: backend, runner
- Status: open
- Evidence: `backend/app/config.py:13-15`, `backend/app/services.py:185-195`, `tools/runner/main.py:1667-1686`
- Description: The backend calculates the runner HTTP timeout for `subdomain_inventory_basic` from candidate count, three DNS record types, up to two wildcard probes, up to three nameservers, and `INSPECTRA_DOMAIN_DNS_TIMEOUT_SECONDS`. With defaults, a 100-candidate job can budget roughly 76 minutes in the worst case: `(100 candidates * 3 record types + 2 probes * 3 record types) * 3 nameservers * 5 seconds + 10 seconds`.
- Impact: This is bounded and not an uncontrolled scan, but it can tie up a background job and an HTTP client connection for a long time if DNS resolvers are slow or unreachable. In local MVP use this is mostly availability/UX risk; in shared deployments it would be more concerning.
- Recommendation: Add a global `subdomain_inventory_basic` deadline or maximum backend runner timeout, and have the runner return a completed/truncated result with controlled timeout findings once the budget is exhausted. Consider lowering the default candidate limit or making the long worst-case budget explicit in docs.
- Priority suggested: P2 before recommending larger candidate lists or shared/lab multiuser usage.

### INSPECTRA-SUBDOMAIN-REVIEW-002

- Severity: low
- Area: backend, runner, docs
- Status: needs-review
- Evidence: `backend/app/main.py:200-205`, `tools/runner/main.py:1432-1507`, `README.md:272-274`
- Description: The public backend rejects the entire request if any candidate is invalid, while the runner and result JSON support per-candidate rejected entries and findings. This is safe and conservative, but it means `candidates_rejected` in normal public-API jobs mostly reflects duplicates, while invalid candidate reporting is only visible if the internal runner endpoint is called directly.
- Impact: A single typo blocks the entire job instead of producing a partial report with accepted and rejected candidates. The split behavior can also make the result schema look richer than the public API path normally allows.
- Recommendation: Decide the intended contract explicitly. Either keep fail-fast public validation and document that all candidates must validate before job creation, or allow partial jobs where invalid candidates are retained as rejected rows and only accepted candidates are resolved.
- Priority suggested: P3 UX/contract cleanup.

### INSPECTRA-SUBDOMAIN-REVIEW-003

- Severity: low
- Area: backend
- Status: open
- Evidence: `backend/app/models.py:78-81`, `backend/app/domain_security.py:52-97`
- Description: `INSPECTRA_SUBDOMAIN_MAX_CANDIDATES` bounds the number of entries, and domain validation bounds normalized names, but there is no request-body limit for JSON payloads and no Pydantic per-field length constraint before FastAPI parses the request body. Very large candidate strings or JSON bodies are rejected eventually, but only after request parsing and initial Python string handling.
- Impact: In the local MVP this is an accepted resource guardrail gap similar to other JSON endpoints. If exposed beyond localhost, it could be used to waste memory/CPU before validation rejects the request.
- Recommendation: Add Pydantic length constraints for `root_domain` and candidate strings, consider a maximum JSON body size at the ASGI/proxy layer, and document that Inspectra remains a local/dev tool unless deployed behind auth and request-size controls.
- Priority suggested: P3 hardening.

### INSPECTRA-SUBDOMAIN-REVIEW-004

- Severity: info
- Area: tests, reporting
- Status: open
- Evidence: `backend/tests/test_backend.py:1349-1375`, `backend/tests/test_backend.py:1379-1509`
- Description: Completed-job report exports for `subdomain_inventory_basic` are tested across Markdown, HTML, XML, and PDF, but sparse queued/running/failed subdomain jobs do not yet have the same regression coverage that `domain_basic` has.
- Impact: The reporting helpers appear tolerant of missing fields, but future changes could introduce a `KeyError` or sparse-result export regression without a dedicated subdomain test catching it.
- Recommendation: Add export tests for queued, running, failed, and completed sparse `subdomain_inventory_basic` jobs, mirroring the existing `domain_basic` sparse export coverage.
- Priority suggested: P4 tests.

### INSPECTRA-SUBDOMAIN-REVIEW-005

- Severity: info
- Area: runner, docs
- Status: accepted-risk
- Evidence: `tools/runner/main.py:1592-1617`, `README.md:274`, `docs/architecture.md:102`, `docs/security-scope.md:60`
- Description: The wildcard-DNS heuristic intentionally generates up to two random DNS names under the root domain. This is documented and bounded, but it is still the only part of the module that queries names not explicitly provided by the user.
- Impact: The behavior remains passive and low volume, but it is worth keeping conceptually separate from inventory. Operators with strict "only submitted names" policies may want to set `INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS=0`.
- Recommendation: Keep as accepted MVP behavior. In a future hardening pass, consider surfacing the setting in UI copy or result metadata more prominently.
- Priority suggested: P4 accepted risk.

## 5. Acceptable MVP risks

- No authentication or authorization layer: acceptable only for local/dev use; do not expose publicly.
- `subdomain_inventory_basic` is a controlled inventory helper, not a discovery engine.
- Wildcard DNS is a heuristic and can produce false positives or false negatives.
- DNS is UDP-only and best-effort through the same small resolver used by `domain_basic`.
- No Certificate Transparency, no external APIs, no wordlists, no brute force, no AXFR.
- No Nmap, no port scanning, no HTTP crawling, no fuzzing, no exploit checks.
- Private/reserved IP and external CNAME findings are indicators for manual review, not confirmed vulnerabilities.
- DNS results can contain operational metadata and should be treated as sensitive inventory data.
- Candidate names provided by users can reveal internal naming conventions.

## 6. Test gaps

Priority order:

1. Add sparse/non-completed export tests for `subdomain_inventory_basic` jobs.
2. Add backend validation tests for root-candidate self reference (`example.com`), trailing dots (`api.` and `api.example.com.`), IPv6 literal candidates, `.local` candidate suffixes, label length, and total domain length.
3. Add runner tests proving no DNS queries are made for rejected candidates, not just that rejected candidates are reported.
4. Add tests for private/reserved IPv6 classes such as `::1`, `fc00::/7`, `fe80::/10`, multicast, and unspecified.
5. Add tests for external CNAME comparison with trailing dots and mixed case.
6. Add frontend test that the Subdomain Inventory button is disabled until authorization confirmation is checked.
7. Add tests for `INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS=0` in backend config and for high values being capped to two probes in runner behavior.

## 7. Documentation gaps

- Document the worst-case subdomain inventory runtime formula or at least warn that large candidate lists with slow resolvers can take a long time.
- Clarify whether invalid candidates are meant to fail the whole public request or appear as rejected rows in the report.
- State explicitly that the submitted root domain itself is rejected as a candidate because this audit is scoped to subdomains.
- Mention that `INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS=0` disables the only automatically generated DNS names.
- Consider adding a short note that private/reserved IP findings are not blocked because internal DNS can be legitimate in authorized lab environments.

## 8. Recommendation for next microphases

1. Address `INSPECTRA-SUBDOMAIN-REVIEW-001` with a global deadline/cap and truncated-result behavior.
2. Decide and document the invalid-candidate contract from `INSPECTRA-SUBDOMAIN-REVIEW-002`.
3. Add the test hardening items from `INSPECTRA-SUBDOMAIN-REVIEW-004` and the prioritized test gaps.
4. Only after those fixes, consider `django_config_basic` or another local/passive module.
5. Add `infra_basic` with Nmap only later, with explicit authorization, target allowlists, strict port/rate controls, and separate documentation.
6. Add Certificate Transparency or CVE/advisory enrichment only after defining explicit online mode, rate limits, data-source trust boundaries, and user consent.

## Follow-up status

- `INSPECTRA-SUBDOMAIN-REVIEW-001`: mitigated in the deadline hardening microfase. `subdomain_inventory_basic` now has `INSPECTRA_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS`, the backend runner timeout is based on that deadline plus one in-flight DNS query budget and a fixed margin, and the runner returns partial/truncated results with skipped candidates and an informational deadline finding when the budget is exhausted.
- `INSPECTRA-SUBDOMAIN-REVIEW-002`: decided and documented as fail-fast for the public API. Any invalid candidate rejects the whole request before job creation and before runner invocation; per-candidate rejected rows remain for duplicates, limits, deadline/skipped states, and internal runner defense.
- `INSPECTRA-SUBDOMAIN-REVIEW-003`: partially mitigated with Pydantic length constraints for root domains and individual candidates, plus explicit tests for oversized strings and label/domain edge cases. General ASGI/proxy request-size limits remain deployment hardening.
- `INSPECTRA-SUBDOMAIN-REVIEW-004`: covered with regression tests for queued, running, failed, and sparse completed `subdomain_inventory_basic` exports across Markdown, HTML, XML, and PDF.
