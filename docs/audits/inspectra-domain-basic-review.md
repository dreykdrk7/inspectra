# Inspectra domain_basic security review

## 1. Executive summary

The `domain_basic` module is integrated coherently with the current Inspectra MVP. The backend requires explicit authorization confirmation, rejects URL-shaped and internal-looking targets, creates jobs without `file_id` using `target_domain`, and delegates analysis to the `audit-tools` runner. The runner keeps the DNS baseline narrow: it queries only bounded record types for the authorized domain, `_dmarc.<domain>`, and `www.<domain>`, parses SPF/DMARC/CAA/MX/NS/SOA/TXT into informational findings, and does not brute-force subdomains, use wordlists, attempt AXFR, call CT logs, crawl, scan ports, run Nmap, or query CVE/reputation services.

Overall recommendation: continue after accepting the low/info items below. No critical or high findings were observed. The main follow-up before broader domain/infrastructure work is to make timeout behavior and DNS parser limitations more explicit, and to add a few targeted tests around validation and wire-format edge cases.

Main strengths:

- Clear public endpoint and internal runner endpoint for `domain_basic`.
- Explicit authorization confirmation in API and UI.
- Domain validation rejects URLs, userinfo, paths, queries, fragments, IP literals, localhost-style names, and reserved/internal suffixes.
- Jobs without `file_id` are compatible with job listing, details, summaries, and report exports.
- Runner scope is bounded to the requested domain, `_dmarc`, and a single `www` baseline.
- Findings use prudent language and stay within `info`, `low`, and `medium`.
- Tests cover backend job creation/rejection, runner DNS summaries/findings/errors, frontend launch/report helpers, and export support.

Main risks:

- Backend request timeout is shorter than the worst-case runner DNS query budget when multiple DNS queries time out.
- The custom DNS client is UDP-only and uses IPv4 nameservers from `/etc/resolv.conf`; truncated answers and IPv6-only resolver environments are best-effort.
- Domain validation and DNS wire parsing have useful but still thin edge-case test coverage.

## 2. Scope reviewed

- Backend: `backend/app/main.py`, `backend/app/models.py`, `backend/app/services.py`, `backend/app/storage.py`, `backend/app/reporting.py`, `backend/app/domain_security.py`, `backend/app/config.py`, backend tests.
- Runner: `tools/runner/main.py`, DNS query/parse helpers, SPF, DMARC, CAA, TXT redaction, runner tests.
- Frontend: `frontend/src/App.tsx`, `frontend/src/api.ts`, `frontend/src/types.ts`, `frontend/src/DomainJobReport.tsx`, `frontend/src/domainReport.ts`, `frontend/src/dashboardFilters.ts`, frontend tests.
- Reporting/export: Markdown, HTML, XML, PDF paths for `domain_basic`.
- Docker: `docker-compose.yml`, service networks, mounts, exposed ports, security options, domain DNS timeout variable.
- Documentation: `README.md`, `docs/architecture.md`, `docs/security-scope.md`, previous audit notes.
- Tests and local risk-pattern searches.

## 3. Validations executed

| Command | Result | Observations |
| --- | --- | --- |
| `git status --short` initial | Passed | Working tree was clean. |
| `git log --oneline -10` | Passed | Includes `161e71a feat(audits): add passive domain DNS baseline`. |
| `docker compose config` | Passed | `INSPECTRA_DOMAIN_DNS_TIMEOUT_SECONDS` is present for backend and `audit-tools`; runner remains unexposed and keeps the separate egress-capable network. |
| `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools` | Passed | Python sources compile. |
| `.venv/bin/python -m pytest` inside sandbox | Failed due sandbox | `95 passed`, `8 failed`; all failures were existing web tests blocked by local server bind/listen on `127.0.0.1` with `PermissionError`. |
| `.venv/bin/python -m pytest` outside sandbox with approval | Passed | `103 passed`; no internet targets were used. |
| `npm run build` in `frontend` | Passed | TypeScript and Vite production build completed. |
| `npm run test -- --run` in `frontend` | Passed | `18 passed`. |
| Risk-pattern searches | Passed with expected hits | No `shell=True`, `os.system`, `eval(`, `exec(`, `dangerouslySetInnerHTML`, `docker.sock`, wildcard CORS, Nmap, subdomain tools, wordlist/bruteforce implementation, AXFR implementation, CT lookup, crawler, or CVE lookup found in reviewed source. Hits were docs, tests, local healthchecks, lock/package metadata, or passive parser strings. |
| `git diff --check` | Passed | No whitespace errors. |
| `git diff --cached --check` | Passed | No staged whitespace errors before commit. |

## 4. Findings

### INSPECTRA-DOMAIN-REVIEW-001

- Severity: low
- Area: backend, runner
- Status: open
- Evidence: `backend/app/services.py:185-187`, `tools/runner/main.py:1257-1278`, `tools/runner/main.py:1312-1331`
- Description: The backend HTTP client timeout for the runner call is `domain_dns_timeout_seconds + 10`, but the runner can perform multiple sequential DNS queries. Each record query can try up to three nameservers with the configured timeout.
- Impact: In a degraded resolver environment, the backend can mark the job failed before the runner finishes its bounded DNS baseline. This is more of a reliability/accuracy risk than a security issue, but it can make `domain_basic` look broken for slow or partially failing DNS.
- Recommendation: In a follow-up microfase, either calculate the backend runner timeout from the maximum DNS query count and nameserver count, or add a runner-level global deadline and return a completed/truncated result with controlled timeout errors.
- Priority suggested: P2 before relying on `domain_basic` in slower lab networks.

### INSPECTRA-DOMAIN-REVIEW-002

- Severity: info
- Area: runner, docs
- Status: accepted-risk
- Evidence: `tools/runner/main.py:1320-1328`, `tools/runner/main.py:1334-1352`, `tools/runner/main.py:1361-1392`
- Description: The DNS client is intentionally small and standard-library based, but it is UDP-only, reads IPv4 nameservers from `/etc/resolv.conf`, does not use EDNS, and does not perform TCP fallback for truncated responses.
- Impact: Domains with large TXT/CAA/SOA responses, DNSSEC-heavy answers, or IPv6-only resolver configuration may produce partial data or controlled errors. The behavior remains passive and bounded, but the report should be interpreted as a baseline, not a complete DNS inventory.
- Recommendation: Keep as accepted MVP behavior and document it more explicitly. If accuracy becomes important, consider `dnspython` or a carefully scoped resolver helper with TCP fallback and IPv6 nameserver support.
- Priority suggested: P3 unless users report incomplete DNS results.

### INSPECTRA-DOMAIN-REVIEW-003

- Severity: info
- Area: tests
- Status: open
- Evidence: `backend/tests/test_backend.py:752-784`, `tools/tests/test_runner.py:868-969`, `backend/app/domain_security.py:14-49`
- Description: Existing tests cover core acceptance/rejection and mocked DNS outcomes, but edge cases are thin for query/fragment/userinfo rejection, IPv6 literals, IDNA normalization, malformed labels, compression pointer parsing, truncated DNS packets, and CAA/SOA wire decoding.
- Impact: The implementation appears conservative, but regressions in validator behavior or DNS parser edge cases could slip through without targeted unit tests.
- Recommendation: Add a small tests-focused microfase covering `normalize_domain` directly in backend and runner, plus parser-level DNS wire fixtures for compressed names, truncation, CAA, SOA, TXT redaction, and response-code handling.
- Priority suggested: P3 before expanding to subdomain inventory.

### INSPECTRA-DOMAIN-REVIEW-004

- Severity: info
- Area: docs
- Status: open
- Evidence: `docs/security-scope.md:56`, `docs/security-scope.md:123-125`
- Description: The security scope correctly describes `domain_basic` as bounded DNS baseline work, but the container-boundary guardrail list still describes the egress-capable network as being for explicit `web_basic` target requests only.
- Impact: This is a documentation precision issue. The Compose configuration already gives `audit-tools` an egress-capable network used by both `web_basic` and `domain_basic`, so the scope page should avoid implying DNS egress is not part of the runtime model.
- Recommendation: Update the container-boundary bullets to mention bounded `domain_basic` DNS queries and `INSPECTRA_DOMAIN_DNS_TIMEOUT_SECONDS` alongside the web controls.
- Priority suggested: P4 documentation cleanup.

## 5. Acceptable MVP risks

- No authentication or authorization layer: acceptable only for local/dev use; do not expose publicly.
- `domain_basic` is a DNS baseline, not a deep DNS scanner.
- No AXFR, no zone transfer attempts, no reverse DNS sweeps.
- No DKIM selector discovery or selector wordlists.
- No Certificate Transparency queries.
- No subdomain inventory or brute-force enumeration.
- No Nmap, no port scanning, no crawling, no fuzzing, no exploit checks.
- No CVE enrichment or external reputation/API lookups.
- DNS results may include TXT, SOA contact-style values, MX/NS hostnames, and other operational metadata; treat stored results as potentially sensitive.
- Findings are indicators for manual review, not confirmed vulnerabilities.
- DNS answers depend on the runner's configured resolver and network environment.

## 6. Test gaps

Priority order:

1. Direct unit tests for backend and runner domain normalization: query, fragment, userinfo, IPv6 literal, IDNA, invalid labels, and reserved suffixes.
2. Parser-level DNS wire fixtures for CAA, SOA, TXT chunk handling, compression pointers, truncation bit, NXDOMAIN, SERVFAIL, and malformed packets.
3. Test that `www.<domain>` is skipped when the submitted domain already starts with `www.`.
4. Test that `dns_nameservers()` handles no nameservers and documents/returns IPv4-only behavior.
5. Frontend test that the Domain audit button is disabled until authorization confirmation is checked.
6. Export regression tests for queued/running/failed `domain_basic` jobs with sparse result fields.

## 7. Documentation gaps

- Clarify in `docs/security-scope.md` that the egress-capable runner network supports both authorized `web_basic` HTTP/HTTPS requests and bounded `domain_basic` DNS queries.
- Document the DNS client as UDP-only/best-effort and without TCP fallback in README or architecture.
- Make it explicit that DNS result JSON can contain operational metadata from TXT, SOA, NS, and MX records.
- If a future resolver dependency is added, document the dependency choice and whether DNS lookups still use only the system resolver.

## 8. Recommendation for next microphases

1. No critical/high fixes are required before continuing.
2. Address low/medium domain hardening before expanding domain capabilities:
   - align backend runner timeout with worst-case DNS baseline duration,
   - add parser/validator tests,
   - tighten documentation around DNS egress and UDP-only behavior.
3. Add subdomain inventory only as a passive/controlled module with explicit sources or strict limits; avoid brute force and wordlists.
4. Add `django_config_basic` for uploaded/local config artifacts before internet-facing framework probes.
5. Add `infra_basic` with Nmap only later, with explicit authorization, target allowlists, strict port/rate controls, and separate documentation.
6. Add CVE/advisory enrichment only after defining offline/online modes and data-source trust boundaries.

## Follow-up status

- `INSPECTRA-DOMAIN-REVIEW-001`: mitigated in the timeout hardening microfase. The backend now calculates the runner HTTP timeout from the bounded domain query set, the runner's maximum nameserver attempts, and a fixed margin instead of using `INSPECTRA_DOMAIN_DNS_TIMEOUT_SECONDS + 10`.
- `INSPECTRA-DOMAIN-REVIEW-003`: mostly addressed for MVP. Added direct domain validation coverage, DNS parser wire-format tests for core record types, compression pointers, truncation, response codes, malformed packets, TXT chunking, TXT redaction, string truncation, `www` baseline skip behavior, IPv4-only resolver parsing, no-resolver behavior, and sparse/non-completed export regression tests. Full resolver integration behavior remains future work.
- `INSPECTRA-DOMAIN-REVIEW-004`: addressed in documentation. The security scope now states that the egress-capable runner network supports both authorized web HTTP/HTTPS requests and bounded domain DNS queries, and notes that domain DNS results can contain operational metadata.
