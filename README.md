# Inspectra

Inspectra is a lightweight, open source MVP for defensive and educational security audits. It is local-first and self-hosted-first: people and teams should be able to install it on their own machine or server to audit their own projects and explicitly authorized targets. It is not a commercial SaaS, subscription platform, enterprise multi-tenant service, or scan-as-a-service product. The current phase focuses on passive local file inspection plus controlled baseline web and DNS audits inside Docker containers so audit tools do not need to be installed on the host system.

This project is intentionally small: a FastAPI backend, a containerized tool runner, local job/result storage, and clear boundaries for authorized use.

## Passive Alpha At A Glance

Inspectra Passive Alpha is an open-source, altruistic, local-first, and self-hosted-first security audit workbench for defensive review of projects and artifacts you own or are explicitly authorized to assess. It focuses on passive local analysis: uploaded files and archives, configuration review, dependency and package metadata, local reports, SBOM exports, Raw JSON, and redacted evidence.

It is not a commercial SaaS, billing platform, tenant system, quota product, paid-plan product, production-ready service, public/community hosting package, or general active scanner.

### Current Use Modes

`trusted_local_no_auth` is the default localhost/dev/local trusted mode. Use it only on a trusted local workstation with no network exposure, no public reverse proxy, and no third-party access.

`self_hosted_single_admin` is the private self-hosted alpha mode. It requires a supported admin password hash and provides login/logout, an `HttpOnly` session cookie, CSRF checks on mutating cookie-auth routes, owner-scoped sensitive routes, generic `401` responses, controlled login `429` handling, optional SQLite-backed persistent sessions and login-attempt lockout state, and no frontend `localStorage` or `sessionStorage` auth state. It remains private alpha behavior, not production, public/community, or multi-user readiness.

### Deployment Hardening

For any use outside localhost, the current guidance expects HTTPS/TLS, a reverse proxy in front of the app, no direct backend exposure to the internet, explicit allowed origins, no wildcard CORS with credentials, and logs that avoid secrets, cookies, tokens, request bodies, Raw JSON, report contents, and SBOM contents. SQLite-backed persistent sessions and login-attempt lockout state are available only when explicitly enabled for `self_hosted_single_admin`; secure-cookie runtime enforcement, trusted-proxy runtime enforcement, and admin recovery/setup guidance remain known gaps until separately designed and implemented.

Reference docs:

- self-hosted alpha release notes: `docs/future/passive-alpha-self-hosted-release-notes.md`
- deployment hardening design: `docs/future/passive-alpha-deployment-hardening-design.md`
- deployment hardening runbook: `docs/future/passive-alpha-deployment-hardening-runbook.md`
- deployment hardening closeout: `docs/future/passive-alpha-deployment-hardening-closeout.md`
- persistent auth state design: `docs/future/passive-alpha-persistent-auth-state-design.md`
- SQLite auth store scaffold: `docs/future/passive-alpha-sqlite-auth-store-scaffold.md`
- persistent session store integration: `docs/future/passive-alpha-persistent-session-store-integration.md`
- persistent login-attempt store design: `docs/future/passive-alpha-persistent-login-attempt-store-design.md`
- persistent login-attempt store integration: `docs/future/passive-alpha-persistent-login-attempt-store-integration.md`
- auth-state cleanup and rotation design: `docs/future/passive-alpha-auth-state-cleanup-rotation-design.md`
- auth-state cleanup and rotation smoke: `docs/future/passive-alpha-auth-state-cleanup-rotation-smoke.md`
- persistent auth closeout: `docs/future/passive-alpha-persistent-auth-closeout.md`
- persistent auth final regression smoke: `docs/future/passive-alpha-persistent-auth-final-regression-smoke.md`
- release candidate checklist: `docs/future/passive-alpha-release-candidate-checklist.md`
- tag/release prep: `docs/future/passive-alpha-tag-release-prep.md`
- post-release technical pause: `docs/future/passive-alpha-post-release-technical-pause.md`

### What Passive Alpha Does Not Promise

- No exposed production deployment approval.
- No public/community readiness.
- No SaaS.
- No billing.
- No tenant billing.
- No subscriptions.
- No quotas.
- No paid plans.
- No enterprise tenancy.
- No OAuth/OIDC.
- No multi-user runtime.
- No persistent sessions or login-attempt store by default; SQLite-backed auth state is opt-in for private `self_hosted_single_admin`.
- No admin recovery yet.
- No Docker execution as a deployment guarantee.
- No Nmap.
- No port scanning.
- No crawling.
- No probes.
- No DNS expansion.
- No external HTTP or live target expansion beyond separately documented authorized target flows.

### Immediate Roadmap

1. Passive Alpha `v0.1.0-alpha.1` publication is complete.
2. Product technical pause is recorded in `docs/future/passive-alpha-post-release-technical-pause.md`.
3. Active Nmap Basic design is frozen in `docs/future/active-nmap-basic-design.md` as docs-only future scope; no Nmap runtime, port-scanning implementation, or broader Active capability is added.
4. Active Nmap Basic implementation planning is frozen in `docs/future/active-nmap-basic-implementation-plan.md` as docs-only future sequencing.
5. Active Nmap Basic Microphase 01 added the initial backend contract gate: `POST /active/network/nmap-basic` is disabled by default through `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=false`; when explicitly enabled it validates the exact request contract before any later job lifecycle.
6. Active Nmap Basic Microphase 08 adds only a frontend informational panel shell. It can show disabled/prepared availability copy and guardrails, but it has no submit, creates no jobs, does not call the backend Nmap contract, does not render full Nmap reports, and is not connected to archive/run-all actions.
7. Active Nmap Basic Microphase 09 wires the frontend form to the existing backend contract gate only. The UI requires one explicit target, bounded numeric TCP ports, fixed `live_nmap_basic` / `tcp_connect_small`, and the three confirmations; backend `403` and current `501` / `not_executed` states are controlled and no real Nmap jobs are created.
8. Active Nmap Basic Microphase 10 renders already-structured frontend reports and redacted Raw JSON only. It adds no backend runtime, runner connection, real Nmap jobs, raw XML display, CVE matching, archive/run-all integration, or vulnerability/exploitability claims.
9. Active Nmap Basic Microphase 12 creates real Inspectra jobs only when the feature flag is explicitly enabled, but wires them only to a backend no-live test-double. Jobs are owner-scoped, target-based with `file_id: null`, and complete with `not_executed` metadata; no real Nmap, executor call, subprocess, Docker, DNS, probes, external HTTP, runner endpoint, archive/run-all integration, or `tools/runner/main.py` integration is added.
10. Active Nmap Basic Microphase 15 plans the first local smoke as no-live fake/mocked adapter validation only; real local Nmap smoke remains blocked until a later phase freezes an exact loopback/local controlled target, and VPS/domain smoke remains blocked for the first smoke.
11. Active Nmap Basic Microphase 16 executed the first no-live smoke with fake/mocked adapters only. Backend, active-runner fake-based, frontend, build, compile, and source-search validations passed without Nmap, Docker, probes, DNS checks, external HTTP traffic, real external targets, VPS/domain smoke, backend subprocesses, runner HTTP endpoints, archive/run-all, or `tools/runner/main.py` integration.
12. Active Nmap Basic Microphase 17 freezes a future real local smoke target to numeric loopback `127.0.0.1` and port `[65000]` only. It writes future commands and cleanup/no-go criteria but does not execute Nmap, change runtime, use `localhost`, use a domain/VPS/LAN target, or approve real execution.
13. Active Nmap Basic Microphase 18 attempted the first real local smoke preflight, but `command -v nmap` found no local Nmap binary. The phase is blocked as `ACTIVE_NMAP_BASIC_18_REAL_LOCAL_SMOKE_EXECUTION_BLOCKED_NMAP_MISSING`; no Nmap install, Docker, backend smoke server, live request, job, export, DNS, external HTTP, target change, or port change occurred.
14. Active Nmap Basic Microphase 19 recommends packaging Nmap inside a separate Dockerized Active runner/image such as `active-tools`, not as a normal host-local manual install and not inside the passive runner monolith. It is docs-only and makes no Dockerfile, Compose, runtime, or Nmap execution changes.
15. Active Nmap Basic Microphase 20 designs the future `active-tools` Docker/Compose architecture: separate Active service/image, disabled by default, no public port by default, no host network by default, no privileged container, no Docker socket, and no passive runner absorption. It is docs-only and makes no Dockerfile, Compose, runtime, build, container, or Nmap execution changes.
16. Active Nmap Basic Microphase 21 adds a no-run `active-tools` Docker scaffold: Dockerfile, Dockerfile-specific ignore, separate Compose example, and static guardrail tests. It does not modify the main Compose file, build images, run Docker, execute Nmap, change runtime, add endpoints, or approve targets.
17. Active Nmap Basic Microphase 22 statically reviews the `active-tools` Docker scaffold and passes it only for a future separately approved build-only phase. It does not build images, run Docker, start containers, execute Nmap, change runtime, add endpoints, or approve targets.
18. Active Nmap Basic Microphase 23 builds the `active-tools` scaffold image with a temporary local tag and inspects image metadata only. It does not start containers, run Nmap, execute commands inside the image, change runtime, add endpoints, or approve targets.
19. Active Nmap Basic Microphase 24 starts the built `active-tools` image once with `--network none` and strict no-target runtime flags, then exits after controlled scaffold readiness JSON. It does not run Nmap, use Compose, publish ports, change runtime, add endpoints, or approve targets.
20. Active Nmap Basic Microphase 25 runs only `nmap --version` inside the built image with `--network none` and strict no-target runtime flags. It observes Nmap `7.95` without target, scan, probes, DNS/HTTP target traffic, Compose, runtime changes, endpoints, or target approval.
21. Active Nmap Basic Microphase 26 freezes the first future Dockerized target-bearing smoke semantics to container loopback `127.0.0.1`, port `65000`, and `--network none` only. It is docs-only, runs no Docker or Nmap, and does not approve owned domains, LAN/VPS/public targets, Compose service targets, endpoints, or backend integration.
22. Active Nmap Basic Microphase 27 runs exactly one target-bearing `active-tools` container-loopback smoke against `127.0.0.1:65000` with `--network none`, observing a closed port. It does not approve host exposure claims, domains, LAN/VPS/public targets, Compose, backend integration, endpoints, jobs, or exports.
23. Active Nmap Basic Microphase 28 freezes `www.urlbreve.es:443` as the first future own-domain smoke candidate and documents DNS semantics for a later execution. It is docs-only, runs no Docker/Nmap/DNS/HTTP checks, and keeps `www.vildek.es`, `app.vildek.es`, port `80`, LAN/VPS/public targets, endpoints, jobs, and exports blocked.
24. Active Nmap Basic Microphase 29 runs exactly one own-domain `active-tools` smoke against `www.urlbreve.es:443`; Nmap reports `443/tcp` as open. This is only an observed TCP exposure / review indicator and does not approve vulnerabilities, exploitability, target safety, `www.vildek.es`, `app.vildek.es`, port `80`, backend integration, jobs, exports, or public scanner behavior.
25. Active Nmap Basic Microphase 30 closes the technical smoke v0 block as docs-only. It approves `active-tools` as viable packaging and preserves the `www.urlbreve.es:443` run as historical evidence only, while keeping backend integration, jobs, exports, runner endpoints, `www.vildek.es`, `app.vildek.es`, port `80`, multi-domain scans, LAN/VPS/public expansion, and public scanner behavior blocked.
26. Active Nmap Basic Microphase 31 designs real-output parser/redaction hardening. PTR hostnames, reverse-DNS data, raw XML, raw args, stdout/stderr, service/banner/version details, stylesheet references, and default resolved-IP display for FQDN targets remain out of future report/export/Raw JSON surfaces.
27. Active Nmap Basic Microphase 32 adds synthetic XML fixtures and offline parser/redaction tests only. It hardens pure helper behavior for PTR/IP/raw args omission, accepted-port checks, multi-host and script-output rejection, and observed exposure review-indicator metadata without Docker, Nmap, DNS/HTTP checks, runtime wiring, jobs, exports, or new target approval.
28. Active Nmap Basic Microphase 33 adds backend/report/export/Raw JSON redaction coverage for synthetic real-shape payloads only. It keeps PTR, FQDN resolved IPs, raw XML/args, stdout/stderr, service/banner/version, stylesheet, script/NSE-like output, credentials, headers, cookies, and tokens out of backend surfaces without live runtime, active-tools jobs, Docker, Nmap, DNS/HTTP checks, or new target approval.
29. Active Nmap Basic Microphase 34 designs the future backend-to-active-tools boundary as docs-only. It prefers a private internal service boundary with backend-owned auth/owner scope/validation/jobs/redaction and `active-tools` as bounded executor only, while rejecting backend direct subprocess/import, Docker socket control, public scanner behavior, archive/run-all, and `tools/runner/main.py` integration.
30. Active Nmap Basic Microphase 35 adds no-live backend boundary contract tests and pure helpers only. It validates request units, response allowlists, controlled errors, policy drift, redaction, owner scope, and source-boundary absence without an active-tools endpoint, backend live call, Docker, Nmap, Compose, archive/run-all, or `tools/runner/main.py` integration.
31. Active Nmap Basic Microphase 36 adds a pure internal `active-tools` service skeleton only. It provides offline-testable health and `active_nmap_basic` no-scan handlers that return controlled readiness/not-executed states and reject dangerous fields without Docker, Compose, Nmap, backend live calls, public endpoints, real jobs, exports, archive/run-all, or `tools/runner/main.py` integration.
32. Active Nmap Basic Microphase 37 hardens the pure `active-tools` health/readiness handler. Health now accepts only absent/empty payloads, returns stable `disabled_no_scan` metadata, and blocks target/port/credential/header/cookie/token/command/script/NSE payloads without Docker, Compose, Nmap, backend live calls, public endpoints, fake execution, jobs, exports, archive/run-all, or `tools/runner/main.py` integration.
33. Active Nmap Basic Microphase 38 adds a fake/no-live execution path through the pure internal `active-tools` boundary only when tests inject an explicit fake executor. The default remains `not_executed`; fake responses are allowlisted, redacted, port-bounded, and worded as observed exposure / review indicators without Docker, Compose, Nmap, backend live calls, public endpoints, real jobs, exports, archive/run-all, or `tools/runner/main.py` integration.
34. Active Nmap Basic Microphase 39 adds a minimal internal ASGI app skeleton for `active-tools`, reusing the pure handlers for `GET /health` and `POST /active/nmap-basic`. It remains no-live: no server start, backend live call, Docker/Compose/Nmap execution, real jobs, exports, archive/run-all, frontend runtime, new target approval, or `tools/runner/main.py` integration.
35. Active Nmap Basic Microphase 40 validates the `active-tools` ASGI app inside the container with a loopback-only `/health` smoke. It adds minimal FastAPI/Uvicorn packaging, preserves the default no-run command, and confirms `scaffold_ready` / `disabled_no_scan` with zero network requests and no Nmap execution, backend live call, jobs, exports, Compose runtime wiring, frontend runtime, new target approval, or `tools/runner/main.py` integration.
36. Active Nmap Basic Microphase 41 validates the containerized `POST /active/nmap-basic` route with a synthetic `127.0.0.1:65000` backend-boundary payload. It returns `not_executed`, no observations, `job_created: false`, zero network requests, and no Nmap execution, backend live call, jobs, exports, Compose runtime wiring, frontend runtime, target approval, or `tools/runner/main.py` integration.
37. Active Nmap Basic Microphase 42 wires `active-tools` as an optional Compose internal ASGI service behind profile `active`. The service publishes no host ports, uses an internal network and no-new-privileges/read-only/tmpfs/cap-drop guardrails, and its Compose smoke returns `/health` plus `POST /active/nmap-basic` no-live responses without Nmap execution, backend live calls, jobs, exports, main Compose runtime wiring, frontend runtime, target approval, or `tools/runner/main.py` integration.
38. Active Nmap Basic Microphase 43 adds a backend `active-tools` `/health` client/helper with default-empty configuration and fake-transport tests. It validates allowlisted readiness fields and controlled error states without backend runtime invocation, `/active/nmap-basic` calls, Nmap execution, jobs, exports, frontend runtime, archive/run-all, or `tools/runner/main.py` integration.
39. Active Nmap Basic Microphase 44 smoke-tests the backend `check_active_tools_health` helper against the Compose-started `active-tools` service through the internal Docker network only. The helper returns `available: true`, `scaffold_ready`, `disabled_no_scan`, `target_input_allowed: false`, `network_requests_sent: 0`, and `nmap_executed: false` without calling `/active/nmap-basic`, executing Nmap, creating jobs/exports, touching frontend runtime, archive/run-all, or `tools/runner/main.py`.
40. Active Nmap Basic Microphase 45 adds a controlled backend `GET /health/active-tools` runtime surface for targetless `active-tools` readiness. It rejects query/body input, uses default-empty `INSPECTRA_ACTIVE_TOOLS_URL`, maps unconfigured/unavailable states into controlled health metadata, and does not call `/active/nmap-basic`, execute Nmap, accept targets, create jobs/exports, touch frontend runtime, archive/run-all, or `tools/runner/main.py`.
41. Active Nmap Basic Microphase 46 adds a backend `run_active_nmap_basic` client contract for the internal `active-tools` `/active/nmap-basic` endpoint, tested only with fake transport. It validates bounded request and no-live `not_executed` response shape, preserves `execution_enabled: false`, `target_input_allowed: false`, `network_requests_sent: 0`, and `nmap_executed: false`, rejects dangerous fields/flags, and is not invoked by routes, jobs, exports, frontend, archive/run-all, or `tools/runner/main.py`.
42. Active Nmap Basic Microphase 47 adds an isolated backend lifecycle skeleton for a future `active_nmap_basic` job using only an injected fake/no-live client. It models blocked-unconfigured, blocked-missing-approval, controlled client-error, and completed-no-live states without creating jobs, persisting storage, calling real `active-tools`, executing Nmap, accepting targets through a new route, touching frontend, exports, archive/run-all, or `tools/runner/main.py`.
43. Active Nmap Basic Microphase 48 connects the existing `POST /active/network/nmap-basic` route to that lifecycle skeleton in no-live/fake-client mode only. Enabled requests now return controlled lifecycle metadata directly with `job_created: false`, `storage_persisted: false`, `active_tools_real_call_allowed: false`, `network_requests_sent: 0`, and `nmap_executed: false`; the route creates no persistent jobs, exports, frontend changes, archive/run-all integration, or `tools/runner/main.py` integration.
44. Active Nmap Basic Microphase 49 freezes a docs-only design for future no-live job persistence after lifecycle completion. It keeps persistence owner-scoped, `file_id: null`, redacted before write, and explicit that `not_executed` / `completed_no_live` are not live execution states; it adds no storage runtime, jobs, exports, frontend changes, active-tools calls, Nmap execution, archive/run-all, or `tools/runner/main.py` integration.
45. Active Nmap Basic Microphase 50 reintroduces backend no-live persistence for valid enabled route calls after lifecycle validation. It creates at most one owner-scoped `active_nmap_basic` job with `file_id: null`, `[REDACTED_TARGET]`, and an allowlisted no-live result that records no Nmap, no network/DNS requests, no evidence, and no observations; it adds no real active-tools call, frontend runtime, export implementation, archive/run-all integration, or `tools/runner/main.py` integration.
46. Active Nmap Basic Microphase 51 hardens existing backend job surfaces for no-live jobs. Detail, list, Raw JSON-style job output, and existing report/export routes now carry explicit no-live caveats and omit no-live-incompatible raw target, payload, command, output, service, credential/header/cookie/token, observation, and evidence fields.
47. Active Nmap Basic Microphase 52 connects the existing frontend panel to the backend no-live `202 JobRecord` behavior. Successful submits select the returned `active_nmap_basic` job, refresh the jobs list, and render no-live caveats: no Nmap executed, no network/DNS requests, no evidence, no observations, and manual validation required. The UI keeps targets redacted and does not add real active-tools calls, backend runtime, exports, archive/run-all, Docker/Compose, or `tools/runner/main.py` integration.
48. Active Nmap Basic Microphase 53 validates the no-live product flow end to end with in-process backend tests and mocked frontend tests: submit contract, `202 JobRecord`, list refresh, selected job report, Raw JSON redaction, and owner-scope checks. It adds no real active-tools calls, Nmap execution, external traffic, Docker/Compose, archive/run-all, or `tools/runner/main.py` integration.
49. Active Nmap Basic Microphase 54 wires the minimal real path through backend -> internal `active-tools` -> bounded Nmap executor only when the backend feature flag, internal active-tools URL, request contract, target policy, confirmations, and active-tools execution flag are all explicitly enabled. Jobs remain owner-scoped, target-redacted, `file_id: null`, and report minimal TCP observations only as observed exposure / review indicators requiring manual validation; the backend still runs no subprocesses and the flow adds no public scanner behavior, archive/run-all, `tools/runner/main.py`, release, tag, or push state.
50. Active Nmap Basic Microphase 55 reviews and hardens the real minimal integration. Backend active-tools URLs now fail closed unless they are internal/local service URLs, observation state/reason values are allowlisted across active-tools, backend boundary, and lifecycle layers, and review evidence confirms backend has no Nmap/subprocess/Docker execution path while storage, reports, frontend, and Compose remain redaction-first and bounded.
51. Active Nmap Basic Microphase 56 closes Active / Nmap basic v0 as a functional minimum for self-hosted/local/private use: disabled by default, explicit opt-in, backend policy/lifecycle/storage/reporting authority, Nmap execution isolated to internal `active-tools`, owner-scoped redacted jobs, redaction-first UI/reports/Raw JSON, and observed TCP exposure / review-indicator wording with manual validation required.
52. Active Nmap Basic Microphase 57 adds operational usage guidance for local/private/self-hosted deployments: required flags, internal `active-tools` URL requirements, static Compose config review, targetless health checks, bounded target policy, loopback/local example shape, troubleshooting, and redaction/report wording. It adds no runtime features, Nmap execution, Docker runtime smoke, archive/run-all, release, tag, or push state.
53. Any future `active_nmap_basic` expansion must be separately approved, disabled by default, opt-in, local/private/self-hosted, explicitly authorized, bounded, redaction-first, and worded as observed exposure or review indicators.
54. Active TLS Basic Microphase 01 freezes a docs-only design for a future `active_tls_basic` capability: one explicit authorized local/private/self-hosted target, one bounded port, explicit confirmations, short timeout, redaction-first owner-scoped jobs, bounded TLS handshake/certificate review indicators, and no runtime implementation, sockets, OpenSSL command, Python `ssl` connection, Nmap, Docker, crawling, credentials, archive/run-all, `tools/runner/main.py`, release, tag, or push state.
55. Active TLS Basic Microphase 02 adds the backend contract gate `POST /active/network/tls-basic`, disabled by default through `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED=false`. Enabled valid requests validate the exact `live_tls_basic` / `tls_handshake_summary` contract and return a controlled `not_executed` response with no TLS handshake, sockets, DNS, HTTP, jobs, storage, frontend, reports/exports, archive/run-all, or `tools/runner/main.py`.
56. Active TLS Basic Microphase 03 turns the same gated backend contract into a real-minimal TLS handshake job: one validated target, one bounded port, Python `socket`/`ssl` only in `backend/app/active_tls_basic.py`, owner-scoped `active_tls_basic` `JobRecord` with `file_id: null`, redacted target, bounded certificate summary, review-indicator wording, and no OpenSSL shell, subprocess, Nmap, Docker, HTTP/crawling, frontend, archive/run-all, or `tools/runner/main.py`.
57. Active TLS Basic Microphase 04 connects the frontend to the real-minimal backend job contract with mocked product smoke coverage. The UI sends the exact `live_tls_basic` / `tls_handshake_summary` request, selects the returned `202 JobRecord`, refreshes jobs, and renders TLS handshake/certificate expiry review indicators with redacted Raw JSON. It adds no new real target execution, OpenSSL, subprocess, Nmap, Docker, HTTP/crawling, archive/run-all, `tools/runner/main.py`, release, tag, or push state.
58. Active TLS Basic Microphase 05 closes `active_tls_basic` v0 functionally as a bounded self-hosted/local/private capability: disabled by default, exact contract, one target, one TLS-basic port, one bounded handshake, owner-scoped `file_id: null` jobs, redacted target/certificate surfaces, frontend review-indicator rendering, and no new target execution, OpenSSL command, subprocess, Nmap, Docker/Compose, HTTP/crawling, archive/run-all, `tools/runner/main.py`, release, tag, or push state.
59. Active DNS Inventory Microphase 01 freezes a docs-only design for future `active_dns_inventory`: one authorized root domain, exact confirmations, bounded standard DNS records, controlled subdomain discovery, explicit coverage levels, future AXFR/provider-import phases, owner-scoped redaction, and no runtime DNS queries, sockets, subprocess, Nmap, Docker, HTTP, archive/run-all, or `tools/runner/main.py` behavior.
60. Active DNS Inventory Microphase 02 adds the backend contract gate `POST /active/network/dns-inventory`, disabled by default through `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=false`. Enabled valid requests validate the exact future contract and return `not_executed` with zero DNS/subdomain queries, no AXFR/provider import, no jobs, no storage, and redacted domain output.
61. Active DNS Inventory Microphase 03 persists bounded DNS inventory jobs behind the same disabled-by-default gate. Enabled valid requests now create owner-scoped `active_dns_inventory` `JobRecord`s with `file_id: null`, `[REDACTED_DOMAIN]`, allowlisted standard record groups, SPF/DMARC/CAA review indicators, fixed-candidate subdomain counts, controlled `best_effort_inventory` / `partial_inventory` coverage, and redaction-first detail/list/export surfaces. DNS runtime is isolated to `backend/app/active_dns_inventory.py`; tests use fake resolvers, and the phase adds no frontend, Nmap, Docker, HTTP, AXFR, provider import, archive/run-all, or `tools/runner/main.py`.
62. Active DNS Inventory Microphase 04 reviews and hardens the backend runtime boundary. Query accounting now matches actual UDP send caps by using a single configured nameserver per query, public limit metadata avoids raw-domain wording, and the review confirms no AXFR/provider/CT/passive DNS, no DNS CLI/subprocess, no Nmap/Docker/HTTP, bounded subdomain discovery, redaction-first storage/reporting, and no complete-coverage claims.
63. Active DNS Inventory Microphase 05 connects the frontend to the existing backend contract with a separate `Active / DNS inventory` panel, exact request body, required confirmations, default `attempt_zone_transfer: false`, grouped-record rendering, SPF/DMARC/CAA indicators, bounded subdomain summary, and redacted Raw JSON. It adds no new DNS runtime, AXFR/provider/CT/passive DNS, subprocess/DNS CLI, Nmap, Docker, HTTP, archive/run-all, or `tools/runner/main.py`.
64. Active DNS Inventory Microphase 06 closes `active_dns_inventory` v0 as a bounded functional minimum: disabled by default, one explicit authorized root domain, allowlisted standard records, SPF/DMARC/CAA review indicators, fixed-candidate subdomain discovery, owner-scoped redacted jobs, `best_effort_inventory` / `partial_inventory` coverage only, redaction-first reports/Raw JSON/frontend, and no AXFR, provider import, CT/passive DNS, DNS CLI/subprocess, Nmap, Docker, HTTP/crawling, archive/run-all, `tools/runner/main.py`, public scanner behavior, or complete-coverage claims.
65. Active DNS Inventory Microphase 07 adds backend-only authorized AXFR as a separate bounded submodule. The endpoint accepts `attempt_zone_transfer: true` only with `zone_transfer_authorized_confirmed: true`, tries at most one authoritative nameserver for the exact domain, persists only redacted counters/allowlisted record groups, and uses `zone_transfer_complete` only when bounded authorized AXFR succeeds. Refused, unavailable, timed-out, malformed, or oversized AXFR remains controlled best-effort/partial inventory. It adds no frontend AXFR control, provider import, CT/passive DNS, DNS CLI/subprocess, Nmap, Docker, HTTP, archive/run-all, `tools/runner/main.py`, public scanner behavior, or vulnerability claims.
66. Active DNS Inventory Microphase 08 reviews and hardens the authorized AXFR backend. The review fixes a blocker so `zone_transfer_complete` now requires a terminal SOA pair; incomplete AXFR responses become controlled malformed/partial inventory. It also keeps attempted-NS counters tied to valid bounded candidates and caps parsed TXT values internally. No frontend, provider API, CT/passive DNS, DNS CLI/subprocess, Nmap, Docker, HTTP, archive/run-all, `tools/runner/main.py`, release, tag, or push behavior is added.
67. Active DNS Inventory Microphase 09 exposes authorized AXFR in the DNS inventory UI behind an explicit optional checkbox and a separate `zone_transfer_authorized_confirmed` confirmation. The frontend still sends `attempt_zone_transfer: false` by default, renders AXFR states/counters as controlled DNS configuration review indicators, treats `zone_transfer_complete` as high-risk manual-review evidence only, and keeps Raw JSON redaction-first. Tests use mocked product flows only; no real AXFR, new DNS traffic, provider import, CT/passive DNS, DNS CLI/subprocess, Nmap, Docker, HTTP, archive/run-all, `tools/runner/main.py`, release, tag, or push behavior is added.
68. Active DNS Inventory Microphase 10 reviews the authorized AXFR frontend boundary introduced in `fb01b7c`. The review confirms AXFR remains off by default, requires the specific confirmation, sends the correct request contract, renders AXFR outcomes conservatively, keeps report/Raw JSON redaction-first, and adds no runtime DNS, AXFR execution, provider/CT/passive DNS, subprocess/DNS CLI, Nmap, Docker, HTTP, archive/run-all, `tools/runner/main.py`, release, tag, or push behavior.
69. Active DNS Inventory Microphase 11 closes `active_dns_inventory` v0 with authorized AXFR and freezes the product direction as attacker-equivalent DNS visibility, not privileged provider administration. The accepted state is disabled by default, one explicit authorized domain, allowlisted records, SPF/DMARC/CAA indicators, bounded subdomain discovery, optional specifically confirmed AXFR against authoritative nameservers for the exact domain, terminal-SOA validation before `zone_transfer_complete`, owner-scoped `[REDACTED_DOMAIN]` jobs, redaction-first reports/Raw JSON/frontend, and manual validation required. It adds no provider import in core Active DNS, CT/passive DNS in this block, broad discovery, DNS CLI/subprocess, Nmap, Docker, HTTP/crawling, archive/run-all, `tools/runner/main.py`, release, tag, or push behavior.
70. Active DNS OSINT Microphase 01 freezes a docs-only design for a separate `active_dns_osint` capability. It keeps core DNS attacker-equivalent, starts with future bounded Certificate Transparency discovery, defers passive DNS to a later source-specific phase, keeps provider DNS/API import out of core Active DNS, and requires one authorized domain, explicit public-OSINT confirmation, source caps, retained-name caps, owner-scoped redaction, `osint_best_effort` coverage, and manual validation. It adds no runtime CT/passive DNS queries, HTTP requests, DNS queries, provider credentials, crawling, scraping, Nmap, Docker, subprocess, archive/run-all, `tools/runner/main.py`, release, tag, or push behavior.
71. Active DNS OSINT Microphase 02 adds the backend contract gate `POST /active/network/dns-osint`, disabled by default through `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=false`. Enabled valid requests validate the exact future `live_dns_osint` / `ct_subdomain_discovery_bounded` contract and return controlled `not_executed` metadata with zero external/CT/passive-DNS queries, no jobs, no storage, and redacted domain output.
72. Active DNS OSINT Microphase 03 persists backend `active_dns_osint` jobs from an injectable fakeable CT source adapter. Enabled valid requests now create owner-scoped `file_id: null` jobs with `[REDACTED_DOMAIN]`, `coverage_level: osint_best_effort`, source status, observed-name counters, placeholder samples, truncation state, and manual-validation wording. The default CT source is disabled and tests use fakes only; the phase adds no real CT, HTTP, DNS, passive-DNS, provider API, frontend runtime, archive/run-all, `tools/runner/main.py`, Nmap, Docker, subprocess, release, tag, or push behavior.
73. Active DNS OSINT Microphase 04 reviews the CT bounded backend persistence from `d233d51`. The review confirms the feature flag stays disabled by default, disabled/invalid/auth-blocked requests do not call sources, the default CT source remains disabled, fake sources stay test-only, observed names are in-domain bounded/redacted, storage/reporting/export/Raw JSON remain redaction-first, and OSINT best-effort is not presented as exhaustive coverage or a vulnerability/exploitability/target-safety claim. No functional blockers were found.
74. Active DNS OSINT Microphase 05 adds a bounded real `crt.sh` CT source behind `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED=false` and explicit `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_URL=https://crt.sh/`. Runtime remains one CT request per accepted job, with bounded timeout, response bytes, parsed names, retained names, in-domain normalization, redacted storage/reporting/export/Raw JSON, and tests using fake HTTP transports only. It adds no passive DNS, provider API, DNS queries, frontend, archive/run-all, `tools/runner/main.py`, Nmap, Docker, subprocess, release, tag, or push behavior.
75. Active DNS OSINT Microphase 06 reviews the bounded `crt.sh` source. The review found and fixed one URL-boundary blocker: explicit custom ports are now rejected before source construction. The source remains disabled by default, requires explicit `https://crt.sh/` configuration, uses fake HTTP transports in tests, and keeps `osint_best_effort`, redacted outputs, manual validation, and no passive DNS/provider/frontend/archive-run-all behavior.
76. Active DNS OSINT Microphase 07 connects the frontend to `active_dns_osint` with a separate `Active / DNS OSINT` panel, exact CT-bounded request contract, required authorization/public-OSINT confirmations, `202 JobRecord` selection and refresh, redacted CT OSINT report rendering, passive DNS shown as unavailable, and Raw JSON redaction-first. It adds no passive DNS/provider API, frontend CT direct call, DNS query from the browser, observed-name auto-scan, archive/run-all, `tools/runner/main.py`, Nmap, Docker, subprocess, release, tag, or push behavior.

## What This MVP Does

- Uploads local PDF files through a REST API.
- Uploads local JPEG, PNG, and WebP images through a REST API.
- Uploads local dependency manifests: `package.json`, `requirements.txt`, and `pyproject.toml`.
- Uploads local ZIP, TAR, TAR.GZ, and TGZ archives through a REST API.
- Lists registered local files without exposing host paths.
- Stores uploaded files under `data/uploads`.
- Starts basic PDF, image, manifest, and archive audit jobs.
- Starts project-archive manifest analysis jobs for archives that contain supported dependency manifests.
- Starts passive Django configuration analysis jobs for archive uploads.
- Starts passive Docker/Compose configuration analysis jobs for archive uploads.
- Starts passive secrets exposure review jobs for archive uploads.
- Starts passive Node package configuration analysis jobs for archive uploads.
- Starts passive CI/CD configuration analysis jobs for archive uploads.
- Starts passive Kubernetes manifest configuration analysis jobs for archive uploads.
- Starts passive Terraform/OpenTofu/Terragrunt configuration analysis jobs for archive uploads through the API.
- Starts passive Nginx/reverse-proxy configuration analysis jobs for archive uploads through the API.
- Starts passive Docker Compose service wiring/configuration analysis jobs for archive uploads through the API.
- Starts passive PostgreSQL/MySQL/MariaDB configuration analysis jobs for archive uploads through the API.
- Starts passive SQL DB configuration analysis jobs for archive uploads through the API and UI.
- Starts passive Redis/Sentinel configuration analysis jobs for archive uploads through the API.
- Starts authorized baseline web configuration audit jobs for a single URL.
- Starts authorized DNS baseline audit jobs for a single domain.
- Starts authorized controlled subdomain inventory jobs for explicitly supplied candidates.
- Starts opt-in Active network dry-run planning jobs with no network traffic when `INSPECTRA_ACTIVE_DRY_RUN_ENABLED=true`.
- Starts opt-in authorized Active HTTP header probe jobs when `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED=true`; each permitted job sends at most one HTTP `HEAD` request after explicit live-traffic confirmation.
- Creates opt-in Active / Nmap basic jobs when `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=true`; real minimal execution requires an internal `active-tools` URL plus explicit active-tools execution enablement. Jobs are owner-scoped, target-redacted, bounded, and render TCP observations only as observed exposure / review indicators requiring manual validation. Without configured active-tools execution, controlled no-live or unconfigured states remain redacted.
- Creates opt-in Active / TLS basic jobs when `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED=true`; each accepted request is one explicit authorized local/private/self-hosted target and one bounded TLS-basic port. Jobs are owner-scoped, target-redacted, and render TLS handshake/certificate expiry values only as review indicators requiring manual validation.
- Creates opt-in Active / DNS inventory jobs when `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=true`; each accepted request is one explicit authorized root domain with allowlisted DNS record types. Jobs are owner-scoped, domain-redacted, and render bounded standard records, SPF/DMARC/CAA indicators, fixed-candidate subdomain summaries, and optional explicitly authorized AXFR counters/allowlisted record groups only as DNS configuration review indicators requiring manual validation. Complete-zone coverage wording is limited to `zone_transfer_complete` after bounded authorized AXFR acceptance.
- Creates opt-in Active / DNS OSINT jobs when `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=true`; accepted requests use an injectable CT source adapter, persist owner-scoped `[REDACTED_DOMAIN]` jobs with `osint_best_effort` coverage, redacted observed-name counters/samples, and public-source observed-name review-indicator wording. The default source is disabled; bounded `crt.sh` use requires explicit CT-source configuration, and the frontend renders the flow as manual-review CT OSINT with passive DNS unavailable.
- Runs passive tools inside the `audit-tools` container.
- Calculates file hashes inside the tool container.
- Stores job state and results under `data/results/jobs`.
- Lists audit jobs with a compact summary.
- Exports job reports as Markdown, HTML, XML, and PDF.
- Exports offline SBOMs as CycloneDX JSON and SPDX JSON from completed manifest and project-archive manifest jobs.
- Deletes uploaded source files while keeping historical job results.
- Deletes completed or failed job/result records through the API.
- Provides a minimal React UI for uploads, web audits, Active dry-run/header-probe panels, filters, jobs, readable PDF/image/manifest/archive/project-archive/Django-config/Docker-config/secrets-review/Node-package-config/CI-CD-config/web reports, exports, and raw JSON results.
- Provides a minimal React UI for archive-only passive config reports including Kubernetes, Terraform, Nginx, Compose, Database, and Redis.
- Exposes OpenAPI docs at `http://localhost:8000/docs`.

## What This MVP Does Not Do

- It does not run exploits.
- It does not scan ports or networks.
- It does not crawl websites or follow links from HTML.
- It does not brute-force, fuzz, or automate aggressive checks.
- It does not install audit tools on the host.
- It does not install dependencies from uploaded manifests.
- It does not execute package scripts or project code.
- It does not execute npm, pnpm, yarn, bun, npx, lifecycle scripts, JS/TS configs, registry lookups, `npm audit`, or advisory/CVE queries for Node package config audits.
- It does not execute workflows, emulate CI runners, call provider APIs, validate tokens, download actions/images, or query advisory/CVE data for CI/CD config audits.
- It does not execute Terraform, OpenTofu, or Terragrunt, run init/validate/plan/apply, download providers/modules, access state remotely, call cloud APIs, or query advisory/CVE data for Terraform config audits.
- It does not execute Nginx, run `nginx -t`, start containers, resolve includes, perform DNS/network checks, validate live servers/certificates, or query advisory/CVE data for Nginx config audits.
- It does not execute Docker or Docker Compose, run `docker compose config`, build/pull/inspect images, interpolate `.env` values, merge multiple Compose files, contact registries, or query advisory/CVE data for Compose config audits.
- It does not execute database clients or servers, validate database configs against live instances, resolve includes, read dumps/backups/credential files, connect to databases, or query advisory/CVE data for Database or SQL DB config audits.
- It does not execute Redis or Sentinel, use `redis-cli`, open sockets, resolve includes, read `.env`/ACL/RDB/AOF/appendonly/backup contents, validate credentials, or query advisory/CVE data for Redis config audits.
- It does not extract archives broadly to the filesystem.
- It does not execute, install, or resolve anything found inside archives.
- It does not execute Django projects, import settings modules, run `manage.py`, connect to databases, or read real `.env`/`.env.*` files from archives.
- It does not execute Docker, build images, start containers, inspect the Docker socket, download images, or resolve image tags.
- It does not validate secrets, query providers, scan Git history, run external secret scanners, or claim credentials are active.
- It does not parse unsupported internal manifest formats beyond filename detection.
- It does not call external services to generate reports.
- It does not call external services to generate SBOMs.
- It does not query external CVE or vulnerability databases yet.
- It does not resolve transitive dependencies or infer installed package versions.
- It does not process targets unless you upload them intentionally.
- It does not audit web targets unless you provide a single URL and confirm authorization.
- It does not inventory subdomains unless you provide explicit candidates and confirm authorization.
- It does not brute-force subdomains, use wordlists, query Certificate Transparency logs, attempt unconfirmed AXFR, crawl, scan ports, or call reputation APIs.
- It does not perform live Active probes in the Active dry-run flow; dry-run jobs send no DNS queries, HTTP requests, socket traffic, Nmap commands, or live checks.
- It does not run Nmap, scan ports, crawl, read response bodies, follow redirects, validate certificates beyond the HTTP client default, or send more than one authorized `HEAD` request in the opt-in Active HTTP header probe flow.
- It does not run Nmap in the backend, expose `active-tools` publicly by default, accept raw flags/NSE/scripts, perform broad scans, expand targets, collect raw output, or present Active / Nmap basic observations as vulnerability findings.
- It does not run OpenSSL commands, subprocess TLS probes, HTTP crawling, credential validation, client-certificate checks, broad target expansion, or complete certificate inventory for Active / TLS basic; TLS results are bounded review indicators with redacted targets and certificate material.
- It does not turn Active / DNS inventory into provider DNS/API import, broad subdomain enumeration, CT/passive-DNS runtime, DNS CLI execution, raw DNS packet storage, public scanner behavior, or all-records-found reporting. Core Active DNS models attacker-equivalent visibility; provider import would require a separate admin inventory connector. AXFR is attempted only when the bounded Active DNS request is explicitly enabled and separately confirms `zone_transfer_authorized_confirmed: true`; refused or failed AXFR remains controlled best-effort/partial review-indicator output.

## Passive Technical Alpha Scope

Inspectra Passive technical alpha is closed for new module expansion. The current passive suite is ready for technical-alpha smoke and UX polish instead of opening more analyzers.

The alpha includes local file uploads, bounded archive analysis, project-archive manifest parsing, passive configuration reviews for Django, Docker, secrets exposure, Node package config, CI/CD, Kubernetes, Terraform, Nginx, Docker Compose, Database, SQL DB, and Redis, plus the already bounded web/DNS/subdomain baseline flows. Archive-based config analyzers are offered only for uploaded files registered as `kind: "archive"`.

All passive config findings are heuristic review indicators. They are not confirmed vulnerabilities, exploitability claims, live reachability checks, breach claims, or proof of compromise. The shared posture is local, bounded, archive/file-only, redaction-first, and intentionally avoids runtime execution, credential validation, registry/CVE/advisory lookups, and external service calls unless a separate authorized audit family explicitly documents that behavior.

The recommended next product block is UI/report polish and smoke-demo coherence, not MongoDB, RabbitMQ, Elasticsearch/OpenSearch, Apache, or another new analyzer.

## Local Technical Alpha Demo

For trusted local alpha demos, use only the synthetic fixture pack under `tests/fixtures/demo/passive-alpha/` and follow `docs/future/passive-alpha-smoke-demo-checklist.md`. The packaging/readiness decision is documented in `docs/future/passive-alpha-packaging-readiness.md`, the trusted local closeout/release-candidate record is documented in `docs/future/passive-alpha-closeout-or-release-candidate.md`, the public/external readiness gap plan is documented in `docs/future/passive-alpha-gap-fixes-01-plan.md`, the deployment threat model is documented in `docs/future/passive-alpha-gap-fixes-02-deployment-threat-model.md`, the docs-first auth/user isolation design is documented in `docs/future/passive-alpha-gap-fixes-03-auth-and-user-isolation-design.md`, the retention/cleanup/reset design is documented in `docs/future/passive-alpha-gap-fixes-04-retention-cleanup-reset-design.md`, the disclaimers/onboarding copy design is documented in `docs/future/passive-alpha-gap-fixes-05-disclaimers-and-onboarding-copy.md`, the limits/report polish design is documented in `docs/future/passive-alpha-gap-fixes-06-limits-messaging-and-report-polish.md`, the gap-fixes closeout is documented in `docs/future/passive-alpha-gap-fixes-07-closeout.md`, the implementation readiness plan is documented in `docs/future/passive-alpha-gap-fixes-08-implementation-readiness-plan.md`, the open-source/self-hosted product framing is documented in `docs/future/passive-alpha-p0-00-open-source-self-hosted-product-framing.md`, the auth-boundary runtime plan is documented in `docs/future/passive-alpha-p0-01-auth-boundary-design-to-runtime-plan.md`, the owner model/storage migration plan is documented in `docs/future/passive-alpha-p0-02-owner-model-and-storage-migration-plan.md`, the deny-anonymous API guards plan is documented in `docs/future/passive-alpha-p0-03-deny-anonymous-reads-api-guards.md`, the owner-scoped resources plan is documented in `docs/future/passive-alpha-p0-04-owner-scoped-jobs-results-exports.md`, the retention/delete runtime plan is documented in `docs/future/passive-alpha-p0-05-retention-delete-semantics-runtime-plan.md`, the deployment hardening checklist is documented in `docs/future/passive-alpha-p0-06-deployment-hardening-checklist.md`, the P0 runtime planning closeout is documented in `docs/future/passive-alpha-p0-07-p0-runtime-planning-closeout.md`, the auth-mode/local-operator runtime slice is documented in `docs/future/passive-alpha-runtime-01-auth-mode-flag-and-local-operator.md`, the single-admin auth skeleton is documented in `docs/future/passive-alpha-runtime-02-single-admin-auth-skeleton.md`, the deny-anonymous sensitive routes runtime slice is documented in `docs/future/passive-alpha-runtime-03-deny-anonymous-sensitive-routes.md`, the owner metadata write-path runtime slice is documented in `docs/future/passive-alpha-runtime-04-owner-metadata-write-path.md`, the legacy local data mapping runtime slice is documented in `docs/future/passive-alpha-runtime-05-legacy-local-data-mapping.md`, the owner-scoped reads/exports runtime slice is documented in `docs/future/passive-alpha-runtime-06-owner-scoped-reads-and-exports.md`, the owner-scoped delete runtime slice is documented in `docs/future/passive-alpha-runtime-07-delete-source-and-job-results.md`, the deployment hardening smoke is documented in `docs/future/passive-alpha-runtime-08-deployment-hardening-smoke.md`, the Runtime P0 closeout is documented in `docs/future/passive-alpha-runtime-09-runtime-p0-closeout.md`, the single-admin login/session plan is documented in `docs/future/passive-alpha-runtime-10-single-admin-login-session-plan.md`, the password verifier slice is documented in `docs/future/passive-alpha-runtime-11-password-verify-helper.md`, the session/cookie skeleton is documented in `docs/future/passive-alpha-runtime-12-session-cookie-skeleton.md`, the login/logout endpoint slice is documented in `docs/future/passive-alpha-runtime-13-login-logout-endpoints.md`, the CSRF mutating-route guard slice is documented in `docs/future/passive-alpha-runtime-14-csrf-mutating-routes.md`, the frontend auth status/login/logout UX slice is documented in `docs/future/passive-alpha-runtime-15-frontend-auth-status-login-ux.md`, the auth flow smoke is documented in `docs/future/passive-alpha-runtime-16-auth-flow-smoke.md`, the self-hosted auth closeout is documented in `docs/future/passive-alpha-runtime-17-self-hosted-auth-closeout.md`, the rate-limit/lockout plan is documented in `docs/future/passive-alpha-runtime-18-rate-limit-lockout-plan.md`, the isolated login-attempt store is documented in `docs/future/passive-alpha-runtime-19-login-attempt-store.md`, the login rate-limit enforcement slice is documented in `docs/future/passive-alpha-runtime-20-login-rate-limit-backoff.md`, and the frontend login rate-limit copy slice is documented in `docs/future/passive-alpha-runtime-21-frontend-rate-limit-copy.md`.

The self-hosted auth hardening smoke is documented in `docs/future/passive-alpha-runtime-22-auth-hardening-smoke.md`.

The self-hosted auth hardening closeout is documented in `docs/future/passive-alpha-runtime-23-self-hosted-auth-hardening-closeout.md`; it closes the current private/self-hosted alpha line without adding public/community readiness, runtime expansion, SaaS/billing behavior, Nmap, or release/tag state.

Private self-hosted alpha release notes are available at `docs/future/passive-alpha-self-hosted-release-notes.md`; they summarize supported auth state, Runtime-22 validation evidence, explicit no-scope, and remaining exposed-use gaps without creating a tag, release, public launch, or runtime expansion.

The private self-hosted deployment hardening design is documented in `docs/future/passive-alpha-deployment-hardening-design.md`; it covers TLS, reverse proxy expectations, secure-cookie direction, and trusted proxy header policy without implementing runtime changes or approving public/community or production-ready deployment.

The private self-hosted deployment hardening runbook is documented in `docs/future/passive-alpha-deployment-hardening-runbook.md`; it gives operators a pre-exposure checklist for mode selection, reverse proxy posture, cookies/sessions, rate limiting, CORS, logging, and red flags without executing deployment steps or approving production/public use.

The persistent auth state design is documented in `docs/future/passive-alpha-persistent-auth-state-design.md`; it accepts a future local SQLite auth-state store for private/self-hosted sessions and login attempts without implementing runtime changes, public/community readiness, production approval, SaaS/billing behavior, or multi-user auth.

The SQLite auth store scaffold is documented in `docs/future/passive-alpha-sqlite-auth-store-scaffold.md`; it adds an isolated backend store and tests for hashed session, CSRF, and login-attempt state.

Persistent session-store integration is documented in `docs/future/passive-alpha-persistent-session-store-integration.md`; it wires SQLite-backed sessions into `self_hosted_single_admin` when `INSPECTRA_AUTH_STATE_STORE=sqlite`, while keeping default trusted-local behavior memory-backed.

Persistent login-attempt store design is documented in `docs/future/passive-alpha-persistent-login-attempt-store-design.md`; it accepted SQLite-backed login-attempt persistence as the runtime direction for `self_hosted_single_admin` when `INSPECTRA_AUTH_STATE_STORE=sqlite`.

Persistent login-attempt store integration is documented in `docs/future/passive-alpha-persistent-login-attempt-store-integration.md`; it wires SQLite-backed login-attempt/rate-limit state into `self_hosted_single_admin` when `INSPECTRA_AUTH_STATE_STORE=sqlite`, while preserving memory defaults, generic `429`, safe `Retry-After`, and current backend-observed client-key semantics.

Auth-state cleanup and rotation design is documented in `docs/future/passive-alpha-auth-state-cleanup-rotation-design.md`; it defines docs-first expectations for session/attempt cleanup, local DB rotation, backup sensitivity, offline operator intervention, and next smoke criteria without adding runtime behavior.

Auth-state cleanup and rotation smoke is documented in `docs/future/passive-alpha-auth-state-cleanup-rotation-smoke.md`; it validates current SQLite session and login-attempt cleanup, pruning, revocation, expiration, restart/store recreation, redaction, and auth-contract behavior without frontend runtime changes.

Persistent auth closeout is documented in `docs/future/passive-alpha-persistent-auth-closeout.md`; it closes Pathing C for private/self-hosted alpha by consolidating SQLite auth-state design, scaffold, persistent sessions, persistent login attempts, cleanup/rotation design, and smoke evidence without adding runtime behavior or approving production/public/community readiness.

Persistent auth final regression smoke is documented in `docs/future/passive-alpha-persistent-auth-final-regression-smoke.md`; it records a green backend/frontend/build regression pass for Pathing C without adding runtime behavior or changing auth contracts.

The Passive Alpha release candidate checklist is documented in `docs/future/passive-alpha-release-candidate-checklist.md`; it consolidates the private/self-hosted alpha state, release blockers, residual gaps, and pre-tag validation path without creating a tag, release, push, or runtime expansion.

The Passive Alpha tag/release prep is documented in `docs/future/passive-alpha-tag-release-prep.md`; it freezes `v0.1.0-alpha.1` as the preferred tag candidate and `Inspectra Passive Alpha v0.1.0-alpha.1` as the release title without creating a tag, release, push, or runtime expansion.

The Passive Alpha post-release technical pause is documented in `docs/future/passive-alpha-post-release-technical-pause.md`; it records the published `v0.1.0-alpha.1` state, accepted residual debt, and next pathing without adding runtime behavior, a new tag/release, Docker/Nmap/probes, CVE matching, or production/public/community readiness.

Do not upload real secrets or production archives for demos. Inspectra redacts sensitive-looking values in results, exports, and Raw JSON with `[REDACTED]`, but redaction does not sanitize the original uploaded file stored locally.

Release notes for the local passive alpha tag `v0.1.0-passive-alpha` are available at `docs/releases/v0.1.0-passive-alpha.md`.

Active Alpha is internal and limited. It includes `active_network_dry_run` as no-network planning and `active_http_header_probe` as the only limited live capability: opt-in, disabled by default, explicitly authorized, double-confirmed, target-based, and capped to one HTTP `HEAD` request with no redirects and no response body read. It does not add Nmap, port scanning, crawling, custom headers, auth/cookies, fuzzing, exploitation, credential validation, production readiness, external-user readiness, policy relaxation, or additional Active capabilities.

Active Alpha references: operator guide `docs/future/active-network-block-22-active-alpha-operator-guide.md`, test-double smoke execution `docs/future/active-network-block-23-limited-live-smoke-test-execution.md`, closeout `docs/future/active-network-block-25-active-alpha-closeout.md`, passive readiness recheck `docs/future/active-network-block-26-passive-alpha-readiness-recheck.md`, and security scope `docs/security-scope.md`. The smoke record passed runner, backend/API/reporting/export, and frontend mocked subsets without external target traffic. The closeout decision is internal and limited; it is not production readiness, external-user readiness, Nmap readiness, or approval for broader Active behavior.

Active Nmap Basic future design is documented in `docs/future/active-nmap-basic-design.md` with decision `ACTIVE_NMAP_BASIC_DESIGN_FROZEN`. The design phase was docs-only and did not add Nmap runtime, arbitrary internet scanning, broad ranges, stealth, evasion, aggressive NSE defaults, brute force, exploit scripts, credential validation, crawling, DNS expansion, custom scripts, SaaS/public scanner behavior, frontend/backend/runner changes, Docker execution, tags, or releases.

Active Nmap Basic implementation planning is documented in `docs/future/active-nmap-basic-implementation-plan.md` with decision `ACTIVE_NMAP_BASIC_IMPLEMENTATION_PLAN_FROZEN`. It sequences possible work into small backend, target-policy, command-builder, runner, parser, reporting, frontend, test, and local-smoke phases.

Active Nmap Basic Microphase 01 introduced the backend contract gate. The endpoint `POST /active/network/nmap-basic` remains disabled by default through `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=false` and still validates `mode: live_nmap_basic`, `profile: tcp_connect_small`, bounded `targets` and `ports`, and all required confirmations before any job lifecycle behavior.

Active Nmap Basic Microphase 08 is implemented as a frontend panel shell only. The `Active / Nmap basic` panel displays disabled/prepared availability states, local/private/self-hosted and authorized-target guardrails, live-traffic warning copy, observed-exposure/review-indicator wording, and a disabled nonfunctional button. It does not submit requests, create jobs, call `POST /active/network/nmap-basic`, run Nmap, render full Nmap reports, or integrate with archive/run-all actions.

Active Nmap Basic Microphase 09 is implemented as a frontend confirmations and submit contract only. The panel now accepts one explicit target, bounded numeric TCP ports, and explicit authorization, local/private/self-hosted scope, and live-traffic confirmations before calling only `POST /active/network/nmap-basic`. Current disabled or `not_implemented` / `not_executed` backend responses are shown as controlled states, not completed scans. The backend still does not create real Nmap jobs, call a runner, execute Nmap, or connect to archive/run-all actions.

Active Nmap Basic Microphase 10 is implemented as frontend report and Raw JSON rendering only for already-structured `active_nmap_basic` payloads. The report shows minimal TCP port observations as observed exposure / review indicators with manual validation required and redacts raw targets, commands, XML, stdout/stderr, service/banner fields, headers, cookies, tokens, credentials, and malformed legacy fields. It does not connect backend to runner execution, create real Nmap jobs, run Nmap, add runner HTTP endpoints, add archive/run-all actions, infer vulnerabilities or exploitability, map open ports to high severity, or display raw XML.

Active Nmap Basic Microphase 12 is implemented as backend job lifecycle wiring to a no-live test-double only. When `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=true`, valid requests create owner-scoped `active_nmap_basic` jobs with `file_id: null`, redacted target metadata, bounded handoff counts, and a structured `not_executed` result from the backend no-live adapter. It does not call the real active-runner executor, execute Nmap, invoke subprocesses from backend, add runner HTTP endpoints, run Docker, perform probes, perform DNS checks, make external HTTP requests, integrate archive/run-all, integrate `tools/runner/main.py`, accept raw flags, add custom scripts, add NSE, add brute force, add credential validation, add crawling, add DNS expansion, add broad ranges, or treat test-double results as real Nmap scans.

Active Nmap Basic Microphase 13 is documented as a live wiring readiness review only. The decision `ACTIVE_NMAP_BASIC_13_LIVE_WIRING_READINESS_REVIEW_PASSED` allows only a future mocked/no-live backend slice toward an injectable executor interface. It does not approve real Nmap execution, Docker/Nmap packaging, local authorized Nmap smoke, runner HTTP endpoints, archive/run-all integration, `tools/runner/main.py` integration, broader fanout, target expansion, raw flags, custom scripts, NSE, stealth/evasion, brute force, credential validation, crawling, DNS expansion, public scanner behavior, or confirmed-vulnerability/exploitability claims.

Active Nmap Basic Microphase 14 wires backend job lifecycle to an injectable executor adapter with mocks/fakes only. The default adapter still returns controlled no-live `not_executed`, while tests can inject synthetic `completed`, `failed`, `timed_out`, `nmap_missing`, `malformed`, `truncated`, and `no_ports` states for parser/result/report coverage. It does not execute Nmap, invoke backend subprocesses, add runner HTTP endpoints, run Docker, perform probes, perform DNS checks, make external HTTP requests, integrate archive/run-all, integrate `tools/runner/main.py`, relax target policy or owner scope, or make confirmed-vulnerability/exploitability claims.

Active Nmap Basic Microphase 15 is documented in `docs/future/active-nmap-basic-local-smoke-plan-no-unauthorized-traffic.md` with decision `ACTIVE_NMAP_BASIC_15_LOCAL_SMOKE_PLAN_NO_UNAUTHORIZED_TRAFFIC_ACCEPTED`. It is docs-only planning for the first local smoke: Option A no-live fake/mocked adapter validation is the recommended first path, Option B real local authorized Nmap smoke remains blocked until a later phase defines exact loopback/local target control and limits, and Option C own VPS/domain smoke remains blocked for the first smoke. It does not run Nmap, Docker, probes, DNS checks, external HTTP traffic, or runtime changes.

Active Nmap Basic Microphase 16 is documented in `docs/future/active-nmap-basic-no-live-smoke-execution.md` with decision `ACTIVE_NMAP_BASIC_16_NO_LIVE_SMOKE_EXECUTION_PASSED`. The smoke executed only Option A no-live fake/mocked adapter validation and passed backend, active-runner, frontend, build, compile, and source-search checks. It does not approve real local Nmap smoke, Docker/Nmap packaging, VPS/domain smoke, backend subprocesses, runner HTTP endpoints, archive/run-all, `tools/runner/main.py` integration, target-policy relaxation, feature-flag default relaxation, broad scanning, or confirmed-vulnerability/exploitability claims.

Active Nmap Basic Microphase 17 is documented in `docs/future/active-nmap-basic-real-local-smoke-target-freeze.md` with decision `ACTIVE_NMAP_BASIC_17_REAL_LOCAL_SMOKE_TARGET_FREEZE_ACCEPTED`. It freezes the next possible real local smoke to target `127.0.0.1`, port `[65000]`, mode `live_nmap_basic`, profile `tcp_connect_small`, temporary feature-flag enablement, future local commands, cleanup, rollback, evidence checks, and no-go criteria. It does not run Nmap, run Docker, change runtime, use `localhost`, use a domain/VPS/LAN target, add runner endpoints, integrate archive/run-all, integrate `tools/runner/main.py`, or approve real execution in this phase.

Active Nmap Basic Microphase 18 is documented in `docs/future/active-nmap-basic-real-local-smoke-execution.md` with decision `ACTIVE_NMAP_BASIC_18_REAL_LOCAL_SMOKE_EXECUTION_BLOCKED_NMAP_MISSING`. The real local smoke did not execute because Nmap is not installed in the local environment. The frozen argv was rechecked through the allowlisted builder, no-live backend/runner/frontend validations passed, and no Nmap installation, Docker, backend smoke server, live request, job creation, export, DNS check, external HTTP traffic, target change, port change, runner endpoint, archive/run-all, or `tools/runner/main.py` integration occurred.

Active Nmap Basic Microphase 19 is documented in `docs/future/active-nmap-basic-nmap-availability-and-packaging-plan.md` with decision `ACTIVE_NMAP_BASIC_19_NMAP_PACKAGING_PLAN_ACTIVE_RUNNER_RECOMMENDED`. It recommends solving Nmap availability through a separate Dockerized Active runner/image such as `active-tools`, while rejecting host-local manual Nmap installation as the normal Inspectra requirement and keeping Nmap out of the backend and passive runner monolith. It does not install Nmap, execute Nmap, run Docker, modify Dockerfile or Compose, change runtime, add runner endpoints, integrate archive/run-all, approve LAN/VPS/domain targets, or add public scanner behavior.

Active Nmap Basic Microphase 20 is documented in `docs/future/active-nmap-basic-active-tools-docker-design.md` with decision `ACTIVE_NMAP_BASIC_20_ACTIVE_TOOLS_DOCKER_DESIGN_ACCEPTED`. It designs a future separate Dockerized `active-tools` Active service/image with no public port by default, no host network by default, no privileged container, no Docker socket, explicit activation, bounded execution, redacted logs, and continued separation from backend direct subprocess execution, archive/run-all, and `tools/runner/main.py`. It does not modify Dockerfile or Compose, build images, start containers, install Nmap, execute Nmap, change runtime, add runner endpoints, approve LAN/VPS/domain/public targets, or add public scanner behavior.

Active Nmap Basic Microphase 21 is documented in `docs/future/active-nmap-basic-active-tools-docker-scaffold-no-run.md` with decision `ACTIVE_NMAP_BASIC_21_ACTIVE_TOOLS_DOCKER_SCAFFOLD_NO_RUN_ACCEPTED`. It adds the initial `active-tools` Dockerfile, Dockerfile-specific ignore file, separate `docker-compose.active-tools.example.yml`, and static scaffold tests. The main `docker-compose.yml` is unchanged, the scaffold is not built or run, and no Nmap execution, backend live call, runner HTTP endpoint, archive/run-all integration, `tools/runner/main.py` integration, LAN/VPS/domain/public target approval, or public scanner behavior is added.

Active Nmap Basic Microphase 22 is documented in `docs/future/active-nmap-basic-active-tools-docker-static-review.md` with decision `ACTIVE_NMAP_BASIC_22_ACTIVE_TOOLS_DOCKER_STATIC_REVIEW_PASSED`. It reviews the `active-tools` Dockerfile, Dockerfile-specific ignore, Compose example, and static scaffold tests and accepts the scaffold only for a future separately approved build-only phase. It does not build images, run Docker, start containers, execute Nmap, add backend live calls, add runner HTTP endpoints, integrate archive/run-all, integrate `tools/runner/main.py`, approve LAN/VPS/domain/public targets, or add public scanner behavior.

Active Nmap Basic Microphase 23 is documented in `docs/future/active-nmap-basic-active-tools-docker-build-only.md` with decision `ACTIVE_NMAP_BASIC_23_ACTIVE_TOOLS_DOCKER_BUILD_ONLY_PASSED`. It builds the scaffold image as `inspectra-active-tools:build-smoke` and inspects image metadata only. It does not run `docker run`, run `docker compose up`, start containers, execute Nmap, run commands inside the image, add backend live calls, add runner HTTP endpoints, integrate archive/run-all, integrate `tools/runner/main.py`, approve LAN/VPS/domain/public targets, or add public scanner behavior.

Active Nmap Basic Microphase 24 is documented in `docs/future/active-nmap-basic-active-tools-run-no-target-readiness.md` with decision `ACTIVE_NMAP_BASIC_24_ACTIVE_TOOLS_RUN_NO_TARGET_READINESS_PASSED`. It starts the built image once with `--network none`, `--read-only`, tmpfs `/tmp`, dropped capabilities, and `no-new-privileges`, then exits after controlled scaffold JSON with `mode: scaffold_no_run` and `nmap_present: true` by path lookup only. It does not execute Nmap, use Compose, publish ports, perform probes, perform DNS checks, send external HTTP target traffic, add backend live calls, add runner HTTP endpoints, integrate archive/run-all, integrate `tools/runner/main.py`, approve LAN/VPS/domain/public targets, or add public scanner behavior.

Active Nmap Basic Microphase 25 is documented in `docs/future/active-nmap-basic-active-tools-nmap-version-no-target.md` with decision `ACTIVE_NMAP_BASIC_25_ACTIVE_TOOLS_NMAP_VERSION_NO_TARGET_PASSED`. It runs only `nmap --version` inside `inspectra-active-tools:build-smoke` with `--network none`, `--read-only`, tmpfs `/tmp`, dropped capabilities, and `no-new-privileges`, observing Nmap `7.95`. It does not supply a target, run a scan, run NSE/scripts, use Compose, publish ports, perform probes, perform DNS checks, send external HTTP target traffic, add backend live calls, add runner HTTP endpoints, integrate archive/run-all, integrate `tools/runner/main.py`, approve LAN/VPS/domain/public targets, or add public scanner behavior.

Active Nmap Basic Microphase 26 is documented in `docs/future/active-nmap-basic-active-tools-local-smoke-target-freeze.md` with decision `ACTIVE_NMAP_BASIC_26_ACTIVE_TOOLS_LOCAL_SMOKE_TARGET_FREEZE_ACCEPTED`. It freezes the first future Dockerized target-bearing smoke semantics to container loopback `127.0.0.1`, port `65000`, and Docker `--network none`, interpreted only as a closed-port local container loopback smoke. It records `www.vildek.es`, `app.vildek.es`, and `www.urlbreve.es` as future owned-domain candidates only; it does not approve them now, run Docker, run Nmap, perform probes, perform DNS checks, send external HTTP target traffic, use Compose, publish ports, add backend live calls, add runner HTTP endpoints, integrate archive/run-all, integrate `tools/runner/main.py`, approve LAN/VPS/domain/public targets, or add public scanner behavior.

Active Nmap Basic Microphase 27 is documented in `docs/future/active-nmap-basic-active-tools-container-loopback-smoke.md` with decision `ACTIVE_NMAP_BASIC_27_ACTIVE_TOOLS_CONTAINER_LOOPBACK_SMOKE_PASSED`. It runs exactly one target-bearing `active-tools` smoke using Docker `--network none`, target `127.0.0.1`, port `65000`, and the allowlisted `tcp_connect_small` argv shape. Nmap reports `65000/tcp` as `closed` with `conn-refused` inside the container. This confirms only container-loopback execution mechanics; it does not approve host exposure claims, Compose connectivity, backend integration, jobs, exports, runner endpoints, archive/run-all, `tools/runner/main.py`, owned-domain targets, LAN/VPS/public targets, runtime changes, tags, releases, or public scanner behavior.

Active Nmap Basic Microphase 28 is documented in `docs/future/active-nmap-basic-own-domain-authorized-smoke-target-freeze.md` with decision `ACTIVE_NMAP_BASIC_28_OWN_DOMAIN_AUTHORIZED_SMOKE_TARGET_FREEZE_ACCEPTED`. It freezes the first future own-domain smoke target to exactly `www.urlbreve.es` on port `443`, records `www.vildek.es` and `app.vildek.es` as still blocked, and chooses DNS decision Option A for a later execution: only the minimum Nmap DNS resolution required for that exact FQDN, with no DNS expansion, no subdomain discovery, no reverse-DNS sweep, and no manual DNS checks in this phase. It does not run Docker, run Nmap, perform probes, perform manual DNS checks, send manual HTTP traffic, use `curl` or a browser against domains, approve port `80`, approve LAN/VPS/public targets, add backend live calls, add runner HTTP endpoints, integrate archive/run-all, integrate `tools/runner/main.py`, create jobs, create exports, create tags, create releases, or approve public scanner behavior.

Active Nmap Basic Microphase 29 is documented in `docs/future/active-nmap-basic-own-domain-authorized-smoke-execution.md` with decision `ACTIVE_NMAP_BASIC_29_OWN_DOMAIN_AUTHORIZED_SMOKE_EXECUTION_PASSED`. It runs exactly one `active-tools` Nmap smoke against `www.urlbreve.es` on port `443` using the frozen `tcp_connect_small` command shape. Nmap reports `443/tcp` as `open` with reason `syn-ack`; this is only an observed TCP exposure / review indicator for the exact authorized FQDN at that moment. Nmap also emits a PTR hostname in XML through default DNS behavior; no manual DNS check or reverse-DNS sweep command is run. The phase does not use `www.vildek.es`, `app.vildek.es`, port `80`, manual HTTP checks, `curl`, browser checks, Compose, backend live calls, runner HTTP endpoints, jobs, exports, archive/run-all, `tools/runner/main.py`, runtime changes, tags, releases, vulnerability claims, exploitability claims, target-safety claims, full-scan claims, all-ports-found claims, or public scanner behavior.

Active Nmap Basic Microphase 30 is documented in `docs/future/active-nmap-basic-v0-technical-smoke-closeout.md` with decision `ACTIVE_NMAP_BASIC_30_ACTIVE_NMAP_V0_TECHNICAL_SMOKE_CLOSEOUT_ACCEPTED`. It consolidates build-only, no-target readiness, Nmap `7.95`, container-loopback `127.0.0.1:65000` closed/conn-refused, and own-domain `www.urlbreve.es:443` open/syn-ack evidence. It approves `active-tools` only as viable technical packaging and treats `www.urlbreve.es:443` as historical executed smoke evidence, not general permission. Backend integration, jobs, exports, runner HTTP endpoints, archive/run-all, `tools/runner/main.py`, `www.vildek.es`, `app.vildek.es`, port `80`, multi-domain scans, LAN/VPS/public target expansion, public scanner behavior, release, and tag state remain blocked.

Active Nmap Basic Microphase 31 is documented in `docs/future/active-nmap-basic-real-output-redaction-hardening-design.md` with decision `ACTIVE_NMAP_BASIC_31_REAL_OUTPUT_REDACTION_HARDENING_DESIGN_ACCEPTED`. It designs future parser/redaction hardening for real Nmap XML before backend/jobs/reports/Raw JSON integration. The v0 policy allows only minimal structured TCP observations and keeps PTR hostnames, reverse-DNS data, raw XML, raw args, stdout/stderr, stylesheet references, service/banner/version details, and default resolved-IP display for FQDN targets out of future report/export/Raw JSON surfaces. It does not implement parser/runtime changes, add backend integration, create jobs or exports, run Docker/Nmap/DNS/HTTP checks, approve new targets, or create release/tag state.

Active Nmap Basic Microphase 32 is documented in `docs/future/active-nmap-basic-parser-redaction-tests-no-runtime.md` with decision `ACTIVE_NMAP_BASIC_32_REAL_OUTPUT_PARSER_REDACTION_TESTS_NO_RUNTIME_ACCEPTED`. It adds synthetic XML fixtures and offline parser/redaction tests for PTR, documentary resolved IPs, raw args, raw XML, multiple hostnames, multiple hosts, unexpected ports, malformed/truncated XML, and service/NSE-like output. Pure helper hardening keeps visible payloads to minimal TCP observations with `manual_validation_required: true` and `result_interpretation: observed_exposure_review_indicator`; it does not run Docker/Nmap/DNS/HTTP checks, add runtime integration, create real jobs/exports, approve new targets, or create release/tag state.

Active Nmap Basic Microphase 33 is documented in `docs/future/active-nmap-basic-backend-report-redaction-real-shape-no-live.md` with decision `ACTIVE_NMAP_BASIC_33_BACKEND_REPORT_REDACTION_REAL_SHAPE_NO_LIVE_ACCEPTED`. It adds backend job detail, list summary, Markdown/HTML/XML/PDF export, and Redacted Raw JSON coverage for synthetic real-output-like `active_nmap_basic` payloads. Backend reporting now treats resolved IP, PTR hostname, stylesheet, and script/NSE-like fields as sensitive for this audit type. It does not run Docker/Nmap/DNS/HTTP checks, add backend-to-active-tools live calls, add runner endpoints, create real active-tools jobs/exports, integrate archive/run-all, integrate `tools/runner/main.py`, approve new targets, or create release/tag state.

Active Nmap Basic Microphase 34 is documented in `docs/future/active-nmap-basic-backend-active-tools-boundary-design.md` with decision `ACTIVE_NMAP_BASIC_34_BACKEND_ACTIVE_TOOLS_BOUNDARY_DESIGN_ACCEPTED`. It designs a future private internal backend-to-active-tools boundary where backend keeps auth, owner scope, request validation, target policy, job lifecycle, storage, reporting, and redaction, while `active-tools` executes only the bounded executor and returns minimal structured responses. It rejects backend direct subprocess/import, Docker socket or `docker exec` control from backend, public scanner behavior, archive/run-all, and `tools/runner/main.py` integration. It does not run Docker/Nmap/DNS/HTTP checks, add live calls, add runner endpoints, create real jobs or exports, approve new targets, or create release/tag state.

Active Nmap Basic Microphase 35 is documented in `docs/future/active-nmap-basic-backend-active-tools-boundary-contract-tests-no-live.md` with decision `ACTIVE_NMAP_BASIC_35_BACKEND_ACTIVE_TOOLS_BOUNDARY_CONTRACT_TESTS_NO_LIVE_ACCEPTED`. It adds pure backend boundary contract helpers and no-live tests for request building, response validation, controlled error mapping, policy drift, owner scope, redaction, and source-boundary checks. It does not add an `active-tools` endpoint, backend-to-active-tools live call, Docker/Nmap/DNS/HTTP checks, Compose wiring, real active-tools jobs, live exports, archive/run-all, `tools/runner/main.py` integration, frontend runtime changes, new target approval, or release/tag state.

Active Nmap Basic Microphase 36 is documented in `docs/future/active-nmap-basic-active-tools-internal-service-skeleton-no-scan.md` with decision `ACTIVE_NMAP_BASIC_36_ACTIVE_TOOLS_INTERNAL_SERVICE_SKELETON_NO_SCAN_ACCEPTED`. It adds a pure internal `active-tools` service skeleton for offline tests only, with conceptual `GET /health` and `POST /active/nmap-basic` handlers that return scaffold-ready/not-executed states and reject dangerous or expanded request shapes. It does not add a running server, public endpoint, backend live call, backend runtime wiring, Docker/Compose/Nmap execution, probes, DNS/HTTP checks, real active-tools jobs, live exports, archive/run-all, `tools/runner/main.py` integration, frontend runtime changes, target approval, or release/tag state.

Active Nmap Basic Microphase 37 is documented in `docs/future/active-nmap-basic-active-tools-health-readiness-hardening-no-scan.md` with decision `ACTIVE_NMAP_BASIC_37_ACTIVE_TOOLS_HEALTH_READINESS_HARDENING_NO_SCAN_ACCEPTED`. It hardens the pure internal health/readiness handler so `GET /health` accepts only absent/empty payloads, returns small stable `scaffold_ready` / `disabled_no_scan` metadata, and rejects target, port, credential, header, cookie, token, command, script, and NSE payloads without leaking values. It does not add fake execution, a running server, public endpoint, backend live call, backend runtime wiring, Docker/Compose/Nmap execution, probes, DNS/HTTP checks, real active-tools jobs, live exports, archive/run-all, `tools/runner/main.py` integration, frontend runtime changes, target approval, or release/tag state.

Active Nmap Basic Microphase 38 is documented in `docs/future/active-nmap-basic-active-tools-fake-execution-boundary-no-live.md` with decision `ACTIVE_NMAP_BASIC_38_ACTIVE_TOOLS_FAKE_EXECUTION_BOUNDARY_NO_LIVE_ACCEPTED`. It adds an explicitly injected fake executor path for offline boundary tests while preserving default `not_executed` behavior. Synthetic responses are allowlisted, metadata-bounded, accepted-port checked, and forced to `manual_validation_required` / `observed_exposure_review_indicator` wording. It does not add a running server, public endpoint, backend live call, backend runtime wiring, Docker/Compose/Nmap execution, probes, DNS/HTTP checks, real active-tools jobs, live exports, archive/run-all, `tools/runner/main.py` integration, frontend runtime changes, target approval, or release/tag state.

Active Nmap Basic Microphase 39 is documented in `docs/future/active-nmap-basic-active-tools-asgi-service-skeleton-no-live.md` with decision `ACTIVE_NMAP_BASIC_39_ACTIVE_TOOLS_ASGI_SERVICE_SKELETON_NO_LIVE_ACCEPTED`. It adds a minimal internal ASGI app skeleton for `active-tools`, with `GET /health` and `POST /active/nmap-basic` reusing the pure handlers. Tests use an in-memory ASGI harness only; no uvicorn/gunicorn server, public endpoint, backend live call, backend runtime wiring, Docker/Compose/Nmap execution, probes, DNS/HTTP checks, real active-tools jobs, live exports, archive/run-all, `tools/runner/main.py` integration, frontend runtime changes, target approval, or release/tag state is added.

Active Nmap Basic Microphase 40 is documented in `docs/future/active-nmap-basic-active-tools-asgi-container-no-live-smoke.md` with decision `ACTIVE_NMAP_BASIC_40_ACTIVE_TOOLS_ASGI_CONTAINER_NO_LIVE_SMOKE_PASSED`. It adds minimal FastAPI/Uvicorn packaging to the separate `active-tools` image while preserving the default scaffold no-run command, then starts the ASGI app manually in a hardened local container and checks only `/health` through a host-loopback publish. The smoke returns `scaffold_ready` / `disabled_no_scan` with `network_requests_sent: 0` and `nmap_executed: false`; it does not execute Nmap, run `nmap --version`, perform DNS/probe/external target HTTP checks, call backend, create jobs or exports, wire Compose runtime, integrate archive/run-all, integrate `tools/runner/main.py`, change frontend runtime, approve targets, or create release/tag state.

Active Nmap Basic Microphase 41 is documented in `docs/future/active-nmap-basic-active-tools-asgi-nmap-basic-no-live-container-smoke.md` with decision `ACTIVE_NMAP_BASIC_41_ACTIVE_TOOLS_ASGI_NMAP_BASIC_NO_LIVE_CONTAINER_SMOKE_PASSED`. It reuses the `inspectra-active-tools:asgi-smoke` image, starts the ASGI app manually in a hardened local container, checks `/health`, and posts a synthetic `127.0.0.1:65000` boundary payload to `/active/nmap-basic`. The route returns `not_executed`, `manual_validation_required: true`, no observations, `job_created: false`, `network_requests_sent: 0`, and `summary.nmap_executed: false`; it does not execute Nmap, run `nmap --version`, perform DNS/probe/external target HTTP checks, call backend, create jobs or exports, wire Compose runtime, integrate archive/run-all, integrate `tools/runner/main.py`, change frontend runtime, approve targets, or create release/tag state.

Active Nmap Basic Microphase 42 is documented in `docs/future/active-nmap-basic-active-tools-compose-internal-service-no-live.md` with decision `ACTIVE_NMAP_BASIC_42_ACTIVE_TOOLS_COMPOSE_INTERNAL_SERVICE_NO_LIVE_PASSED`. It updates the optional `docker-compose.active-tools.example.yml` so `active-tools` can run as an internal ASGI service behind profile `active`, with no published host ports, no host networking, no privileged mode, no Docker socket, read-only filesystem, tmpfs `/tmp`, dropped capabilities, and `no-new-privileges`. Compose config passes, `/health` returns `scaffold_ready` / `disabled_no_scan`, and an internal synthetic `POST /active/nmap-basic` returns `not_executed`, no observations, `job_created: false`, `network_requests_sent: 0`, and `summary.nmap_executed: false`; it does not add backend live calls, execute Nmap, perform DNS/probe/external target HTTP checks, create jobs or exports, wire the main Compose runtime, integrate archive/run-all, integrate `tools/runner/main.py`, change frontend runtime, approve targets, or create release/tag state.

Active Nmap Basic Microphase 43 is documented in `docs/future/active-nmap-basic-backend-active-tools-health-client-no-live.md` with decision `ACTIVE_NMAP_BASIC_43_BACKEND_ACTIVE_TOOLS_HEALTH_CLIENT_NO_LIVE_ACCEPTED`. It adds a backend `active-tools` health client/helper for `GET /health` only, plus default-empty `INSPECTRA_ACTIVE_TOOLS_URL` and bounded `INSPECTRA_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS` configuration. Tests use fake HTTP transport only and validate controlled readiness/error states, unexpected-field rejection, no dangerous response reflection, and no `/active/nmap-basic` backend call. This phase does not invoke the helper from backend runtime, call Nmap, run `nmap --version`, perform DNS/probe/external target HTTP checks, create jobs or exports, change frontend runtime, integrate archive/run-all, integrate `tools/runner/main.py`, approve targets, or create release/tag state.

Active Nmap Basic Microphase 44 is documented in `docs/future/active-nmap-basic-backend-active-tools-health-compose-smoke-no-live.md` with decision `ACTIVE_NMAP_BASIC_44_BACKEND_ACTIVE_TOOLS_HEALTH_COMPOSE_SMOKE_NO_LIVE_PASSED`. It starts `active-tools` through `docker-compose.active-tools.example.yml` with profile `active`, validates Compose config, and runs the backend `check_active_tools_health` helper from a one-off container on the same internal Docker network against `http://active-tools:8080/health`. The helper returns available/readiness metadata with `disabled_no_scan`, `target_input_allowed: false`, `network_requests_sent: 0`, and `nmap_executed: false`. No `/active/nmap-basic` backend call, Nmap execution, `nmap --version`, probes, external HTTP, DNS checks, jobs, exports, frontend runtime, archive/run-all, `tools/runner/main.py`, target approval, release, or tag state is added.

Active Nmap Basic Microphase 45 is documented in `docs/future/active-nmap-basic-backend-active-tools-health-runtime-surface-no-live.md` with decision `ACTIVE_NMAP_BASIC_45_BACKEND_ACTIVE_TOOLS_HEALTH_RUNTIME_SURFACE_NO_LIVE_PASSED`. It adds `GET /health/active-tools` as a targetless backend runtime health surface that calls only the `check_active_tools_health` helper. The route rejects query parameters and request bodies, stays auth-protected in auth-required modes, returns controlled `active_tools_unconfigured` / unavailable states when `INSPECTRA_ACTIVE_TOOLS_URL` is empty or unreachable, and does not call `/active/nmap-basic`, execute Nmap, run `nmap --version`, accept targets, create jobs or exports, change frontend runtime, integrate archive/run-all, integrate `tools/runner/main.py`, approve targets, release, or tag state.

Active Nmap Basic Microphase 46 is documented in `docs/future/active-nmap-basic-backend-active-tools-nmap-basic-client-contract-no-live.md` with decision `ACTIVE_NMAP_BASIC_46_BACKEND_ACTIVE_TOOLS_NMAP_BASIC_CLIENT_CONTRACT_NO_LIVE_PASSED`. It adds `run_active_nmap_basic` as an internal backend client helper for the future `active-tools` `/active/nmap-basic` call, covered only by fake HTTP transport tests. The helper validates allowlisted request and no-live response contracts, normalizes timeout/connection/status/JSON/field errors, redacts target and payload values from errors, and rejects dangerous response fields or flags. It is not invoked by backend public routes or analysis runtime, does not create jobs or exports, does not execute Nmap or `nmap --version`, does not perform probes/DNS/external HTTP, does not change frontend runtime, does not integrate archive/run-all or `tools/runner/main.py`, and does not approve targets, release, or tag state.

Active Nmap Basic Microphase 47 is documented in `docs/future/active-nmap-basic-backend-active-nmap-job-lifecycle-skeleton-no-live.md` with decision `ACTIVE_NMAP_BASIC_47_BACKEND_ACTIVE_NMAP_JOB_LIFECYCLE_SKELETON_NO_LIVE_PASSED`. It adds an isolated backend lifecycle skeleton for a future `active_nmap_basic` job that accepts only a prevalidated internal handoff and an injected fake/no-live client. The skeleton blocks when configuration or internal approval is missing, rejects non-fake clients and unbounded lifecycle plans, normalizes controlled fake-client errors, and accepts only no-live `not_executed` results with no job creation, no storage persistence, no real `active-tools` call, no Nmap execution, no probes/DNS/external HTTP, no frontend changes, no exports, no archive/run-all, and no `tools/runner/main.py` integration.

Active Nmap Basic Microphase 48 is documented in `docs/future/active-nmap-basic-backend-active-nmap-route-to-lifecycle-no-live.md` with decision `ACTIVE_NMAP_BASIC_48_BACKEND_ACTIVE_NMAP_ROUTE_TO_LIFECYCLE_NO_LIVE_PASSED`. It connects the existing `POST /active/network/nmap-basic` endpoint to the lifecycle skeleton only in no-live/fake-client mode. The route keeps the feature flag disabled by default, validates the existing request contract and target policy before lifecycle invocation, returns controlled lifecycle metadata directly, and no longer creates a persistent `active_nmap_basic` job on that path. It does not call real `active-tools`, execute Nmap, run `nmap --version`, perform probes/DNS/external HTTP, persist storage, create exports, change frontend runtime, integrate archive/run-all, integrate `tools/runner/main.py`, approve targets, release, or tag state.

Active Nmap Basic v0 functional closeout is documented in `docs/future/active-nmap-basic-v0-functional-closeout.md` with decision `ACTIVE_NMAP_BASIC_56_ACTIVE_NMAP_V0_FUNCTIONAL_CLOSEOUT_ACCEPTED`. It closes the bounded v0 capability after real-minimal integration and boundary review: frontend submit contract, backend policy/lifecycle/storage/reporting, internal/local active-tools calls only, Nmap isolated to active-tools, owner-scoped redacted jobs, redaction-first reporting/Raw JSON/frontend, observed TCP exposure / review-indicator wording, manual validation required, and disabled-by-default feature posture. It does not approve public scanner/SaaS behavior, arbitrary public targets, unfrozen LAN/VPS/domain targets, port `80`, broad ranges/CIDR/wildcards, top ports, `-p-`, raw flags, NSE/scripts, service/version or OS detection, UDP/SYN, brute force, exploit scripts, credential validation, crawling, DNS expansion, backend subprocesses, Docker socket, archive/run-all, `tools/runner/main.py`, vulnerability/exploitability/target-safety/full-coverage claims, release, tag, or push state.

Active Nmap Basic v0 operational usage polish is documented in `docs/future/active-nmap-basic-v0-operational-usage.md` with decision `ACTIVE_NMAP_BASIC_57_OPERATIONAL_USAGE_POLISH_ACCEPTED`. It explains how trusted operators enable or disable the backend and internal `active-tools` flags, review the optional active-tools Compose profile, check `GET /health/active-tools`, use only authorized local/private/self-hosted targets, interpret owner-scoped redacted jobs, and troubleshoot controlled disabled/unconfigured/no-live states. This is documentation only and adds no runtime behavior, Docker runtime smoke, Nmap execution, release, tag, or push state.

Active TLS Basic design is documented in `docs/future/active-tls-basic-design.md` with decision `ACTIVE_TLS_BASIC_01_DESIGN_FROZEN`. It defines a future opt-in `active_tls_basic` contract for one explicit authorized local/private/self-hosted target, one bounded port, explicit confirmations, short timeout, owner-scoped redacted storage, bounded handshake/certificate summary fields, manual validation, and TLS review-indicator wording. This phase is docs-only and does not add socket/network execution, OpenSSL commands, Python `ssl` connections, Nmap, Docker, crawling, credential validation, frontend runtime, archive/run-all, `tools/runner/main.py`, release, tag, or push state.

Active TLS Basic backend contract gate is documented in `docs/future/active-tls-basic-backend-contract-gate.md` with decision `ACTIVE_TLS_BASIC_02_BACKEND_CONTRACT_GATE_ACCEPTED`. It adds `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED=false` and `POST /active/network/tls-basic`, validates only the exact future contract and required confirmations, rejects dangerous extra fields, and returns `not_executed` without creating jobs or attempting TLS/network execution.

Active TLS Basic backend real-minimal job persistence is documented in `docs/future/active-tls-basic-backend-real-minimal-job-persistence.md` with decision `ACTIVE_TLS_BASIC_03_BACKEND_REAL_MINIMAL_TLS_JOB_PERSISTENCE_PASSED`. The enabled route now creates an owner-scoped `active_tls_basic` job after auth, feature gate, exact contract validation, target policy acceptance, and confirmations. It attempts one bounded TLS handshake through structured Python APIs in the dedicated backend module only, stores `[REDACTED_TARGET]`, bounded handshake/certificate metadata, controlled reason codes, and review-indicator wording, and still adds no OpenSSL shell, subprocess, Nmap, Docker, HTTP/crawling, frontend runtime, archive/run-all, or `tools/runner/main.py`.

Active TLS Basic frontend and product smoke is documented in `docs/future/active-tls-basic-frontend-and-e2e-product-smoke.md` with decision `ACTIVE_TLS_BASIC_04_FRONTEND_AND_E2E_PRODUCT_SMOKE_PASSED`. The UI now provides a separate Active / TLS basic panel, sends the exact backend contract, selects the returned `202 JobRecord`, refreshes jobs, and renders TLS handshake and certificate expiry review indicators with redacted Raw JSON. The smoke uses mocks/control fixtures and adds no new real target execution, OpenSSL command, subprocess, Nmap, Docker, HTTP/crawling, archive/run-all, or `tools/runner/main.py`.

Active TLS Basic v0 functional closeout is documented in `docs/future/active-tls-basic-v0-functional-closeout.md` with decision `ACTIVE_TLS_BASIC_05_FUNCTIONAL_REVIEW_AND_CLOSEOUT_ACCEPTED`. It freezes the v0 boundary after backend and frontend review: disabled by default, exact contract, one authorized local/private/self-hosted target, one bounded TLS-basic port, one structured Python TLS handshake attempt in the dedicated backend module, owner-scoped redacted jobs, reporting/Raw JSON/frontend review-indicator wording, and no new real target execution, OpenSSL command, subprocess, Nmap, Docker/Compose, HTTP/crawling, archive/run-all, or `tools/runner/main.py`.

Active DNS Inventory design is documented in `docs/future/active-dns-inventory-design.md` with decision `ACTIVE_DNS_INVENTORY_01_DESIGN_FROZEN`. It defines a future opt-in `active_dns_inventory` contract for one explicit authorized domain, bounded standard DNS record types, controlled subdomain discovery, explicit `coverage_level`, future authorized AXFR, owner-scoped redaction, and DNS configuration review-indicator wording. The design is now amended by the AXFR closeout to keep core Active DNS attacker-equivalent and to keep provider import out-of-core as a possible separate admin inventory connector. This phase is docs-only and adds no DNS query runtime, sockets, shell commands, Nmap, Docker, HTTP, frontend runtime, archive/run-all, `tools/runner/main.py`, release, tag, or push state.

Active DNS Inventory backend contract gate is documented in `docs/future/active-dns-inventory-backend-contract-gate.md` with decision `ACTIVE_DNS_INVENTORY_02_BACKEND_CONTRACT_GATE_ACCEPTED`. It adds `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED=false` and `POST /active/network/dns-inventory`, validates the exact future contract, rejects unsafe fields and unsupported AXFR attempts, and returns controlled `not_executed` metadata without DNS queries, jobs, storage, frontend runtime, archive/run-all, or `tools/runner/main.py`.

Active DNS Inventory standard records and bounded discovery are documented in `docs/future/active-dns-inventory-standard-records-bounded-discovery.md` with decision `ACTIVE_DNS_INVENTORY_03_STANDARD_RECORDS_AND_BOUNDED_DISCOVERY_PASSED`. The enabled endpoint now creates owner-scoped `active_dns_inventory` jobs with redacted domain storage, allowlisted standard DNS record groups, SPF/DMARC/CAA review indicators, fixed-candidate subdomain discovery counts, controlled partial coverage, and report/export redaction. DNS runtime is confined to `backend/app/active_dns_inventory.py`; there is no frontend runtime, Nmap, Docker, HTTP, AXFR, provider import, archive/run-all, or `tools/runner/main.py` integration.

Active DNS Inventory backend runtime review is documented in `docs/future/active-dns-inventory-backend-runtime-review.md` with decision `ACTIVE_DNS_INVENTORY_04_BACKEND_RUNTIME_REVIEW_PASSED`. It hardens query accounting to one configured nameserver per logical query and confirms the runtime remains bounded, redaction-first, and distinct from complete-zone coverage, with no AXFR, provider API, CT/passive DNS, DNS CLI, subprocess, Nmap, Docker, HTTP, frontend, archive/run-all, or `tools/runner/main.py` integration.

Active DNS Inventory frontend and product smoke are documented in `docs/future/active-dns-inventory-frontend-e2e-product-smoke.md` with decision `ACTIVE_DNS_INVENTORY_05_FRONTEND_AND_E2E_PRODUCT_SMOKE_PASSED`. The UI now creates owner-scoped DNS inventory jobs through the existing backend contract, refreshes/selects the returned `JobRecord`, and renders grouped redacted records, SPF/DMARC/CAA review indicators, bounded subdomain summary, not-attempted AXFR/provider states, manual validation copy, and redacted Raw JSON without presenting best-effort results as complete-zone coverage.

Active DNS Inventory v0 functional closeout is documented in `docs/future/active-dns-inventory-v0-functional-closeout.md` with decision `ACTIVE_DNS_INVENTORY_06_FUNCTIONAL_REVIEW_AND_CLOSEOUT_ACCEPTED`. It freezes the v0 approved state as disabled-by-default, one explicit authorized root domain, allowlisted standard records, SPF/DMARC/CAA indicators, fixed-candidate bounded subdomain discovery, owner-scoped redacted jobs, and `best_effort_inventory` / `partial_inventory` coverage only, while keeping AXFR, provider import, CT/passive DNS, broad discovery, DNS CLI/subprocess, Nmap, Docker, HTTP/crawling, archive/run-all, public scanner behavior, and complete-coverage claims out of scope.

Active DNS Inventory authorized AXFR backend is documented in `docs/future/active-dns-inventory-authorized-axfr-backend.md` with decision `ACTIVE_DNS_INVENTORY_07_AUTHORIZED_AXFR_BACKEND_PASSED`. The existing backend route can now accept `attempt_zone_transfer: true` only with `zone_transfer_authorized_confirmed: true`; it resolves authoritative NS records for the exact domain, attempts a bounded TCP AXFR through the dedicated DNS inventory module, and persists only redacted counters plus allowlisted record groups. Successful bounded AXFR may set `coverage_level: zone_transfer_complete`; refused, unavailable, timed-out, malformed, or oversized AXFR stays controlled. This adds no frontend AXFR control, provider import, CT/passive DNS, DNS CLI/subprocess, Nmap, Docker, HTTP/crawling, archive/run-all, `tools/runner/main.py`, public scanner behavior, or vulnerability/exploitability claims.

Active DNS Inventory authorized AXFR backend review is documented in `docs/future/active-dns-inventory-authorized-axfr-backend-review.md` with decision `ACTIVE_DNS_INVENTORY_08_AUTHORIZED_AXFR_BACKEND_REVIEW_PASSED`. The review found and fixed the terminal-SOA boundary so partial AXFR data cannot become `zone_transfer_complete`, tightened attempted-NS accounting, and added an internal TXT value cap while preserving the backend-only, redaction-first, no-provider/no-CT/no-passive-DNS/no-frontend boundary.

Active DNS Inventory authorized AXFR frontend integration is documented in `docs/future/active-dns-inventory-frontend-authorized-axfr.md` with decision `ACTIVE_DNS_INVENTORY_09_FRONTEND_AUTHORIZED_AXFR_PASSED`. The UI exposes AXFR only as an off-by-default option with a separate `zone_transfer_authorized_confirmed` confirmation, sends `attempt_zone_transfer: true` only when specifically confirmed, and renders AXFR states/counters as controlled DNS configuration review indicators with redacted Raw JSON. It adds no real AXFR execution, new DNS traffic, provider import, CT/passive DNS, DNS CLI/subprocess, Nmap, Docker, HTTP/crawling, archive/run-all, or `tools/runner/main.py`.

Active DNS Inventory authorized AXFR frontend review is documented in `docs/future/active-dns-inventory-frontend-authorized-axfr-review.md` with decision `ACTIVE_DNS_INVENTORY_10_FRONTEND_AUTHORIZED_AXFR_REVIEW_PASSED`. It confirms AXFR remains off by default, requires the specific confirmation, sends the correct request contract, renders refused/timed-out/malformed/unavailable/record-limit outcomes as controlled states, keeps report/Raw JSON redaction-first, and adds no new DNS runtime, real AXFR execution, provider API, CT/passive DNS, DNS CLI/subprocess, Nmap, Docker, HTTP/crawling, archive/run-all, or `tools/runner/main.py`.

Active DNS Inventory functional closeout with authorized AXFR is documented in `docs/future/active-dns-inventory-with-authorized-axfr-functional-closeout.md` with decision `ACTIVE_DNS_INVENTORY_11_FUNCTIONAL_CLOSEOUT_WITH_AXFR_ACCEPTED`. It closes the expanded v0 boundary as attacker-equivalent DNS visibility: disabled by default, one authorized domain, allowlisted records, bounded subdomain discovery, optional specifically confirmed AXFR against authoritative nameservers for the exact domain, terminal-SOA validation before `zone_transfer_complete`, owner-scoped `[REDACTED_DOMAIN]` jobs, redaction-first reports/Raw JSON/frontend, conservative AXFR wording, and manual validation required. Provider import is out of core Active DNS and would require a separate admin inventory connector if ever pursued; CT/passive DNS remains a possible separate public-OSINT phase, not part of this block. Broad discovery, DNS CLI/subprocess, Nmap, Docker, HTTP/crawling, archive/run-all, `tools/runner/main.py`, public scanner behavior, and vulnerability/exploitability/target-safety claims remain out of scope.

Active DNS OSINT design is documented in `docs/future/active-dns-osint-design.md` with decision `ACTIVE_DNS_OSINT_01_DESIGN_FROZEN`. It defines a future separate `active_dns_osint` capability for one authorized domain and public-source observed names, starting with bounded Certificate Transparency discovery and leaving passive DNS for a later concrete-source phase. Results are always `osint_best_effort` review indicators with redacted domain/name samples and manual validation required. It adds no runtime CT/passive DNS queries, HTTP requests, DNS queries, provider DNS/API import, credentials/API keys, crawling, broad scraping, search-engine scraping, broad wordlists, reverse-IP/ASN/range discovery, Nmap, Docker, subprocess, archive/run-all, `tools/runner/main.py`, release, tag, or push behavior.

Active DNS OSINT backend contract gate is documented in `docs/future/active-dns-osint-backend-contract-gate.md` with decision `ACTIVE_DNS_OSINT_02_BACKEND_CONTRACT_GATE_ACCEPTED`. That phase introduced `POST /active/network/dns-osint` behind `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED=false` by default. Enabled valid requests validate the exact `live_dns_osint` / `ct_subdomain_discovery_bounded` body, authorization confirmations, CT/passive-DNS source flags, one-domain policy, and `max_names` cap before returning `not_executed`. It created no jobs, persisted no storage, sent no CT/passive-DNS/HTTP/DNS requests, handled no provider credentials, and did not touch frontend, archive/run-all, or `tools/runner/main.py`.

Active DNS OSINT CT bounded backend persistence is documented in `docs/future/active-dns-osint-ct-bounded-backend-job-persistence.md` with decision `ACTIVE_DNS_OSINT_03_CT_BOUNDED_BACKEND_JOB_PERSISTENCE_PASSED`. The same endpoint now persists owner-scoped `active_dns_osint` jobs with `file_id: null`, `[REDACTED_DOMAIN]`, `coverage_level: osint_best_effort`, source status, observed-name counters, placeholder samples, truncation state, and redaction-first detail/list/export surfaces. The CT source is injectable/fakeable and disabled by default; this phase still sends no real CT, HTTP, DNS, passive-DNS, or provider requests and adds no frontend, archive/run-all, `tools/runner/main.py`, Nmap, Docker, or subprocess behavior.

Active DNS OSINT CT bounded backend review is documented in `docs/future/active-dns-osint-ct-bounded-backend-review.md` with decision `ACTIVE_DNS_OSINT_04_CT_BOUNDED_BACKEND_REVIEW_PASSED`. It reviews `d233d51` and confirms contract gating, disabled-by-default behavior, fakeable/default-disabled CT source semantics, in-domain observed-name filtering, redaction-first storage/report/export/Raw JSON, and OSINT best-effort wording without approving real CT, HTTP, passive DNS, provider API, DNS queries, frontend, archive/run-all, `tools/runner/main.py`, Nmap, Docker, subprocess, release, tag, or push behavior.

Active DNS OSINT real CT source is documented in `docs/future/active-dns-osint-real-ct-source-bounded.md` with decision `ACTIVE_DNS_OSINT_05_REAL_CT_SOURCE_BOUNDED_PASSED`. It chooses `crt.sh` as the first source and accepts only a bounded `GET /?q=%.<authorized-domain>&output=json` call after both the backend feature flag and CT source flag are enabled, the source URL is explicitly configured, and the request contract passes. Public surfaces remain `[REDACTED_DOMAIN]` / `[REDACTED_DNS_NAME]`, `osint_best_effort`, and manual-validation wording.

Active DNS OSINT real CT source review is documented in `docs/future/active-dns-osint-real-ct-source-review.md` with decision `ACTIVE_DNS_OSINT_06_REAL_CT_SOURCE_REVIEW_PASSED`. It reviews `57bc31d`, hardens source URL validation to reject explicit custom ports, and confirms bounded `crt.sh` behavior, fake-transport tests, in-domain parsing, redaction-first reporting/export/Raw JSON, and best-effort OSINT wording.

Active DNS OSINT frontend CT product flow is documented in `docs/future/active-dns-osint-frontend-ct-osint-product-flow.md` with decision `ACTIVE_DNS_OSINT_07_FRONTEND_CT_OSINT_PRODUCT_FLOW_PASSED`. It adds a separate `Active / DNS OSINT` panel, exact CT-bounded submit contract, required authorization/domain/public-OSINT confirmations, `202 JobRecord` selection and refresh, redacted report/Raw JSON rendering, and passive DNS displayed as unavailable. The browser does not call CT, passive DNS, provider APIs, DNS resolvers, archive/run-all, or `tools/runner/main.py`.

## Requirements

- Docker
- Docker Compose v2

## Run Locally

```bash
mkdir -p data/uploads data/results
docker compose up --build
```

The backend will be available at:

```text
http://localhost:8000
```

The frontend will be available at:

```text
http://localhost:5173
```

Healthcheck:

```bash
curl http://localhost:8000/health
```

## Configuration

The application defaults are intentionally conservative. Docker Compose sets many of these values explicitly, and the backend/runner fall back to these defaults when a variable is unset:

| Variable | Service | Default | Purpose |
| --- | --- | --- | --- |
| `INSPECTRA_AUTH_MODE` | backend | `trusted_local_no_auth` | Explicit auth/deployment mode flag. Current default preserves trusted local behavior; accepted values also include `self_hosted_single_admin`, `private_team_lightweight_users`, and `public_community_limited_instance` for future gated runtime work. |
| `INSPECTRA_ADMIN_PASSWORD_HASH` | backend | unset | Single-admin credential hash for `self_hosted_single_admin`. Supported format is `pbkdf2_sha256$iterations$salt$digest`; the hash is used only by backend login verification and is never returned by `/auth/status` or login responses. |
| `INSPECTRA_SESSION_TTL_SECONDS` | backend | `3600` | Single-admin session TTL and session-cookie max age. Login/logout endpoints use it for the `inspectra_session` cookie, mutating cookie-auth routes require the session-bound `X-CSRF-Token`, and the frontend fetches auth status, performs login/logout, keeps CSRF in memory only, sends `X-CSRF-Token` on mutating requests, and shows controlled copy for login `429` rate-limit responses. |
| `INSPECTRA_AUTH_STATE_STORE` | backend | `memory` | Auth-state backend for `self_hosted_single_admin` sessions and login-attempt lockout state. Accepted values are `memory` and `sqlite`; `sqlite` is opt-in and keeps `trusted_local_no_auth` memory-backed. |
| `INSPECTRA_AUTH_STATE_DB_PATH` | backend | `data/runtime/auth_state.sqlite3` under `INSPECTRA_DATA_DIR` when SQLite is enabled | Optional SQLite auth-state DB path for persistent self-hosted sessions and login attempts. The DB stores hashed session, CSRF, and login client-key material, not raw session ids, CSRF tokens, passwords, admin password hashes, request bodies, or raw client keys. |
| `INSPECTRA_CORS_ORIGINS` | backend | `http://localhost:5173` | Comma-separated browser origins allowed in development. |
| `INSPECTRA_DATA_DIR` | backend, audit-tools | `/app/data` | Local data mount used for uploads and results. |
| `INSPECTRA_MAX_UPLOAD_BYTES` | backend | `20971520` | Maximum accepted upload size. Default is 20 MB. |
| `INSPECTRA_TOOL_RUNNER_URL` | backend | `http://audit-tools:8081` | Internal URL for the tool runner. |
| `INSPECTRA_TOOL_TIMEOUT_SECONDS` | audit-tools | `10` | Timeout applied to each external tool command. |
| `INSPECTRA_ARCHIVE_MAX_ENTRIES` | audit-tools | `5000` | Maximum archive entries inspected before truncating the result. |
| `INSPECTRA_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES` | audit-tools | `209715200` | Informational archive-size threshold, defaulting to 200 MB. |
| `INSPECTRA_ARCHIVE_MAX_ENTRY_NAME_LENGTH` | audit-tools | `512` | Entry-name length threshold for review findings. |
| `INSPECTRA_ARCHIVE_MAX_LISTED_ENTRIES` | audit-tools | `200` | Maximum archive entries and detected manifests listed in the result. |
| `INSPECTRA_ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES` | audit-tools | `8388608` | Maximum standard ZIP central directory size accepted before detailed ZIP metadata parsing. |
| `INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFESTS` | audit-tools | `25` | Maximum supported manifests parsed from one archive. |
| `INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFEST_BYTES` | audit-tools | `1048576` | Maximum bytes read per supported manifest inside an archive. |
| `INSPECTRA_PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES` | audit-tools | `5242880` | Maximum total supported-manifest bytes read per project archive analysis. |
| `INSPECTRA_PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES` | audit-tools | `5000` | Maximum archive entries scanned while looking for internal manifests. |
| `INSPECTRA_DJANGO_CONFIG_MAX_FILES` | backend, audit-tools | `100` | Maximum Django-related config/deployment/dependency files read from one archive. |
| `INSPECTRA_DJANGO_CONFIG_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one Django config candidate file. |
| `INSPECTRA_DJANGO_CONFIG_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one Django config audit. |
| `INSPECTRA_DOCKER_CONFIG_MAX_FILES` | backend, audit-tools | `100` | Maximum Docker/Compose candidate files read from one archive. |
| `INSPECTRA_DOCKER_CONFIG_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one Docker config candidate file. |
| `INSPECTRA_DOCKER_CONFIG_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one Docker config audit. |
| `INSPECTRA_SECRETS_REVIEW_MAX_FILES` | backend, audit-tools | `100` | Maximum secrets-review candidate files read from one archive. |
| `INSPECTRA_SECRETS_REVIEW_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one secrets-review candidate file. |
| `INSPECTRA_SECRETS_REVIEW_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one secrets-review audit. |
| `INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILES` | backend, audit-tools | `100` | Maximum Node package/config candidate files read from one archive. |
| `INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one Node package/config candidate file. |
| `INSPECTRA_NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one Node package/config audit. |
| `INSPECTRA_CI_CD_CONFIG_MAX_FILES` | backend, audit-tools | `100` | Maximum CI/CD config candidate files read from one archive. |
| `INSPECTRA_CI_CD_CONFIG_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one CI/CD config candidate file. |
| `INSPECTRA_CI_CD_CONFIG_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one CI/CD config audit. |
| `INSPECTRA_K8S_CONFIG_MAX_FILES` | backend, audit-tools | `100` | Maximum Kubernetes manifest/config candidate files read from one archive. |
| `INSPECTRA_K8S_CONFIG_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one Kubernetes config candidate file. |
| `INSPECTRA_K8S_CONFIG_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one Kubernetes config audit. |
| `INSPECTRA_TERRAFORM_CONFIG_MAX_FILES` | backend, audit-tools | `100` | Maximum Terraform/OpenTofu/Terragrunt candidate files read from one archive. |
| `INSPECTRA_TERRAFORM_CONFIG_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one Terraform config candidate file. |
| `INSPECTRA_TERRAFORM_CONFIG_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one Terraform config audit. |
| `INSPECTRA_NGINX_CONFIG_MAX_FILES` | backend, audit-tools | `100` | Maximum Nginx/reverse-proxy config candidate files read from one archive. |
| `INSPECTRA_NGINX_CONFIG_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one Nginx config candidate file. |
| `INSPECTRA_NGINX_CONFIG_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one Nginx config audit. |
| `INSPECTRA_COMPOSE_CONFIG_MAX_FILES` | backend, audit-tools | `100` | Maximum Docker Compose candidate files read from one archive. |
| `INSPECTRA_COMPOSE_CONFIG_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one Compose config candidate file. |
| `INSPECTRA_COMPOSE_CONFIG_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one Compose config audit. |
| `INSPECTRA_DATABASE_CONFIG_MAX_FILES` | backend, audit-tools | `100` | Maximum PostgreSQL/MySQL/MariaDB config candidate files read from one archive. |
| `INSPECTRA_DATABASE_CONFIG_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one Database config candidate file. |
| `INSPECTRA_DATABASE_CONFIG_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one Database config audit. |
| `INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILES` | backend, audit-tools | `100` | Maximum SQL database config candidate files read from one archive. |
| `INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one SQL DB config candidate file. |
| `INSPECTRA_SQL_DATABASE_CONFIG_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one SQL DB config audit. |
| `INSPECTRA_REDIS_CONFIG_MAX_FILES` | backend, audit-tools | `100` | Maximum Redis/Sentinel config candidate files read from one archive. |
| `INSPECTRA_REDIS_CONFIG_MAX_FILE_BYTES` | backend, audit-tools | `524288` | Maximum bytes read from one Redis config candidate file. |
| `INSPECTRA_REDIS_CONFIG_MAX_TOTAL_BYTES` | backend, audit-tools | `2097152` | Maximum total bytes read for one Redis config audit. |
| `INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS` | backend, audit-tools | `false` | Allows private/loopback web targets for labs when set to `true`; cloud metadata/link-local targets remain blocked. |
| `INSPECTRA_WEB_TIMEOUT_SECONDS` | backend, audit-tools | `10` | Timeout for each controlled HTTP/HTTPS request in the web audit. |
| `INSPECTRA_WEB_MAX_RESPONSE_BYTES` | backend, audit-tools | `1048576` | Maximum bytes read from each web response. |
| `INSPECTRA_WEB_MAX_REDIRECTS` | backend, audit-tools | `5` | Maximum redirects followed by the web audit. Each redirect target is validated before use. |
| `INSPECTRA_WEB_ALLOWED_PORTS` | backend, audit-tools | `80,443` | Comma-separated ports accepted in web audit URLs. Add lab ports such as `8000,8080,8443` only for authorized environments. |
| `INSPECTRA_DOMAIN_DNS_TIMEOUT_SECONDS` | backend, audit-tools | `5` | Timeout for each bounded DNS query/resolver attempt in the domain baseline audit. The backend calculates a larger runner-call timeout from this value so the runner can finish its bounded query set. |
| `INSPECTRA_SUBDOMAIN_MAX_CANDIDATES` | backend, audit-tools | `100` | Maximum explicitly supplied subdomain candidates accepted for one controlled inventory job. |
| `INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS` | backend, audit-tools | `2` | Maximum random wildcard-DNS probe labels checked under the root domain. Set to `0` to disable the heuristic. |
| `INSPECTRA_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS` | backend, audit-tools | `30` | Global runner deadline for one subdomain inventory job. The backend runner-call timeout is this deadline plus one in-flight DNS query budget and a small safety margin. |
| `INSPECTRA_ACTIVE_DRY_RUN_ENABLED` | backend | `false` | Enables `POST /active/network/dry-run`, which creates no-network `active_network_dry_run` planning jobs. Disabled deployments reject the endpoint without creating jobs. |
| `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED` | backend | `false` | Enables `POST /active/network/http-header-probe`, which creates `active_http_header_probe` jobs after explicit live authorization. Disabled deployments reject the endpoint without creating jobs. |
| `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED` | backend | `false` | Enables the bounded `POST /active/network/nmap-basic` backend contract gate. Real minimal execution still requires configured internal `active-tools`, explicit confirmations, target policy acceptance, and active-tools execution enablement. |
| `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED` | backend | `false` | Enables the bounded `POST /active/network/tls-basic` backend route. Enabled valid requests create owner-scoped redacted `active_tls_basic` jobs after one structured Python TLS handshake attempt against the validated target/port; no OpenSSL shell, subprocess, Nmap, Docker, HTTP/crawling, frontend runtime, archive/run-all, or runner behavior is added. |
| `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED` | backend | `false` | Enables the bounded `POST /active/network/dns-inventory` backend route. Enabled valid requests create owner-scoped redacted `active_dns_inventory` jobs for one authorized root domain with allowlisted DNS records, SPF/DMARC/CAA indicators, fixed-candidate subdomain discovery, and optional explicitly authorized AXFR. `zone_transfer_complete` is used only after bounded authorized AXFR succeeds; otherwise output remains best-effort or partial review-indicator coverage. |
| `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED` | backend | `false` | Enables the bounded `POST /active/network/dns-osint` backend route. Enabled valid requests create owner-scoped redacted `active_dns_osint` jobs using an injectable CT source adapter; the default source is disabled, and bounded `crt.sh` use requires `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED=true` plus `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_URL=https://crt.sh/`. |
| `INSPECTRA_ACTIVE_TOOLS_URL` | backend | empty | Optional internal `active-tools` base URL for backend health checks and the Active / Nmap basic internal client. Empty means unconfigured and maps to controlled unavailable/no-live behavior. Non-empty values must be internal/local service URLs without credentials, path, query, or fragment. |
| `INSPECTRA_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS` | backend | `2` | Timeout for the backend `active-tools` `/health` helper. |
| `INSPECTRA_ACTIVE_TOOLS_NMAP_BASIC_EXECUTION_ENABLED` | active-tools | `false` | Enables bounded Nmap execution inside the internal `active-tools` service only. Disabled mode returns controlled no-live behavior; the backend never executes Nmap directly. |
| `VITE_API_BASE_URL` | frontend | `http://localhost:8000` | Browser-facing backend URL used by the React app. |

The `audit-tools` container is attached to the internal Inspectra network and to a separate egress-capable network so `web_basic` can make authorized HTTP/HTTPS requests and `domain_basic`/`subdomain_inventory_basic` can make bounded DNS queries. The runner still does not publish a public port.

### Active / Nmap Basic v0

Active / Nmap basic v0 is an opt-in local/private/self-hosted capability. The backend gate is controlled by `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED`; real minimal execution also requires `INSPECTRA_ACTIVE_TOOLS_URL` to point to an internal/local active-tools base URL without credentials, path, query, or fragment, and requires `INSPECTRA_ACTIVE_TOOLS_NMAP_BASIC_EXECUTION_ENABLED=true` inside active-tools. The backend never executes Nmap directly.

The optional active-tools Compose example is behind profile `active`, publishes no host ports by default, and can be reviewed statically with:

```bash
COMPOSE_DISABLE_ENV_FILE=1 docker compose -f docker-compose.active-tools.example.yml --profile active config --no-interpolate
```

Use `GET /health/active-tools` for targetless active-tools readiness. Approved targets must be authorized and local/private/self-hosted; broad ranges, CIDR, wildcards, top ports, `-p-`, port `80`, raw flags, NSE/scripts, service/version or OS detection, UDP/SYN, brute force, credential validation, crawling, DNS expansion, and arbitrary public target use remain outside v0. Jobs are owner-scoped, `file_id: null`, target-redacted, and reports/Raw JSON/frontend render minimal TCP observations only as observed exposure / review indicators requiring manual validation. See `docs/future/active-nmap-basic-v0-operational-usage.md` for the full operational guide.

## Use the Web UI

Open:

```text
http://localhost:5173
```

From the UI you can check backend health, upload PDFs, images, manifests, or archives, submit an authorized URL for baseline web audit, submit an authorized domain for DNS baseline audit, submit explicit authorized subdomain candidates for inventory, list uploaded files, launch matching audits, delete uploaded files, list recent jobs, and inspect job results.

For archive files, the file list shows archive actions for `Analyze archive`, `Analyze project manifests`, `Analyze Django config`, `Analyze Docker config`, `Analyze secrets review`, `Analyze Node package config`, `Analyze CI/CD config`, `Analyze Kubernetes config`, `Analyze Terraform config`, `Analyze Nginx config`, `Analyze Compose config`, `Analyze database config`, `Analyze SQL DB config`, and `Analyze Redis config`. These launch passive, bounded, archive-only review jobs for their respective configuration surfaces.

The dashboard includes client-side counters, file filters by kind, job filters by status and audit type, quick search fields, manual refresh, and gentle auto-refresh while jobs are queued or running.

From the upload panel, choose `PDF`, `Image`, `Manifest`, or `Archive`. Image uploads currently accept JPEG, PNG, and WebP. Manifest uploads currently accept `package.json`, `requirements.txt`, and `pyproject.toml`. Archive uploads currently accept `.zip`, `.tar`, `.tar.gz`, and `.tgz`. Inspectra does not render image previews or extract archives broadly in this phase.

Completed PDF, image, manifest, archive, project-archive, Django config, Docker config, secrets review, Node package config, CI/CD config, Kubernetes config, Terraform config, Nginx config, Compose config, Database config, SQL DB config, Redis config, web, domain, and subdomain jobs show readable reports with:

- General job summary.
- Hashes.
- File identification.
- Metadata from passive tools.
- PDF `qpdf --check` validation when relevant.
- Image privacy indicators such as GPS, creator, serial number, device, and software metadata presence.
- Manifest project metadata, dependencies by group, scripts, and informational supply-chain indicators.
- Archive structure metrics, detected manifest filenames, entries sample, path traversal indicators, sensitive-name indicators, nested archives, and size/compression indicators.
- Project-archive supported manifests, unsupported manifest filenames, parsed dependencies, scripts, parser findings, limits, truncation, and controlled errors.
- Django config detected files, settings/deployment signals, secret-redaction notes, heuristic findings, limits, truncation, and controlled errors.
- Docker config exported reports include detected Docker/Compose files, Dockerfile stages, Compose service names, heuristic findings, redaction notes, limits, truncation, and controlled errors.
- Secrets review reports include sensitive files detected but not read, files reviewed, heuristic findings grouped by severity, confidence/context metadata, redaction notes, limits, truncation, controlled errors, and redacted raw JSON.
- Node package config reports include package/workspace overview, scripts, dependency groups, package manager config signals, lockfile signals, heuristic findings, redaction notes, limits, truncation, controlled errors, and redacted raw JSON.
- CI/CD config reports include workflow overviews, triggers, permissions, jobs/steps, actions/images, service containers, publish/deploy signals, heuristic findings, redaction notes, limits, truncation, controlled errors, and redacted raw JSON.
- Kubernetes config reports include resource overviews, workloads/containers, services/ingress, RBAC, secrets/config references, Helm/Kustomize signals, heuristic findings, redaction notes, limits, truncation, controlled errors, and redacted raw JSON.
- Terraform config reports include providers/backends, modules, resources, variables/outputs, state files detected but not read, heuristic findings, redaction notes, limits, truncation, controlled errors, and redacted raw JSON.
- Nginx config reports include server blocks, locations, upstreams/proxy targets, includes detected but not resolved, directives, heuristic findings, redaction notes, limits, truncation, controlled errors, and redacted raw JSON.
- Compose config reports include services, images/build contexts, published ports, volumes, networks, secrets/env file references detected but not read, heuristic findings, redaction notes, limits, truncation, controlled errors, and redacted raw JSON.
- Database config reports include PostgreSQL/MySQL/MariaDB settings, pg_hba rules, includes detected but not resolved, dumps/backups/credential files detected but not read, heuristic findings, redaction notes, limits, truncation, controlled errors, and redacted raw JSON.
- SQL DB config reports include PostgreSQL/MySQL/MariaDB settings, pg_hba rules, includes detected but not resolved, hidden credential files, dumps/backups, data/WAL/binlog/InnoDB files detected but not read, heuristic findings, redaction notes, limits, truncation, controlled errors, and redacted raw JSON.
- Redis config reports include Redis settings, Sentinel settings, includes detected but not resolved, ACL files detected but not read, dumps/RDB/AOF/appendonly/backups detected but not read, heuristic findings, redaction notes, limits, truncation, controlled errors, and redacted raw JSON.
- Web target URL, redirects, HTTP status, response headers, security headers, cookies, TLS certificate summary, `robots.txt`, `security.txt`, and informational configuration findings.
- Domain DNS baseline records, email security checks, `www` baseline, and informational DNS findings.
- Subdomain inventory candidate normalization, A/AAAA/CNAME results, wildcard-DNS heuristic, and informational findings.
- Tool errors and timeouts.
- Optional raw JSON for debugging.

The job detail panel also offers export buttons for Markdown, HTML, XML, and PDF. Completed `manifest_basic` and `project_archive_basic` jobs also show SBOM export buttons for CycloneDX JSON and SPDX JSON. Exports are generated by the backend from the stored job JSON and downloaded from Inspectra.

## Upload a PDF

```bash
curl -sS -F "file=@/path/to/file.pdf;type=application/pdf" \
  http://localhost:8000/files/pdf
```

The response includes an `id`. Use it to launch the audit.

## Upload an Image

```bash
curl -sS -F "file=@/path/to/image.png;type=image/png" \
  http://localhost:8000/files/image
```

JPEG, PNG, and WebP are accepted. Inspectra validates image content using magic bytes, not only file extension or `Content-Type`.

## Upload a Manifest

```bash
curl -sS -F "file=@/path/to/package.json;type=application/json" \
  http://localhost:8000/files/manifest
```

Accepted names are `package.json`, `requirements.txt`, and `pyproject.toml`. Inspectra validates the filename and basic text/JSON/TOML structure, applies the same upload size limit, and stores the file as `kind: "manifest"`.

## Upload an Archive

```bash
curl -sS -F "file=@/path/to/project.zip;type=application/zip" \
  http://localhost:8000/files/archive
```

Accepted archive names are `.zip`, `.tar`, `.tar.gz`, and `.tgz`. Inspectra validates filename and initial content signatures before storing the file as `kind: "archive"`. Stronger format validation happens inside the `audit-tools` runner using Python standard library parsers.

## List Uploaded Files

```bash
curl -sS http://localhost:8000/files
```

The response contains registered metadata such as `id`, original filename, size, hash, and creation time. It does not expose absolute host paths.

## Launch a PDF Audit

```bash
curl -sS -X POST http://localhost:8000/audits/pdf/<file_id>
```

The response includes a job `id`.

## Launch an Image Audit

```bash
curl -sS -X POST http://localhost:8000/audits/image/<file_id>
```

The image audit runs passive identification, metadata extraction, hashing, and privacy indicator checks inside `audit-tools`.

## Launch a Manifest Audit

```bash
curl -sS -X POST http://localhost:8000/audits/manifest/<file_id>
```

The manifest audit parses local text only. It does not run npm, pip, Poetry, pnpm, yarn, project scripts, or dependency installation. It does not query external CVE databases in this phase.

## Launch an Archive Audit

```bash
curl -sS -X POST http://localhost:8000/audits/archive/<file_id>
```

The archive audit inspects container metadata passively with Python standard library parsers. It does not extract the full archive to the filesystem, follow symlinks, execute files, install dependencies, resolve internal manifests, or call the internet.

For ZIP files, Inspectra first reads the standard end-of-central-directory metadata to estimate declared entry count and central directory size before opening the archive with Python `zipfile`. If the declared entry count or central directory size exceeds configured limits, the result is marked truncated and detailed entry parsing is skipped. ZIP64 or inconclusive metadata is handled conservatively in this MVP. Upload size remains the primary guardrail for unusual ZIP metadata layouts.

## Launch a Project Archive Manifest Audit

```bash
curl -sS -X POST http://localhost:8000/audits/project-archive/<file_id>
```

The source file must be `kind: "archive"`. This audit opens the archive with Python standard library parsers, locates supported internal manifests, and reads only bounded manifest bytes in memory. It currently parses `package.json`, `requirements.txt`, and `pyproject.toml`; it detects but does not parse lockfiles and other ecosystem files such as `go.mod`, `Cargo.toml`, `pom.xml`, `composer.json`, and Docker Compose files.

It does not extract the project, execute files or scripts, follow symlinks, install dependencies, invoke package managers, resolve transitive dependencies, query CVEs, or call the internet.

## Launch a Django Config Audit

```bash
curl -sS -X POST http://localhost:8000/audits/django-config/<file_id>
```

The source file must be `kind: "archive"`. This creates a `django_config_basic` job that opens the archive with Python standard library parsers and reads only bounded text from Django-related candidate files such as `settings.py`, `settings/*.py`, environment templates, `requirements.txt`, `pyproject.toml`, `Dockerfile`, Docker Compose, nginx, gunicorn, systemd, and Procfile entries.

The analysis is heuristic and local. It looks for configuration indicators such as `DEBUG=True`, hardcoded or fallback `SECRET_KEY`, broad `ALLOWED_HOSTS`, insecure cookie/proxy/HTTPS settings, permissive CORS, SQLite or hardcoded database passwords, development `runserver` commands, and exposed database/cache ports in Compose files. Findings are review indicators, not confirmed vulnerabilities. Inspectra treats obvious development, test, local, example, and sample settings as lower-confidence context, ignores full-line comments for stronger settings evidence, and groups repeated missing-setting indicators to keep the report readable.

Inspectra does not execute Python, import Django settings, run `manage.py check`, install dependencies, connect to databases, extract the project, follow symlinks or hardlinks, query CVEs, or call the internet. Real environment files such as `.env`, `.env.production`, `.env.local`, and other `.env.*` variants are detected but not read; template files such as `.env.example`, `.env.template`, `.env.sample`, `env.example`, `env.template`, `env.sample`, and `sample.env` may be read within limits. Secret-like values in findings, exports, and the Django config UI report are redacted best-effort, but uploaded archives are stored locally and should not include real secrets unless that local storage risk is acceptable.

## Launch a Docker Config Audit

```bash
curl -sS -X POST http://localhost:8000/audits/docker-config/<file_id>
```

The source file must be `kind: "archive"`. This creates a `docker_config_basic` job that opens the archive with Python standard library parsers and reads only bounded text from Docker-related candidate files such as `Dockerfile`, `Dockerfile.*`, Docker Compose files, and `.dockerignore`.

The analysis is heuristic and local. It looks for review indicators such as missing or root `USER` directives, mutable `latest` image tags, unpinned base images, `curl`/`wget` piped to shell, privileged Compose services, host network or host namespace settings, Docker socket mounts, published database/cache ports, real `.env` file references, and sensitive-looking environment variable names. Findings are indicators for manual review, not confirmed vulnerabilities.

Inspectra does not execute Docker, invoke `docker compose`, build images, start containers, inspect the Docker socket, download images, resolve image tags, scan ports, query CVEs, extract the project broadly, follow symlinks or hardlinks, execute scripts, or call the internet. Secret-like values in Docker config findings and exports are redacted best-effort, but uploaded archives are stored locally and should not include real secrets unless that local storage risk is acceptable.

## Launch a Secrets Review Audit

```bash
curl -sS -X POST http://localhost:8000/audits/secrets-review/<file_id>
```

The source file must be `kind: "archive"`. This creates a `secrets_review_basic` job that opens the archive with Python standard library parsers, detects real `.env`, `.env.*`, and `.envrc` files without reading their content, and reads only bounded text from explicit candidate templates, app config, CI/CD config, Docker/Compose, Kubernetes, and Terraform-style files.

The analysis is heuristic and local. It looks for indicators such as secret-like assignments, private key blocks, credential-bearing database/Redis/basic-auth URLs, JWT-like values, inline CI secrets, Docker/Compose secret-like environment values, Kubernetes plaintext secret-like data, and Terraform variable defaults. Findings are review indicators, not confirmation that a credential is valid, active, leaked, or compromised.

Inspectra does not validate tokens, call provider APIs, scan Git history, run external scanners such as TruffleHog or Gitleaks, install dependencies, execute code, extract the project broadly, follow symlinks or hardlinks, query CVEs, or call the internet. Evidence and exports are redacted best-effort without storing prefixes, suffixes, or fingerprints of detected values. Uploaded archive bytes are still stored locally and may contain secrets, so avoid uploading real credentials unless that local storage risk is acceptable.

## Launch a Node Package Config Audit

```bash
curl -sS -X POST http://localhost:8000/audits/node-package-config/<file_id>
```

The source file must be `kind: "archive"`. This creates a `node_package_config_basic` job that opens the archive with Python standard library parsers and reads only bounded text from Node package/config candidates such as `package.json`, lockfiles, `.npmrc`, workspace config, JS/TS tool config, CI/publishing hints, and environment templates. Real `.env`, `.env.*`, and `.envrc` files are detected as sensitive but not read.

The analysis is heuristic and local. It looks for review indicators such as lifecycle scripts, curl-pipe-shell script patterns, broad or wildcard dependency ranges, Git/URL/file/workspace/alias dependency declarations, multiple or mismatched lockfiles, npm config token references, disabled npm TLS checks, unsafe-perm settings, and simple dev-server/config hints. Findings are indicators for manual review, not confirmed vulnerabilities or malicious-package verdicts.

Inspectra does not execute npm, pnpm, yarn, bun, npx, lifecycle scripts, JavaScript, TypeScript, or config files; it does not install dependencies, resolve transitive dependencies, download packages, query registries, run `npm audit`, query CVEs/advisories, extract the project broadly, follow symlinks or hardlinks, or call the internet. Secret-like `.npmrc` values, URLs with credentials, sensitive query parameters, and script assignment fragments are redacted best-effort in results and exports.

## Launch a CI/CD Config Audit

```bash
curl -sS -X POST http://localhost:8000/audits/ci-cd-config/<file_id>
```

The source file must be `kind: "archive"`. This creates a `ci_cd_config_basic` job that opens the archive with Python standard library parsers and reads only bounded text from CI/CD candidates such as GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines, CircleCI, Jenkins/generic pipeline files, release helpers, and workflow action descriptors. Real `.env`, `.env.*`, and `.envrc` files are detected as sensitive but not read.

The analysis is heuristic and local. It looks for review indicators such as broad or privileged triggers, missing or broad GitHub permissions, unpinned actions or mutable Docker image tags, inline secret-like CI environment values, secret store references, curl-pipe-shell patterns, publish/deploy commands, self-hosted runner usage, artifact/cache usage, and service container hints. Findings are indicators for manual review, not confirmed vulnerabilities or proof of pipeline compromise.

Inspectra does not execute workflows, emulate GitHub/GitLab/Bitbucket/Azure/CircleCI/Jenkins runners, evaluate dynamic expressions, call provider APIs, validate tokens, execute scripts, install dependencies, resolve remote actions or reusable workflows, download actions/images, query registries, query CVEs/advisories, extract the project broadly, follow symlinks or hardlinks, or call the internet. Secret-like CI values, URLs with credentials, sensitive query parameters, provider-token-like strings, and private key blocks are redacted best-effort in results and exports.

## Launch a Kubernetes Config Audit

```bash
curl -sS -X POST http://localhost:8000/audits/k8s-config/<file_id>
```

The source file must be `kind: "archive"`. This creates a `k8s_config_basic` job that opens the archive with Python standard library parsers and reads only bounded text from Kubernetes manifest, Helm context, and Kustomize context candidates. Real `.env`, `.env.*`, and `.envrc` files are detected as sensitive but not read.

The analysis is heuristic and local. It looks for review indicators such as plaintext Kubernetes Secret data/stringData, secret-like ConfigMap/env values, privileged containers, host namespaces, hostPath/Docker socket usage, mutable or unpinned images, missing resources/probes, LoadBalancer/NodePort services, Ingress without TLS, wildcard ClusterRole rules, namespace defaults, and Helm/Kustomize files that were detected but not rendered or built. Findings are indicators for manual review, not confirmed vulnerabilities or proof of exploitability.

Inspectra does not run `kubectl`, access clusters, validate manifests against an API server, apply manifests, render Helm, build Kustomize overlays, resolve remote bases/charts/includes, download images, query registries, query CVEs/advisories, extract the project broadly, follow symlinks or hardlinks, or call the internet. Kubernetes Secret values, secret-like env/config values, credential-bearing URLs, and private key blocks are redacted best-effort in results and exports.

## Launch a Terraform Config Audit

```bash
curl -sS -X POST http://localhost:8000/audits/terraform-config/<file_id>
```

The source file must be `kind: "archive"`. This creates a `terraform_config_basic` job that opens the archive with Python standard library parsers and reads only bounded text from Terraform/OpenTofu-compatible `.tf`, `.tf.json`, `.tfvars`, `.tfvars.json`, `.auto.tfvars*`, `.terraform.lock.hcl`, and Terragrunt `.hcl` candidates. Terraform state files such as `terraform.tfstate`, `*.tfstate`, and `*.tfstate.backup` are detected as sensitive files present but are not read.

The analysis is heuristic and local. It looks for review indicators such as secret-like tfvars/default/output/backend/provider values, Terraform state files in archives, missing version/backend/lockfile signals, unpinned providers/modules, AWS security group world ingress, IAM wildcard policy hints, and S3 public-access hints. Findings are indicators for manual review, not confirmed vulnerabilities or proof of exploitability.

Inspectra does not execute Terraform, OpenTofu, or Terragrunt; run `init`, `validate`, `plan`, `apply`, or `destroy`; download providers or modules; resolve remote module sources; evaluate expressions or variables; access remote state; call cloud, Kubernetes, or provider APIs; query registries; query CVEs/advisories; extract the project broadly; follow symlinks or hardlinks; or call the internet. Secret-like Terraform values, credential-bearing URLs, private key blocks, state-content-like fields, errors, and exports are redacted best-effort.

## Launch a Nginx Config Audit

```bash
curl -sS -X POST http://localhost:8000/audits/nginx-config/<file_id>
```

The source file must be `kind: "archive"`. This creates a `nginx_config_basic` job that opens the archive with Python standard library parsers and reads only bounded text from Nginx/reverse-proxy config candidates such as `nginx.conf`, `*.conf`, `conf.d/*.conf`, `sites-available/*`, `sites-enabled/*`, and Nginx config paths under deployment/infra/proxy directories. `include` directives are detected as context but not resolved.

The analysis is heuristic and local. It looks for review indicators such as legacy TLS protocols, missing HTTPS/HSTS/security-header signals, `server_tokens on`, `autoindex on`, sensitive or backup locations, stub status exposure, HTTP upstream proxying, disabled proxy TLS verification, missing forwarding headers, wildcard CORS, large body limits, high proxy timeouts, disabled access logs, debug error logs, and secret-like proxy/header/variable values. Findings are indicators for manual review, not confirmed vulnerabilities or proof of exploitability.

Inspectra does not execute Nginx, run `nginx -t`, start containers, resolve includes, read host absolute paths, perform DNS lookups, scan ports, validate live servers or certificates, query CVEs/advisories, extract the project broadly, follow symlinks or hardlinks, or call the internet. Inline basic auth, credential-bearing `proxy_pass` URLs, Authorization headers, cookies/session values, private key blocks, and secret-like variables are redacted best-effort in results and exports.

## Launch a Docker Compose Config Audit

```bash
curl -sS -X POST http://localhost:8000/audits/compose-config/<file_id>
```

The source file must be `kind: "archive"`. This creates a `compose_config_basic` job that opens the archive with Python standard library parsers and reads only bounded text from Docker Compose candidates such as `docker-compose.yml`, `compose.yaml`, override files, and Compose files under deployment, stack, Docker, or infrastructure directories. Real `.env`, `.env.*`, and `.envrc` files are detected as sensitive files present but are not read. `env_file` and `secrets.file` references are recorded as references and their target contents are not read by resolution.

The analysis is heuristic and local. It looks for review indicators such as secret-like environment values, env file references, Docker socket mounts, privileged or host-mode services, published sensitive ports, writable sensitive bind mounts, mutable image tags, build contexts, external networks, legacy links, missing healthchecks/restart policies/resource limits, and multiple/override Compose files. Findings are indicators for manual review, not confirmed vulnerabilities or proof of exploitability.

Inspectra does not execute Docker or Docker Compose; run `docker compose config`, `up`, `build`, `pull`, `push`, or `logs`; inspect images; contact registries; interpolate `.env` values; merge multiple Compose files into an effective configuration; query CVEs/advisories; extract the project broadly; follow symlinks or hardlinks; or call the internet. Secret-like environment values, credential URLs, registry credentials, database/Redis URLs with passwords, private key blocks, labels, command/entrypoint fragments, errors, and exports are redacted best-effort.

## Launch a Database Config Audit

```bash
curl -sS -X POST http://localhost:8000/audits/database-config/<file_id>
```

The source file must be `kind: "archive"`. This creates a `database_config_basic` job that opens the archive with Python standard library parsers and reads only bounded text from PostgreSQL, MySQL, and MariaDB configuration candidates such as `postgresql.conf`, `pg_hba.conf`, `my.cnf`, `mariadb.conf`, and related config paths. Real `.env`, `.env.*`, `.envrc`, `.pgpass`, hidden client credential files, dumps, and backups are detected as sensitive files present but are not read. Database include directives are detected as context but not resolved.

The analysis is heuristic and local. It looks for review indicators such as public listen/bind settings, pg_hba trust/password/open-world rules, disabled or weak TLS settings, weak password/auth settings, logging/backup/replication posture, include directives, dumps/backups present, and secret-like database config values. Findings are indicators for manual review, not confirmed vulnerabilities or proof of exploitability.

Inspectra does not execute `psql`, `mysql`, `mariadb`, `pg_ctl`, `postgres`, `mysqld`, `mysqladmin`, `pg_dump`, `mysqldump`, or similar tools; connect to database servers; validate configs against live instances; resolve includes; read host paths; read dumps/backups/credential files; query CVEs/advisories; extract the project broadly; follow symlinks or hardlinks; or call the internet. Database credentials, DSNs, `PGPASSWORD`/`MYSQL_PWD`, private key blocks, errors, and exports are redacted best-effort.

## Launch a SQL DB Config Audit

```bash
curl -sS -X POST http://localhost:8000/audits/sql-database-config/<file_id>
```

The source file must be `kind: "archive"`. This creates a `sql_database_config_basic` job that opens the archive with Python standard library parsers and reads only bounded text from PostgreSQL, MySQL, and MariaDB configuration candidates such as `postgresql.conf`, `pg_hba.conf`, `my.cnf`, `mariadb.conf`, and related config paths. Real `.env`, `.env.*`, `.envrc`, `.pgpass`, `.my.cnf`, `.mylogin.cnf`, dumps, backups, data files, WAL/binlog/InnoDB files, and key/certificate-like files are detected as sensitive files present but are not read. Database include directives are detected as context but not resolved.

The analysis is heuristic and local. It looks for review indicators such as public listen/bind settings, pg_hba trust/password/open-world rules, disabled or weak TLS settings, weak password/auth settings, logging/backup/replication posture, include directives, sensitive adjacent files present, and secret-like SQL database values. Findings are indicators for manual review, not confirmed vulnerabilities, live reachability, compromise, breach, or proof of exploitability.

Inspectra does not execute PostgreSQL, MySQL, or MariaDB clients or servers; run `psql`, `mysql`, `mysqladmin`, `mysqld`, `postgres`, `pg_ctl`, `mariadb`, `mariadbd`, `pg_dump`, `mysqldump`, or similar tools; open sockets; connect to database servers; validate configs against live instances; resolve includes; read host paths; read dumps/backups/credential/data files; query CVEs/advisories; extract the project broadly; follow symlinks or hardlinks; or call the internet. SQL database credentials, DSNs, `PGPASSWORD`/`MYSQL_PWD`, private key blocks, errors, raw JSON, and exports are redacted best-effort.

## Launch a Redis Config Audit

```bash
curl -sS -X POST http://localhost:8000/audits/redis-config/<file_id>
```

The source file must be `kind: "archive"`. This creates a `redis_config_basic` job that opens the archive with Python standard library parsers and reads only bounded text from Redis and Sentinel config candidates such as `redis.conf`, `redis-*.conf`, `sentinel.conf`, `redis-sentinel.conf`, and Redis config paths under deployment, Docker, infrastructure, cache, database, or config directories. Real `.env`, `.env.*`, `.envrc`, ACL, RDB, AOF, appendonly, dump, and backup files are detected as sensitive files present but are not read. Redis include directives are detected as context but not resolved.

The analysis is heuristic and local. It looks for review indicators such as bind/protected-mode exposure, `requirepass` and `masterauth` posture, ACL references, TLS settings, persistence and backup posture, replication/Sentinel settings, dangerous command renames, module loading, logging/runtime signals, limits/resources, include directives, and secret-like Redis values. Findings are indicators for manual review, not confirmed vulnerabilities or proof of exploitability.

Inspectra does not execute Redis or Sentinel; run `redis-server`, `redis-cli`, `redis-sentinel`, `redis-benchmark`, or similar tools; open sockets; connect to Redis/Sentinel; validate credentials; resolve includes; read host paths; read `.env`, ACL, RDB, AOF, appendonly, dump, or backup contents; query CVEs/advisories; extract the project broadly; follow symlinks or hardlinks; or call the internet. Redis passwords, Sentinel auth values, Redis URLs with credentials, ACL-like values, private key blocks, errors, and exports are redacted best-effort.

## Launch a Web Baseline Audit

```bash
curl -sS -X POST http://localhost:8000/audits/web/basic \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","authorization_confirmed":true}'
```

This creates a `web_basic` job. The audit accepts only absolute `http` and `https` URLs, rejects embedded URL credentials, requires explicit authorization confirmation, limits redirects, validates every redirect target, limits response bytes, and applies anti-SSRF checks. By default it blocks localhost, private RFC1918 ranges, link-local addresses, and cloud metadata targets. Set `INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS=true` only for authorized lab environments; cloud metadata/link-local targets remain blocked.

Web audits connect only to the port in the URL. The default allowed ports are `80` and `443`; set `INSPECTRA_WEB_ALLOWED_PORTS=80,443,8000,8080,8443` for authorized lab services. Inspectra does not probe alternate ports.

Cookie values and sensitive response headers such as `Set-Cookie`, `Authorization`, `Proxy-Authorization`, `X-Api-Key`, and `X-Auth-Token` are redacted in web results and exports. Inspectra uses the submitted URL for the authorized request, but stores and exports a display URL where common sensitive query parameters such as `token`, `api_key`, `session`, `password`, `code`, and `state` are replaced with `REDACTED`. Non-sensitive query parameters are preserved for context. Avoid placing real secrets in audited URLs; uncommon parameter names may not be recognized.

The web audit performs a small set of passive HTTP/HTTPS requests for the provided URL plus `robots.txt` and common `security.txt` locations on the same origin. It does not execute JavaScript, render HTML, crawl links, fuzz, brute-force, exploit, scan ports, use Nmap, query CVEs, or call external reputation APIs.

## Launch a Domain DNS Baseline Audit

```bash
curl -sS -X POST http://localhost:8000/audits/domain/basic \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","authorization_confirmed":true}'
```

This creates a `domain_basic` job. The audit accepts a domain name, not a URL, and rejects IP literals, localhost-style names, paths, query strings, userinfo, and reserved/internal suffixes such as `.local`, `.localhost`, `.internal`, `.test`, and `.invalid`.

The runner performs bounded DNS queries for `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `CAA`, and `SOA`, plus `_dmarc.<domain>` TXT and `www.<domain>` A/AAAA/CNAME. If the target already starts with `www.`, Inspectra skips the extra `www` baseline instead of querying `www.www.<domain>`. It parses SPF, DMARC, CAA, MX, NS, SOA, and TXT records into informational findings. The DNS client is a small UDP-only, best-effort baseline that uses configured IPv4 resolvers from `/etc/resolv.conf` and reports controlled errors for truncation or resolver failures rather than attempting TCP fallback. It does not brute-force subdomains, use wordlists, attempt AXFR, crawl websites, scan ports, use Nmap, query CVEs, or call external reputation APIs.

## Launch a Controlled Subdomain Inventory

```bash
curl -sS -X POST http://localhost:8000/audits/subdomains/basic \
  -H "Content-Type: application/json" \
  -d '{"root_domain":"example.com","subdomains":["www","api.example.com","admin"],"authorization_confirmed":true}'
```

This creates a `subdomain_inventory_basic` job. The root domain must pass the same defensive validation as `domain_basic` and is limited to 253 characters. Candidates must be provided explicitly as relative labels such as `api` or FQDNs inside the root domain such as `api.example.com`; each candidate is limited to 253 characters. Inspectra normalizes, deduplicates, and resolves only accepted candidates for `A`, `AAAA`, and `CNAME`.

The public API is fail-fast: if any submitted candidate is invalid, the whole request is rejected and no job is created. The root domain itself, trailing-dot names, URLs, paths, query strings, userinfo, IP literals, wildcards, candidates outside the root domain, empty labels, and invalid names are rejected. Normal result rows with `candidates_rejected` are reserved for dedupe, configured limits, deadline/skipped states, and internal runner defense. It does not generate permutations, use wordlists, query Certificate Transparency, call external APIs, attempt AXFR, crawl, scan ports, use Nmap, or perform brute force. A bounded wildcard-DNS heuristic may query up to `INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS` random labels under the root domain; this is only an indicator for manual review. Set `INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS=0` to disable those probes.

`INSPECTRA_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS` caps the whole runner analysis. If the deadline is reached, Inspectra returns a completed but partial result with `truncated`, `deadline_reached`, processed/pending candidate counts, skipped candidates, and an informational finding. Prefer reducing the candidate list or fixing slow DNS resolvers before raising this deadline in authorized lab environments.

## Read Job Results

```bash
curl -sS http://localhost:8000/jobs/<job_id>
```

Jobs start as `queued`, move to `running`, and then become `completed` or `failed`. Results are also stored locally in `data/results/jobs/<job_id>.json`.

Inspectra stores MVP state as local JSON. Writes use atomic temp-file replacement plus a storage lock file under `data/.locks/storage.lock` for write and read-modify-write operations. The lock is held only during quick local persistence steps, not while external analysis runs. This reduces local races but is still not a substitute for SQLite or another database in multi-user/high-volume deployments.

## Export Job Reports

Every existing job can be exported, including jobs that are still queued, running, or failed. The report clearly includes the job state.

```bash
curl -sS -OJ http://localhost:8000/jobs/<job_id>/export/markdown
curl -sS -OJ http://localhost:8000/jobs/<job_id>/export/html
curl -sS -OJ http://localhost:8000/jobs/<job_id>/export/xml
curl -sS -OJ http://localhost:8000/jobs/<job_id>/export/pdf
```

Supported formats:

| Format | Content-Type | Notes |
| --- | --- | --- |
| Markdown | `text/markdown; charset=utf-8` | Plain readable report. Dynamic values are rendered as code spans or code blocks to avoid misleading Markdown links, images, HTML, headings, or table structure. |
| HTML | `text/html; charset=utf-8` | Static, self-contained HTML with inline CSS and no JavaScript. |
| XML | `application/xml; charset=utf-8` | Inspectra-specific XML rooted at `inspectraAuditReport`. |
| PDF | `application/pdf` | Generated locally by Inspectra without external services or browser automation. |

## Export SBOMs

SBOM export is available for completed dependency jobs:

- `manifest_basic`
- `project_archive_basic`

The SBOM is generated offline from declared dependencies already present in the stored job JSON. Inspectra does not call package registries, resolve transitive dependencies, install packages, execute package managers, query CVEs, or infer licenses.

Inspectra generates package URLs (`purl`) only for dependencies that look like registry packages with a clear npm or PyPI identity. URL, VCS, `file:`, local path, workspace, alias, and editable dependencies are preserved as declared requirements and marked with Inspectra properties/comments explaining why `purl` was omitted.

```bash
curl -sS -OJ http://localhost:8000/jobs/<job_id>/sbom/cyclonedx-json
curl -sS -OJ http://localhost:8000/jobs/<job_id>/sbom/spdx-json
```

Supported SBOM formats:

| Format | Content-Type | Notes |
| --- | --- | --- |
| CycloneDX JSON | `application/vnd.cyclonedx+json; charset=utf-8` | Basic CycloneDX document with declared library components and Inspectra properties. |
| SPDX JSON | `application/spdx+json; charset=utf-8` | Basic SPDX 2.3 document using `NOASSERTION` where Inspectra does not know supplier, license, or download location. |

## List Jobs

```bash
curl -sS http://localhost:8000/jobs
```

Jobs are returned with the most recently created first. Completed jobs include a compact summary with analyzer name, hash, validation state, warnings, timed-out tools, manifest dependency/finding counts, archive entry/finding counts, project-archive dependency/finding counts, passive config/review file/finding counts, or web/domain/subdomain metrics when present.

## Delete an Uploaded File

```bash
curl -sS -X DELETE http://localhost:8000/files/<file_id>
```

This deletes the uploaded source file and its metadata for the current/effective owner. Existing job results are kept. Associated owned jobs are marked with `source_file_deleted_at` so historical results remain readable while making it clear that the original source file is no longer available.

## Delete a Job Result

```bash
curl -sS -X DELETE http://localhost:8000/jobs/<job_id>
```

This deletes a completed or failed job/result record for the current/effective owner. After deletion, job detail, Raw JSON, Markdown/HTML/XML/PDF exports, and SBOM exports derived from that job are unavailable. Queued or running jobs are not deleted in this slice.

## Development

To run backend and tool-runner tests without installing dependencies globally:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
pytest
```

To build the frontend locally without installing anything globally:

```bash
cd frontend
npm install
npm run build
```

To run frontend unit tests:

```bash
cd frontend
npm run test -- --run
```

Validate Compose configuration:

```bash
docker compose config
```

## Documentation

- [Architecture](docs/architecture.md)
- [Security Scope](docs/security-scope.md)

## License

MIT. See [LICENSE](LICENSE).
