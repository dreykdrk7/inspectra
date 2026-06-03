# Active Network Block 18 Authorized HTTP Header Probe Closeout

Status: `ACTIVE_HTTP_HEADER_PROBE_V0_CLOSED_LIMITED_LIVE`.

Frontend review: `docs/future/active-network-block-17-end-to-end-authorized-http-header-probe-frontend-review.md`

Backend review: `docs/future/active-network-block-14-end-to-end-authorized-http-header-probe-contract-redaction-review.md`

Dry-run closeout: `docs/future/active-network-block-10-dry-run-closeout.md`

Commit scope: documentation closeout, smoke checklist, final product decision, and handoff guidance. No runner, backend, frontend, passive analyzer, fixture, tag, release, push, or runtime changes are included in this block.

## Estado Final

`active_http_header_probe` v0 is closed as the first limited live Active capability.

The capability remains opt-in, target-based, explicitly authorized, and intentionally narrow. When enabled by deployment configuration and accepted by target policy, one job may send at most one HTTP `HEAD` request to one explicit `http://` or `https://` URL. The request follows no redirects, reads no response body, sends no custom user headers, sends no auth/cookies, performs no crawling, performs no port checks, and does not run Nmap.

Decision field:

```text
ACTIVE_HTTP_HEADER_PROBE_V0_CLOSED_LIMITED_LIVE
```

## Commit Series

Relevant Authorized HTTP Header Probe series:

- `72819d8 docs(active): design authorized http header probe`
- `79e6635 feat(active): add authorized http header probe backend`
- `cae896e test(active): review http header probe e2e backend only`
- `d24c6c3 docs(active): design http header probe frontend UX`
- `715bb8e feat(active): add http header probe frontend`
- `e9f9bfb test(active): review http header probe frontend e2e`

This closeout records the final v0 documentation handoff after those design, implementation, and review blocks.

## Implemented Surfaces

- Separate Active runner path under `tools/active_runner/`.
- Runner module for authorized HTTP header probing.
- Backend feature flag `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED`, default `false`.
- Backend endpoint `POST /active/network/http-header-probe`.
- Job/audit type `active_http_header_probe`.
- Target-based jobs with `file_id: null`.
- Existing job lifecycle with queued, running, completed, failed, blocked, sparse, and malformed payload tolerance.
- Compact summaries through `GET /jobs`.
- Full job results through `GET /jobs/{job_id}`.
- Markdown, HTML, XML, and PDF exports.
- Frontend `Authorized HTTP Header Probe` panel in the `Active / Network` dashboard area.
- Frontend API helper for `POST /active/network/http-header-probe`.
- Double-confirmation UI for authorization and live traffic.
- Audit catalog and dashboard filter metadata for `active_http_header_probe`.
- Redacted job-table target display.
- `ActiveHttpHeaderProbeJobReport`.
- Redacted Raw JSON.

## Safety Guarantees

The v0 live probe capability preserves:

- feature flag disabled by default;
- no job creation while disabled;
- explicit authorization confirmation required;
- explicit live-traffic confirmation required;
- one target only;
- explicit `http://` or `https://` URL only;
- no URL userinfo;
- no CIDR, IP range, wildcard, target list, or multi-target input;
- fail-closed target policy;
- bounded DNS safety check only after feature flag, authorization, target, profile, and limits pass;
- fail closed when any resolved address is blocked;
- at most one HTTP `HEAD` request;
- no GET fallback;
- no redirects;
- no response body read;
- no custom user-supplied headers;
- no request body;
- no auth or cookies;
- no crawling;
- no port scanning;
- no Nmap;
- no subprocess probes;
- no archive action integration;
- no run-all integration;
- no dry-run auto-run path;
- passive archive/file analyzers retain their no-network guarantee.

The Active dry-run remains separate and closed as `ACTIVE_DRY_RUN_V0_CLOSED_NO_NETWORK`. Dry-run jobs continue to report `network_requests_sent: 0` and do not fetch DNS answers, HTTP status codes, or response headers.

## Redaction Guarantees

Defensive redaction covers current and legacy `active_http_header_probe` payload surfaces:

- target display;
- URL userinfo;
- sensitive query parameters;
- Authorization headers;
- Bearer and Basic credentials;
- cookies and session values;
- response headers;
- observations;
- findings;
- controlled errors;
- audit log entries;
- storage/API summaries;
- `GET /jobs`;
- `GET /jobs/{job_id}`;
- Markdown, HTML, XML, and PDF exports;
- frontend job table;
- frontend report DOM;
- frontend Redacted Raw JSON;
- malformed or legacy nested fields.

The fixed placeholder is:

```text
[REDACTED]
```

The implementation does not intentionally emit secret prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

## Tests/Validations

The reviewed blocks validated:

- backend disabled-state handling;
- enabled job creation with `active_http_header_probe`;
- exact request contract;
- feature flag independence from Active dry-run;
- target policy rejection before DNS/HTTP for forbidden targets;
- DNS fail-closed behavior;
- one-HEAD behavior;
- no GET fallback;
- no redirects;
- no response body read;
- bounded response-header capture;
- backend summaries, result retrieval, and exports;
- frontend form gating and disabled state;
- frontend catalog/filter behavior;
- frontend job-table target redaction;
- completed, blocked, failed, queued/running, sparse, malformed, and legacy report rendering;
- forbidden-copy absence in the new frontend surface;
- runner/backend/API/export/frontend redaction;
- dry-run no-network regression behavior;
- Nmap/subprocess absence in the reviewed Active code path.

Reference validation commands from the implementation and review blocks:

```text
python3 -m compileall backend tools/active_runner
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools/active_runner
.venv/bin/python -m pytest tools/tests/test_active_runner.py
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_http or http_header"
.venv/bin/python -m pytest backend/tests/test_backend.py
.venv/bin/python -m pytest
npm run test -- --run ActiveHttpHeaderProbeJobReport App dashboardFilters reportHelpers
npm run test -- --run
npm run build
rg "Run Nmap|Nmap scan|port scan|brute force|credential valid|vulnerability confirmed|target is safe|bypass|evade|exploit|attack" frontend/src/ActiveHttpHeaderProbeJobReport.tsx frontend/src/App.tsx frontend/src/*Header* frontend/src/*Probe*
git diff --check
git diff --cached --check
```

This closeout is docs-only, so no pytest or npm suite is required for this closeout commit unless runtime files change.

## Manual Smoke Checklist

Use only explicitly authorized local or owned targets.

1. Confirm `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED=false` rejects `POST /active/network/http-header-probe` without creating a job.
2. Enable `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED=true` in a trusted local runtime.
3. Open the frontend and locate the separate `Authorized HTTP Header Probe` panel.
4. Confirm the panel is separate from `Active / Network dry-run` and from uploaded file/archive actions.
5. Submit a single authorized `https://` target only after checking both authorization boxes.
6. Confirm the request creates an `active_http_header_probe` target-based job with `file_id: null`.
7. Confirm queued/running/completed or controlled failed states render without breaking the UI.
8. Confirm a completed allowed job records at most one HTTP `HEAD` request.
9. Confirm the report states that the response body was not read and redirects were not followed.
10. Confirm response headers, observations, findings, blocked reasons, limits, audit log, errors, and Redacted Raw JSON render.
11. Export Markdown, HTML, XML, and PDF reports if available in the local runtime.
12. Submit a blocked target such as URL userinfo, private/loopback/metadata address, CIDR, wildcard, unsupported scheme, or bare hostname and confirm no HTTP request is sent.
13. Submit fixture-like sensitive target/query/header/result payloads only through controlled tests or mocked data and confirm secrets do not appear in API, exports, UI, or Raw JSON.
14. Confirm Active dry-run still reports `network_requests_sent: 0` and remains independent from the live probe feature flag.
15. Confirm the smoke does not run Nmap, scan ports, crawl, follow redirects, read response bodies, send custom headers, validate credentials, fuzz, exploit, or use third-party targets.

## Known Limitations

- This is a limited live capability and may be logged by the target when enabled and allowed.
- Authorization is a user assertion, not proof of ownership.
- DNS and HTTP behavior depend on the local runtime and target behavior.
- Only one `HEAD` request is supported.
- No GET fallback exists.
- Redirects are not followed.
- Response bodies are not read.
- No custom headers, authentication, cookies, or request bodies are supported.
- No certificate inventory or live security validation is performed beyond the HTTP client behavior already needed for the request.
- Header observations are heuristic review indicators, not confirmed vulnerabilities, safe-target claims, exploitability claims, or compromise evidence.
- Redaction is defensive and best-effort.
- The capability is not production or external-user readiness.
- Nmap and broader Active scanning remain unimplemented.

## Next Product Options

Completed hardening checkpoint:

```text
ACTIVE-NETWORK-BLOCK-19-LIMITED-LIVE-HARDENING-CHECKPOINT-DOCS-FIRST
```

Checkpoint record: `docs/future/active-network-block-19-limited-live-hardening-checkpoint.md`

That block reviews feature-flag operations, local-only smoke discipline, logging/redaction expectations, target-policy wording, and readiness criteria before any additional live capability is designed.

Recommended next option after the checkpoint:

```text
ACTIVE-NETWORK-BLOCK-20-LIMITED-LIVE-SMOKE-RUN-LOCAL
```

Alternative options:

- `POST_ALPHA_READINESS_BACKLOG_EXECUTION-01-DOCS-FIRST-PLAN` if product readiness work should pause Active expansion.
- A separate docs-first design for a local-lab-only Active smoke harness, still without Nmap.
- A separate docs-first design for the next tiny live check, only after the hardening checkpoint.

Do not proceed to Nmap, port scanning, crawling, credential validation, fuzzing, exploitation, or broad target support without a separate docs-first scope decision, safety review, implementation block, and end-to-end redaction review.

## Final Decision

```text
ACTIVE_HTTP_HEADER_PROBE_V0_CLOSED_LIMITED_LIVE
```

`active_http_header_probe` v0 is ready to close as a narrowly scoped, opt-in, authorized one-HEAD live probe with layered redaction and explicit no-scope boundaries.
