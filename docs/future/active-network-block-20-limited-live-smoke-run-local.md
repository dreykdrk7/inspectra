# Active Network Block 20 Limited Live Smoke Run Local

Status: `ACTIVE_LIMITED_LIVE_LOCAL_SMOKE_METHOD_ACCEPTED`.

Base checkpoint: `docs/future/active-network-block-19-limited-live-hardening-checkpoint.md`

Closeout reference: `docs/future/active-network-block-18-authorized-http-header-probe-closeout.md`

Commit scope: docs-first local smoke method definition for the already implemented `active_http_header_probe` v0. No backend, frontend, runner, passive analyzer, test, fixture, `.env`, tag, release, push, or runtime changes are included in this block.

## Decision Final

Decision:

```text
ACTIVE_LIMITED_LIVE_LOCAL_SMOKE_METHOD_ACCEPTED
```

The accepted local smoke method is a controlled test-double smoke, not a production-policy relaxation and not a real loopback/private live probe.

This resolves the Block 19 tension:

- the production target policy stays fail-closed for loopback/private/metadata/link-local targets;
- no local-lab runtime bypass is added;
- no real third-party target is used;
- the existing mocked/fake resolver and fake HEAD transport are the approved mechanism for validating the one-HEAD behavior locally;
- backend/API/reporting smoke uses in-process ASGI transport plus monkeypatched runner results;
- frontend smoke remains mocked API/report rendering, as already reviewed in Block 17.

This method validates the closed v0 behavior without adding a new Active capability.

## Method Chosen

Use the existing local test-double harness as the smoke method:

1. Runner-level smoke uses `run_authorized_http_header_probe` with injected `resolver` and `head_request` functions.
2. Successful-path runner smoke returns a public test address from the fake resolver and a synthetic `HeadResponse` from the fake HEAD transport.
3. Blocked-path runner smoke uses fake resolvers or forbidden callbacks that raise if DNS/HTTP would happen when policy should block.
4. Backend/API smoke uses `ASGITransport(app=app)` and `monkeypatch` to exercise FastAPI in process without opening sockets.
5. Backend enabled-path smoke monkeypatches `audit_services.run_authorized_http_header_probe` with a deterministic fake runner result.
6. Backend disabled-path smoke confirms `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED=false` rejects without creating a job.
7. Reporting/export smoke uses stored/fake job payloads and asserts Markdown, HTML, XML, and PDF redaction.
8. Frontend smoke uses mocked API/report payloads from the existing frontend review pattern; it should not contact external targets.

Reference harness evidence from current tests:

- `tools/tests/test_active_runner.py` uses fake resolver and fake HEAD callbacks to validate one `HEAD`, blocked targets, DNS fail-closed behavior, no GET fallback, no redirects, no body read, fixed request headers, and response-header redaction.
- `backend/tests/test_backend.py` uses `ASGITransport`, `monkeypatch.setenv`, and monkeypatched runner functions to validate disabled-state behavior, feature flag independence, job creation, target-based `file_id: null`, summaries, exports, and redaction without real network.
- Frontend review documentation records mocked UI/API tests for double confirmation, disabled state, report rendering, Raw JSON redaction, and forbidden-copy absence.

The smoke method is therefore local and deterministic, but not a real network smoke. That tradeoff is intentional until a separate docs-first local-lab design exists.

## Method Explicitly Discarded

Do not relax production target policy to make loopback/private smoke easier.

Rejected approaches:

- allowing `127.0.0.1`, `localhost`, RFC1918, metadata, or link-local targets through the production live policy;
- adding a runtime `local-lab mode` in this microphase;
- adding an operator bypass flag for loopback/private;
- using a third-party public demo target;
- using DNS tricks to map a public-looking hostname to loopback/private;
- running a real local HTTP server and weakening target policy to reach it;
- adding GET fallback, redirect following, body reads, custom headers, auth/cookies, Nmap, port checks, crawling, fuzzing, or exploit behavior.

Any future local-lab mode must be a separate docs-first design with explicit safety review. It must not be introduced as an incidental smoke convenience.

## Smoke Checklist

This checklist describes the accepted local test-double smoke. It should run only known no-external-network tests or equivalent in-process harnesses.

### Feature Flags

1. Confirm disabled live flag rejects `POST /active/network/http-header-probe`.
2. Confirm disabled live flag creates no job.
3. Confirm disabled live flag sends no DNS and no HTTP.
4. Confirm enabling `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED` in test context does not enable `INSPECTRA_ACTIVE_DRY_RUN_ENABLED`.
5. Confirm dry-run remains independent and `network_requests_sent: 0`.

### Authorization And Request Contract

1. Confirm missing authorization blocks before DNS/HTTP.
2. Confirm missing live-traffic confirmation blocks before DNS/HTTP.
3. Confirm `mode: live_header_probe` and `profile: http_header_probe` are required.
4. Confirm unknown request, authorization, or limit fields are rejected without job creation.
5. Confirm successful request creates `active_http_header_probe` with `file_id: null`.

### Target Policy

1. Confirm URL userinfo is rejected before DNS/HTTP.
2. Confirm bare hostnames are rejected as `live_url_required`.
3. Confirm CIDR/ranges/wildcards are rejected before DNS/HTTP.
4. Confirm private, loopback, metadata, and link-local targets are blocked.
5. Confirm fake DNS returning blocked or mixed answers fails closed before HEAD.
6. Confirm fake DNS answer overflow fails closed.
7. Confirm fake DNS failure is controlled and sends no HTTP.

### One-HEAD Behavior

1. Use a fake resolver that returns an allowed public test address.
2. Use a fake HEAD transport that records calls and returns a synthetic response.
3. Confirm exactly one call is made.
4. Confirm method is `HEAD`.
5. Confirm request headers are fixed to `User-Agent` and `Accept`.
6. Confirm no custom headers, `Authorization`, or `Cookie` are sent.
7. Confirm `network_requests_sent` becomes `1` only after the fake HEAD is attempted.
8. Confirm response body is not read and body bytes remain `0`.

### Redirects And Errors

1. Return synthetic `405` and confirm no GET fallback.
2. Return synthetic `302` with `Location` and confirm redirects are not followed.
3. Confirm redirect target/query secrets are redacted.
4. Confirm controlled runner/backend errors remain redacted.

### Reporting, API, UI, And Exports

1. Confirm `GET /jobs` summary contains `active_http_header_probe` metadata.
2. Confirm `GET /jobs/{job_id}` returns redacted result JSON.
3. Confirm Markdown, HTML, XML, and PDF exports render active sections.
4. Confirm frontend report renders queued/running/completed/failed/blocked/sparse/malformed states.
5. Confirm frontend Raw JSON is redacted.
6. Confirm disabled-state UI stays calm and does not mention `.env`, bypasses, retries, DNS attempts, or HTTP attempts.

### Redaction Negative Checks

Verify that these fixture values do not appear in API responses, exports, frontend DOM, Raw JSON, audit log, errors, observations, findings, response headers, or target display:

- `super-secret-password`
- `token_should_never_render`
- `raw-api-key-123456`
- `Authorization: Bearer token_should_never_render`
- `http://user:pass@example.com`
- `session_should_not_render`
- `cookie_should_not_render`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`

Expected placeholder:

```text
[REDACTED]
```

## No-Scope

- No code.
- No real live probes in this microphase.
- No live probes against third parties.
- No external network tests.
- No production target-policy relaxation.
- No loopback/private/metadata/link-local bypass.
- No local-lab runtime mode.
- No Nmap.
- No port scanning.
- No crawling.
- No redirects.
- No GET fallback.
- No body reads.
- No custom headers.
- No auth/cookies.
- No fuzzing.
- No exploitation.
- No credential validation.
- No new Active capability.
- No backend changes.
- No frontend changes.
- No runner changes.
- No passive analyzer changes.
- No Passive work.
- No `.env` reads or guidance.
- No push.
- No tag or release.

## Residual Risks

- The accepted smoke method validates behavior through test doubles, not through a real local HTTP server.
- The current production policy still blocks loopback/private targets, so a real local server smoke is intentionally not available without a future design.
- Fake transports can prove the one-HEAD contract and redaction, but they do not establish live target truth.
- Authorization remains a user assertion, not proof of ownership.
- Redaction remains defensive and best-effort.
- Active has no separate alpha/release plan yet.

## Acceptance Criteria

The local smoke method is accepted when:

- disabled live feature flag creates no job and sends no DNS/HTTP;
- enabled test context can create a target-based `active_http_header_probe` job with `file_id: null`;
- double confirmation is required;
- fake resolver/fake HEAD successful path records exactly one `HEAD`;
- blocked targets preserve `network_requests_sent: 0`;
- no redirects are followed;
- no body is read;
- no custom headers, auth, or cookies are sent;
- API summaries, full results, exports, frontend report, and Raw JSON are redacted;
- Active dry-run remains independent and no-network;
- production target policy remains unchanged.

## Next Product Recommendation

Recommended next microphase:

```text
ACTIVE-NETWORK-BLOCK-21-ACTIVE-ALPHA-CHECKPOINT-RELEASE-PLANNING
```

Rationale:

- The limited live line now has docs-first design, implementation, E2E reviews, closeout, hardening checkpoint, and a local smoke method.
- Before designing any additional live capability, product should decide whether Active v0 deserves an internal alpha checkpoint, what operator guidance is needed, and how feature-flag enablement should be documented without encouraging bypasses.

Alternative next paths:

- `ACTIVE-NETWORK-BLOCK-21-LIMITED-LIVE-SMOKE-TEST-EXECUTION` if the team wants to execute only the already identified no-external-network test subset and record the results.
- `ACTIVE-NETWORK-BLOCK-21-LOCAL-LAB-MODE-DESIGN-DOCS-FIRST` only if real loopback/private local smoke is required; this must not alter production policy by default.
- `ACTIVE-NETWORK-BLOCK-21-NEXT-LIVE-CAPABILITY-DESIGN-DOCS-FIRST` only after product explicitly accepts deferring Active alpha planning.

Do not proceed to Nmap, port scanning, crawling, or broader target support from this block.

## Validation Commands

Closeout validation for this docs-first smoke method:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
```

No pytest/npm suite is required unless runtime/test files change. If the smoke is executed in a future block, run only the known no-external-network tests or an equivalent in-process harness.
