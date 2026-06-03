# Active Network Block 19 Limited Live Hardening Checkpoint

Status: `ACTIVE_LIMITED_LIVE_HARDENING_ACCEPTED_FOR_NEXT_DESIGN`.

Base closeout: `docs/future/active-network-block-18-authorized-http-header-probe-closeout.md`

Dry-run hardening reference: `docs/future/active-network-block-11-dry-run-hardening-review.md`

Commit scope: docs-first hardening checkpoint for the limited Active line. No backend, frontend, runner, passive analyzer, fixture, `.env`, tag, release, push, or runtime changes are included in this block.

## 1. Estado Actual

- `active_network_dry_run` v0 is closed as `ACTIVE_DRY_RUN_V0_CLOSED_NO_NETWORK`.
- `active_http_header_probe` v0 is closed as `ACTIVE_HTTP_HEADER_PROBE_V0_CLOSED_LIMITED_LIVE`.
- Active live behavior now exists, but only as a limited one-HEAD HTTP header probe.
- The live probe requires `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED=true`; the default remains disabled.
- Active dry-run requires `INSPECTRA_ACTIVE_DRY_RUN_ENABLED=true`; the default remains disabled.
- The dry-run and live probe feature flags are independent.
- The live probe requires one explicit `http://` or `https://` URL, explicit authorization, and explicit live-traffic confirmation.
- The live probe sends at most one HTTP `HEAD` request, follows no redirects, reads no response body, sends no custom headers, and sends no auth or cookies.
- DNS is bounded and fail-closed before HTTP.
- Nmap remains unimplemented.
- Port scanning, crawling, fuzzing, exploitation, credential validation, and broader Active scanning remain out of scope.
- Passive Alpha and passive analyzers are outside this line of work.

## 2. Superficies Revisadas

- Feature flags:
  - `INSPECTRA_ACTIVE_DRY_RUN_ENABLED`
  - `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED`
- Backend endpoints:
  - `POST /active/network/dry-run`
  - `POST /active/network/http-header-probe`
- Active runner separation under `tools/active_runner/`.
- DNS safety behavior for the live header probe.
- HTTP request behavior for the one-HEAD live probe.
- Target-based job storage with `file_id: null`.
- `GET /jobs` summaries and `GET /jobs/{job_id}` result retrieval.
- Markdown, HTML, XML, and PDF reporting/export.
- Frontend dry-run panel and `Authorized HTTP Header Probe` panel.
- `ActiveDryRunJobReport` and `ActiveHttpHeaderProbeJobReport`.
- Redaction across runner/backend/API/export/frontend/Raw JSON.
- Manual smoke checklist from Block 18.
- README, architecture, and security-scope documentation.

## 3. Hardening Checklist

Classification key:

- `PASS`: sufficient for the next docs-first step.
- `NEEDS FIX BEFORE NEXT LIVE CAPABILITY`: must be handled before any new live capability is designed or implemented.
- `BACKLOG`: useful hardening, not blocking the next docs-first step.
- `NOT APPLICABLE`: not relevant to this checkpoint.

### Feature Flags

| Check | Status | Notes |
| --- | --- | --- |
| `INSPECTRA_ACTIVE_DRY_RUN_ENABLED` default false | PASS | Dry-run is opt-in and disabled by default. |
| `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED` default false | PASS | Live header probe is opt-in and disabled by default. |
| Independent flags | PASS | Backend review confirmed enabling live does not enable dry-run. |
| Disabled state creates no job/request | PASS | Dry-run and live disabled states reject without job creation; live disabled state sends no DNS/HTTP. |
| Docs explain opt-in | PASS | README, architecture, security scope, and closeout docs document the opt-in posture. |

### Authorization

| Check | Status | Notes |
| --- | --- | --- |
| Dry-run authorization | PASS | Dry-run requires explicit authorization confirmation. |
| Live authorization | PASS | Live request requires explicit authorization confirmation. |
| Live traffic confirmation | PASS | Live request requires a second live-traffic confirmation. |
| Authorization is assertion, not proof | PASS | Docs and reports avoid proof-of-ownership claims. |
| No auto-run from dry-run | PASS | Live probe is separate and is not triggered from dry-run output. |

### Target Policy

| Check | Status | Notes |
| --- | --- | --- |
| One target | PASS | Live request accepts one target only. |
| Explicit URL only for live | PASS | Bare hostnames are rejected; `http://` or `https://` is required. |
| URL userinfo rejected | PASS | Userinfo targets are rejected and redacted. |
| Private/loopback/metadata/link-local blocked | PASS | Target policy and DNS fail-closed tests cover blocked address classes. |
| CIDR/ranges/wildcards blocked | PASS | Target policy rejects these before DNS/HTTP. |
| DNS fail-closed | PASS | Any blocked resolved address prevents HTTP. |
| Redirects not followed | PASS | `max_redirects: 0`; no redirect following. |
| No local-lab mode | PASS | No local-lab bypass exists in v0. |
| Local-only live smoke path | NEEDS FIX BEFORE NEXT LIVE CAPABILITY | A real local smoke run is recommended next, but the current live policy blocks loopback/private targets. Block 20 should define a controlled local smoke method without widening production policy. |

### Limits

| Check | Status | Notes |
| --- | --- | --- |
| Dry-run limits zero | PASS | Dry-run request limits are zero and `network_requests_sent` remains `0`. |
| Live `max_requests` 1 | PASS | Live request is capped to one request. |
| Timeout cap | PASS | Frontend contract and backend tests use the bounded v0 timeout. |
| Headers cap | PASS | Response headers are bounded. |
| DNS answer cap | PASS | DNS answer count is capped and overflow fails closed. |
| No retries | PASS | Live retries are `0`. |
| No concurrency | PASS | Live concurrency is `1`. |
| No body read | PASS | Response body bytes are `0`; no body read. |
| No redirects | PASS | Redirects are not followed. |

### Runtime Behavior

| Check | Status | Notes |
| --- | --- | --- |
| Dry-run `network_requests_sent` 0 | PASS | Dry-run remains no-network. |
| Live `network_requests_sent` 1 only when `HEAD` attempted | PASS | Backend review confirms pre-request blockers preserve `0`. |
| No GET fallback | PASS | One `HEAD` only. |
| No Nmap | PASS | No Nmap runtime exists. |
| No subprocess | PASS | Reviewed Active path has no subprocess behavior. |
| No port scan | PASS | No port scanning behavior exists. |
| No crawling | PASS | No crawling behavior exists. |
| No custom headers | PASS | Custom user headers are not accepted. |
| No auth/cookies | PASS | Authorization and Cookie request headers are not sent. |

### Redaction

| Check | Status | Notes |
| --- | --- | --- |
| Targets | PASS | Target display is defensively redacted. |
| Query params | PASS | Sensitive query params are redacted. |
| Response headers | PASS | Sensitive response headers are redacted. |
| Cookies | PASS | Cookie/session values are redacted. |
| Auth headers | PASS | Authorization/Bearer/Basic patterns are redacted. |
| Audit log | PASS | Reviewed payloads avoid secret-bearing audit log output. |
| Errors | PASS | Controlled errors are redacted. |
| Legacy payloads | PASS | Backend and frontend reviews cover malformed/legacy secret-bearing payloads. |
| Exports | PASS | Markdown, HTML, XML, and PDF exports are covered. |
| DOM/Raw JSON | PASS | Frontend report DOM and Raw JSON are redacted. |
| Operator reminder to avoid secrets in targets | BACKLOG | Existing docs cover redaction, but future Active alpha docs should make operator guidance more visible. |

### UX/Copy

| Check | Status | Notes |
| --- | --- | --- |
| Dry-run vs live distinction clear | PASS | Separate panels and copy distinguish no-network dry-run from one-HEAD live probe. |
| Double confirmation | PASS | Live submit requires authorization and live-traffic confirmation. |
| No `scan` action wording | PASS | New live action uses `Create authorized header probe job`. |
| No exploitability claims | PASS | Reports call observations review indicators. |
| No credential-valid claims | PASS | No credential validation is implied. |
| No safe-target claims | PASS | UI does not claim target ownership, safety, or reachability proof. |
| Disabled state calm | PASS | Disabled copy is controlled and avoids `.env`, bypass, retry, DNS, or HTTP claims. |
| Blocked reasons safe | PASS | Blocked/pre-request payloads show `No HTTP request was sent.` without bypass guidance. |

### Operations

| Check | Status | Notes |
| --- | --- | --- |
| Local smoke checklist exists | PASS | Block 18 documents a manual smoke checklist. |
| Local/owned targets only | PASS | Block 18 requires explicitly authorized local or owned targets. |
| No external demo targets by default | NEEDS FIX BEFORE NEXT LIVE CAPABILITY | The next smoke block should make local-only discipline explicit and avoid third-party demo targets. |
| No production readiness claim | PASS | Block 18 states the capability is not production or external-user readiness. |
| Logs/results retention caveat | BACKLOG | README documents local uploads/results generally; future Active alpha docs should call out target/result retention for Active jobs specifically. |
| Release/versioning not yet defined for Active | BACKLOG | Active has no separate alpha/release decision yet. |

## 4. Findings

### Blockers Before Next Live Design

None found for docs-first work.

The limited live line is coherent enough to proceed to a next docs-first step. That acceptance does not approve additional runtime, Nmap, broader target support, local-lab bypasses, or another live capability.

### Must-Fix Before Next Live Runtime

- Define and run a local-only smoke method before adding any new live runtime behavior.
- Resolve the local smoke tension: current live policy blocks loopback/private targets, so Block 20 must use an approved controlled method without weakening the production target policy by accident.
- Freeze a no-external-demo-target rule for Active smoke by default.
- Keep any future live runtime behind its own feature flag, authorization, bounded limits, redaction tests, and fail-closed target policy.

### Should-Fix Before Broader Active Alpha

- Add operator-facing Active enablement guidance that does not mention `.env` editing shortcuts, bypasses, or production readiness.
- Document Active target/result retention more explicitly for local jobs.
- Decide whether Active needs its own alpha checkpoint or release-note path separate from Passive Alpha.
- Re-run forbidden-copy checks before any broader Active alpha surface.

### Backlog

- Consider a separate docs-first local-lab mode only if the product truly needs local loopback/private smoke outside tests.
- Consider richer policy/audit event versioning for future Active modules.
- Consider a dedicated Active operations guide after the local smoke block.
- Consider a future Nmap design only after separate scope, safety, and redaction review. Nmap remains out of scope now.

## 5. Decision

Decision:

```text
ACTIVE_LIMITED_LIVE_HARDENING_ACCEPTED_FOR_NEXT_DESIGN
```

The limited live line is accepted for the next docs-first step. The recommended next step is not a new live capability yet; it is a local smoke block that verifies the already closed one-HEAD capability under controlled conditions.

## 6. Next Path Recommendation

Completed next path:

```text
ACTIVE-NETWORK-BLOCK-20-LIMITED-LIVE-SMOKE-RUN-LOCAL
```

Smoke method record: `docs/future/active-network-block-20-limited-live-smoke-run-local.md`

That block accepts a local test-double smoke method without relaxing production target policy.

Original rationale:

- It validates the first live path in a controlled way before designing more live behavior.
- It can prove the feature flag, disabled state, double confirmation, job lifecycle, one-HEAD behavior, no-body/no-redirect behavior, report rendering, exports, and redaction with a local controlled target or approved mock/local harness.
- It avoids jumping straight to a second live capability while the first live path has not had a real local smoke.

Alternative paths:

- `ACTIVE-NETWORK-BLOCK-20-NEXT-LIVE-CAPABILITY-DESIGN-DOCS-FIRST` if product leadership explicitly accepts deferring local smoke.
- `ACTIVE-NETWORK-BLOCK-20-ACTIVE-ALPHA-CHECKPOINT-RELEASE-PLANNING` if the next priority is packaging/release discipline rather than more live behavior.

The recommended sequencing is Option A first, then decide whether the Active line deserves an internal alpha checkpoint or a new tiny live capability design.

## 7. No-Scope

- No code.
- No live probes.
- No Nmap.
- No backend changes.
- No frontend changes.
- No runner changes.
- No passive analyzer changes.
- No Passive work.
- No push.
- No tag or release.
- No `.env` reads or guidance.
- No local-lab mode implementation.
- No new Active capability.
- No target execution.
- No external network tests.

## Validation Commands

Closeout validation for this docs-first checkpoint:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
```

No pytest/npm suite is required unless runtime files change.
