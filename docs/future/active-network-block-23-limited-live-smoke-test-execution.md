# Active Network Block 23 Limited Live Smoke Test Execution

Status: `ACTIVE_LIMITED_LIVE_TEST_DOUBLE_SMOKE_EXECUTED`.

Operator guide: `docs/future/active-network-block-22-active-alpha-operator-guide.md`

Accepted local smoke method: `docs/future/active-network-block-20-limited-live-smoke-run-local.md`

Limited live closeout: `docs/future/active-network-block-18-authorized-http-header-probe-closeout.md`

Commit scope: execute and record the accepted no-external-network/test-double smoke subset. This block does not change backend, frontend, runner, tests, fixtures, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
ACTIVE_LIMITED_LIVE_TEST_DOUBLE_SMOKE_EXECUTED
```

The accepted Block 20 test-double smoke subset was executed successfully for:

- runner-level fake resolver/fake HEAD behavior;
- backend/API/storage/reporting/export behavior through in-process `ASGITransport` and monkeypatches;
- frontend mocked API/report rendering, filter metadata, and Raw JSON redaction.

No real probes, external traffic, target DNS, target HTTP, Docker, Nmap, scanners, local servers, or policy bypasses were used.

## Scope Executed

### Runner

The runner smoke used `tools/tests/test_active_runner.py` with injected fake resolver and fake HEAD callbacks. Successful and blocked paths are deterministic and do not use real DNS or HTTP target traffic.

### Backend/API/Reporting

The backend smoke used `backend/tests/test_backend.py` with `ASGITransport(app=app)`, temporary data directories, monkeypatched settings, and monkeypatched runner functions. Export checks exercise stored/fake payloads in process.

### Frontend

The frontend smoke used Vitest and Testing Library. `globalThis.fetch` is stubbed/mocked in the selected tests, and report rendering uses local fixture payloads rather than live backend or target requests.

## Commands Executed

```text
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache .venv/bin/python -m pytest tools/tests/test_active_runner.py -k "http_header or active_http or authorized_http"
```

Result:

```text
9 passed, 21 deselected in 0.09s
```

```text
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache .venv/bin/python -m pytest backend/tests/test_backend.py -k "active_http or http_header"
```

Result:

```text
8 passed, 198 deselected in 1.57s
```

```text
npm run test -- --run ActiveHttpHeaderProbeJobReport App dashboardFilters reportHelpers
```

Result:

```text
Test Files  4 passed (4)
Tests       80 passed (80)
```

## Coverage Confirmed

- Disabled Active HTTP header probe feature flag rejects requests without job creation.
- Disabled state does not create DNS or HTTP target activity in the tested path.
- Active dry-run remains independent from the live header-probe feature flag.
- Live header-probe request requires explicit authorization and live-traffic confirmation.
- Backend creates target-based `active_http_header_probe` jobs with `file_id: null` when enabled and accepted.
- Blocked targets preserve `network_requests_sent: 0`.
- URL credentials, private/loopback/metadata/link-local targets, CIDR/range/wildcard inputs, unsupported schemes, bare hostnames, Nmap profiles, and invalid limits are blocked before HTTP.
- Fake successful runner path records exactly one HTTP `HEAD` attempt.
- No GET fallback is present.
- Redirects are not followed.
- Response body is not read and `body_bytes_read` remains `0`.
- Custom headers, Authorization headers, and cookies are not sent.
- Response headers are redacted.
- API summaries and full job results are redacted.
- Markdown, HTML, XML, and PDF exports render Active sections and redact sensitive values.
- Frontend report sections tolerate completed, blocked, queued/running, failed, sparse, and malformed/legacy payloads.
- Frontend job table and Raw JSON redact legacy target/header secrets.
- Dashboard filter metadata labels `active_http_header_probe` under `Active / Network`.
- Forbidden copy such as Nmap, broad scan, exploit, bypass, credential-valid, and confirmed-vulnerability wording remains absent in the selected Active surfaces.

## Coverage Not Executed

- No real local HTTP server smoke was executed.
- No real loopback/private target smoke was executed.
- No real public or third-party target smoke was executed.
- No live DNS or live HTTP target traffic was executed.
- No full backend suite was executed in this block; the selected backend subset was limited to Active HTTP/header-related tests.
- No full frontend suite was executed in this block; the selected frontend subset was limited to Active HTTP/header/report/filter helper tests.

Reason:

- Block 20 accepted test doubles as the safe local smoke method.
- Production policy must remain fail-closed for loopback/private targets.
- Real target smoke, if needed later, requires a separate docs-first local-lab or operator execution design.

Residual risk from non-executed coverage:

- Test-double smoke validates contracts, redaction, and no-scope behavior, but it does not establish live target truth or real infrastructure behavior.

## Negative Confirmations

- No `.env`, `.env.*`, or `.envrc` files were read.
- No external traffic was sent.
- No real probes were executed.
- No live DNS or HTTP target calls were executed.
- No Docker command was executed.
- No Nmap command or runtime exists in this smoke.
- No port scanning was executed.
- No crawling was executed.
- No local server was started.
- No local-lab mode was created.
- No production target policy was relaxed.
- No new Active capability was added.
- No push, tag, or release was created.

## Residual Risks

- Test-double smoke does not prove target ownership or live target truth.
- Authorization remains a user/operator assertion, not proof of ownership.
- A real enabled one-HEAD request may still be logged by a target in future trusted use.
- Redaction remains defensive and best-effort.
- Operator misuse remains possible if feature flags are enabled outside the intended trusted context.
- Real loopback/private smoke would require a separate design that does not weaken production policy by default.

## Next Recommendation

Completed next microphase:

```text
ACTIVE-NETWORK-BLOCK-24-ACTIVE-ALPHA-README-LINKING-AND-COPY-POLISH
```

Rationale:

- The internal alpha planning, operator guide, and test-double smoke execution are now recorded.
- A small documentation polish pass can align README-facing copy, internal references, and release-readiness language before product decides whether to design another live capability.

Alternative next paths:

- `ACTIVE-NETWORK-BLOCK-24-SMOKE-GAP-FIX-DOCS-FIRST` only if product wants to close the real local-lab gap before any copy polish.
- `ACTIVE-NETWORK-BLOCK-24-NEXT-LIVE-CAPABILITY-DESIGN-DOCS-FIRST` only if product accepts broader Active design after this smoke record.
- `ACTIVE-NETWORK-BLOCK-24-LOCAL-LAB-MODE-DESIGN-DOCS-FIRST` only if real loopback/private smoke becomes necessary and production policy remains unchanged by default.

Do not proceed to Nmap, port scanning, crawling, broader target support, or another live capability from this block.

## Validation Commands

Reference checks for this block:

```text
git status --short
git status --branch --short
git log --oneline -8
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache .venv/bin/python -m pytest tools/tests/test_active_runner.py -k "http_header or active_http or authorized_http"
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache .venv/bin/python -m pytest backend/tests/test_backend.py -k "active_http or http_header"
npm run test -- --run ActiveHttpHeaderProbeJobReport App dashboardFilters reportHelpers
git diff --check
git diff --cached --check
git status --short
```
