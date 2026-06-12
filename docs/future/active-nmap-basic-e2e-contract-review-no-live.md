# Active Nmap Basic E2E Contract Review, No Live

Status: `ACTIVE_NMAP_BASIC_10A_E2E_CONTRACT_REVIEW_NO_LIVE_PASSED`

This document records a review-only checkpoint for the current
`active_nmap_basic` implementation line before any backend-to-runner live
wiring is attempted. It does not implement runtime behavior, backend runner
calls, runner HTTP endpoints, Docker changes, migrations, tags, releases,
probes, DNS checks, external HTTP checks, or Nmap execution.

The review scope was deliberately no-live:

- no `.env`, `.env.*`, or `.envrc` contents were read or printed;
- no Docker command was run;
- no Nmap command was run;
- no probe, DNS check, or external HTTP traffic was performed;
- no backend-to-runner connection was added;
- no `tools/runner/main.py` Active integration was added;
- no real Nmap job creation path was added;
- no archive/run-all integration was added.

## Reviewed State

The review covers the code and docs state after:

```text
d9a788d feat(active): render nmap basic reports
```

The previously accepted `active_nmap_basic` decisions are:

- `ACTIVE_NMAP_BASIC_DESIGN_FROZEN`
- `ACTIVE_NMAP_BASIC_IMPLEMENTATION_PLAN_FROZEN`
- `ACTIVE_NMAP_BASIC_01_BACKEND_CONTRACT_GATE_ACCEPTED`
- `ACTIVE_NMAP_BASIC_02_TARGET_POLICY_ACCEPTED`
- `ACTIVE_NMAP_BASIC_03_COMMAND_BUILDER_ACCEPTED`
- `ACTIVE_NMAP_BASIC_04_RUNNER_SKELETON_ACCEPTED`
- `ACTIVE_NMAP_BASIC_05_CONTROLLED_SUBPROCESS_ACCEPTED`
- `ACTIVE_NMAP_BASIC_06_BOUNDED_PARSER_ACCEPTED`
- `ACTIVE_NMAP_BASIC_07_REDACTION_REPORTING_ACCEPTED`
- `ACTIVE_NMAP_BASIC_08_FRONTEND_PANEL_SHELL_ACCEPTED`
- `ACTIVE_NMAP_BASIC_09_FRONTEND_CONFIRMATIONS_ACCEPTED`
- `ACTIVE_NMAP_BASIC_10_FRONTEND_REPORT_RENDERING_ACCEPTED`

## Files Reviewed

Documentation:

- `docs/future/active-nmap-basic-design.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `docs/security-scope.md`
- `docs/architecture.md`
- `docs/future/active-network-block-18-authorized-http-header-probe-closeout.md`

Backend contract, policy, storage, and reporting:

- `backend/app/config.py`
- `backend/app/main.py`
- `backend/app/active_nmap_policy.py`
- `backend/app/models.py`
- `backend/app/reporting.py`
- `backend/app/storage.py`
- `backend/tests/test_backend.py`
- `backend/tests/test_active_nmap_policy.py`

Active runner modules:

- `tools/active_runner/contracts.py`
- `tools/active_runner/nmap_basic/command_builder.py`
- `tools/active_runner/nmap_basic/service.py`
- `tools/active_runner/nmap_basic/executor.py`
- `tools/active_runner/nmap_basic/parser.py`
- `tools/active_runner/nmap_basic/target_policy.py`
- `tools/tests/test_active_runner_nmap_basic_command_builder.py`
- `tools/tests/test_active_runner_nmap_basic_service.py`
- `tools/tests/test_active_runner_nmap_basic_executor.py`
- `tools/tests/test_active_runner_nmap_basic_parser.py`

Frontend contract and reports:

- `frontend/src/ActiveNmapBasicPanel.tsx`
- `frontend/src/ActiveNmapBasicJobReport.tsx`
- `frontend/src/activeNmapBasicReport.ts`
- `frontend/src/api.ts`
- `frontend/src/auditCatalog.ts`
- `frontend/src/types.ts`
- `frontend/src/App.tsx`
- focused frontend tests for panel, reports, dashboard filters, and app wiring

## Findings

No release-blocking issue was found for this checkpoint.

The backend remains a contract gate, not a live execution path. The feature flag
`INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED` is disabled by default. When disabled,
`POST /active/network/nmap-basic` rejects without job creation. When enabled,
the route validates the exact `live_nmap_basic` / `tcp_connect_small` contract,
required confirmations, targets, and ports, then returns a controlled
`not_implemented` / `not_executed` response with `job_created: false`.

The backend target policy is exact-target and fail-closed. It rejects CIDR,
dash ranges, wildcards, URL-shaped values, paths, queries, fragments, userinfo,
pasted lists, metadata/control-plane names, special-purpose IP ranges,
public-looking hostnames, excessive targets, overlong targets, and duplicate
normalized targets. It does not resolve DNS or expand targets.

The Active runner implementation is modular and remains separate from the
backend route. The command builder emits an argv list only for the fixed
`tcp_connect_small` profile. The skeleton returns `not_executed` metadata
without target or command preview. The executor can call a supplied runner or
`subprocess.run` with `shell=False`, but it is not exposed through a runner HTTP
endpoint and is not connected to backend job creation. The parser is bounded,
machine-readable, and returns only minimal TCP port observations.

The reviewed `tools/runner/main.py` surface has no `active_nmap_basic` route or
backend integration. Existing references to `socket`, HTTP, DNS, and subprocess
inside that monolith belong to previously implemented passive/web/domain or
legacy runner behavior, not to an Active Nmap Basic path.

Backend reporting and storage treat `active_nmap_basic` as redacted review
evidence. Public job detail, summaries, Markdown, HTML, XML, PDF, and Raw JSON
redact raw targets, commands, stdout/stderr, XML, service/banner fields,
headers, cookies, tokens, credentials, and legacy malformed sensitive strings.
Report wording stays in the "Observed TCP exposure", "Review indicator", and
"Manual validation required" lane and does not assert confirmed vulnerability,
exploitability, target safety, complete coverage, credential validity, or CVE
matching.

The frontend has a bounded panel and report renderer, but no live job result
launch beyond the existing backend contract request. The panel sends only the
fixed request shape after three confirmations, exposes no raw flags, scripts,
target files, CIDR/range/wildcard controls, custom profiles, advanced scan
settings, credential/header/cookie/token fields, or crawling controls. The
report renderer handles completed and controlled failed, timed-out,
`nmap_missing`, malformed, truncated, no-ports, sparse, and legacy payloads
with defensive Raw JSON redaction.

## Residual Risks

Before backend-to-runner wiring, these risks remain intentionally open:

- backend and runner target-policy mirrors can drift unless parity tests are
  added at the handoff boundary;
- the backend currently validates `targets` as a list while the runner service
  accepts one `target`; wiring must define per-target fanout without widening
  target count, concurrency, or storage scope;
- the executor currently returns bounded raw stdout/stderr states but is not
  yet composed with the parser into a final stored job result;
- job lifecycle semantics for target-based `active_nmap_basic` jobs are not
  implemented and must preserve owner scope, `file_id: null`, redacted
  persistence, and disabled-by-default behavior;
- Nmap binary availability and version variance remain operational concerns for
  a future local/private/self-hosted deployment;
- target-side logs are outside Inspectra cleanup control when live execution is
  eventually enabled;
- a no-live test-double smoke should precede any real local lab smoke.

## Gaps Before Backend To Runner Wiring

The next implementation step must not jump directly to live Nmap execution.
These gaps should be closed first:

- define a backend-to-runner handoff shape that serializes one target at a time,
  not broad target batches;
- add policy-parity tests for backend target validation and runner target
  validation using the same accepted and rejected cases;
- add a no-live runner test-double path so backend job lifecycle can be tested
  without Nmap, Docker, probes, DNS, or external HTTP;
- define how executor output is parsed, bounded, redacted, and converted into
  the existing `active_nmap_basic` report payload;
- ensure disabled feature flag and auth-required anonymous denial still happen
  before target validation and before any runner handoff;
- ensure archive/run-all and passive runner paths still cannot trigger
  `active_nmap_basic`;
- keep reports as observed-exposure and review-indicator evidence only.

## Validation Record

Validation commands were run locally without Docker, Nmap, probes, DNS checks,
external HTTP traffic, or `.env` file access.

Passed:

- `git status --short`
- `git status --branch --short`
- `git diff --check`
- `git diff --cached --check`
- `.venv/bin/python -m py_compile backend/app/config.py backend/app/main.py backend/app/active_nmap_policy.py backend/app/reporting.py backend/app/storage.py tools/active_runner/contracts.py tools/active_runner/nmap_basic/command_builder.py tools/active_runner/nmap_basic/service.py tools/active_runner/nmap_basic/executor.py tools/active_runner/nmap_basic/parser.py tools/active_runner/nmap_basic/target_policy.py`
- `.venv/bin/python -m pytest backend/tests/test_active_nmap_policy.py backend/tests/test_backend.py -k active_nmap_basic`
  - `50 passed, 346 deselected`
- `.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_service.py tools/tests/test_active_runner_nmap_basic_executor.py tools/tests/test_active_runner_nmap_basic_parser.py`
  - `75 passed`
- `.venv/bin/python -m pytest backend/tests`
  - `396 passed`
- `npm run test -- --run ActiveNmapBasicPanel ActiveNmapBasicJobReport App dashboardFilters reportHelpers`
  - `100 passed`
- `npm run test -- --run`
  - `142 passed`
- `npm run build`
  - passed with the existing Vite chunk-size warning only

Searches:

- `rg -n "active_nmap_basic|Nmap|nmap|Active" README.md docs/architecture.md docs/security-scope.md docs/future`
- `rg -n "active_nmap_basic|nmap|Nmap|INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED" backend docs README.md`
- `rg -n "subprocess|shell=True|os.system|popen|nmap " backend tools frontend`
- `rg -n "confirmed vulnerability|exploitable|target is safe|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags" backend tools frontend docs/future/active-nmap-basic-e2e-contract-review-no-live.md docs/future/active-nmap-basic-implementation-plan.md README.md docs/architecture.md docs/security-scope.md`

The searches returned expected historical documentation, explicit no-scope
guardrails, synthetic tests/redaction assertions, the isolated
`active_nmap_basic` executor module, and unrelated existing subprocess use in
the passive runner monolith. They did not reveal a new `active_nmap_basic`
backend-to-runner live path, runner HTTP endpoint, archive/run-all trigger,
shell execution path, broad scanning promise, or confirmed-vulnerability claim.

## Decision

The current state passes this no-live end-to-end contract review.

The next phase is allowed only if it remains separately gated and does not
enable real Nmap execution by surprise. Recommended next microphase:

```text
ACTIVE-NMAP-BASIC-11-BACKEND-RUNNER-WIRING-PLAN-NO-LIVE
```

That phase should be docs-only or test-double-only and should specify the job
lifecycle, owner scope, single-target fanout, policy parity, redacted result
shape, and no-live validation method before any actual backend-to-executor live
wiring occurs.

Final decision:

```text
ACTIVE_NMAP_BASIC_10A_E2E_CONTRACT_REVIEW_NO_LIVE_PASSED
```
