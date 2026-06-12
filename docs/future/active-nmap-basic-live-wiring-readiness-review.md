# Active Nmap Basic Live Wiring Readiness Review

Status: `ACTIVE_NMAP_BASIC_13_LIVE_WIRING_READINESS_REVIEW_PASSED`

This is a docs-only/read-only review of the accepted `active_nmap_basic`
implementation state before any real backend-to-runner live wiring is allowed.
No runtime behavior, backend executor wiring, frontend behavior, runner endpoint,
Docker packaging, migration, tag, or release is added by this review.

## Commits Covered

- `f324633 docs(active): review nmap basic e2e contract before live wiring`
- `5cc62f2 test(active): harden nmap basic before live wiring`
- `c9067ef feat(active): wire nmap basic jobs to test double`

## Files Reviewed

- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`
- `docs/future/active-nmap-basic-design.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `docs/future/active-nmap-basic-e2e-contract-review-no-live.md`
- `docs/future/active-nmap-basic-pre-wiring-hardening-no-live.md`
- `docs/future/active-nmap-basic-backend-runner-wiring-test-double-no-live.md`
- `backend/app/main.py`
- `backend/app/services.py`
- `backend/app/storage.py`
- `backend/app/active_nmap_policy.py`
- `backend/app/active_nmap_handoff.py`
- `backend/app/reporting.py`
- `backend/tests/test_active_nmap_policy.py`
- `backend/tests/test_backend.py`
- `tools/active_runner/contracts.py`
- `tools/active_runner/nmap_basic/command_builder.py`
- `tools/active_runner/nmap_basic/service.py`
- `tools/active_runner/nmap_basic/executor.py`
- `tools/active_runner/nmap_basic/parser.py`
- `tools/active_runner/nmap_basic/result.py`
- `tools/active_runner/nmap_basic/target_policy.py`
- `tools/tests/test_active_runner_nmap_basic_command_builder.py`
- `tools/tests/test_active_runner_nmap_basic_service.py`
- `tools/tests/test_active_runner_nmap_basic_executor.py`
- `tools/tests/test_active_runner_nmap_basic_parser.py`
- `frontend/src/ActiveNmapBasicPanel.tsx`
- `frontend/src/ActiveNmapBasicPanel.test.tsx`
- `frontend/src/ActiveNmapBasicJobReport.tsx`
- `frontend/src/ActiveNmapBasicJobReport.test.tsx`
- `frontend/src/activeNmapBasicReport.ts`
- `frontend/src/App.test.tsx`

## Findings

### Backend Lifecycle

Reviewed state: pass.

- `POST /active/network/nmap-basic` remains disabled by default through
  `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=false`.
- Disabled mode returns a controlled `403` before creating a job.
- Auth-required anonymous requests are denied by the existing sensitive-route
  guard before validation details or job creation.
- Enabled valid requests validate the exact `live_nmap_basic` /
  `tcp_connect_small` contract, required confirmations, target policy, port
  bounds, and target-port-check bounds before job creation.
- Enabled valid requests create `active_nmap_basic` jobs with `file_id: null`
  and current owner metadata.
- Job list, detail, Markdown, HTML, XML, PDF, and Raw JSON use owner checks and
  redaction before public output.
- Wrong-owner detail/export reads are covered by tests and receive generic
  not-found responses.
- The current adapter is `ActiveNmapBasicNoLiveService.record_no_live_result`,
  which stores `status: not_executed`, `execution_attempted: false`,
  `runner_connected: false`, `nmap_executed: false`,
  `subprocess_invoked: false`, `network_requests_sent: 0`, and
  `dns_queries_sent: 0`.

### Runner And Executor

Reviewed state: pass for an isolated runner package, not yet approved for
backend live use.

- The real executor remains isolated under
  `tools/active_runner/nmap_basic/executor.py`.
- The backend does not import `execute_active_nmap_basic`, the executor module,
  `subprocess`, or `tools/runner/main.py` for `active_nmap_basic`.
- The executor builds argv only through the allowlisted command builder.
- The command builder emits a fixed `nmap -sT -Pn -n --max-retries ...`
  structured argv list, with `-oX -`, `-p`, `--`, and no shell string.
- The executor calls the supplied runner or `subprocess.run` with `shell=False`.
- Runner-side target policy mirrors backend rejection for CIDR, dash ranges,
  wildcards, URLs, userinfo, public-looking targets, metadata/control-plane
  names, target files, special-purpose IPs, duplicates at backend batch level,
  and unsupported syntax.
- Timeout, stdout, and stderr handling is bounded by constants.
- Controlled executor states include `completed`, `failed`, `timed_out`, and
  `nmap_missing`.
- Runner tests use fakes/mocks by default and do not require Nmap to be
  installed.

### Handoff And Fanout

Reviewed state: pass for bounded handoff; live fanout remains blocked.

- Backend `targets[]` is converted into one handoff unit per normalized target.
- `implicit_concurrency` is fixed at `1`.
- Target count is bounded by backend policy.
- Per-target port count is bounded at 32.
- Total target-port checks are bounded at 96.
- Multi-target requests currently create one no-live job with aggregate bounded
  metadata and redacted target display, not parallel execution.
- Broad ranges, CIDR, wildcards, pasted target lists, target files, custom
  profiles, raw flags, shell commands, and unsupported fields are rejected
  before job creation.

### Parser, Result, And Reporting

Reviewed state: pass.

- Executor output can be converted into parser output with
  `parse_active_nmap_basic_xml` and then composed into a structured
  `active_nmap_basic` payload with `build_active_nmap_basic_result_payload`.
- Parser input is bounded and rejects unsupported XML shapes such as DOCTYPE or
  entity declarations.
- Parser output returns only minimal TCP port observations and controlled parser
  states.
- Raw XML, raw target, raw command, stdout/stderr, service/version/banner
  fields, and findings are not returned by parser/result composition.
- Backend reporting and public API redaction defensively remove raw targets,
  command fragments, XML, stdout/stderr, service/banner fields, headers,
  cookies, tokens, credentials, and malformed nested sensitive strings.
- Report wording uses "Observed TCP exposure", "Review indicator", and "Manual
  validation required".
- Reports and frontend redaction avoid confirmed vulnerability, exploitability,
  target-safety, "all ports found", and complete-coverage claims.

### Frontend

Reviewed state: pass.

- The UI distinguishes disabled/unavailable, legacy `not_implemented` /
  `not_executed`, and created no-live test-double jobs from completed live scan
  behavior.
- A mocked created no-live job renders controlled copy: Nmap was not executed.
- Submit uses the exact backend contract: one target, bounded numeric TCP
  ports, fixed `live_nmap_basic` / `tcp_connect_small`, and the three
  confirmations.
- The panel exposes no raw flags, target-file, CIDR/range/wildcard,
  custom-profile, advanced-scan, credential/header/cookie/token, NSE,
  brute-force, credential-validation, crawling, or DNS-expansion controls.
- Report rendering handles `completed`, `failed`, `timed_out`, `nmap_missing`,
  `malformed`, `truncated`, `no_ports`, sparse payloads, and `not_executed`
  controlled states with defensive Raw JSON redaction.

## Blockers

No blockers were found for a next no-live/mocked backend-to-executor wiring
microphase.

The following remain blockers for real Nmap execution or a live local smoke:

- no backend call to the real executor has been implemented or reviewed;
- no operator runbook for real Nmap execution has been accepted;
- no live execution feature flag separate from the current contract gate has
  been designed;
- no Docker/package installation story for Nmap has been accepted;
- no local authorized Nmap smoke target and procedure has been accepted;
- no final review of stored real executor stdout/stderr/parser failure payloads
  has been performed after backend integration;
- no approval exists for broader fanout, concurrency, target expansion, public
  targets, raw flags, custom scripts, NSE, brute force, credential validation,
  crawling, or DNS expansion.

## Risks Residuals

- A future backend integration could accidentally treat executor `completed` as
  a vulnerability finding instead of an observed exposure / review indicator.
- Real Nmap stderr/stdout may contain unexpected target, hostname, version, or
  environment strings that require another redaction pass after integration.
- Background-task timing may need careful UI messaging when transitioning from
  no-live `not_executed` jobs to mocked executor states.
- Target policy parity currently relies on mirrored backend and runner logic;
  future edits should keep parity tests mandatory.
- Packaging/installing Nmap would widen the operational surface and should not
  be bundled into backend wiring.

## Operational Readiness Decision

Decision: passed with constraints.

The project is ready for option **b** only:

```text
backend live wiring toward the real executor interface, with tests mocked and
no real Nmap execution
```

This review does not approve option **c** local authorized Nmap smoke or option
**d** Docker/Nmap packaging. Option **a** backend live wiring with only another
fake runner is allowed but lower value than the next mocked executor-interface
slice because the no-live test-double lifecycle is already implemented.

The next implementation must still preserve disabled-by-default behavior,
explicit opt-in, owner scope, target policy, bounded handoff, redaction-first
storage/reporting, no archive/run-all integration, no `tools/runner/main.py`
integration, no runner HTTP endpoint, and no real Nmap process execution in
tests.

## Next Microphase Recommended

Recommended next step:

```text
ACTIVE-NMAP-BASIC-14-BACKEND-EXECUTOR-WIRING-MOCKED-NO-LIVE
```

Expected shape:

- backend service boundary calls an injectable executor interface only;
- default tests inject mocks/fakes and never require Nmap installed;
- no real subprocess is invoked from backend tests;
- job results remain owner-scoped and redacted;
- parser/result composition is exercised through synthetic executor outputs;
- real Nmap execution remains blocked for a later separately approved local
  smoke microphase.

## Validation Evidence

Validation was run locally with no Docker, no Nmap, no probes, no DNS checks,
no external HTTP traffic, no `.env` file reads, no migrations, no tags, and no
releases.

Final validation record:

- `git status --short`: documentation changes only.
- `git status --branch --short`: `main...origin/main [ahead 16]` before this
  review commit.
- `git diff --check`: pass.
- `git diff --cached --check`: pass.
- `py_compile` for relevant backend and active-runner modules: pass.
- `pytest backend/tests/test_active_nmap_policy.py backend/tests/test_backend.py -k active_nmap_basic`:
  101 passed, 346 deselected.
- `pytest backend/tests/test_backend.py`: 363 passed.
- `pytest tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_service.py tools/tests/test_active_runner_nmap_basic_executor.py tools/tests/test_active_runner_nmap_basic_parser.py`:
  76 passed.
- `npm run test -- --run ActiveNmapBasicPanel ActiveNmapBasicJobReport App dashboardFilters reportHelpers`:
  5 files passed, 102 tests passed.
- `npm run test -- --run`: 20 files passed, 144 tests passed.
- `npm run build`: pass; Vite reported the existing chunk-size warning after a
  successful build.
- `rg -n "active_nmap_basic|Nmap|nmap|Active / Nmap basic|not_executed|nmap_missing|Observed TCP exposure|Review indicator" frontend backend tools docs README.md`:
  reviewed expected references.
- `rg -n "shell=True|os.system|popen|Popen\\(|subprocess|run\\(|nmap " tools/active_runner backend frontend`:
  reviewed expected test redaction fixtures, dry-run naming, and isolated
  active-runner executor references; no backend live subprocess path for
  `active_nmap_basic`.
- `rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges" frontend backend tools docs README.md`:
  reviewed expected no-scope and forbidden-copy guardrails.
- `rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py`:
  reviewed backend contract/no-live service references; no
  `tools/runner/main.py` integration.

Search hits are expected for explicit guardrails, tests, redaction, the
isolated runner executor, and the backend no-live adapter. They must not show
backend calls to the real executor, passive-runner integration, runner HTTP
endpoint wiring, archive/run-all integration, broad scanning promises, or
confirmed-vulnerability/exploitability claims.

## Decision

The live wiring readiness review is passed:

```text
ACTIVE_NMAP_BASIC_13_LIVE_WIRING_READINESS_REVIEW_PASSED
```
