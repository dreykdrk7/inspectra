# Active Nmap Basic Pre-Wiring Hardening, No Live

Status: `ACTIVE_NMAP_BASIC_11_PRE_WIRING_HARDENING_NO_LIVE_ACCEPTED`

This document records the no-live hardening checkpoint before any
backend-to-runner wiring for `active_nmap_basic`. The phase adds pure helpers
and tests for policy parity, single-target handoff serialization, structured
result composition, redaction, and frontend controlled-state behavior.

It does not create real Nmap jobs, connect the backend to the runner executor,
add a runner HTTP endpoint, integrate with archive/run-all, integrate Active
into `tools/runner/main.py`, run Docker, run Nmap, run probes, perform DNS
checks, perform external HTTP traffic, create migrations, create tags, or
create releases.

## Objective

The objective is to reduce cross-boundary risk before live wiring by proving,
with fakes and offline fixtures, that:

- backend and runner target policies stay aligned;
- backend `targets: [...]` can be serialized into single-target handoff units
  without widening scope;
- confirmations and bounded ports are preserved in the handoff shape;
- fake executor output can be parsed into a structured `active_nmap_basic`
  payload without raw target, command, XML, stdout, stderr, service, or banner
  evidence;
- backend reporting keeps the structured payload redacted in API responses,
  summaries, Markdown, HTML, XML, PDF, and Raw JSON;
- frontend `not_executed`, disabled, and legacy/malformed states remain
  controlled and are not presented as completed scans.

## Gaps Closed

Policy parity:

- Added backend/runner acceptance parity tests for valid private, loopback,
  local hostname, and self-hosted-style targets.
- Added backend/runner rejection parity tests for CIDR, dash ranges, wildcards,
  URL-shaped values, userinfo, pasted lists, metadata/control-plane names,
  special-purpose IP ranges, public-looking targets, ambiguous/trailing-dot
  names, port suffixes, and target-file-like values.
- Kept duplicate and too-many-target checks in the backend list validator,
  where those batch-level semantics exist.

Handoff serialization:

- Added `backend/app/active_nmap_handoff.py` as a pure/offline helper.
- The helper validates the exact `live_nmap_basic` / `tcp_connect_small`
  contract, required confirmations, target policy, port bounds, and total
  target-port check bounds.
- The helper converts normalized `targets[]` into one
  `ActiveNmapBasicHandoffUnit` per target.
- The helper records `implicit_concurrency: 1` and sequence indexes so tests can
  assert no implicit fanout concurrency or broad batch expansion.
- The helper does not call a runner, create jobs, start background tasks, build
  commands, use subprocesses, resolve DNS, send probes, or execute Nmap.

Result composition:

- Added `tools/active_runner/nmap_basic/result.py` as a pure/offline result
  composer.
- The composer combines fake execution metadata and bounded parser output into
  an already-structured `active_nmap_basic` report payload.
- The payload intentionally does not include raw XML, raw targets, commands,
  stdout, stderr, service/version/banner data, findings, CVE matches, or
  vulnerability/exploitability claims.
- Backend tests store the composed payload as synthetic job data and verify
  API/report/export redaction without connecting backend to runner execution.

Frontend controlled-state hardening:

- Added an explicit frontend report test for `not_executed`.
- The report says the job was not executed and does not present it as a
  completed scan.
- Existing disabled, `501` / `not_implemented`, Raw JSON redaction, no
  forbidden controls, and forbidden-copy tests remain in place.

## Tests Added

Backend policy and handoff tests:

- `test_active_nmap_basic_backend_and_runner_policy_acceptance_parity`
- `test_active_nmap_basic_backend_and_runner_policy_rejection_parity`
- `test_active_nmap_basic_handoff_serializes_targets_to_single_target_units_no_live`
- `test_active_nmap_basic_handoff_rejects_wide_batches_and_unsupported_fields_no_live`

Backend composition/reporting test:

- `test_active_nmap_basic_fake_execution_parser_payload_exports_no_live`

Runner parser/result test:

- `test_result_payload_composes_fake_execution_and_parser_without_raw_evidence`

Frontend report test:

- `renders not-executed as not connected rather than a completed scan`

## Still Blocked

The following remain blocked after this phase:

- backend-to-runner live wiring;
- real `active_nmap_basic` job creation;
- background task execution for Nmap;
- runner HTTP endpoint exposure;
- real Nmap subprocess invocation from backend flows;
- Docker or Nmap dependency changes;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- broad batches, broad ranges, CIDR expansion, DNS expansion, crawling,
  credential validation, brute force, NSE/scripts, raw flags, custom scripts,
  stealth, evasion, exploit checks, public scanner behavior, and SaaS/public
  scan-as-a-service operation.

Authorization remains a user assertion, not proof of ownership. Future live
execution must still be disabled by default, opt-in, local/private/self-hosted,
target-authorized, bounded, owner-scoped, redacted before public surfaces, and
worded only as observed exposure or review indicators.

## Validation Evidence

Validation was run locally with no Docker, no Nmap, no probes, no DNS checks,
no external HTTP traffic, no `.env` file reads, no migrations, no tags, and no
releases.

Final validation record:

- `git status --short`: expected changed files only.
- `git status --branch --short`: `main` ahead of origin with expected changed
  files only.
- `git diff --check`: passed.
- `git diff --cached --check`: passed.
- `py_compile` for relevant backend and active-runner modules: passed.
- `pytest backend/tests/test_active_nmap_policy.py backend/tests/test_backend.py -k active_nmap_basic`:
  `97 passed, 346 deselected`.
- `pytest backend/tests/test_backend.py`: `359 passed`.
- `pytest tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_service.py tools/tests/test_active_runner_nmap_basic_executor.py tools/tests/test_active_runner_nmap_basic_parser.py`:
  `76 passed`.
- `npm run test -- --run ActiveNmapBasicPanel ActiveNmapBasicJobReport App dashboardFilters reportHelpers`:
  `5 passed`, `101 tests passed`.
- `npm run test -- --run`: `20 passed`, `143 tests passed`.
- `npm run build` from `frontend/`: passed.
- `rg -n "active_nmap_basic|Nmap|nmap|Active / Nmap basic|not_executed|nmap_missing|Observed TCP exposure|Review indicator" frontend backend tools docs README.md`
- `rg -n "shell=True|os.system|popen|Popen\\(|subprocess|run\\(|nmap " tools/active_runner backend frontend`
- `rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges" frontend backend tools docs README.md`
- `rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py`:
  hits are limited to the existing backend contract; no `tools/runner/main.py`
  or backend service live-runner integration was found.

The searches are expected to return explicit guardrails, synthetic tests,
redaction code, and the isolated active-runner executor. They must not reveal a
backend-to-runner live path, runner HTTP endpoint, archive/run-all trigger,
shell execution path, broad scanning promise, or confirmed-vulnerability claim.

## Recommended Next Microphase

Recommended next step:

```text
ACTIVE-NMAP-BASIC-12-BACKEND-RUNNER-WIRING-TEST-DOUBLE-NO-LIVE
```

That phase should wire backend job lifecycle only to a test-double or
not-executing adapter, preserving `file_id: null`, owner scope,
disabled-by-default behavior, single-target fanout, bounded ports, redacted
storage, and `not_executed` semantics. Real executor calls and real Nmap should
remain blocked until a later separately approved live-wiring phase.

## Decision

The pre-wiring hardening checkpoint is accepted:

```text
ACTIVE_NMAP_BASIC_11_PRE_WIRING_HARDENING_NO_LIVE_ACCEPTED
```
