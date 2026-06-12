# Active Nmap Basic Backend Executor Wiring Mocked No-Live

Status: `ACTIVE_NMAP_BASIC_14_BACKEND_EXECUTOR_WIRING_MOCKED_NO_LIVE_ACCEPTED`

This microphase connects the backend `active_nmap_basic` job lifecycle to an
injectable executor adapter interface while keeping all default runtime and
tests no-live. It does not execute Nmap, invoke backend subprocesses, add Docker
behavior, add runner HTTP endpoints, integrate archive/run-all, integrate
`tools/runner/main.py`, perform probes, perform DNS checks, or send external
HTTP traffic.

## Objective

The objective is to prove the backend can create owner-scoped
`active_nmap_basic` jobs, call a bounded executor boundary through dependency
injection, compose structured parser/result payloads from synthetic outputs,
and store redacted reportable results without connecting to real Nmap
execution.

This phase keeps the user-visible contract from the accepted backend gate:

- `POST /active/network/nmap-basic`;
- disabled by default through `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=false`;
- exact `mode: live_nmap_basic`;
- exact `profile: tcp_connect_small`;
- bounded `targets[]` and TCP `ports[]`;
- required authorization, local/private/self-hosted scope, and live-traffic
  confirmations.

## Mocked No-Live State

The backend now uses `ActiveNmapBasicService` with an injectable
`ActiveNmapBasicExecutorAdapter` protocol. The default adapter is
`ActiveNmapBasicNoLiveExecutorAdapter`, which returns only a controlled
`not_executed` result.

Tests may inject a fake adapter named `mocked_executor`. That fake adapter
returns synthetic execution states and synthetic XML/stdout values. The backend
then composes results through the bounded parser and result composer without
running Nmap or invoking subprocesses.

Stored payloads preserve:

- `audit_type: active_nmap_basic`;
- `file_id: null`;
- owner metadata;
- redacted target display metadata;
- `runner_connected: false`;
- `nmap_executed: false`;
- `subprocess_invoked: false`;
- `network_requests_sent: 0`;
- `dns_queries_sent: 0`;
- bounded target, port, and target-port-check counts.

## Injectable Interface

The injectable interface is intentionally small:

```text
execute(unit: ActiveNmapBasicHandoffUnit) -> Mapping[str, Any]
```

The backend supplies already-validated handoff units. The adapter returns a
bounded execution mapping. The backend accepts only controlled status and reason
values from that mapping before parsing or storing any result.

The backend does not import or call `execute_active_nmap_basic`, does not import
`tools/active_runner/nmap_basic/executor.py`, and does not import `subprocess`.
The real executor remains isolated under `tools/active_runner/nmap_basic/` and
is still tested with fakes.

## States Covered

Backend tests cover these injected states:

- `completed`;
- `failed`;
- `timed_out`;
- `nmap_missing`;
- `malformed`;
- `truncated`;
- `no_ports`;
- `not_executed`.

For `completed`, `malformed`, `truncated`, and `no_ports`, tests use synthetic
stdout/XML and the bounded parser. Raw XML is not stored or returned. Service,
version, banner, target, command, stdout, and stderr data are omitted or
redacted before API/report/export/Raw JSON surfaces.

## Still Blocked

This microphase does not approve:

- real Nmap execution;
- backend subprocess invocation;
- unmocked executor calls in tests;
- Docker execution or Nmap packaging;
- runner HTTP endpoint;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- probes, DNS checks, or external HTTP traffic;
- raw flags;
- custom scripts;
- NSE;
- stealth or evasion;
- brute force;
- credential validation;
- crawling;
- DNS expansion;
- broad ranges;
- target-policy relaxation;
- owner-scope relaxation;
- treating mocked results as authorization for local smoke;
- confirmed vulnerability, exploitability, target-safety, complete-coverage, or
  public scanner claims.

## Validation Evidence

Validation was run locally with no Docker, no Nmap, no probes, no DNS checks,
no external HTTP traffic, no `.env` file reads, no migrations, no tags, and no
releases.

Final validation record:

- `git status --short`: expected source, test, and documentation changes only.
- `git status --branch --short`: `main...origin/main [ahead 17]` before this
  commit.
- `git diff --check`: pass.
- `git diff --cached --check`: pass.
- `py_compile` for relevant backend and active-runner modules: pass.
- `pytest backend/tests/test_active_nmap_policy.py backend/tests/test_backend.py -k active_nmap_basic`:
  108 passed, 346 deselected.
- `pytest backend/tests/test_backend.py`: 370 passed.
- `pytest tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_service.py tools/tests/test_active_runner_nmap_basic_executor.py tools/tests/test_active_runner_nmap_basic_parser.py`:
  76 passed.
- `npm run test -- --run ActiveNmapBasicPanel ActiveNmapBasicJobReport App dashboardFilters reportHelpers`:
  5 files passed, 102 tests passed.
- `npm run test -- --run`: 20 files passed, 144 tests passed.
- `npm run build`: pass; Vite reported the existing chunk-size warning after a
  successful build.
- `rg -n "active_nmap_basic|Nmap|nmap|Active / Nmap basic|not_executed|nmap_missing|Observed TCP exposure|Review indicator" frontend backend tools docs README.md`
- `rg -n "shell=True|os.system|popen|Popen\\(|subprocess|run\\(|nmap " tools/active_runner backend frontend`
- `rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges" frontend backend tools docs README.md`
- `rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py`

Search hits were reviewed. Expected hits were limited to guardrails, tests,
reporting redaction, the isolated active-runner executor module, and backend
mocked/no-live adapter wiring. They did not show backend subprocess use,
backend direct calls to the real executor, runner HTTP endpoint wiring,
archive/run-all integration, `tools/runner/main.py` integration, broad scanning
promises, or confirmed-vulnerability/exploitability claims.

## Recommendation

Recommended next microphase:

```text
ACTIVE-NMAP-BASIC-15-LOCAL-SMOKE-PLAN-NO-UNAUTHORIZED-TRAFFIC
```

Before any real Nmap smoke is considered, the next phase should first freeze a
smoke plan that names the authorized target-control method, confirms no
unauthorized external traffic, defines operator steps, records rollback/cleanup
expectations, and keeps real execution separately approved.

## Decision

The backend executor-interface mocked/no-live wiring is accepted:

```text
ACTIVE_NMAP_BASIC_14_BACKEND_EXECUTOR_WIRING_MOCKED_NO_LIVE_ACCEPTED
```
