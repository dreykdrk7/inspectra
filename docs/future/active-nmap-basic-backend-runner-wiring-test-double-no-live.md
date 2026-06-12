# Active Nmap Basic Backend Runner Wiring Test-Double No-Live

Status: `ACTIVE_NMAP_BASIC_12_BACKEND_RUNNER_WIRING_TEST_DOUBLE_NO_LIVE_ACCEPTED`

This microphase enables the first backend job lifecycle for
`active_nmap_basic` while preserving the no-live boundary. It creates real
Inspectra jobs only when `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=true`, but the
job execution path is wired only to a backend-owned test-double adapter that
does not execute Nmap, call the real active-runner executor, invoke
subprocesses, resolve DNS, send probes, run Docker, or make external HTTP
requests.

## Objective

The objective is to prove the backend lifecycle boundary before any real live
wiring:

- create owner-scoped `active_nmap_basic` jobs with `file_id: null`;
- validate the exact `live_nmap_basic` / `tcp_connect_small` contract and the
  three confirmations before job creation;
- reuse the Microphase 11 handoff helper to derive bounded target and port
  counts;
- store only a controlled `not_executed` result from a no-live test-double;
- preserve redaction across job detail, job list, Markdown, HTML, XML, PDF, and
  Raw JSON;
- keep frontend submit behavior controlled when a created no-live job is
  returned.

## No-Live State

This phase remains no-live.

The enabled endpoint creates a job and schedules only
`ActiveNmapBasicNoLiveService.record_no_live_result`. That service records:

- `status: not_executed`;
- `execution_state: not_executed`;
- `execution_attempted: false`;
- `adapter: test_double_no_live`;
- `runner_connected: false`;
- `nmap_executed: false`;
- `subprocess_invoked: false`;
- `network_requests_sent: 0`;
- `dns_queries_sent: 0`;
- bounded target, port, target-port-check, and `implicit_concurrency: 1`
  metadata.

It does not import or call the real Nmap executor. It does not construct a
command, return a command preview, parse XML, read stdout/stderr, create
findings, or store raw target evidence.

## Job Lifecycle Enabled

When the feature flag is disabled, `POST /active/network/nmap-basic` continues
to return a controlled `403` and creates no job.

When the feature flag is enabled and the request is valid:

- the backend validates request shape, confirmations, target policy, port
  bounds, and target-port-check bounds;
- the backend builds a handoff plan that serializes `targets[]` into bounded
  single-target units;
- the backend creates one Inspectra job with `audit_type:
  active_nmap_basic`, `file_id: null`, current owner metadata, and redacted
  target display metadata;
- the backend schedules the no-live adapter;
- the stored job completes with a structured `active_nmap_basic` payload whose
  result state is explicitly `not_executed`.

Multi-target requests are represented as one bounded job with aggregate
metadata. The handoff helper retains single-target units internally, but this
phase does not execute them and does not introduce parallelism.

## How Real Nmap Is Avoided

The backend no-live service depends only on the existing result-payload
composer and the backend handoff plan. It does not depend on:

- `tools/active_runner/nmap_basic/executor.py`;
- `subprocess`;
- a shell command;
- a runner HTTP endpoint;
- `tools/runner/main.py`;
- Docker;
- DNS, socket, probe, or HTTP client behavior.

The runner executor remains isolated in the active-runner package and is not
called by backend tests or backend runtime in this phase.

## Still Blocked

The following remain blocked and out of scope:

- real Nmap jobs;
- backend-to-runner live executor wiring;
- runner HTTP endpoints;
- backend subprocess calls;
- Docker execution;
- probes, DNS checks, and external HTTP traffic;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- raw flags, extra args, shell commands, custom scripts, NSE, brute force,
  exploit scripts, credential validation, crawling, DNS expansion, and broad
  ranges;
- policy relaxation for public internet targets;
- wording that treats the result as a confirmed vulnerability, exploitability
  proof, proof that all ports were found, or proof that a target is safe.

## Validation Coverage

Backend coverage added or updated:

- disabled flag rejects without job creation;
- enabled flag creates an owner-scoped `active_nmap_basic` job with `file_id:
  null`;
- invalid request bodies create no job;
- target-policy rejection creates no job;
- auth-required anonymous requests fail before validation details and before
  job creation;
- no-live multi-target handoff stores only bounded aggregate metadata and
  `implicit_concurrency: 1`;
- job detail, list, Markdown, HTML, XML, PDF, and Raw JSON remain redacted;
- wrong-owner list/detail/export access is denied;
- archive audit paths cannot create `active_nmap_basic` jobs;
- backend source does not import the real active-runner executor, `subprocess`,
  `tools/runner/main.py`, or frontend code for this path.

Frontend coverage added or preserved:

- submit with a mocked created no-live job renders controlled test-double copy;
- created no-live jobs are not presented as completed live scans;
- disabled `403` behavior remains generic and does not reflect target details;
- legacy `501` / `not_executed` behavior remains controlled;
- no raw-flag, credential, header, cookie, token, target-file, custom-profile,
  NSE, brute-force, credential-validation, crawling, DNS-expansion, or
  broad-scan controls are introduced.

Runner coverage remains regression-only in this phase. Existing command
builder, service, executor, and parser tests continue to use fakes/synthetic
fixtures and do not require Nmap to be installed.

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
  `101 passed, 346 deselected`.
- `pytest backend/tests/test_backend.py`: `363 passed`.
- `pytest tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_service.py tools/tests/test_active_runner_nmap_basic_executor.py tools/tests/test_active_runner_nmap_basic_parser.py`:
  `76 passed`.
- `npm run test -- --run ActiveNmapBasicPanel ActiveNmapBasicJobReport App dashboardFilters reportHelpers`:
  `5 passed`, `102 tests passed`.
- `npm run test -- --run`: `20 passed`, `144 tests passed`.
- `npm run build`: passed.
- `rg -n "active_nmap_basic|Nmap|nmap|Active / Nmap basic|not_executed|nmap_missing|Observed TCP exposure|Review indicator" frontend backend tools docs README.md`
- `rg -n "shell=True|os.system|popen|Popen\\(|subprocess|run\\(|nmap " tools/active_runner backend frontend`
- `rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges" frontend backend tools docs README.md`
- `rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py`

The expected search hits are explicit guardrails, tests, redaction code, the
isolated active-runner executor module, and the backend no-live adapter. They
must not reveal backend calls to the real executor, `tools/runner/main.py`
integration, runner HTTP endpoints, archive/run-all wiring, or claims of
confirmed vulnerability/exploitability.

## Recommended Next Microphase

Recommended next step:

```text
ACTIVE-NMAP-BASIC-13-LIVE-WIRING-READINESS-REVIEW
```

That phase should be a review checkpoint before any real backend-to-runner
executor call is considered. It should re-check owner scope, target policy,
redaction, frontend wording, runner executor controls, and operational no-go
criteria. Real Nmap execution should remain blocked unless a later,
separately-approved live microphase explicitly authorizes it.

## Decision

The backend runner wiring test-double no-live checkpoint is accepted:

```text
ACTIVE_NMAP_BASIC_12_BACKEND_RUNNER_WIRING_TEST_DOUBLE_NO_LIVE_ACCEPTED
```
