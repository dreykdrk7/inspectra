# Active Nmap Basic No-Live Smoke Execution

Decision:

```text
ACTIVE_NMAP_BASIC_16_NO_LIVE_SMOKE_EXECUTION_PASSED
```

This records the first `active_nmap_basic` smoke execution. The smoke used
Option A from the local-smoke plan: no-live validation with fake/mocked
adapters only. It did not run Nmap, run Docker, execute probes, perform DNS
checks, make external HTTP requests, use a real external target, use a VPS or
domain, add runner HTTP endpoints, integrate archive/run-all, integrate Active
into `tools/runner/main.py`, switch the backend to a real executor, invoke a
backend subprocess, relax the default feature flag, or relax target policy.

## Objective

Validate that the accepted no-live `active_nmap_basic` path still exercises the
backend contract, owner-scoped job lifecycle, redacted reporting/export, Raw
JSON handling, frontend controlled states, and no-live safety metadata without
creating unauthorized traffic.

This smoke does not prove any target is vulnerable, exploitable, safe, secure,
fully scanned, or completely covered. Mocked completed states remain observed
TCP exposure / review indicators that require manual validation.

## Smoke Type

Type: Option A no-live smoke with fake/mocked adapter results.

The smoke used existing backend tests, active-runner tests with fake runners,
and frontend mocked API tests. It did not use a real local target and did not
construct or run a real Nmap command from the backend.

## Commands Executed

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m py_compile backend/app/main.py backend/app/services.py backend/app/active_nmap_policy.py backend/app/active_nmap_handoff.py tools/active_runner/contracts.py tools/active_runner/nmap_basic/__init__.py tools/active_runner/nmap_basic/command_builder.py tools/active_runner/nmap_basic/executor.py tools/active_runner/nmap_basic/parser.py tools/active_runner/nmap_basic/target_policy.py tools/active_runner/nmap_basic/service.py tools/active_runner/nmap_basic/result.py
.venv/bin/python -m pytest backend/tests/test_active_nmap_policy.py backend/tests/test_backend.py -k active_nmap_basic
.venv/bin/python -m pytest backend/tests/test_backend.py
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_service.py tools/tests/test_active_runner_nmap_basic_executor.py tools/tests/test_active_runner_nmap_basic_parser.py
npm run test -- --run ActiveNmapBasicPanel ActiveNmapBasicJobReport App dashboardFilters reportHelpers
npm run test -- --run
npm run build
rg -n "active_nmap_basic|Nmap|nmap|smoke|not_executed|nmap_missing|Observed TCP exposure|Review indicator" frontend backend tools docs README.md
rg -n "shell=True|os.system|popen|Popen\(|subprocess|run\(|nmap " tools/active_runner backend frontend
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges" frontend backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

## Results

- Initial `git status --short`: clean.
- Initial `git status --branch --short`: `main...origin/main [ahead 19]`.
- `git diff --check`: pass.
- `git diff --cached --check`: pass.
- `py_compile` for relevant backend and active-runner files: pass.
- Focused backend `active_nmap_basic` tests: 108 passed, 346 deselected.
- Full backend suite: 370 passed.
- Focused active-runner Nmap basic tests: 76 passed.
- Focused frontend Nmap basic/App/filter/report tests: 5 files passed, 102
  tests passed.
- Full frontend suite: 20 files passed, 144 tests passed.
- Frontend build: pass. Vite reported the existing chunk-size warning after a
  successful build.

## Job Lifecycle Evidence

Backend smoke coverage confirms:

- feature-disabled `POST /active/network/nmap-basic` rejects without creating a
  job;
- feature-enabled test configuration accepts only the exact bounded contract;
- valid requests create owner-scoped `active_nmap_basic` jobs;
- created jobs are target-based with `file_id: null`;
- default no-live adapter results are controlled `not_executed` results;
- test-double metadata records `execution_attempted: false`,
  `nmap_executed: false`, `subprocess_invoked: false`,
  `network_requests_sent: 0`, and `dns_queries_sent: 0`;
- mocked adapter states cover `completed`, `failed`, `timed_out`,
  `nmap_missing`, `malformed`, `truncated`, `no_ports`, and `not_executed`;
- wrong-owner reads and exports remain blocked with generic not-found behavior;
- archive audit paths cannot create `active_nmap_basic` jobs.

## Reporting, Export, And Redaction Evidence

Backend report/export smoke coverage confirms:

- job detail remains redacted;
- job list summaries remain redacted;
- Markdown export remains redacted;
- HTML export remains redacted;
- XML export remains redacted;
- PDF export remains redacted;
- Raw JSON remains redacted;
- raw targets, raw commands, raw XML, stdout, stderr, service/banner values,
  headers, cookies, tokens, credentials, and malformed nested sensitive values
  are not exposed in user-visible report surfaces;
- report language remains observed exposure / review indicator wording, not
  confirmed vulnerability or exploitability wording.

## Frontend Evidence

Frontend smoke coverage confirms:

- the `Active / Nmap basic` panel keeps submit behavior controlled by the
  existing mocked API flow;
- disabled and unavailable backend states render as controlled states;
- `not_executed` does not appear as a completed live scan;
- mocked completed observations render as `Observed TCP exposure / Review
  indicator` with manual validation required;
- frontend Raw JSON applies `active_nmap_basic` redaction to raw targets,
  commands, XML, stdout/stderr, headers, cookies, tokens, credentials, and
  malformed nested sensitive values.

## No-Go Checks

The source searches were reviewed.

Expected hits:

- `tools/active_runner/nmap_basic/executor.py` contains the isolated runner-side
  controlled subprocess wrapper and uses `subprocess.run` with an argv list.
  These tests inject fake runners and do not require Nmap installed.
- Backend tests and frontend tests include raw Nmap-looking strings only as
  redaction fixtures.
- Documentation and tests contain forbidden wording as no-scope guardrails or
  assertions that the wording is not rendered.

No-go conditions were not observed:

- no backend import of `subprocess` for `active_nmap_basic`;
- no backend direct call to the real active-runner executor;
- no `shell=True`, `os.system`, or shell-string execution path in the
  `active_nmap_basic` backend path;
- no runner HTTP endpoint;
- no archive/run-all integration;
- no `active_nmap_basic` or `nmap_basic` integration in `tools/runner/main.py`;
- no raw flags, custom scripts, NSE, brute force, credential validation,
  crawling, DNS expansion, broad ranges, or public scanner behavior accepted by
  the smoke path.

## No-Live Confirmation

During this smoke:

- Nmap was not executed.
- Docker was not executed.
- No probes were run.
- No DNS checks were run.
- No external HTTP traffic was sent.
- No real external target was used.
- No VPS or domain was used.
- No `.env`, `.env.*`, or `.envrc` files were read, opened, or printed.
- No migrations, tags, or releases were created.

## Still Blocked

The following remain blocked:

- real Nmap execution;
- Docker/Nmap packaging;
- backend subprocess invocation;
- backend direct calls to the real active-runner executor;
- runner HTTP endpoints;
- archive/run-all integration;
- integration with `tools/runner/main.py`;
- local authorized real Nmap smoke;
- VPS/domain smoke;
- raw flags;
- scripts or NSE;
- stealth or evasion;
- brute force;
- exploit scripts;
- credential validation;
- crawling;
- DNS expansion;
- broad ranges;
- target-policy relaxation;
- feature-flag default relaxation;
- public scanner behavior;
- confirmed-vulnerability, exploitability, target-safety, full-scan, or
  all-ports-found claims.

## Recommended Next Microphase

Recommended next step:

```text
ACTIVE-NMAP-BASIC-17-REAL-LOCAL-SMOKE-TARGET-FREEZE
```

That step should remain docs-first/readiness-gated unless explicitly rescoped.
It should freeze an exact loopback or local controlled target, exact bounded
ports, exact timeout/output limits, cleanup expectations, and no-go criteria
before any real local Nmap execution is considered.

## Final Decision

```text
ACTIVE_NMAP_BASIC_16_NO_LIVE_SMOKE_EXECUTION_PASSED
```

The first `active_nmap_basic` smoke passed using only no-live fake/mocked
adapter validation. It validates the accepted backend, runner-test, reporting,
export, Raw JSON, and frontend controlled-state coverage without unauthorized
traffic or real Nmap execution.
