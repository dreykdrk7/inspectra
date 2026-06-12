# Active Nmap Basic Real Local Smoke Execution

Decision:

```text
ACTIVE_NMAP_BASIC_18_REAL_LOCAL_SMOKE_EXECUTION_BLOCKED_NMAP_MISSING
```

This records the attempted first real local authorized `active_nmap_basic`
smoke. The phase was blocked during preflight because the local `nmap` binary
was not installed. No Nmap installation was attempted.

The frozen smoke scope remains:

- target: `127.0.0.1`;
- ports: `[65000]`;
- mode: `live_nmap_basic`;
- profile: `tcp_connect_small`;
- temporary feature flag only: `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=true`;
- allowlisted argv only;
- no raw flags, shell execution, DNS, domains, VPS, third parties, LAN targets,
  Docker, NSE, scripts, UDP, SYN scan, OS detection, service/version detection,
  brute force, credential validation, crawling, DNS expansion, or broad ranges.

## Objective

Attempt the first real local smoke only if the frozen target, frozen port,
local Nmap availability, and no-go criteria all pass preflight. Because Nmap
was missing, this document records a blocked result rather than a passed smoke.

No backend process was started for the real smoke, no request was submitted,
no job was created, and no exports were generated.

## Preflight

Commit under test:

```text
5dcd237 docs(active): freeze nmap basic real local smoke target
```

Preflight results:

- `git status --short`: clean.
- `git status --branch --short`: `main...origin/main [ahead 21]`.
- `command -v nmap`: exit code 1, no path returned.
- Nmap availability: not installed / unavailable in this environment.
- Block decision: do not install Nmap, do not use Docker, do not execute the
  real local smoke.

The frozen argv was rechecked with the existing allowlisted builder:

```text
['nmap', '-sT', '-Pn', '-n', '--max-retries', '1', '--host-timeout', '30s', '-oX', '-', '-p', '65000', '--', '127.0.0.1']
```

This matches the Microphase 17 target-freeze command shape. It was only built
as an argv value in Python and was not executed.

## Commands Executed

```text
git status --short
git status --branch --short
command -v nmap
PYTHONPATH=tools .venv/bin/python -c 'from active_runner.nmap_basic.command_builder import build_active_nmap_basic_argv; print(build_active_nmap_basic_argv(target="127.0.0.1", ports=[65000]))'
.venv/bin/python -m py_compile backend/app/main.py backend/app/services.py backend/app/active_nmap_policy.py backend/app/active_nmap_handoff.py tools/active_runner/contracts.py tools/active_runner/nmap_basic/__init__.py tools/active_runner/nmap_basic/command_builder.py tools/active_runner/nmap_basic/executor.py tools/active_runner/nmap_basic/parser.py tools/active_runner/nmap_basic/target_policy.py tools/active_runner/nmap_basic/service.py tools/active_runner/nmap_basic/result.py
.venv/bin/python -m pytest backend/tests/test_active_nmap_policy.py backend/tests/test_backend.py -k active_nmap_basic
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_service.py tools/tests/test_active_runner_nmap_basic_executor.py tools/tests/test_active_runner_nmap_basic_parser.py
npm run test -- --run ActiveNmapBasicPanel ActiveNmapBasicJobReport App dashboardFilters reportHelpers
```

No command was run that executed Nmap. No backend smoke server was started with
the feature flag because the preflight failed first.

## Validation Results

- `py_compile` for relevant backend and active-runner files: pass.
- Focused backend `active_nmap_basic` tests: 108 passed, 346 deselected.
- Focused active-runner Nmap basic tests: 76 passed.
- Focused frontend Nmap basic/App/filter/report tests: 5 files passed, 102
  tests passed.

These validations are no-live/fake-based. They do not replace the blocked real
local smoke.

## Job, Detail, Export, And Redaction Evidence

Because Nmap was missing, the execution stopped before backend launch:

- backend smoke command: not run;
- request to `POST /active/network/nmap-basic`: not sent;
- job id: none;
- final job state: none;
- `file_id: null`: not applicable because no job was created;
- target `127.0.0.1`: preserved as the frozen future target only;
- port `[65000]`: preserved as the frozen future port only;
- `nmap_executed: true`: not observed;
- `subprocess_invoked: true`: not observed;
- `dns_queries_sent: 0`: no DNS checks were run by this phase;
- exports: not generated;
- Raw JSON: not generated;
- UI review: not performed against a real smoke job.

Existing no-live tests continue to cover redaction for job detail, summaries,
Markdown, HTML, XML, PDF, Raw JSON, and frontend rendering using fake/mocked
payloads.

## No-Go Checks

No-go conditions were avoided because the phase stopped at missing Nmap:

- no DNS lookup;
- no target other than `127.0.0.1`;
- no port other than `65000`;
- no domain, hostname, VPS, LAN target, container target, or third party;
- no raw flags;
- no NSE or `--script`;
- no `shell=True`, `os.system`, `popen`, or shell-string execution;
- no archive/run-all trigger;
- no `tools/runner/main.py` integration;
- no confirmed vulnerability, exploitability, target-safety, full-scan, or
  all-ports-found claim.

Source searches were also run after documentation updates to confirm expected
guardrail hits only.

## Cleanup

Cleanup outcome:

- no backend smoke process was started;
- no feature flag persisted;
- no smoke job was created;
- no smoke job deletion was needed;
- no report/export artifacts were created;
- no Nmap installation was attempted;
- no Docker command was run.

## Still Blocked

The following remain blocked:

- real local Nmap smoke execution until Nmap is available and a later phase
  reruns the exact frozen smoke;
- installing Nmap in this phase;
- Docker/Nmap packaging;
- backend real-executor default wiring outside an explicitly approved smoke;
- backend subprocess invocation outside an explicitly approved smoke;
- runner HTTP endpoints;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- any target other than `127.0.0.1`;
- any port other than `65000`;
- `localhost`, `::1`, hostnames, LAN targets, domains, VPS, third-party targets,
  and container targets;
- raw flags, scripts, NSE, stealth/evasion, UDP, SYN scan, OS detection,
  service/version detection, brute force, exploit scripts, credential
  validation, crawling, DNS expansion, broad ranges, and public scanner
  behavior.

## Recommended Next Microphase

Recommended next step after Nmap is installed by the operator outside Inspectra
and outside this phase:

```text
ACTIVE-NMAP-BASIC-18-REAL-LOCAL-SMOKE-EXECUTION-RERUN
```

That rerun must use the same frozen target `127.0.0.1`, frozen port `[65000]`,
temporary feature flag, allowlisted argv, cleanup, and no-go criteria. It must
not install Nmap, use Docker, change targets, or widen scope.

## Final Decision

```text
ACTIVE_NMAP_BASIC_18_REAL_LOCAL_SMOKE_EXECUTION_BLOCKED_NMAP_MISSING
```

The first real local `active_nmap_basic` smoke did not execute because Nmap was
not installed. The bounded no-live checks passed, but the real local smoke
remains blocked.
