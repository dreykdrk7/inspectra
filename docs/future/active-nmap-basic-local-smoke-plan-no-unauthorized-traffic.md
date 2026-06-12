# Active Nmap Basic Local Smoke Plan, No Unauthorized Traffic

Decision:

```text
ACTIVE_NMAP_BASIC_15_LOCAL_SMOKE_PLAN_NO_UNAUTHORIZED_TRAFFIC_ACCEPTED
```

This is a docs-only and planning-only checkpoint for the first controlled local
smoke of `active_nmap_basic`. It does not run Nmap, run Docker, execute probes,
perform DNS checks, make external HTTP requests, change backend/frontend/runner
runtime, create migrations, create tags, create releases, or approve a real
live scan.

## Objective

Plan the first smoke method that can prove the `active_nmap_basic` contract,
job lifecycle, reporting, redaction, and frontend rendering remain bounded
without creating unauthorized traffic. The smoke must verify safe behavior
before any broader live path is considered.

The objective is not to prove that a target is vulnerable, exploitable, safe,
secure, fully scanned, or completely covered. Any later result must be worded
only as observed exposure or a review indicator that requires manual validation.

## Current Approved State

- The backend executor interface is accepted only in mocked/no-live form.
- The default backend adapter still returns controlled `not_executed` results.
- Tests may inject synthetic executor/parser states for `completed`, `failed`,
  `timed_out`, `nmap_missing`, `malformed`, `truncated`, and `no_ports`.
- Real Nmap execution remains blocked.
- Docker and Nmap packaging remain blocked.
- Runner HTTP endpoints remain blocked.
- Archive/run-all integration remains blocked.
- Integration with `tools/runner/main.py` remains blocked.
- Local authorized Nmap smoke is not approved by the current runtime state.

## Smoke Options

### Option A: No-Live Smoke With Fake Or Mocked Adapter

Option A uses the existing no-live backend adapter and injected fake/mocked
executor results. It exercises request validation, owner-scoped job creation,
structured result storage, report/export rendering, Raw JSON redaction, and
frontend controlled states without invoking Nmap, subprocesses, DNS, probes,
external HTTP traffic, or Docker.

This is the recommended first smoke because it matches the currently accepted
backend executor-interface state and creates no target-side network activity.

### Option B: Real Local Authorized Smoke Against Loopback Or Local Lab

Option B would run real Nmap only in a later separately approved execution
phase, and only against a predeclared local controlled target such as loopback
or a local service owned by the operator. The target must be numeric loopback
or another explicitly documented local/private/self-hosted address that does
not require DNS expansion or third-party routing.

Option B is acceptable only after the exact target-control method, exact port
set, exact timeout limits, cleanup steps, and evidence expectations are frozen
in a later execution record. If the local lab depends on containers, Docker
must be approved in that later phase; it is not approved here.

### Option C: Real Smoke Against Own VPS Or Domain

Option C is not recommended for the first smoke and remains blocked. Even when
the operator owns the VPS or domain, it can introduce internet routing, public
DNS, provider logs, external perimeter effects, and ambiguity about what was
authorized. It must not be used until after successful no-live and local-target
smoke evidence, and only if a later phase explicitly scopes and approves it.

## Recommendation

Use Option A first. It is the only smoke path accepted by this planning
checkpoint.

Use Option B only in a future execution phase if a loopback or local controlled
service is named before the run and all limits are fixed in writing.

Keep Option C blocked for later. It is not part of the first smoke path.

## Target-Control Method

For Option A, targets are synthetic values inside tests or mocked payloads.
They must not be resolved, contacted, expanded, logged raw in reports, or used
to build a command that is executed.

For any later Option B, target control must follow all of these rules:

- use only loopback or a controlled local/private/self-hosted target;
- prefer numeric loopback such as `127.0.0.1` or `::1` when possible;
- name exactly one target unless a later phase explicitly justifies a small
  bounded count;
- name exact TCP ports only;
- use no public domains, third-party hosts, or external SaaS services;
- use no CIDR, dash ranges, wildcard targets, target files, pasted host lists,
  or DNS expansion;
- perform no root-domain discovery, subdomain generation, reverse DNS, crawler
  discovery, or target fanout.

## Feature Flags

`INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=true` may be used only for an explicit
future smoke session. It must be scoped to that session, test process, or
documented local configuration and disabled immediately after the smoke.

The default remains disabled. The smoke must not leave accidental persistent
enablement behind, and the cleanup record should confirm the feature flag is
back to its default disabled posture.

## Future Commands And Limits

The first approved smoke commands are no-live validations only. A future phase
may run a focused set like:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap_basic"
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_service.py tools/tests/test_active_runner_nmap_basic_executor.py tools/tests/test_active_runner_nmap_basic_parser.py
npm run test -- --run ActiveNmapBasicJobReport App dashboardFilters reportHelpers
rg -n "active_nmap_basic|Nmap|nmap|smoke|unauthorized traffic|loopback|local" docs README.md backend frontend tools
rg -n "subprocess|shell=True|os.system|popen|nmap " backend tools frontend
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges" docs README.md backend frontend tools
```

This document does not approve an exact real-Nmap command because no real local
target has been frozen. A later Option B execution record must replace this
planning gap with an exact loopback/local target, exact ports, exact timeouts,
and an allowlisted argv-only command. That future command must keep all of
these limits:

- bounded target count;
- bounded numeric TCP port list;
- bounded timeout;
- bounded stdout/stderr/XML handling;
- no raw flags;
- no NSE or `--script`;
- no stealth, evasion, UDP, OS detection, service/version detection, brute
  force, exploit scripts, credential validation, crawling, DNS expansion, or
  shell execution.

## Expected Evidence

A successful first smoke should show:

- an owner-scoped `active_nmap_basic` job where applicable;
- `file_id: null`;
- bounded target and port metadata;
- no raw target, raw command, raw XML, stdout, stderr, service banner, header,
  cookie, token, or credential leakage in API payloads, reports, exports, or
  Raw JSON;
- backend `not_executed` or synthetic mocked states clearly separated from real
  Nmap execution;
- frontend rendering that treats results as controlled states or observed
  exposure / review indicators;
- no vulnerability, exploitability, target-safety, complete-coverage, or
  all-ports-discovered claims.

## No-Go Criteria

Stop the future smoke and do not accept it if any of these occur:

- unexpected external traffic;
- any external DNS lookup;
- any non-local, third-party, public-domain, or unauthorized target;
- CIDR, broad range, wildcard, target-file, pasted-list, or generated target
  expansion;
- raw flags, custom scripts, NSE, `--script`, stealth, evasion, UDP, OS/service
  detection, brute force, exploit, credential validation, or crawling behavior;
- `shell=True`, `os.system`, `popen`, or shell-string command execution;
- archive/run-all triggers;
- raw target/command/XML/stdout/stderr leakage in user-visible evidence;
- wording that implies confirmed vulnerability, exploitability, target safety,
  full network scan, all ports found, or production/public readiness.

## Cleanup And Rollback

After any future smoke:

- disable `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED`;
- delete synthetic jobs or fixtures created only for the smoke if the phase
  records them as disposable;
- preserve any intentionally retained redacted evidence only in the agreed docs
  or test artifacts;
- note that target-side logs, local service logs, provider logs, browser copies,
  downloaded exports, backups, and snapshots are outside Inspectra cleanup.

If a no-go criterion is hit, close the smoke as failed, keep the feature flag
disabled, and fix defects in separate commits before trying again.

## Future Smoke Validations

A later execution phase should run only the smallest relevant no-live or
local-target subset. It should include:

- git status and whitespace checks;
- focused backend `active_nmap_basic` tests;
- focused active-runner Nmap basic command-builder, service, executor, and
  parser tests that do not require Nmap unless the phase explicitly approves
  real local execution;
- focused frontend `ActiveNmapBasicJobReport`, dashboard filter, report helper,
  and form tests;
- source searches for Nmap, subprocess, shell execution, raw flags, forbidden
  claims, broad scanning language, archive/run-all integration, and passive
  runner integration;
- smoke evidence that states whether the run was Option A no-live or Option B
  real local authorized.

## Acceptance Criteria

- The first smoke path is Option A no-live with fake/mocked adapter results.
- Option B remains a later separately approved phase unless an exact local
  controlled target is frozen before execution.
- Option C remains blocked for the first smoke.
- No Docker, Nmap, probes, DNS checks, external HTTP traffic, runtime changes,
  migrations, tags, or releases are introduced by this planning checkpoint.
- Feature-flag enablement remains explicit, temporary, and disabled by default.
- Evidence expectations remain bounded, owner-scoped, redacted, and worded as
  observed exposure or review indicators.

## Final Decision

```text
ACTIVE_NMAP_BASIC_15_LOCAL_SMOKE_PLAN_NO_UNAUTHORIZED_TRAFFIC_ACCEPTED
```

The first `active_nmap_basic` local smoke is planned as a no-live mocked smoke.
Real local authorized Nmap smoke remains blocked until a later execution phase
freezes the exact loopback/local target-control method and limits. VPS/domain
smoke remains blocked for the first smoke.
