# Active Nmap Basic Pre-Execution Review

Date: 2026-06-12

Decision: `ACTIVE_NMAP_BASIC_04A_PRE_EXECUTION_REVIEW_PASSED`

This review covers the accepted `active_nmap_basic` work before any real Nmap
execution, subprocess control, parser, frontend, Docker change, migration, tag,
or release is allowed. It is read-only / docs-only except for this review record
and the implementation-plan status update.

## State Reviewed

Accepted decisions reviewed:

- `ACTIVE_NMAP_BASIC_01_BACKEND_CONTRACT_GATE_ACCEPTED`
- `ACTIVE_NMAP_BASIC_02_TARGET_POLICY_ACCEPTED`
- `ACTIVE_NMAP_BASIC_03_COMMAND_BUILDER_ACCEPTED`
- `ACTIVE_NMAP_BASIC_04_RUNNER_SKELETON_ACCEPTED`

Commits covered:

- `2c263b5 feat(active): add nmap basic backend contract gate`
- `dc4066e feat(active): add nmap basic target policy`
- `2315eda feat(active): add nmap basic allowlisted command builder`
- `fbe6d5d feat(active): add nmap basic runner skeleton`

Files reviewed:

- `backend/app/config.py`
- `backend/app/main.py`
- `backend/app/active_nmap_policy.py`
- `backend/tests/test_active_nmap_policy.py`
- `backend/tests/test_backend.py`
- `tools/active_runner/__init__.py`
- `tools/active_runner/contracts.py`
- `tools/active_runner/nmap_basic/__init__.py`
- `tools/active_runner/nmap_basic/command_builder.py`
- `tools/active_runner/nmap_basic/service.py`
- `tools/tests/test_active_runner.py`
- `tools/tests/test_active_runner_nmap_basic_command_builder.py`
- `tools/tests/test_active_runner_nmap_basic_service.py`
- `docs/future/active-nmap-basic-design.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `docs/architecture.md`
- `docs/security-scope.md`
- `README.md`

`tools/runner/main.py` was searched for Active/Nmap integration references and
was not integrated with `active_nmap_basic`.

## Findings

No blocking findings were identified.

Architecture and modularity:

- Active Nmap Basic remains separate from the passive runner.
- `tools/runner/main.py` has not absorbed Active code.
- The new Active modules are small and focused: target policy, shared
  contracts, allowlisted command builder, and offline skeleton service.
- No parser, executor, complex redaction, HTTP API, and command-building logic
  are mixed into one module.
- No `tools/active_runner/main.py` dispatcher or runner endpoint was introduced.

Backend contract:

- `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED` is disabled by default.
- `POST /active/network/nmap-basic` rejects disabled environments without
  creating jobs.
- When explicitly enabled, the endpoint validates the exact
  `live_nmap_basic` / `tcp_connect_small` contract, required confirmations,
  target policy, bounded ports, and target-port limits.
- The enabled path returns controlled `not_implemented` / `not_executed`
  metadata and does not create a job.
- The backend contract gate does not call the active runner, passive runner, or
  any subprocess.
- In auth-required mode, anonymous requests fail before field-level validation
  details are exposed.

Target policy:

- The backend policy fails closed for CIDR notation, dash ranges, wildcards,
  URL-shaped values, paths, queries, fragments, userinfo, metadata/control-plane
  targets, special-purpose IP ranges, public-looking targets, pasted target
  lists, excessive target counts, overlong targets, and duplicates.
- The target policy does not perform DNS resolution, reverse DNS, hostname
  generation, IP generation, target expansion, or traffic.
- A test monkeypatches `socket.getaddrinfo` to fail if DNS resolution is
  attempted.

Command builder:

- The builder returns an argv list, never a shell string.
- The public builder signature accepts only `target`, `ports`, and `profile`.
- Raw flags, extra args, script fields, and shell fields are not accepted by the
  builder API.
- The generated argv is deterministic, uses the fixed `tcp_connect_small`
  profile, places the target after `--`, and keeps output to `-oX -`.
- Forbidden flags are listed and tested not to appear in generated argv.
- The builder does not look up an Nmap binary and does not execute anything.

Runner skeleton:

- The skeleton service returns only `status: not_executed`.
- It validates structured input and all three confirmations.
- It rejects raw flags, extra args, script fields, shell fields, command fields,
  target files, credentials, cookies, headers, tokens, and output-like fields.
- It calls the allowlisted builder only to prove argv construction, then
  discards the argv.
- It does not return raw command, argv, raw target, stdout, stderr, evidence, or
  vulnerability claims.
- It does not create jobs, communicate with the backend, expose a runner HTTP
  endpoint, parse Nmap output, or execute Nmap.

Tests:

- Backend tests cover disabled-by-default behavior, enabled-not-implemented
  behavior, required mode/profile/confirmations, unsupported fields,
  malformed targets/ports, target policy, no-job behavior, and auth-required
  anonymous denial before validation detail.
- Target policy tests cover accepted local/private/self-hosted targets, rejected
  broad/ambiguous/public/control-plane targets, duplicate normalization, target
  count, length limits, and no DNS resolution.
- Builder tests cover argv list shape, deterministic port normalization,
  unsupported profiles, invalid ports, ambiguous targets, target after `--`,
  forbidden flags, no raw/extra/script parameters, and no execution or passive
  runner integration in source.
- Service tests cover valid `not_executed` responses, invalid profile/mode,
  invalid targets/ports, missing/false confirmations, unsupported raw/script/
  shell/credential/header/token fields, builder invocation without returning
  argv or target, no stdout/stderr/evidence, no vulnerability wording, no raw
  argument parameters, and no execution/network/passive-runner terms in source.
- The tests do not require Nmap to be installed.
- The reviewed tests did not execute Docker, Nmap, DNS checks, probes, or
  external HTTP traffic.

## Residual Risks

- The backend and active-runner contract constants are currently duplicated in a
  few places. This is acceptable before execution, but Microphase 05 should
  avoid divergence when introducing an execution boundary.
- The runner skeleton intentionally does not yet enforce the full backend target
  policy. Because it cannot execute anything and has no endpoint, this is not a
  blocking issue for 04A. Before any subprocess is reachable, the execution path
  must enforce or faithfully mirror the same local/private/self-hosted target
  policy at the runner boundary.
- Future Nmap output may contain hostnames, addresses, command errors, version
  strings, and target data. Parser, truncation, redaction, storage, and reporting
  phases must treat that data as sensitive evidence, not as a confirmed
  vulnerability.
- `network_requests_sent` cannot be counted reliably for real Nmap behavior.
  Future runtime should avoid implying exact packet/request counts.

## Gaps Before Microphase 05

The following gaps are not blockers for this review, but must be addressed
before real execution is accepted:

- Add runner-side or shared target-policy enforcement before invoking any
  subprocess.
- Keep the execution API structured-only; do not add raw flags, raw command
  strings, custom scripts, credential fields, cookie/header/token fields, target
  files, or shell fields.
- Add a controlled executor with argv-only subprocess invocation, no shell,
  bounded timeout, kill/cleanup handling, bounded stdout/stderr, and controlled
  Nmap-missing errors.
- Add tests with fakes/mocks proving no real Nmap or network traffic is required
  for default test execution.
- Keep parser and report integration out of the first execution commit unless a
  separate microphase explicitly approves them.
- Keep archive/run-all, passive runner, frontend, migration, Docker, tag, and
  release work out of Microphase 05 unless separately scoped.

## Microphase 05 Decision

Microphase 05 may proceed only as a controlled implementation phase for bounded
subprocess execution. This review does not approve real Nmap use outside the
future guarded execution path, does not approve broad scanning, and does not
approve release-readiness.

Required preconditions before any real subprocess is introduced:

- Feature remains disabled by default.
- Explicit opt-in remains required.
- Authorization, local/private/self-hosted scope, and live-traffic confirmations
  remain required.
- Backend target policy remains fail-closed.
- Runner execution path enforces or mirrors target policy.
- Command builder remains allowlisted and argv-only.
- No shell execution is used.
- No raw user flags or custom scripts are accepted.
- No NSE, stealth, evasion, OS detection, service detection, UDP, brute force,
  exploit, credential validation, crawling, DNS expansion, target-file, or broad
  range behavior is introduced.
- Timeout, output, stderr, and storage limits are enforced before parsing or
  persistence.
- Nmap absence, timeout, nonzero exit, and truncated output return controlled
  non-sensitive errors.
- Tests use fakes/mocks by default and do not require Nmap installed.
- Reports continue to use observed exposure / review indicator wording, never
  confirmed vulnerability wording.

Decision: `ACTIVE_NMAP_BASIC_04A_PRE_EXECUTION_REVIEW_PASSED`

## Validation Record

Commands run:

- `git status --short`
- `git status --branch --short`
- `wc -l backend/app/config.py backend/app/main.py backend/app/active_nmap_policy.py tools/active_runner/contracts.py tools/active_runner/nmap_basic/command_builder.py tools/active_runner/nmap_basic/service.py tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_service.py backend/tests/test_active_nmap_policy.py`
- `py_compile` for active backend and active-runner modules
- `pytest tools/tests/test_active_runner_nmap_basic_command_builder.py`
- `pytest tools/tests/test_active_runner_nmap_basic_service.py`
- `pytest tools/tests/test_active_runner.py tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_service.py`
- `pytest backend/tests/test_active_nmap_policy.py backend/tests/test_backend.py -k active_nmap_basic`
- `pytest backend/tests/test_active_nmap_policy.py backend/tests/test_backend.py`
- `rg -n "active_nmap_basic|nmap|Nmap|active_runner|not_executed" ...`
- `rg -n "subprocess|shell=True|os.system|popen|Popen\(|run\(|nmap " tools/active_runner backend frontend`
- `rg -n "confirmed vulnerability|exploitable|target is safe|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags" backend tools frontend docs README.md`

Results:

- `py_compile`: passed.
- Builder tests: `18 passed`.
- Skeleton service tests: `32 passed`.
- Combined Active runner tests: `80 passed`.
- Focused backend Active Nmap tests: `47 passed, 346 deselected`.
- Full backend tests: `393 passed`.
- Execution-term search: expected hits only for existing dry-run function names,
  documentation/reporting no-scope wording, and tests that assert prohibited
  wording.
- No-scope wording search: expected hits only in no-scope documentation,
  forbidden-flag lists, and tests that assert prohibited wording is absent.

No `.env`, `.env.*`, or `.envrc` files were read. No Docker command, Nmap
command, DNS check, probe, external HTTP traffic, backend runner call, passive
runner integration, frontend change, migration, tag, or release was performed.
