# Active Nmap Basic v0 Functional Closeout

Status: accepted

Decision: `ACTIVE_NMAP_BASIC_56_ACTIVE_NMAP_V0_FUNCTIONAL_CLOSEOUT_ACCEPTED`

This closeout declares Active / Nmap basic v0 functionally closed as a bounded
self-hosted/local/private capability. It does not create a release, tag, push,
new runtime feature, new target approval, or broader Active scope.

## Context

Relevant final commits:

- `212399f feat(active): wire real nmap through active tools`
- `792cda1 fix(active): harden real nmap minimal integration`

Microphase 54 connected the real-minimal path:

- frontend bounded submit contract;
- backend request contract, target policy, lifecycle, storage, and reporting;
- internal backend-to-active-tools client;
- bounded Nmap execution inside `active-tools` only;
- redacted owner-scoped `active_nmap_basic` job persistence.

Microphase 55 reviewed the integration boundary, found a real
`INSPECTRA_ACTIVE_TOOLS_URL` boundary issue, fixed it, and hardened TCP
observation state/reason allowlists across active-tools, backend boundary, and
lifecycle normalization. The review left no blockers.

## Approved State

Active / Nmap basic v0 is approved only as a functional minimum with these
properties:

- disabled by default through `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=false`;
- explicit operator opt-in for the backend route;
- explicit `active-tools` opt-in for real Nmap execution through
  `INSPECTRA_ACTIVE_TOOLS_NMAP_BASIC_EXECUTION_ENABLED=true`;
- self-hosted/local/private use only;
- explicitly authorized targets only;
- frontend submits only the bounded `live_nmap_basic` /
  `tcp_connect_small` contract with required confirmations;
- backend remains the authority for auth, owner scope, request validation,
  target policy, lifecycle, storage, reporting, and redaction;
- backend calls only a configured internal/local `active-tools` URL accepted by
  fail-closed URL validation;
- backend does not execute Nmap, import or call subprocess, use Docker SDK, or
  access the Docker socket;
- Nmap execution occurs only inside `active-tools`;
- active-tools uses allowlisted command construction with `shell=False`;
- jobs are owner-scoped target-based records with `file_id: null`;
- target display is stored and returned as `[REDACTED_TARGET]`;
- reporting, exports, Raw JSON, and frontend rendering are redaction-first;
- no raw target, raw payload, command/argv, stdout/stderr, XML, PTR/resolved
  IP, banners, versions, service details, credentials, headers, cookies, or
  tokens are public result data;
- observations are minimal TCP observations only;
- observations are worded as observed TCP exposure / review indicators;
- manual validation is always required;
- no vulnerability, exploitability, target-safety, or full-coverage claim is
  made.

## Not Approved

This closeout does not approve:

- public scanner behavior;
- SaaS scanner behavior;
- arbitrary public targets;
- LAN, VPS, or domain targets that have not been separately frozen and smoked;
- port `80`;
- broad ranges;
- CIDR targets;
- wildcards;
- target files;
- top-ports scans;
- `-p-`;
- raw flags;
- NSE or scripts;
- service/version detection;
- OS detection;
- UDP scans;
- SYN scans;
- brute force;
- exploit scripts;
- credential validation;
- crawling;
- DNS expansion;
- subdomain discovery;
- backend subprocess execution;
- Docker SDK or Docker socket use by backend;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- claims such as confirmed vulnerability, exploitable, target is safe, full
  scan, all ports found, or scan completed.

## Technical Boundaries

Backend:

- route: `POST /active/network/nmap-basic`;
- feature gate: `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED`;
- active-tools URL: default-empty, internal/local only, no credentials, no path,
  no query, no fragment;
- owner scope: current owner, wrong-owner generic behavior preserved;
- storage: `active_nmap_basic`, `file_id: null`, `[REDACTED_TARGET]`;
- errors: controlled and non-leaking.

Active-tools:

- default is no-live;
- real execution requires explicit active-tools execution flag;
- Nmap argv is built from allowlisted structured inputs;
- command runs with `shell=False`;
- output, process time, parser input, parser observations, response, and storage
  are bounded;
- public response omits raw command/output/XML/target and service details.

Frontend:

- submits only the fixed bounded contract;
- renders no-live and real-minimal states separately;
- treats `completed_real_minimal` as bounded observations, not broad scan
  completion;
- displays observations as review indicators;
- keeps Raw JSON redacted.

Compose:

- `docker-compose.active-tools.example.yml` remains optional;
- `active-tools` is behind profile `active`;
- no public host ports by default;
- internal network only;
- no host networking;
- no privileged mode;
- no Docker socket mount;
- read-only filesystem, tmpfs `/tmp`, dropped capabilities, and
  `no-new-privileges`.

## Validation Evidence

Final validation run for this closeout passed:

- `git status --short --branch`: branch was clean before docs-only closeout
  edits, ahead of origin with accumulated local commits.
- `.venv/bin/pytest -q backend/tests/test_backend.py -k "active_nmap_basic or active_tools"`:
  passed.
- `.venv/bin/pytest -q backend/tests`: passed.
- `.venv/bin/pytest -q tools/tests/test_active_tools_asgi_service_skeleton.py tools/tests/test_active_tools_internal_service_skeleton.py tools/tests/test_active_tools_health_readiness.py tools/tests/test_active_tools_fake_execution_boundary.py tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_executor.py tools/tests/test_active_runner_nmap_basic_parser.py tools/tests/test_active_runner_nmap_basic_parser_redaction.py tools/tests/test_active_runner_nmap_basic_service.py`:
  passed.
- `npm test -- --run ActiveNmapBasicPanel ActiveNmapBasicJobReport App`:
  passed.
- `npm test -- --run`: passed.
- `npm run build`: passed.
- `COMPOSE_DISABLE_ENV_FILE=1 docker compose -f docker-compose.active-tools.example.yml --profile active config --no-interpolate`:
  passed static Compose config validation.
- `git diff --check`: passed.
- `git diff --cached --check`: passed.
- Guardrail searches for backend subprocess/Nmap/Docker SDK, active-tools raw
  flags/NSE/scripts, archive/run-all, `tools/runner/main.py`, raw leakage, and
  prohibited wording found only denylist/redaction code, negative tests, or
  docs no-scope wording.

No Nmap execution, Docker runtime smoke, Compose up, target smoke, DNS checks,
probes, or external HTTP traffic were run in this closeout phase.

## Roadmap

Recommended next steps:

- push accumulated commits when the operator decides;
- keep Active Nmap v0 as a bounded self-hosted/local/private capability;
- do not add archive/run-all yet;
- do not broaden target classes without a separate target-freeze and smoke
  phase;
- consider operational polish, docs, install/run guidance, or a separate Active
  tool only after this closeout is accepted;
- keep future target expansion, output expansion, and UI expansion behind
  separate microphases with explicit no-scope and guardrail tests.

## Acceptance

Active / Nmap basic v0 is functionally closed as a minimum bounded capability.
The accepted path is self-hosted/local/private, opt-in, owner-scoped,
redaction-first, and report wording remains limited to observed TCP exposure /
review indicators requiring manual validation.

Decision: `ACTIVE_NMAP_BASIC_56_ACTIVE_NMAP_V0_FUNCTIONAL_CLOSEOUT_ACCEPTED`
