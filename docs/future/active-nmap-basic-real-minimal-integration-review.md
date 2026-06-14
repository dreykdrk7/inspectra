# Active Nmap Basic Real Minimal Integration Review

Status: accepted after hardening

Decision: `ACTIVE_NMAP_BASIC_55_REAL_MINIMAL_INTEGRATION_REVIEW_PASSED`

Reviewed commit: `212399f feat(active): wire real nmap through active tools`

Commit footprint reviewed:

- 23 files changed.
- 1643 insertions and 98 deletions.
- Backend, active-tools, frontend, tests, README, architecture, security scope, and future docs were included in the review.

## Review Scope

Reviewed files from the real minimal integration commit:

- `README.md`
- `backend/app/active_nmap_boundary.py`
- `backend/app/active_nmap_lifecycle.py`
- `backend/app/active_tools_client.py`
- `backend/app/main.py`
- `backend/app/reporting.py`
- `backend/app/storage.py`
- `backend/tests/test_backend.py`
- `docs/architecture.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `docs/future/active-nmap-basic-real-minimal-integration.md`
- `docs/security-scope.md`
- `frontend/src/ActiveNmapBasicPanel.test.tsx`
- `frontend/src/ActiveNmapBasicPanel.tsx`
- `frontend/src/App.test.tsx`
- `tools/active_runner/app.py`
- `tools/active_runner/nmap_basic/parser.py`
- `tools/active_runner/service.py`
- `tools/tests/test_active_runner_nmap_basic_parser.py`
- `tools/tests/test_active_tools_asgi_service_skeleton.py`
- `tools/tests/test_active_tools_fake_execution_boundary.py`
- `tools/tests/test_active_tools_health_readiness.py`
- `tools/tests/test_active_tools_internal_service_skeleton.py`

Additional review surface:

- `docker-compose.active-tools.example.yml`
- `frontend/src/ActiveNmapBasicJobReport.tsx`
- `frontend/src/activeNmapBasicReport.ts`

## Finding Fixed

The review found one boundary issue in `backend/app/active_tools_client.py`: configured `INSPECTRA_ACTIVE_TOOLS_URL` values were normalized but not constrained to an internal/local active-tools host shape before the backend client attempted HTTP. That left too much room for accidental external active-tools destinations even though target policy and response validation remained bounded.

Fix applied in this microphase:

- `active-tools` base URLs now fail closed unless they use `http` or `https`, contain no credentials, path, query, params, or fragment, and point to `active-tools`, `localhost`, a loopback/private IP, or an internal/local service-style hostname.
- Invalid active-tools URLs return controlled `active_tools_unconfigured` states.
- Tests confirm no HTTP request is sent for external, path-bearing, or credential-bearing active-tools URLs.

The review also hardened observation values:

- Backend boundary, backend lifecycle, and active-tools fake/real response normalization now allow only the bounded TCP state and reason vocabulary already recognized by the parser.
- Unallowlisted state/reason values are treated as malformed or unsafe controlled results, not successful real-minimal observations.

## Backend Review

Passed with the hardening above:

- Backend does not import or execute `subprocess` for Active Nmap.
- Backend does not execute Nmap, call `nmap --version`, use the Docker SDK, or access the Docker socket.
- Backend calls only the configured internal `active-tools` HTTP client path under feature flag, request contract, target policy, confirmation, lifecycle, and response-boundary checks.
- `POST /active/network/nmap-basic` keeps owner scope, `file_id: null`, target redaction, controlled errors, and generic wrong-owner behavior.
- Active-tools client timeouts and response/status/JSON errors normalize into controlled non-leaking states.

## Active-Tools Review

Passed:

- Real Nmap execution is isolated to `tools/active_runner/nmap_basic/executor.py`.
- Execution is gated by `INSPECTRA_ACTIVE_TOOLS_NMAP_BASIC_EXECUTION_ENABLED=true`; default remains no-live.
- Command construction is allowlisted for `tcp_connect_small`, uses `shell=False`, and does not accept raw flags or shell strings.
- NSE/scripts, service/version detection, OS detection, UDP/SYN scans, stealth/evasion, brute force, credential validation, crawling, target files, and broad ranges remain blocked.
- Parser output is bounded and reduced to minimal TCP observations.
- Public active-tools responses do not return raw target, command/argv, stdout/stderr, raw XML, PTR/resolved IP, banner, version, service details, credentials, headers, cookies, or tokens.

## Storage And Reports

Passed:

- Persisted `active_nmap_basic` jobs remain owner-scoped and `file_id: null`.
- Stored target display is `[REDACTED_TARGET]`.
- Storage/reporting surfaces keep raw target, raw payload, command/argv, stdout/stderr, XML, PTR/resolved IP, banner, version, service details, credentials, headers, cookies, and tokens out of public output.
- Real-minimal observations are displayed only as observed TCP exposure / review indicators.
- Manual validation remains required.
- No "confirmed vulnerability", exploitability, target-safety, full-coverage, or public-scanner claim is introduced.

## Frontend Review

Passed:

- The Active / Nmap basic panel submits the bounded contract only.
- UI copy separates no-live lifecycle records from real-minimal bounded observations.
- `completed_real_minimal` is treated as a bounded observation record, not a broad scan result.
- Raw JSON is redacted defensively.
- Raw target, command, XML, stdout/stderr, service/banner fields, headers, cookies, tokens, credentials, and legacy unsafe claims are hidden or redacted.
- No frontend archive/run-all integration was added.

## Docker And Compose Review

Passed:

- `docker-compose.active-tools.example.yml` keeps `active-tools` behind profile `active`.
- No host ports are published by default.
- The network is internal.
- No host networking, privileged mode, or Docker socket mount is present.
- The service keeps read-only filesystem, tmpfs `/tmp`, dropped capabilities, `no-new-privileges`, PID limit, and memory limit.

## Validation Evidence

Commands run:

- `git status --short --branch`: initial branch was clean and ahead of origin before review fixes.
- `git show --stat --oneline 212399f`: confirmed 23 files, +1643/-98.
- `git show --name-only --oneline 212399f`: confirmed the reviewed file list.
- `python3 -m py_compile backend/app/active_tools_client.py backend/app/active_nmap_lifecycle.py backend/app/main.py backend/app/active_nmap_boundary.py tools/active_runner/app.py tools/active_runner/service.py tools/active_runner/nmap_basic/parser.py tools/active_runner/nmap_basic/executor.py tools/active_runner/nmap_basic/command_builder.py`: passed.
- `.venv/bin/pytest -q backend/tests/test_backend.py -k "active_tools_health_client or active_tools_nmap_basic_client or active_nmap_basic_boundary or active_nmap_basic_lifecycle_skeleton or active_nmap_basic_enabled_route"`: passed, 48 tests.
- `.venv/bin/pytest -q backend/tests`: passed.
- `.venv/bin/pytest -q tools/tests/test_active_tools_asgi_service_skeleton.py tools/tests/test_active_tools_internal_service_skeleton.py tools/tests/test_active_tools_health_readiness.py tools/tests/test_active_tools_fake_execution_boundary.py tools/tests/test_active_runner_nmap_basic_command_builder.py tools/tests/test_active_runner_nmap_basic_executor.py tools/tests/test_active_runner_nmap_basic_parser.py tools/tests/test_active_runner_nmap_basic_parser_redaction.py tools/tests/test_active_runner_nmap_basic_service.py`: passed.
- `npm test -- --run ActiveNmapBasicPanel ActiveNmapBasicJobReport App`: passed, 57 tests.
- `npm test -- --run`: passed, 147 tests.
- `npm run build`: passed.
- `env COMPOSE_DISABLE_ENV_FILE=1 docker compose -f docker-compose.active-tools.example.yml --profile active config --no-interpolate`: passed static Compose config validation without reading a Compose `.env` file.

Guardrail searches confirmed:

- No backend Active Nmap subprocess/Nmap/Docker SDK execution path.
- Active-tools subprocess use is limited to the controlled executor and `subprocess.run(..., shell=False)`.
- Raw flags, NSE/script options, service/version detection, OS detection, UDP/SYN scanning, brute force, credential validation, crawling, archive/run-all, `tools/runner/main.py`, raw XML/stdout/stderr/command/target leakage, and prohibited wording appear only as denylist/redaction/test/documentation guardrails, not as enabled product behavior.

## Residual Boundaries

- This review did not repeat public, LAN, VPS, domain, or port-80 target execution.
- No release, tag, push, archive/run-all, or `tools/runner/main.py` integration was performed.
- Any future active-tools hostname pattern beyond the accepted internal/local forms requires a separate review and tests.

## Acceptance

The real-minimal integration is accepted after hardening. Nmap execution remains isolated to `active-tools`, backend remains a policy/lifecycle/storage/reporting authority without subprocess execution, storage and UI remain redaction-first, and no public scanner scope is introduced.

Decision: `ACTIVE_NMAP_BASIC_55_REAL_MINIMAL_INTEGRATION_REVIEW_PASSED`
