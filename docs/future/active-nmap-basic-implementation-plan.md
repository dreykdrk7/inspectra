# Active Nmap Basic Implementation Plan

Status: `ACTIVE_NMAP_BASIC_IMPLEMENTATION_PLAN_FROZEN`

This document freezes a docs-only implementation plan for the possible future
`active_nmap_basic` capability designed in
`docs/future/active-nmap-basic-design.md`.

This phase does not implement backend runtime, frontend runtime, runner
behavior, Docker changes, migrations, tags, releases, endpoints, probes, DNS
checks, external HTTP checks, Nmap execution, or functional behavior. It does
not read or print `.env`, `.env.*`, or `.envrc` contents.

## Source Decision

The prior design closed with:

```text
ACTIVE_NMAP_BASIC_DESIGN_FROZEN
```

Reference commit:

```text
f5d489b docs(active): design bounded nmap basic capability
```

The design accepts only a future bounded, defensive, local/private/self-hosted
`active_nmap_basic` shape. It requires explicit opt-in, explicit target
authorization, small target and port bounds, allowlisted command construction,
no shell execution, bounded timeouts/output/storage, layered redaction, and
report wording as observed exposure or review indicators.

## Planning Scope

This planning phase allows only:

- this implementation plan document;
- optional references from `README.md`, `docs/architecture.md`, and
  `docs/security-scope.md`;
- docs-only validation commands;
- one final docs commit.

This planning phase does not:

- add `POST /active/network/nmap-basic`;
- add request handlers;
- add feature-flag runtime;
- add validators;
- add command-builder code;
- add runner endpoints;
- add Nmap installation or execution;
- add parser code;
- add reports;
- add frontend UI;
- add tests;
- add migrations;
- run Docker;
- run Nmap;
- run probes;
- run DNS checks;
- run external HTTP checks;
- create tags or releases.

## Non-Negotiable Guardrails

Every future implementation microphase must preserve:

- disabled by default;
- explicit opt-in;
- local/private/self-hosted use only;
- explicitly authorized targets only;
- no arbitrary internet scanning;
- no broad ranges;
- no CIDR or IP range expansion;
- no stealth or evasion;
- no NSE scripts;
- no aggressive Nmap mode;
- no brute force;
- no exploit scripts;
- no credential validation;
- no crawling;
- no DNS expansion;
- no raw user flags;
- no shell execution;
- bounded output;
- bounded timeouts;
- bounded storage;
- owner-scoped sensitive data;
- redaction before storage/API/reports/exports/UI/Raw JSON;
- report wording as "observed exposure" or "review indicator";
- no confirmed vulnerability, exploitability, target-safety, or credential-valid
  claims.

## Recommended Order

The future work should be split into small reviewable commits:

1. Backend contract, feature flag, and request validation.
2. Target policy validator.
3. Allowlisted command builder with no execution.
4. Active runner skeleton with no real Nmap.
5. Controlled Nmap subprocess execution.
6. Bounded machine-readable output parser.
7. Redaction and report integration.
8. Frontend panel disabled/enabled states.
9. Frontend confirmations and submit contract.
10. Report and Raw JSON rendering.
10A. End-to-end contract review before live backend-to-runner wiring.
11. Pre-wiring hardening, no-live.
12. Backend job lifecycle wiring to a test-double adapter, no-live.
13. Live wiring readiness review.
14. Backend executor-interface wiring with mocks, no-live.
15. Final local smoke with no unauthorized external traffic.

Each microphase should be accepted only when its own validation passes and the
next phase remains separately gated.

## Microphase 01: Backend Contract, Feature Flag, Request Validation

Objective:

Define the backend contract for `active_nmap_basic` without calling a runner or
executing Nmap. Add the disabled-by-default feature flag, request schema,
authorization confirmations, audit type, and fail-closed rejection behavior.

Probable files:

- `backend/app/config.py`
- `backend/app/main.py`
- `backend/app/models.py` or local request models
- `backend/app/storage.py` only if existing job metadata helpers need small
  additions
- `backend/tests/test_backend.py`
- `docs/security-scope.md`
- `docs/architecture.md`

No-scope:

- No runner call.
- No Nmap command construction.
- No Nmap execution.
- No target DNS resolution.
- No subprocess use.
- No frontend changes.
- No Docker changes.
- No migrations.
- No public scanner behavior.

Expected validations:

- disabled flag rejects without creating a job;
- enabled flag requires `mode: live_nmap_basic`;
- enabled flag requires `profile: tcp_connect_small`;
- all confirmation booleans are required and must be `true`;
- raw flag fields are rejected;
- missing or malformed targets/ports are rejected;
- auth-required anonymous requests fail before validation details leak;
- created jobs, if any, are target-based with `file_id: null` and
  `audit_type: active_nmap_basic`;
- `git diff --check`;
- `git diff --cached --check`;
- no-scope search for forbidden wording.

Risks:

- Accidentally creating jobs while the feature is disabled.
- Letting request validation imply broad target support.
- Returning detailed validation errors before auth in auth-required modes.
- Treating authorization confirmation as proof of ownership.

Acceptance criteria:

- The endpoint contract exists but cannot execute live behavior.
- Default runtime keeps the feature disabled.
- Every accepted request is explicit, confirmed, owner-scoped, and still blocked
  before runner execution.
- Documentation says the capability remains unavailable until later phases.

Suggested commit:

```text
feat(active): add nmap basic backend contract gate
```

Status:

`ACTIVE_NMAP_BASIC_01_BACKEND_CONTRACT_GATE_ACCEPTED` implements this
microphase as a backend contract gate only. `POST /active/network/nmap-basic`
is disabled by default through `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=false`.
When explicitly enabled, it validates the exact `live_nmap_basic` /
`tcp_connect_small` request shape, required confirmations, and bounded
target/port lists, then returns `not_implemented` / `not_executed` without
creating a job, calling a runner, constructing commands, using subprocesses,
executing Nmap, resolving DNS, sending probes, making external HTTP requests,
adding frontend behavior, or integrating with archive/run-all flows.

## Microphase 02: Target Policy Validator

Objective:

Add a reusable target policy validator for exact, small, explicitly authorized
local/private/self-hosted targets. The validator must reject expansion patterns
before command building or runner calls.

Probable files:

- `backend/app/active_nmap.py` or a focused backend policy module
- `backend/app/main.py`
- `backend/tests/test_backend.py`
- optionally `tools/active_runner/` tests later mirror the same policy
- `docs/security-scope.md`

No-scope:

- No DNS expansion.
- No reverse DNS.
- No public internet free-form scanning.
- No CIDR blocks.
- No IP ranges.
- No wildcard targets.
- No target files.
- No URL paths, query strings, or fragments.
- No Nmap command building.
- No subprocess use.

Expected validations:

- accepts only exact host/IP inputs allowed by the frozen design;
- rejects comma-separated or whitespace-separated target lists in one field;
- rejects CIDR, dash ranges, wildcards, root-domain discovery inputs, and URLs
  with paths/queries/fragments;
- rejects metadata/control-plane/special-purpose targets;
- enforces target count and normalized target length limits;
- preserves local/private/self-hosted copy;
- returns controlled blocked results or request errors without runner calls.

Risks:

- Policy drift between backend and runner.
- Ambiguous host parsing.
- Accidentally allowing public target scanning as the default path.
- Mistaking exact host validation for DNS discovery.

Acceptance criteria:

- Ambiguous targets fail closed.
- No target expansion occurs.
- The validator can be tested without network access.
- Future runner phases can reuse or mirror the policy without loosening it.

Suggested commit:

```text
feat(active): add nmap basic target policy
```

Status:

`ACTIVE_NMAP_BASIC_02_TARGET_POLICY_ACCEPTED` implements this microphase as a
small backend policy module, `backend/app/active_nmap_policy.py`, plus endpoint
integration. The policy validates exact local/private/self-hosted IP or hostname
inputs without DNS resolution, reverse DNS, hostname generation, IP generation,
runner calls, command building, subprocess use, Nmap execution, Docker, frontend
changes, archive/run-all integration, or traffic. It fails closed for CIDR,
dash ranges, wildcard targets, pasted target lists, URL-shaped values, paths,
queries, fragments, userinfo, metadata/control-plane names, special-purpose IP
ranges, public-looking hostnames, too many targets, overlong targets, and
duplicate normalized targets.

## Microphase 03: Allowlisted Command Builder, No Execution

Objective:

Add a command builder that converts validated structured inputs into a fixed argv
array, but does not execute it. This phase proves that raw user flags cannot
reach Nmap.

Probable files:

- `tools/active_runner/active_nmap_basic.py`
- `tools/tests/test_active_runner.py`
- optional backend-side mirror tests if command preview metadata is exposed only
  internally
- `docs/architecture.md`

No-scope:

- No subprocess execution.
- No Nmap binary lookup.
- No shell execution.
- No user-supplied raw flags.
- No NSE, stealth, evasion, OS detection, service detection, UDP, brute force,
  exploit, credential, crawling, or discovery flags.
- No frontend changes.

Expected validations:

- generated command is an argv list;
- no shell string is produced;
- target appears only after an end-of-options marker where supported;
- profile is fixed to `tcp_connect_small`;
- host discovery and reverse DNS are disabled by fixed flags;
- ports are bounded numeric TCP ports only;
- forbidden flags such as `-A`, `-O`, `-sV`, `-sC`, `-sS`, `-sU`, `--script`,
  `--script-args`, `-iL`, `-D`, `-S`, `--spoof-mac`, `-f`, `--mtu`,
  `--data-length`, and `--source-port` cannot appear;
- tests inspect argv without executing Nmap.

Risks:

- Building a command string instead of argv.
- Letting convenience options expand scope.
- Capturing a free-form "extra_args" field.
- Logging full targets or command lines.

Acceptance criteria:

- Command construction is deterministic, allowlisted, and testable offline.
- No execution path exists in this commit.
- Forbidden features are covered by tests and source searches.

Suggested commit:

```text
feat(active): add nmap basic allowlisted command builder
```

Status:

`ACTIVE_NMAP_BASIC_03_COMMAND_BUILDER_ACCEPTED` implements this microphase as a
pure offline builder under `tools/active_runner/nmap_basic/command_builder.py`
with small shared constants in `tools/active_runner/contracts.py`. It accepts
structured inputs only, emits an argv list with the fixed `tcp_connect_small`
profile, fixed TCP-connect/no-discovery/no-reverse-DNS/bounded-timeout flags,
numeric bounded TCP ports, XML output to stdout, and the explicit target after
`--`. It does not add a runner endpoint, parser, subprocess use, shell command,
Nmap execution, binary lookup, DNS resolution, probes, external HTTP traffic,
frontend behavior, archive/run-all integration, or passive runner integration.

## Microphase 04: Active Runner Skeleton, No Real Nmap

Objective:

Add a structured Active runner endpoint or handler for `active_nmap_basic` that
validates profile, limits, and target policy, then returns a controlled
not-executed result. This keeps backend/runner wiring testable before Nmap can
run.

Probable files:

- `tools/active_runner/main.py`
- `tools/active_runner/active_nmap_basic.py`
- `tools/tests/test_active_runner.py`
- `backend/app/main.py` only if wiring to the runner is included in this phase
- `backend/tests/test_backend.py`

No-scope:

- No real Nmap execution.
- No subprocess use.
- No network traffic.
- No DNS checks.
- No parser for real Nmap XML.
- No Docker changes.
- No frontend changes.

Expected validations:

- handler rejects disabled/malformed profiles;
- handler rejects blocked targets before command building;
- handler returns a controlled `blocked` or `not_executed` shape;
- `network_requests_sent` is omitted or explicitly non-authoritative;
- no Nmap output is present;
- no `subprocess` call is reachable;
- no passive runner integration exists.

Risks:

- Skeleton response becoming confused with a real scan result.
- Backend treating `not_executed` as completed evidence.
- Accidentally importing passive runner code.

Acceptance criteria:

- Runner path is separate under `tools/active_runner/`.
- The skeleton can be called in tests without Nmap installed.
- Reports and summaries remain clear that no live result exists yet.

Suggested commit:

```text
feat(active): add nmap basic runner skeleton
```

Status:

`ACTIVE_NMAP_BASIC_04_RUNNER_SKELETON_ACCEPTED` implements this microphase as a
small offline handler in `tools/active_runner/nmap_basic/service.py`, reusing
the shared contracts and allowlisted command builder. The handler accepts a
structured single-target request, requires the exact `live_nmap_basic` /
`tcp_connect_small` contract and all three confirmations, rejects raw flags,
extra args, script fields, shell fields, and other unsupported command-like
inputs, calls the builder only to verify argv construction, then discards the
argv and returns a controlled `not_executed` response with no raw command,
target, stdout, stderr, evidence, vulnerability claim, job creation, backend
communication, endpoint, parser, Nmap execution, subprocess use, DNS checks,
network probes, Docker behavior, frontend behavior, archive/run-all
integration, or passive runner integration.

## Microphase 04A: Pre-Execution Review

Objective:

Review all accepted `active_nmap_basic` implementation slices before any real
Nmap execution, subprocess control, parser, frontend, Docker change, migration,
tag, or release can proceed.

Probable files:

- `docs/future/active-nmap-basic-pre-execution-review.md`
- `docs/future/active-nmap-basic-implementation-plan.md`

No-scope:

- No runtime behavior changes.
- No backend execution changes.
- No frontend changes.
- No runner endpoint.
- No Nmap execution.
- No subprocess use.
- No parser.
- No Docker changes.
- No migrations, tags, or releases.

Expected validations:

- backend contract, target policy, builder, and skeleton reviewed together;
- source searches confirm no unexpected execution path;
- tests still pass without Nmap installed;
- gaps before Microphase 05 are recorded explicitly.

Risks:

- Treating a docs-only review as permission for broad scanning.
- Missing a duplicated-contract drift risk before execution.
- Letting Microphase 05 introduce subprocess behavior before runner-side target
  policy and output controls are in place.

Acceptance criteria:

- A review record states whether Microphase 05 may proceed.
- The record includes reviewed files, findings, residual risks, gaps, validation
  evidence, and explicit confirmation that no Nmap or external traffic ran.

Suggested commit:

```text
docs(active): review nmap basic before execution
```

Status:

`ACTIVE_NMAP_BASIC_04A_PRE_EXECUTION_REVIEW_PASSED` is recorded in
`docs/future/active-nmap-basic-pre-execution-review.md`. The review found no
blocking issues and permits Microphase 05 to proceed only as a tightly bounded
subprocess-execution implementation phase. It records a required condition that
the execution boundary must enforce or mirror the backend target policy before
any real subprocess can be reachable. The review did not add runtime behavior,
backend execution, frontend behavior, runner endpoints, parsers, Docker changes,
migrations, tags, releases, Nmap execution, DNS checks, probes, external HTTP
traffic, archive/run-all integration, or passive runner integration.

## Microphase 05: Controlled Nmap Subprocess Execution

Objective:

Introduce actual Nmap subprocess execution only after contract, policy, builder,
and skeleton are accepted. Execution must be controlled, allowlisted,
non-shell, short-timeout, and bounded-output.

Probable files:

- `tools/active_runner/active_nmap_basic.py`
- `tools/tests/test_active_runner.py`
- possibly container packaging files in a separate reviewed implementation step
  if Nmap must be installed
- `docs/security-scope.md`
- `docs/architecture.md`

No-scope:

- No raw user flags.
- No shell execution.
- No NSE scripts.
- No stealth or evasion flags.
- No SYN/UDP/OS/service detection.
- No brute force.
- No exploit scripts.
- No credential validation.
- No crawling.
- No DNS expansion.
- No broad ranges.
- No public scanner mode.
- No frontend feature expansion in the same commit.

Expected validations:

- subprocess receives argv only from the allowlisted builder;
- subprocess timeout and kill grace are enforced;
- stdout and stderr byte limits are enforced before parsing/storage;
- timeout produces controlled failed/truncated output;
- Nmap absence produces controlled failure;
- command/environment/host paths are not leaked;
- tests use fakes/mocks for subprocess execution by default.

Risks:

- Nmap behavior differs across versions.
- Timeout handling leaves child processes running.
- stderr leaks target or environment details.
- Installing Nmap changes Docker/runtime surface and needs its own review.
- Tests accidentally perform real network traffic.

Acceptance criteria:

- Real execution is reachable only through the gated Active runner path.
- No shell is used.
- Timeouts/output limits are enforced before storage.
- Tests prove execution control without contacting external targets.

Suggested commit:

```text
feat(active): execute bounded nmap basic command
```

Status:

`ACTIVE_NMAP_BASIC_05_CONTROLLED_SUBPROCESS_ACCEPTED` implements this
microphase as a small modular executor under
`tools/active_runner/nmap_basic/executor.py`, plus a runner-side target policy
mirror under `tools/active_runner/nmap_basic/target_policy.py`. The executor
accepts only structured inputs, validates the existing service contract, applies
target policy before subprocess execution, builds argv exclusively through the
allowlisted command builder, invokes the provided runner or `subprocess.run`
with an argv list and `shell=False`, enforces a bounded process timeout, bounds
stdout and stderr before returning them, redacts raw target values and forbidden
claim wording from output, and returns controlled `completed`, `failed`,
`timed_out`, or `nmap_missing` states. Tests use fakes/mocks by default and do
not require Nmap to be installed. This phase does not add raw flags, shell
commands, custom scripts, NSE, stealth, evasion, OS/service/version detection,
UDP, brute force, exploit scripts, credential validation, crawling, DNS
expansion, broad ranges, XML parsing, findings, jobs, backend calls, runner
HTTP endpoints, frontend behavior, archive/run-all integration, Docker changes,
migrations, tags, releases, or passive runner integration.

## Microphase 06: Bounded Machine-Readable Parser

Objective:

Parse bounded Nmap machine-readable output into normalized observations without
storing full raw output by default.

Probable files:

- `tools/active_runner/active_nmap_basic.py`
- `tools/tests/test_active_runner.py`
- fixture files under a controlled test fixture path, if needed
- `docs/security-scope.md`

No-scope:

- No service banner trust.
- No vulnerability detection.
- No CVE matching.
- No exploitability inference.
- No full raw XML reports.
- No unbounded parser input.
- No parser network behavior.

Expected validations:

- parser accepts bounded XML/stdout only;
- parser extracts target count, TCP port, protocol, and state;
- parser bounds observations to the configured maximum;
- malformed XML returns controlled sparse/malformed output;
- oversized XML marks `output_truncated=true`;
- unknown states are represented conservatively;
- service/version fields are ignored or redacted in v0.

Risks:

- Treating Nmap state as complete truth.
- Parsing partial output into misleading certainty.
- Retaining raw XML with sensitive host inventory.
- Unexpected Nmap XML shape causing report crashes.

Acceptance criteria:

- Parsed output is small, structured, redacted, and manually reviewable.
- No confirmed-vulnerability claims are generated.
- Malformed and truncated outputs are safe and explicit.

Suggested commit:

```text
feat(active): parse bounded nmap basic output
```

Status:

`ACTIVE_NMAP_BASIC_06_BOUNDED_PARSER_ACCEPTED` implements this microphase as
an isolated parser at `tools/active_runner/nmap_basic/parser.py`. The parser
accepts only bounded XML/stdout bytes or strings, rejects unsupported XML
shapes, returns controlled `completed`, `empty`, `malformed`,
`unsupported_shape`, `truncated`, or `no_ports` states, extracts only minimal
TCP port observations, bounds observation count, marks oversized input as
truncated before parsing, normalizes unknown states conservatively, and keeps
raw XML, raw target values, command details, service/version/banner data,
findings, reports, jobs, backend calls, frontend behavior, archive/run-all
integration, and passive runner integration out of scope. Tests use synthetic
fixtures only and do not require Nmap, Docker, DNS, probes, external HTTP, or
network access.

## Microphase 07: Redaction And Report Integration

Objective:

Integrate `active_nmap_basic` with summaries, job detail, Markdown/HTML/XML/PDF
exports, and shared redaction so evidence is safe before UI work.

Probable files:

- `backend/app/reporting.py`
- `backend/app/redaction.py` or existing redaction helpers
- `backend/app/storage.py` if summary shaping is centralized there
- `backend/tests/test_backend.py`
- `docs/security-scope.md`

No-scope:

- No frontend panel.
- No new Nmap behavior.
- No new target support.
- No raw Nmap XML export.
- No confirmed vulnerability wording.
- No target-safety wording.

Expected validations:

- summaries redact target display;
- job detail redacts target strings, command fragments, stderr, and malformed
  nested payloads;
- exports render static report sections;
- report text says observed exposure and review indicator;
- reports state manual validation is required;
- reports state authorization is user asserted, not proof of ownership;
- no "secure", "safe", "confirmed vulnerability", "exploitable", or
  "all ports found" wording appears.

Risks:

- Legacy/malformed payloads bypass redaction.
- Reports overstate port observations.
- Raw JSON exposes command/output details.
- Export formats drift from API redaction.

Acceptance criteria:

- Stored, API, export, and Raw JSON surfaces are redaction-reviewed.
- Reports are readable but conservative.
- Existing report formats remain stable for other audit types.

Suggested commit:

```text
feat(active): report bounded nmap observations
```

Status:

`ACTIVE_NMAP_BASIC_07_REDACTION_REPORTING_ACCEPTED` implements this
microphase as backend reporting/redaction support for already-structured
`active_nmap_basic` payloads. Job detail, summaries, Markdown, HTML, XML, PDF,
and redacted Raw JSON now handle synthetic bounded Nmap observation results
without creating Nmap execution jobs, connecting backend to the runner executor,
adding runner HTTP endpoints, touching frontend runtime, integrating with
archive/run-all, storing raw XML, exposing raw target values, exposing raw
commands, or trusting stdout/stderr/service banners. Reports render minimal TCP
port observations as observed exposure and review indicators with manual
validation required. Controlled `failed`, `timed_out`, `nmap_missing`,
`malformed`, `truncated`, and `no_ports` states render without crashing or
claiming complete coverage, target safety, exploitability, or vulnerability
confirmation.

## Microphase 08: Frontend Panel Disabled/Enabled States

Objective:

Add a separate `Active / Nmap basic` panel that renders disabled/enabled state
copy without submitting jobs yet.

Probable files:

- `frontend/src/App.tsx`
- `frontend/src/api.ts`
- `frontend/src/dashboardFilters.ts`
- `frontend/src/*.test.tsx`
- `docs/architecture.md`

No-scope:

- No submit action yet.
- No live Nmap execution from UI.
- No report rendering.
- No archive card action.
- No run-all integration.
- No public scanner wording.

Expected validations:

- disabled state renders when backend reports feature unavailable;
- enabled state remains clearly local/private/self-hosted and authorized-use
  only;
- panel is separate from dry-run, HTTP header probe, and archive/file actions;
- copy avoids "full scan", "internet scan", "find assets", and "vulnerability
  scan" promises;
- UI tests cover disabled and enabled display states.

Risks:

- Users may interpret the panel as production-ready.
- Panel placement may blur passive and Active actions.
- Disabled copy may leak unnecessary deployment/config details.

Acceptance criteria:

- The UI shows availability without allowing submission.
- No functional Nmap workflow is exposed by this phase alone.
- Copy remains bounded and conservative.

Suggested commit:

```text
feat(active): add nmap basic panel shell
```

Status:

`ACTIVE_NMAP_BASIC_08_FRONTEND_PANEL_SHELL_ACCEPTED` implements this
microphase as a frontend-only informational panel. The UI renders a separate
`Active / Nmap basic` shell with disabled/prepared availability states, bounded
local/private/self-hosted and authorized-target copy, live-traffic warning,
manual-validation wording, and explicit no-scope limits. It does not add a
functional submit, create Nmap jobs, call the backend Nmap contract, connect the
backend to the runner executor, add runner endpoints, render full frontend
reports, expose raw flags or credential/header/cookie/token fields, integrate
with archive/run-all actions, run Nmap, run Docker, perform probes, perform DNS
checks, or send external HTTP traffic.

## Microphase 09: Frontend Confirmations And Submit Contract

Objective:

Wire the panel form to the backend request contract with explicit authorization,
local/private/self-hosted scope, and live-traffic confirmations.

Probable files:

- `frontend/src/App.tsx`
- `frontend/src/api.ts`
- `frontend/src/dashboardFilters.ts`
- frontend tests for request payloads
- `docs/security-scope.md`

No-scope:

- No raw flags input.
- No target files.
- No CIDR/range/wildcard UI.
- No custom Nmap profiles.
- No advanced scan settings.
- No credential fields.
- No crawling options.

Expected validations:

- submit is disabled until all confirmations are checked;
- request body exactly matches the backend contract;
- target and port counts are bounded client-side as UX aid;
- server remains authoritative for validation;
- no raw flags or script arguments can be entered;
- errors render generically without leaking sensitive target details.

Risks:

- Client-side validation diverges from backend policy.
- Confirmation text becomes too casual for live traffic.
- Users paste lists/ranges into a single field.

Acceptance criteria:

- UI requires all confirmations before submit.
- Payload is exact and bounded.
- Backend policy remains the source of truth.

Suggested commit:

```text
feat(active): wire nmap basic confirmations
```

Status:

`ACTIVE_NMAP_BASIC_09_FRONTEND_CONFIRMATIONS_ACCEPTED` implements this
microphase as a frontend-only form contract. The `Active / Nmap basic` panel
accepts one explicit target, a small bounded numeric TCP port list, fixed
`mode: live_nmap_basic`, fixed `profile: tcp_connect_small`, and the three
required confirmations before submit. The request body sent to
`POST /active/network/nmap-basic` matches the existing backend contract exactly.
The UI treats backend `403` as disabled/unavailable and backend
`501` / `not_implemented` / `not_executed` as the expected current state. It
does not render the result as a completed scan, expose raw flags, target-file,
CIDR/range/wildcard, custom-profile, advanced-scan, credential/header/cookie/
token, or crawling controls, create real Nmap jobs, connect backend to the
runner executor, add runner HTTP endpoints, render full frontend Nmap reports,
integrate with archive/run-all, execute Nmap, run Docker, perform probes,
perform DNS checks, or send external HTTP traffic outside mocked/local tests.

## Microphase 10: Report And Raw JSON Rendering

Objective:

Render `active_nmap_basic` completed, blocked, failed, timed-out, truncated,
sparse, and malformed payloads in the frontend with redacted Raw JSON.

Probable files:

- `frontend/src/ActiveNmapBasicJobReport.tsx`
- `frontend/src/reportHelpers.ts`
- `frontend/src/dashboardFilters.ts`
- `frontend/src/App.tsx`
- frontend report tests

No-scope:

- No new backend behavior.
- No new runner behavior.
- No raw XML display.
- No service-version or CVE display.
- No confirmed vulnerability claims.
- No high-severity auto-mapping from open ports.

Expected validations:

- observed port states render as review indicators;
- blocked/failed/timeout/truncated states are explicit;
- Raw JSON redacts target strings, command fragments, stderr, and malformed
  nested fields;
- no "target is safe", "confirmed vulnerability", "exploitable", "full scan",
  or "all ports found" copy appears;
- report handles missing optional fields without crashing.

Risks:

- Raw JSON shows more than report view.
- UI overemphasizes open ports as vulnerabilities.
- Sparse payloads break rendering.

Acceptance criteria:

- UI report matches backend wording and redaction posture.
- All expected job states are covered by tests.
- Report remains separate from passive reports and other Active reports.

Suggested commit:

```text
feat(active): render nmap basic reports
```

Status:

`ACTIVE_NMAP_BASIC_10_FRONTEND_REPORT_RENDERING_ACCEPTED` implements this
microphase as frontend-only report and Raw JSON rendering for already
structured `active_nmap_basic` payloads. The renderer handles completed,
failed, timed-out, `nmap_missing`, malformed, truncated, no-ports, and sparse
payloads without adding backend runtime behavior, runner endpoints, real Nmap
jobs, archive/run-all integration, raw flags input, target files,
CIDR/range/wildcard UI, custom profiles, advanced scan settings, credential/
header/cookie/token fields, crawling options, raw XML display, raw command
display, raw target display, or stdout/stderr display without frontend
defensive redaction. Port rows are rendered as observed TCP exposure and review
indicators with manual validation required. Raw JSON receives additional
frontend redaction for target values, command fragments, raw XML, stdout/
stderr, service/banner fields, headers, cookies, tokens, credentials, and
legacy/malformed nested sensitive fields. The report does not infer
vulnerabilities, exploitability, target safety, complete coverage, CVE matches,
or high severity from open ports.

## Microphase 10A: E2E Contract Review, No Live Wiring

Objective:

Review the current end-to-end `active_nmap_basic` contract before backend-to-
runner live wiring. This checkpoint verifies that the backend, target policy,
isolated runner modules, parser, reporting, frontend panel, and frontend report
renderer still align with the frozen design and do not accidentally expose live
Nmap execution.

Probable files:

- `docs/future/active-nmap-basic-e2e-contract-review-no-live.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- existing backend, runner, reporting, and frontend tests as read-only review
  evidence

No-scope:

- No backend-to-runner connection.
- No real Nmap job creation.
- No runner HTTP endpoint.
- No Nmap execution.
- No Docker execution.
- No probes.
- No DNS checks.
- No external HTTP traffic.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No functional changes unless a separately scoped blocker is found.

Expected validations:

- backend contract remains disabled by default and returns `not_executed`
  without job creation when explicitly enabled;
- backend target policy and runner target policy remain fail-closed and
  local/private/self-hosted only;
- command builder remains allowlisted and argv-only;
- executor remains isolated from backend and runner HTTP surfaces;
- parser remains bounded and does not return raw XML, targets, commands,
  stdout/stderr, service banners, or findings;
- reporting and frontend Raw JSON redaction cover legacy and malformed payloads;
- frontend submits only the exact contract after all confirmations;
- source search confirms no active_nmap_basic integration in `tools/runner/main.py`
  and no archive/run-all trigger path.

Risks:

- Policy drift between backend and runner validators before live wiring.
- Backend `targets[]` shape and runner single-`target` shape need a carefully
  bounded fanout contract.
- Executor output and parser output are not yet composed into a stored job
  result.
- Tests may validate modules in isolation while missing cross-boundary
  serialization and redaction behavior.

Acceptance criteria:

- Review document records files reviewed, findings, residual risks, gaps before
  backend-to-runner wiring, and the next recommended microphase.
- No live behavior is introduced.
- The next phase remains separately gated and preferably no-live/test-double
  before any real Nmap execution is wired.

Suggested commit:

```text
docs(active): review nmap basic e2e contract before live wiring
```

Status:

`ACTIVE_NMAP_BASIC_10A_E2E_CONTRACT_REVIEW_NO_LIVE_PASSED` records the
review-only checkpoint in
`docs/future/active-nmap-basic-e2e-contract-review-no-live.md`. The review
confirms that the current backend endpoint is still a disabled-by-default
contract gate, the active runner modules remain isolated from backend job
creation and from `tools/runner/main.py`, reporting and frontend Raw JSON use
defensive redaction and review-indicator wording, and no real Nmap jobs,
runner HTTP endpoints, archive/run-all integration, Docker, probes, DNS checks,
external HTTP traffic, or backend-to-runner live wiring are introduced.

## Microphase 11: Pre-Wiring Hardening, No-Live

Objective:

Close the no-live hardening gap before backend-to-runner wiring. This phase
adds parity, serialization, handoff, composition, redaction, and frontend
controlled-state tests using pure helpers, fakes, and synthetic fixtures only.

Probable files:

- `backend/app/active_nmap_handoff.py`
- `backend/tests/test_active_nmap_policy.py`
- `backend/tests/test_backend.py`
- `tools/active_runner/nmap_basic/result.py`
- `tools/tests/test_active_runner_nmap_basic_parser.py`
- `frontend/src/ActiveNmapBasicJobReport.test.tsx`
- `docs/future/active-nmap-basic-pre-wiring-hardening-no-live.md`
- `docs/future/active-nmap-basic-implementation-plan.md`

No-scope:

- No backend-to-runner live wiring.
- No real Nmap job creation.
- No background task execution for Nmap.
- No runner HTTP endpoint.
- No Nmap execution.
- No Docker execution.
- No probes.
- No DNS checks.
- No external HTTP traffic.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No raw flags, custom scripts, NSE, brute force, credential validation,
  crawling, DNS expansion, broad ranges, or public scanner behavior.

Expected validations:

- backend and runner target-policy acceptance/rejection parity;
- backend duplicate and too-many-target rejection remains batch-level;
- backend `targets[]` serializes to one handoff unit per target;
- handoff preserves confirmations and bounded ports;
- handoff records `implicit_concurrency: 1`;
- fake executor output plus synthetic parser output composes to structured
  `active_nmap_basic` payload;
- composed payload omits raw target, command, XML, stdout, stderr, service, and
  banner evidence;
- backend API/report/export surfaces keep the composed payload redacted;
- frontend `not_executed` is rendered as not connected/not executed, not as a
  completed scan;
- source searches confirm no live runner path or archive/run-all trigger.

Risks:

- Adding helper code that quietly becomes a live path.
- Policy drift between backend and runner validators.
- Accidentally widening `targets[]` into concurrent or broad batches.
- Treating fake parser/result composition as release readiness.
- Frontend copy implying completion for `not_executed`.

Acceptance criteria:

- Pure helpers are offline and do not call runners, create jobs, execute
  commands, resolve DNS, send probes, or run Nmap.
- Focused backend, runner, and frontend tests pass.
- Full backend and frontend suites pass.
- Documentation records gaps closed, tests added, still-blocked behavior,
  validation evidence, and next recommended no-live step.

Suggested commit:

```text
test(active): harden nmap basic before live wiring
```

Status:

`ACTIVE_NMAP_BASIC_11_PRE_WIRING_HARDENING_NO_LIVE_ACCEPTED` implements this
microphase with a pure backend handoff helper, a pure active-runner result
composer, backend/runner target-policy parity tests, single-target handoff
serialization tests, fake execution/parser/reporting redaction tests, and an
extra frontend `not_executed` report test. It does not connect backend to the
runner executor, create real Nmap jobs, add background tasks, add runner HTTP
endpoints, execute Nmap, run Docker, perform probes, perform DNS checks, make
external HTTP requests, integrate archive/run-all, integrate with
`tools/runner/main.py`, add raw flags, add custom scripts, add NSE, add brute
force, add credential validation, add crawling, add DNS expansion, or add broad
ranges.

## Microphase 12: Backend Runner Wiring, Test-Double No-Live

Objective:

Create real Inspectra `active_nmap_basic` jobs when the feature flag is enabled,
but wire them only to a backend-owned no-live test-double adapter. This phase
proves owner-scoped job lifecycle, handoff fanout, redacted storage, report
exports, Raw JSON, frontend controlled-state handling, and source boundaries
before any backend-to-runner live executor connection.

Probable files:

- `backend/app/main.py`
- `backend/app/services.py`
- `backend/app/storage.py`
- `backend/tests/test_backend.py`
- `frontend/src/ActiveNmapBasicPanel.tsx`
- `frontend/src/ActiveNmapBasicPanel.test.tsx`
- `frontend/src/types.ts`
- `docs/future/active-nmap-basic-backend-runner-wiring-test-double-no-live.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- README, architecture, or security-scope docs if the visible state changes

No-scope:

- No real Nmap execution.
- No backend call to the real active-runner executor.
- No subprocess from backend.
- No runner HTTP endpoint.
- No Docker execution.
- No probes.
- No DNS checks.
- No external HTTP traffic.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No raw flags, custom scripts, NSE, brute force, credential validation,
  crawling, DNS expansion, broad ranges, target-policy relaxation, or owner
  scope relaxation.

Expected validations:

- disabled flag still rejects without creating a job;
- enabled valid requests create `active_nmap_basic` jobs with `file_id: null`;
- no-live adapter records `not_executed`, `execution_attempted: false`, no
  subprocess, no DNS, no network, and no Nmap execution;
- `targets[]` handoff is bounded, redacted, and records `implicit_concurrency:
  1`;
- invalid contracts and target-policy rejections create no job;
- auth-required anonymous requests fail before validation detail or job
  creation;
- owner-scoped detail/list/export/Raw JSON behavior holds for target-based jobs;
- Markdown, HTML, XML, PDF, and Raw JSON remain redacted;
- frontend successful submit with mocked job response is controlled no-live
  copy, not a completed live scan;
- archive/run-all and `tools/runner/main.py` remain unintegrated;
- runner focused tests continue to pass without Nmap installed.

Risks:

- A test-double result being mistaken for real Nmap execution.
- Owner-scoped target jobs leaking raw target metadata.
- Background-task semantics making `not_executed` look like a completed live
  scan in UI copy.
- Backend source accidentally importing the real executor while tests still
  mock behavior.

Acceptance criteria:

- The feature remains disabled by default.
- Enabled valid requests create exactly bounded target-based jobs and only run
  the no-live adapter.
- Backend, runner, frontend, build, source-search, and no-scope validations
  pass.
- Documentation records the no-live state, blocked behavior, validation
  evidence, final decision, and next recommended microphase.

Suggested commit:

```text
feat(active): wire nmap basic jobs to test double
```

Status:

`ACTIVE_NMAP_BASIC_12_BACKEND_RUNNER_WIRING_TEST_DOUBLE_NO_LIVE_ACCEPTED`
implements this microphase with real owner-scoped backend job creation, a
backend no-live test-double service, redacted target metadata, handoff-derived
bounded counts, frontend controlled-state copy for created no-live jobs, and
backend/frontend/runner regression coverage. It does not call the real
active-runner executor, execute Nmap, invoke subprocesses from backend, add a
runner HTTP endpoint, run Docker, perform probes, perform DNS checks, make
external HTTP requests, integrate archive/run-all, integrate
`tools/runner/main.py`, accept raw flags, add custom scripts, add NSE, add
brute force, add credential validation, add crawling, add DNS expansion, or
add broad ranges.

## Microphase 13: Live Wiring Readiness Review

Objective:

Perform a docs-only/read-only readiness review before allowing backend wiring
toward the real executor interface. This phase decides whether the next
backend slice may call an injectable executor boundary under mocks, while still
blocking real Nmap execution.

Probable files:

- `docs/future/active-nmap-basic-live-wiring-readiness-review.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`
- existing backend, runner, and frontend source files for read-only review

No-scope:

- No backend runtime changes.
- No frontend runtime changes.
- No runner runtime changes.
- No backend-to-runner live wiring.
- No backend call to the real executor.
- No runner HTTP endpoint.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No Nmap execution.
- No subprocess invocation from backend.
- No Docker execution.
- No probes.
- No DNS checks.
- No external traffic.
- No migrations, tags, or releases.
- No broad ranges, raw flags, custom scripts, NSE, stealth, evasion, brute
  force, credential validation, crawling, DNS expansion, or public scanner
  behavior.

Expected validations:

- backend lifecycle still uses the disabled-by-default gate;
- disabled mode creates no job;
- enabled valid requests still create only owner-scoped no-live jobs;
- auth-required anonymous requests fail before validation detail;
- backend does not import or call the real active-runner executor;
- backend does not import subprocess for `active_nmap_basic`;
- `tools/runner/main.py`, archive/run-all, and runner HTTP endpoint paths
  remain unintegrated;
- handoff remains target-bounded and single-concurrency;
- parser/result/reporting redaction remains bounded and conservative;
- frontend report and Raw JSON rendering still distinguish no-live from live
  execution;
- focused and full backend, runner, frontend, build, source-search, and
  no-scope validations pass without Docker, Nmap, probes, DNS checks, or
  external HTTP traffic.

Risks:

- A review could accidentally be interpreted as approval for real Nmap smoke.
- Backend executor-interface wiring could be bundled with packaging or
  subprocess execution.
- Test-double job results could be mistaken for completed live scans.
- Future stdout/stderr/parser failures may contain new strings that require
  another redaction pass.

Acceptance criteria:

- A review document records the files reviewed, findings, blockers, residual
  risks, validation evidence, decision, and next recommended microphase.
- The decision explicitly allows only mocked/no-live backend wiring toward an
  executor interface.
- Real Nmap execution, Docker/Nmap packaging, live local smoke, runner HTTP
  endpoints, archive/run-all, and passive-runner integration remain blocked.
- Documentation keeps observed exposure / review indicator wording and avoids
  confirmed-vulnerability, exploitability, target-safety, and complete-coverage
  claims.

Suggested commit:

```text
docs(active): review nmap basic live wiring readiness
```

Status:

`ACTIVE_NMAP_BASIC_13_LIVE_WIRING_READINESS_REVIEW_PASSED` records this
docs-only/read-only checkpoint in
`docs/future/active-nmap-basic-live-wiring-readiness-review.md`. The review
finds no blocker for a next mocked/no-live backend slice that calls an
injectable executor interface, but it does not approve real Nmap execution,
Docker/Nmap packaging, local authorized Nmap smoke, runner HTTP endpoints,
archive/run-all integration, `tools/runner/main.py` integration, broader
fanout, target expansion, raw flags, NSE, stealth/evasion, brute force,
credential validation, crawling, DNS expansion, public scanner behavior, or
confirmed-vulnerability/exploitability claims.

## Microphase 14: Backend Executor Wiring, Mocked No-Live

Objective:

Connect the backend job lifecycle to an injectable active-runner executor
interface while tests use mocks/fakes only. This phase may exercise
parser/result composition with synthetic executor outputs, but must not invoke
real Nmap or backend subprocesses.

Probable files:

- `backend/app/main.py`
- `backend/app/services.py`
- `backend/app/storage.py`
- `backend/app/active_nmap_handoff.py`
- `backend/tests/test_backend.py`
- focused runner parser/result fixtures if needed
- `docs/future/active-nmap-basic-backend-executor-wiring-mocked-no-live.md`
- `docs/future/active-nmap-basic-implementation-plan.md`

No-scope:

- No real Nmap execution.
- No backend subprocess invocation.
- No unmocked executor call in tests.
- No Docker execution or Nmap packaging.
- No runner HTTP endpoint.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No probes, DNS checks, or external HTTP traffic.
- No raw flags, custom scripts, NSE, stealth, evasion, brute force, credential
  validation, crawling, DNS expansion, broad ranges, target-policy relaxation,
  concurrency expansion, or public scanner behavior.

Expected validations:

- disabled flag still rejects without creating a job;
- enabled valid requests call only the injected executor interface in tests;
- mocked completed, failed, timed-out, `nmap_missing`, malformed, truncated,
  and no-ports executor/parser states store redacted results;
- no raw target, command, XML, stdout, stderr, service, or banner values appear
  in API, reports, exports, or Raw JSON;
- wrong-owner reads and exports remain generic not-found responses;
- backend source search shows no direct `subprocess` or real executor default
  path used by tests;
- runner focused tests still pass without Nmap installed;
- frontend controlled-state rendering remains stable.

Risks:

- Dependency injection could hide an accidental real executor default.
- Mocked completed states could make UI copy look like approved live scanning.
- Synthetic parser output might miss redaction strings from real Nmap output.
- Background job timing could make status transitions harder to reason about.

Acceptance criteria:

- The backend can be tested against an executor interface without real Nmap.
- All stored and rendered results remain bounded, owner-scoped, and redacted.
- Source searches confirm no backend subprocess path, runner HTTP endpoint,
  archive/run-all integration, or passive-runner integration.
- Documentation states that real Nmap smoke remains a later separately
  approved phase.

Suggested commit:

```text
feat(active): wire nmap basic executor interface with mocks
```

Status:

`ACTIVE_NMAP_BASIC_14_BACKEND_EXECUTOR_WIRING_MOCKED_NO_LIVE_ACCEPTED`
implements this microphase with a backend `ActiveNmapBasicService`, an
injectable executor adapter protocol, a default no-live adapter, tests that
inject mocked executor states, parser/result composition from synthetic output,
redacted owner-scoped storage, and backend/frontend/runner regression coverage.
It preserves disabled-by-default behavior, exact request validation, target
policy, owner scope, redacted reporting, no archive/run-all integration, no
`tools/runner/main.py` integration, no runner HTTP endpoint, no backend
subprocess use, no real Nmap execution, no Docker, no probes, no DNS checks,
and no external HTTP traffic. Real Nmap smoke remains blocked pending a
separate approved phase.

## Microphase 15: Local Smoke Plan, No Unauthorized Traffic

Objective:

Plan the first controlled local smoke method before any execution. The plan must
decide whether the first smoke is no-live mocked or real local authorized, and
must keep third-party targets, external DNS, public internet targets, and
unauthorized external traffic out of scope.

Probable files:

- `docs/future/active-nmap-basic-local-smoke-plan-no-unauthorized-traffic.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No real smoke execution in this phase.
- No Nmap execution.
- No Docker execution.
- No probes, DNS checks, or external HTTP traffic.
- No backend, frontend, or runner runtime changes.
- No public internet targets.
- No arbitrary internet scanning.
- No broad ranges.
- No third-party demo targets.
- No production policy relaxation.
- No Nmap run against unauthorized hosts.
- No runner HTTP endpoint.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No tags or releases.

Expected validations:

- the new plan recommends no-live fake/mocked smoke first;
- real local Nmap smoke remains blocked unless a later phase freezes an exact
  loopback/local controlled target and exact bounded ports/timeouts;
- VPS/domain smoke remains blocked for the first smoke;
- the target-control method excludes third parties, public domains, CIDR/ranges,
  wildcards, target files, and DNS expansion;
- feature-flag enablement is explicit, temporary, and disabled after any future
  smoke;
- future validations are listed without running Nmap, Docker, probes, DNS
  checks, or external HTTP traffic in this phase;
- no-scope search confirms no broad scanning or confirmed-vulnerability claims.

Risks:

- Local smoke accidentally reaches external networks.
- Local lab exceptions become production policy.
- Smoke evidence is mistaken for release readiness.
- Target-side logs contain scan evidence outside Inspectra cleanup control.

Acceptance criteria:

- The smoke plan names Option A no-live mocked smoke as the first recommended
  path.
- Option B real local authorized smoke is allowed only as a later separately
  approved execution phase with exact loopback/local target control.
- Option C own VPS/domain smoke is blocked for the first smoke.
- No unauthorized traffic is approved or generated.
- Documentation states that this is internal/local/private planning, not
  production or public readiness.

Suggested commit:

```text
docs(active): plan nmap basic local smoke
```

Status:

`ACTIVE_NMAP_BASIC_15_LOCAL_SMOKE_PLAN_NO_UNAUTHORIZED_TRAFFIC_ACCEPTED`
implements this docs-only planning checkpoint. The accepted first smoke method
is Option A no-live fake/mocked adapter validation. Option B real local
authorized Nmap smoke remains blocked until a later execution phase freezes an
exact loopback/local controlled target, exact ports, exact timeouts, cleanup,
and evidence limits. Option C own VPS/domain smoke remains blocked for the
first smoke. This phase does not run Nmap, Docker, probes, DNS checks, external
HTTP traffic, backend/frontend/runner runtime changes, runner HTTP endpoints,
archive/run-all integration, `tools/runner/main.py` integration, migrations,
tags, releases, or public scanner behavior.

## Microphase 16: No-Live Smoke Execution

Objective:

Execute the first `active_nmap_basic` smoke using only Option A no-live
fake/mocked adapter validation. This phase validates backend lifecycle,
owner scope, reporting/export, Raw JSON, frontend controlled states, and
absence of unauthorized traffic without running real Nmap.

Probable files:

- `docs/future/active-nmap-basic-no-live-smoke-execution.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No real Nmap execution.
- No Docker execution.
- No probes, DNS checks, or external HTTP traffic.
- No real external target, VPS, or domain.
- No backend, frontend, or runner runtime changes.
- No backend direct call to the real active-runner executor.
- No backend subprocess invocation.
- No runner HTTP endpoint.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No target-policy relaxation.
- No feature-flag default relaxation.
- No raw flags, scripts, NSE, brute force, credential validation, crawling, DNS
  expansion, broad ranges, or public scanner behavior.

Expected validations:

- disabled feature flag rejects without creating a job;
- enabled test configuration creates owner-scoped `active_nmap_basic` jobs with
  `file_id: null`;
- no-live metadata records no execution, no Nmap, no subprocess, no network
  requests, and no DNS queries;
- mocked states cover `completed`, `failed`, `timed_out`, `nmap_missing`,
  `malformed`, `truncated`, `no_ports`, and `not_executed`;
- job detail, summary, Markdown, HTML, XML, PDF, and Raw JSON stay redacted;
- frontend disabled/unavailable, `not_executed`, and mocked completed states
  render as controlled states or observed TCP exposure / review indicators;
- source searches confirm no backend real executor wiring, no runner endpoint,
  no archive/run-all integration, and no passive-runner integration.

Risks:

- Treating no-live smoke as approval for real local Nmap execution.
- Treating mocked completed observations as live scan evidence.
- Missing a future accidental integration point in broad source searches.

Acceptance criteria:

- All no-live backend, runner, frontend, build, and source-search validations
  pass.
- The smoke record documents commands, results, lifecycle evidence,
  redaction/export evidence, frontend evidence, and no-go checks.
- Documentation confirms that real local Nmap smoke remains blocked pending a
  later target-freeze/readiness gate.

Suggested commit:

```text
test(active): execute nmap basic no-live smoke
```

Status:

`ACTIVE_NMAP_BASIC_16_NO_LIVE_SMOKE_EXECUTION_PASSED` records this smoke in
`docs/future/active-nmap-basic-no-live-smoke-execution.md`. The smoke passed
with no-live fake/mocked adapter validation only: backend focused and full
tests, active-runner fake-based tests, frontend focused and full tests, build,
compile checks, and source searches all passed. It did not run Nmap, Docker,
probes, DNS checks, external HTTP traffic, real external targets, VPS/domain
smoke, backend subprocesses, runner HTTP endpoints, archive/run-all, or
`tools/runner/main.py` integration. Real local Nmap smoke remains blocked.

## Microphase 17: Real Local Smoke Target Freeze

Objective:

Freeze the exact target, ports, feature-flag handling, future commands,
cleanup, rollback, and no-go criteria for a later real local authorized smoke
without executing Nmap in this phase.

Probable files:

- `docs/future/active-nmap-basic-real-local-smoke-target-freeze.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Nmap execution.
- No Docker execution.
- No probes, DNS checks, or external HTTP traffic.
- No backend, frontend, or runner runtime changes.
- No backend real-executor default wiring.
- No backend subprocess invocation.
- No runner HTTP endpoint.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No real external target, VPS, domain, third-party host, LAN target, container
  target, hostname, or `localhost`.
- No raw flags, scripts, NSE, UDP, SYN scan, OS detection, service/version
  detection, brute force, credential validation, crawling, DNS expansion, broad
  ranges, or public scanner behavior.

Expected validations:

- target is frozen to exactly `127.0.0.1`;
- port set is frozen to exactly `[65000]`;
- optional `::1`, `localhost`, LAN, VPS, domain, and public targets remain
  blocked;
- future command shape preserves `live_nmap_basic`, `tcp_connect_small`, one
  target, one port, no DNS expansion, and allowlisted argv only;
- future feature-flag enablement is temporary and disabled after the smoke;
- future evidence checklist avoids raw target/command/XML/stdout/stderr leakage
  and avoids confirmed-vulnerability/exploitability wording.

Risks:

- Target-freeze text could be mistaken for execution approval.
- Operators could replace `127.0.0.1` with `localhost` or a LAN address.
- A closed-port smoke could be overinterpreted as target safety.

Acceptance criteria:

- The target-freeze document states that no real execution is approved.
- Only `127.0.0.1` and `[65000]` are accepted for the next smoke.
- All commands are clearly marked as future commands, not executed in this
  phase.
- Documentation keeps real local execution blocked until a separate execution
  phase.

Suggested commit:

```text
docs(active): freeze nmap basic real local smoke target
```

Status:

`ACTIVE_NMAP_BASIC_17_REAL_LOCAL_SMOKE_TARGET_FREEZE_ACCEPTED` freezes the
future real local smoke to target `127.0.0.1`, port `[65000]`, mode
`live_nmap_basic`, profile `tcp_connect_small`, temporary feature-flag
enablement, allowlisted argv shape, cleanup, rollback, evidence checklist, and
no-go criteria. It does not run Nmap, Docker, probes, DNS checks, external HTTP
traffic, backend/frontend/runner runtime changes, real executor default wiring,
backend subprocesses, runner HTTP endpoints, archive/run-all, or
`tools/runner/main.py` integration. Real local execution remains blocked until
a later execution phase explicitly approves it.

## Microphase 18: Real Local Smoke Execution

Objective:

Run the frozen real local smoke only if local Nmap is available. The smoke must
use exactly target `127.0.0.1`, port `[65000]`, mode `live_nmap_basic`, profile
`tcp_connect_small`, and temporary feature-flag enablement.

Probable files:

- `docs/future/active-nmap-basic-real-local-smoke-execution.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Nmap installation.
- No Docker execution.
- No DNS checks.
- No external HTTP traffic.
- No target other than `127.0.0.1`.
- No port other than `65000`.
- No `localhost`, `::1`, hostname, domain, VPS, LAN, container, or third-party
  target.
- No raw flags, NSE, `--script`, UDP, SYN scan, OS detection, service/version
  detection, brute force, credential validation, crawling, DNS expansion, broad
  ranges, archive/run-all integration, runner HTTP endpoints, or
  `tools/runner/main.py` integration.

Expected validations:

- `command -v nmap` gates execution;
- missing Nmap blocks the phase without installation;
- allowlisted builder still emits the frozen argv;
- no-live backend/runner/frontend tests pass before any real execution;
- if Nmap is available in a later rerun, backend launch uses an inline temporary
  feature flag and binds only to `127.0.0.1`;
- request body uses only `targets: ["127.0.0.1"]` and `ports: [65000]`;
- cleanup stops the backend and leaves the feature flag disabled.

Risks:

- Treating missing Nmap as a reason to install tooling inside the phase.
- Accidentally replacing numeric loopback with `localhost`.
- Treating a blocked smoke as evidence of real Nmap execution.

Acceptance criteria:

- If Nmap is missing, document
  `ACTIVE_NMAP_BASIC_18_REAL_LOCAL_SMOKE_EXECUTION_BLOCKED_NMAP_MISSING`.
- If Nmap is available, execute only the frozen smoke and document either pass
  or no-go failure.
- Documentation states exactly what ran and what stayed blocked.

Suggested commit:

```text
test(active): execute nmap basic real local smoke
```

Status:

`ACTIVE_NMAP_BASIC_18_REAL_LOCAL_SMOKE_EXECUTION_BLOCKED_NMAP_MISSING` records
that `command -v nmap` returned no local binary. No Nmap installation, Docker,
backend smoke server, live request, job creation, export, DNS check, external
HTTP traffic, target change, port change, raw flags, runner HTTP endpoint,
archive/run-all integration, or `tools/runner/main.py` integration occurred.
The frozen argv was rechecked through the allowlisted builder, and no-live
backend, active-runner, and frontend tests passed.

## Microphase 19: Nmap Availability And Packaging Plan

Objective:

Decide how Nmap should become available to Inspectra after the correct
Microphase 18 block for missing local Nmap. This phase is docs-only and chooses
a packaged Active runner/image path instead of a normal host-local manual Nmap
dependency.

Probable files:

- `docs/future/active-nmap-basic-nmap-availability-and-packaging-plan.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Nmap installation.
- No Nmap execution.
- No Docker execution.
- No Dockerfile or Compose changes.
- No backend, frontend, or runner runtime changes.
- No backend direct subprocess execution for Nmap.
- No runner HTTP endpoint.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No LAN target approval.
- No VPS/domain smoke approval.
- No public scanner behavior.

Expected validations:

- documentation explains the Microphase 18 missing-binary block;
- host-local manual Nmap install is rejected as the normal Inspectra path;
- adding Nmap to the passive runner is discouraged;
- a separate Dockerized Active runner/image, tentatively `active-tools`, is
  recommended;
- mocked/no-live behavior remains the fallback until packaging and execution
  are separately implemented;
- disabled-by-default, opt-in, authorization, target, time, output, storage,
  redaction, and wording guardrails remain unchanged.

Risks:

- Treating a packaging plan as approval to build or run Docker.
- Treating `active-tools` as a public scanner service.
- Letting the passive runner monolith absorb Active/Nmap.
- Reintroducing host-local Nmap installation as a hidden product dependency.

Acceptance criteria:

- The plan recommends `active-tools` / separate Active runner packaging.
- The plan explicitly rejects host-local Nmap as the default requirement.
- The plan keeps backend direct Nmap subprocess execution blocked.
- The plan keeps `tools/runner/main.py`, archive/run-all, LAN targets,
  VPS/domain smoke, and public scanner behavior blocked.
- No runtime, Docker, or Nmap execution changes are made.

Suggested commit:

```text
docs(active): plan nmap availability and packaging
```

Status:

`ACTIVE_NMAP_BASIC_19_NMAP_PACKAGING_PLAN_ACTIVE_RUNNER_RECOMMENDED` records
that future Nmap availability should be provided by a separate Dockerized Active
runner/image such as `active-tools`. Host-local Nmap installation is not the
normal Inspectra requirement, backend direct Nmap execution remains blocked,
the passive runner must not absorb Active/Nmap, and no Docker/Nmap/runtime
changes were made in this docs-only phase.

## Microphase 20: Active Tools Docker Design

Objective:

Design the future Docker/Compose architecture for a separate Active runner
service/image, tentatively `active-tools`, that packages Nmap for
`active_nmap_basic` without implementing Dockerfile, Compose, runtime, service
endpoints, Nmap installation, or Nmap execution.

Probable files:

- `docs/future/active-nmap-basic-active-tools-docker-design.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Nmap installation.
- No Nmap execution.
- No Docker execution.
- No Dockerfile changes.
- No Compose changes.
- No image build.
- No container startup.
- No backend, frontend, or runner runtime changes.
- No runner HTTP endpoint.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No host network approval.
- No privileged container approval.
- No LAN/VPS/domain/public target approval.
- No public scanner behavior.

Expected validations:

- design names the tentative `active-tools` service/image;
- design keeps `active-tools` separate from backend, frontend, audit-tools, and
  `tools/runner/main.py`;
- design proposes a minimal pinned image strategy and future Nmap installation
  strategy without implementing it;
- design proposes disabled-by-default Compose activation with no public port by
  default;
- design covers capabilities, filesystem, tmpfs, resource limits, logs, and
  cleanup;
- design compares internal HTTP, CLI wrapper, and backend internal adapter
  boundary options;
- design explains container loopback versus host loopback;
- design keeps smoke execution blocked until a later phase freezes the
  Dockerized target semantics.

Risks:

- Treating Docker design as approval to modify Compose or Dockerfiles.
- Confusing `127.0.0.1` inside `active-tools` with host loopback.
- Using host network, privileged containers, or broad capabilities to make a
  smoke easier.
- Accidentally exposing `active-tools` as a public scanner.

Acceptance criteria:

- The design accepts `ACTIVE_NMAP_BASIC_20_ACTIVE_TOOLS_DOCKER_DESIGN_ACCEPTED`.
- The design recommends a separate `active-tools` Dockerized Active boundary.
- The design keeps backend direct subprocess execution, passive runner
  absorption, archive/run-all, public targets, LAN/VPS/domain smoke, and public
  scanner behavior blocked.
- No Dockerfile, Compose, runtime, Nmap installation, or Nmap execution changes
  are made.

Suggested commit:

```text
docs(active): design active tools docker packaging
```

Status:

`ACTIVE_NMAP_BASIC_20_ACTIVE_TOOLS_DOCKER_DESIGN_ACCEPTED` records a docs-only
Docker/Compose architecture for `active-tools`: separate service/image,
disabled by default, no public port by default, no host network by default, no
privileged container, no Docker socket, bounded execution, redacted logs, and
continued separation from backend subprocess execution, archive/run-all, and
`tools/runner/main.py`.

## Microphase 21: Active Tools Docker Scaffold No-Run

Objective:

Create the initial `active-tools` Docker/Compose scaffold for future review
without building images, running Docker, executing Nmap, changing backend,
frontend, runner runtime, adding runner HTTP endpoints, or wiring backend live
calls.

Probable files:

- `docker/active-tools/Dockerfile`
- `docker/active-tools/Dockerfile.dockerignore`
- `docker-compose.active-tools.example.yml`
- `tools/tests/test_active_tools_docker_scaffold_static.py`
- `docs/future/active-nmap-basic-active-tools-docker-scaffold-no-run.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Docker build.
- No Docker Compose run.
- No Nmap execution.
- No Nmap smoke.
- No backend integration.
- No runner HTTP endpoint.
- No service availability runtime.
- No target approval.
- No feature flag change.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No LAN/VPS/domain/public target approval.
- No public scanner behavior.

Expected validations:

- Dockerfile exists and uses a minimal Python slim base aligned with current
  service images;
- Dockerfile declares Nmap packaging without running Nmap at build time;
- Dockerfile copies only `tools/active_runner`, not `tools/runner/main.py`;
- Dockerfile exposes no port and defines no scanning healthcheck;
- Compose example is separate from main `docker-compose.yml`;
- Compose example uses profile `active`;
- Compose example has no published ports, no host network, no privileged
  container, no Docker socket, and no passive runner integration;
- Dockerfile ignore excludes `.env`, `.env.*`, `.envrc`, runtime data,
  node modules, caches, and local virtualenvs;
- static tests pass without Docker or Nmap.

Risks:

- Treating scaffold as build/run approval.
- Accidentally letting normal `docker compose up` start `active-tools`.
- Copying passive runner code into the Active image.
- Publishing ports or adding host network to simplify later smoke work.

Acceptance criteria:

- Scaffold files exist and are static-reviewable.
- Main `docker-compose.yml` behavior is unchanged.
- Static tests verify the no-run/no-public/no-passive-runner guardrails.
- Documentation states that `active-tools` is not built, run, or wired yet.
- No Docker, Nmap, probe, DNS, external HTTP, runtime, endpoint, migration, tag,
  or release action occurs.

Suggested commit:

```text
chore(active): scaffold active tools docker packaging
```

Status:

`ACTIVE_NMAP_BASIC_21_ACTIVE_TOOLS_DOCKER_SCAFFOLD_NO_RUN_ACCEPTED` records the
initial `active-tools` Dockerfile, Dockerfile-specific ignore file, separate
Compose example, and static test scaffold. The scaffold remains disabled/no-run:
no Docker build, Docker run, Nmap execution, backend integration, runner HTTP
endpoint, archive/run-all integration, or `tools/runner/main.py` integration was
added.

## Microphase 22: Active Tools Docker Static Review

Objective:

Statically review the `active-tools` Docker/Compose scaffold before any future
build. Decide whether the scaffold is safe to advance to a later build-only
phase without running Docker, building images, starting containers, executing
Nmap, changing runtime, or widening target scope.

Probable files:

- `docs/future/active-nmap-basic-active-tools-docker-static-review.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Docker build.
- No Docker Compose run.
- No container start.
- No Nmap execution.
- No probes.
- No DNS checks.
- No external HTTP traffic.
- No backend runtime changes.
- No frontend runtime changes.
- No runner runtime changes.
- No runner HTTP endpoint.
- No backend-to-active-tools live call.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No LAN/VPS/domain/public target approval.
- No broad ranges, target expansion, NSE/scripts, raw flags, stealth, evasion,
  brute force, exploits, credential validation, crawling, or public scanner
  behavior.

Expected validations:

- Dockerfile uses the accepted minimal Python slim base direction;
- Dockerfile does not run Nmap at build time or as its default command;
- Dockerfile copies only the isolated Active runner package;
- Dockerfile exposes no port and defines no scanning healthcheck;
- Dockerfile does not install broad scanner, exploitation, brute-force,
  crawling, credential, fuzzing, or custom-script tooling;
- Dockerfile switches to a non-root user;
- Dockerfile-specific ignore excludes local environment files, runtime data,
  caches, node modules, frontend build output, and local virtualenvs;
- Compose example is separate from the main Compose file and requires profile
  `active`;
- Compose example publishes no ports, uses no host network, sets no privileged
  mode, mounts no Docker socket, and keeps an internal network;
- static scaffold tests pass without Docker or Nmap;
- documentation records gaps and residual risks before any build-only phase.

Risks:

- Treating static review as approval to build, run, or smoke-test the service.
- Treating package presence as authorization to run scans.
- Forgetting that container loopback is not the same as host loopback.
- Relying on Dockerfile-specific ignore behavior without validating it in the
  future build phase.
- Allowing package drift without base-image digest pinning, Nmap version
  metadata, or build provenance.

Acceptance criteria:

- Static review document exists and names the reviewed files.
- Findings, gaps, residual risks, and remaining blocked work are documented.
- The review explicitly allows only a future separately approved build-only
  phase.
- It preserves no-run/no-Nmap/no-target-traffic/no-runtime boundaries.
- It keeps backend direct subprocess execution, runner HTTP endpoints,
  archive/run-all integration, and passive runner integration blocked.

Suggested commit:

```text
docs(active): review active tools docker scaffold
```

Status:

`ACTIVE_NMAP_BASIC_22_ACTIVE_TOOLS_DOCKER_STATIC_REVIEW_PASSED` records that the
`active-tools` Docker/Compose scaffold passes static review for a future
separately approved build-only phase. The scaffold remains unbuilt, unrun,
disconnected from backend live execution, disconnected from runner HTTP
endpoints, disconnected from archive/run-all, separated from `tools/runner/main.py`,
and not approved for Nmap execution, probes, DNS checks, external HTTP traffic,
or target scanning.

## Microphase 23: Active Tools Docker Build-Only

Objective:

Execute a build-only validation of the `active-tools` Docker scaffold. Confirm
that the image can be built and inspected as local metadata without starting a
container, executing Nmap, changing runtime, or approving any target traffic.

Probable files:

- `docs/future/active-nmap-basic-active-tools-docker-build-only.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No `docker run`.
- No `docker compose up`.
- No `docker exec`.
- No container startup.
- No Nmap execution.
- No `nmap --version` inside a container.
- No probes.
- No DNS checks.
- No external HTTP target traffic.
- No backend runtime changes.
- No frontend runtime changes.
- No runner runtime changes.
- No runner HTTP endpoint.
- No backend-to-active-tools live call.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No LAN/VPS/domain/public target approval.
- No public scanner behavior.

Expected validations:

- existing static scaffold tests pass;
- Compose example parses locally when PyYAML is available;
- `docker build -f docker/active-tools/Dockerfile -t inspectra-active-tools:build-smoke .`
  completes;
- Docker build context remains small enough to support the ignore strategy;
- `docker image inspect inspectra-active-tools:build-smoke` returns image
  metadata without starting the image;
- inspect metadata confirms non-root configured user and no-run scaffold command;
- source searches confirm no passive-runner absorption or no-scope wording
  regression.

Risks:

- Treating build success as approval to run containers or scans.
- Treating package installation as Nmap execution evidence.
- Forgetting that Docker build package traffic is not target traffic.
- Leaving digest pinning and Nmap package pinning unresolved.
- Treating local image metadata as runtime hardening proof.

Acceptance criteria:

- The image builds with the temporary local tag.
- Only image metadata inspection is performed after build.
- No container is started.
- No Nmap command is executed.
- No probes, DNS checks, or external HTTP target traffic occur.
- Documentation records build evidence, local tag, inspect evidence, no-run
  confirmation, gaps, and final decision.

Suggested commit:

```text
test(active): build active tools docker image
```

Status:

`ACTIVE_NMAP_BASIC_23_ACTIVE_TOOLS_DOCKER_BUILD_ONLY_PASSED` records that
`docker build -f docker/active-tools/Dockerfile -t inspectra-active-tools:build-smoke .`
completed successfully and that `docker image inspect` returned image metadata
without starting a container. The phase does not approve container runtime,
Nmap execution, target traffic, backend live calls, runner HTTP endpoints,
archive/run-all integration, `tools/runner/main.py` integration, LAN/VPS/domain
targets, public scanner behavior, or release/tag state.

## Microphase 24: Active Tools Run No-Target Readiness

Objective:

Start the built `active-tools` image exactly once in no-target readiness mode.
Validate that the scaffold default command emits controlled readiness output
under `--network none` without executing Nmap, probing targets, performing DNS
checks, sending external HTTP traffic, changing runtime, or wiring backend
integration.

Probable files:

- `docs/future/active-nmap-basic-active-tools-run-no-target-readiness.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No `docker compose up`.
- No Compose service start.
- No published ports.
- No host network.
- No privileged container.
- No Docker socket mount.
- No bind mounts.
- No sensitive environment variables.
- No Nmap execution.
- No `nmap 127.0.0.1`.
- No `nmap localhost`.
- No `nmap --script`.
- No probes.
- No DNS checks.
- No external HTTP target traffic.
- No backend runtime changes.
- No frontend runtime changes.
- No runner runtime changes.
- No runner HTTP endpoint.
- No backend-to-active-tools live call.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No LAN/VPS/domain/public target approval.
- No public scanner behavior.

Expected validations:

- existing static scaffold tests pass;
- Compose example parses locally when PyYAML is available;
- `docker image inspect inspectra-active-tools:build-smoke` confirms image
  metadata;
- `docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true inspectra-active-tools:build-smoke`
  exits successfully;
- readiness output is controlled JSON with `mode: scaffold_no_run`;
- readiness output may report `nmap_present: true` by path lookup only;
- source searches confirm no passive-runner absorption or no-scope wording
  regression.

Risks:

- Treating no-target container start as scan approval.
- Treating path-based `nmap_present` as Nmap execution.
- Accidentally adding network, published ports, host network, privileged mode,
  Docker socket mounts, or target-bearing commands to make the run easier.
- Letting no-target readiness imply backend integration readiness.

Acceptance criteria:

- The image starts and exits with the strict no-target Docker flags.
- Output is controlled and contains `mode: scaffold_no_run`.
- No Nmap command is executed.
- No target is supplied.
- No probes, DNS checks, or external HTTP target traffic occur.
- No Compose service is started.
- Documentation records run command, observed output, no-run/no-target
  confirmation, remaining gaps, and final decision.

Suggested commit:

```text
test(active): run active tools no-target readiness
```

Status:

`ACTIVE_NMAP_BASIC_24_ACTIVE_TOOLS_RUN_NO_TARGET_READINESS_PASSED` records that
`docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true inspectra-active-tools:build-smoke`
started and exited successfully with controlled scaffold JSON:
`{"service": "active-tools", "mode": "scaffold_no_run", "nmap_present": true}`.
The phase does not approve Nmap execution, target traffic, Compose service
startup, published ports, backend live calls, runner HTTP endpoints,
archive/run-all integration, `tools/runner/main.py` integration, LAN/VPS/domain
targets, public scanner behavior, or release/tag state.

## Microphase 25: Active Tools Nmap Version No-Target

Objective:

Run exactly `nmap --version` inside the built `active-tools` image under
`--network none` and strict Docker runtime flags. Confirm Nmap version/presence
without a target, without scan behavior, without probes, without DNS checks,
without external HTTP target traffic, without Compose, and without backend,
frontend, or runner runtime changes.

Probable files:

- `docs/future/active-nmap-basic-active-tools-nmap-version-no-target.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No target-bearing Nmap command.
- No `nmap 127.0.0.1`.
- No `nmap localhost`.
- No `nmap <hostname>`.
- No `nmap --script`.
- No NSE execution.
- No probes.
- No DNS checks.
- No external HTTP target traffic.
- No `docker compose up`.
- No Compose service start.
- No published ports.
- No host network.
- No privileged container.
- No Docker socket mount.
- No unnecessary bind mounts.
- No sensitive environment variables.
- No backend runtime changes.
- No frontend runtime changes.
- No runner runtime changes.
- No runner HTTP endpoint.
- No backend-to-active-tools live call.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No LAN/VPS/domain/public target approval.
- No public scanner behavior.

Expected validations:

- existing static scaffold tests pass;
- Compose example parses locally when PyYAML is available;
- `docker image inspect inspectra-active-tools:build-smoke` confirms image
  metadata;
- `docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true inspectra-active-tools:build-smoke nmap --version`
  exits successfully;
- output records Nmap version only;
- source searches confirm no passive-runner absorption or no-scope wording
  regression.

Risks:

- Treating `nmap --version` as approval for target-bearing Nmap execution.
- Accidentally adding a target argument or script flag.
- Treating version readiness as backend integration readiness.
- Letting the observed package version imply reproducible pinning.

Acceptance criteria:

- The version command exits successfully with strict no-target Docker flags.
- Output contains Nmap version information.
- No target is supplied.
- No scan is run.
- No probes, DNS checks, or external HTTP target traffic occur.
- No Compose service is started.
- Documentation records command, observed output, version, no-target
  confirmation, remaining gaps, and final decision.

Suggested commit:

```text
test(active): record active tools nmap version
```

Status:

`ACTIVE_NMAP_BASIC_25_ACTIVE_TOOLS_NMAP_VERSION_NO_TARGET_PASSED` records that
`docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true inspectra-active-tools:build-smoke nmap --version`
exited successfully and reported Nmap version `7.95`. The phase does not
approve target-bearing Nmap execution, probes, DNS checks, external HTTP target
traffic, Compose service startup, published ports, backend live calls, runner
HTTP endpoints, archive/run-all integration, `tools/runner/main.py`
integration, LAN/VPS/domain targets, public scanner behavior, or release/tag
state.

## Microphase 26: Active Tools Local Smoke Target Freeze

Objective:

Freeze Dockerized `active-tools` local smoke target semantics before any Nmap
command is run with a target. Clarify that `127.0.0.1` inside `active-tools` is
container loopback, not host loopback, and keep LAN/VPS/domain/public targets
blocked.

Probable files:

- `docs/future/active-nmap-basic-active-tools-local-smoke-target-freeze.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Nmap execution.
- No `nmap --version`.
- No target-bearing Nmap command.
- No probes.
- No DNS checks.
- No external HTTP target traffic.
- No Compose.
- No published ports.
- No host network.
- No privileged container.
- No Docker socket mount.
- No backend runtime changes.
- No frontend runtime changes.
- No runner runtime changes.
- No backend-to-active-tools live call.
- No runner HTTP endpoint.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No approval for LAN, VPS, domain, or public targets.
- No public scanner behavior.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
rg -n "active-tools|active_nmap_basic|Nmap|nmap|127.0.0.1|65000|loopback|container|own-domain|vildek|urlbreve|target freeze" docs README.md
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- Confusing container loopback with host loopback.
- Treating a future `127.0.0.1:65000` container smoke as evidence of external
  exposure.
- Treating operator-owned domains as approved targets before a separate
  own-domain freeze.
- Letting a target freeze become backend integration or public scanner approval.

Acceptance criteria:

- Documentation states that `127.0.0.1` inside `active-tools` is container
  loopback.
- Documentation states that the earlier host-local `127.0.0.1:65000` freeze
  does not automatically equal the Dockerized smoke.
- Option A is recommended for a later first target-bearing Docker smoke:
  exact target `127.0.0.1`, exact port `65000`, Docker `--network none`.
- The future interpretation is "closed-port local container loopback smoke".
- Owned domains `www.vildek.es`, `app.vildek.es`, and `www.urlbreve.es` are
  recorded only as future candidates and remain blocked in this phase.
- LAN/VPS/domain/public targets, Compose service targets, backend integration,
  runner endpoints, archive/run-all, and public scanner behavior remain blocked.

Suggested commit:

```text
docs(active): freeze active tools local smoke target
```

Status:

`ACTIVE_NMAP_BASIC_26_ACTIVE_TOOLS_LOCAL_SMOKE_TARGET_FREEZE_ACCEPTED` records
that the first future Dockerized target-bearing smoke should use only
container-loopback target `127.0.0.1`, port `65000`, and Docker network
disabled with `--network none`, interpreted as a closed-port local container
loopback smoke. The phase does not run Docker or Nmap, does not approve
owned-domain, LAN, VPS, Compose, or public targets, and does not approve backend
live calls, runner endpoints, archive/run-all integration,
`tools/runner/main.py` integration, public scanner
behavior, or release/tag state.

## Microphase 27: Active Tools Container Loopback Smoke

Objective:

Execute the first target-bearing `active-tools` container smoke using only the
frozen target `127.0.0.1`, port `65000`, and Docker `--network none`. Validate
only that an allowlisted minimal Nmap invocation can run inside the container
against its own loopback, without external network, DNS, Compose, backend
integration, or approval for real targets.

Probable files:

- `docs/future/active-nmap-basic-active-tools-container-loopback-smoke.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No target other than `127.0.0.1`.
- No port other than `65000`.
- No `localhost`, `::1`, hostname, domain, LAN, VPS, public, or third-party
  target.
- No `www.vildek.es`, `app.vildek.es`, or `www.urlbreve.es`.
- No Compose.
- No published ports.
- No host network.
- No privileged container.
- No Docker socket mount.
- No unnecessary bind mounts.
- No sensitive environment variables.
- No DNS checks.
- No external HTTP traffic.
- No crawling.
- No NSE or `--script`.
- No service/version detection.
- No OS detection.
- No UDP or SYN scan.
- No brute force.
- No credential validation.
- No raw user flags.
- No backend/frontend/runner runtime changes.
- No runner HTTP endpoint.
- No backend-to-active-tools live call.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No migrations, tags, or releases.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest tools/tests/test_active_tools_docker_scaffold_static.py
.venv/bin/python -c "import pathlib, yaml; yaml.safe_load(pathlib.Path('docker-compose.active-tools.example.yml').read_text()); print('PyYAML available'); print('YAML parsed')"
docker image inspect inspectra-active-tools:build-smoke
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true inspectra-active-tools:build-smoke nmap -sT -Pn -n --max-retries 1 --host-timeout 30s -oX - -p 65000 -- 127.0.0.1
rg -n "active-tools|active_nmap_basic|Nmap|nmap|127.0.0.1|65000|loopback|container|network none|container loopback smoke" docker docs README.md tools
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" docker docs README.md tools
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- Treating a closed container-loopback result as host or domain exposure
  evidence.
- Re-running the target-bearing smoke outside the frozen command.
- Accidentally using `localhost`, a hostname, an owned domain, LAN, VPS, or a
  public target.
- Letting a container-local smoke imply backend integration readiness.

Acceptance criteria:

- Image metadata is recorded.
- The target-bearing command is executed exactly once.
- Command uses only target `127.0.0.1` and port `65000`.
- Command uses Docker `--network none`.
- Command includes `-n` and does not perform DNS resolution.
- Command uses no NSE, `--script`, raw flags, service/version detection, OS
  detection, UDP, SYN scan, brute force, credential validation, crawling, or
  target expansion.
- Observed output is bounded and records only the container-loopback result.
- Documentation states no Compose, backend integration, job, export, runner
  endpoint, archive/run-all, owned-domain, LAN/VPS/public target, runtime
  change, tag, or release is approved.

Suggested commit:

```text
test(active): run active tools container loopback smoke
```

Status:

`ACTIVE_NMAP_BASIC_27_ACTIVE_TOOLS_CONTAINER_LOOPBACK_SMOKE_PASSED` records
that the first target-bearing Dockerized `active-tools` smoke ran exactly once
against container loopback `127.0.0.1:65000` with Docker `--network none` and
the allowlisted `tcp_connect_small` argv shape. Nmap reported `65000/tcp` as
`closed` with `conn-refused`. The phase does not approve host exposure claims,
Compose connectivity, backend integration, jobs, exports, runner endpoints,
archive/run-all integration, owned-domain targets, LAN/VPS/public targets,
runtime changes, public scanner behavior, or release/tag state.

## Microphase 28: Own-Domain Authorized Smoke Target Freeze

Objective:

Freeze one exact operator-authorized own-domain target for a future extremely
limited `active-tools` Nmap smoke without executing Docker, Nmap, DNS checks,
manual HTTP checks, probes, backend integration, runner endpoints, or
archive/run-all. The freeze chooses only one domain and keeps the remaining
candidate domains blocked.

Probable files:

- `docs/future/active-nmap-basic-own-domain-authorized-smoke-target-freeze.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Nmap execution.
- No `nmap --version`.
- No probes.
- No manual DNS checks.
- No manual external HTTP checks.
- No `curl` or browser checks against domains.
- No Compose.
- No published ports.
- No host network.
- No privileged container.
- No Docker socket mount.
- No backend/frontend/runner runtime changes.
- No runner HTTP endpoint.
- No backend-to-active-tools live call.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No migrations, tags, or releases.
- No LAN targets.
- No generic VPS target.
- No arbitrary public target.
- No public scanner behavior.
- No approval of all candidate domains together.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
rg -n "active-tools|active_nmap_basic|Nmap|nmap|own-domain|authorized|[www.urlbreve.es|www.vildek.es|app.vildek.es|443|DNS|target](http://www.urlbreve.es|www.vildek.es|app.vildek.es|443|DNS|target) freeze" docs README.md
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- Treating operator authorization context as independent proof of ownership.
- Accidentally approving all three candidate domains instead of one.
- Keeping `-n` while using an unresolved FQDN.
- Letting a domain freeze imply approval for arbitrary public targets or public
  scanner behavior.
- Letting a future domain smoke add backend integration or runner endpoints in
  the same phase.

Acceptance criteria:

- Exactly one domain is chosen.
- Chosen domain is `www.urlbreve.es`.
- `www.vildek.es` remains blocked.
- `app.vildek.es` remains blocked for later phases because it is a business
  application surface.
- Frozen port set is exactly `[443]`.
- Port `80`, ranges, top ports, `-p-`, and discovery-style port selection remain
  blocked.
- DNS decision is explicit.
- Future command is documented and clearly marked as not executed.
- No backend integration, runner endpoint, archive/run-all, `tools/runner/main.py`
  integration, runtime change, tag, or release is approved.

Suggested commit:

```text
docs(active): freeze own domain nmap smoke target
```

Status:

`ACTIVE_NMAP_BASIC_28_OWN_DOMAIN_AUTHORIZED_SMOKE_TARGET_FREEZE_ACCEPTED`
freezes the first future own-domain smoke target to exactly `www.urlbreve.es`
on port `443`. DNS decision Option A is accepted for a future execution: allow
only the minimum Nmap DNS resolution required for that exact FQDN, with no DNS
expansion, no subdomain discovery, no reverse-DNS sweep, and no manual DNS
checks in this phase. The proposed command is documented but not executed.
`www.vildek.es`, `app.vildek.es`, port `80`, LAN/VPS/public targets, backend
integration, runner endpoints, archive/run-all, `tools/runner/main.py`
integration, public scanner behavior, and release/tag state remain blocked.

## Microphase 29: Own-Domain Authorized Smoke Execution

Objective:

Execute exactly one own-domain authorized `active-tools` Nmap smoke using the
frozen target `www.urlbreve.es`, port `443`, and the `tcp_connect_small` command
shape. Preserve one-shot scope, no raw flags, no scripts/NSE, no manual DNS
checks, no manual HTTP checks, no Compose, no backend integration, no runner
endpoint, no jobs, no exports, and no scope expansion.

Probable files:

- `docs/future/active-nmap-basic-own-domain-authorized-smoke-execution.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No target other than `www.urlbreve.es`.
- No `www.vildek.es`.
- No `app.vildek.es`.
- No more than one domain.
- No port other than `443`.
- No port `80`.
- No ranges, `-p-`, or top ports.
- No LAN target.
- No generic VPS target.
- No third-party target.
- No arbitrary public target.
- No manual DNS checks with `dig`, `host`, `nslookup`, or similar tools.
- No `curl`.
- No browser.
- No manual HTTP checks.
- No Compose.
- No published ports.
- No host network.
- No privileged container.
- No Docker socket mount.
- No bind-mounted target files.
- No sensitive environment variables.
- No raw user flags.
- No NSE or `--script`.
- No service/version detection.
- No OS detection.
- No UDP or SYN scan.
- No brute force.
- No credential validation.
- No crawling.
- No DNS expansion.
- No subdomain discovery.
- No backend/frontend/runner runtime changes.
- No runner HTTP endpoint.
- No backend-to-active-tools live call.
- No jobs.
- No exports.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No migrations, tags, or releases.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest tools/tests/test_active_tools_docker_scaffold_static.py
.venv/bin/python -c "import pathlib, yaml; yaml.safe_load(pathlib.Path('docker-compose.active-tools.example.yml').read_text()); print('PyYAML available'); print('YAML parsed')"
docker image inspect inspectra-active-tools:build-smoke
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true inspectra-active-tools:build-smoke nmap -sT -Pn --max-retries 1 --host-timeout 30s -oX - -p 443 -- www.urlbreve.es
rg -n "active-tools|active_nmap_basic|Nmap|nmap|own-domain|authorized|[www.urlbreve.es|www.vildek.es|app.vildek.es|443|DNS|target](http://www.urlbreve.es|www.vildek.es|app.vildek.es|443|DNS|target) freeze|smoke execution" docker docs README.md tools
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" docker docs README.md tools
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- Treating an `open` result as a confirmed vulnerability.
- Treating the result as proof that production is secure or insecure.
- Treating Nmap's default PTR hostname output as approval for reverse-DNS
  workflow expansion.
- Accidentally approving `www.vildek.es`, `app.vildek.es`, port `80`, or a
  generic public scan after the first domain smoke.
- Letting the smoke imply backend integration readiness.

Acceptance criteria:

- Image metadata is recorded.
- Command is executed exactly once.
- Command uses only target `www.urlbreve.es`.
- Command uses only port `443`.
- Command does not use `-n`, matching the FQDN/DNS Option A freeze.
- Command uses no raw flags, scripts/NSE, service/version detection, OS
  detection, UDP, SYN scan, brute force, credential validation, crawling,
  subdomain discovery, or DNS expansion flags.
- Output is captured as bounded XML.
- Result is interpreted only as observed TCP exposure / review indicator.
- Documentation confirms no manual DNS checks, manual HTTP checks, `curl`,
  browser, Compose, backend integration, jobs, exports, runner endpoints,
  archive/run-all, runtime changes, tags, releases, or public scanner approval.

Suggested commit:

```text
test(active): run own domain nmap smoke
```

Status:

`ACTIVE_NMAP_BASIC_29_OWN_DOMAIN_AUTHORIZED_SMOKE_EXECUTION_PASSED` records
that the first own-domain authorized `active-tools` Nmap smoke ran once against
exact target `www.urlbreve.es`, exact port `443`, and the frozen
`tcp_connect_small` command shape. Nmap reported `443/tcp` as `open` with
reason `syn-ack`. This is only an observed TCP exposure / review indicator for
that exact FQDN at that moment. Nmap also emitted a PTR hostname in XML; no
manual DNS check or reverse-DNS sweep command was run, and future hardening may
prefer IP-freeze plus `-n` if PTR output should be avoided. The phase does not
approve vulnerability claims, exploitability claims, target-safety claims,
full-scan claims, all-ports-found claims, `www.vildek.es`, `app.vildek.es`,
port `80`, backend integration, runner endpoints, jobs, exports,
archive/run-all integration, `tools/runner/main.py` integration, runtime
changes, public scanner behavior, or release/tag state.

## Microphase 30: Active Nmap V0 Technical Smoke Closeout

Objective:

Consolidate the bounded `active-tools` technical smoke block after build-only,
no-target readiness, Nmap version, container-loopback smoke, and the first
own-domain authorized smoke. Freeze what is approved, what is not approved,
residual risks, and the recommended roadmap before any future backend-to-
active-tools integration.

Probable files:

- `docs/future/active-nmap-basic-v0-technical-smoke-closeout.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Nmap execution.
- No `nmap --version`.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No `curl` or browser checks.
- No Compose.
- No backend runtime changes.
- No frontend runtime changes.
- No runner runtime changes.
- No backend-to-active-tools live call.
- No runner HTTP endpoint.
- No real jobs.
- No exports with real live Nmap output.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No approval for `www.vildek.es`.
- No approval for `app.vildek.es`.
- No approval for port `80`.
- No multi-domain scans.
- No LAN, generic VPS, arbitrary public, or public-scanner targets.
- No raw flags, NSE/scripts, service/version detection, OS detection, UDP/SYN,
  brute force, credential validation, crawling, DNS expansion, or reverse-DNS
  sweep.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
rg -n "ACTIVE_NMAP_BASIC_2[3-9]|ACTIVE_NMAP_BASIC_30|active-tools|active_nmap_basic|[www.urlbreve.es|www.vildek.es|app.vildek.es|PTR|443|65000|observed](http://www.urlbreve.es|www.vildek.es|app.vildek.es|PTR|443|65000|observed) TCP exposure|review indicator|closeout" docs README.md
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- Treating the first own-domain smoke as approval for more domains or ports.
- Treating PTR output as acceptable for future backend reports without redaction
  review.
- Letting the smoke block imply backend integration, jobs, exports, or release
  readiness.
- Treating the observed open TCP state as a confirmed vulnerability or
  exploitability finding.

Acceptance criteria:

- Final decision is recorded as
  `ACTIVE_NMAP_BASIC_30_ACTIVE_NMAP_V0_TECHNICAL_SMOKE_CLOSEOUT_ACCEPTED`.
- Documentation summarizes the `inspectra-active-tools:build-smoke` image,
  Nmap `7.95`, `127.0.0.1:65000` closed/conn-refused, and
  `www.urlbreve.es:443` open/syn-ack.
- The PTR hostname observed in XML is recorded as a hardening gap.
- Approved and not-approved scope is explicit.
- Roadmap requires redaction/parser hardening, optional IP-freeze plus `-n`,
  backend-to-active-tools boundary design, controlled job lifecycle, and
  separately frozen future targets.
- No runtime, Docker, Nmap, DNS, HTTP, Compose, backend integration, runner
  endpoint, archive/run-all, job, export, tag, or release change is made.

Suggested commit:

```text
docs(active): close active nmap technical smoke v0
```

Status:

`ACTIVE_NMAP_BASIC_30_ACTIVE_NMAP_V0_TECHNICAL_SMOKE_CLOSEOUT_ACCEPTED`
consolidates the bounded `active-tools` technical smoke block. It approves
`active-tools` only as viable technical packaging and preserves the executed
`www.urlbreve.es:443` smoke as historical evidence only. It does not approve
backend integration, runner endpoints, jobs, exports, archive/run-all,
`tools/runner/main.py`, `www.vildek.es`, `app.vildek.es`, port `80`,
multi-domain scans, LAN/VPS/public target expansion, public scanner behavior,
raw flags, scripts/NSE, service/version detection, brute force, credential
validation, crawling, DNS expansion, reverse-DNS sweep, vulnerability claims,
exploitability claims, target-safety claims, release, or tag state.

## Microphase 31: Real Output Redaction Hardening Design

Objective:

Design parser and redaction hardening for real `active_nmap_basic` output before
any backend/jobs/reports/Raw JSON integration with live Nmap results. Use the
documented `www.urlbreve.es:443` smoke as reference, especially the observed
resolved IP and PTR hostname in XML.

Probable files:

- `docs/future/active-nmap-basic-real-output-redaction-hardening-design.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No parser implementation.
- No redaction runtime implementation.
- No Docker execution.
- No Nmap execution.
- No `nmap --version`.
- No probes.
- No DNS checks.
- No HTTP checks.
- No `curl` or browser checks.
- No Compose.
- No backend runtime changes.
- No frontend runtime changes.
- No runner runtime changes.
- No backend-to-active-tools live call.
- No runner HTTP endpoint.
- No real jobs.
- No exports with real live Nmap output.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No approval for `www.vildek.es`.
- No approval for `app.vildek.es`.
- No approval for port `80`.
- No public scanner behavior.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
rg -n "ACTIVE_NMAP_BASIC_30|ACTIVE_NMAP_BASIC_31|PTR|hostname|hostnames|raw XML|raw args|resolved IP|redaction|Raw JSON|observed TCP exposure|review indicator|www\\.urlbreve\\.es|51\\.38\\.225\\.243|vps-40567620" docs README.md
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- Treating PTR hostnames as harmless display data.
- Showing resolved IPs for FQDN targets by default in reports or Raw JSON.
- Letting raw XML, raw args, stdout, stderr, stylesheet references, service
  labels, or timestamps become stable user-facing contract fields.
- Using reason strings such as `syn-ack` as vulnerability or exploitability
  evidence.

Acceptance criteria:

- Final decision is recorded as
  `ACTIVE_NMAP_BASIC_31_REAL_OUTPUT_REDACTION_HARDENING_DESIGN_ACCEPTED`.
- The design classifies target FQDN, resolved IP, PTR hostname, port/protocol/
  state/reason, service table label, raw args, timestamps, stylesheet reference,
  and runstats.
- Payload v0 allows only minimal structured TCP observations and
  `result_interpretation: observed_exposure_review_indicator`.
- PTR is blocked from UI/API/report/export/Raw JSON.
- Resolved IP for exact FQDN targets is omitted from report/Raw JSON by default.
- Future parser hardening handles malformed/truncated XML, multiple hosts,
  unexpected hostnames, unexpected addresses, and unexpected ports as controlled
  states.
- Future tests cover PTR, service labels, raw args, multiple hostnames,
  malformed/truncated XML, redaction surfaces, and conservative observation
  rendering.

Suggested commit:

```text
docs(active): design real nmap output redaction hardening
```

Status:

`ACTIVE_NMAP_BASIC_31_REAL_OUTPUT_REDACTION_HARDENING_DESIGN_ACCEPTED`
accepts only a docs-first redaction hardening design. It keeps raw XML, raw
args, stdout, stderr, PTR hostnames, non-user hostnames, reverse-DNS data,
stylesheet references, service/banner/version details, and default FQDN resolved
IP display out of future report/export/Raw JSON surfaces. It does not implement
parser or redaction runtime, add backend integration, add runner endpoints,
create jobs, create exports, run Docker, run Nmap, perform DNS/HTTP checks,
approve new targets, or create release/tag state.

## Microphase 32: Real Output Parser Redaction Tests, No Runtime

Objective:

Add synthetic fixtures and offline tests for the Microphase 31 parser/redaction
hardening design. Validate PTR removal, FQDN resolved-IP omission, raw args/raw
XML omission, controlled malformed/truncated states, unsupported multi-host
shapes, accepted-port enforcement, and minimal observed TCP exposure review
indicator payloads without live execution or runtime wiring.

Probable files:

- `tools/tests/fixtures/active_nmap_basic/*.xml`
- `tools/tests/test_active_runner_nmap_basic_parser_redaction.py`
- `tools/tests/test_active_runner_nmap_basic_parser.py`
- `tools/active_runner/nmap_basic/parser.py`
- `tools/active_runner/nmap_basic/result.py`
- `backend/tests/test_backend.py`
- `docs/future/active-nmap-basic-parser-redaction-tests-no-runtime.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Nmap execution.
- No `nmap --version`.
- No DNS checks.
- No probes.
- No HTTP checks.
- No `curl` or browser checks.
- No Compose.
- No backend live endpoint changes.
- No frontend runtime changes.
- No runner HTTP endpoint.
- No backend-to-active-tools live call.
- No real jobs.
- No real exports.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No approval for `www.vildek.es`.
- No approval for `app.vildek.es`.
- No approval for port `80`.
- No public scanner behavior.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_parser_redaction.py
.venv/bin/python -m pytest tools/tests/test_active_runner.py -k "nmap"
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or redaction"
rg -n "PTR|redacted-ptr|203.0.113.10|raw args|resolved IP|Raw JSON|observed_exposure_review_indicator|manual_validation_required|unsupported_shape|malformed|truncated" tools docs README.md
rg -n "vps-40567620|51.38.225.243" tools/tests || true
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- Accidentally copying real IP/PTR data into fixtures.
- Letting raw args, raw XML, stdout, stderr, service data, or script output
  become user-visible payload fields.
- Treating multiple hosts or unexpected ports as normal observations.
- Changing live runner/backend behavior while trying to harden pure helpers.

Acceptance criteria:

- Synthetic fixtures use documentary/synthetic data only.
- PTR, non-user hostnames, FQDN resolved IPs, raw args, raw XML, stdout/stderr,
  stylesheet references, service/version/banner data, and script output do not
  appear in parser/result payloads.
- Minimal TCP observations preserve port, protocol, state, allowlisted reason,
  `manual_validation_required: true`, and
  `result_interpretation: observed_exposure_review_indicator`.
- Container-loopback output keeps `target_kind: container_loopback` and no extra
  hostname/IP display.
- Multiple hosts, unexpected ports, malformed/truncated XML, and NSE-like output
  return controlled states.
- Tests pass without Docker, Nmap, DNS checks, HTTP traffic, Compose, live jobs,
  exports, backend live calls, runner endpoints, archive/run-all, or
  `tools/runner/main.py` integration.

Suggested commit:

```text
test(active): harden nmap output redaction parser
```

Status:

`ACTIVE_NMAP_BASIC_32_REAL_OUTPUT_PARSER_REDACTION_TESTS_NO_RUNTIME_ACCEPTED`
adds synthetic XML fixtures, offline parser/redaction tests, and pure helper
hardening for accepted ports, target kind, multi-host rejection, script/OS
section rejection, and conservative observation metadata. It does not run Docker
or Nmap, perform DNS/HTTP checks, change backend/frontend live endpoints, add
runner HTTP endpoints, create real jobs or exports, integrate archive/run-all,
integrate `tools/runner/main.py`, approve new targets, or create release/tag
state.

## Microphase 33: Backend Report Redaction Real Shape, No Live

Objective:

Add backend/report/export/Raw JSON coverage for the hardened
`active_nmap_basic` shape derived from real-output parser hardening. Use
already-structured synthetic payloads to verify PTR hostnames, resolved IPs for
FQDN targets, raw XML, raw args, commands, stdout/stderr, service/banner/version
details, stylesheet references, and script/NSE-like output do not appear in
backend public surfaces.

Probable files:

- `backend/tests/test_backend.py`
- `backend/app/reporting.py`
- `docs/future/active-nmap-basic-backend-report-redaction-real-shape-no-live.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Nmap execution.
- No `nmap --version`.
- No DNS checks.
- No probes.
- No external HTTP checks.
- No `curl` or browser checks.
- No Compose.
- No backend-to-active-tools live calls.
- No runner HTTP endpoint.
- No real jobs created from `active-tools`.
- No real exports from live execution.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No frontend runtime changes.
- No target approval for `www.vildek.es`.
- No target approval for `app.vildek.es`.
- No approval for port `80`.
- No public scanner behavior.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or redaction"
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_parser_redaction.py
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_parser.py
rg -n "PTR|redacted-ptr|203.0.113.10|raw_xml|raw args|resolved_ip|ptr_hostname|Raw JSON|observed_exposure_review_indicator|manual_validation_required|stylesheet|script_output" backend tools docs README.md
rg -n "vps-40567620|51.38.225.243" backend tools/tests || true
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- Backend Raw JSON, report, or export surfaces expose fields that pure parser
  helpers already omit.
- Legacy or malformed payloads smuggle sensitive values through new key names
  such as `resolved_ip`, `ptr_hostname`, `stylesheet`, or `script_output`.
- Wording drifts from observed exposure / review indicator into vulnerability,
  exploitability, target-safety, full-scan, or all-ports-found claims.
- Wrong-owner reads reveal target metadata through errors or exports.

Acceptance criteria:

- Synthetic backend payload uses only synthetic/documentary values.
- Job detail, list summary, Markdown, HTML, XML, PDF, and backend Redacted Raw
  JSON omit PTR, FQDN resolved IP, raw XML, raw args, commands, stdout/stderr,
  service/banner/version, stylesheet, script/NSE-like output, credentials,
  headers, cookies, and tokens.
- `manual_validation_required` and
  `result_interpretation: observed_exposure_review_indicator` remain visible.
- Allowed observation fields preserve port, protocol, state, and reason.
- Wrong-owner detail/export reads return generic not found.
- No Docker, Nmap, DNS/HTTP, Compose, live backend-to-active-tools call, runner
  HTTP endpoint, active-tools-created job, live export, archive/run-all, or
  `tools/runner/main.py` integration is added.

Suggested commit:

```text
test(active): harden backend nmap report redaction
```

Status:

`ACTIVE_NMAP_BASIC_33_BACKEND_REPORT_REDACTION_REAL_SHAPE_NO_LIVE_ACCEPTED`
adds backend/report/export/Raw JSON tests for the hardened real-output-like
shape and extends backend reporting redaction key coverage for PTR, resolved IP,
stylesheet, and script/NSE-like fields. It does not run Docker or Nmap, perform
DNS/HTTP checks, add live backend-to-active-tools calls, add runner HTTP
endpoints, create real jobs or exports, integrate archive/run-all, integrate
`tools/runner/main.py`, approve new targets, or create release/tag state.

## Microphase 34: Backend Active Tools Boundary Design

Objective:

Design the future backend to `active-tools` boundary for `active_nmap_basic`
before any live calls, runner HTTP endpoint, real jobs, Docker/Nmap execution,
Compose wiring, or runtime changes. Decide architecture, contracts, security,
logging, job lifecycle, error handling, target/DNS policy, redaction, and next
steps.

Probable files:

- `docs/future/active-nmap-basic-backend-active-tools-boundary-design.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Nmap execution.
- No `nmap --version`.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No `curl` or browser checks.
- No Compose.
- No backend runtime changes.
- No frontend runtime changes.
- No runner runtime changes.
- No runner HTTP endpoint.
- No backend-to-active-tools live calls.
- No real jobs.
- No real exports.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No target approval for `www.vildek.es`.
- No target approval for `app.vildek.es`.
- No approval for port `80`.
- No public scanner behavior.
- No migrations, tags, or releases.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
rg -n "ACTIVE_NMAP_BASIC_3[0-4]|active-tools|backend-to-active-tools|boundary|runner HTTP|internal service|Docker socket|archive/run-all|tools/runner/main.py|redaction|Raw JSON|PTR|resolved IP|tcp_connect_small" docs README.md
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- Letting boundary design imply live execution approval.
- Letting `active-tools` become the authorization or ownership authority.
- Accepting backend direct subprocess/import or Docker socket control because
  it appears simpler.
- Exposing a public scanner endpoint or public host port.
- Returning raw XML, stdout/stderr, args, PTR, resolved IP for FQDN, service
  details, local paths, or script output through the boundary.

Acceptance criteria:

- Backend remains responsible for auth, owner scope, request validation, target
  policy, job lifecycle, storage, reporting, and redaction.
- `active-tools` is responsible only for bounded executor execution and
  structured minimal responses.
- Internal private service boundary is the preferred direction, only with no
  public port, private network, feature flag, prior contract validation, double
  timeout, minimal response, redacted logs, and no raw XML/args/stdout/stderr.
- Backend direct subprocess/import, Docker socket, and backend-managed
  `docker exec` are rejected for real execution.
- Future request/response contracts are documented with one target unit,
  accepted ports, neutral correlation, safe statuses, minimal observations,
  manual validation, and observed exposure / review indicator semantics.
- Security, logging, job lifecycle, error handling, target/DNS policy, testing
  roadmap, and still-blocked scope are explicit.
- No runtime, Docker, Nmap, DNS/HTTP, Compose, live call, endpoint, job, export,
  archive/run-all, `tools/runner/main.py`, target approval, tag, or release is
  added.

Suggested commit:

```text
docs(active): design backend active tools boundary
```

Status:

`ACTIVE_NMAP_BASIC_34_BACKEND_ACTIVE_TOOLS_BOUNDARY_DESIGN_ACCEPTED` accepts a
docs-only architecture direction for a private internal backend to `active-tools`
boundary. Backend remains the authority for auth, owner scope, validation,
target policy, jobs, storage, reporting, and redaction; `active-tools` remains a
bounded executor only. The design prefers a no-public-port internal service
boundary for future work and rejects backend direct subprocess/import, Docker
socket control, public scanner behavior, archive/run-all, and
`tools/runner/main.py` integration. It does not implement runtime changes,
Docker/Nmap execution, live calls, runner endpoints, jobs, exports, targets,
tags, or releases.

## Microphase 35: Backend Active Tools Boundary Contract Tests, No Live

Objective:

Add no-live backend contract tests for the future backend to `active-tools`
boundary. Validate request and response shapes, response allowlists, redaction,
controlled error states, and policy drift handling using only pure helpers and
fakes. Do not implement an `active-tools` endpoint, backend live call, Docker or
Nmap execution, Compose wiring, real active-tools jobs, live exports,
archive/run-all, or `tools/runner/main.py` integration.

Probable files:

- `backend/app/active_nmap_boundary.py`
- `backend/tests/test_backend.py`
- `docs/future/active-nmap-basic-backend-active-tools-boundary-contract-tests-no-live.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Nmap execution.
- No `nmap --version`.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No `curl` or browser checks.
- No Compose.
- No real `active-tools` endpoint.
- No backend-to-active-tools live calls.
- No real jobs created from `active-tools`.
- No real exports from live execution.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No frontend runtime changes.
- No target approval for `www.vildek.es`.
- No target approval for `app.vildek.es`.
- No approval for port `80`.
- No public scanner behavior.
- No migrations, tags, or releases.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_parser_redaction.py
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_parser.py
rg -n "active_tools_unavailable|active_tools_timeout|policy_drift|result_too_large|unexpected_fields|fqdn_resolution_failed|manual_validation_required|observed_exposure_review_indicator|raw_xml|ptr_hostname|resolved_ip|boundary" backend docs README.md
rg -n "vps-40567620|51.38.225.243" backend tools/tests || true
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- Contract helper drifts toward live HTTP behavior or endpoint implementation.
- Request shape leaks raw flags, scripts, credentials, target files, or shell
  command fields.
- Response validation allows raw XML, stdout/stderr, args, PTR, resolved IP,
  local paths, service/banner/version data, script output, or unsafe claims.
- Policy drift from `active-tools` is mistaken for a normal completed result.
- Wrong-owner reads expose target metadata.

Acceptance criteria:

- Boundary request builder emits one validated target unit with mode, profile,
  target kind, exact accepted ports, neutral ids, backend-verified
  confirmations, and explicit limits.
- Request builder includes no raw flags, extra args, scripts/NSE, credentials,
  headers, cookies, tokens, target files, target ranges, or shell commands.
- Response validator accepts minimal completed observations and preserves
  `manual_validation_required: true` and
  `result_interpretation: observed_exposure_review_indicator`.
- Response validator rejects or blocks unexpected sensitive fields and response
  ports outside the accepted set.
- Response validator blocks oversized boundary payloads as controlled
  `result_too_large` failures with `output_truncated: true`.
- Error mapping covers `active_tools_unavailable`, `active_tools_timeout`,
  `nmap_missing`, `malformed_output`, `unsupported_shape`, `policy_drift`,
  `result_too_large`, `unexpected_fields`, `network_failure`, and
  `fqdn_resolution_failed`.
- Wrong-owner synthetic reads remain generic 404.
- Archive/run-all and `tools/runner/main.py` remain outside Active Nmap.
- No runtime, Docker, Nmap, DNS/HTTP, Compose, live call, endpoint, real job,
  live export, frontend runtime, target approval, tag, or release is added.

Suggested commit:

```text
test(active): add active tools boundary contract tests
```

Status:

`ACTIVE_NMAP_BASIC_35_BACKEND_ACTIVE_TOOLS_BOUNDARY_CONTRACT_TESTS_NO_LIVE_ACCEPTED`
adds pure backend boundary contract helpers and no-live tests for request
building, response validation, controlled error mapping, policy drift, owner
scope, redaction, and source-boundary checks. It does not add an
`active-tools` endpoint, backend live call, Docker/Nmap execution, Compose
wiring, real active-tools jobs, live exports, archive/run-all,
`tools/runner/main.py` integration, frontend runtime changes, target approval,
tags, or releases.

## Microphase 36: Active Tools Internal Service Skeleton, No Scan

Objective:

Create the pure internal `active-tools` service skeleton for future
`active_nmap_basic` handling. Provide offline-testable health and
`active_nmap_basic` handlers while returning only controlled no-scan states.
Do not run Docker, Compose, Nmap, `nmap --version`, probes, DNS checks, external
HTTP checks, `curl`, or a browser. Do not add backend live calls, backend
runtime wiring, public endpoints, real active-tools jobs, live exports,
archive/run-all integration, `tools/runner/main.py` integration, frontend
runtime changes, target approval, tags, or releases.

Probable files:

- `tools/active_runner/service.py`
- `tools/tests/test_active_tools_internal_service_skeleton.py`
- `docs/future/active-nmap-basic-active-tools-internal-service-skeleton-no-scan.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Compose execution.
- No Nmap execution.
- No `nmap --version`.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No `curl` or browser checks.
- No real `active-tools` server process.
- No public endpoint.
- No backend-to-active-tools live calls.
- No backend runtime change to call the service.
- No real jobs created from `active-tools`.
- No live exports.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No frontend runtime changes.
- No target approval for `www.vildek.es`.
- No target approval for `app.vildek.es`.
- No approval for port `80`.
- No public scanner behavior.
- No migrations, tags, or releases.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest tools/tests/test_active_tools_internal_service_skeleton.py
.venv/bin/python -m pytest tools/tests/test_active_runner.py -k "nmap"
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
rg -n "subprocess|docker|DockerClient|from docker|docker.sock|nmap --version|nmap -sT|Nmap execution|tools/runner/main.py" tools/active_runner tools/tests
rg -n "raw_xml|stdout|stderr|ptr_hostname|resolved_ip|script_output|nse|credentials|cookies|tokens|headers|manual_validation_required|observed_exposure_review_indicator" tools backend docs README.md
rg -n "vps-40567620|51.38.225.243" backend tools/tests || true
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- The skeleton drifts into a live HTTP server or public endpoint.
- The handler imports the real executor or subprocess path.
- Rejection responses leak targets, raw XML, stdout/stderr, command data, PTR,
  resolved IPs, service/banner/version data, script output, credentials,
  cookies, tokens, headers, or unsafe claims.
- Health/readiness starts accepting target-bearing payloads.
- The skeleton implies approval for backend live wiring, Docker/Compose
  runtime, or public scanner behavior.

Acceptance criteria:

- Health/readiness returns `service: active-tools`, controlled readiness, zero
  network requests, no target requirement, and `active_nmap_basic` disabled
  no-scan status.
- Target-bearing health payloads are rejected without target leakage.
- `POST /active/nmap-basic` conceptual handler accepts only the single-unit
  backend boundary shape and returns `not_executed` with
  `manual_validation_required: true`.
- No observation is emitted in this phase; therefore no
  `observed_exposure_review_indicator` result is attached to an empty
  observation set.
- Raw flags, scripts/NSE, extra args, shell command fields, credentials,
  cookies, tokens, headers, target files, multiple targets, target ranges,
  custom profiles, and invalid ports are rejected.
- Skeleton source imports no subprocess, Docker SDK, executor, backend service,
  `tools/runner/main.py`, or live network client.
- Backend runtime and `tools/runner/main.py` remain unchanged for live
  integration.

Suggested commit:

```text
feat(active): add active tools service skeleton
```

Status:

`ACTIVE_NMAP_BASIC_36_ACTIVE_TOOLS_INTERNAL_SERVICE_SKELETON_NO_SCAN_ACCEPTED`
adds a pure internal `active-tools` service skeleton and offline tests for
health/readiness, no-scan `active_nmap_basic`, dangerous-field rejection,
response redaction, dispatch blocking, and source-boundary checks. It does not
add Docker/Compose/Nmap execution, backend live calls, backend runtime wiring,
public endpoints, real active-tools jobs, live exports, archive/run-all,
`tools/runner/main.py` integration, frontend runtime changes, target approval,
tags, or releases.

## Microphase 37: Active Tools Health Readiness Hardening, No Scan

Objective:

Harden the pure internal `active-tools` health/readiness handler so it is
explicitly no-target, no-scan, small, stable, and redaction-safe before any
fake-execution, ASGI/server runtime, or backend live-call phase. Do not run
Docker, Compose, Nmap, `nmap --version`, probes, DNS checks, external HTTP
checks, `curl`, or a browser. Do not start a real server, add a real HTTP
endpoint, add backend live calls, change backend runtime, create real
active-tools jobs, create live exports, integrate archive/run-all, integrate
`tools/runner/main.py`, change frontend runtime, approve targets, create tags,
or create releases.

Probable files:

- `tools/active_runner/service.py`
- `tools/tests/test_active_tools_internal_service_skeleton.py`
- `tools/tests/test_active_tools_health_readiness.py`
- `docs/future/active-nmap-basic-active-tools-health-readiness-hardening-no-scan.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Compose execution.
- No Nmap execution.
- No `nmap --version`.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No `curl` or browser checks.
- No real server process.
- No real HTTP endpoint.
- No backend-to-active-tools live calls.
- No backend runtime change to call the service.
- No real jobs created from `active-tools`.
- No live exports.
- No fake execution.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No frontend runtime changes.
- No target approval for `www.vildek.es`.
- No target approval for `app.vildek.es`.
- No approval for port `80`.
- No public scanner behavior.
- No migrations, tags, or releases.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest tools/tests/test_active_tools_internal_service_skeleton.py
.venv/bin/python -m pytest tools/tests/test_active_tools_health_readiness.py
.venv/bin/python -m pytest tools/tests/test_active_runner.py -k "nmap"
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
rg -n "subprocess|docker|DockerClient|from docker|docker.sock|nmap --version|nmap -sT|Nmap execution|tools/runner/main.py|os.environ|socket.gethostname" tools/active_runner tools/tests
rg -n "raw_xml|stdout|stderr|ptr_hostname|resolved_ip|script_output|nse|credentials|cookies|tokens|headers|network_requests_sent|nmap_executed|disabled_no_scan|scaffold_ready" tools backend docs README.md
rg -n "vps-40567620|51.38.225.243" backend tools/tests || true
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- Health/readiness accepts target, port, credential, header, cookie, token, or
  command-bearing payloads.
- Health/readiness performs host introspection, local path disclosure, Nmap
  path lookup, or Nmap version lookup.
- Rejection responses echo submitted targets, secrets, commands, raw XML,
  stdout/stderr, PTR, resolved IP, service/banner/version data, or unsafe
  claims.
- Readiness metadata is mistaken for a public endpoint or runtime approval.

Acceptance criteria:

- No-payload health returns only `service: active-tools`, `status:
  scaffold_ready`, stable capability metadata, `network_requests_sent: 0`, and
  `nmap_executed: false`.
- Capability metadata marks `active_nmap_basic` as `disabled_no_scan`,
  `execution_enabled: false`, and `target_input_allowed: false`.
- Target, targets, target unit, ports, credentials, headers, cookies, tokens,
  raw command, args, scripts, NSE, local path, environment, and hostname inputs
  are rejected or ignored safely without leakage. The accepted behavior for this
  phase is controlled rejection.
- Health does not expose hostname, local paths, environment variables, Nmap
  version, targets, command/argv, stdout/stderr, raw XML, resolved IP, PTR,
  service/banner/version data, or secrets.
- Method/path dispatch remains controlled.
- Source guards show no subprocess, Docker SDK, `nmap --version`, real
  executor, backend service import, host introspection, or `tools/runner/main.py`
  integration.

Suggested commit:

```text
test(active): harden active tools health readiness
```

Status:

`ACTIVE_NMAP_BASIC_37_ACTIVE_TOOLS_HEALTH_READINESS_HARDENING_NO_SCAN_ACCEPTED`
hardens pure `active-tools` health/readiness so it accepts only absent/empty
payloads, returns stable `disabled_no_scan` capability metadata, blocks
target/port/credential/header/cookie/token/command/script/NSE payloads without
leakage, and remains no-scan/no-live. It does not add Docker/Compose/Nmap
execution, backend live calls, backend runtime wiring, public endpoints, real
active-tools jobs, live exports, archive/run-all, `tools/runner/main.py`
integration, frontend runtime changes, target approval, tags, or releases.

## Microphase 38: Active Tools Fake Execution Through Boundary, No Live

Objective:

Add a fake/no-live execution path through the pure internal `active-tools`
boundary so `active_nmap_basic` can validate one synthetic executor response in
offline tests without enabling real Nmap execution, Docker/Compose runtime,
backend live calls, public endpoints, real jobs, live exports, or frontend
runtime behavior.

Probable files:

- `tools/active_runner/service.py`
- `tools/tests/test_active_tools_fake_execution_boundary.py`
- `tools/tests/test_active_tools_internal_service_skeleton.py`
- `docs/future/active-nmap-basic-active-tools-fake-execution-boundary-no-live.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Compose execution.
- No Nmap execution.
- No `nmap --version`.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No `curl` or browser checks.
- No real server process.
- No real HTTP endpoint.
- No backend-to-`active-tools` live calls.
- No backend runtime change to call the service.
- No real jobs created from `active-tools`.
- No live exports.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No frontend runtime changes.
- No target approval for `www.vildek.es`.
- No target approval for `app.vildek.es`.
- No approval for port `80`.
- No public scanner behavior.
- No migrations, tags, or releases.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest tools/tests/test_active_tools_fake_execution_boundary.py
.venv/bin/python -m pytest tools/tests/test_active_tools_health_readiness.py
.venv/bin/python -m pytest tools/tests/test_active_tools_internal_service_skeleton.py
.venv/bin/python -m pytest tools/tests/test_active_runner.py -k "nmap"
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
rg -n "subprocess|docker|DockerClient|from docker|docker.sock|nmap --version|nmap -sT|Nmap execution|tools/runner/main.py" tools/active_runner tools/tests
rg -n "raw_xml|stdout|stderr|ptr_hostname|resolved_ip|script_output|nse|credentials|cookies|tokens|headers|manual_validation_required|observed_exposure_review_indicator|policy_drift|not_executed" tools backend docs README.md
rg -n "vps-40567620|51.38.225.243" backend tools/tests || true
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- The fake executor becomes a hidden live execution seam instead of a pure
  injected test helper.
- Default handling changes from `not_executed` to a fake completed state.
- Fake responses echo targets, raw XML, stdout/stderr, PTR, resolved IP,
  service/banner/version data, commands, credentials, cookies, tokens, headers,
  or unsafe vulnerability/exploitability wording.
- Fake observations include ports outside the backend-accepted set.
- Backend or runner code starts importing the pure service module as runtime
  wiring.

Acceptance criteria:

- `handle_active_nmap_basic_no_scan(payload)` without executor still returns
  `not_executed`, `network_requests_sent: 0`, `summary.nmap_executed: false`,
  `job_created: false`, and no observations.
- A keyword-only injected fake executor can return a minimal synthetic
  `443/tcp open syn-ack` observation in offline tests only.
- The executor receives only a sanitized request with sorted accepted ports and
  no raw flags, scripts/NSE, credentials, cookies, tokens, headers, shell
  commands, target files, raw XML, stdout/stderr, PTR, or resolved-IP fields.
- Fake responses are allowlisted, accepted-port checked, metadata-bounded, and
  forced to `manual_validation_required: true` plus
  `observed_exposure_review_indicator`.
- Fake executor exceptions and fake timeout/error states map to controlled
  responses without leakage.
- Source guards show no subprocess, Docker SDK, Docker socket, Nmap version
  call, real executor import, backend import, or `tools/runner/main.py`
  integration.

Suggested commit:

```text
test(active): add active tools fake boundary execution
```

Status:

`ACTIVE_NMAP_BASIC_38_ACTIVE_TOOLS_FAKE_EXECUTION_BOUNDARY_NO_LIVE_ACCEPTED`
adds an explicitly injected fake executor path for offline boundary tests while
preserving default `not_executed` behavior. Synthetic responses are allowlisted,
metadata-bounded, accepted-port checked, redaction-safe, and worded only as
observed exposure / review indicators. It does not add Docker/Compose/Nmap
execution, backend live calls, backend runtime wiring, public endpoints, real
active-tools jobs, live exports, archive/run-all, `tools/runner/main.py`
integration, frontend runtime changes, target approval, tags, or releases.

## Microphase 39: Active Tools ASGI Service Skeleton, No Live

Objective:

Create a minimal internal ASGI app skeleton for `active-tools`, reusing the pure
handlers for health/readiness and `active_nmap_basic`, without starting a real
server, adding backend live calls, changing backend runtime, running
Docker/Compose/Nmap, creating real jobs, creating live exports, or approving
new targets.

Product direction:

- Keep the focus on Active/Nmap integration.
- Do not return to Passive work in this phase.
- Prefer a pragmatic OSS integration path over enterprise-style platform
  machinery.
- Avoid future hardening phases unless they directly unblock integration or
  materially reduce risk.

Probable files:

- `tools/active_runner/app.py`
- `tools/tests/test_active_tools_asgi_service_skeleton.py`
- `docs/future/active-nmap-basic-active-tools-asgi-service-skeleton-no-live.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Docker execution.
- No Compose execution.
- No Nmap execution.
- No `nmap --version`.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No `curl` or browser checks.
- No real server process.
- No uvicorn/gunicorn startup.
- No backend-to-`active-tools` live calls.
- No backend runtime change to call the service.
- No real jobs created from `active-tools`.
- No live exports.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No frontend runtime changes.
- No target approval for `www.vildek.es`.
- No target approval for `app.vildek.es`.
- No approval for port `80`.
- No public scanner behavior.
- No migrations, tags, or releases.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest tools/tests/test_active_tools_asgi_service_skeleton.py
.venv/bin/python -m pytest tools/tests/test_active_tools_fake_execution_boundary.py
.venv/bin/python -m pytest tools/tests/test_active_tools_health_readiness.py
.venv/bin/python -m pytest tools/tests/test_active_tools_internal_service_skeleton.py
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
rg -n "subprocess|docker|DockerClient|from docker|docker.sock|nmap --version|nmap -sT|tools/runner/main.py" tools/active_runner tools/tests
rg -n "raw_xml|stdout|stderr|ptr_hostname|resolved_ip|script_output|nse|credentials|cookies|tokens|headers|manual_validation_required|observed_exposure_review_indicator|not_executed|disabled_no_scan" tools backend docs README.md
rg -n "vps-40567620|51.38.225.243" backend tools/tests || true
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- The ASGI app is mistaken for public runtime approval.
- A test-only fake executor path becomes default live execution.
- The app imports backend runtime, the real Nmap executor, Docker SDK,
  subprocess, uvicorn/gunicorn startup, or `tools/runner/main.py`.
- Unknown methods/paths fall back to framework defaults that echo submitted
  targets or secrets.
- Health/readiness begins accepting target-bearing payloads.

Acceptance criteria:

- `GET /health` returns stable `scaffold_ready` readiness with
  `active_nmap_basic.status: disabled_no_scan`, `network_requests_sent: 0`, and
  `nmap_executed: false`.
- `POST /active/nmap-basic` accepts the existing boundary request and returns
  `not_executed` by default.
- Body/query target payloads for health are controlled and do not leak values.
- Dangerous Nmap-basic request fields, multi-target shapes, ranges, and invalid
  ports are rejected without leakage.
- An injected fake executor can be used only through app construction in tests.
- Wrong methods and unknown paths return controlled bodies.
- Source guards show no subprocess, Docker SDK, Docker socket, Nmap version
  call, Nmap command literal, real executor import, backend import,
  uvicorn/gunicorn startup, or `tools/runner/main.py` integration.

Suggested commit:

```text
feat(active): add active tools asgi skeleton
```

Status:

`ACTIVE_NMAP_BASIC_39_ACTIVE_TOOLS_ASGI_SERVICE_SKELETON_NO_LIVE_ACCEPTED`
adds a minimal internal ASGI app skeleton for `active-tools`, with
`GET /health` and `POST /active/nmap-basic` reusing pure handlers and remaining
no-live by default. It does not add Docker/Compose/Nmap execution, backend live
calls, backend runtime wiring, public endpoints, real active-tools jobs, live
exports, archive/run-all, `tools/runner/main.py` integration, frontend runtime
changes, target approval, tags, or releases.

## Microphase 40: Active Tools ASGI Container No-Live Smoke

Objective:

Validate that the internal `active-tools` ASGI app can start inside the
separate `active-tools` container and answer `GET /health` in no-live mode,
without executing Nmap, calling backend, creating jobs, wiring Compose runtime,
or approving targets.

Product direction:

- Keep the focus on practical Active/Nmap integration.
- Prefer a small OSS-friendly container smoke over abstract hardening.
- Treat this as service-start readiness only, not live scan approval.

Probable files:

- `docker/active-tools/Dockerfile`
- `docker/active-tools/requirements.txt`
- `tools/tests/test_active_tools_docker_scaffold_static.py`
- `docs/future/active-nmap-basic-active-tools-asgi-container-no-live-smoke.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No-scope:

- No Nmap execution.
- No `nmap --version`.
- No target-bearing scan command.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No browser or curl against targets.
- No backend-to-`active-tools` live calls.
- No backend runtime change.
- No real jobs created from `active-tools`.
- No live exports.
- No Compose runtime wiring requirement.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No frontend runtime changes.
- No target approval for `www.vildek.es`.
- No target approval for `app.vildek.es`.
- No approval for port `80`.
- No public scanner behavior.
- No migrations, tags, or releases.

Expected validations:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest tools/tests/test_active_tools_asgi_service_skeleton.py
.venv/bin/python -m pytest tools/tests/test_active_tools_fake_execution_boundary.py
.venv/bin/python -m pytest tools/tests/test_active_tools_health_readiness.py
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
docker build -f docker/active-tools/Dockerfile -t inspectra-active-tools:asgi-smoke .
docker run --rm -d --name inspectra-active-tools-asgi-smoke --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true -p 127.0.0.1:18080:8080 inspectra-active-tools:asgi-smoke python -m uvicorn active_runner.app:app --host 0.0.0.0 --port 8080
docker rm -f inspectra-active-tools-asgi-smoke
rg -n "subprocess|docker.sock|nmap --version|nmap -sT|tools/runner/main.py" tools/active_runner tools/tests docker docs README.md
rg -n "raw_xml|stdout|stderr|ptr_hostname|resolved_ip|script_output|nse|credentials|cookies|tokens|headers|disabled_no_scan|scaffold_ready|network_requests_sent|nmap_executed" tools backend docs README.md
rg -n "vps-40567620|51.38.225.243" backend tools/tests || true
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Risks:

- A manually started ASGI smoke is mistaken for product runtime exposure.
- A loopback host publish is mistaken for public service approval.
- Minimal ASGI packaging is confused with live execution readiness.
- The service-start smoke accidentally expands into `/active/nmap-basic`,
  backend calls, Compose wiring, or Nmap execution.

Acceptance criteria:

- The image builds with minimal ASGI runtime packaging.
- The default Dockerfile `CMD` remains scaffold no-run readiness.
- The container starts with read-only filesystem, tmpfs `/tmp`, dropped
  capabilities, no-new-privileges, no host network, no privileged mode, no
  Docker socket, and host publish bound only to `127.0.0.1`.
- `GET /health` returns `service: active-tools`, `status: scaffold_ready`,
  `active_nmap_basic.status: disabled_no_scan`, `execution_enabled: false`,
  `target_input_allowed: false`, `network_requests_sent: 0`, and
  `nmap_executed: false`.
- The container is cleaned up after the smoke.
- No Nmap, DNS, probes, external target HTTP, backend live call, real job,
  export, frontend runtime, archive/run-all, or `tools/runner/main.py`
  integration occurs.

Suggested commit:

```text
test(active): smoke active tools asgi no live
```

Status:

`ACTIVE_NMAP_BASIC_40_ACTIVE_TOOLS_ASGI_CONTAINER_NO_LIVE_SMOKE_PASSED`
packages minimal ASGI runtime dependencies in the separate `active-tools` image,
keeps the default scaffold no-run command, starts the ASGI app manually in a
hardened local container, and confirms `GET /health` returns
`scaffold_ready` / `disabled_no_scan` with `network_requests_sent: 0` and
`nmap_executed: false`. It does not execute Nmap, run `nmap --version`, probe
targets, perform DNS checks, send external target HTTP, call backend, create
jobs or exports, wire Compose runtime, integrate archive/run-all, integrate
`tools/runner/main.py`, change frontend runtime, approve targets, or create
release/tag state.

## Cross-Phase Validation Checklist

Every implementation phase should run the smallest relevant subset plus final
whitespace checks. Later phases should broaden coverage.

Expected recurring checks:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
rg -n "active_nmap_basic|Nmap|nmap|Active" README.md docs/architecture.md docs/security-scope.md docs/future backend frontend tools
rg -n "arbitrary internet scanning|broad ranges|wide ranges|exploit|brute force|credential validation|crawling|SaaS|public scanner|confirmed vulnerability|exploitable|target is safe|scan the internet|full network scan" README.md docs/architecture.md docs/security-scope.md docs/future backend frontend tools
```

Expected implementation test groups, introduced only when relevant runtime files
exist:

```text
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic"
.venv/bin/python -m pytest tools/tests/test_active_runner.py -k "nmap"
.venv/bin/python -m pytest backend/tests/test_backend.py
npm run test -- --run ActiveNmapBasicJobReport App dashboardFilters reportHelpers
npm run test -- --run
npm run build
```

These commands are future implementation expectations. This docs-only planning
phase does not run Nmap, Docker, probes, DNS checks, external HTTP checks, or
runtime test suites.

## Release And Closeout Gates

`active_nmap_basic` must not be treated as releasable until all of the following
are true:

- design and implementation plan are both frozen;
- backend contract is reviewed;
- target policy is reviewed;
- command builder is reviewed;
- runner execution control is reviewed;
- parser behavior is reviewed;
- redaction/reporting is reviewed;
- frontend UX is reviewed;
- backend, runner, and frontend tests pass;
- local smoke records no unauthorized external traffic;
- docs preserve local/private/self-hosted scope;
- final closeout explicitly says what is and is not approved.

No tag or release should be created from this plan. A future implementation
closeout must be separate from a release decision.

## Final Decision

```text
ACTIVE_NMAP_BASIC_IMPLEMENTATION_PLAN_FROZEN
```

The future implementation path for `active_nmap_basic` is planned as small,
reviewable, safety-gated microphases. This document does not implement runtime
behavior, add endpoints, modify backend/frontend/runner code, install or execute
Nmap, run Docker, run probes, perform DNS checks, perform external HTTP checks,
create migrations, create tags, create releases, or approve arbitrary internet
scanning.
