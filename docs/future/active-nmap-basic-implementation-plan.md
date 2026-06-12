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
11. Backend tests.
12. Runner tests.
13. Frontend tests.
14. Final local smoke with no unauthorized external traffic.

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

## Microphase 11: Backend Tests

Objective:

Run focused and full backend tests for the accepted backend/reporting contract.
This phase may be a review/test-only commit if implementation commits were kept
small.

Probable files:

- `backend/tests/test_backend.py`
- maybe backend report/export fixtures
- `docs/future/active-nmap-basic-backend-review.md` if a review record is useful

No-scope:

- No new runtime behavior.
- No Nmap execution.
- No frontend changes.
- No Docker execution.
- No external traffic.

Expected validations:

- disabled-state contract;
- enabled creation contract;
- auth-required denial before validation detail;
- owner-scoped reads/exports/Raw JSON;
- target policy rejection;
- port/target bounds;
- report/export redaction;
- no forbidden copy;
- no archive action path.

Risks:

- Focused tests passing while full suite reveals regressions.
- Tests accidentally relying on local environment state.
- Review docs drifting from actual test evidence.

Acceptance criteria:

- Focused backend tests pass.
- Full backend suite passes or any skipped scope is explicitly justified.
- Test output records no Nmap, Docker, DNS, probe, or external HTTP execution.

Suggested commit:

```text
test(active): cover nmap basic backend contract
```

## Microphase 12: Runner Tests

Objective:

Run focused runner tests for target policy mirroring, command builder,
subprocess control, output bounds, parser behavior, and redaction.

Probable files:

- `tools/tests/test_active_runner.py`
- `tools/active_runner/active_nmap_basic.py`
- controlled fixtures under `tools/tests/fixtures/` if needed
- optional runner review doc

No-scope:

- No unauthorized external traffic.
- No broad scan fixtures.
- No real credentials.
- No real `.env` contents.
- No Docker execution as a test dependency.

Expected validations:

- command builder no-shell behavior;
- forbidden flags absent;
- fake subprocess receives allowlisted argv only;
- timeout path kills fake process and truncates output;
- parser handles completed, timed-out, truncated, malformed, sparse, and blocked
  payloads;
- redaction covers stdout, stderr, command fragments, and target display;
- source search confirms no passive runner integration.

Risks:

- Mocked subprocess tests missing real process-control issues.
- Fixture XML accidentally becoming too large or too revealing.
- Tests allowing `subprocess(..., shell=True)`.

Acceptance criteria:

- Runner focused tests pass.
- No real Nmap is required for default test execution.
- Real Nmap smoke, if ever needed, is deferred to the final local smoke plan.

Suggested commit:

```text
test(active): cover nmap basic runner controls
```

## Microphase 13: Frontend Tests

Objective:

Run focused and full frontend tests for the panel, confirmations, request body,
catalog/filter metadata, reports, and Raw JSON redaction.

Probable files:

- `frontend/src/App.test.tsx`
- `frontend/src/ActiveNmapBasicJobReport.test.tsx`
- `frontend/src/dashboardFilters.test.ts`
- `frontend/src/reportHelpers.test.ts`
- optional frontend review doc

No-scope:

- No backend changes.
- No runner changes.
- No Nmap execution.
- No external traffic.
- No browser storage auth state changes.

Expected validations:

- disabled-state copy;
- enabled panel copy;
- confirmation gating;
- exact request payload;
- blocked/failed/completed/truncated/malformed report rendering;
- job table target redaction;
- Raw JSON redaction;
- forbidden-copy absence;
- no archive action integration.

Risks:

- UI tests miss copy that implies broad scanning.
- Raw JSON viewer diverges from report redaction.
- Dashboard filter labels imply production readiness.

Acceptance criteria:

- Focused frontend tests pass.
- Full frontend test run and build pass when appropriate.
- No forbidden copy appears in frontend source or rendered output.

Suggested commit:

```text
test(active): cover nmap basic frontend flow
```

## Microphase 14: Final Local Smoke, No Unauthorized External Traffic

Objective:

Record a final controlled local smoke after implementation and tests are green.
This smoke must not use third-party targets or unauthorized external traffic.

Probable files:

- `docs/future/active-nmap-basic-local-smoke.md`
- maybe test harness docs if a local fake Nmap fixture is used
- no runtime files unless a defect fix is separately scoped

No-scope:

- No public internet targets.
- No arbitrary internet scanning.
- No broad ranges.
- No third-party demo targets.
- No production policy relaxation.
- No Nmap run against unauthorized hosts.
- No Docker execution unless a separate smoke block explicitly approves it.
- No tags or releases.

Expected validations:

- default disabled flag rejects job creation;
- enabled local/private/self-hosted configuration is explicit;
- smoke target is controlled and authorized, or Nmap is faked/mocked;
- target count and port count are within frozen limits;
- no raw flags are accepted;
- no shell execution is observed;
- no NSE, stealth, evasion, brute force, exploit, credential validation,
  crawling, or DNS expansion behavior occurs;
- reports and Raw JSON remain redacted;
- no-scope search confirms no broad scanning or confirmed-vulnerability claims.

Risks:

- Local smoke accidentally reaches external networks.
- Local lab exceptions become production policy.
- Smoke evidence is mistaken for release readiness.
- Target-side logs contain scan evidence outside Inspectra cleanup control.

Acceptance criteria:

- Smoke record names the target-control method.
- No unauthorized external traffic is used.
- The result remains internal/local/private, not production or public readiness.
- Any defects are fixed in separate commits before closeout.

Suggested commit:

```text
test(active): record nmap basic local smoke
```

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
