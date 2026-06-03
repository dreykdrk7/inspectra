# Active Network Block 25 Active Alpha Closeout

Status: `ACTIVE_ALPHA_V0_CLOSED_INTERNAL_LIMITED`.

README/copy polish: `docs/future/active-network-block-24-active-alpha-readme-linking-and-copy-polish.md`

Passive alpha readiness recheck: `docs/future/active-network-block-26-passive-alpha-readiness-recheck.md`

Smoke execution: `docs/future/active-network-block-23-limited-live-smoke-test-execution.md`

Operator guide: `docs/future/active-network-block-22-active-alpha-operator-guide.md`

Internal alpha planning: `docs/future/active-network-block-21-active-alpha-checkpoint-release-planning.md`

Local smoke method: `docs/future/active-network-block-20-limited-live-smoke-run-local.md`

Limited live closeout: `docs/future/active-network-block-18-authorized-http-header-probe-closeout.md`

Commit scope: docs-only Active Alpha v0 closeout. This block does not change backend, frontend, runner, tests, fixtures, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
ACTIVE_ALPHA_V0_CLOSED_INTERNAL_LIMITED
```

Active Alpha v0 is closed as an internal, limited package. It includes no-network dry-run planning plus one opt-in, authorized, one-HEAD HTTP header probe capability. It is not closed for production, external users, Nmap, broader live checks, or additional Active capability.

## Closed Active Alpha V0 State

The closed internal alpha package includes:

- `active_network_dry_run` as no-network planning.
- `active_http_header_probe` as the only limited live capability.
- Operator guidance for trusted internal use.
- A test-double smoke execution record.
- README, architecture, and security-scope copy polish.
- Explicit no-scope boundaries for production readiness, external-user readiness, policy relaxation, Nmap, and broader Active behavior.

The live capability remains:

- opt-in;
- disabled by default;
- target-based with `file_id: null`;
- limited to one explicit `http://` or `https://` target;
- gated by explicit authorization and live-traffic confirmation;
- capped to at most one HTTP `HEAD` request;
- bounded by fail-closed target policy and defensive redaction.

## Accepted Evidence

Accepted evidence for this closeout:

- Block 18 closed `active_http_header_probe` v0 as a narrow, opt-in, authorized one-HEAD live capability.
- Block 20 accepted the local smoke method based on fake resolver/fake HEAD transport and in-process API/UI test doubles, not production loopback/private policy relaxation.
- Block 21 accepted internal alpha planning for trusted operators only.
- Block 22 accepted an internal operator guide without bypasses, external demo targets, or runtime changes.
- Block 23 executed the accepted test-double smoke subset.
- Block 24 aligned README, architecture, and security-scope copy without dangerous positive claims.

Block 23 smoke results:

```text
runner: 9 passed, 21 deselected
backend: 8 passed, 198 deselected
frontend: 4 files passed, 80 tests passed
```

These results verify contracts, redaction, disabled-state behavior, blocked-target behavior, reporting/export rendering, and frontend rendering using test doubles. They do not prove live target truth.

## Included Capabilities

### `active_network_dry_run`

No-network planning only:

- target-based job with `file_id: null`;
- no DNS;
- no HTTP;
- no sockets;
- no subprocess probes;
- no Nmap;
- `network_requests_sent: 0`;
- policy decisions and blocked reasons are planning outputs.

### `active_http_header_probe`

The only limited live capability:

- disabled by default through feature flag;
- explicit authorization and live-traffic confirmation required;
- one explicit `http://` or `https://` target;
- URL userinfo rejected;
- fail-closed target policy;
- at most one HTTP `HEAD` request;
- no redirects;
- no body reads;
- no GET fallback;
- no custom headers;
- no auth or cookies;
- no crawling;
- no port scanning;
- no Nmap.

This is not a broader scanner and must not be described as one.

## Closed No-Scope

Active Alpha v0 does not include:

- Nmap;
- port scanning;
- crawling;
- redirects;
- GET fallback;
- body reads;
- custom headers;
- auth or cookies;
- fuzzing;
- exploitation;
- credential validation;
- multiple target expansion;
- third-party demo targets;
- production readiness;
- external-user readiness;
- local-lab mode;
- loopback/private production policy relaxation;
- any additional Active capability.

## Internal Alpha Use Conditions

Internal alpha use requires:

- trusted environment;
- trusted operator;
- target owned by the operator or explicitly authorized for this exact one-HEAD check;
- live feature flag enabled only in the intended trusted environment;
- double confirmation;
- understanding that one HTTP `HEAD` request may appear in target logs;
- acceptance that redaction is defensive and best-effort;
- understanding that authorization is a user assertion, not proof of ownership;
- acceptance of local retention for targets, summaries, results, reports, exports, controlled errors, and Raw JSON;
- no attempt to relax production loopback/private target policy.

## Residual Risks

- Test-double smoke does not validate a real target.
- Redaction is best-effort and may miss unusual secret formats.
- Authorization does not prove target ownership.
- Operator misuse remains possible if the feature flag is enabled outside the intended trusted context.
- One real future `HEAD` request can be logged by the target.
- Real loopback/private smoke requires a separate docs-first design and must not weaken production policy by default.
- Broader Active behavior requires a separate docs-first review, safety review, implementation block, and redaction review.

## Release And Readiness Statement

Closed for:

- internal alpha planning;
- trusted internal operator guidance;
- test-double smoke evidence;
- a narrow, opt-in, one-HEAD live capability.

Not closed for:

- production;
- external users;
- Nmap;
- port scanning;
- crawling;
- broader Active scanning;
- another live capability;
- local-lab mode;
- production target-policy relaxation.

## Product Decision Gate

Before any new Active capability, require:

- docs-first scope;
- safety review;
- threat and no-scope review;
- redaction review;
- focused tests;
- operator-copy review;
- no-external-demo-target rule;
- explicit product acceptance.

No future Active block should infer permission from this closeout to add Nmap, broader target support, crawling, port checks, credential validation, exploitation, or local policy bypasses.

## Closeout Checklist

- README aligned.
- Architecture aligned.
- Security scope aligned.
- Operator guide exists.
- Smoke execution record exists.
- No-scope is visible.
- Forbidden-copy review was completed in Block 24.
- No runtime changes.
- No policy relaxation.
- No new capability.
- No external target traffic.
- No `.env`, `.env.*`, or `.envrc` reads.

## Next Recommendation

Completed next microphase:

```text
ACTIVE-NETWORK-BLOCK-26-PASSIVE-ALPHA-READINESS-RECHECK
```

Rationale:

- Active Alpha v0 is now packaged as internal and limited.
- Product should return to release/readiness posture before choosing any new Active work.
- The passive alpha and broader product handoff can be rechecked without expanding live behavior.

Alternative next paths:

- `ACTIVE-NETWORK-BLOCK-26-NEXT-LIVE-CAPABILITY-DESIGN-DOCS-FIRST` only if product explicitly decides to broaden Active after this closeout.
- `ACTIVE-NETWORK-BLOCK-26-LOCAL-LAB-MODE-DESIGN-DOCS-FIRST` only if real loopback/private smoke is required without touching production policy.
- `ACTIVE-NETWORK-BLOCK-26-NMAP-SCOPE-DECISION-DOCS-FIRST` only if product wants to discuss Nmap scope without implementation.

Do not proceed directly from this closeout to implementation of another Active capability.

## Validation Commands

Reference checks for this docs-only block:

```text
git status --short
git status --branch --short
git log --oneline -10
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
