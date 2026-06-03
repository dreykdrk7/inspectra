# Active Network Block 21 Active Alpha Checkpoint Release Planning

Status: `ACTIVE_LIMITED_LIVE_INTERNAL_ALPHA_PLANNING_ACCEPTED`.

Base smoke method: `docs/future/active-network-block-20-limited-live-smoke-run-local.md`

Hardening checkpoint: `docs/future/active-network-block-19-limited-live-hardening-checkpoint.md`

Limited live closeout: `docs/future/active-network-block-18-authorized-http-header-probe-closeout.md`

Commit scope: docs-first internal alpha planning only. This block does not change runtime, tests, fixtures, feature flags, tags, release artifacts, or any Active network behavior.

## Decision

`ACTIVE_LIMITED_LIVE_INTERNAL_ALPHA_PLANNING_ACCEPTED`

Inspectra may treat the limited Active line as ready for internal alpha planning, not as production readiness and not as approval for broader live scanning.

This decision is intentionally narrow:

- Active dry-run remains a no-network planning capability.
- `active_http_header_probe` remains the only limited live capability.
- The live capability remains opt-in, disabled by default, double-confirmed, target-based, and limited to at most one HTTP `HEAD` request.
- The accepted local smoke path remains the Block 20 test-double method, not a relaxation of production loopback/private target policy.
- Nmap, port scanning, crawling, multiple-target probing, redirects, response body reads, custom headers, auth/cookies, credential validation, fuzzing, exploitation, and target expansion remain out of scope.

## Current Active Line

The current Active line has these closed or accepted checkpoints:

- No-network dry-run v0 is closed.
- Authorized HTTP header probe v0 is closed as the first limited live capability.
- Backend/API/storage/reporting/export and frontend E2E-style redaction reviews have passed for the one-HEAD path.
- The limited live hardening checkpoint was accepted for the next docs-first step only.
- The local smoke method was accepted using fake resolver/fake HEAD transport and in-process API/UI test doubles.

No production policy has been weakened to support local smoke.

## What Internal Alpha Means

Internal alpha means a trusted operator can plan how to exercise the existing limited Active capability in a controlled environment with explicit feature flags, clear copy, and known restrictions.

Internal alpha does not mean:

- Enabled by default.
- External-user readiness.
- Production deployment readiness.
- Authorization or ownership proof for a target.
- Safe permission to test third-party targets.
- A vulnerability scanner.
- A credential validation tool.
- Nmap readiness.
- Approval for any additional live capability.

## Enablement Gate

Before any internal operator enables the limited live feature flag in a trusted environment, all of the following should be true:

- The operator controls or is explicitly authorized to test the single target.
- The operator understands that one HTTP `HEAD` request may be visible in target logs.
- `INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED` is enabled only in the intended trusted environment.
- Double confirmation remains required in the frontend/API flow.
- The request still uses `mode: live_header_probe` and `profile: http_header_probe`.
- The target remains single-target and target-based with `file_id: null`.
- Redirects, response body reads, custom headers, auth/cookies, retries, concurrency, and target expansion remain disabled.
- Production loopback/private target blocking remains unchanged.
- The accepted Block 20 smoke method is available for local verification without real network traffic.
- The operator understands local storage and redaction caveats for targets, errors, response metadata, reports, exports, and Raw JSON.
- Disabled-state behavior is known and expected when the feature flag is off.

This block intentionally does not provide `.env` editing instructions, bypass guidance, demo targets, or third-party target suggestions.

## Copy And UX Guardrails

Recommended internal alpha wording:

- `Authorized HTTP Header Probe`
- `one HTTP HEAD request`
- `explicit authorization required`
- `review indicators`
- `no redirects`
- `no response body is read`
- `disabled by default`
- `redaction is best-effort`

Avoid wording that implies broader capability:

- `scan`
- `safe target`
- `validated target`
- `vulnerability confirmed`
- `exploitability confirmed`
- `credential valid`
- `bypass`
- `Nmap ready`
- `production ready`
- `external alpha ready`

If the word `scan` appears in future user-facing copy, it should be reviewed carefully and avoided for this one-HEAD capability unless the surrounding context makes the narrow behavior unmistakable.

## Internal Alpha Acceptance Criteria

The limited Active line can remain in internal alpha planning only while these criteria hold:

- Active dry-run remains no-network and reports `network_requests_sent: 0`.
- `active_http_header_probe` remains the only live Active capability.
- The live endpoint remains disabled by default.
- The live flow requires explicit authorization and live-traffic confirmation.
- The backend continues to reject disabled or blocked targets without creating unsafe traffic.
- The runner continues to fail closed for blocked resolved addresses before HTTP.
- The successful path sends at most one HTTP `HEAD` request.
- No redirects are followed and no response body is read.
- No custom headers, auth, cookies, retries, concurrency, crawling, port checks, or Nmap behavior exists.
- API, storage, reporting/export, frontend report, job table, and Raw JSON keep defensive redaction.
- Local smoke uses test doubles rather than production policy relaxation.
- Any new Active capability starts from a separate docs-first design and review.

## Internal Release Note Draft

Suggested internal note:

Inspectra now has an internal alpha planning checkpoint for the limited Active line. The available Active surfaces are a no-network dry-run planner and an opt-in authorized HTTP header probe that can send at most one HTTP `HEAD` request to a single explicitly authorized target when the feature flag is enabled. The probe follows no redirects, reads no response body, sends no custom headers, uses no auth/cookies, performs no crawling or port scanning, and does not use Nmap. Results are heuristic review indicators, not confirmed vulnerabilities, exploitability claims, or ownership proof. Redaction is defensive and best-effort across API, reports, exports, frontend views, and Raw JSON.

Not included:

- Nmap.
- Port scanning.
- Crawling.
- Multiple targets.
- GET fallback.
- Redirect following.
- Response body reads.
- Custom headers.
- Auth or cookies.
- Credential validation.
- Third-party demo targets.
- Production readiness.
- External-user release readiness.

## Smoke And Verification Position

The accepted local smoke method is documented in Block 20. It uses:

- fake resolver and fake HEAD transport for runner-level verification;
- in-process API/backend test doubles for job, storage, reporting, disabled-state, and redaction checks;
- mocked frontend/API responses for UI and Raw JSON redaction checks.

This block does not execute the smoke and does not send live traffic. It records the alpha planning decision that should come before a future operator guide or smoke execution record.

## No-Scope

This block does not:

- change backend, runner, frontend, tests, fixtures, or feature flags;
- read `.env`, `.env.*`, or `.envrc`;
- create tags, pushes, or GitHub releases;
- run probes, sockets, DNS, HTTP, Nmap, Docker, or subprocess network tools;
- add Active capabilities;
- relax loopback/private target blocking;
- add local-lab runtime;
- provide bypass instructions;
- approve third-party target testing;
- approve production or external-user readiness.

## Residual Risks

- Authorization remains a user/operator assertion, not proof of ownership.
- One authorized `HEAD` request may still be logged by the target when live mode is enabled in a trusted environment.
- Redaction is defensive and best-effort.
- Test-double smoke verifies contracts but does not establish live target truth.
- Misconfiguration or operator misuse remains possible if feature flags are enabled outside the intended trusted context.
- Broader Active behavior remains unimplemented and should not be inferred from this checkpoint.

## Next Recommendation

Recommended next microphase:

```text
ACTIVE-NETWORK-BLOCK-22-ACTIVE-ALPHA-OPERATOR-GUIDE
```

Rationale:

- The limited Active line now has closeout, hardening, local smoke method, and internal alpha planning decisions.
- Before executing more smoke or designing another live capability, operators need a concise guide that explains safe enablement, copy, expected disabled behavior, result interpretation, redaction caveats, and no-scope boundaries without providing bypass guidance.

Alternative next paths:

- `ACTIVE-NETWORK-BLOCK-22-LIMITED-LIVE-SMOKE-TEST-EXECUTION` if the team wants to execute only the already accepted no-external-network test-double smoke subset and record results.
- `ACTIVE-NETWORK-BLOCK-22-LOCAL-LAB-MODE-DESIGN-DOCS-FIRST` only if real loopback/private local smoke becomes necessary, and only without changing production policy by default.
- `ACTIVE-NETWORK-BLOCK-22-NEXT-LIVE-CAPABILITY-DESIGN-DOCS-FIRST` only after product explicitly accepts deferring operator guidance.

Do not proceed to Nmap, port scanning, crawling, or broader target support from this block.

## Validation Commands

Reference checks for this docs-only block:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required when this block remains docs-only.
