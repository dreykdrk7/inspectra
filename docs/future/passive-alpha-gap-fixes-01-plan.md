# Passive Alpha Gap Fixes 01 Plan

Status: `PASSIVE_ALPHA_GAP_FIXES_01_PLAN_ACCEPTED`.

Base closeout: `docs/future/passive-alpha-closeout-or-release-candidate.md`

Readiness recheck: `docs/future/active-network-block-26-passive-alpha-readiness-recheck.md`

Packaging readiness: `docs/future/passive-alpha-packaging-readiness.md`

Backlog triage: `docs/future/post-alpha-readiness-backlog-triage.md`

Commit scope: docs-only planning for public/external readiness gap fixes. This block does not change backend, frontend, runner, tests, fixtures, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_GAP_FIXES_01_PLAN_ACCEPTED
```

The trusted local Passive Alpha/release-candidate documentation package is accepted. The next line of work should address public/external readiness gaps in small docs-first microphases, starting with deployment threat modeling.

This plan does not add analyzers, Active behavior, Nmap, production policy changes, or runtime implementation.

## Reason

Passive Alpha is accepted for trusted local use, and Active Alpha v0 is closed as internal and limited. Before Inspectra can move toward public/external users, the remaining work is product hardening and deployment readiness rather than more passive modules or broader Active behavior.

The goal of this plan is to turn the should-fix list into a safe execution sequence.

## Consolidated Gaps

The consolidated should-fix list is:

- authentication and deployment hardening;
- retention, cleanup, and reset controls;
- onboarding;
- legal/security disclaimers;
- multi-user isolation;
- deployment threat model;
- visible limits and file-size messaging;
- report/export polish.

These gaps are not blockers for trusted local Passive Alpha. They are blockers or quality gates before public/external use.

## Prioritization

### P0: Blocks Public Or External Use

- Deployment threat model.
- Authentication and deployment hardening.
- Multi-user isolation.
- Retention, cleanup, and reset controls.
- Legal/security disclaimers.

Rationale:

- These define who can use Inspectra, where it can run, what data is retained, and what risks users/operators must explicitly accept.
- Implementing auth, isolation, or retention before defining the deployment threat model risks building the wrong boundary.

### P1: Improves Trust And First-Use Clarity

- Onboarding.
- Visible limits and file-size messaging.

Rationale:

- Users need clear expectations before uploading files or interpreting results.
- Limits and storage copy reduce misuse and surprise without requiring new analyzer behavior.

### P2: Polish And Backlog

- Report/export polish.

Rationale:

- Report and export quality matters, but it should follow the threat model, data-retention story, and user-facing disclaimers.
- This can be refined incrementally after the public/external safety boundaries are clearer.

## Proposed Microphase Sequence

1. `PASSIVE-ALPHA-GAP-FIXES-02-DEPLOYMENT-THREAT-MODEL`

   Define supported deployment shapes, trusted/local assumptions, public/external exclusions, actor model, data flows, storage risks, network assumptions, and first security gates.

2. `PASSIVE-ALPHA-GAP-FIXES-03-AUTH-AND-USER-ISOLATION-DESIGN`

   Design authentication, authorization, operator/user separation, file/job ownership, and multi-user isolation boundaries. Docs-first only unless explicitly re-scoped later.

3. `PASSIVE-ALPHA-GAP-FIXES-04-RETENTION-CLEANUP-RESET-DESIGN`

   Design uploaded-file retention, result retention, cleanup/reset behavior, demo reset, deletion semantics, and local-data guidance.

4. `PASSIVE-ALPHA-GAP-FIXES-05-DISCLAIMERS-AND-ONBOARDING-COPY`

   Align user-facing copy for local storage, authorized use, heuristic findings, no credential validation, no confirmed vulnerabilities, no production readiness, and accepted use.

5. `PASSIVE-ALPHA-GAP-FIXES-06-LIMITS-MESSAGING-AND-REPORT-POLISH`

   Improve visible file-size/limit messaging, truncation/error explanations, report/export readability, and severity/confidence explanations.

This sequence keeps implementation pressure low until product/security boundaries are described.

## First Recommended Microphase

Recommended next microphase:

```text
PASSIVE-ALPHA-GAP-FIXES-02-DEPLOYMENT-THREAT-MODEL
```

Rationale:

- Deployment threat model comes before auth, multi-user isolation, retention, and public/external copy.
- It should decide which deployment scenarios are supported, which are explicitly unsupported, and which risks must be controlled before implementation.
- It can remain docs-only while giving later design blocks concrete boundaries.

## No-Scope

- No code.
- No runtime changes.
- No tests or fixture changes.
- No probes.
- No live traffic.
- No DNS or HTTP.
- No Docker.
- No Nmap.
- No port scanning.
- No crawling.
- No GET fallback.
- No redirects.
- No body reads.
- No custom headers.
- No auth or cookies.
- No fuzzing.
- No exploitation.
- No credential validation.
- No new Active capability.
- No new Passive analyzer implementation.
- No target-policy relaxation.
- No local-lab mode.
- No `.env`, `.env.*`, or `.envrc` reads.
- No push.
- No real tag or release.

## Acceptance Criteria

- Gaps are consolidated.
- Priorities are clear.
- Microphase sequence is clear.
- First executable gap is recommended.
- No capability is added.
- Nmap and Active expansion remain out of scope.
- README, architecture, and security scope remain coherent if referenced.

## Next Recommendation

```text
PASSIVE-ALPHA-GAP-FIXES-02-DEPLOYMENT-THREAT-MODEL
```

Do not proceed directly to runtime auth, multi-user storage changes, Nmap, another Active capability, or a new passive analyzer implementation from this planning block.

## Validation Commands

Reference checks for this docs-only block:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
