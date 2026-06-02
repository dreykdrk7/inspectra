# Post-Passive Alpha Runner Architecture Decision

Status: `START_ACTIVE_WITH_SEPARATE_MODULAR_RUNNER_DESIGN`.

Passive release: `https://github.com/dreykdrk7/inspectra/releases/tag/v0.1.0-passive-alpha`

Passive tag: `v0.1.0-passive-alpha`

Tagged commit: `c3ce00fd3259cc49494db1ee0ef4cdffc229dca9`

Related decision: `docs/future/post-passive-alpha-active-block-decision.md`

This document freezes the runner architecture decision after the Passive Technical Alpha publication and before any Active/Nmap/network work begins. It does not move files, refactor the passive runner, create an active runner, add endpoints, change backend/frontend/runtime behavior, create tags, create releases, run active checks, or add Nmap.

## 1. Current State

Inspectra Passive Technical Alpha v0.1.0 has been published as a GitHub prerelease. The published snapshot remains stable and does not include Active/Nmap/network scanning.

The post-passive Active decision is already documented as:

```text
HYBRID_ACTIVE_DESIGN_WITH_HARDENING_GATES
```

That decision allows Active design docs to start, while blocking Active runtime behind safety and hardening gates.

The current passive tool runner lives primarily in:

```text
tools/runner/main.py
```

Observed during this decision pass:

- `tools/runner/main.py` is approximately 17k lines (`17192` lines at the time of review).
- It contains the FastAPI app, request models, runner endpoints, passive file analyzers, archive analyzers, web/DNS/subdomain baseline logic, redaction helpers, and many analyzer-specific helpers in one module.
- It includes many `@app.post("/analyze/...")` endpoints for the implemented passive families.

This monolithic shape was acceptable technical debt for reaching and publishing the Passive Alpha. It does not invalidate the release. It does, however, matter for how Inspectra should start any Active/Nmap/network block.

## 2. Risk

Continuing to add new tool families into the same monolithic runner increases risk:

- Lower maintainability as unrelated analyzers share one very large file.
- Harder focused tests because helpers, models, endpoints, and analyzers are interleaved.
- Higher regression risk when changing shared redaction, archive safety, or request-handling code.
- Harder separation between Passive and Active scope.
- Harder auditability of safety boundaries for Active/network behavior.
- Higher onboarding cost for future contributors.
- Harder ownership boundaries by analyzer family.
- More temptation to reuse passive helpers in ways that blur active authorization, target validation, and audit logging requirements.

The largest product risk is not file size by itself. The larger risk is accidentally hiding Active behavior inside a passive runner module whose existing mental model is broad but mostly passive/local.

## 3. Decision

Decision:

```text
START_ACTIVE_WITH_SEPARATE_MODULAR_RUNNER_DESIGN
```

This means:

- Do not perform a large Passive runner refactor before starting Active docs-first work.
- Do not add Active/Nmap/network runtime code to `tools/runner/main.py`.
- Start Active as a separate, modular architecture from the beginning.
- Keep the Passive runner stable except for critical bugs, security fixes, and tightly scoped compatibility fixes.
- Plan Passive modularization as a future independent product/engineering block.
- Keep Active/Nmap/network scope explicitly separate from the Passive Alpha tag and release line.

The intent is to avoid both extremes: no risky big-bang passive refactor right now, and no more growth of the monolith for a higher-risk Active capability.

## 4. Recommended Active Architecture

Future Active architecture should be separate and modular. A possible shape is:

```text
tools/active_runner/
  main.py
  config.py
  models.py
  safety.py
  authorization.py
  audit_log.py
  probes/
    __init__.py
    http_basic.py
    dns_basic.py
    nmap_plan.py
```

This is a design sketch only. Do not create these files in this decision phase.

Design expectations:

- `main.py` should wire API routes and startup only.
- `config.py` should own Active-specific environment flags, limits, and defaults.
- `models.py` should define request/result contracts with authorization and dry-run fields.
- `safety.py` should own target normalization, rejected target classes, range restrictions, and limit checks.
- `authorization.py` should own explicit user authorization confirmation models.
- `audit_log.py` should own structured audit metadata for requested active checks.
- `probes/` should contain small, focused probe families.
- `nmap_plan.py` should be design/planning first, not runtime execution.

The first Active runtime, if it is ever implemented, should be dry-run/no-network. Nmap should not be the first runtime implementation. Any real probe must require explicit authorization, strict target validation, rate limits, timeouts, and audit logging.

## 5. Active Security Contracts

Active contracts must be frozen before runtime code exists:

- Active disabled by default.
- Explicit enable flag required.
- Explicit user authorization required per target/check.
- Allowlisted or strictly validated target required.
- Target normalization before storage, logging, or execution.
- Rejected target classes documented and enforced.
- No broad ranges in v0.
- No stealth.
- No evasion.
- No exploitation.
- No brute force.
- No credential attacks.
- No credential validation.
- No DoS or stress behavior.
- Strict per-check rate limits.
- Strict timeouts and global deadlines.
- Audit logs for requested active checks.
- Dry-run first.
- Clear UI/API copy that findings are indicators and that authorization is required.

These contracts should be treated as product and safety requirements, not optional implementation details.

## 6. Relationship With Backend

Future backend Active routing should be clearly separated from passive audit routes. Possible route families include:

```text
/active/...
```

or:

```text
/audits/active/...
```

Do not define final endpoints in this decision document. Endpoint shape should be decided during `ACTIVE-NETWORK-BLOCK-01-DOCS-FIRST-SCOPE` and contract design.

Future Active jobs, if implemented, should be distinguishable from Passive jobs with explicit metadata:

- audit type;
- category;
- target;
- target normalization result;
- authorization confirmation;
- active/dry-run flag;
- configured limits;
- rejected target classes when applicable;
- audit log metadata;
- runner/probe family;
- controlled errors and truncation.

Backend storage/reporting should not make Active jobs look like passive archive/file analysis. The job model may be shared where practical, but Active safety metadata must remain visible.

## 7. Relationship With Passive

The Passive release remains stable:

- Do not mutate `v0.1.0-passive-alpha`.
- Do not retag the passive release.
- Do not add Active/Nmap behavior to the passive release line.
- Keep Passive runner behavior stable.
- Fix critical Passive bugs when needed.
- Do not let Passive refactor block Active docs-first scope work.
- Do not let Active work force a big-bang Passive refactor.

Passive modularization should happen later as its own scoped block with tests and compatibility checks.

## 8. Future Passive Modularization Plan

Recommended future block:

```text
PASSIVE-RUNNER-MODULARIZATION-01-DOCS-FIRST-INVENTORY
```

Suggested phased plan:

1. Inventory analyzers and shared helpers currently inside `tools/runner/main.py`.
2. Classify helpers into archive safety, redaction, file analysis, web/DNS, and analyzer-specific groups.
3. Extract common helpers first only where contracts are clear.
4. Extract one small analyzer first as a pilot.
5. Preserve existing endpoint paths and JSON outputs.
6. Run focused tests before and after each extraction.
7. Smoke the migrated analyzer through backend and frontend if its public behavior is touched.
8. Avoid big-bang migration.
9. Document compatibility notes for every extracted analyzer.
10. Stop the migration if output compatibility or redaction behavior becomes uncertain.

Passive modularization should optimize maintainability without changing the meaning of Passive Alpha outputs.

## 9. Options Considered

### Option A: Refactor Passive Now Before Active

Pros:

- Reduces current monolith debt.
- Could improve helper boundaries before new work.
- Might make future changes easier.

Cons:

- High risk after a just-published alpha.
- Could introduce regressions across many passive analyzers.
- Delays Active design without directly improving Active safety.
- Creates a large diff before product scope is settled.

Assessment: useful later, but too expensive and risky as the immediate next step.

### Option B: Add Active To The Current Runner

Pros:

- Fastest short-term path.
- Reuses existing container/backend call pattern.
- Requires fewer new files initially.

Cons:

- Blurs Passive/Active boundaries.
- Makes a 17k-line file larger and harder to audit.
- Increases chance of safety mistakes.
- Makes authorization, target validation, and audit logging harder to isolate.
- Encourages Nmap/network code to sit beside passive archive parsers.

Assessment: rejected.

### Option C: Create Separate Active Architecture And Leave Passive Stable

Pros:

- Keeps Passive Alpha stable.
- Avoids a big-bang passive refactor.
- Creates clean safety and authorization boundaries for Active.
- Makes Active docs-first design easier to audit.
- Allows dry-run and no-network contracts to be designed cleanly.

Cons:

- Adds a new architectural surface later.
- Requires integration design with backend/jobs/reporting.
- Does not immediately reduce Passive runner debt.

Assessment: recommended.

### Option D: Refactor Passive And Active Together

Pros:

- Could produce a fully modernized runner layout.
- Might reduce duplication across passive and active families.

Cons:

- Highest complexity.
- Highest regression risk.
- Hardest to review.
- Mixes product scope decisions with architectural migration.
- Makes safety review harder because too much changes at once.

Assessment: rejected.

## 10. Final Decision

Decision:

```text
START_ACTIVE_WITH_SEPARATE_MODULAR_RUNNER_DESIGN
```

Operational meaning:

- Continue with Active docs-first scope.
- Do not add Active/Nmap/network code to `tools/runner/main.py`.
- Do not create `tools/active_runner/` yet.
- Do not refactor Passive now.
- Keep Passive stable except for critical bugs.
- Plan Passive modularization as a separate future block.

## 11. Relationship With The Next Active Microphase

The next Active microphase remains:

```text
ACTIVE-NETWORK-BLOCK-01-DOCS-FIRST-SCOPE
```

That docs-first scope is now recorded in:

```text
docs/future/active-network-block-01-docs-first-scope.md
```

This architecture decision constrains that microphase:

- no Active runtime;
- no Nmap runtime;
- no Active code inside `tools/runner/main.py`;
- separate Active runner design;
- dry-run first;
- explicit authorization and target validation first;
- safety and abuse boundaries before endpoints or probes.

## 12. No-Scope

This decision does not include:

- code changes;
- file moves;
- passive runner refactor;
- active runner creation;
- backend changes;
- frontend changes;
- runtime changes;
- tests beyond docs checks;
- active scanning;
- Nmap execution;
- network checks;
- new endpoints;
- tags;
- releases;
- push;
- mutation of `v0.1.0-passive-alpha`.

## 13. Validation

Required validation for this docs-only decision:

```bash
git status --short
git log --oneline -12
git diff --check
git diff --cached --check
```

No pytest, npm, backend, runner, frontend, or Docker validations are required because this microphase does not touch runtime code.
