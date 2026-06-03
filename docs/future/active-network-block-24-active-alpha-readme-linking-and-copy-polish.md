# Active Network Block 24 Active Alpha README Linking And Copy Polish

Status: `ACTIVE_ALPHA_README_LINKING_AND_COPY_POLISH_ACCEPTED`.

Smoke execution: `docs/future/active-network-block-23-limited-live-smoke-test-execution.md`

Operator guide: `docs/future/active-network-block-22-active-alpha-operator-guide.md`

Internal alpha planning: `docs/future/active-network-block-21-active-alpha-checkpoint-release-planning.md`

Closeout: `docs/future/active-network-block-25-active-alpha-closeout.md`

Commit scope: docs-only copy/linking polish for README, architecture, and security scope. This block does not change backend, frontend, runner, tests, fixtures, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
ACTIVE_ALPHA_README_LINKING_AND_COPY_POLISH_ACCEPTED
```

The Active Alpha documentation is now visible from the README and aligned across architecture and security scope without broadening Active behavior.

## Polish Objective

- Make the limited Active Alpha state visible without implying production or external-user readiness.
- Link the operator guide and test-double smoke execution record from user-facing documentation.
- Keep Active clearly separate from Passive Alpha and passive archive reviews.
- Avoid language that implies a general live scanner, target safety proof, confirmed vulnerabilities, exploitability, credential validation, Nmap readiness, or bypass guidance.
- Preserve the current boundaries: no-network dry-run plus one opt-in authorized HTTP `HEAD` capability.

## README Changes

README copy now groups the Active line under an internal alpha paragraph:

- `active_network_dry_run` is described as no-network planning.
- `active_http_header_probe` is described as the only limited live capability.
- The live capability is described as disabled by default, explicitly authorized, double-confirmed, target-based, and capped to one HTTP `HEAD` request.
- The test-double smoke execution is linked and described as no-external-target validation.
- Operator guide and security scope links are included.
- Nmap, port scanning, crawling, redirects, response body reads, custom headers, auth/cookies, fuzzing, exploitation, credential validation, production readiness, external-user readiness, policy relaxation, and additional Active capability remain excluded.

## Architecture Changes

Architecture wording now:

- references the Block 24 polish document in the Active document list;
- keeps Active runner separation explicit;
- keeps Passive analyzers' no-network guarantee explicit;
- keeps dry-run no-network and `network_requests_sent: 0` explicit;
- describes `active_http_header_probe` as target-based with `file_id: null`;
- describes the Block 23 smoke as test-double verification, not live target proof;
- states that the polish adds no runtime behavior, policy relaxation, or new Active capability.

## Security Scope Changes

Security scope wording now:

- references the Block 24 polish document and decision;
- keeps the allowed Active surfaces narrow;
- preserves fail-closed loopback/private/metadata/link-local policy;
- restates that authorization is an assertion, not proof of ownership;
- restates best-effort redaction;
- keeps no-scope wording for Nmap, port scanning, crawling, redirects, body reads, GET fallback, custom headers, auth/cookies, fuzzing, exploitation, credential validation, external demo targets, production readiness, external-user readiness, local-lab mode, and additional Active capability.

## Recommended Copy

Use:

- `Authorized HTTP Header Probe`
- `one HTTP HEAD request`
- `review indicators`
- `no response body is read`
- `redirects are not followed`
- `disabled by default`
- `internal alpha`
- `test-double smoke`

Avoid:

- `vulnerability confirmed`
- `exploitability confirmed`
- `credential valid`
- `safe target`
- `production ready`
- `Nmap ready`
- `bypass`
- `scanner`
- `scan`, unless the context is explicitly narrow and restates the one-HEAD limit.

## Forbidden-Copy Review

Command used for manual review:

```text
rg -n "vulnerability confirmed|exploitability confirmed|credential valid|safe target|production ready|Nmap ready|bypass|port scan|brute force|exploit|scanner|scan" README.md docs/architecture.md docs/security-scope.md docs/future/active-network-block-2*.md
```

Expected hit classes:

- no-scope statements such as `no Nmap`, `no port scanning`, `no crawling`, `no exploitation`, and `no bypass`;
- warning copy that tells operators not to claim `production ready`, `Nmap ready`, `safe target`, `credential valid`, `vulnerability confirmed`, or `exploitability confirmed`;
- documentation of the terms that should be avoided.

Execution result in this block: the check returned expected hits in README, architecture, security-scope, and Active Block 20-24 docs. The hits were no-scope statements, avoid-copy lists, passive-module caveats, or validation-command text. No dangerous positive Active capability claim was found.

No dangerous positive claims are accepted by this block. Any future forbidden-copy hit that presents those phrases as a capability, result, or recommendation should be corrected before release.

## Acceptance Criteria

- README summarizes Active Alpha without overpromising.
- README links the operator guide, smoke execution, and security scope.
- Architecture links Block 24 and preserves Active runner separation.
- Security scope links Block 24 and preserves explicit no-scope.
- The test-double smoke is described as contract verification, not real target proof.
- No bypass instructions are added.
- No external demo targets are added.
- No production or external-user readiness is announced.
- No Nmap or broader Active capability is announced.
- No code, tests, fixtures, runtime, target-policy, tag, release, or push change is included.

## Next Recommendation

Completed next microphase:

```text
ACTIVE-NETWORK-BLOCK-25-ACTIVE-ALPHA-CLOSEOUT
```

Rationale:

- Active Alpha now has planning, operator guidance, test-double smoke execution, and README/scope polish.
- A closeout can package the current internal alpha state, residual risks, accepted smoke evidence, no-scope boundaries, and product decision before any new Active design work.

Alternative next paths:

- `ACTIVE-NETWORK-BLOCK-25-SMOKE-GAP-FIX-DOCS-FIRST` only if product wants to close the real local-lab gap before closeout.
- `ACTIVE-NETWORK-BLOCK-25-NEXT-LIVE-CAPABILITY-DESIGN-DOCS-FIRST` only if product explicitly chooses to broaden Active after closeout.
- `ACTIVE-NETWORK-BLOCK-25-LOCAL-LAB-MODE-DESIGN-DOCS-FIRST` only if real loopback/private smoke becomes necessary and production policy remains unchanged by default.

Do not proceed to Nmap, port scanning, crawling, broader target support, or another live capability from this polish block.

## Validation Commands

Reference checks for this docs-only block:

```text
git status --short
git status --branch --short
git log --oneline -8
rg -n "vulnerability confirmed|exploitability confirmed|credential valid|safe target|production ready|Nmap ready|bypass|port scan|brute force|exploit|scanner|scan" README.md docs/architecture.md docs/security-scope.md docs/future/active-network-block-2*.md
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required when this block remains docs-only.
