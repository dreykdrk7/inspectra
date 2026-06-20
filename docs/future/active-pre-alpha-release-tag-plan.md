# Active Pre-Alpha Release Tag Plan

Decision: `ACTIVE_PRE_ALPHA_RELEASE_TAG_PLAN_07_READY`

Status: docs-only tag and provenance plan for the Inspectra Active technical
alpha. This phase does not create the tag, publish a release, deploy, upload
commits, run Docker, run the app, invoke Nmap, submit Active jobs, contact
targets, or capture images.

## Proposed Tag

Recommended tag:

```text
v0.2.0-alpha.1
```

Rationale:

- Passive Alpha used the `v0.1.0` family.
- Active technical alpha is the next product line after the passive alpha and
  packaging validation work.
- The `alpha.1` suffix preserves the technical-alpha maturity signal.

Release title:

```text
Inspectra Active Technical Alpha v0.2.0-alpha.1
```

## Tag Target Policy

The tag target should be the final clean commit produced by
`ACTIVE_PRE_ALPHA_RELEASE_NOTES_FINALIZE_07`, not an earlier RC-validation or
packaging-validation commit and not a later feature commit.

The next tag phase must record the exact current commit hash before creating
the tag. If any tracked file changes after this release-notes-finalization
commit, stop and either commit a narrowly scoped documentation fix or rerun the
release/tag plan.

Current pre-finalization base inspected by this phase:

```text
7d6ee46 fix(active): validate pre-alpha docker packaging
```

The final tag target will be the commit created by this release-notes
finalization phase.

## Release Notes Source

The release should point to:

```text
docs/future/active-pre-alpha-release-notes.md
```

Before tagging, verify the release notes include:

- local/private/self-hosted positioning;
- explicit authorization requirement;
- disabled-by-default Active features;
- redaction-first reporting;
- review-indicator wording;
- manual validation requirement;
- RC validation evidence;
- Docker packaging validation evidence;
- packaging fixes and remaining gaps;
- dependency audit warning handling without inventing package names or
  severity.

## Pre-Tag Checklist

Required checks for the next phase:

- `git status --short --branch` is clean.
- Current branch is the intended branch.
- Current commit hash is recorded.
- `git log -1 --oneline` shows the release-notes-finalization commit.
- `git diff --check` passes.
- `git diff --cached --check` passes.
- Release notes contain no secrets, credentials, cookies, tokens, raw targets,
  private hostnames, account identifiers, or real target examples.
- Release notes do not overclaim capability, completeness, ownership,
  production readiness, target approval, or human-review replacement.
- No runtime files changed after the release-notes-finalization commit.
- No archive/run-all or `tools/runner/main.py` change is present.
- No new Active capability is included.
- Docker packaging evidence still points to
  `docs/future/active-pre-alpha-docker-packaging-validation.md`.

## Publication Boundary

This plan does not publish anything. The next phase may create the local tag
and prepare release metadata only after the clean-state checks pass.

Recommended next phase:

```text
ACTIVE_PRE_ALPHA_RELEASE_TAG_08
```

Keep remote server deploy/smoke separate unless the operator explicitly asks to
combine that work with tagging. Prefer a later VPS deploy/smoke phase after the
alpha tag exists.

## Blockers

Block the tag if any of these are true:

- working tree is dirty;
- release notes still contain placeholder validation status;
- release notes contain secrets or real target examples;
- release notes overclaim readiness or coverage;
- package validation evidence is missing;
- dependency audit warnings are treated as fixed without a separate record;
- another Active runtime capability is added before publication;
- Docker packaging evidence is superseded by unvalidated packaging changes.

## Decision

```text
ACTIVE_PRE_ALPHA_RELEASE_TAG_PLAN_07_READY
```
