# Passive Alpha Release Tag v0.1.0-passive-alpha

Status: `TAG_PREPARED_FOR_LOCAL_CREATION`.

Initial HEAD: `dcfbdb2 docs(alpha): record final browser smoke before tag`

Release notes: `docs/releases/v0.1.0-passive-alpha.md`

Tag name: `v0.1.0-passive-alpha`

This document records the local tag preparation for Inspectra Passive Technical Alpha v0.1.0. It does not create a GitHub release, push commits, push tags, add analyzers, change runtime behavior, change endpoints, change frontend behavior, change exports, or open active/network scope.

## A. Preconditions

- Final browser smoke decision: `READY_TO_TAG_PASSIVE_ALPHA`.
- Final browser smoke record: `docs/future/passive-alpha-manual-browser-smoke-rerun-before-tag.md`.
- Target tag did not exist before this microphase.
- Working tree was clean before creating release notes.
- No release or tag was created before the docs commit.

## B. Release Notes

Release notes were prepared at:

```text
docs/releases/v0.1.0-passive-alpha.md
```

They describe:

- trusted local technical alpha scope;
- included passive analyzers and authorized baseline flows;
- UI/report/export highlights;
- API and browser smoke results;
- redaction posture and fixture-negative checks;
- security non-scope;
- known limitations;
- fixture/demo assets;
- post-alpha roadmap.

## C. Checks Run Before Docs Commit

Commands used before preparing the release docs:

```bash
git status --short
git log --oneline -8
git tag --list v0.1.0-passive-alpha
```

Expected result before docs commit:

- `git status --short` clean.
- `HEAD` at `dcfbdb2 docs(alpha): record final browser smoke before tag`.
- `git tag --list v0.1.0-passive-alpha` empty.

## D. Checks Before Tag

Commands to run after staging release docs and before committing/tagging:

```bash
git diff --check
git diff --cached --check
git status --short
```

Commands to run after the release-docs commit and before creating the tag:

```bash
git status --short
git log --oneline -5
git tag --list v0.1.0-passive-alpha
```

Required state before tag creation:

- working tree clean;
- release notes commit at `HEAD`;
- target tag absent.

## E. Tag Command

Local annotated tag command:

```bash
git tag -a v0.1.0-passive-alpha -m "Inspectra Passive Technical Alpha v0.1.0"
```

The tag must point to the final release-docs commit, not the prior smoke commit.

## F. Tag Verification

Commands to run immediately after tag creation:

```bash
git status --short
git tag --list v0.1.0-passive-alpha
git show --stat --oneline v0.1.0-passive-alpha
```

Expected final verification:

- working tree clean;
- `v0.1.0-passive-alpha` exists locally;
- `git show --stat --oneline v0.1.0-passive-alpha` shows the annotated tag and the release-docs commit;
- no GitHub release created;
- no push performed.

Exact command output is intentionally reported in the final response rather than written after the tag, so the tag can point at this final release-docs commit.

## G. No-Scope Confirmed

This release-tag microphase does not:

- create a GitHub release;
- push commits or tags;
- touch backend, runner, or frontend functional code;
- modify fixtures;
- add analyzers;
- change endpoints;
- change redaction logic;
- run active/Nmap/network analysis;
- use real data;
- inspect real `.env` files.

## H. Next Product Step

Recommended next step after the local tag:

`POST_ALPHA_READINESS_BACKLOG_TRIAGE execution`

Focus on external-user blockers first: authentication, deployment hardening, storage retention, upload cleanup, onboarding, disclaimers, and multi-user isolation. Active/Nmap/network work remains separate until explicitly re-scoped.
