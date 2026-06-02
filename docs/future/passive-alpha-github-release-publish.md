# Passive Alpha GitHub Release Publish

Status: `GITHUB_RELEASE_PUBLISHED`.

Release URL: `https://github.com/dreykdrk7/inspectra/releases/tag/v0.1.0-passive-alpha`

Tag: `v0.1.0-passive-alpha`

Tagged commit: `c3ce00fd3259cc49494db1ee0ef4cdffc229dca9`

Release notes: `docs/releases/v0.1.0-passive-alpha.md`

This document records the GitHub publication of Inspectra Passive Technical Alpha v0.1.0. It does not change the release tag content, create a new tag, add analyzers, touch runtime behavior, change endpoints, change redaction logic, modify fixtures, attach binaries, or open active/network scope.

## A. Initial State

Initial local state before publishing:

- Working tree: clean.
- Current branch: `main`.
- Branch status: `main...origin/main [ahead 89]`.
- Remote: `origin git@github.com:dreykdrk7/inspectra.git`.
- Local tag existed: `v0.1.0-passive-alpha`.
- Local tag pointed to: `c3ce00fd3259cc49494db1ee0ef4cdffc229dca9`.
- Release notes existed at `docs/releases/v0.1.0-passive-alpha.md`.
- No GitHub release existed before this microphase.

Initial verification commands:

```bash
git status --short
git log --oneline -8
git tag --list v0.1.0-passive-alpha
git rev-list -n 1 v0.1.0-passive-alpha
git show --stat --oneline v0.1.0-passive-alpha
git remote -v
git branch --show-current
git status --branch --short
```

## B. GitHub CLI And Remote Verification

GitHub CLI was available:

```text
gh version 2.4.0+dfsg1
```

Authentication check:

- `gh auth status` reported login to `github.com` as `dreykdrk7`.

Remote branch check:

```bash
git ls-remote --heads origin main
```

Remote `origin/main` initially pointed to:

```text
cb120c51b728140444059038fb4e62dca53586a9
```

## C. Branch Push

Because local `main` was ahead of `origin/main`, the branch was pushed before publishing the tag:

```bash
git push origin HEAD
```

Result:

```text
cb120c5..3fd95ea  HEAD -> main
```

This pushed the already completed local release-preparation and post-tag handoff commits. No force push was used.

## D. Tag Push

The local annotated tag was pushed:

```bash
git push origin v0.1.0-passive-alpha
```

Result:

```text
[new tag] v0.1.0-passive-alpha -> v0.1.0-passive-alpha
```

Remote tag verification:

```bash
git ls-remote --tags origin v0.1.0-passive-alpha
git ls-remote origin 'refs/tags/v0.1.0-passive-alpha^{}'
```

Observed:

```text
6de2e753ab45e40fc3f95c2f789c594514b1ce7c refs/tags/v0.1.0-passive-alpha
c3ce00fd3259cc49494db1ee0ef4cdffc229dca9 refs/tags/v0.1.0-passive-alpha^{}
```

The first SHA is the annotated tag object. The peeled `^{}` ref confirms the tag points to the intended release-notes commit.

## E. GitHub Release Creation

Command used:

```bash
gh release create v0.1.0-passive-alpha \
  --title "Inspectra Passive Technical Alpha v0.1.0" \
  --notes-file docs/releases/v0.1.0-passive-alpha.md \
  --prerelease
```

Result:

```text
https://github.com/dreykdrk7/inspectra/releases/tag/v0.1.0-passive-alpha
```

No binary/package assets were attached.

## F. Release Verification

Command:

```bash
gh release view v0.1.0-passive-alpha
```

Observed:

- Title: `Inspectra Passive Technical Alpha v0.1.0`
- Tag: `v0.1.0-passive-alpha`
- Draft: `false`
- Prerelease: `true`
- Author: `dreykdrk7`
- URL: `https://github.com/dreykdrk7/inspectra/releases/tag/v0.1.0-passive-alpha`
- Body: release notes from `docs/releases/v0.1.0-passive-alpha.md`

JSON verification:

```bash
gh release view v0.1.0-passive-alpha --json tagName,name,isPrerelease,url
```

Observed:

```json
{
  "isPrerelease": true,
  "name": "Inspectra Passive Technical Alpha v0.1.0",
  "tagName": "v0.1.0-passive-alpha",
  "url": "https://github.com/dreykdrk7/inspectra/releases/tag/v0.1.0-passive-alpha"
}
```

Assets verification:

```bash
gh release view v0.1.0-passive-alpha --json assets
```

Observed:

```json
{"assets":[]}
```

## G. No-Scope Maintained

This publication microphase did not:

- change the tagged release content;
- create another tag;
- create runtime/backend/runner/frontend changes;
- modify fixtures;
- add analyzers;
- change endpoints;
- change redaction logic;
- attach binaries or packages;
- force push;
- open Active/Nmap/network work;
- use real data or inspect real `.env` files.

## H. Final State

- Branch `main` was pushed to `origin`.
- Tag `v0.1.0-passive-alpha` was pushed to `origin`.
- GitHub release was created as a prerelease.
- Release body uses `docs/releases/v0.1.0-passive-alpha.md`.
- Release has no assets.
- The release tag points to `c3ce00f docs(alpha): prepare passive alpha release notes`.

## I. Next Recommended Step

Recommended next product step:

`POST_PASSIVE_ALPHA_ACTIVE_BLOCK_DECISION`

That decision should choose whether to begin an Active/Nmap/network product block. If active work is opened, start with a docs-first scope microphase such as:

`ACTIVE-NETWORK-BLOCK-01-DOCS-FIRST-SCOPE`

Do not mix Active/Nmap work into the passive alpha release line.
