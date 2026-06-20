# Active Pre-Alpha Release Publication

Decision: `ACTIVE_PRE_ALPHA_RELEASE_TAG_08_ACCEPTED`

Status: Inspectra Active Technical Alpha release tag and GitHub prerelease were
published from the finalized release notes. This phase did not deploy to a VPS,
run Docker, invoke Nmap, submit Active jobs, use real targets, or capture
screenshots.

## Release Identity

Tag:

```text
v0.2.0-alpha.1
```

Annotated tag object:

```text
efb459946e4511522581415c3e7bbd6dbac1ebd6
```

Tag target commit:

```text
45a50b8738dd54e43973d6a7568620095cf7f0aa
```

Tagged commit subject:

```text
45a50b8 docs(active): finalize pre-alpha release notes
```

Release title:

```text
Inspectra Active Technical Alpha v0.2.0-alpha.1
```

Release notes source:

```text
docs/future/active-pre-alpha-release-notes.md
```

Release URL:

```text
https://github.com/dreykdrk7/inspectra/releases/tag/v0.2.0-alpha.1
```

## Preflight Results

Initial status:

```text
## main...origin/main
```

Initial head:

```text
45a50b8 docs(active): finalize pre-alpha release notes
```

Full initial head:

```text
45a50b8738dd54e43973d6a7568620095cf7f0aa
```

Local tag pre-check:

```text
git tag --list "v0.2.0-alpha.1"
```

Result: no local tag existed before this phase.

Remote tag pre-check:

```text
git ls-remote --tags origin v0.2.0-alpha.1
```

Result: no remote tag existed before this phase.

Release notes existed at:

```text
docs/future/active-pre-alpha-release-notes.md
```

Diff checks:

```text
git diff --check
git diff --cached --check
```

Result: both passed.

Guardrail checks over the finalized release notes and tag plan passed for:

- secret-like token/key signatures;
- real target examples;
- unsupported certainty or overclaim wording.

## Commands Run

Local tag creation:

```text
git tag -a v0.2.0-alpha.1 -m "Inspectra Active Technical Alpha v0.2.0-alpha.1"
```

Local tag target verification:

```text
git rev-list -n 1 v0.2.0-alpha.1
git show --stat --oneline v0.2.0-alpha.1
```

Main push:

```text
git push origin main
```

Result:

```text
Everything up-to-date
```

Tag push:

```text
git push origin v0.2.0-alpha.1
```

Result:

```text
[new tag] v0.2.0-alpha.1 -> v0.2.0-alpha.1
```

GitHub release creation first attempted the planned short target value:

```text
gh release create v0.2.0-alpha.1 --title "Inspectra Active Technical Alpha v0.2.0-alpha.1" --notes-file docs/future/active-pre-alpha-release-notes.md --target 45a50b8 --prerelease
```

GitHub rejected that attempt because the short target value was not accepted as
a release target. The release was then created with the full commit hash:

```text
gh release create v0.2.0-alpha.1 --title "Inspectra Active Technical Alpha v0.2.0-alpha.1" --notes-file docs/future/active-pre-alpha-release-notes.md --target 45a50b8738dd54e43973d6a7568620095cf7f0aa --prerelease
```

Result:

```text
https://github.com/dreykdrk7/inspectra/releases/tag/v0.2.0-alpha.1
```

Remote tag verification:

```text
git ls-remote --tags origin v0.2.0-alpha.1
git ls-remote origin 'refs/tags/v0.2.0-alpha.1^{}'
```

Observed:

```text
efb459946e4511522581415c3e7bbd6dbac1ebd6 refs/tags/v0.2.0-alpha.1
45a50b8738dd54e43973d6a7568620095cf7f0aa refs/tags/v0.2.0-alpha.1^{}
```

Release verification:

```text
gh release view v0.2.0-alpha.1 --json tagName,name,isPrerelease,url,targetCommitish
gh release view v0.2.0-alpha.1 --json assets
```

Observed:

```json
{"isPrerelease":true,"name":"Inspectra Active Technical Alpha v0.2.0-alpha.1","tagName":"v0.2.0-alpha.1","targetCommitish":"45a50b8738dd54e43973d6a7568620095cf7f0aa","url":"https://github.com/dreykdrk7/inspectra/releases/tag/v0.2.0-alpha.1"}
```

```json
{"assets":[]}
```

## Scope Confirmations

This phase did not:

- deploy to a VPS;
- run Docker;
- invoke Nmap;
- submit Active jobs;
- use real targets;
- capture screenshots;
- attach release artifacts;
- create any tag other than `v0.2.0-alpha.1`;
- modify backend, frontend, tools, archive/run-all, or `tools/runner/main.py`.

## Residual Next Step

Recommended next phase:

```text
ACTIVE_PRE_ALPHA_VPS_DEPLOY_PLAN_09
```

Alternative if the operator wants to combine planning and execution:

```text
ACTIVE_PRE_ALPHA_VPS_DEPLOY_SMOKE_09
```

Keep VPS deploy/smoke separate from this release publication record.

## Decision

```text
ACTIVE_PRE_ALPHA_RELEASE_TAG_08_ACCEPTED
```
