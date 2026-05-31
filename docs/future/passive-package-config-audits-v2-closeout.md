# Passive Package Config Audits v2 Closeout

Status: `django_config_basic`, `docker_config_basic`, `secrets_review_basic`, and `node_package_config_basic` are closed as v1 passive archive-based audit modules.

This document is a lightweight smoke and scope reference before opening another passive module. Runtime details remain in `README.md`, `docs/architecture.md`, and `docs/security-scope.md`; design documents in `docs/future/` remain historical references.

## Module Status

| Module | Status | Primary value | Key guardrails |
| --- | --- | --- | --- |
| `django_config_basic` | v1 closed | Reviews Django settings, deployment hints, environment templates, and related config inside uploaded archives. | Does not execute Python, import settings, run `manage.py`, install dependencies, connect to databases, or read real `.env` files. |
| `docker_config_basic` | v1 closed | Reviews Dockerfile, Docker Compose, and `.dockerignore` indicators inside uploaded archives. | Does not execute Docker, build images, start containers, inspect the Docker socket, download images, resolve tags, scan ports, or query CVEs. |
| `secrets_review_basic` | v1 closed | Performs redaction-first review of candidate text files for secret-exposure indicators. | Does not validate credentials, call providers, scan Git history, run external scanners, compute fingerprints, or read real `.env`, `.env.*`, or `.envrc` content. |
| `node_package_config_basic` | v1 closed | Reviews Node package manifests, lockfiles, package-manager config, JS/TS tool config, and CI/publishing hints inside uploaded archives. | Does not execute npm, pnpm, yarn, bun, npx, lifecycle scripts, JavaScript, TypeScript, or config files; install dependencies; resolve transitive dependencies; query registries; run `npm audit`; query advisories/CVEs; or claim malicious-package verdicts. |

## Shared Capabilities

- All four modules accept uploaded files registered as `kind: "archive"`.
- Archive reads are bounded by per-module file count, per-file byte, total-byte, archive-entry, and ZIP central directory metadata limits.
- ZIP/TAR/TAR.GZ/TGZ archives are inspected with standard library parsers.
- Path traversal entries, absolute paths, symlinks, hardlinks, non-regular entries, oversized files, and unsupported binary content are skipped or handled as controlled errors.
- Findings are heuristic review indicators and require manual validation.
- Results are persisted as jobs, included in compact job summaries, rendered in the frontend, and exportable as Markdown, HTML, XML, and PDF.
- Secret-like evidence is redacted best-effort in runner results, backend exports, frontend reports, and raw JSON views for modules that handle sensitive-looking text.

## Module Differences

- Config/deployment audits: `django_config_basic` and `docker_config_basic` focus on framework and deployment configuration posture.
- Exposure/redaction audit: `secrets_review_basic` focuses on secret-like values, sensitive files present, and safe evidence redaction.
- Package/supply-chain hygiene audit: `node_package_config_basic` focuses on package manifests, lifecycle scripts, dependency declaration indicators, package-manager config signals, and lockfile consistency hints without installing or resolving packages.

## Explicit Non-Scope

- No project code execution.
- No broad extraction of archives to the filesystem.
- No Docker build/run/compose execution, Docker socket access, image downloads, or image tag resolution.
- No npm, pnpm, yarn, bun, npx, lifecycle-script, JavaScript, TypeScript, or config-file execution.
- No package installation, transitive dependency resolution, registry access, `npm audit`, advisory lookup, CVE lookup, or malicious-package verdicts.
- No secret validation against external providers.
- No network calls, provider APIs, Git history scanning, deep external secret scanners, or credential activity claims.
- No claim that findings are confirmed vulnerabilities, active credentials, leaked tokens, malicious packages, or exploitable deployment issues.

## Smoke Checklist

Recommended smoke checks before opening a new passive module:

- Upload a small archive containing Django settings, Dockerfile/Compose files, secret-review fixtures, `package.json`, a lockfile, and `.npmrc` fixture data.
- Launch `django_config_basic`, `docker_config_basic`, `secrets_review_basic`, and `node_package_config_basic` from the UI archive actions.
- Confirm each job reaches a terminal state and appears in `GET /jobs` with compact summary metrics.
- Open each frontend report and confirm summary, findings, context, files reviewed/detected, limits/errors, redaction notes, and raw JSON render clearly.
- Export each job to Markdown, HTML, XML, and PDF.
- Confirm real `.env`, `.env.*`, and `.envrc` files are detected but not read where the module handles env-like paths.
- Confirm fixture tokens, passwords, URL credentials, private-key material, and npm auth values do not appear unredacted in UI reports, raw JSON, exports, or controlled errors.
- Confirm Node package config findings remain review indicators and do not use malicious/vulnerable/exploited wording.

For docs-only closeout changes, the minimum validation is:

```bash
git status --short
git diff --check
git diff --cached --check
```

If runtime code changes, also run the relevant focused suites plus the normal build/test commands for the touched layer.

## Residual Risks

- Heuristics do not replace manual review, production hardening, or dedicated ecosystem tooling.
- Development, test, local, sample, and template context detection is best-effort.
- Secret redaction is best-effort and may miss uncommon formats or names.
- Uploaded archive bytes are stored locally and can contain secrets even when Inspectra results are redacted.
- No CVE, advisory, registry, provider, token-validity, or malicious-package checks are performed.
- Inspectra remains a local MVP and should not be exposed publicly without authentication, authorization, TLS, and deployment hardening.

## Recommended Next Module

Open the next module as docs-first: `ci_cd_config_basic`.

Rationale: CI/CD configuration sits naturally between package, secrets, Docker, and deployment posture. A passive archive-based review can reuse the bounded-read and redaction patterns already established while checking workflow files for risky triggers, inline secrets, broad permissions, unpinned actions/images, publish/deploy jobs, and environment handling. Keep it strictly local and heuristic: no provider API calls, no token validation, no execution, and no runner emulation.

Suggested pattern:

1. Freeze scope and non-scope in `docs/future/`.
2. Implement runner/parser passively with bounded reads and redaction where relevant.
3. Add backend job/reporting.
4. Add frontend report UX.
5. Close with an end-to-end contract and redaction review.
