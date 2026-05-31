# Passive CI/CD Config Audits v3 Closeout

Status: historical pre-Kubernetes closeout. `django_config_basic`, `docker_config_basic`, `secrets_review_basic`, `node_package_config_basic`, and `ci_cd_config_basic` were closed as v1 passive archive-based audit modules here; `k8s_config_basic` was later implemented and closed in `docs/future/k8s-config-basic-closeout.md`.

This document is a lightweight smoke and scope reference before opening another passive module. Runtime details remain in `README.md`, `docs/architecture.md`, and `docs/security-scope.md`; design documents in `docs/future/` remain historical references.

## Module Status

| Module | Status | Primary value | Key guardrails |
| --- | --- | --- | --- |
| `django_config_basic` | v1 closed | Reviews Django settings, deployment hints, environment templates, and related config inside uploaded archives. | Does not execute Python, import settings, run `manage.py`, install dependencies, connect to databases, or read real `.env` files. |
| `docker_config_basic` | v1 closed | Reviews Dockerfile, Docker Compose, and `.dockerignore` indicators inside uploaded archives. | Does not execute Docker, build images, start containers, inspect the Docker socket, download images, resolve tags, scan ports, or query CVEs. |
| `secrets_review_basic` | v1 closed | Performs redaction-first review of candidate text files for secret-exposure indicators. | Does not validate credentials, call providers, scan Git history, run external scanners, compute fingerprints, or read real `.env`, `.env.*`, or `.envrc` content. |
| `node_package_config_basic` | v1 closed | Reviews Node package manifests, lockfiles, package-manager config, JS/TS tool config, and CI/publishing hints inside uploaded archives. | Does not execute npm, pnpm, yarn, bun, npx, lifecycle scripts, JavaScript, TypeScript, or config files; install dependencies; resolve transitive dependencies; query registries; run `npm audit`; query advisories/CVEs; or claim malicious-package verdicts. |
| `ci_cd_config_basic` | v1 closed | Reviews CI/CD workflows, triggers, permissions, action/image pinning, secret/env handling, publish/deploy signals, runners, artifacts, caches, and service-container hints inside uploaded archives. | Does not execute workflows, emulate runners, evaluate dynamic expressions, call provider APIs, validate tokens, execute scripts, resolve remote actions or reusable workflows, download actions/images, query CVEs/advisories, or claim compromised-pipeline verdicts. |

## Shared Capabilities

- All five modules accept uploaded files registered as `kind: "archive"`.
- Archive reads are bounded by per-module file count, per-file byte, total-byte, archive-entry, and ZIP central directory metadata limits.
- ZIP/TAR/TAR.GZ/TGZ archives are inspected with Python standard library parsers.
- Path traversal entries, absolute paths, symlinks, hardlinks, non-regular entries, oversized files, and unsupported binary content are skipped or handled as controlled errors.
- Findings are heuristic review indicators and require manual validation.
- Results are persisted as jobs, included in compact job summaries, rendered in the frontend, and exportable as Markdown, HTML, XML, and PDF.
- Secret-like evidence is redacted best-effort in runner results, backend exports, frontend reports, and raw JSON views for modules that handle sensitive-looking text.
- Real `.env`, `.env.*`, and `.envrc` files are detected but not read by modules that inspect env-like paths.

## Module Differences

- Config/deployment audits: `django_config_basic` and `docker_config_basic` focus on framework and deployment configuration posture.
- Exposure/redaction audit: `secrets_review_basic` focuses on secret-like values, sensitive files present, and safe evidence redaction.
- Package/supply-chain hygiene audit: `node_package_config_basic` focuses on package manifests, lifecycle scripts, dependency declaration indicators, package-manager config signals, and lockfile consistency hints without installing or resolving packages.
- Workflow/pipeline posture audit: `ci_cd_config_basic` focuses on workflow triggers, permissions, action/image pinning, secret/env handling, publish/deploy signals, runner hints, artifacts, caches, and service containers without executing or emulating CI providers.

## Explicit Non-Scope

- No project code execution.
- No broad extraction of archives to the filesystem.
- No Docker build/run/compose execution, Docker socket access, image downloads, image tag resolution, or port scanning.
- No npm, pnpm, yarn, bun, npx, lifecycle-script, JavaScript, TypeScript, or config-file execution.
- No package installation, transitive dependency resolution, registry access, `npm audit`, advisory lookup, CVE lookup, or malicious-package verdicts.
- No workflow execution, runner emulation, provider expression evaluation, provider API calls, token validation, action/image downloads, remote reusable workflow/include resolution, or compromised-pipeline verdicts.
- No secret validation against external providers.
- No network calls, Git history scanning, deep external secret scanners, credential activity claims, or exploitability claims.
- No claim that findings are confirmed vulnerabilities, active credentials, leaked tokens, malicious packages, compromised pipelines, or exploitable deployment issues.

## Smoke Checklist

Recommended smoke checks before opening a new passive module:

- Upload a small archive containing Django settings, Dockerfile/Compose files, secret-review fixtures, `package.json`, a lockfile, `.npmrc` fixture data, and CI/CD workflow files.
- Launch `django_config_basic`, `docker_config_basic`, `secrets_review_basic`, `node_package_config_basic`, and `ci_cd_config_basic` from the UI archive actions.
- Confirm each job reaches a terminal state and appears in `GET /jobs` with compact summary metrics.
- Open each frontend report and confirm summary, findings, context, files reviewed/detected, limits/errors, redaction notes, and raw JSON render clearly.
- Confirm the CI/CD report shows workflow overview, triggers, permissions, jobs/steps, actions/images, service containers, publish/deploy signals, findings, redaction notes, limits/errors, and redacted raw JSON.
- Export each job to Markdown, HTML, XML, and PDF.
- Confirm real `.env`, `.env.*`, and `.envrc` files are detected but not read where the module handles env-like paths.
- Confirm fixture tokens, passwords, URL credentials, private-key material, npm auth values, and CI provider-token-like values do not appear unredacted in UI reports, raw JSON, exports, or controlled errors.
- Confirm CI/CD findings remain review indicators and do not use compromised-pipeline, confirmed-vulnerability, exploited, or vulnerable wording.

For docs-only closeout changes, the minimum validation is:

```bash
git status --short
git diff --check
git diff --cached --check
```

If runtime code changes, also run the relevant focused suites plus the normal build/test commands for the touched layer.

## Residual Risks

- Heuristics do not replace manual review, production hardening, or dedicated ecosystem tooling.
- Development, test, local, sample, template, publish, release, and deployment context detection is best-effort.
- Secret redaction is best-effort and may miss uncommon formats or names.
- Uploaded archive bytes are stored locally and can contain secrets even when Inspectra results are redacted.
- No CVE, advisory, registry, provider, token-validity, exploitability, or malicious-package checks are performed.
- CI/CD workflows are not executed, emulated, or resolved against provider APIs.
- Inspectra remains a local MVP and should not be exposed publicly without authentication, authorization, TLS, and deployment hardening.

## Recommended Next Module

Open the next module as docs-first: `k8s_config_basic`.

Rationale: Kubernetes manifests often sit downstream of Docker, CI/CD, and secrets handling. A passive archive-based review can reuse the bounded-read, context, and redaction patterns already established while checking manifests for plaintext secret data, overly broad workloads, privileged pods, host namespaces, hostPath mounts, missing resource limits, image pull/tag hygiene, service exposure hints, and deployment context. Keep it strictly local and heuristic: no cluster access, no `kubectl`, no admission simulation, no Helm rendering unless explicitly designed later, no CVEs, and no exploitability claims.

Suggested pattern:

1. Freeze scope and non-scope in `docs/future/`.
2. Implement runner/parser passively with bounded reads and redaction where relevant.
3. Add backend job/reporting.
4. Add frontend report UX.
5. Close with an end-to-end contract and redaction review.
