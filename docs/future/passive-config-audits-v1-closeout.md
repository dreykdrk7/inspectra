# Passive Config Audits v1 Closeout

Status: `django_config_basic`, `docker_config_basic`, and `secrets_review_basic` are closed as v1 passive archive-based audit modules.

This document is a lightweight smoke and scope reference before opening the next module. Runtime details remain in `README.md`, `docs/architecture.md`, and `docs/security-scope.md`.

## Module Status

| Module | Status | Primary value | Key guardrails |
| --- | --- | --- | --- |
| `django_config_basic` | v1 closed | Reviews Django settings, deployment hints, environment templates, and related config inside uploaded archives. | Does not execute Python, import settings, run `manage.py`, install dependencies, connect to databases, or read real `.env` files. |
| `docker_config_basic` | v1 closed | Reviews Dockerfile, Docker Compose, and `.dockerignore` indicators inside uploaded archives. | Does not execute Docker, build images, start containers, inspect the Docker socket, download images, resolve tags, scan ports, or query CVEs. |
| `secrets_review_basic` | v1 closed | Performs redaction-first review of candidate text files for secret-exposure indicators. | Does not validate credentials, call providers, scan Git history, run external scanners, compute fingerprints, or read real `.env`, `.env.*`, or `.envrc` content. |

## Shared Capabilities

- All three modules accept uploaded files registered as `kind: "archive"`.
- Archive reads are bounded by per-module file count, per-file byte, total-byte, archive-entry, and ZIP central directory metadata limits.
- ZIP/TAR/TAR.GZ/TGZ archives are inspected with standard library parsers.
- Path traversal entries, absolute paths, symlinks, hardlinks, non-regular entries, oversized files, and unsupported binary content are skipped or handled as controlled errors.
- Findings are heuristic review indicators and require manual validation.
- Results are persisted as jobs, included in job summaries, rendered in the frontend, and exportable as Markdown, HTML, XML, and PDF.
- Secret-like evidence is redacted best-effort in runner results, backend exports, frontend reports, and raw JSON views for sensitive modules.

## Explicit Non-Scope

- No project code execution.
- No broad extraction of archives to the filesystem.
- No Docker build/run/compose execution or Docker socket access.
- No secret validation against external providers.
- No network calls, CVE lookups, registry lookups, package-manager installs, or external scanners.
- No Git history scanning or deep secret-scanning replacement.
- No claim that findings are confirmed vulnerabilities, active credentials, leaked tokens, or exploitable deployment issues.

## Smoke Checklist

Recommended smoke checks before opening a new passive module:

- Upload a small archive containing Django settings, Dockerfile/Compose files, and secret-review fixtures.
- Launch `django_config_basic`, `docker_config_basic`, and `secrets_review_basic` from the UI archive actions.
- Confirm each job reaches a terminal state and appears in `GET /jobs` with compact summary metrics.
- Open each frontend report and confirm summary, findings, files, limits/errors, redaction notes, and raw JSON render clearly.
- Export each job to Markdown, HTML, XML, and PDF.
- Confirm real env files are detected but not read.
- Confirm fixture secrets do not appear unredacted in reports, raw JSON, exports, or controlled errors.

For docs-only closeout changes, the minimum validation is:

```bash
git status --short
git diff --check
git diff --cached --check
```

If runtime code changes, also run the relevant focused suites plus the normal build/test commands for the touched layer.

## Residual Risks

- Heuristics do not replace manual review or production hardening.
- Development, test, sample, and template context detection is best-effort.
- Secret redaction is best-effort and may miss uncommon formats or names.
- Uploaded archive bytes are stored locally and can contain secrets even when Inspectra results are redacted.
- No CVE, advisory, registry, provider, or token-validity checks are performed.
- Inspectra remains a local MVP and should not be exposed publicly without authentication, authorization, TLS, and deployment hardening.

## Recommended Next Module

Open the next module as docs-first: `node/package config` passive review. Keep the same pattern:

1. Freeze scope and non-scope in `docs/future/`.
2. Implement runner/parser passively with bounded reads and redaction where relevant.
3. Add backend job/reporting.
4. Add frontend report UX.
5. Close with an end-to-end contract and redaction review.
