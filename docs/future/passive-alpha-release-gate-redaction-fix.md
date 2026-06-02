# Passive Alpha Release Gate Redaction Fix

Status: `REDACTION_FIX_VALIDATED_API_RERUN_PASSED_BROWSER_PENDING`.

Base blocker document: `docs/future/passive-alpha-release-gate-smoke-run.md`

Fix commit target: `fix(redaction): block passive alpha ci nginx leaks`

This document records the focused follow-up for the release-gate redaction blockers found in the Passive Technical Alpha smoke run. It does not create a tag, create a release, add analyzers, change endpoints, add frontend behavior, expand passive scope, or introduce active/network execution.

Full API smoke rerun follow-up: `docs/future/passive-alpha-release-gate-smoke-rerun.md`.

## Blocker Summary

The smoke run at `c23c0ca docs(alpha): record passive release gate smoke run` found release-blocking leaks before the alpha tag:

- `ci_cd_config_basic` exposed `token_should_never_render` and `Authorization: Bearer token_should_never_render`.
- `nginx_config_basic` exposed synthetic secret strings from the redaction-negative archive through parser error/reporting surfaces.
- Affected API surfaces included stored job JSON, `GET /jobs/{job_id}`, and Markdown/HTML/XML/PDF exports.
- Affected fixtures were `demo-archive-container-infra.zip` and `demo-archive-redaction-negative.zip`.

## Root Causes Fixed

- CI/CD runner redaction did not handle bare `Authorization: Bearer ...` or `Bearer ...` script/header excerpts.
- CI/CD backend service stored the runner response directly instead of applying the analyzer-specific defensive redaction before persistence.
- `GET /jobs/{job_id}` did not include `ci_cd_config_basic` in the public-result redaction allowlist used by newer passive modules.
- Nginx parser controlled errors could include sensitive lines from broad `*.conf` candidates such as Redis-style `requirepass` and `masterauth` directives.
- Backend Nginx legacy redaction did not treat `auth_basic` directive arguments as secret-bearing when malformed/legacy payloads supplied raw values.

## Surfaces Covered

- Runner result JSON for `ci_cd_config_basic`.
- Runner result JSON for `nginx_config_basic`, including controlled parser errors.
- Backend stored job result for `ci_cd_config_basic`.
- `GET /jobs/{job_id}` public result for `ci_cd_config_basic`.
- Markdown, HTML, XML, and PDF exports through existing public-result/reporting paths.
- Legacy/malformed backend payloads with raw CI/CD bearer headers or Nginx auth directives.

## Redaction Strings Checked

- `token_should_never_render`
- `Authorization: Bearer token_should_never_render`
- `super-secret-password`
- `http://user:pass@example.com`
- `http://registry-user:registry-pass@example.com`
- `registry-user:registry-pass`
- `PRIVATE KEY`

Expected replacement remains the fixed placeholder `[REDACTED]`. No prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers are intentionally emitted.

## Scope Preserved

- No CI workflow execution.
- No Nginx execution or `nginx -t`.
- No Docker/container startup.
- No network, DNS, port, provider, registry, CVE, advisory, credential-validation, or external API calls.
- No `.env`, ACL, RDB, AOF, backup, or host-path reads.
- No new analyzers, endpoints, frontend behavior, jobs, or findings.
- Findings remain heuristic review indicators, not confirmed vulnerabilities or compromise claims.

## Validation Plan

Required validation commands for this fix:

- `git status --short`
- `git log --oneline -12`
- `python3 -m compileall backend tools`
- `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools`
- `.venv/bin/python -m pytest tools/tests/test_runner.py -k "ci_cd_config or nginx_config"`
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k "ci_cd_config or nginx_config or redaction"`
- `.venv/bin/python -m pytest tools/tests/test_runner.py -k "not web_basic"`
- `.venv/bin/python -m pytest backend/tests/test_backend.py`
- A partial API smoke for affected fixtures/analyzers when local service ports are available.
- `git diff --check`
- `git diff --cached --check`

## Validation Results

Focused validations completed during this microphase:

| Validation | Result | Notes |
| --- | --- | --- |
| `git status --short` | Pass | Confirmed dirty working tree only after expected fix files changed. |
| `git log --oneline -12` | Pass | Confirmed `c23c0ca docs(alpha): record passive release gate smoke run` as current base. |
| `python3 -m compileall backend tools` | Pass | Backend and runner files compiled. |
| `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools` | Pass | Backend and runner files compiled with cache outside repo. |
| `.venv/bin/python -m pytest tools/tests/test_runner.py -k "ci_cd_config or nginx_config"` | Pass | `11 passed, 117 deselected`. |
| `.venv/bin/python -m pytest backend/tests/test_backend.py -k "ci_cd_config or nginx_config or redaction"` | Pass | `14 passed, 175 deselected`. |
| `.venv/bin/python -m pytest tools/tests/test_runner.py -k "not web_basic"` | Pass | `117 passed, 11 deselected`. |
| `.venv/bin/python -m pytest backend/tests/test_backend.py` | Pass | `189 passed`. |

Partial API smoke also passed for the release-gate redaction blockers:

| Fixture | Analyzer | Surfaces checked | Result |
| --- | --- | --- | --- |
| `demo-archive-container-infra.zip` | `ci-cd-config` | `GET /jobs/{job_id}`, Markdown, HTML, XML, PDF | Pass |
| `demo-archive-redaction-negative.zip` | `ci-cd-config` | `GET /jobs/{job_id}`, Markdown, HTML, XML, PDF | Pass |
| `demo-archive-redaction-negative.zip` | `nginx-config` | `GET /jobs/{job_id}`, Markdown, HTML, XML, PDF | Pass |

The first sandbox-local client attempt failed with `Operation not permitted` on localhost sockets. The smoke was then executed in a single approved localhost context with local runner/backend processes started on alternate ports and stopped at exit.

## Product Decision

This fix cleared the API/export redaction blockers in the full smoke rerun. It is still not sufficient for tagging the alpha because real browser DOM and Raw JSON smoke remains pending.

Recommended next microphase:

```text
PASSIVE-ALPHA-MANUAL-BROWSER-SMOKE-BEFORE-TAG
```
