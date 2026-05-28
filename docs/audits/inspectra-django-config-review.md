# Inspectra Django Config Basic Review

Date: 2026-05-28

Reviewed commit: `9190705 feat(audits): add passive Django config analysis`

## 1. Executive Summary

`django_config_basic` is integrated coherently with Inspectra's existing archive-based audit model. The backend accepts only uploaded `kind: "archive"` files, creates a `django_config_basic` job, and delegates bounded static analysis to the runner. The runner does not execute Python, import Django settings, install dependencies, connect to databases, extract full archives, or follow symlinks/hardlinks. The UI, summaries, filters, exports, Docker configuration, and documentation were updated consistently.

The module is suitable for MVP use as a passive indicator generator, not as a production-readiness verdict. The strongest parts are the archive safety posture, bounded reads, clear `.env` non-read behavior for plain `.env`, and redacted finding evidence for the primary implemented checks.

Main risks are precision and defense-in-depth rather than active exploitation: real `.env.*` variants are not detected as sensitive Django files, reporting does not add a Django-specific redaction safety net for malformed or future legacy job payloads, and some heuristics can generate noisy findings on development settings or comments.

Recommendation: continue, but schedule a short hardening microphase before treating this module as a stable security signal. No critical or high severity issues were found.

## 2. Scope Reviewed

- Backend: `backend/app/main.py`, `backend/app/models.py`, `backend/app/services.py`, `backend/app/storage.py`, `backend/app/reporting.py`, `backend/app/config.py`, backend tests.
- Runner: `tools/runner/main.py`, Django config archive handling, candidate file selection, limits, redaction helpers, Django heuristics, runner tests.
- Frontend: `frontend/src/App.tsx`, `frontend/src/api.ts`, `frontend/src/types.ts`, `frontend/src/DjangoConfigJobReport.tsx`, `frontend/src/djangoConfigReport.ts`, `frontend/src/dashboardFilters.ts`, frontend tests.
- Reporting: Markdown, HTML, XML, PDF section generation for `django_config_basic`.
- Docker/config: `docker-compose.yml` and environment variable defaults.
- Docs: `README.md`, `docs/architecture.md`, `docs/security-scope.md`.
- Tests: backend, runner, frontend coverage related to `django_config_basic`.

## 3. Validations Executed

| Command | Result | Observations |
| --- | --- | --- |
| `git status --short` | Passed | Initial tree was clean. |
| `git log --oneline -10` | Passed | Reviewed recent history; `9190705` is the latest commit. |
| `git show --stat --oneline 9190705` | Passed | Confirmed 22 files changed, 1756 insertions, 16 deletions. |
| `git show --name-only --oneline 9190705` | Passed | Confirmed touched backend, runner, frontend, docs, tests, and Compose files. |
| Risk-pattern search | Passed with expected hits | Hits were Django passive parser strings, documentation, and tests. No `shell=True`, `os.system`, `eval(`, `exec(`, `compile(`, `importlib`, `django.setup`, archive extraction, `dangerouslySetInnerHTML`, Docker socket, package-manager execution, or offensive tooling implementation found in the Django path. |
| `docker compose config` | Passed | Compose renders with new Django config variables and existing container hardening. |
| `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools` | Passed | Backend and runner compile. |
| `.venv/bin/python -m pytest` | Passed outside sandbox | Sandbox blocks local HTTP server sockets used by existing web tests. Re-ran outside sandbox; full Python suite passed. |
| `npm run build` in `frontend` | Passed | TypeScript and Vite build completed. |
| `npm run test -- --run` in `frontend` | Passed | Frontend tests passed. |
| `git diff --check` | Passed | No whitespace errors. |
| `git diff --cached --check` | Passed | No staged whitespace errors before commit. |

## 4. Findings

### INSPECTRA-DJANGO-REVIEW-001

Severity: low

Area: runner

Status: open

Evidence:
- `tools/runner/main.py:3581`
- `tools/runner/main.py:3583`
- `tools/runner/main.py:4447`
- `tools/runner/main.py:4449`

Description:
The Django config classifier treats only basename `.env` as `env_sensitive`, and only explicit template/sample names as readable templates. Existing archive metadata helpers already recognize `.env.*` names as sensitive, but `django_config_basic` does not classify `.env.production`, `.env.prod`, `.env.local`, or similar real environment files as detected sensitive Django files.

Impact:
This does not read or leak those files because unclassified entries are ignored. The risk is misleading coverage: users may believe real environment files were detected when only plain `.env` is currently reported.

Recommendation:
Extend Django candidate classification to detect real `.env*` variants as `env_sensitive` while preserving the existing allowlist for `.env.example`, `.env.template`, `.env.sample`, `env.example`, `env.template`, and `sample.env`.

Suggested priority: P1, small hardening.

### INSPECTRA-DJANGO-REVIEW-002

Severity: low

Area: reporting

Status: open

Evidence:
- `backend/app/reporting.py:298`
- `backend/app/reporting.py:306`
- `backend/app/reporting.py:308`
- `frontend/src/DjangoConfigJobReport.tsx:184`
- `frontend/src/DjangoConfigJobReport.tsx:188`

Description:
Current runner-generated Django findings use redacted evidence, but reporting and the UI flatten/display stored job data directly for `django_config_basic`. There is no Django-specific defensive redaction pass in exports or raw JSON rendering for malformed, manually edited, or future legacy job results that contain unredacted secret-like strings.

Impact:
Default results from the current runner do not appear to store raw secret values in finding evidence. However, if a future parser change or legacy payload stores a raw `SECRET_KEY`, password, token, database URL, or private key in `result`, exports and raw JSON could reproduce it.

Recommendation:
Add a defensive Django result redaction helper in reporting and, if practical, frontend report normalization. Add regression tests with a legacy `django_config_basic` job containing raw secret-like evidence and assert Markdown/HTML/XML/PDF exports do not include the secret.

Suggested priority: P1, defense-in-depth.

### INSPECTRA-DJANGO-REVIEW-003

Severity: low

Area: runner

Status: open

Evidence:
- `tools/runner/main.py:3700`
- `tools/runner/main.py:3727`
- `tools/runner/main.py:3781`
- `tools/runner/main.py:3814`
- `tools/runner/main.py:3857`
- `tools/runner/main.py:3916`
- `tools/runner/main.py:3944`

Description:
Several heuristics are intentionally simple regex/string checks. Some are unanchored or apply missing-setting findings to every settings file. This can flag comments, example snippets, development/test settings, or partial settings modules. Secure-cookie, SSL redirect, HSTS, and `X_FRAME_OPTIONS` findings are emitted per settings file when not observed as explicit true/configured values.

Impact:
The module may produce noisy reports on common Django layouts with `settings/base.py`, `settings/dev.py`, and `settings/prod.py`, or on archives that include examples. Noise can reduce trust in higher-signal findings such as `DEBUG=True` or hardcoded secrets.

Recommendation:
Add comment-aware line scanning and context labels for likely dev/test/example files. Consider grouping missing-setting findings once per archive or marking them as "not observed in inspected settings" instead of per-file findings.

Suggested priority: P2, precision hardening.

### INSPECTRA-DJANGO-REVIEW-004

Severity: info

Area: runner

Status: open

Evidence:
- `tools/runner/main.py:3546`
- `tools/runner/main.py:3550`
- `tools/runner/main.py:3555`
- `tools/runner/main.py:3557`

Description:
`files_read` and `bytes_read` are incremented before UTF-8 decoding. If decoding fails, the file record is changed back to `read: false`, but the summary still counts it as read.

Impact:
This is not a security issue, but it can make summary metrics inconsistent for archives containing binary or non-UTF-8 candidate files.

Recommendation:
Increment `files_read` only after successful decoding, or introduce a separate `files_opened`/`bytes_scanned` metric if the current behavior is intentional.

Suggested priority: P3.

### INSPECTRA-DJANGO-REVIEW-005

Severity: info

Area: tests

Status: open

Evidence:
- `tools/tests/test_runner.py:557`
- `tools/tests/test_runner.py:596`
- `tools/tests/test_runner.py:630`
- `tools/tests/test_runner.py:649`
- `tools/tests/test_runner.py:680`
- `backend/tests/test_backend.py:1486`
- `frontend/src/reportHelpers.test.ts:298`

Description:
The initial tests cover the happy path, plain `.env` non-read behavior, path traversal, symlink/hardlink skipping, limits, non-execution, export basics, and frontend helper normalization. Gaps remain for `.env.*` variants, SECRET_KEY fallback patterns, comment false positives, non-UTF-8 candidate files, corrupt/unsupported archive Django exports, and sparse/queued/running/failed `django_config_basic` exports.

Impact:
The current coverage catches the most important safety guarantees but does not yet lock down the edge cases most likely to regress during heuristic tuning.

Recommendation:
Add targeted tests before expanding Django checks. Prioritize `.env.production` non-read/detection, fallback secret redaction, comments not causing medium findings, export redaction for legacy raw secrets, and sparse/non-completed exports.

Suggested priority: P2.

## 5. Acceptable MVP Risks

- Heuristics are not equivalent to a manual Django deployment review.
- Findings are indicators, not confirmed vulnerabilities.
- Development/test/example settings can produce false positives.
- Inspectra does not run `manage.py check --deploy`.
- Inspectra does not import settings modules or execute Django code.
- Inspectra does not read real `.env` content.
- Inspectra does not install dependencies, resolve project configuration dynamically, or connect to databases.
- Docker, nginx, gunicorn, systemd, and Compose analysis is intentionally shallow.
- Static regex parsing can miss complex dynamic configuration.
- Archive metadata parsing still depends on Python standard library ZIP/TAR behavior and configured upload limits.

## 6. Test Gaps

Priority order:

1. `.env.production`, `.env.prod`, `.env.local`, and `.env.*` are detected as sensitive and not read.
2. Legacy/malformed `django_config_basic` result with raw secret-like finding evidence is redacted in Markdown/HTML/XML/PDF exports.
3. SECRET_KEY fallback variants are detected and redacted.
4. Comments and documentation snippets do not trigger medium findings.
5. Multi-settings archives avoid excessive duplicate low/info findings.
6. Non-UTF-8 candidate files produce consistent summary metrics.
7. Unsupported/corrupt archives return controlled Django config results.
8. Queued/running/failed/sparse `django_config_basic` exports do not throw and remain useful.
9. Docker Compose hardcoded password-like environment entries are either detected or explicitly documented as out of scope.
10. Frontend action visibility is tested for non-archive files, not only archive positive path.

## 7. Documentation Gaps

- The docs say real `.env` files are detected but do not clarify that only plain `.env` is currently detected by the Django classifier.
- The docs could more explicitly state that settings file path context is not interpreted as production/dev/test in this first phase.
- The docs could mention that missing security setting findings mean "not observed in bounded static text," not proof that the deployed app lacks the control.
- The docs could list concrete env-template names that may be read and real env patterns that are skipped once `.env.*` detection is added.

## 8. Recommendations For Next Microphases

1. Fix `INSPECTRA-DJANGO-REVIEW-001` and `INSPECTRA-DJANGO-REVIEW-002`: detect `.env.*` variants as sensitive and add defensive export redaction for Django config results.
2. Add edge tests from `INSPECTRA-DJANGO-REVIEW-005`, especially legacy secret export redaction and sparse/non-completed exports.
3. Reduce heuristic noise by making comment-aware checks and grouping missing-setting findings.
4. Review deployment-file secret detection for Compose/systemd environment formats.
5. Only after the above, consider a `production_readiness_docs` or more refined Django deployment checklist module.
6. Keep `infra_basic` with Nmap and CVE/advisory enrichment for later, explicitly controlled phases.
