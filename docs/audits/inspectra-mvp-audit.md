# Inspectra MVP Internal Audit

Date: 2026-05-26

## 1. Executive Summary

Inspectra is in a coherent MVP state. The recent additions for `archive_basic`, `project_archive_basic`, report export, SBOM export, UI reporting, and tests follow the original defensive architecture: the backend stores state and delegates passive analysis to the `audit-tools` container; the runner validates paths under `data/`; archive and manifest handling avoids broad extraction, package-manager execution, and internet access.

Main strengths:

- Clear file kinds and audit types with cross-kind rejection in backend endpoints.
- Strong local path guardrails for uploaded files, job records, and tool-runner analysis paths.
- External PDF/image commands run without a shell and have per-command timeouts.
- Archive and project-archive parsing uses Python standard library metadata access with explicit limits.
- HTML/XML report exports escape dynamic content; PDF export is local and simple.
- SBOM export is limited to completed dependency-analysis jobs and does not include vulnerabilities, license claims, package-manager execution, or dependency resolution.
- Tests now cover backend, runner, reporting, SBOM exports, frontend filters, report helpers, and the dashboard render path.
- Docker Compose keeps `audit-tools` internal, read-only over `data/`, with dropped capabilities and `no-new-privileges`.

Main risks:

- SBOM package URLs can be too confident for URL/VCS/local dependency declarations.
- Markdown reports only minimally escape dynamic content.
- ZIP analysis still relies on `zipfile.infolist()`, which materializes ZIP metadata before entry limits are applied.
- JSON storage is atomic per write but has no concurrency locking across background job updates and delete/mark operations.

Recommendation: continue development, but schedule a hardening microfase before adding larger new analyzers. No critical or high severity issues were found in this review.

## 2. Scope Reviewed

- Backend FastAPI endpoints, services, storage, configuration, and models.
- Tool runner analysis code for PDF, image, manifest, archive, and project-archive flows.
- Reporting exports in Markdown, HTML, XML, and PDF.
- Offline SBOM export in CycloneDX JSON and SPDX JSON.
- Frontend API client, dashboard, filters, report helpers, and report components.
- Docker Compose and Dockerfiles.
- README, architecture, and security-scope documentation.
- Backend, runner, and frontend tests.
- Git history, `.gitignore`, generated-file hygiene, and local risk-pattern searches.

## 3. Validations Executed

| Command | Result | Observations |
| --- | --- | --- |
| `git status --short` | Passed | Initial tree was clean. |
| `git log --oneline -10` | Passed | Recent commits are coherent and map to microfases. |
| `docker compose config` | Passed | Compose resolves with backend, frontend, internal `audit-tools`, read-only tool mount, dropped capabilities, and documented environment variables. |
| `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools` | Passed | Python sources compiled without syntax errors. |
| `.venv/bin/python -m pytest` | Passed | `57 passed`. |
| `npm run build` in `frontend` | Passed | TypeScript and Vite production build completed. |
| `npm run test -- --run` in `frontend` | Passed | `12 passed`. |
| `git diff --check` | Passed | No whitespace errors; rerun after report creation also passed. |
| `git diff --cached --check` | Passed | No staged whitespace errors before report staging. |
| Risk-pattern search for `shell=True`, `os.system`, `eval(`, `exec(`, `extractall`, `.extract(`, `unpack_archive`, `dangerouslySetInnerHTML`, `docker.sock`, wildcard CORS | Passed | No matches in reviewed source, excluding dependencies, build output, caches, `.git`, and `data`. |
| Search for URLs, package-manager strings, CVE/vulnerability language, TODO/FIXME | Passed with expected hits | Hits were documentation, lockfile registry metadata, tests, Docker install commands, local healthchecks, or passive string detection. No runtime package-manager execution against audit input found. |
| Search for file/archive/process APIs | Reviewed | Expected use of `subprocess.run` without shell, `zipfile`, `tarfile`, `archive.open`, `extractfile`, JSON reads/writes, and safe unlink paths. |

## 4. Findings

### INSPECTRA-AUDIT-001

- Severity: medium
- Area: sbom
- Status: needs-review
- Evidence: `backend/app/sbom.py:248-256`, `tools/runner/main.py:428-442`, `tools/runner/main.py:641-644`
- Description: SBOM export builds package URLs for any normalized npm/PyPI dependency name. For URL, VCS, editable, or local-path dependency declarations, a generated package URL can imply a registry package identity that Inspectra has not verified.
- Impact: SBOM consumers may over-trust a generated `purl` for dependencies that were actually declared from a URL, VCS source, or local path. This is an accuracy and supply-chain interpretation risk, not an execution risk.
- Recommendation: In the next SBOM hardening microfase, suppress `purl` for URL/VCS/local/editable declarations unless the parser can identify a registry package unambiguously. Preserve the original declaration in properties/comments.
- Suggested priority: P1

### INSPECTRA-AUDIT-002

- Severity: low
- Area: reporting
- Status: open
- Evidence: `backend/app/reporting.py:31-32`, `backend/app/reporting.py:431-432`
- Description: Markdown export only replaces `<` and `>` in dynamic values. Markdown syntax such as links or image references is not neutralized.
- Impact: If a report is opened in a rich Markdown renderer, attacker-controlled metadata could render as clickable links or remote image references. Inspectra does not execute this content, but a Markdown renderer outside Inspectra may fetch remote resources or make the report visually misleading.
- Recommendation: Escape or code-format dynamic Markdown values more aggressively, or render all untrusted values inside fenced/code spans in a future reporting hardening pass.
- Suggested priority: P2

### INSPECTRA-AUDIT-003

- Severity: low
- Area: runner
- Status: open
- Evidence: `tools/runner/main.py:680-682`, `tools/runner/main.py:820-821`
- Description: ZIP archive analysis uses `zipfile.ZipFile(...).infolist()`, which materializes ZIP entry metadata before Inspectra applies `ARCHIVE_MAX_ENTRIES` or `PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES`.
- Impact: The upload size limit bounds the practical impact, but highly fragmented ZIP central directories can still consume more memory/time than the configured entry limit suggests.
- Recommendation: Document this limitation and consider a stricter archive upload size for ZIP-heavy workflows, a lower entry cap, or a streaming/early-abort strategy if Python's ZIP API can support it sufficiently for the use case.
- Suggested priority: P2

### INSPECTRA-AUDIT-004

- Severity: low
- Area: backend
- Status: accepted-risk
- Evidence: `backend/app/storage.py:41-45`, `backend/app/storage.py:267-292`
- Description: JSON writes are atomic through temp-file replacement, but there is no file lock or compare-and-swap protection around job updates. Concurrent background updates and deletion marking can overwrite fields such as `source_file_deleted_at` or result/error state.
- Impact: Under concurrent local use, historical job metadata can lose a recent field update. This does not currently allow path traversal or arbitrary file writes, but it can reduce result consistency.
- Recommendation: Accept for the MVP. Before multi-user or parallel-heavy use, introduce a small persistence layer with locking, optimistic version checks, or SQLite.
- Suggested priority: P2

### INSPECTRA-AUDIT-005

- Severity: info
- Area: backend
- Status: accepted-risk
- Evidence: `backend/app/main.py:45-50`, `backend/app/config.py:55-60`, `docs/architecture.md:151`
- Description: CORS defaults are explicit and development-only, but the environment parser does not prevent operators from configuring a wildcard origin.
- Impact: This is acceptable for local development, but production-like deployments could weaken browser boundary assumptions if `INSPECTRA_CORS_ORIGINS=*` is set.
- Recommendation: Keep as MVP accepted risk. If Inspectra gains auth or remote deployment guidance, validate or warn on wildcard CORS.
- Suggested priority: P3

## 5. Acceptable MVP Risks

- No authentication or authorization: acceptable only for trusted local development or controlled lab use.
- JSON file storage: simple and inspectable, but not intended for multi-user concurrency or high write volume.
- No pagination for files/jobs: acceptable while local result counts remain small.
- Development CORS default: acceptable because the default is `http://localhost:5173` and credentials are disabled.
- Simple PDF writer: acceptable because it is local, static, and does not use browser automation or external services.
- SBOM export without schema validation: acceptable for early MVP; generated JSON is parseable and tested, but not externally schema-validated.
- Archive analysis is metadata-oriented: it intentionally avoids broad extraction and therefore cannot prove archive safety.
- Tool container boundary: useful hardening, but not a complete sandbox against parser bugs in underlying tools.

## 6. Test Gaps

Priority test gaps:

1. SBOM dependencies declared via URL, VCS, `file:`, editable requirements, and local paths should verify that package URLs are omitted or marked carefully after hardening.
2. Markdown export should include malicious Markdown fixture cases such as links/images and verify the chosen neutralization strategy.
3. ZIP archives with many entries should exercise configured truncation and measure behavior around entry limits.
4. Backend storage concurrency should cover delete/mark racing with background job completion once persistence is hardened.
5. Frontend auto-refresh should have a focused test that fake timers clear the interval when active jobs disappear.
6. CORS configuration should be tested if wildcard rejection or warning is added.
7. Docker/Compose smoke tests could verify service health and mounted-data permissions in CI if that becomes practical.

Existing coverage is healthy for the MVP: uploads, cross-kind audit rejection, invalid IDs, archive path traversal indicators, corrupt archives, internal manifest parsing, SBOM compatible/incompatible jobs, reporting exports, frontend filters, report helpers, and dashboard rendering are covered.

## 7. Documentation Gaps

- Document SBOM limitations around package URLs for URL/VCS/local dependencies after the SBOM hardening decision.
- Add a short "production readiness" note: no auth, local-only assumption, CORS guidance, and storage limitations.
- Clarify that ZIP entry limits are applied after Python has parsed ZIP metadata, so upload size remains the primary resource guardrail for central-directory-heavy ZIP files.
- Add a short persistence note explaining atomic JSON writes but no strong concurrency semantics.
- Add an "audit report history" index if future internal audit reports accumulate under `docs/audits/`.

## 8. Recommendations For Next Microfases

1. SBOM hardening: refine component normalization for URL/VCS/local/editable dependency declarations and add tests.
2. Reporting hardening: neutralize Markdown dynamic values more completely and add malicious Markdown fixtures.
3. Archive hardening: document or reduce ZIP metadata enumeration risk, and add stress-style unit fixtures within small upload limits.
4. Persistence hardening: introduce file-level locking or SQLite before multi-user use.
5. Frontend reliability: add fake-timer tests for auto-refresh lifecycle and more interaction tests around job details.
6. Production readiness docs: explicitly state local-only assumptions and deployment warnings.
7. New features only after the above hardening pass, with ZIP/project archive workflows remaining bounded and offline.

## Follow-up Status

- `INSPECTRA-AUDIT-001`: addressed in the follow-up microfase `fix(sbom): avoid purl for ambiguous dependency sources`. SBOM export now generates package URLs only for clear npm/PyPI registry dependencies, preserves ambiguous declarations, and records an omitted-`purl` reason for URL, VCS, local, editable, workspace, and alias sources.
- `INSPECTRA-AUDIT-002`: addressed in the follow-up microfase `fix(reports): harden markdown export escaping`. Markdown report export now renders dynamic job values as code spans or fenced code blocks, including malicious Markdown links/images, inline HTML, headings, pipes, blockquotes, and multiline tool output.
- `INSPECTRA-AUDIT-003`: mitigated in the follow-up microfase `fix(audits): harden archive entry limit handling`. ZIP analysis now performs a standard EOCD metadata preflight for declared entry count and central directory size before detailed `zipfile` parsing, marks results truncated when limits are exceeded, and documents conservative handling for ZIP64 or inconclusive metadata.
- `INSPECTRA-AUDIT-004`: mitigated in the follow-up microfase `fix(storage): add file locking for JSON persistence`. Backend JSON writes now use a local storage lock for write and read-modify-write operations, and stale job saves preserve existing `source_file_deleted_at` markers. This improves local consistency while keeping SQLite as the recommended future step for multi-user/high-volume deployments.
