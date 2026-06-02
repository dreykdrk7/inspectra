# Passive Alpha Release Gate Manifest Upload Listing Fix

Status: `READY_FOR_BROWSER_SMOKE_RERUN_BEFORE_TAG`.

Base commit: `fb3c289 docs(alpha): record manual browser smoke before tag`

Target tag: `v0.1.0-passive-alpha`

This document records the release-gate fix for the manifest upload/listing blocker found in the manual browser smoke. It does not create a tag, create a release, add analyzers, add scripts, add fixtures, change exports, change redaction logic, or open active/network scope.

## A. Blocker

The browser smoke recorded in `docs/future/passive-alpha-manual-browser-smoke-before-tag.md` passed DOM and expanded Raw JSON checks for seven archive jobs, but failed the non-archive sanity check:

- uploading `tests/fixtures/demo/passive-alpha/sources/demo-file-basic/manifest/package.json` as `Manifest` left the UI showing `Cannot read properties of null (reading 'reset')`;
- backend `/files` returned `500 Internal Server Error` after the manifest upload;
- the smoke could not verify that the non-archive row exposed `Analyze manifest` and did not expose archive-only actions.

## B. Root Cause

Two small bugs combined into the browser blocker:

1. Backend upload listing used `uploads/*.json` for metadata discovery.
   - Manifest uploads store `package.json` as `{file_id}-package.json`.
   - That uploaded file matched the metadata glob even though it is payload, not metadata.
   - `FileStore.list()` tried to parse the uploaded `package.json` as `StoredFile` metadata and returned `500`.

2. Frontend upload handling used `event.currentTarget.reset()` after async work.
   - During the async upload path, React can no longer guarantee `event.currentTarget`.
   - The browser smoke observed `Cannot read properties of null (reading 'reset')`.

## C. Fix Applied

Backend:

- `FileStore.list()` now loads only metadata files whose stem matches the 32-character hex file id pattern.
- Uploaded payloads such as `{file_id}-package.json` are no longer treated as metadata.
- Manifest uploads still preserve their existing stored filename contract.

Frontend:

- `handleUpload()` now captures `const form = event.currentTarget` before any `await`.
- The successful upload path calls `form.reset()` instead of reading `event.currentTarget` after async work.
- Existing archive upload behavior is preserved.

## D. Regression Tests

Backend regression:

- `test_manifest_upload_accepts_package_json` now uploads `package.json`, then calls `GET /files`.
- The test asserts `GET /files` returns `200`, lists exactly the uploaded manifest, and keeps `kind: manifest`.

Frontend regression:

- `App` now tests uploading a manifest `package.json`.
- The test asserts the UI does not show `Cannot read properties of null`.
- The `package.json` row appears and shows `Analyze manifest`.
- The row does not show archive-only actions:
  - `Analyze Redis config`
  - `Analyze SQL DB config`
  - `Analyze secrets review`
  - `Analyze CI/CD config`
  - `Analyze Nginx config`
  - `Analyze Docker config`
  - `Analyze Kubernetes config`
  - `Analyze Terraform config`
- The row does not show `Run all recommended passive checks`.

## E. Smoke Minimum Affected

A focused real-browser smoke was run with local backend/frontend and Google Chrome headless:

- Backend: `127.0.0.1:19300`
- Frontend: `http://localhost:5173`
- Browser: `google-chrome --headless=new`
- Fixture: `tests/fixtures/demo/passive-alpha/sources/demo-file-basic/manifest/package.json`
- Temporary summary: `/tmp/inspectra-manifest-upload-listing-smoke.json`

Smoke result:

```text
status: passed
backend_files_status: 200
kind: manifest
DOM row: package.json ... Analyze manifest Delete
```

The smoke confirmed:

- manifest upload completed;
- backend `/files` returned `200`;
- the non-archive row appeared in the real browser DOM;
- no `.reset` error was visible;
- `Analyze manifest` was visible;
- archive-only actions were absent from the manifest row;
- `Run all recommended passive checks` was absent.

## F. Validations

Commands executed:

```bash
git status --short
git log --oneline -12
python3 -m compileall backend tools
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
.venv/bin/python -m pytest backend/tests/test_backend.py -k "file or upload or manifest"
npm run test -- --run App dashboardFilters reportHelpers
npm run test -- --run
npm run build
.venv/bin/python -m pytest backend/tests/test_backend.py
git diff --check
```

`git diff --cached --check` is run immediately before the commit.

## G. Final State

Decision: `READY_FOR_BROWSER_SMOKE_RERUN_BEFORE_TAG`.

The manifest upload/listing blocker found in the previous browser smoke is fixed and covered by backend, frontend, and focused browser smoke checks.

Do not create `v0.1.0-passive-alpha` yet. The next required microphase is a full browser smoke rerun using the synthetic fixtures, followed by a clean-tree tag decision.

## H. Next Recommended Microphase

`PASSIVE-ALPHA-MANUAL-BROWSER-SMOKE-RERUN-BEFORE-TAG`
