# redis_config_basic Backend Integration

Status: backend/job/reporting microphase for the passive Redis config audit.

## Integrated Surface

- Backend endpoint: `POST /audits/redis-config/{file_id}`.
- Audit type/job analyzer: `redis_config_basic`.
- Runner endpoint used by backend jobs: `POST /analyze/redis-config`.
- Source files: uploaded files registered as `kind: archive`.
- Storage: full runner result is persisted with a compact `GET /jobs` summary.
- Reporting/export: existing Markdown, HTML, XML, and PDF paths render Redis config sections and findings.
- Backend redaction: Redis payloads are defensively redacted before storage and again in API/reporting/export compatibility paths.

The backend does not parse Redis config itself. It delegates parsing to the local runner and preserves the passive, bounded analyzer contract.

## Scope Kept Out

This microphase does not add frontend UI, periodic jobs, new Redis findings, Redis execution, Sentinel execution, `redis-cli`, sockets, network calls, include resolution, `.env`/ACL/RDB/AOF/appendonly/backup reads, credential validation, CVE/advisory lookup, or claims of exploitability/compromise.

Findings remain heuristic review indicators that require human validation in the intended deployment context.

## Validation Focus

- Archive-only endpoint behavior.
- Runner call target `/analyze/redis-config`.
- Job creation and controlled runner failure handling.
- Summary extraction for complete, sparse, and malformed payloads.
- Redis sections in Markdown/HTML/XML/PDF export paths.
- Defensive redaction for legacy payloads containing raw Redis passwords, ACL material, credential URLs, Authorization-like tokens, private key blocks, and dump/AOF-like values.

Reference commands:

```bash
python3 -m compileall backend tools
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
.venv/bin/python -m pytest backend/tests/test_backend.py -k redis_config
.venv/bin/python -m pytest tools/tests/test_runner.py -k redis_config
.venv/bin/python -m pytest
git diff --check
git diff --cached --check
```

## Residual Risks

- Redis config parsing remains runner-side, textual, best-effort, and heuristic.
- Redaction is defensive and best-effort for malformed or legacy payloads.
- Uploaded archive bytes remain stored locally according to the existing Inspectra file storage model.
- Sensitive adjacent files are detected as present but not read; this can hide additional context that must be reviewed manually.
- Includes are detected but not resolved, so effective Redis config may differ from visible archive text.

## Next Microphase

Recommended next step: `REDIS-CONFIG-BASIC-03-FRONTEND-ACTION-REPORT-UX`, adding the archive-only frontend action and Redis report UX without expanding Redis runtime scope.
