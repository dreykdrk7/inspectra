# redis_config_basic Frontend Report UX

Status: frontend action/report microphase for the passive Redis config audit.

## Integrated Surface

- Frontend archive action: `Analyze Redis config`.
- Backend endpoint consumed: `POST /audits/redis-config/{file_id}`.
- Audit type rendered: `redis_config_basic`.
- Report view: summary, files/configs, Redis settings, Sentinel settings, includes, ACL files, dumps/RDB/AOF/appendonly/backups, findings, redaction notes, limits, errors, and Raw JSON.
- Raw JSON is rendered through the Redis frontend redaction helper.

The action is visible only for uploaded files with `kind: archive`, following the existing passive config audit pattern.

## UX Scope

The report presents Redis as a passive archive-only Redis/Sentinel configuration review. It explicitly states that Inspectra does not execute Redis or Sentinel, use `redis-cli`, open sockets, make network calls, resolve includes, read sensitive adjacent files, validate credentials, query CVEs, or confirm exploitability.

Includes are shown as detected and not resolved. ACL, `.env`, RDB, AOF, appendonly, dump, and backup-like files are shown as detected/not-read context.

## Frontend Redaction

The Redis report defensively redacts legacy or malformed payload content before rendering tables, findings, errors, and Raw JSON. It uses the fixed placeholder `[REDACTED]` for:

- `requirepass`, `masterauth`, and Sentinel `auth-pass` values.
- Redis URLs with embedded passwords.
- Authorization/Bearer-style tokens.
- ACL material and dump/AOF-like values.
- API keys, passwords, client secrets, private keys, and credential-like values.

The helper avoids prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers.

## Validation Focus

- Redis action appears only for archive files.
- Action calls `POST /audits/redis-config/{file_id}`.
- `redis_config_basic` is available in job filters/labels.
- Completed, sparse, running, and failed payloads render without breaking.
- Redis/Sentinel settings, includes, ACL files, dump/AOF files, findings, redaction notes, limits, errors, and Raw JSON are visible when present.
- Fixture secrets do not appear in rendered DOM or Raw JSON.

Reference commands:

```bash
npm run test -- --run RedisConfigJobReport reportHelpers App dashboardFilters
npm run test -- --run
npm run build
python3 -m compileall backend tools
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
.venv/bin/python -m pytest backend/tests/test_backend.py -k redis_config
.venv/bin/python -m pytest tools/tests/test_runner.py -k redis_config
.venv/bin/python -m pytest
git diff --check
git diff --cached --check
```

## Residual Risks

- Redis findings remain static heuristics from the runner and require human review.
- Frontend redaction is defensive and best-effort for malformed legacy payloads.
- Includes remain unresolved, so effective Redis config may differ from displayed file content.
- Sensitive adjacent files are detected as present but not read, which can omit important deployment context.

## Next Microphase

Recommended next step: `REDIS-CONFIG-BASIC-04-END-TO-END-CONTRACT-REDACTION-REVIEW`, validating runner, backend, API, exports, frontend DOM, and Raw JSON together before closeout.
