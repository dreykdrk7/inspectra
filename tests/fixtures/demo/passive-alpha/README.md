# Inspectra Passive Alpha Demo Fixtures

These fixtures are synthetic demo inputs for local Inspectra Passive alpha smoke checks.

They are intentionally small and public-repo-safe. They are not production config, customer data, real credentials, real private keys, or third-party project material.

## Safety Notes

- All secret-looking strings are fake and intentionally included for redaction checks.
- Do not replace these files with real project data.
- Do not add real credentials, tokens, database URLs, private keys, dumps, ACL files, or `.env` content.
- Original uploaded fixture archives can contain fake secret strings.
- Inspectra results, reports, exports, and Raw JSON should redact those strings with `[REDACTED]`.
- Redaction does not sanitize the original uploaded archive.
- Passive config analyzers should not execute tools, run projects, contact live services, validate credentials, query CVEs/advisories, or prove exploitability.

## Fixture Root

```text
tests/fixtures/demo/passive-alpha/
```

Layout:

```text
sources/   readable source trees for each demo pack
archives/  small zip archives generated from selected source trees
```

## Packs

- `sources/demo-file-basic/`
  - Simple manifest/text fixtures for file and manifest smoke.
  - PDF/image fixtures are intentionally left for a future pass if the project adopts a tiny synthetic binary fixture convention.
- `sources/demo-archive-app-config/`
  - Django, Node, `.npmrc`, `.env.example`, and `.env` synthetic app config.
- `sources/demo-archive-container-infra/`
  - Dockerfile, Compose, CI/CD, Kubernetes, Terraform, Nginx, and `.env` synthetic deployment config.
- `sources/demo-archive-data-layer/`
  - Redis/Sentinel, PostgreSQL, MySQL/MariaDB, dumps/data/no-read marker files, and `.env`.
- `sources/demo-archive-redaction-negative/`
  - Fake secret strings placed across config surfaces for redaction-negative smoke.

Generated archives:

- `archives/demo-archive-app-config.zip`
- `archives/demo-archive-container-infra.zip`
- `archives/demo-archive-data-layer.zip`
- `archives/demo-archive-redaction-negative.zip`

## Fake Secret Strings

These strings are fake and should not appear in Inspectra result surfaces after analysis:

- `super-secret-password`
- `token_should_never_render`
- `raw-api-key-123456`
- `postgres://user:pass@example.com/db`
- `mysql://user:pass@example.com/db`
- `redis://:super-secret-password@redis:6379/0`
- `Authorization: Bearer token_should_never_render`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`
- `dump_row_secret_should_not_render`
- `pgpass_secret_should_not_render`
- `mycnf_secret_should_not_render`
- `acl_password_hash_should_not_render`

Expected positive signal:

- `[REDACTED]` appears in results where redaction applies.

## Manual Smoke Use

Full checklist:

```text
docs/future/passive-alpha-smoke-demo-checklist.md
```

Readiness/packaging decision:

```text
docs/future/passive-alpha-packaging-readiness.md
```

1. Start Inspectra locally.
2. Upload a source archive from `archives/`.
3. Confirm the file is registered as `kind: "archive"`.
4. Launch relevant grouped archive actions.
5. Open completed reports.
6. Confirm passive-scope copy, no-read sections, not-resolved references, redaction notes, and Redacted Raw JSON.
7. Export Markdown/HTML/XML/PDF where available.
8. Confirm the fake secret strings above do not appear in UI, Raw JSON, API responses, exports, or controlled errors.

## Regenerating Zip Archives

From the repository root:

```bash
mkdir -p tests/fixtures/demo/passive-alpha/archives
(cd tests/fixtures/demo/passive-alpha/sources/demo-archive-app-config && zip -X -r ../../archives/demo-archive-app-config.zip .)
(cd tests/fixtures/demo/passive-alpha/sources/demo-archive-container-infra && zip -X -r ../../archives/demo-archive-container-infra.zip .)
(cd tests/fixtures/demo/passive-alpha/sources/demo-archive-data-layer && zip -X -r ../../archives/demo-archive-data-layer.zip .)
(cd tests/fixtures/demo/passive-alpha/sources/demo-archive-redaction-negative && zip -X -r ../../archives/demo-archive-redaction-negative.zip .)
```

Do not run Docker, Docker Compose, Terraform, Nginx, Kubernetes, Redis, SQL DB clients/servers, package managers, CI workflows, or uploaded project code while using these fixtures.
