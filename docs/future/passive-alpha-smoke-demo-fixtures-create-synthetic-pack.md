# Passive Alpha Smoke Demo Fixtures: Create Synthetic Pack

Status: implemented as a fixtures/docs-only microphase.

Base commit: `1e6d19a docs(demo): design passive alpha smoke fixture pack`

This microphase creates the first synthetic Inspectra Passive alpha smoke/demo fixture pack. It does not change backend, runner, frontend, job contracts, exports, analyzers, findings, severities, or redaction logic.

## Created Structure

```text
tests/fixtures/demo/passive-alpha/
  README.md
  sources/
    demo-file-basic/
    demo-archive-app-config/
    demo-archive-container-infra/
    demo-archive-data-layer/
    demo-archive-redaction-negative/
  archives/
    demo-archive-app-config.zip
    demo-archive-container-infra.zip
    demo-archive-data-layer.zip
    demo-archive-redaction-negative.zip
```

The source folders are readable and intended for review. The zip archives are small upload-ready copies of the archive fixture source folders.

## Packs Created

### `demo-file-basic`

Source-only fixture for simple file/manifest smoke:

- `manifest/package.json`
- `manifest/requirements.txt`
- `notes/demo-manifest.txt`

No PDF or image binary was added in this microphase. That remains a future option if the repository adopts a tiny synthetic binary fixture convention.

### `demo-archive-app-config`

Synthetic app config archive source and zip:

- Django settings.
- Node `package.json` and `package-lock.json`.
- `.npmrc` with fake token.
- `.env.example` with fake secret-like values.
- `.env` fixture for no-read behavior where applicable.

Expected smoke coverage:

- `archive_basic`
- `project_archive_basic`
- `django_config_basic`
- `node_package_config_basic`
- `secrets_review_basic`

### `demo-archive-container-infra`

Synthetic container/infrastructure/web-edge archive source and zip:

- `Dockerfile`
- `docker-compose.yml`
- GitHub Actions workflow.
- Kubernetes manifests and RBAC.
- Terraform config and a synthetic `terraform.tfstate` marker.
- Nginx config.
- `.env` fixture.

Expected smoke coverage:

- `docker_config_basic`
- `compose_config_basic`
- `ci_cd_config_basic`
- `k8s_config_basic`
- `terraform_config_basic`
- `nginx_config_basic`
- `secrets_review_basic`
- `archive_basic`

### `demo-archive-data-layer`

Synthetic Redis/SQL database archive source and zip:

- Redis and Sentinel config.
- Redis ACL/RDB/AOF/appendonly marker files.
- PostgreSQL config and `pg_hba.conf`.
- PostgreSQL credential/WAL marker files.
- MySQL/MariaDB config.
- dump/binlog/InnoDB marker files.
- `.env` fixture.

Expected smoke coverage:

- `redis_config_basic`
- `database_config_basic`
- `sql_database_config_basic`
- `secrets_review_basic`
- `archive_basic`

### `demo-archive-redaction-negative`

Synthetic redaction-negative archive source and zip:

- App `.env.example`.
- YAML settings.
- Redis/PostgreSQL/MySQL config.
- Nginx config.
- Compose config.
- Terraform config.
- CI workflow.
- dump/ACL/private-key marker files.

Expected smoke coverage:

- Redaction-heavy archive config analyzers.
- UI/API/export/Raw JSON negative checks.

## Fake Secret Strings

The fixtures intentionally include fake strings for redaction checks:

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

These strings are deliberately fake and can appear in fixture source files and uploaded archives. They should not appear in Inspectra result JSON, UI reports, Raw JSON, API responses, exports, or controlled errors after analysis.

Expected positive signal:

- `[REDACTED]` appears where redaction applies.

## Archive Generation

The archives were generated from the source folders with `zip -X` to keep them small and avoid extra file attributes.

Regeneration commands from the repository root:

```bash
mkdir -p tests/fixtures/demo/passive-alpha/archives
(cd tests/fixtures/demo/passive-alpha/sources/demo-archive-app-config && zip -X -r ../../archives/demo-archive-app-config.zip .)
(cd tests/fixtures/demo/passive-alpha/sources/demo-archive-container-infra && zip -X -r ../../archives/demo-archive-container-infra.zip .)
(cd tests/fixtures/demo/passive-alpha/sources/demo-archive-data-layer && zip -X -r ../../archives/demo-archive-data-layer.zip .)
(cd tests/fixtures/demo/passive-alpha/sources/demo-archive-redaction-negative && zip -X -r ../../archives/demo-archive-redaction-negative.zip .)
```

## Scope Kept

This microphase did not:

- Add analyzers.
- Add endpoints.
- Touch backend code.
- Touch runner code.
- Touch frontend code.
- Add runtime tests.
- Add scripts.
- Execute Docker, Docker Compose, Terraform, Nginx, Kubernetes, Redis, SQL DB clients/servers, package managers, CI workflows, or project code.
- Contact live services.
- Query CVEs/advisories.
- Use real credentials or real data.

## Residual Notes

- The fixtures are intentionally broad and may trigger overlapping findings.
- The fake secret strings remain in original fixture files by design.
- Result redaction does not sanitize uploaded archives.
- No-read marker files are tiny text markers, not real dumps, state, WAL, AOF, ACL, or database files.
- PDF/image demo fixtures are deferred.

## Reference Validation

Validation commands for this microphase:

```bash
git status --short
git log --oneline -12
find tests/fixtures/demo/passive-alpha -maxdepth 5 -type f -print
du -sh tests/fixtures/demo/passive-alpha
python3 - <<'PY'
from pathlib import Path
import zipfile

root = Path("tests/fixtures/demo/passive-alpha/archives")
for path in sorted(root.glob("*.zip")):
    with zipfile.ZipFile(path) as z:
        print(path, len(z.namelist()))
        for name in z.namelist()[:20]:
            print("  ", name)
PY
git diff --check
git diff --cached --check
```

No pytest or npm validation is required for this fixtures/docs-only microphase because no runtime code changed.

## Next Microphase

Recommended next step:

`PASSIVE-ALPHA-SMOKE-DEMO-FIXTURES-03-WIRE-SMOKE-CHECKLIST-DOCS`
