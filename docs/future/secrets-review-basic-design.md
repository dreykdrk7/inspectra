# secrets_review_basic Design

Status: implemented in v1 across runner, backend, exports, and frontend. This document remains as the historical docs-first design reference for the passive secrets review audit.

## 1. Module Objective

`secrets_review_basic` is a future passive archive-based audit type for reviewing user-supplied project archives for indicators of accidental secret exposure. It should help Inspectra users identify files and lines that deserve manual cleanup before sharing an archive, deploying to a VPS, or publishing a repository.

The module should detect review signals such as real environment files present in an archive, secret-like assignments in configuration text, private key blocks, database URLs with credentials, cloud access key patterns, inline CI tokens, Kubernetes or Terraform plaintext secret hints, Docker build args with secret-like names, and weak placeholder values in example files.

The module should not prove that a credential is valid, compromised, reachable, or exploitable. It must not validate tokens against providers, call external services, scan Git history, crack passwords, download dependencies, run code, or perform deep secret scanning comparable to dedicated tools such as TruffleHog or Gitleaks. Findings must remain heuristic indicators for manual validation.

This module is useful for Inspectra because uploaded archives often contain deployment, CI/CD, framework, and infrastructure files. A bounded local review can catch obvious secret-handling mistakes while preserving Inspectra's no-execution, no-network, defensive MVP model.

## 2. Allowed Scope

The initial module should accept only uploaded archives already registered as `kind: "archive"`. It should reuse the same archive safety posture as existing archive-based modules:

- open ZIP/TAR/TAR.GZ/TGZ archives with Python standard library parsers;
- inspect archive metadata defensively;
- read only bounded candidate text files into memory;
- avoid broad extraction to the filesystem;
- skip path traversal entries, absolute paths, symlinks, hardlinks, non-regular files, oversized files, entry-heavy archives, and files beyond configured limits;
- never execute scripts, import modules, install dependencies, or make network calls;
- never validate whether a secret works;
- never store or display complete secret values.

The analysis should be textual and heuristic. It may use simple line-oriented parsing and lightweight structured parsing when a safe local parser already exists, but it should not require package managers, provider SDKs, remote repositories, cloud APIs, image registries, or external scanners.

Fingerprints should be avoided in v1 unless there is a clear user need. If a future implementation adds fingerprints, they must be irreversible and designed so they cannot reconstruct the secret. A local HMAC with a non-exported deployment secret would be safer than raw hashing, but v1 should probably omit this complexity.

## 3. Candidate Files

The module should classify candidates conservatively and keep file reads bounded.

Environment and config templates that may be read within limits:

- `.env.example`
- `.env.template`
- `.env.sample`
- `env.example`
- `env.template`
- `env.sample`
- `sample.env`

Real environment files should be detected as sensitive files and not read in v1:

- `.env`
- `.env.*`
- `.env.production`
- `.env.prod`
- `.env.local`
- `.env.staging`
- `.env.development`
- `.env.test`
- `.envrc`

Application config candidates:

- `settings.py`
- `config.py`
- `config/*.py`
- `settings/*.py`
- `appsettings.json`
- `application.yml`
- `application.yaml`
- `config.yml`
- `config.yaml`
- `docker-compose.yml`
- `docker-compose.yaml`
- `compose*.yml`
- `compose*.yaml`
- `Dockerfile`
- `Dockerfile.*`
- `package.json` scripts or environment hints
- `pyproject.toml`
- `requirements.txt` for context only, not normally secret findings

CI/CD config candidates:

- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`
- `.gitlab-ci.yml`
- `bitbucket-pipelines.yml`
- `azure-pipelines.yml`

Infrastructure config candidates:

- Terraform `*.tf`
- Ansible variable YAML such as `group_vars/*.yml`, `host_vars/*.yml`, and `vars/*.yml`
- Helm `values.yaml` and `values*.yaml`
- Kubernetes manifests such as `deployment.yaml`, `secret.yaml`, `configmap.yaml`, and generic `*.k8s.yaml`

The exact first implementation can start with a smaller subset, but it should keep the same contract: explicit archive input, bounded text reads, sensitive real env files detected but not read, and no external validation.

## 4. Out Of Scope

The first implementation must explicitly exclude:

- deep secret scanning comparable to TruffleHog, Gitleaks, or similar tools;
- validating tokens, credentials, or webhooks against any provider;
- calls to GitHub, npm, PyPI, AWS, GCP, Azure, Stripe, OpenAI, Slack, Discord, Sentry, or any other service;
- Git history scanning;
- remote repository scanning;
- package manager execution;
- code execution;
- broad archive extraction;
- recursive decompression beyond the primary uploaded archive;
- OCR or image/PDF secret detection;
- binary analysis;
- malware scanning;
- CVE or advisory lookups;
- password cracking, hash cracking, or entropy-only credential guessing;
- classifying a credential as active, revoked, leaked, or compromised.

## 5. Initial Finding Model

Finding IDs should be stable, conservative, and framed as review indicators:

- `sensitive_file_present`: a sensitive-looking file path is present in the archive.
- `real_env_file_present_not_read`: a real `.env` or `.env.*` file was detected and intentionally not read.
- `secret_like_assignment`: a key/value assignment uses a secret-like name with a non-placeholder value.
- `private_key_block_detected`: a PEM-style private key block was detected and redacted.
- `cloud_access_key_pattern`: a cloud access key pattern with plausible shape was observed.
- `api_token_pattern`: an API token-like value was observed.
- `database_url_with_credentials`: a database URL appears to include credentials.
- `redis_url_with_credentials`: a Redis URL appears to include credentials.
- `basic_auth_url`: a URL appears to include embedded username/password credentials.
- `ci_secret_exposed_inline`: a CI/CD configuration appears to set a secret inline rather than referencing a secret store.
- `jwt_like_value`: a JWT-like value shape was observed.
- `webhook_url_with_token`: a webhook URL appears to include a token-bearing path or query.
- `oauth_client_secret_name`: an OAuth client secret-like key name was observed.
- `weak_placeholder_secret`: a placeholder such as `changeme`, `password`, `example`, or `secret` is used where a secret is expected.
- `example_secret_placeholder`: an example/template file contains placeholder secret material.
- `secret_in_docker_build_arg`: a Docker build arg or environment instruction uses a secret-like name.
- `secret_in_compose_environment`: a Compose environment entry uses a secret-like name.
- `secret_in_k8s_manifest_plaintext`: a Kubernetes manifest appears to store plaintext secret-like data.
- `secret_in_terraform_variable_default`: a Terraform variable default appears to contain secret-like data.

No finding should use wording such as "credential leaked", "secret is valid", or "compromised token". Preferred wording: "secret-like value observed", "sensitive file present", "review required", and "manual validation recommended".

## 6. Severity And Confidence

The module should report both severity and confidence if practical:

- `medium` or `high confidence`: private key blocks, database or Redis URLs with credentials, basic-auth URLs, plausible cloud access key patterns, long token-like values in active config, inline CI tokens, or plaintext Kubernetes Secret data.
- `low` or `medium confidence`: secret-like key names with values that could be placeholders, Docker/Compose secret-looking environment entries, OAuth client secret names without strong value evidence, or webhook-like URLs with partial token shape.
- `info` or `low confidence`: names without values, explicit template/sample/example files, weak placeholders, comments, or development/test/local contexts.

Severity should not exceed `medium` in v1 unless the project later defines a very narrow high-confidence category. Even then, "high" should mean high review priority, not confirmed exploitability.

Context should influence severity and wording:

- production/shared contexts: root config files, CI/CD deployment workflows, `deploy/`, `production/`, `terraform/`, `k8s/`, `helm/`, and production-named compose or values files;
- lower-confidence contexts: `tests/`, `test/`, `examples/`, `sample/`, `docs/`, `local/`, `dev/`, `development/`, template files, and example env files;
- ambiguous contexts: everything else.

Development, test, local, sample, and example contexts should generally downgrade severity or add a lower-confidence note. If there is doubt, keep the finding but use cautious wording.

## 7. Redaction And Safe Evidence

Redaction is the central contract of this module:

- never store the full matched secret value;
- never display the full matched secret value;
- evidence should show the key name and a redacted placeholder;
- raw JSON in future UI should also be redacted;
- reports should apply an additional defensive redaction pass for legacy or malformed payloads;
- errors must not include raw matched values.

Evidence examples:

- `SECRET_KEY=[REDACTED]`
- `DATABASE_URL=[REDACTED]`
- `redis://[REDACTED]@host:6379/0`
- `https://[REDACTED]@example.com/path`
- `PRIVATE_KEY_BLOCK_REDACTED`

Optional metadata can be useful but must be handled carefully:

- approximate value length, such as `value_length_bucket: "32-64"`;
- line number if available;
- key name;
- file path and context.

The v1 design should avoid showing prefixes or suffixes. Even short prefixes can help identify real credentials in shared reports. Raw hashes of secrets are also risky for low-entropy values; omit them unless a later design introduces local HMAC-based fingerprints with clear threat-modeling.

## 8. Comments And Non-Executable Lines

The analyzer should ignore full-line comments for strong findings:

- shell/YAML/TOML/Python comments starting with `#` after whitespace;
- JavaScript/JSON-like comments only where file type allows comments or where a line clearly starts with `//`;
- Dockerfile and Compose comments following the same full-line rule.

Inline comments should be handled conservatively. If a secret-like value appears only in a comment or example, the analyzer can either skip it or emit an `info` finding with low confidence. It should not produce a strong finding from a commented-out example.

The first implementation does not need a full language parser. Line-oriented heuristics are acceptable if they are conservative and well tested.

## 9. Proposed Result JSON

The result should match Inspectra's existing style and tolerate sparse data:

```json
{
  "analyzer": "secrets_review_basic",
  "archive_type": "zip",
  "completed_at": "2026-05-31T00:00:00Z",
  "hashes": {
    "sha256": "..."
  },
  "summary": {
    "files_considered": 0,
    "files_reviewed": 0,
    "sensitive_files_detected": 0,
    "findings_count": 0,
    "high_confidence_count": 0,
    "redacted_values_count": 0,
    "truncated": false
  },
  "limits": {
    "max_files": 100,
    "max_file_bytes": 524288,
    "max_total_bytes": 2097152,
    "max_archive_entries": 5000
  },
  "files_detected": [
    {
      "path": ".env.production",
      "category": "env_sensitive",
      "context": "production",
      "read": false,
      "skip_reason": "real_env_file_not_read",
      "size_bytes": 2048
    }
  ],
  "files_reviewed": [
    {
      "path": ".env.example",
      "category": "env_template",
      "context": "example",
      "bytes_read": 512
    }
  ],
  "sensitive_files": [
    {
      "path": ".env.production",
      "category": "env_sensitive",
      "read": false,
      "skip_reason": "real_env_file_not_read"
    }
  ],
  "findings": [
    {
      "id": "database_url_with_credentials",
      "title": "Database URL with credentials observed",
      "level": "medium",
      "confidence": "high",
      "category": "credential_url",
      "context": "production",
      "file_path": "config/settings.py",
      "line": 42,
      "description": "A database URL appears to include embedded credentials. Inspectra redacted the value and did not validate it.",
      "evidence": "DATABASE_URL=[REDACTED]",
      "recommendation": "Move real credentials to an approved secret store or runtime injection mechanism and rotate if this archive was shared outside trusted storage."
    }
  ],
  "redaction_notes": [
    "Secret-like values are redacted before storage and export on a best-effort basis."
  ],
  "errors": []
}
```

Potential limits can mirror Django and Docker config defaults:

- `INSPECTRA_SECRETS_REVIEW_MAX_FILES`, default `100`;
- `INSPECTRA_SECRETS_REVIEW_MAX_FILE_BYTES`, default `524288`;
- `INSPECTRA_SECRETS_REVIEW_MAX_TOTAL_BYTES`, default `2097152`.

The exact variable names can be adjusted during implementation, but the module should remain bounded by file count, per-file bytes, total bytes, archive entry count, and archive path/name limits.

## 10. Expected UX And Reporting

The UI should make the result understandable without opening raw JSON:

- Summary: files considered, files reviewed, sensitive files detected, findings count, high-confidence count, redacted values count, truncation status.
- Sensitive files detected but not read.
- Findings grouped by severity, confidence, and category.
- Files reviewed and skipped files, with context badges.
- Redaction notes.
- Limits, truncation, and controlled errors.
- Raw JSON as a secondary collapsed/debug section, always redacted.

Markdown and HTML exports should include context, confidence, category, file path, line number when available, safe evidence, and recommendation. XML and PDF should tolerate queued/running/failed/sparse jobs through the generic reporting model. All formats should apply defensive redaction even if a legacy or malformed result contains raw secret-like values.

## 11. Future Tests

Minimum tests for the first implementation:

- `.env.production` is detected as sensitive and not read.
- `.env.local` and generic `.env.*` variants are detected as sensitive and not read.
- `.env.example` is read within limits and secret-like values are redacted.
- `SECRET_KEY=long-value` produces `secret_like_assignment` with redacted evidence.
- `DATABASE_URL=postgres://user:pass@db/app` produces `database_url_with_credentials` with redacted evidence.
- `REDIS_URL=redis://:pass@redis:6379/0` produces `redis_url_with_credentials` with redacted evidence.
- A PEM private key block is detected and redacted as `PRIVATE_KEY_BLOCK_REDACTED`.
- A full-line comment such as `# SECRET_KEY=abc` does not produce a strong finding.
- GitHub Actions workflow with an inline token-like value produces a CI finding without storing the token.
- Kubernetes Secret with plaintext `stringData` produces a Kubernetes plaintext secret indicator.
- Docker Compose `environment` with `PASSWORD` produces a Compose secret indicator.
- Terraform variable default with a secret-like value produces a Terraform finding.
- Placeholder values such as `changeme`, `example`, `password`, or `secret` lower severity/confidence.
- Files in `examples/`, `tests/`, `docs/`, `sample/`, `local/`, or `dev/` lower severity/confidence.
- Path traversal entries, symlinks, hardlinks, non-regular TAR entries, binary files, and oversized files are not read.
- File count, per-file byte, total byte, and archive entry limits mark truncation predictably.
- Legacy/sparse/malformed result payloads do not break backend exports or frontend reports.
- Raw JSON, Markdown, HTML, XML, PDF, and future UI helpers do not contain unredacted test secrets.

## 12. Proposed Implementation Microphases

1. Runner/parser passive analyzer:
   - add candidate classification;
   - detect real env files without reading them;
   - read bounded text candidates;
   - implement redaction-first matching and runner tests.

2. Backend job integration and exports:
   - add `secrets_review_basic` audit type and `POST /audits/secrets-review/{file_id}`;
   - accept only `kind: "archive"`;
   - add service delegation, storage summary, Markdown/HTML/XML/PDF reporting, redaction tests, and sparse job tests.

3. Frontend report UX:
   - add archive action;
   - add report helper/component;
   - group findings by severity/confidence/category;
   - show sensitive files, reviewed files, limits, redaction notes, errors, and redacted raw JSON.

4. End-to-end review:
   - review runner/backend/frontend contract;
   - verify no raw secrets leak in results or exports;
   - tighten labels, empty states, and sparse/legacy compatibility.

5. Documentation and smoke validation:
   - update README, architecture, and security scope;
   - document variables and limitations;
   - manually test a small archive with env templates, CI config, Compose, and Kubernetes examples.

## 13. Documentation Changes When Implemented

When `secrets_review_basic` is implemented, update:

- `README.md`
  - endpoint usage;
  - UI action;
  - supported archive source;
  - limits and variables;
  - passive/no-validation/no-network scope;
  - redaction and local storage caveats.

- `docs/architecture.md`
  - archive-based flow;
  - runner parsing model;
  - result schema;
  - relationship to `django_config_basic`, `docker_config_basic`, and archive safety helpers.

- `docs/security-scope.md`
  - add allowed scope for passive secret exposure review;
  - explicitly keep token validation, provider APIs, Git history scanning, external scanners, and credential validity claims out of scope;
  - document that redaction is best-effort and uploaded archive bytes may still contain real secrets in local storage.

Runtime documentation now lives in `README.md`, `docs/architecture.md`, and `docs/security-scope.md`. This design document should not be treated as the source of truth for exact UI wording or implementation status.
