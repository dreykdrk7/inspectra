# docker_config_basic Design

## 1. Module Objective

`docker_config_basic` is a future passive archive-based audit type for reviewing Docker and deployment configuration supplied by the user. It should help Inspectra users quickly identify configuration indicators that deserve manual review before deploying applications to a VPS, CI environment, or small production host.

The module should detect review signals such as containers that appear to run as root, broad host mounts, Docker socket exposure, privileged mode, sensitive environment names, unpinned or latest image references, development-oriented Compose files, and potentially risky deployment defaults.

The module should not prove exploitability, confirm vulnerabilities, build images, run containers, inspect the host Docker daemon, download images, resolve image tags, query CVEs, or perform deep secret scanning. Findings must remain heuristic indicators for manual validation.

This module is useful for Inspectra because uploaded project archives commonly include Dockerfiles and Compose files. A bounded static review can give immediate defensive value while preserving the existing local, passive, no-execution model used by `project_archive_basic` and `django_config_basic`.

## 2. Allowed Scope

The initial module should accept only uploaded archives already registered as `kind: "archive"`. It should reuse the same archive safety posture as existing archive-based modules:

- open ZIP/TAR/TAR.GZ/TGZ archives with Python standard library parsers;
- inspect archive metadata defensively;
- read only bounded candidate text files into memory;
- avoid broad extraction to the filesystem;
- skip path traversal entries, absolute paths, symlinks, hardlinks, non-regular files, files above size limits, and entries beyond configured limits;
- redact obvious secret-like values before storage and export where evidence is captured.

Candidate files:

- `Dockerfile`
- `Dockerfile.*`
- `docker-compose.yml`
- `docker-compose.yaml`
- `compose.yml`
- `compose.yaml`
- `compose.*.yml`
- `compose.*.yaml`
- `.dockerignore`
- optionally shared deployment signal files already recognized by Django config analysis, such as `nginx/*.conf`, `gunicorn.conf.py`, `*.service`, and `Procfile`, as supporting context only.

The analysis should be textual and heuristic. It can use lightweight parsers from the Python standard library where useful, but it should not require Docker, Compose, package managers, image registries, or external services.

## 3. Out Of Scope

The first implementation must explicitly exclude:

- building Docker images;
- running containers;
- invoking `docker`, `docker compose`, or `docker-compose`;
- mounting or accessing the Docker socket;
- `docker inspect`;
- Docker Scout;
- Trivy, Grype, Syft, or other external scanners in this phase;
- CVE, advisory, package registry, or image registry lookups;
- downloading base images or resolving image digests;
- executing scripts from the archive;
- broad archive extraction;
- network or port scanning;
- crawling, fuzzing, exploitation, or brute force;
- deep secret scanning;
- reading real `.env` or `.env.*` files referenced by Compose files or present in archives.

## 4. Initial Finding Model

Finding IDs should be stable, conservative, and framed as review indicators. Suggested initial categories:

- `runs_as_root`: explicit `USER root`, `user: root`, `user: "0"`, or equivalent.
- `missing_user_directive`: Dockerfile has no observed non-root `USER`.
- `privileged_container`: Compose service uses `privileged: true`.
- `host_network`: Compose service uses `network_mode: host`.
- `host_pid_or_ipc`: Compose service uses `pid: host` or `ipc: host`.
- `docker_socket_mount`: volume includes `/var/run/docker.sock`.
- `broad_bind_mount`: volume mounts broad host paths such as `/`, `/etc`, `/var`, `/home`, or the project root in a likely production context.
- `sensitive_env_name`: environment key names suggest secrets, tokens, passwords, private keys, or database URLs.
- `env_file_real_reference`: Compose references `.env`, `.env.production`, `.env.local`, or other real env files.
- `latest_tag`: image reference uses `:latest`.
- `unpinned_base_image`: Dockerfile `FROM` lacks a tag or digest.
- `exposed_sensitive_port`: Dockerfile `EXPOSE` includes database/cache/admin ports.
- `published_database_port`: Compose publishes ports such as `5432:5432`, `3306:3306`, `6379:6379`, `27017:27017`, or similar.
- `missing_healthcheck`: no Dockerfile `HEALTHCHECK` or Compose healthcheck observed.
- `missing_read_only_root_fs`: Compose service lacks `read_only: true`.
- `missing_no_new_privileges`: Compose service lacks `security_opt: ["no-new-privileges:true"]` or equivalent.
- `added_capabilities`: Compose service uses `cap_add`.
- `disabled_security_opts`: Compose service disables labels/security confinement where visible, such as unconfined seccomp or AppArmor.
- `build_secrets_in_args`: `ARG`, `ENV`, or Compose build args include secret-like names.
- `suspicious_curl_pipe_shell`: Dockerfile includes a curl/wget pipe-to-shell pattern.
- `package_install_without_cleanup`: package manager install command appears without obvious cache cleanup in the same Dockerfile stage.
- `compose_profiles_or_dev_context`: Compose file appears to be development-only or profile-gated; this should usually lower severity rather than raise it.

No finding should call itself a confirmed vulnerability by default. Recommendations should say "review", "consider", "confirm", or "validate manually".

## 5. Severity And Context

The module should classify file context by path and filename, following the direction used by `django_config_basic`:

- stronger production/shared contexts: `Dockerfile`, `Dockerfile.prod`, `compose.prod.yml`, `compose.production.yaml`, `deploy/`, `production/`, `nginx/`, `systemd/`, and similar;
- lower-confidence development/test/example contexts: `Dockerfile.dev`, `compose.dev.yml`, `docker-compose.override.yml`, `tests/`, `examples/`, `sample/`, `docs/`, `local/`, `development/`, and similar;
- `ambiguous` when the path does not clearly indicate production or development.

Suggested severity posture:

- `medium`: Docker socket mount, privileged mode, host network, host PID/IPC, hardcoded secret-like values in active deployment text, explicit root user in production context, or curl-pipe-shell in a production/ambiguous Dockerfile.
- `low`: missing user directive, latest tag, published database/cache ports, missing read-only/no-new-privileges/healthcheck, broad bind mounts, package install without cleanup.
- `info`: env file references, dev/example context signals, missing hardening options in clearly local files, exposed ports without published mappings, `.dockerignore` observations.

Development, test, local, sample, and example contexts should generally downgrade severity or add a lower-confidence note. Production and shared contexts can keep the default severity. If there is doubt, keep the finding but use a lower level or clearer wording.

## 6. Proposed Result JSON

The result should match Inspectra's existing style and tolerate sparse data:

```json
{
  "analyzer": "docker_config_basic",
  "archive_type": "zip",
  "completed_at": "2026-05-31T00:00:00Z",
  "hashes": {
    "sha256": "..."
  },
  "summary": {
    "files_considered": 0,
    "files_reviewed": 0,
    "dockerfiles_detected": 0,
    "compose_files_detected": 0,
    "dockerignore_detected": false,
    "services_detected": 0,
    "findings_count": 0,
    "secrets_redacted_count": 0,
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
      "path": "Dockerfile",
      "category": "dockerfile",
      "context": "shared",
      "read": true,
      "skip_reason": null,
      "size_bytes": 2048
    }
  ],
  "files_reviewed": [
    {
      "path": "docker-compose.yml",
      "category": "compose",
      "context": "ambiguous"
    }
  ],
  "dockerfile_stages": [
    {
      "file_path": "Dockerfile",
      "stage": "runtime",
      "base_image": "python:3.12-slim",
      "user_observed": "app",
      "healthcheck_observed": false
    }
  ],
  "compose_services": [
    {
      "file_path": "docker-compose.yml",
      "service": "db",
      "image": "postgres:16",
      "ports": ["5432:5432"],
      "privileged": false,
      "read_only": false
    }
  ],
  "findings": [
    {
      "id": "docker_socket_mount",
      "title": "Docker socket mount observed",
      "level": "medium",
      "category": "runtime_privilege",
      "context": "production",
      "file_path": "compose.prod.yml",
      "description": "A service appears to mount the Docker socket.",
      "evidence": "/var/run/docker.sock:/var/run/docker.sock",
      "recommendation": "Avoid mounting the Docker socket into application containers unless there is a tightly controlled operational need."
    }
  ],
  "redaction_notes": [
    "Secret-like values in evidence were redacted best-effort."
  ],
  "errors": []
}
```

Potential limits:

- `INSPECTRA_DOCKER_CONFIG_MAX_FILES`, default `100`;
- `INSPECTRA_DOCKER_CONFIG_MAX_FILE_BYTES`, default `524288`;
- `INSPECTRA_DOCKER_CONFIG_MAX_TOTAL_BYTES`, default `2097152`.

The exact names can be adjusted during implementation, but they should mirror Django config limits unless there is a strong reason to diverge.

## 7. Expected UX And Reporting

The UI should make the result understandable without opening raw JSON:

- Summary: files reviewed, Dockerfiles detected, Compose files detected, services detected, findings count, truncation status, redaction count.
- Findings grouped by severity and optionally category.
- Files reviewed and skipped files, with context badges.
- Sensitive env references and secret-like names, without showing secret values.
- Compose services overview, if simple to derive from bounded text.
- Dockerfile stages overview, if simple to derive from `FROM ... AS ...` and `USER` lines.
- Limits, truncation, and errors.
- Raw JSON as a secondary collapsed/debug section.

Markdown and HTML exports should include context near `file_path` and `evidence` when available, use existing escaping/redaction helpers, and continue to tolerate queued/running/failed/sparse jobs. XML/PDF can inherit the generic section data unless a later UX pass warrants custom formatting.

## 8. Future Tests

Minimum tests for the first implementation:

- Dockerfile without `USER` produces a `missing_user_directive` review finding.
- Dockerfile with non-root `USER` records a positive signal and avoids the missing-user finding.
- Dockerfile `FROM python:latest` produces `latest_tag`.
- Dockerfile `FROM python` produces `unpinned_base_image`.
- Compose service with `privileged: true` produces `privileged_container`.
- Compose service with `network_mode: host` produces `host_network`.
- Compose service mounting `/var/run/docker.sock` produces `docker_socket_mount`.
- Compose service publishing `5432:5432` or `6379:6379` produces `published_database_port`.
- Development/test/example Compose files downgrade severity or include a lower-confidence context.
- `.env.production` referenced by Compose or present in the archive is recorded as sensitive but not read.
- `.env.example` or `.env.template` can be read within limits if treated as templates.
- Full-line commented examples such as `# privileged: true` do not create strong findings.
- Path traversal entries, symlinks, hardlinks, and non-regular TAR entries are not read.
- File count, per-file byte, total byte, and archive entry limits mark truncation predictably.
- Legacy/sparse/malformed result payloads do not break backend exports or frontend reports.
- Secret-like evidence is redacted in runner results, Markdown, HTML, XML/PDF where applicable, and UI raw JSON.

## 9. Proposed Implementation Microphases

1. Runner/parser design spike and passive analyzer:
   - add candidate classification;
   - read bounded Docker/Compose files;
   - implement comment-aware line heuristics;
   - generate minimal result JSON and runner tests.

2. Backend job integration:
   - add `docker_config_basic` audit type and `POST /audits/docker-config/{file_id}`;
   - accept only `kind: "archive"`;
   - add service delegation, storage compatibility, and backend tests.

3. Reporting and exports:
   - add Markdown/HTML/XML/PDF sections;
   - ensure context, redaction, sparse results, queued/running/failed states, and grouped findings are readable.

4. Frontend report UX:
   - add archive action;
   - add report helper/component;
   - group findings by severity/category;
   - show files, services, stages, limits, redaction notes, errors, and raw JSON.

5. Documentation and manual smoke validation:
   - update README, architecture, and security scope;
   - document variables and limitations;
   - manually test a small archive with Dockerfile and Compose examples.

## 10. Documentation Changes When Implemented

When `docker_config_basic` is implemented, update:

- `README.md`
  - endpoint usage;
  - UI action;
  - limits and variables;
  - passive/no-Docker/no-CVE scope;
  - redaction behavior.

- `docs/architecture.md`
  - archive-based flow;
  - runner parsing model;
  - result schema;
  - relationship to `django_config_basic` and shared deployment signals.

- `docs/security-scope.md`
  - add allowed scope for Docker config static review;
  - explicitly keep Docker build/run/socket/scanner/CVE/image-registry actions out of scope;
  - document local storage sensitivity and best-effort redaction.

No existing docs should claim that `docker_config_basic` exists until the runtime module is implemented. This design document is only a future-plan artifact.
