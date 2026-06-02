# compose_config_basic Design

Status: historical docs-first design. `compose_config_basic` was implemented and closed as a v1 passive archive-based Docker Compose config audit. See `docs/future/compose-config-basic-closeout.md` for the runtime scope, smoke checklist, residual risks, and product decision.

## 1. Module Objective

`compose_config_basic` is a future passive archive audit for Docker Compose and Compose-like configuration files supplied by the user.

The module should help users review static service wiring signals around published ports, networks, volumes, secrets, environment variables, healthchecks, restart policies, image/build posture, and reverse-proxy-facing labels before running or sharing a deployment archive.

It should not execute Docker, run `docker compose config`, run `docker compose up`, build images, pull images, inspect images, contact registries, resolve environment variables from real `.env` files, query CVEs, or prove exploitability. Findings must remain conservative review indicators that require human validation.

This is useful for Inspectra because Compose files often connect real services: web apps, databases, workers, queues, reverse proxies, storage volumes, and operational networks. A bounded, local, archive-only review gives defenders early signal without Docker daemon access, provider credentials, registry access, or external services.

## 2. Allowed Scope

The module should only analyze archives uploaded by the user and registered as `kind: archive`.

Allowed behavior:

- Bounded reads of candidate Compose YAML/YML text inside uploaded archives.
- Safe local YAML parsing if a safe parser is already available in the runner.
- Bounded YAML-like heuristics if no safe parser is available.
- Best-effort support for top-level `services`, `networks`, `volumes`, `secrets`, and `configs`.
- Detection of service-level image, build, ports, expose, environment, env_file, volumes, networks, secrets, healthcheck, restart, labels, capabilities, and namespace settings.
- Detection of `.env`, `.env.*`, and `.envrc` files as sensitive files present without reading their content.
- Detection of `env_file` references without resolving or reading referenced files.
- Detection of Dockerfile paths referenced by `build` as context only.
- Detection of Nginx/reverse-proxy config paths referenced by volumes as context only.
- Detection of Kubernetes/Terraform files in the same archive only as supporting context if already visible through archive metadata; their audits belong to their own modules.
- Redaction-first handling of secret-like values in evidence, errors, raw results, and future exports.
- Recording parse uncertainty, unsupported syntax, truncation, and controlled errors.

Disallowed behavior in v1:

- No Docker execution.
- No `docker compose config`.
- No `docker compose up`, `run`, `exec`, `build`, `pull`, `push`, or `logs`.
- No Docker daemon validation.
- No image inspection.
- No image pull.
- No registry lookup.
- No CVE or advisory lookup.
- No network calls.
- No reading real `.env`, `.env.*`, or `.envrc` contents.
- No reading secret files referenced by Compose `secrets`.
- No full environment interpolation.
- No merging multiple Compose files into an effective runtime config.
- No broad extraction.
- No symlink or hardlink following.
- No exploitability, compromise, or confirmed-vulnerability claims.

## 3. Candidate Files

Primary Compose candidates:

- `docker-compose.yml`
- `docker-compose.yaml`
- `compose.yml`
- `compose.yaml`
- `docker-compose.*.yml`
- `docker-compose.*.yaml`
- `compose.*.yml`
- `compose.*.yaml`
- `stacks/*.yml`
- `stacks/*.yaml`
- `deploy/compose/*.yml`
- `deploy/compose/*.yaml`
- `docker/compose/*.yml`
- `docker/compose/*.yaml`
- `infra/compose/*.yml`
- `infra/compose/*.yaml`

Context files detected but not expanded into primary scope:

- Dockerfiles referenced by `build`, only as path/context.
- `.env`, `.env.*`, and `.envrc`, detected as sensitive files present and not read.
- Nginx configs referenced by volumes, only as paths/context; their audit belongs to `nginx_config_basic`.
- Kubernetes/Terraform files present in the same archive, only as supporting archive context; their audits belong to `k8s_config_basic` and `terraform_config_basic`.

Candidate folders and path contexts:

- `compose/**`
- `docker/compose/**`
- `deploy/compose/**`
- `infra/compose/**`
- `infrastructure/compose/**`
- `stacks/**`
- `deploy/**`
- `environments/**`
- `envs/**`

## 4. Environment and Secret File Handling

Real environment files often contain secrets and should not be read in v1:

- Detect `.env`, `.env.*`, and `.envrc` as sensitive files present.
- Do not read their contents.
- Do not resolve variables from `.env`.
- Do not interpolate real values into Compose fields.
- Do not render values from secret files referenced by Compose `secrets`.

For `env_file`:

- Detect `env_file` references.
- Do not read the referenced file by resolution.
- If the referenced path appears as an independent `.env*` archive candidate, record it as sensitive and not read.
- Report `compose_env_file_reference` and, where applicable, `compose_env_file_sensitive_present`.

## 5. Out of Scope

`compose_config_basic` v1 must not perform:

- Docker execution.
- Docker Compose execution.
- `docker compose config`.
- `docker compose up`, `run`, `exec`, `build`, `pull`, `push`, or `logs`.
- Container startup.
- Image build, pull, or inspection.
- Registry lookup.
- CVE, advisory, reputation, or image metadata lookup.
- Docker daemon validation.
- Network calls.
- Full environment interpolation.
- Multi-file Compose merge into an effective runtime config.
- Secret validation.
- Reading `.env`, `.env.*`, `.envrc`, or secret file contents.
- Reading host paths outside the archive.
- Exploitability, compromise, or confirmed-vulnerability claims.

Findings must remain heuristic review indicators.

## 6. Initial Finding Model

Secrets and environment:

- `compose_environment_secret_like_value`
- `compose_environment_secret_like_key`
- `compose_env_file_reference`
- `compose_env_file_sensitive_present`
- `compose_secrets_defined`
- `compose_secret_file_reference`
- `compose_secret_like_label`
- `compose_plaintext_private_key_hint`
- `compose_credential_url_hint`

Ports and exposure:

- `compose_port_published_all_interfaces`
- `compose_sensitive_port_published`
- `compose_database_port_published`
- `compose_admin_port_published`
- `compose_dashboard_port_published`
- `compose_port_range_published`
- `compose_host_network_mode`

Privileges and container hardening:

- `compose_privileged_true`
- `compose_cap_add_present`
- `compose_security_opt_disabled_hint`
- `compose_user_root_or_missing`
- `compose_read_only_missing`
- `compose_pid_host`
- `compose_ipc_host`
- `compose_cgroup_parent_present`

Volumes and mounts:

- `compose_docker_socket_mounted`
- `compose_sensitive_host_path_mounted`
- `compose_root_host_path_mounted`
- `compose_ssh_key_path_mounted`
- `compose_var_run_mounted`
- `compose_bind_mount_writeable_sensitive`
- `compose_named_volume_present`

Images and build:

- `compose_image_latest_tag`
- `compose_image_missing_digest`
- `compose_image_unpinned_tag`
- `compose_build_context_present`
- `compose_build_context_parent_path_hint`
- `compose_image_pull_policy_always_hint`

Networks:

- `compose_external_network_present`
- `compose_network_internal_missing`
- `compose_service_exposes_ports_without_publish_hint`
- `compose_links_legacy_present`

Reliability and runtime posture:

- `compose_healthcheck_missing`
- `compose_restart_policy_missing`
- `compose_restart_always_hint`
- `compose_depends_on_without_health_condition`
- `compose_logging_driver_disabled_or_none`
- `compose_resource_limits_missing`

Reverse proxy and app wiring:

- `compose_traefik_insecure_label_hint`
- `compose_nginx_proxy_exposed_hint`
- `compose_caddy_or_proxy_public_hint`
- `compose_virtual_host_label_present`

Config structure:

- `compose_multiple_files_detected`
- `compose_override_file_detected`
- `compose_profiles_present`
- `compose_unsupported_or_malformed_yaml`

## 7. Severity and Confidence

Use conservative defaults.

Medium severity:

- Docker socket mounted.
- `privileged: true`.
- Host network, PID, or IPC mode.
- Sensitive ports published on all interfaces.
- Database, admin, or dashboard ports published.
- Root host path mounted.
- SSH key path mounted.
- Secret-like environment values.
- Credential URLs.
- Plaintext private key material.

Low severity:

- Latest or unpinned images.
- Missing healthcheck.
- Missing restart policy.
- Missing resource limits.
- Writable sensitive bind mounts when context is uncertain.
- External networks.
- `env_file` references.

Info severity:

- Named volumes present.
- Build context present.
- Secrets defined without raw value exposure.
- Profiles or override files detected.
- Parser uncertainty.
- Supporting context detected.

Path context:

- `production`, `prod`, `live`, `deploy`, `stacks`, `server`, and `vps` preserve severity.
- `dev`, `test`, `local`, `example`, `sample`, `docs`, and `sandbox` degrade severity.
- `docker-compose.override.yml` should be context-aware and usually lower severity unless the path or filename is production-like.

Never claim confirmed compromise, runtime exposure, or exploitability.

## 8. Redaction and Safe Evidence

The module must reuse the defensive redaction posture established by `secrets_review_basic`, `docker_config_basic`, `k8s_config_basic`, `terraform_config_basic`, and `nginx_config_basic`.

Never show raw values for:

- Environment secret-like keys or values.
- `.env` or `env_file` contents.
- Compose secret file contents.
- Credential URLs.
- Registry credentials.
- Database URLs.
- Redis URLs with passwords.
- API keys, tokens, passwords, and client secrets.
- Private key blocks.
- Labels containing secret-like values.
- Command or entrypoint arguments containing secret-like values.

Safe evidence may include:

- File path.
- Service name.
- Field path.
- Key name.
- Port number and protocol.
- Mount target path.
- Non-secret image name/tag when safe.
- Network name when safe.
- Fixed `[REDACTED]` placeholder.

Evidence must not include prefixes, suffixes, hashes, fingerprints, or reversible identifiers for secrets. Raw JSON, future backend exports, frontend reports, and errors must be defensively redacted even for legacy or malformed payloads.

Uploaded archive bytes may still contain secrets and are stored locally; redaction protects Inspectra results and reports, not the original uploaded archive.

## 9. Parsing Strategy

Preferred approach:

- Use a safe local YAML parser only if already available in the runner runtime and appropriate for untrusted text.
- Otherwise use bounded YAML-like heuristics.

v1 should support best-effort parsing for:

- Top-level `services`.
- Top-level `networks`.
- Top-level `volumes`.
- Top-level `secrets`.
- Top-level `configs`, if easy and safe.
- Service fields such as `image`, `build`, `ports`, `expose`, `environment`, `env_file`, `volumes`, `networks`, `secrets`, `healthcheck`, `restart`, `labels`, `privileged`, `cap_add`, `security_opt`, `user`, `read_only`, `network_mode`, `pid`, `ipc`, `depends_on`, and `logging`.

Parser constraints:

- Do not run `docker compose config`.
- Do not interpolate env vars.
- Do not read `.env` or secret files.
- Do not merge multiple Compose files into an effective config in v1.
- Detect multiple compose files and overrides as context.
- Record parse uncertainty/errors as controlled errors.
- Do not read outside the archive.
- Do not follow symlinks or hardlinks.

## 10. Proposed JSON Result

The result should align with existing passive audit modules:

```json
{
  "analyzer": "compose_config_basic",
  "archive_type": "zip",
  "summary": {
    "files_considered": 0,
    "files_reviewed": 0,
    "compose_files_detected": 0,
    "services_detected": 0,
    "networks_detected": 0,
    "volumes_detected": 0,
    "secrets_detected": 0,
    "published_ports_detected": 0,
    "env_files_detected": 0,
    "findings_count": 0,
    "redacted_values_count": 0,
    "truncated": false
  },
  "limits": {
    "max_files": 100,
    "max_file_bytes": 524288,
    "max_total_bytes": 2097152
  },
  "files_detected": [],
  "files_reviewed": [],
  "services": [],
  "ports": [],
  "volumes": [],
  "networks": [],
  "secrets": [],
  "env_files": [],
  "build_contexts": [],
  "images": [],
  "findings": [],
  "redaction_notes": [],
  "errors": [],
  "truncated": false
}
```

Finding objects should include, when available:

- `id` / `code`
- `title`
- `level`
- `confidence`
- `category`
- `context`
- `file_path`
- `line`
- `service`
- `field_path`
- `image`
- `port`
- `protocol`
- `host_path`
- `container_path`
- `network`
- `description`
- `evidence`
- `recommendation`

Candidate future limits:

- `INSPECTRA_COMPOSE_CONFIG_MAX_FILES`, default `100`.
- `INSPECTRA_COMPOSE_CONFIG_MAX_FILE_BYTES`, default `524288`.
- `INSPECTRA_COMPOSE_CONFIG_MAX_TOTAL_BYTES`, default `2097152`.

## 11. UX and Reporting Expectations

The future UI and exports should present `compose_config_basic` as a passive static Compose review, not a vulnerability scanner.

Expected sections:

- Summary.
- Files reviewed/skipped.
- Services overview.
- Images and build contexts.
- Ports/exposure.
- Volumes/mounts.
- Networks.
- Secrets and env file references.
- Healthchecks, restart policy, and resource posture.
- Reverse proxy labels/context.
- Findings grouped by severity/category/context.
- Limits/errors/truncation.
- Redaction notes.
- Raw JSON defensively redacted.

Reports should clearly state that Inspectra does not execute Docker, run `docker compose config`, run containers, build or pull images, inspect images, interpolate env vars, read `.env` values, query registries/CVEs/advisories, or confirm exploitability.

## 12. Future Tests

Runner tests:

- `environment` password value generates `compose_environment_secret_like_value` and redacts the value.
- `environment` secret-like key generates `compose_environment_secret_like_key`.
- `env_file` reference is detected but not read.
- `.env` file is detected as sensitive and not read.
- Docker socket mount generates `compose_docker_socket_mounted`.
- `privileged: true` generates `compose_privileged_true`.
- Host network/PID/IPC generates corresponding findings.
- Port `0.0.0.0:5432:5432` generates database exposure findings.
- Port `8080:8080` on all interfaces generates published-all-interfaces findings.
- Image `nginx:latest` generates latest/unpinned findings.
- Image without digest generates missing-digest findings.
- Service without healthcheck generates `compose_healthcheck_missing`.
- Service without restart policy generates `compose_restart_policy_missing`.
- Sensitive bind mounts such as `/etc`, `/root/.ssh`, and `/var/run/docker.sock` generate findings.
- Secrets defined with file references are detected without reading file contents.
- Comments do not generate strong findings.
- Path traversal, absolute archive names, symlinks, hardlinks, and non-regular archive entries are not read.
- Limits and truncation are respected.
- Serialized JSON does not contain fixture secrets.

Backend/reporting tests:

- Endpoint accepts only archives.
- Runner call targets `/analyze/compose-config`.
- Job type is `compose_config_basic`.
- Summary tolerates sparse/malformed payloads.
- Exports redact legacy secrets.
- Findings with missing optional fields render without breaking.

Frontend tests:

- Action appears only for archives.
- Report renders summary, services, ports, volumes, networks, secrets/env files, and findings.
- Queued/running/failed/sparse/malformed payloads do not break.
- Raw JSON is redacted.
- DOM does not contain fixture secrets.

Suggested fixture secrets:

- `super-secret-password`
- `raw-api-key-123456`
- `token_should_never_render`
- `POSTGRES_PASSWORD=super-secret-password`
- `DATABASE_URL=postgres://user:pass@example.com/db`
- `redis://:super-secret-password@redis:6379/0`
- `registry-user:registry-pass`
- `-----BEGIN PRIVATE KEY-----`

## 13. Implementation Microphases

Recommended sequence:

1. Docs-first design and scope freeze.
2. Runner/parser passive analysis plus redaction and tests.
3. Backend endpoint/job/storage/reporting and tests.
4. Frontend action/report UX and tests.
5. End-to-end contract/redaction review.
6. Docs/smoke closeout.

Each runtime phase should preserve the same non-scope: no Docker execution, no `docker compose config`, no builds, no pulls, no registry/CVE lookups, no env interpolation from real `.env`, no network calls, and no exploitability claims.

## 14. Future Documentation Updates

When implemented, update:

- `README.md` with the backend endpoint, UI action, limits, no-scope, and launch example.
- `docs/architecture.md` with the backend/runner/storage/reporting/frontend flow.
- `docs/security-scope.md` with allowed Compose review scope and explicit out-of-scope behavior.
- A future closeout document such as `docs/future/compose-config-basic-closeout.md`.

Documentation must continue to state that Inspectra does not run Docker, execute Compose, build/pull/inspect images, interpolate real env values, query registries/CVEs/advisories, call external services, or confirm exploitability.
