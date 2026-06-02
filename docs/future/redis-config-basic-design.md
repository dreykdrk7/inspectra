# redis_config_basic Design

Status: docs-first design only. `redis_config_basic` is not implemented yet.

## 1. Module Objective

`redis_config_basic` is a future passive archive audit for Redis OSS and redis.conf-style compatible configuration files supplied by the user.

The module should help users review static cache, queue, session-store, and data-layer configuration signals around network exposure, authentication, ACL references, TLS posture, persistence, replication, dangerous commands, modules, logging, resource limits, includes, and sensitive adjacent files before a Redis deployment archive is run or shared.

It should not execute Redis, run `redis-server`, run `redis-cli`, run Sentinel, connect to databases, open sockets, parse dumps, read AOF data, validate credentials, contact live services, query CVEs, or prove exploitability. Findings must remain conservative review indicators that require human validation.

This is useful for Inspectra because Redis is common in real deployments and often holds cache, session, queue, rate-limit, and application state. A bounded, local, archive-only review gives defenders early signal without Redis credentials, live database access, host path reads, or external services.

## 2. Allowed Scope

The module should only analyze archives uploaded by the user and registered as `kind: archive`.

Allowed behavior:

- Bounded reads of candidate Redis and Sentinel config text inside uploaded archives.
- Textual, Redis-like, line-oriented heuristic analysis.
- Comment-aware scanning for `#` comments.
- Best-effort parsing of directives as `directive arg1 arg2 ...`.
- Best-effort handling of quoted strings without executing or evaluating them.
- Detection of Redis config files, Sentinel config files, includes, ACL file references, dump/AOF/backups, and sensitive `.env`-style files.
- Detection of `.env`, `.env.*`, `.envrc`, ACL files, RDB dumps, AOF files, and backup files as sensitive files present without reading their contents.
- Detection of `include`, `aclfile`, TLS key/cert paths, persistence paths, replication settings, Sentinel directives, module load directives, and password-like directives as bounded config context.
- Redaction-first handling of secret-like values in evidence, errors, raw results, and future exports.
- Recording parser uncertainty, unsupported syntax, truncation, skipped files, and controlled errors.

Disallowed behavior in v1:

- No Redis execution.
- No `redis-server`, `redis-cli`, `redis-sentinel`, `redis-benchmark`, or equivalent command execution.
- No Redis, Sentinel, or cluster connection.
- No command execution against any database.
- No socket opening.
- No network calls.
- No Docker execution.
- No container startup.
- No credential validation.
- No reading real `.env`, `.env.*`, or `.envrc` contents.
- No reading ACL file contents.
- No reading RDB dump, AOF, appendonly directory, or backup contents.
- No include resolution outside normal archive candidate scanning.
- No host path reads.
- No broad extraction.
- No symlink or hardlink following.
- No CVE or advisory lookup.
- No exploitability, compromise, data breach, or confirmed-vulnerability claims.

## 3. Candidate Files

Primary Redis and Sentinel config candidates:

- `redis.conf`
- `redis-*.conf`
- `sentinel.conf`
- `redis-sentinel.conf`
- `redis/**/*.conf`
- `redis*/**/*.conf`
- `cache/redis/**/*.conf`
- `db/redis/**/*.conf`
- `database/redis/**/*.conf`
- `infra/redis/**/*.conf`
- `deploy/redis/**/*.conf`
- `docker/redis/**/*.conf`
- `config/redis/**/*.conf`

Sensitive/context files detected but not read:

- `.env`
- `.env.*`
- `.envrc`
- `users.acl`
- `*.acl`
- `dump.rdb`
- `*.rdb`
- `appendonly.aof`
- `*.aof`
- `appendonlydir/**`
- `redis-dump.rdb`
- `redis-backup.rdb`
- `*.backup`
- `*.bak`

Supporting context files may be detected only as context if already visible through archive metadata or normal candidate scanning:

- Docker Compose files referencing Redis services.
- Dockerfiles that clearly install or run Redis.
- Kubernetes manifests with Redis container names or config mount paths.
- Terraform files that reference Redis resources.

Those supporting files should not expand `redis_config_basic` into Docker, Compose, Kubernetes, or Terraform analysis. Their own audits belong to their own modules.

Candidate folders and path contexts:

- `redis/**`
- `redis-*/**`
- `cache/redis/**`
- `db/redis/**`
- `database/redis/**`
- `infra/redis/**`
- `infrastructure/redis/**`
- `deploy/redis/**`
- `docker/redis/**`
- `config/redis/**`
- `sentinel/**`

## 4. Sensitive File Handling

Redis-adjacent files can contain raw keys, passwords, session data, serialized application data, or credential material. v1 should be conservative:

- Detect `.env`, `.env.*`, and `.envrc` as sensitive files present.
- Detect ACL files such as `users.acl` and `*.acl` as sensitive files present.
- Detect RDB dumps, AOF files, appendonly directories, and backup files as sensitive files present.
- Do not read the contents of `.env`, ACL, dump, AOF, appendonly directory, or backup files.
- Do not parse Redis dump data.
- Do not infer keys, values, users, roles, or datasets from dumps/AOF/backups.
- Record these files as no-read context and review indicators where appropriate.

Recommended findings:

- `redis_env_file_sensitive_present`
- `redis_acl_file_present`
- `redis_acl_file_not_read`
- `redis_dump_or_aof_file_present`

## 5. Include and Path Handling

Redis config supports `include`, and paths can point to host files, generated config, secrets, ACL files, dump directories, certificate/key files, or deployment-specific locations. v1 should not resolve includes.

Include rules:

- Detect `include` directives as context.
- Do not resolve includes by path.
- Do not read absolute host paths.
- Do not read outside the archive.
- If an included file is also independently detected as a candidate inside the archive, it may be reviewed as its own file through normal archive scanning, not by resolving the include.
- If an include points to an absolute path, sensitive-looking path, or host path, record a controlled review indicator.
- Treat unresolved includes as parser uncertainty, not a Redis validation failure.

Recommended findings:

- `redis_include_absolute_path`
- `redis_include_not_resolved`

## 6. Out of Scope

`redis_config_basic` v1 must not perform:

- Redis execution.
- Redis Sentinel execution.
- `redis-server`, `redis-cli`, `redis-sentinel`, or `redis-benchmark`.
- DB connections.
- Socket opening.
- Redis command execution.
- Credential validation.
- Live runtime configuration validation.
- Redis Cluster or Sentinel state validation.
- Replication reachability checks.
- Docker execution.
- Container startup.
- Network calls.
- DNS resolution.
- Port scanning.
- Real TLS/certificate validation.
- RDB dump parsing.
- AOF parsing.
- Backup parsing.
- ACL file content parsing.
- `.env`, `.env.*`, or `.envrc` content reads.
- Include resolution outside normal archive candidate scanning.
- Host path reads.
- CVE, advisory, reputation, or version vulnerability lookup.
- Exploitability, compromise, data breach, or confirmed-vulnerability claims.

Findings must remain heuristic review indicators.

## 7. Initial Finding Model

Generic and sensitive files:

- `redis_env_file_sensitive_present`
- `redis_acl_file_present`
- `redis_dump_or_aof_file_present`
- `redis_password_like_value`
- `redis_private_key_hint`
- `redis_include_absolute_path`
- `redis_include_not_resolved`

Network and exposure:

- `redis_bind_all_interfaces`
- `redis_bind_public_address_hint`
- `redis_protected_mode_no`
- `redis_port_default_exposed_hint`
- `redis_tls_port_missing_hint`
- `redis_unixsocket_permissions_permissive`

Authentication and ACL:

- `redis_requirepass_missing`
- `redis_requirepass_present_redacted`
- `redis_masterauth_present_redacted`
- `redis_aclfile_reference`
- `redis_default_user_enabled_hint`
- `redis_acl_file_not_read`

TLS:

- `redis_tls_disabled_or_missing`
- `redis_tls_cert_path_present`
- `redis_tls_key_path_present`
- `redis_tls_auth_clients_disabled_hint`
- `redis_tls_protocols_legacy_hint`

Persistence and backups:

- `redis_save_disabled_hint`
- `redis_appendonly_no`
- `redis_appendfilename_default_hint`
- `redis_dir_sensitive_path_hint`
- `redis_dbfilename_default_hint`
- `redis_rdbcompression_no_hint`

Replication:

- `redis_replicaof_present`
- `redis_replica_read_only_no`
- `redis_masterauth_missing_for_replica_hint`
- `redis_repl_diskless_sync_enabled_hint`

Dangerous commands and modules:

- `redis_rename_command_missing_for_dangerous_command_hint`
- `redis_dangerous_command_renamed_to_empty_hint`
- `redis_module_load_present`
- `redis_lua_time_limit_high_hint`

Logging and runtime posture:

- `redis_loglevel_debug_or_verbose`
- `redis_logfile_stdout_or_empty_hint`
- `redis_supervised_no_hint`
- `redis_daemonize_yes_hint`

Limits and resources:

- `redis_maxmemory_missing`
- `redis_maxmemory_policy_noeviction_hint`
- `redis_timeout_zero_hint`
- `redis_tcp_keepalive_low_or_missing_hint`
- `redis_client_output_buffer_limit_missing_hint`

Sentinel:

- `redis_sentinel_config_detected`
- `redis_sentinel_auth_pass_present_redacted`
- `redis_sentinel_down_after_milliseconds_low_hint`
- `redis_sentinel_monitor_without_auth_hint`

## 8. Severity and Confidence

Use conservative defaults.

Medium severity:

- `protected-mode no`.
- `bind 0.0.0.0`, `bind ::`, or public-address bind in production-like paths.
- `requirepass` missing when combined with public bind or protected mode disabled.
- Default Redis port exposure hints in production-like context.
- TLS disabled or missing in production-like context.
- `requirepass`, `masterauth`, or Sentinel auth values present, with evidence redacted.
- ACL/default-user risky signals.
- RDB, AOF, or backup files present in production-like paths.
- Private key material hints.
- `loadmodule` in production-like paths.

Low severity:

- `requirepass` missing when exposure context is unclear.
- Persistence disabled or AOF disabled when production context is plausible.
- `maxmemory` missing.
- `timeout 0`.
- Include not resolved.
- Debug or verbose logging.
- Permissive `unixsocketperm`.
- Certificate or key paths present.
- Sentinel config detected.

Info severity:

- Redis config detected.
- Sentinel config detected.
- ACL file detected but not read.
- Dump/AOF/backup detected but not read.
- Replication settings present.
- Parser uncertainty or unsupported syntax.
- Supporting Compose, Docker, Kubernetes, or Terraform Redis context detected.

Path context:

- `production`, `prod`, `live`, `deploy`, `server`, `vps`, `data`, `cache`, and `redis` preserve severity.
- `dev`, `test`, `local`, `example`, `sample`, `docs`, and `sandbox` degrade severity.
- Ambiguous snippets should avoid deployment-specific claims.

Confidence should remain high only for direct directive observations or archive metadata observations. Missing-auth, missing-TLS, and missing-limit findings should usually be medium or low confidence because includes and generated config may be unresolved in v1.

Never claim confirmed compromise, runtime exposure, data breach, or exploitability.

## 9. Redaction and Safe Evidence

The module must reuse the defensive redaction posture established by `secrets_review_basic`, `database_config_basic`, `compose_config_basic`, `nginx_config_basic`, `terraform_config_basic`, and `k8s_config_basic`.

Never show raw values for:

- `requirepass`.
- `masterauth`.
- `sentinel auth-pass`.
- ACL file contents.
- Redis user password hashes or password material.
- TLS private keys.
- Private key blocks.
- Certificate contents.
- Redis URLs with passwords.
- Connection strings.
- `.env`, RDB, AOF, dump, appendonly directory, or backup contents.
- Backup destination credentials.
- Password-like, token-like, API-key-like, or client-secret-like directives.
- Module paths if secret-like.

Safe evidence may include:

- File path.
- Config type, such as `redis` or `sentinel`.
- Directive or setting name.
- Line number.
- Bind/listen address when not secret-like.
- Port number.
- Referenced path when not secret-like.
- Fixed `[REDACTED]` placeholder.

Evidence must not include prefixes, suffixes, hashes, fingerprints, or reversible identifiers for secrets. Raw JSON, future backend exports, frontend reports, and errors must be defensively redacted even for legacy or malformed payloads.

Uploaded archive bytes may still contain secrets and are stored locally; redaction protects Inspectra results and reports, not the original uploaded archive.

## 10. Parsing Strategy

No Redis execution is allowed.

Recommended v1 parser approach:

- Use bounded text reads through the same archive safety model as other passive modules.
- Strip or ignore comments beginning with `#`, with care not to treat commented directives as strong findings.
- Parse non-comment lines as `directive arg1 arg2 ...`.
- Preserve best-effort line numbers.
- Support quoted strings best-effort without evaluating escapes beyond safe text handling.
- Detect Redis directives and Sentinel directives.
- Detect `include` directives as context and do not resolve them.
- Detect `aclfile`, `dir`, `dbfilename`, `appendfilename`, TLS cert/key paths, replication directives, and module load directives.
- Do not evaluate variables.
- Do not load ACL files.
- Do not parse RDB, AOF, appendonly directories, or backups.
- Do not validate against a live Redis version.
- Record parser uncertainty and unsupported syntax as controlled errors or info-level findings.

The parser should tolerate sparse, malformed, or partial config snippets without raising unhandled exceptions.

## 11. Proposed JSON Result

The result should align with existing passive audit modules:

```json
{
  "analyzer": "redis_config_basic",
  "archive_type": "zip",
  "summary": {
    "files_considered": 0,
    "files_reviewed": 0,
    "redis_files_detected": 0,
    "sentinel_files_detected": 0,
    "acl_files_detected": 0,
    "dump_or_aof_files_detected": 0,
    "configs_detected": 0,
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
  "configs": [],
  "redis_settings": [],
  "sentinel_settings": [],
  "includes": [],
  "acl_files": [],
  "dump_or_aof_files": [],
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
- `config_type`
- `directive`
- `setting`
- `port`
- `address`
- `path`
- `description`
- `evidence`
- `recommendation`

Candidate future limits:

- `INSPECTRA_REDIS_CONFIG_MAX_FILES`, default `100`.
- `INSPECTRA_REDIS_CONFIG_MAX_FILE_BYTES`, default `524288`.
- `INSPECTRA_REDIS_CONFIG_MAX_TOTAL_BYTES`, default `2097152`.

## 12. UX and Reporting Expectations

The future UI and exports should present `redis_config_basic` as a passive static Redis config review, not a vulnerability scanner or live Redis validator.

Expected sections:

- Summary.
- Files reviewed/skipped.
- Config overview.
- Redis settings.
- Sentinel settings.
- Network and binding posture.
- Authentication and ACL references.
- TLS posture.
- Persistence, dumps, AOF, and backups.
- Replication settings.
- Dangerous commands and modules.
- Limits and resource posture.
- Includes and unresolved config.
- Sensitive files detected but not read.
- Findings grouped by severity, category, and context.
- Limits, truncation, parser uncertainty, and controlled errors.
- Redaction notes.
- Raw JSON, defensively redacted.

Reports should clearly state that Inspectra does not execute Redis, run `redis-cli`, run Sentinel, connect to databases, open sockets, execute commands, resolve includes, read `.env`/ACL/dump/AOF/backups, validate live TLS or runtime state, query CVEs/advisories, or confirm exploitability.

## 13. Future Tests

Runner tests should cover:

- `protected-mode no` generates `redis_protected_mode_no`.
- `bind 0.0.0.0` generates `redis_bind_all_interfaces`.
- Public-looking `bind` values generate `redis_bind_public_address_hint`.
- `requirepass` values generate `redis_requirepass_present_redacted` and do not serialize the value.
- Missing `requirepass` with public bind/protected mode off generates conservative missing-auth findings.
- `masterauth` values generate `redis_masterauth_present_redacted`.
- `aclfile users.acl` generates `redis_aclfile_reference`.
- `users.acl` and `*.acl` files are detected but not read.
- `.env` and `.env.*` files are detected but not read.
- `dump.rdb`, `appendonly.aof`, `appendonlydir/**`, `*.rdb`, `*.aof`, `*.backup`, and `*.bak` are detected but not read.
- `tls-port` missing or TLS disabled generates TLS posture findings where context supports it.
- `tls-key-file` and `tls-cert-file` paths are shown safely.
- Private key blocks in config are redacted and do not preserve `PRIVATE KEY`.
- `appendonly no` generates `redis_appendonly_no`.
- `save ""` generates `redis_save_disabled_hint`.
- `dir /var/lib/redis` and default filenames generate persistence path/name hints.
- `replicaof` generates `redis_replicaof_present`.
- `replica-read-only no` generates `redis_replica_read_only_no`.
- `loadmodule` generates `redis_module_load_present`.
- Dangerous command rename posture generates command findings.
- `loglevel debug` or `verbose` generates logging findings.
- `maxmemory` missing generates `redis_maxmemory_missing`.
- `timeout 0` generates `redis_timeout_zero_hint`.
- Sentinel config generates `redis_sentinel_config_detected`.
- `sentinel auth-pass` generates a redacted auth finding.
- `include /etc/redis/secrets.conf` generates include absolute/not-resolved findings without host reads.
- Full-line comments do not generate strong findings.
- Path traversal, absolute archive names, symlinks, hardlinks, and non-regular archive entries are not read.
- Limits and truncation are respected.
- Serialized JSON does not contain fixture secrets.

Backend/reporting tests should cover:

- Endpoint accepts only archives.
- Runner call targets `/analyze/redis-config`.
- Job type is `redis_config_basic`.
- Summary tolerates sparse, null, and malformed payloads.
- Markdown, HTML, XML, and PDF exports redact legacy secrets.
- ACL, dump, AOF, and backup files render as detected/no-read.
- Includes render as detected/not resolved.
- Findings with missing optional fields render without breaking.

Frontend tests should cover:

- Action appears only for archives.
- Report renders summary, configs, Redis settings, Sentinel settings, includes, ACL files, dumps/AOF/backups, findings, limits, errors, and redaction notes.
- Queued, running, failed, sparse, and malformed payloads do not break.
- Raw JSON is redacted.
- Serialized DOM does not contain fixture secrets.

Suggested fixture secrets:

- `super-secret-password`
- `raw-api-key-123456`
- `token_should_never_render`
- `requirepass super-secret-password`
- `masterauth super-secret-password`
- `sentinel auth-pass mymaster super-secret-password`
- `redis://:super-secret-password@redis:6379/0`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`
- `dump_value_should_not_render`
- `acl_password_hash_should_not_render`

## 14. Implementation Microphases

Recommended sequence:

1. Docs-first design and scope freeze.
2. Runner/parser passive analysis plus redaction and tests.
3. Backend endpoint/job/storage/reporting and tests.
4. Frontend action/report UX and tests.
5. End-to-end contract/redaction review.
6. Docs/smoke closeout.

Each runtime phase should preserve the same non-scope: no Redis execution, no Redis connections, no command execution, no socket opening, no Docker execution, no include resolution, no `.env`/ACL/dump/AOF/backups reads, no network calls, no CVE/advisory lookups, and no exploitability claims.

## 15. Future Documentation Updates

When implemented, update:

- `README.md` with the backend endpoint, UI action, limits, no-scope, and launch example.
- `docs/architecture.md` with the backend/runner/storage/reporting/frontend flow.
- `docs/security-scope.md` with allowed Redis config review scope and explicit out-of-scope behavior.
- A future closeout document such as `docs/future/redis-config-basic-closeout.md`.

Documentation must continue to state that Inspectra does not run Redis, run Redis clients, connect to databases, execute commands, open sockets, read `.env`/ACL/dump/AOF/backups, resolve includes, query CVEs/advisories, call external services, or confirm exploitability.
