# nginx_config_basic Design

Status: historical docs-first design. `nginx_config_basic` was implemented and closed as a v1 passive archive-based web-edge config audit. See `docs/future/nginx-config-basic-closeout.md` for the runtime scope, smoke checklist, residual risks, and product decision.

## 1. Module Objective

`nginx_config_basic` is a future passive archive audit for Nginx and closely related reverse proxy/web edge configuration files supplied by the user.

The module should help users review static configuration signals around TLS, HTTPS redirects, security headers, reverse proxy behavior, CORS, sensitive route exposure, body-size and timeout limits, logging, includes, and secret-like values before a configuration is deployed or shared.

It should not execute Nginx, run `nginx -t`, start containers, contact live servers, resolve DNS, validate certificates, scan ports, query CVEs, or prove exploitability. Findings must remain conservative review indicators that require human validation.

This is useful for Inspectra because Nginx often sits at the web edge of real deployments and connects application, container, Kubernetes, Terraform, and CI/CD posture to the public internet. A bounded, local, archive-only review gives defenders early signal without server credentials or external services.

## 2. Allowed Scope

The module should only analyze archives uploaded by the user and registered as `kind: archive`.

Allowed behavior:

- Bounded reads of candidate Nginx and reverse-proxy config text inside uploaded archives.
- Textual, Nginx-like, line-oriented, and block-aware heuristic analysis.
- Comment-aware scanning for full-line and inline `#` comments.
- Best-effort block tracking for `http`, `server`, `location`, `upstream`, `map`, and `if` contexts.
- Best-effort directive scanning for directive name, arguments, line number, and current block context.
- Multiline directive handling until semicolon where practical.
- Detection of `include` directives as context.
- Detection of related Docker, Compose, or Kubernetes Nginx hints only as supporting context, not as a separate Docker/Kubernetes audit.
- Redaction-first handling of secret-like values in evidence, errors, raw results, and future exports.
- Recording parse uncertainty, unsupported syntax, truncation, and controlled errors.

Disallowed behavior in v1:

- No Nginx execution.
- No `nginx -t`.
- No container startup.
- No Docker execution.
- No server startup.
- No network calls.
- No port scanning.
- No DNS resolution.
- No live server validation.
- No real certificate validation.
- No reading real `.env`, `.env.*`, or `.envrc` files.
- No reading host paths outside the archive.
- No broad extraction.
- No symlink or hardlink following.
- No CVE or advisory lookups.
- No exploitability, compromise, or confirmed-vulnerability claims.

## 3. Candidate Files

Primary Nginx candidates:

- `nginx.conf`
- `*.conf`
- `sites-available/*`
- `sites-enabled/*`
- `conf.d/*.conf`
- `nginx/**/*.conf`
- `docker/nginx/*.conf`
- `deploy/nginx/*.conf`
- `infrastructure/nginx/*.conf`
- `infra/nginx/*.conf`
- `reverse-proxy/*.conf`
- `proxy/*.conf`

Supporting context files, detected but not expanded into separate audit scope:

- Dockerfiles that clearly install or run Nginx.
- Docker Compose files with an Nginx service.
- Kubernetes Ingress Nginx annotations if they appear in files already detected as candidates.
- Certificate/key path references.
- Snippet/include paths referenced by Nginx directives.

Candidate folders and path contexts:

- `nginx/**`
- `reverse-proxy/**`
- `proxy/**`
- `edge/**`
- `gateway/**`
- `infra/nginx/**`
- `infrastructure/nginx/**`
- `deploy/nginx/**`
- `docker/nginx/**`
- `sites-enabled/**`
- `sites-available/**`
- `conf.d/**`

## 4. Include Handling

`include` is common in Nginx configs and can reference host paths, globs, generated files, or snippets outside the uploaded archive. v1 should be conservative:

- Do not resolve includes outside the current file by default.
- Do not read absolute host paths.
- Do not read outside the archive.
- Detect `include` directives as context and record their path or glob safely.
- If an included file is also independently detected as a candidate inside the archive, it may be reviewed as its own file through normal archive scanning, not by resolving the include.
- If an include points to an absolute path, a glob, or a sensitive-looking path, record an informational or low-severity review indicator.
- Treat unresolved includes as parse uncertainty, not a configuration failure.

## 5. Out of Scope

`nginx_config_basic` v1 must not perform:

- Nginx execution.
- `nginx -t`.
- Container execution.
- Docker build or run.
- Network calls.
- DNS resolution.
- Live server probing.
- Port scanning.
- Certificate chain, expiry, or hostname validation against real endpoints.
- Fetching included files from the host, network, or outside the archive.
- Apache, Caddy, Envoy, HAProxy, Traefik, or cloud load balancer analysis, except as future context.
- CVE, advisory, reputation, or registry lookup.
- Secret validation.
- Exploitability, compromise, or confirmed-vulnerability claims.

Findings must remain heuristic review indicators.

## 6. Initial Finding Model

TLS and HTTPS:

- `nginx_ssl_protocol_legacy_enabled`
- `nginx_ssl_protocols_missing`
- `nginx_ssl_ciphers_weak_hint`
- `nginx_https_redirect_missing`
- `nginx_hsts_missing`
- `nginx_hsts_low_max_age`
- `nginx_ssl_verify_disabled_hint`
- `nginx_insecure_upstream_http_hint`

Security headers:

- `nginx_x_frame_options_missing`
- `nginx_content_security_policy_missing`
- `nginx_x_content_type_options_missing`
- `nginx_referrer_policy_missing`
- `nginx_permissions_policy_missing`
- `nginx_security_headers_missing`

Server exposure:

- `nginx_server_tokens_on`
- `nginx_default_server_public_hint`
- `nginx_autoindex_on`
- `nginx_directory_listing_hint`
- `nginx_sensitive_location_exposed`
- `nginx_hidden_files_exposed`
- `nginx_backup_files_exposed`

Proxy behavior:

- `nginx_proxy_pass_http_upstream`
- `nginx_proxy_ssl_verify_off`
- `nginx_proxy_set_header_host_missing`
- `nginx_proxy_set_header_x_forwarded_proto_missing`
- `nginx_proxy_set_header_x_forwarded_for_missing`
- `nginx_websocket_upgrade_incomplete_hint`
- `nginx_proxy_buffering_disabled_hint`

Uploads, body size, and timeouts:

- `nginx_client_max_body_size_unlimited_or_large`
- `nginx_proxy_read_timeout_high`
- `nginx_proxy_connect_timeout_high`
- `nginx_keepalive_timeout_high`
- `nginx_request_timeout_missing_hint`

CORS:

- `nginx_cors_wildcard_origin`
- `nginx_cors_credentials_with_wildcard`
- `nginx_cors_overly_permissive_methods`

Auth and access control:

- `nginx_auth_basic_off_in_sensitive_location`
- `nginx_allow_all_sensitive_location`
- `nginx_deny_rules_missing_for_sensitive_paths`
- `nginx_stub_status_public_hint`

Logging and error handling:

- `nginx_access_log_off`
- `nginx_error_log_debug`
- `nginx_proxy_intercept_errors_missing_hint`

Secrets and redaction:

- `nginx_basic_auth_inline_secret_hint`
- `nginx_proxy_pass_credentials_hint`
- `nginx_header_secret_like_value`
- `nginx_variable_secret_like_value`
- `nginx_ssl_certificate_key_path_present`

Includes and config structure:

- `nginx_include_absolute_path`
- `nginx_include_glob_detected`
- `nginx_include_not_resolved`
- `nginx_unknown_or_unparsed_directive_hint`

## 7. Severity and Confidence

Use conservative defaults:

Medium severity:

- Legacy TLS protocols enabled.
- `server_tokens on` in production-like paths.
- `autoindex on`.
- Sensitive locations exposed.
- Wildcard CORS with credentials.
- `proxy_ssl_verify off`.
- `proxy_pass` with embedded credentials.
- Inline basic-auth-like secret material.
- Public `stub_status`.
- Public `default_server` in production-like context.

Low severity:

- Missing common security headers.
- HSTS missing or low `max-age`.
- Missing proxy forwarding headers.
- Large or unlimited body size.
- High proxy/connect/read/keepalive timeouts.
- `access_log off`.
- Include not resolved.

Info severity:

- Certificate or private key paths present.
- Include or glob detected.
- Nginx service/context detected.
- Parser uncertainty.
- Supporting Docker/Compose/Kubernetes Nginx context detected.

Path context:

- `production`, `prod`, `live`, `deploy`, `sites-enabled`, `conf.d`, `reverse-proxy`, `edge`, and `gateway` preserve severity.
- `dev`, `test`, `local`, `example`, `sample`, `docs`, and `sandbox` degrade severity.
- Ambiguous snippets should avoid deployment-specific claims.

Confidence should remain high only for direct directive observations. Missing-header and missing-redirect findings should usually be medium or low confidence because includes and inherited snippets may be unresolved in v1.

## 8. Redaction and Safe Evidence

The module must reuse the defensive redaction posture established by `secrets_review_basic`, `k8s_config_basic`, and `terraform_config_basic`.

Never show raw values for:

- Inline basic auth credentials.
- `proxy_pass` URLs with credentials.
- `Authorization` headers.
- API keys, tokens, client secrets, passwords, or credential-like values in headers, variables, maps, or snippets.
- Cookie or session values.
- Private key blocks.
- Certificate or private key contents.
- Upstream URLs with embedded credentials.
- Secret-like variables or map values.

Safe evidence may include:

- File path.
- Directive name.
- Context block type.
- Server name when not secret-like.
- Location path.
- Upstream name.
- Line number.
- Fixed `[REDACTED]` placeholder.

Evidence must not include prefixes, suffixes, hashes, fingerprints, or reversible identifiers for secrets. Raw JSON, future backend exports, frontend reports, and errors must be defensively redacted even for legacy or malformed payloads.

Uploaded archive bytes may still contain secrets and are stored locally; redaction protects Inspectra results and reports, not the original uploaded archive.

## 9. Parsing Strategy

No Nginx execution is allowed.

Recommended v1 parser approach:

- Use bounded text reads through the same archive safety model as other passive modules.
- Strip or ignore comments beginning with `#`, with care not to treat commented directives as strong findings.
- Accumulate multiline directives until a semicolon where practical.
- Track simple `{` and `}` block nesting.
- Record current block context for `http`, `server`, `location`, `upstream`, `map`, and `if`.
- Parse directive name, arguments, line number, file path, and context.
- Do not evaluate Nginx variables.
- Do not resolve includes.
- Do not normalize all possible inheritance behavior in v1.
- Record parser uncertainty and unsupported syntax as controlled errors or info-level findings.

The parser should tolerate sparse, malformed, or partial config snippets without raising unhandled exceptions.

## 10. Proposed JSON Result

The result should follow passive audit conventions used by existing Inspectra modules:

```json
{
  "analyzer": "nginx_config_basic",
  "archive_type": "zip",
  "summary": {
    "files_considered": 0,
    "files_reviewed": 0,
    "nginx_files_detected": 0,
    "server_blocks_detected": 0,
    "location_blocks_detected": 0,
    "upstream_blocks_detected": 0,
    "includes_detected": 0,
    "tls_servers_detected": 0,
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
  "servers": [],
  "locations": [],
  "upstreams": [],
  "includes": [],
  "directives": [],
  "findings": [],
  "redaction_notes": [],
  "errors": [],
  "truncated": false
}
```

Finding objects should include:

- `id` or `code`
- `title`
- `level`
- `confidence`
- `category`
- `context`
- `file_path`
- `line`
- `block_type`
- `server_name`
- `location`
- `upstream`
- `directive`
- `description`
- `evidence`
- `recommendation`

Candidate future limits:

- `INSPECTRA_NGINX_CONFIG_MAX_FILES`, default `100`.
- `INSPECTRA_NGINX_CONFIG_MAX_FILE_BYTES`, default `524288`.
- `INSPECTRA_NGINX_CONFIG_MAX_TOTAL_BYTES`, default `2097152`.

## 11. Expected UX and Reporting

The future UI and exports should present `nginx_config_basic` as a passive static web-edge config review, not a vulnerability scanner.

Recommended sections:

- Summary.
- Files reviewed/skipped.
- Server blocks.
- Locations.
- Upstreams and proxy targets, safely redacted.
- TLS/HTTPS posture.
- Security headers.
- CORS and access control.
- Proxy behavior.
- Includes and unresolved config.
- Findings grouped by severity, category, and context.
- Limits, truncation, parser uncertainty, and controlled errors.
- Redaction notes.
- Raw JSON, defensively redacted.

Reports should clearly state that Inspectra does not run Nginx, run `nginx -t`, start containers, contact servers, resolve DNS, validate certificates, scan ports, query CVEs/advisories, or confirm exploitability.

## 12. Future Tests

Runner tests should cover:

- `server_tokens on` generates `nginx_server_tokens_on`.
- `autoindex on` generates `nginx_autoindex_on`.
- `ssl_protocols TLSv1 TLSv1.1` generates `nginx_ssl_protocol_legacy_enabled`.
- Missing common security headers generate low-confidence findings.
- `add_header Access-Control-Allow-Origin *` with credentials true generates CORS findings.
- `proxy_ssl_verify off` generates `nginx_proxy_ssl_verify_off`.
- `proxy_pass http://user:pass@example.com` generates `nginx_proxy_pass_credentials_hint` with credentials redacted.
- `auth_basic_user_file` paths are shown safely while inline auth-like values are redacted.
- `location /.git`, backup paths, or hidden-file patterns generate sensitive-location findings.
- Public `stub_status` generates `nginx_stub_status_public_hint`.
- `include /etc/nginx/secrets.conf` is detected but not read.
- Full-line comments do not generate strong findings.
- Path traversal, absolute archive names, symlinks, hardlinks, and non-regular entries are not read.
- Limits and truncation are respected.
- Serialized JSON does not contain fixture secrets.

Backend/reporting tests should cover:

- Endpoint accepts only archives.
- Runner call targets `/analyze/nginx-config`.
- Job type is `nginx_config_basic`.
- Summary tolerates sparse, null, and malformed payloads.
- Markdown, HTML, XML, and PDF exports redact legacy secrets.
- Findings with missing optional fields render without breaking.

Frontend tests should cover:

- Action appears only for archives.
- Report renders summary, servers, locations, upstreams, includes, findings, limits, errors, and redaction notes.
- Queued, running, failed, sparse, and malformed payloads do not break.
- Raw JSON is redacted.
- Serialized DOM does not contain fixture secrets.

Suggested fixture secrets:

- `super-secret-password`
- `raw-api-key-123456`
- `token_should_never_render`
- `Authorization: Bearer token_should_never_render`
- `http://user:pass@example.com`
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

## 14. Future Documentation Updates

When runtime is implemented, update:

- `README.md` with the endpoint, UI action, limits, and passive scope.
- `docs/architecture.md` with the backend/runner/storage/reporting/frontend flow.
- `docs/security-scope.md` with allowed Nginx config review scope and explicit out-of-scope behavior.
- A future closeout document such as `docs/future/nginx-config-basic-closeout.md`.

Documentation must continue to state that Inspectra does not run Nginx, start containers, contact servers, resolve DNS, validate certificates, query CVEs/advisories, or confirm exploitability.
