# Active TLS Basic Backend Contract Gate

Decision: `ACTIVE_TLS_BASIC_02_BACKEND_CONTRACT_GATE_ACCEPTED`

This phase implements the initial backend contract gate for future
`active_tls_basic` without performing any TLS connection. It adds the
disabled-by-default backend flag, the public backend endpoint, exact request
validation, explicit confirmations, bounded single-target/single-port shape,
and a controlled `not_executed` response.

## Implemented Scope

- Backend feature flag: `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED=false` by default.
- Endpoint: `POST /active/network/tls-basic`.
- Exact contract:
  - `mode: live_tls_basic`;
  - `profile: tls_handshake_summary`;
  - one explicit `target` string;
  - one integer `port` from the bounded TLS-basic set;
  - `authorization_confirmed: true`;
  - `local_private_scope_confirmed: true`;
  - `live_traffic_confirmed: true`.
- Target policy remains local/private/self-hosted and rejects URL-shaped values,
  ranges, CIDR, wildcards, pasted lists, target files, metadata/control-plane
  targets, public-looking hostnames, and ambiguous syntax without DNS.
- Enabled valid requests return a controlled response with:
  - `status: not_executed`;
  - `capability: active_tls_basic`;
  - `execution_enabled: false`;
  - `tls_handshake_attempted: false`;
  - `network_requests_sent: 0`;
  - `dns_queries_sent: 0`;
  - `job_created: false`;
  - `storage_persisted: false`;
  - target redacted as `[REDACTED_TARGET]`.

## Security Boundaries

- Disabled mode rejects without creating jobs or attempting execution.
- Auth-required anonymous requests are rejected before contract validation
  details.
- Dangerous extra fields are rejected, including raw flags, headers, cookies,
  tokens, credentials, client certificate fields, SNI override lists, cipher
  brute-force controls, protocol-fuzzing controls, and HTTP/crawling fields.
- Error responses do not reflect raw target values or payload secrets.
- The response remains review-indicator wording with manual validation required.

## No-Scope

This phase does not add:

- TLS connections;
- sockets;
- Python `ssl` connections;
- OpenSSL commands;
- shell commands;
- Nmap;
- Docker;
- DNS checks;
- HTTP requests;
- crawling;
- credential validation;
- target expansion;
- persistent jobs;
- storage;
- frontend runtime;
- reports or exports;
- archive/run-all;
- `tools/runner/main.py`;
- migrations;
- release, tag, or push state.

## Validation

Expected validation for this phase:

- `python -m py_compile backend/app/config.py backend/app/main.py`;
- focused backend tests for `active_tls_basic`;
- focused Active backend tests for nearby Active gates;
- full backend suite because `backend/app/main.py` changed;
- `git diff --check`;
- `git diff --cached --check`;
- guardrail searches for TLS/socket/OpenSSL/subprocess/Nmap/Docker/DNS/HTTP/
  frontend/archive-runner boundaries and unsafe wording.

## Final Decision

```text
ACTIVE_TLS_BASIC_02_BACKEND_CONTRACT_GATE_ACCEPTED
```

The backend contract gate exists and is disabled by default. It validates the
future `active_tls_basic` request shape and returns only a controlled
`not_executed` response; it performs no TLS, network, storage, frontend, export,
archive/run-all, or runner behavior.
