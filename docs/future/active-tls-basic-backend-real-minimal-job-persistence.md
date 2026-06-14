# Active TLS Basic Backend Real-Minimal Job Persistence

Decision: `ACTIVE_TLS_BASIC_03_BACKEND_REAL_MINIMAL_TLS_JOB_PERSISTENCE_PASSED`

This microphase turns the accepted `active_tls_basic` backend contract into a
bounded, owner-scoped job-producing path. It remains disabled by default and is
available only when `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED=true`.

## Accepted Behavior

- `POST /active/network/tls-basic` keeps the exact
  `live_tls_basic` / `tls_handshake_summary` request contract.
- The backend resolves auth/owner before request validation details in
  auth-required modes.
- A job is created only after the feature flag is enabled, the exact contract
  passes, target policy accepts the single explicit target, the single bounded
  port is accepted, and all confirmations are true.
- The resulting `JobRecord` is owner-scoped, uses
  `audit_type: active_tls_basic`, `file_id: null`, and stores
  `target_url: [REDACTED_TARGET]`.
- TLS execution is exactly one bounded handshake attempt against the already
  validated target/port.
- Python `socket` and `ssl` usage is confined to
  `backend/app/active_tls_basic.py`.
- Successful results store only bounded protocol/cipher and certificate summary
  fields: subject, issuer, SAN count, small redacted SAN sample, not-before,
  not-after, and days-until-expiry.
- Controlled errors store only allowlisted statuses and reason codes:
  `handshake_succeeded`, `handshake_failed`, `timed_out`,
  `certificate_unavailable`, and `tls_error_controlled`.
- Reports, job detail, list summaries, Raw JSON, and exports keep manual
  validation and TLS configuration review-indicator wording.

## Guardrails

- No OpenSSL command.
- No shell command.
- No subprocess.
- No Nmap.
- No Docker runtime.
- No HTTP request.
- No crawling.
- No credential validation.
- No brute force.
- No cipher or protocol fuzzing.
- No SNI override list.
- No mTLS or client certificates.
- No DNS expansion or subdomain discovery.
- No target expansion, redirects, alternate ports, ranges, CIDR, wildcards, or
  target files.
- No frontend runtime change.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No release, tag, or push state.

## Redaction

Persisted and public surfaces must not include raw target, raw request payload,
raw certificate PEM/DER, private keys, full chain dumps, command lines,
stdout/stderr, raw exception text containing host/IP values, credentials,
headers, cookies, tokens, HTTP content, or unbounded SANs.

Public surfaces preserve:

- `target: [REDACTED_TARGET]`;
- bounded handshake status, protocol, and cipher;
- bounded/redacted certificate summary;
- controlled reason codes;
- `manual_validation_required: true`;
- `result_interpretation: tls_configuration_review_indicator`.

## Validation Notes

The backend tests use an injected fake TLS connector for all successful and
controlled-error cases, so test execution does not perform real network
activity. Source guardrails confirm `socket`/`ssl` appear only in the dedicated
TLS module and tests, while route/storage/reporting remain free of TLS runtime
APIs, subprocess, OpenSSL, Nmap, Docker, HTTP/crawling, frontend, archive, and
runner integration.

## Not Approved

This is not a public scanner, SaaS scanner, complete certificate inventory,
target safety assertion, exploitability check, credential check, crawler, or
coverage claim. `JobStatus.completed` means only that the bounded TLS review
indicator result was produced and stored; it does not mean the target is secure
or that no issue exists.
