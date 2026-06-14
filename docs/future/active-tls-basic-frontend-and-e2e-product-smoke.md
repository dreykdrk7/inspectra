# Active TLS Basic Frontend And E2E Product Smoke

Decision: `ACTIVE_TLS_BASIC_04_FRONTEND_AND_E2E_PRODUCT_SMOKE_PASSED`

This microphase connects the existing frontend to the accepted
`active_tls_basic` backend contract and validates the product flow with mocks
and controlled fixtures only. It does not add new TLS runtime behavior outside
the already accepted backend module, does not execute new real targets, and
does not add OpenSSL, subprocess, Nmap, Docker, HTTP crawling, archive/run-all,
or `tools/runner/main.py` integration.

## Accepted Product Flow

- The frontend exposes a separate **Active / TLS basic** panel.
- The panel sends the exact backend contract:
  - `mode: live_tls_basic`;
  - `profile: tls_handshake_summary`;
  - one explicit `target`;
  - one bounded `port`;
  - `authorization_confirmed: true`;
  - `local_private_scope_confirmed: true`;
  - `live_traffic_confirmed: true`.
- The backend response is expected as a `202 JobRecord`.
- The returned job is selected immediately and the job list is refreshed.
- The job detail renders as a TLS handshake review indicator and certificate
  expiry review indicator with manual validation required.
- Raw JSON rendering remains redaction-first.

## Frontend Boundaries

- Target display is redacted as `[REDACTED_TARGET]`.
- Raw certificate PEM/DER values are redacted before browser Raw JSON display.
- Raw exception text is redacted before browser Raw JSON display.
- Credentials, headers, cookies, tokens, client certificates, and payload-like
  fields are redacted defensively if legacy or malformed payloads appear.
- Controlled states such as `timed_out`, `handshake_failed`,
  `certificate_unavailable`, and `tls_error_controlled` render as controlled
  review states, not as security findings.
- The UI does not expose crawler inputs, custom headers, cookies, tokens,
  credentials, client certificates, raw flags, protocol fuzzing, or archive
  run-all actions.

## Smoke Coverage

The smoke is implemented with local test doubles and frontend/backend test
fixtures:

- frontend submit sends the exact contract to
  `POST /active/network/tls-basic`;
- the mocked backend returns a `202 active_tls_basic` `JobRecord`;
- the UI selects the returned job and refreshes the list;
- list summaries include `active_tls_basic` catalog metadata;
- detail/report rendering shows bounded protocol, cipher, certificate summary,
  expiry metadata, controlled errors, and redacted Raw JSON;
- frontend defensive redaction strips raw target, PEM/DER, raw exception,
  credential, header, cookie, and token-shaped content;
- backend focused `active_tls_basic` coverage continues to validate
  owner-scoped job creation, detail/list/Raw JSON/export redaction, and
  wrong-owner generic-not-found behavior.

## Not Approved

- No new real target execution in this phase.
- No OpenSSL command.
- No subprocess.
- No Nmap.
- No Docker or Compose runtime smoke.
- No HTTP request or crawler behavior.
- No credential, header, cookie, token, or client-certificate input.
- No frontend archive/run-all integration.
- No `tools/runner/main.py` integration.
- No release, tag, or push state.

## Result

Active / TLS basic v0 is now visible in the frontend as a bounded
local/private/self-hosted review-indicator workflow. The product flow can create
and display owner-scoped redacted `active_tls_basic` jobs without presenting the
result as a confirmed security finding or complete coverage statement.
