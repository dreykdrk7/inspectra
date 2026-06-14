# Active TLS Basic v0 Functional Closeout

Decision: `ACTIVE_TLS_BASIC_05_FUNCTIONAL_REVIEW_AND_CLOSEOUT_ACCEPTED`

This closeout reviews and freezes `active_tls_basic` v0 after the backend
real-minimal TLS job persistence phase and the frontend product-flow smoke. The
accepted capability remains opt-in, local/private/self-hosted, single-target,
owner-scoped, bounded, and redaction-first.

## Reviewed Commits

- `0a11658 feat(active): persist tls basic handshake jobs`
- `7a1374f feat(active): show tls basic jobs in frontend`

## Approved State

- Backend feature gate remains disabled by default through
  `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED=false`.
- The accepted endpoint is `POST /active/network/tls-basic`.
- Auth-required deployments deny anonymous requests through the sensitive-route
  middleware before request validation details are exposed.
- The backend validates the exact `live_tls_basic` /
  `tls_handshake_summary` contract, one target, one port, and all three
  confirmations.
- Target policy remains single-target and single-port, with the TLS-basic port
  set bounded to `443`, `8443`, and `9443`.
- Python `socket` and `ssl` usage is isolated to
  `backend/app/active_tls_basic.py`.
- Runtime behavior performs at most one bounded TLS handshake attempt.
- Jobs are owner-scoped, use `audit_type: active_tls_basic`, keep
  `file_id: null`, and persist `[REDACTED_TARGET]`.
- Stored and rendered results keep only bounded handshake status,
  protocol/cipher, certificate subject/issuer/SAN count/SAN sample/date
  metadata, controlled reason codes, caveats, and limits.
- Reporting, exports, job detail/list summaries, frontend report rendering, and
  Raw JSON surfaces remain redaction-first.
- Frontend has a separate Active / TLS basic panel, submits the exact contract,
  requires confirmations, selects the returned `202 JobRecord`, refreshes jobs,
  and renders TLS handshake and certificate-expiry review indicators.
- Wording remains "TLS configuration review indicator" / "manual validation
  required" and does not present proof, exploitability, target-safety, or
  complete-coverage statements.

## Not Approved

- No new runtime features.
- No new real target execution in this closeout phase.
- No alternate-port retry behavior.
- No redirects.
- No HTTP request or crawling behavior.
- No DNS expansion or subdomain discovery.
- No OpenSSL command invocation.
- No subprocess execution.
- No Nmap.
- No Docker or Compose runtime behavior.
- No credential, header, cookie, token, mTLS, or client-certificate input.
- No raw target, raw payload, PEM/DER certificate material, full chain, or raw
  exception persistence.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No public scanning service or SaaS-style target intake.
- No release, tag, or push state.

## Boundary Review

Backend:

- `active_tls_basic` is enabled only by explicit feature flag.
- The route calls `current_owner_id_for_request` after the feature gate and
  before contract validation; auth-required anonymous requests are already
  blocked by middleware before route execution.
- The route passes only the validated target and port into
  `ActiveTlsBasicRequest`.
- Controlled errors return bounded reason codes and do not include raw target or
  exception strings.
- Wrong-owner detail, delete, and export requests return generic `Job not
  found.` responses.

TLS runtime:

- The dedicated module creates one TCP connection and wraps it once with the
  default TLS context.
- Timeouts are bounded to the configured maximum of three seconds.
- The implementation does not perform HTTP requests, redirects, retries to
  other ports, crawling, credential checks, shell commands, Docker calls, Nmap
  calls, or target expansion.

Storage and reporting:

- Public result shaping uses `public_active_tls_basic_result`.
- Sensitive value keys include certificate, key, SNI override, credential,
  header/cookie/token, raw exception, and raw target-shaped fields.
- Certificate SAN values are redacted and sampled.
- Report exports include scope, assertion, traffic, authorization, and
  redaction boundaries.

Frontend:

- `ActiveTlsBasicPanel` exposes only target, one bounded TLS port, and the three
  confirmations.
- `ActiveTlsBasicJobReport` renders controlled statuses:
  `handshake_succeeded`, `timed_out`, `handshake_failed`,
  `certificate_unavailable`, `tls_error_controlled`, and `not_executed`.
- `activeTlsBasicReport` applies defensive frontend redaction before Raw JSON
  display.

## Final Validation Set

Required closeout validation:

- `git status --short --branch`;
- `git show --stat --oneline 0a11658`;
- `git show --stat --oneline 7a1374f`;
- `python3 -m py_compile backend/app/active_tls_basic.py backend/app/main.py backend/app/config.py backend/app/storage.py backend/app/reporting.py`;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_tls_basic`;
- `.venv/bin/python -m pytest backend/tests`;
- `npm test -- --run ActiveTlsBasicPanel ActiveTlsBasicJobReport App`;
- `npm test -- --run`;
- `npm run build`;
- `git diff --check`;
- `git diff --cached --check`;
- guardrail searches for source-boundary, redaction, no-scope, and wording
  drift.

## Result

`active_tls_basic` v0 is functionally closed as a bounded self-hosted/local/private
TLS review-indicator capability. The next work should be operational polish or a
separate active tool design, not target expansion, archive/run-all, or broader
scanner-style behavior.
