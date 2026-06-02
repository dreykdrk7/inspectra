# Active Network Block 04 Dry-Run Skeleton No-Network

Status: `ACTIVE_DRY_RUN_SKELETON_IMPLEMENTED_NO_NETWORK`.

Base contract: `docs/future/active-network-block-03-dry-run-contracts-design.md`

Commit scope: separated Active runner skeleton only.

This document records the first Active/Network runtime skeleton. It does not integrate backend, create public endpoints, touch frontend, modify `tools/runner/main.py`, run network checks, resolve DNS, perform HTTP requests, run Nmap, create tags, create releases, or mutate the Passive Alpha.

## A. Implemented Files

Created a separate Active package:

```text
tools/active_runner/
  __init__.py
  audit_log.py
  dry_run.py
  models.py
  safety.py
```

Created focused tests:

```text
tools/tests/test_active_runner.py
```

The passive runner remains separate:

```text
tools/runner/main.py
```

That file was not modified.

## B. Implemented Contract

Implemented pure function:

```python
run_active_network_dry_run(request: ActiveDryRunRequest) -> ActiveDryRunResult
```

The function returns a JSON-serializable dict with:

- `analyzer: active_network_dry_run`
- `mode: dry_run`
- `profile`
- `target`
- `authorization`
- `policy`
- `limits`
- `planned_checks`
- `blocked_reasons`
- `findings`
- `audit_log`
- `errors`
- `summary.network_requests_sent: 0`

Allowed dry-run profile:

```text
http_header_probe_preview
```

Nmap-like profiles are blocked with:

```text
nmap_not_allowed
```

## C. No-Network Guarantee

The skeleton performs no network activity:

- No DNS resolution.
- No HTTP requests.
- No redirects.
- No subprocess execution.
- No Nmap runtime.
- No live probes.
- No live data.
- No response headers.
- No HTTP status codes.

The implementation uses syntactic parsing only and keeps:

```text
network_requests_sent = 0
```

Planned checks are preview records only:

- `would_contact_target: false`
- `network_disabled: true`
- `reason: dry_run`

## D. Target Handling

Supported syntactic target inputs:

- explicit `http`/`https` URLs;
- hostnames/domains;
- single IP addresses.

The skeleton does not resolve hostnames. Hostname classification is syntactic only.

Sensitive query values are redacted before result/audit-log exposure. URL userinfo is rejected and not preserved as raw credentials.

## E. Rejected Target Coverage

Implemented blocked reason coverage includes:

- `authorization_missing`
- `unsupported_scheme`
- `url_credentials_rejected`
- `target_parse_failed`
- `target_cidr_rejected`
- `target_range_rejected`
- `wildcard_rejected`
- `private_range_blocked`
- `loopback_requires_local_lab`
- `metadata_target_blocked`
- `link_local_blocked`
- `multicast_blocked`
- `broadcast_blocked`
- `unspecified_address_blocked`
- `suspicious_target_input`
- `unknown_profile`
- `live_mode_not_available`
- `limits_exceed_dry_run`
- `nmap_not_allowed`

Local-lab mode remains unimplemented. Loopback and private/internal targets remain blocked by default.

## F. Authorization And Limits

Dry-run requires explicit authorization:

```text
I confirm I own or am authorized to test this target.
```

Initial dry-run limits must remain zero:

- `max_requests = 0`
- `timeout_seconds = 0`
- `max_redirects = 0`
- `response_size_bytes = 0`

Nonzero limits are blocked with:

```text
limits_exceed_dry_run
```

Live mode is blocked with:

```text
live_mode_not_available
```

## G. Audit Log

The skeleton produces audit events:

- `active_request_received`
- `authorization_checked`
- `target_normalized` or `target_rejected`
- `policy_evaluated`
- `dry_run_planned` or `dry_run_blocked`

Audit log details are intentionally minimal and must not include:

- URL credentials;
- sensitive query values;
- tokens;
- headers;
- request bodies;
- private key material.

## H. Tests

Added tests cover:

- valid URL dry-run allowed;
- valid hostname dry-run allowed;
- authorization missing blocked;
- live mode rejected;
- unknown profile rejected;
- limits above zero rejected;
- URL credentials rejected and not leaked;
- sensitive query values redacted;
- private IP blocked;
- loopback blocked without local-lab;
- metadata IP blocked;
- CIDR blocked;
- wildcard blocked;
- shell-like input blocked;
- `network_requests_sent` is zero;
- planned checks do not contact targets;
- audit log event coverage;
- audit log redaction;
- Nmap profile blocked;
- safe blocked-reason copy;
- serialized results do not contain fixture secrets;
- unknown request fields rejected by the mapping constructor.

Reference command:

```bash
.venv/bin/python -m pytest tools/tests/test_active_runner.py
```

## I. Safety Grep

The required safety grep is:

```bash
rg "requests|httpx|aiohttp|socket|subprocess|nmap|dns" tools/active_runner tools/tests/test_active_runner.py
```

Expected interpretation:

- Contract fields such as `max_requests` and `network_requests_sent` are expected matches.
- Blocked reason names such as `nmap_not_allowed` are expected matches.
- Test names that assert no DNS/Nmap behavior are expected matches.
- No import or runtime use of HTTP clients, DNS resolvers, sockets, subprocess, or Nmap should appear.

## J. Limitations

This skeleton is intentionally not integrated:

- No backend endpoint.
- No backend job creation.
- No storage/reporting integration.
- No frontend action.
- No public API.
- No active runner service.
- No local-lab mode.
- No live probe.
- No Nmap.

The skeleton exists to validate contracts and safety posture before backend integration is designed.

## K. Next Recommended Microphase

Recommended next step at the time this skeleton was created:

```text
ACTIVE-NETWORK-BLOCK-05-DRY-RUN-BACKEND-CONTRACT-DESIGN
```

Rationale:

- Keep backend integration docs-first before adding routes/jobs.
- Decide endpoint shape, job metadata, storage shape, reporting sections, and API copy before code.
- Preserve the no-network guarantee while designing integration.

Alternative, if implementation is preferred after a contract pass:

```text
ACTIVE-NETWORK-BLOCK-05-DRY-RUN-BACKEND-INTEGRATION
```

The safer path is backend contract design first.

That backend contract design is now documented in:

```text
docs/future/active-network-block-05-dry-run-backend-contract-design.md
```

Decision:

```text
ACTIVE_DRY_RUN_BACKEND_CONTRACT_DESIGNED_NO_RUNTIME_INTEGRATION
```

## L. Decision Field

Final decision:

```text
ACTIVE_DRY_RUN_SKELETON_IMPLEMENTED_NO_NETWORK
```
