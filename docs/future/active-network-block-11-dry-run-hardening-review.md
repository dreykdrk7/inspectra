# Active Network Block 11 Dry-Run Hardening Review

Status: `ACTIVE_DRY_RUN_HARDENING_ACCEPTED_FOR_LIVE_PROBE_DESIGN`.

Base closeout: `docs/future/active-network-block-10-dry-run-closeout.md`

Review scope: docs-first hardening review of `active_network_dry_run` v0 before opening any live-probe design.

## 1. Current State

`active_network_dry_run` v0 is closed as a no-network planning capability.

Current guarantees:

- no DNS resolution;
- no HTTP requests;
- no sockets;
- no subprocess probes;
- no Nmap;
- no live probes;
- no local-lab mode;
- `network_requests_sent: 0`;
- backend endpoint disabled by default through `INSPECTRA_ACTIVE_DRY_RUN_ENABLED=false`;
- frontend form, reporting, exports, and Redacted Raw JSON are integrated;
- Passive Alpha and passive analyzers are out of scope for this line of work.

The current capability is not an Active scanner, not a live validator, not a proof-of-ownership system, and not a target reachability check.

## 2. Surfaces Reviewed

- `tools/active_runner/`
- `run_active_network_dry_run`
- target normalization and safety policy
- backend endpoint `POST /active/network/dry-run`
- feature flag `INSPECTRA_ACTIVE_DRY_RUN_ENABLED`
- job creation, storage, and completion path
- `GET /jobs` summaries
- `GET /jobs/{job_id}` result payloads
- Markdown, HTML, XML, and PDF exports
- frontend `Active / Network dry-run` form
- frontend `ActiveDryRunJobReport`
- frontend report/Raw JSON redaction
- active runner, backend, and frontend tests related to dry-run/no-network behavior

## 3. Hardening Checklist

Classification key:

- `PASS`: sufficient for moving to docs-first live-probe design.
- `NEEDS WORK BEFORE LIVE PROBE`: required before implementing or enabling live runtime.
- `BACKLOG`: useful hardening, not blocking live-probe design.
- `NOT APPLICABLE`: not relevant to dry-run v0.

### Feature Flag / Enablement

| Check | Status | Notes |
| --- | --- | --- |
| Default false | PASS | `DEFAULT_ACTIVE_DRY_RUN_ENABLED = False`. |
| Disabled state safe | PASS | Disabled endpoint returns `403` with controlled copy. |
| No job creation when disabled | PASS | The feature flag is checked before request parsing/job creation. |
| No target processing claims when disabled | PASS | Disabled state does not claim target validation or execution. |

### Authorization

| Check | Status | Notes |
| --- | --- | --- |
| Checkbox required | PASS | Frontend disables submit until confirmation is checked. |
| Statement fixed | PASS | Runner requires `I confirm I own or am authorized to test this target.` |
| Target alone is not authorization | PASS | Missing/altered authorization blocks policy. |
| Authorization stored safely | PASS | Result stores `confirmed`, `statement_version`, and `scope`, not a secret-bearing proof. |
| No proof-of-ownership claim | PASS | Current copy treats authorization as user assertion. |
| Stronger authorization artifact | NEEDS WORK BEFORE LIVE PROBE | Live runtime should design explicit audit logging and possibly stronger authorization metadata before sending traffic. |

### Target Safety

| Check | Status | Notes |
| --- | --- | --- |
| URL credentials rejected/redacted | PASS | Userinfo targets are blocked and redacted. |
| Private targets blocked | PASS | Private IPs are blocked in dry-run. |
| Loopback blocked without local-lab | PASS | Local-lab mode is not implemented. |
| Metadata targets blocked | PASS | Metadata IP/host targets are blocked. |
| CIDR/ranges blocked | PASS | CIDR and range-like inputs are rejected. |
| Wildcard blocked | PASS | Wildcard targets are rejected. |
| Suspicious input blocked | PASS | Shell-like fragments, Authorization headers, and private key blocks are rejected/redacted. |
| No DNS in dry-run | PASS | Hostnames are normalized syntactically only. |
| Live allowlist/port policy | NEEDS WORK BEFORE LIVE PROBE | Any live HTTP probe must define allowed schemes, ports, redirects, private/local-lab behavior, and target revalidation before traffic. |

### Limits

| Check | Status | Notes |
| --- | --- | --- |
| `max_requests = 0` | PASS | Frontend sends zero; runner blocks nonzero. |
| `timeout_seconds = 0` | PASS | Frontend sends zero; runner blocks nonzero. |
| `max_redirects = 0` | PASS | Frontend sends zero; runner blocks nonzero. |
| `response_size_bytes = 0` | PASS | Frontend sends zero; runner blocks nonzero. |
| Nonzero limits blocked | PASS | Runner emits `limits_exceed_dry_run`. |
| Live limits model | NEEDS WORK BEFORE LIVE PROBE | Live design must define nonzero caps, deadlines, redirect handling, response byte limits, and failure behavior. |

### No-Network

| Check | Status | Notes |
| --- | --- | --- |
| No DNS | PASS | No resolver call exists in `tools/active_runner/`. |
| No HTTP | PASS | Dry-run creates preview records only. |
| No sockets | PASS | Source-level test rejects socket imports in `tools/active_runner/`. |
| No subprocess | PASS | Source-level test rejects subprocess imports in `tools/active_runner/`. |
| No Nmap | PASS | Nmap-like profiles are blocked; no Nmap runtime exists. |
| No calls to `tools/runner/main.py` | PASS | Active runner is separate; source-level test rejects imports. |
| `network_requests_sent = 0` | PASS | Runner result summary is fixed at zero. |

### Redaction

| Check | Status | Notes |
| --- | --- | --- |
| URL userinfo | PASS | Runner/backend/frontend redact userinfo. |
| Sensitive query params | PASS | Sensitive query values are redacted. |
| Authorization/Bearer/Basic | PASS | Runner/backend/frontend redact Authorization-like values. |
| Tokens/password/API keys/client secrets | PASS | Secret-like assignment and mapping-key redaction exists. |
| Private key blocks | PASS | Private key blocks and `PRIVATE KEY` text are redacted. |
| Legacy payloads | PASS | Backend/API/export/frontend tests cover malformed/legacy secret-bearing payloads. |
| Exports | PASS | Markdown, HTML, XML, and PDF export redaction is covered. |
| Frontend DOM | PASS | Job table, report, and errors are redacted. |
| Raw JSON | PASS | Frontend Raw JSON is rendered as redacted payload. |
| Central redaction parity for future live payloads | NEEDS WORK BEFORE LIVE PROBE | Live payload fields should be designed with redaction tests before runtime implementation. |

### Reporting / UX

| Check | Status | Notes |
| --- | --- | --- |
| No `scan` action wording | PASS | UI uses dry-run, plan, preview, and no-network copy. |
| No `Nmap` action wording | PASS | Nmap appears only as blocked/out-of-scope language. |
| No exploitability claims | PASS | Reports describe policy and planned checks. |
| No credential-valid claims | PASS | No validation of credentials is implied. |
| No target-safe claims | PASS | Dry-run does not claim target safety or reachability. |
| Blocked reasons safe | PASS | Blocked copy is controlled and avoids bypass guidance. |
| Disabled state safe | PASS | Disabled state gives controlled administrator-facing guidance. |
| Raw JSON redacted | PASS | Redacted Raw JSON is explicit in the report. |
| Live UI separation | NEEDS WORK BEFORE LIVE PROBE | Any future live control should be visually and semantically separate from dry-run and passive archive actions. |

### Audit / Logging

| Check | Status | Notes |
| --- | --- | --- |
| Audit events present | PASS | Runner emits request received, authorization checked, target normalized/rejected, policy evaluated, and planned/blocked events. |
| No secrets in audit log | PASS | Existing tests cover secret-bearing legacy/raw values and runner serialization. |
| Policy version present | PASS | `active-network-v0-dry-run`. |
| Blocked reasons present | PASS | Policy and top-level blocked reasons include reason codes/messages. |
| Failure states controlled | PASS | Backend catches runner exceptions and stores redacted controlled errors. |
| Live audit log schema | NEEDS WORK BEFORE LIVE PROBE | Live design should add request counters, redirect decisions, timeout/error codes, and safety-policy events before runtime. |

## 4. Findings

### Release-Blocking Before Live Probe Design

None found.

### Must-Fix Before Live Runtime

- Design a live authorization/audit record that remains a user assertion but captures enough metadata for accountable local use without storing secrets.
- Define live target policy, allowed ports, redirect revalidation, private/local-lab behavior, and fail-closed behavior before any traffic is sent.
- Define nonzero live limits and deadlines before any traffic is sent.
- Define live payload redaction tests before any runtime implementation.
- Keep live UI/actions separate from dry-run and passive archive actions.
- Extend audit logs for live-specific decisions before enabling live runtime.

### Should-Fix Before Broader Alpha

- Add an operator-facing checklist for enabling `INSPECTRA_ACTIVE_DRY_RUN_ENABLED=true` in trusted local demos without implying production readiness.
- Keep safety grep/AST import checks as regression tests for dry-run packages while live code is designed separately.

### Backlog

- Consider a read-only local-lab mode only through a separate docs-first design.
- Consider richer policy versions once live probes exist.
- Consider clearer product copy explaining that user authorization is not proof of ownership.

## 5. Recommendation

Decision:

```text
ACTIVE_DRY_RUN_HARDENING_ACCEPTED_FOR_LIVE_PROBE_DESIGN
```

The dry-run v0 surface is sufficiently hardened to proceed to docs-first design for the first authorized live probe. This does not approve implementation or enablement of live traffic. It only clears the next design step.

## 6. Next Step

Recommended next microphase:

```text
ACTIVE-NETWORK-BLOCK-12-AUTHORIZED-HTTP-HEADER-PROBE-DESIGN-DOCS-FIRST
```

Design record:

```text
docs/future/active-network-block-12-authorized-http-header-probe-design.md
```

If the product chooses to fix hardening items before design instead, use:

```text
ACTIVE-NETWORK-BLOCK-12-DRY-RUN-HARDENING-FIXES
```

## 7. No-Scope

- No code.
- No live probes.
- No HTTP requests.
- No DNS.
- No sockets.
- No subprocess probes.
- No Nmap.
- No Passive refactor.
- No changes to `tools/runner/main.py`.
- No frontend feature changes.
- No backend endpoint changes.
- No push.
- No `.env` reads.

## Validation Commands

Closeout validation for this docs-first review:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
```

No pytest/npm suite is required unless code changes.
