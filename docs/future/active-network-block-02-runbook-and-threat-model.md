# Active Network Block 02 Runbook And Threat Model

Status: `ACTIVE_RUNBOOK_THREAT_MODEL_FROZEN_NO_RUNTIME`.

Passive release: `https://github.com/dreykdrk7/inspectra/releases/tag/v0.1.0-passive-alpha`

Passive tag: `v0.1.0-passive-alpha`

Scope source: `docs/future/active-network-block-01-docs-first-scope.md`

This document defines the first runbook and threat model for a future Active/Network product block. It does not implement Active runtime, create an active runner, create endpoints, modify backend/runner/frontend code, run network checks, run Nmap, create tags, create releases, or mutate the Passive Alpha.

## A. Starting State

Active scope is already frozen at docs-first level:

```text
ACTIVE_NETWORK_SCOPE_FROZEN_DOCS_FIRST_NO_RUNTIME
```

Current constraints:

- No Active runtime.
- No active runner.
- No Active endpoints.
- No Nmap runtime.
- No network traffic from this block.
- No backend/frontend/runner changes.
- Passive Alpha remains stable and unchanged.
- Active must use a separate modular runner design if runtime is ever implemented.

This document does not enable traffic. It defines threats, abuse cases, controls, logging, failure states, and incident handling before dry-run contracts are designed.

## B. Objective

The runbook and threat model exist to:

- prevent misuse;
- define operational limits;
- identify abuse cases before runtime exists;
- define non-negotiable controls;
- prepare a future dry-run implementation;
- protect users, targets, and Inspectra's product posture;
- ensure Active does not change the Passive Alpha promise.

The immediate next implementation-oriented phase should still be dry-run contract design, not live probes.

## C. Assets And Surfaces To Protect

Assets and surfaces:

- Users and operators.
- Third-party systems that must not be contacted without authorization.
- User-owned infrastructure and local lab targets.
- The local machine running Inspectra.
- Future active runner boundaries.
- Backend job and storage boundaries.
- Frontend authorization and target-summary UX.
- Audit log records.
- Uploaded files and stored passive results.
- Report/export outputs.
- Sensitive target strings, query parameters, credentials, or internal hostnames.
- Inspectra's Passive Alpha release and product reputation.
- The distinction between Passive and Active capabilities.

The most important safety property is that ambiguous or unauthorized targets are blocked before any network boundary is crossed.

## D. Trust Boundaries

Trust boundaries:

- User input boundary: raw targets, authorization text, mode, and limits are untrusted.
- Target normalization boundary: raw targets become normalized target objects or blocked-target records.
- Authorization confirmation boundary: typed targets are not authorization; explicit confirmation is required.
- Backend job boundary: jobs must carry mode, limits, target policy version, and authorization metadata.
- Future active runner boundary: Active execution must be separated from the passive runner monolith.
- Audit log boundary: audit logs must preserve safety decisions without storing secrets.
- Network boundary: not crossed in dry-run; crossed only after later approved runtime phases.
- Report/export boundary: reports must avoid bypass guidance and redact sensitive target values.

Every boundary should fail closed.

## E. Abuse Cases

Potential abuse cases:

- A user attempts to scan a third-party domain without authorization.
- A user enters broad ranges such as CIDR blocks or IP ranges.
- A user enters cloud metadata, link-local, multicast, broadcast, unspecified, or private/internal targets.
- A user enters a URL with credentials or sensitive query parameters.
- A user enters shell-like input, command separators, or payload-like strings as a target.
- A user tries to use Active as fuzzing, brute force, credential stuffing, or stress tooling.
- A user tries to use Inspectra as a proxy for scanning from a different network location.
- A user splits work into many requests to bypass rate limits.
- A user hides the real target behind redirects, DNS changes, CNAMEs, IDNA/punycode confusion, or URL parsing ambiguity.
- A user enables local-lab mode to reach internal networks they are not authorized to test.
- A user interprets heuristic findings as confirmed vulnerabilities or proof of exploitability.
- A user uploads real data expecting Inspectra to sanitize originals.
- Audit logs store sensitive target strings, tokens, or internal hostnames.
- Exports leak sensitive target strings, credentials, or query parameters.
- Future Nmap flags are too broad, stealthy, evasive, or intrusive.
- SSRF-like misuse causes backend or future runner to contact blocked targets.
- A misconfigured check sends too many requests and causes unintended load.
- Missing findings create false confidence that a target is safe.

## F. Threat Model Table

| Threat | Actor | Scenario | Impact | Likelihood | Controls | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Unauthorized third-party scan | User | User enters a public domain they do not own. | Legal risk, abuse reports, target harm. | Medium | Authorization confirmation, target summary, audit logs, clear copy. | Must be controlled before runtime. |
| Broad range scanning | User | User enters CIDR, IP range, wildcard, or many targets. | Wide scan behavior, abuse potential. | Medium | No broad ranges, max targets, fail closed. | Rejected in v0. |
| Metadata or internal target contact | User or mistake | Target resolves to metadata, link-local, private, multicast, or reserved address. | SSRF-like impact, internal exposure. | Medium | Blocked target classes, DNS/address validation, local-lab gate. | Must be blocked by policy. |
| URL credential leakage | User | URL includes userinfo or sensitive query values. | Secret exposure in logs/results. | Medium | Reject URL userinfo, redact sensitive query params, no secrets in audit logs. | Required. |
| Payload-like target input | User | Target contains shell syntax, command separators, or scanner flags. | Injection confusion, unsafe execution later. | Low | Target parser rejects shell-like input; no shell execution. | Required. |
| Active used as scanning proxy | User | User triggers checks from Inspectra's network location. | Product abuse, IP reputation issues. | Medium | Authorization, audit logs, rate limits, target policy, active disabled by default. | Must be addressed. |
| Rate limit evasion | User | User splits many checks across requests. | Unintended load, noisy scans. | Medium | Per-request and global limits, audit logs, future user/session limits. | Design required. |
| Redirect or DNS target switch | User or target | Initial allowed URL redirects or resolves to blocked target. | Blocked target contact. | Medium | No redirects or limited redirects; validate every redirect and resolved address. | Required before live probes. |
| Local-lab overreach | User | Local-lab mode reaches wider RFC1918 networks. | Unauthorized internal scanning. | Medium | Local-lab not implemented yet; loopback-first design; explicit log field. | Deferred with strict gate. |
| Findings overclaimed | User or product copy | User treats indicators as confirmed vulnerabilities. | Miscommunication, bad decisions. | Medium | Copy rules, report disclaimers, no confirmation wording. | Required. |
| Sensitive audit logs | Product | Logs contain tokens, credentials, internal target data. | Privacy/security exposure. | Medium | Redaction, minimal logging, no secrets in audit log. | Required. |
| Export leakage | Product | Reports/exports expose credential URLs or tokens. | Secret disclosure. | Medium | Defensive redaction in report/export and raw JSON. | Required. |
| Nmap misuse | Future implementer/user | Broad or intrusive Nmap flags are allowed. | Active scanning abuse, target harm. | Medium | No Nmap runtime in v0; docs-first Nmap design; allowlisted profiles only later. | Deferred/rejected now. |
| Unintended DoS | Product or user | Too many requests, long timeouts, or large responses. | Target load, user-machine load. | Low/Medium | Rate limits, timeouts, response size caps, global deadlines. | Required before live probes. |
| False sense of safety | User | No findings are interpreted as "safe." | Misplaced confidence. | Medium | Findings are indicators; "no findings" copy requires manual review. | Required. |

## G. Required Controls Before Any Runtime

Non-negotiable controls before any Active runtime exists:

- Active disabled by default.
- Explicit environment/config enable flag.
- Explicit authorization checkbox or API field.
- Visible normalized target preview.
- Rejected target policy.
- Local-lab mode decision.
- Dry-run mode.
- Request/job audit log.
- Rate limits.
- Timeouts and global deadline.
- Target count limit.
- No redirects or very limited redirects.
- Validate every redirect target if redirects are later allowed.
- Response size cap.
- Controlled error taxonomy.
- Redaction for URLs with credentials and sensitive query parameters.
- Tests for blocked targets.
- `docs/security-scope.md` updated before runtime.
- UI/API copy approved before runtime.

If any required control is missing, runtime remains blocked.

## H. Rejected Target Classes

Targets to reject in v0:

- CIDR ranges.
- IP ranges.
- Wildcards.
- `localhost` and loopback unless explicit local-lab mode exists.
- RFC1918/private ranges by default.
- Link-local addresses.
- Cloud metadata IPs and hostnames.
- Multicast addresses.
- Broadcast addresses.
- Unspecified addresses.
- IPv6 special ranges, including link-local, multicast, unspecified, and documentation/reserved ranges unless explicitly allowed by policy.
- Non-HTTP schemes for HTTP probes.
- `file:` URLs.
- URLs with userinfo.
- Shell-like input.
- Payload-like input.
- Overlong hostnames.
- Invalid IDNA/punycode when not safely normalized.
- Redirects to blocked targets.
- Targets without explicit authorization confirmation.

Rejected target errors should be clear but must not teach bypasses.

## I. Local-Lab Mode

Provisional decision:

- Local-lab mode does not exist yet.
- If designed later, it must be explicit.
- It should allow only loopback/local fixtures at first.
- It must not open all RFC1918/private networks by default.
- It must be visible in UI/API request summaries.
- It must be recorded in audit logs.
- It must have clear copy explaining that it is for owned/trusted lab targets only.

Local-lab mode should be a constrained exception, not a broad private-network scanning switch.

## J. Audit Log Requirements

Future audit log records should include:

- request id;
- timestamp;
- user/session if authentication exists;
- raw target with credentials/query secrets redacted;
- normalized target;
- target type;
- authorization confirmed;
- authorization text/version;
- mode: dry-run or live;
- local-lab mode flag if applicable;
- target policy version;
- limits selected;
- blocked target reason;
- planned checks;
- runner/probe family;
- controlled errors;
- result summary.

Audit logs must not store:

- passwords;
- tokens;
- API keys;
- URL userinfo;
- sensitive query parameter values;
- credential-bearing headers;
- exploit payloads;
- raw request/response bodies in v0.

Audit log redaction must happen before storage.

## K. Failure States

Failure states should be structured, reportable, and logged:

| Failure state | User-facing copy | Audit log | Report status |
| --- | --- | --- | --- |
| Target rejected | This target is blocked by the active safety policy. | Include normalized target if safe and blocked reason. | `blocked` |
| Authorization missing | Active checks require explicit confirmation that you own or are authorized to test the target. | Record missing authorization. | `blocked` |
| Active disabled | Active checks are disabled in this environment. | Record disabled-by-policy. | `blocked` |
| Dry-run only | No network traffic was sent. This dry run records the checks that would be planned after authorization and target validation. | Record dry-run mode and planned checks. | `dry_run` |
| Local-lab required | This target requires explicit local-lab mode, which is not enabled. | Record local-lab-required reason. | `blocked` |
| Timeout | The active check reached its configured timeout. | Record timeout and limit profile. | `partial` or `failed_controlled` |
| Rate limit exceeded | The active check was stopped by configured rate limits. | Record rate-limit reason. | `partial` or `blocked` |
| Redirect blocked | A redirect target was blocked by the active safety policy. | Record safe redirect summary and blocked reason. | `blocked` |
| Response too large | The response exceeded the configured size limit. | Record size limit and truncation. | `partial` |
| Unsupported target type | This target type is not supported for active checks. | Record target type. | `blocked` |
| Network disabled by policy | Network access is disabled for this active mode. | Record network-disabled policy. | `blocked` |
| Nmap not allowed | Nmap runtime is not enabled for this phase. | Record nmap-not-allowed. | `blocked` |
| Internal controlled error | The active check stopped due to a controlled internal error. | Record error code, not secrets. | `failed_controlled` |

Error copy must not include bypass instructions.

## L. Error And Copy Guidelines

Approved examples:

```text
This target is blocked by the active safety policy.
```

```text
Active checks require explicit confirmation that you own or are authorized to test the target.
```

```text
Active checks are disabled in this environment.
```

```text
No network traffic was sent. This dry run records the checks that would be planned after authorization and target validation.
```

```text
This result is an indicator for review, not proof of exploitability or compromise.
```

Avoid wording such as:

- bypass;
- try another encoding;
- use a proxy;
- scan anyway;
- vulnerability confirmed;
- target is safe;
- credential valid;
- exploit available;
- stealth;
- evade.

User-facing copy should explain policy outcomes without teaching how to route around them.

## M. Incident Handling

If an active check contacts an unexpected target:

1. Stop the active runner or disable Active immediately.
2. Preserve audit logs.
3. Record request id, normalized target, policy version, mode, limits, and timestamps.
4. Disable the active environment flag.
5. Create a blocker document.
6. Do not delete evidence prematurely.
7. Do not continue active tests until reviewed.

If rate limits fail:

1. Disable Active.
2. Preserve logs and result records.
3. Record the configured limits and observed request behavior.
4. Mark runtime as blocked until limits are fixed and retested.

If logs include sensitive targets or secrets:

1. Stop Active.
2. Preserve enough metadata to investigate without spreading the secret.
3. Document the exposure.
4. Add or fix redaction tests.
5. Rotate any real credential if one was involved.

If a user reports an unauthorized scan:

1. Preserve audit logs.
2. Identify request id, target, timestamp, and authorization record.
3. Disable Active while reviewing.
4. Document findings in a blocker note.
5. Do not resume Active until authorization and target policy are reviewed.

If a future Nmap command is too broad:

1. Stop the Nmap path immediately.
2. Preserve command plan and audit log.
3. Remove or tighten the scan profile.
4. Add tests for rejected flags/profiles.
5. Keep Nmap runtime disabled until the Nmap docs-first design is updated.

## N. Future Testing Requirements

Future phases should test:

- target normalization;
- blocked CIDR/range inputs;
- blocked wildcard targets;
- blocked metadata IP and metadata hostnames;
- blocked link-local, multicast, unspecified, and private targets by default;
- blocked URL credentials;
- redaction of sensitive query parameters;
- shell-like input rejection;
- missing authorization;
- Active disabled behavior;
- dry-run produces no network call;
- audit log redaction;
- failure-state copy;
- no bypass wording in user-facing errors;
- local-lab explicit mode behavior;
- redirects to blocked targets;
- rate limits;
- timeouts;
- response size cap;
- Nmap runtime not available/not allowed in v0.

Tests should assert no network calls for dry-run phases.

## O. Relationship With Future Dry-Run Contracts

The next recommended phase is:

```text
ACTIVE-NETWORK-BLOCK-03-DRY-RUN-CONTRACTS-DESIGN
```

That phase must use this threat model as input. It should design the request/result/job/audit-log contract for dry-run only, including blocked target records and failure-state reporting, without creating runtime network behavior.

## P. Decision Field

Final decision:

```text
ACTIVE_RUNBOOK_THREAT_MODEL_FROZEN_NO_RUNTIME
```

Meaning:

- Abuse cases are documented.
- Required controls are documented.
- Rejected target classes are documented.
- Audit log requirements are documented.
- Failure states are documented.
- Incident handling is documented.
- Future testing requirements are documented.
- No Active runtime exists.
- No Active endpoints exist.
- No Nmap runtime exists.

Next recommended microphase:

```text
ACTIVE-NETWORK-BLOCK-03-DRY-RUN-CONTRACTS-DESIGN
```
