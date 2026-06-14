# Active TLS Basic Design

Decision: `ACTIVE_TLS_BASIC_01_DESIGN_FROZEN`

This document freezes a docs-only design for a future `active_tls_basic`
capability. It does not implement backend runtime, frontend runtime, runner
behavior, socket connections, TLS handshakes, OpenSSL commands, Python `ssl`
connections, Nmap behavior, Docker behavior, probes, DNS checks, HTTP requests,
crawling, archive/run-all integration, `tools/runner/main.py` integration,
release state, tag state, or push state.

## Objective

`active_tls_basic` is intended to perform one minimal, authorized TLS inspection
against one explicit target and one bounded port. The capability should help a
trusted operator review basic certificate and negotiated-connection metadata for
a local/private/self-hosted service without becoming a crawler, fuzzing tool,
credential checker, Nmap extension, or public scanning service.

The result must be framed as TLS configuration review indicators requiring
manual validation. The capability must not claim vulnerability status,
exploitability, target safety, or certificate inventory completeness.

## Activation Model

Future implementation must be disabled by default and require explicit opt-in.
A suggested backend flag is:

```text
INSPECTRA_ACTIVE_TLS_BASIC_ENABLED=false
```

Enabled mode must still require:

- authenticated/owner-scoped access when the deployment uses auth-required mode;
- explicit target authorization confirmation;
- explicit local/private/self-hosted scope confirmation;
- explicit live-traffic confirmation;
- backend target policy acceptance before any network-capable path;
- short timeout and bounded output limits.

Anonymous requests in auth-required deployments must be denied before validation
details are revealed.

## Future Contract Shape

Suggested future route:

```text
POST /active/network/tls-basic
```

Suggested future request:

```json
{
  "mode": "live_tls_basic",
  "profile": "tls_handshake_summary",
  "target": "service.local",
  "port": 443,
  "authorization_confirmed": true,
  "local_private_scope_confirmed": true,
  "live_traffic_confirmed": true
}
```

Required future fields:

- `mode`: exactly `live_tls_basic`;
- `profile`: exactly `tls_handshake_summary`;
- `target`: one explicit target only;
- `port`: one integer TCP port, bounded by policy;
- `authorization_confirmed`: exactly `true`;
- `local_private_scope_confirmed`: exactly `true`;
- `live_traffic_confirmed`: exactly `true`.

Persisted job identity, if implemented later:

- `audit_type: active_tls_basic`;
- `file_id: null`;
- owner-scoped;
- target-based with public target display redacted.

Port `443` may be the default in a future UI only after target policy accepts
the target and only when the operator has not requested a different approved
bounded port. The backend contract should still store the port explicitly.

## Target Policy

The target policy must accept only a single explicit target. It must reject:

- multiple targets;
- empty targets;
- URLs with scheme, path, query, fragment, or userinfo;
- CIDR blocks, dash ranges, wildcards, pasted lists, target files, and generated
  candidates;
- broad public-target use;
- metadata/control-plane names and addresses;
- overly long values or values with control characters;
- ports outside the policy allowlist or configured cap.

Allowed target categories should remain local/private/self-hosted only. If a
future implementation supports hostnames, it must not perform DNS expansion,
subdomain discovery, Certificate Transparency lookup, reverse lookup, or
crawling. Any resolver behavior needed for one bounded TLS connection must be
treated as part of the authorized connection path and fail closed on ambiguous
or blocked results.

## Execution Boundaries

Future execution should perform at most one TLS client handshake attempt for the
single accepted target and port. It must not:

- send HTTP requests;
- crawl links;
- retry across alternate ports or protocols;
- follow redirects;
- enumerate SANs as new targets;
- validate credentials;
- brute force protocols, ciphers, names, or credentials;
- fuzz TLS extensions;
- invoke OpenSSL as a shell command;
- use Nmap;
- integrate with archive/run-all;
- run inside `tools/runner/main.py`.

The implementation should prefer structured language APIs over shell commands,
with strict timeouts and bounded reads. If a separated active-tool boundary is
introduced later, it must keep the backend as the authority for auth, owner
scope, validation, storage, reporting, and redaction.

## Timeouts And Limits

Suggested future defaults:

- connect/handshake timeout: 3 seconds;
- total deadline: 5 seconds;
- target count: 1;
- port count: 1;
- certificate chain items retained publicly: 1 leaf summary by default;
- SAN entries retained publicly: at most 10 bounded/redacted entries;
- subject/issuer string length: bounded before storage and rendering;
- raw response/output bytes: not stored publicly.

Timeouts should fail closed into controlled states such as `timed_out` or
`handshake_failed`, without leaking raw target values.

## Allowed Result Shape

Future stored result should be allowlisted and bounded. Suggested fields:

```json
{
  "audit_type": "active_tls_basic",
  "capability": "active_tls_basic",
  "status": "completed",
  "result_status": "handshake_succeeded",
  "target": "[REDACTED_TARGET]",
  "port": 443,
  "handshake": {
    "status": "succeeded",
    "protocol": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384"
  },
  "certificate": {
    "subject": "[REDACTED_SUBJECT]",
    "san_count": 2,
    "sans": ["[REDACTED_SAN]"],
    "issuer": "Example Issuer",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2026-04-01T00:00:00Z",
    "days_until_expiry": 30
  },
  "manual_validation_required": true,
  "result_interpretation": "tls_configuration_review_indicator"
}
```

Allowed future observations:

- handshake status;
- bounded negotiated protocol and cipher, if safely available;
- certificate subject, redacted or display-safe bounded;
- SAN count and a bounded/redacted SAN sample;
- issuer display string, bounded and redacted if needed;
- `not_before`;
- `not_after`;
- `days_until_expiry`;
- controlled failure state and reason code;
- manual validation marker;
- review-indicator wording.

The result must not include raw certificate PEM by default, raw DER bytes,
private keys, chain dumps, raw target values, credentials, headers, cookies,
tokens, request payloads, command lines, stdout/stderr, packet captures, or
unbounded strings.

## Redaction And Public Surfaces

Public API responses, job detail, job list summaries, Raw JSON views, reports,
and future exports must be redaction-first:

- target shown only as `[REDACTED_TARGET]` or equivalent;
- certificate subject and SANs bounded and redacted where they contain the
  target or sensitive internal names;
- issuer bounded before rendering;
- no raw certificate PEM by default;
- no private key material;
- no credentials, headers, cookies, or tokens;
- no raw exception text that can include hostnames or addresses;
- wrong-owner access remains generic not-found behavior.

Report wording should use phrases such as:

- "TLS handshake review indicator";
- "certificate expiry review indicator";
- "manual validation required";
- "observed during one authorized TLS attempt".

Reports must not present findings as proof of compromise, exploitability,
target safety, or complete certificate coverage.

## UX Expectations

Future UI should be separate from Passive scans and from Active / Nmap basic.
Expected controls:

- target input for one explicit target;
- port input with safe bounded default behavior;
- fixed profile display for `tls_handshake_summary`;
- three explicit confirmations;
- disabled-state copy when the feature flag is off;
- clear no-crawling/no-credential/no-Nmap boundary copy;
- result panel with redacted target, handshake status, bounded certificate
  summary, expiry indicator, and manual validation note.

The UI must not expose controls for raw flags, target files, multiple targets,
SNI override lists, client certificates, credentials, headers, cookies, tokens,
cipher brute force, protocol fuzzing, crawling, HTTP fetching, Nmap, or
archive/run-all.

## Abuse Threats

Primary abuse risks:

- turning a single-target TLS check into broad target enumeration;
- using certificate SANs as a discovery seed;
- leaking internal hostnames from certificates;
- collecting raw certificates or exception strings into public surfaces;
- using TLS errors as proof statements;
- adding credential-bearing mTLS or header/cookie flows;
- routing execution through shell commands;
- merging the feature into passive archive workflows.

Required mitigations:

- disabled-by-default feature gate;
- explicit confirmations;
- single-target policy;
- no target expansion;
- bounded timeout and output;
- allowlisted result schema;
- redaction before storage and rendering;
- owner-scoped jobs;
- generic wrong-owner responses;
- no archive/run-all integration.

## Future Tests

Future implementation should include tests for:

- disabled flag rejects without creating a job;
- auth-required anonymous fails before validation details;
- exact request contract validation;
- missing or false confirmations;
- single-target enforcement;
- target policy rejection for URLs, ranges, wildcards, files, and lists;
- port bounds and default handling;
- timeout and controlled handshake errors;
- no raw target in errors;
- redacted subject/SAN rendering;
- no raw certificate PEM in public result;
- owner scope and generic wrong-owner behavior;
- report/Raw JSON redaction;
- no crawling, HTTP request, Nmap, Docker, archive/run-all, or
  `tools/runner/main.py` integration.

Tests for this design phase are documentation checks only.

## Acceptance Criteria For Future Implementation

A future implementation can be considered for acceptance only when:

- it remains disabled by default and opt-in;
- it accepts exactly one authorized local/private/self-hosted target;
- it performs at most one bounded TLS handshake attempt;
- it stores only allowlisted, redacted, bounded result fields;
- it keeps backend authority over auth, owner scope, validation, storage,
  reporting, and redaction;
- it keeps Passive archive flows separate;
- it does not use Nmap, OpenSSL shell commands, crawling, fuzzing, credential
  checks, or archive/run-all;
- backend, runner/tooling, frontend, report, Raw JSON, and owner-scope tests pass;
- docs continue to frame output as review indicators requiring manual
  validation.

## Final Decision

```text
ACTIVE_TLS_BASIC_01_DESIGN_FROZEN
```

The `active_tls_basic` capability is designed as a future bounded, opt-in,
local/private/self-hosted TLS review indicator for one explicit authorized
target. No runtime implementation is added by this phase.
