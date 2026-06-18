# Active Post-DNS Roadmap Decision

Decision: `ACTIVE_POST_DNS_ROADMAP_DECISION_ACCEPTED`

This docs-only decision chooses the next small Active path after the completed
Active DNS v0 block. It adds no endpoint, flag, contract, test, UI, storage,
report, runtime behavior, Docker behavior, Nmap behavior, network request,
release, tag, or push state.

## Context

The current Active v0 blocks are closed:

- Active / Nmap basic v0 is functionally closed as a bounded
  local/private/self-hosted capability.
- Active / TLS basic v0 is functionally closed.
- Active DNS inventory v0 is functionally closed, including authorized AXFR.
- Active DNS OSINT CT v0 is functionally closed.
- Active DNS v0 operational guidance is accepted as
  `ACTIVE_DNS_OPERATIONS_01_OPERATIONAL_GUIDE_ACCEPTED`.

The next path should add product value without reopening broad DNS discovery,
provider administration, archive/run-all, `tools/runner/main.py`, or hosted
scanning product behavior.

## Options

| Option | Product value | Complexity | Abuse/risk surface | Testing burden | Redaction/reporting |
| --- | --- | --- | --- | --- | --- |
| HTTP basic/header review v1 | Clear user value from a familiar web-edge review: one authorized URL or host, security headers, server header posture, and redirect-policy review indicators. | Low to moderate if it stays one request, disabled by default, and authorization-confirmed. | Lower than Nmap deepening, but still live traffic; must avoid crawling, auth, custom headers, request bodies, and claims about vulnerabilities or safe targets. | Focused contract, target-policy, fake-transport, reporting, export, and frontend tests should be enough for v1. | Redact target display, headers that may contain secrets, redirect locations, cookies, tokens, errors, and Raw JSON; wording stays review-indicator only. |
| Technology fingerprint ultra-bounded | Useful context if based only on already approved bounded signals, such as server/header/TLS metadata already collected by a chosen capability. | Moderate because category labels and confidence rules need careful design. | Risk of drifting into broad scanning, version matching, or unsupported conclusions. | Requires strong fixture coverage for ambiguous and sparse signals. | Must show conservative labels, confidence/caveats, no version-to-CVE mapping unless separately designed. |
| Nmap deeper v1 | Potentially useful for operators who already accepted Nmap v0, but value is tied to broader scan semantics. | High compared with current needs. | Higher policy surface: scan profiles, target classes, ports, output volume, service/version temptation, and stronger abuse perception. | Broad backend, active-tools, parser, report, frontend, and smoke burden. | Must preserve current Nmap v0 redaction and observed-exposure wording; defer unless product need is strong. |
| Operational/release polish | Improves trust and usability through pre-alpha readiness, docs, smoke checklists, screenshots, and README polish. | Low. | Low because it adds no capability. | Docs and smoke-checklist validation only. | Can clarify existing redaction and result interpretation without changing outputs. |

## Deferred Paths

Passive DNS remains deferred because it introduces third-party data-source
terms, retention questions, attribution ambiguity, source-specific rate limits,
and observed-name handling that should not be folded into the completed Active
DNS v0 block.

Provider import remains deferred because it requires privileged administrator
access, provider credentials, account/zone identifiers, and secret handling. If
ever needed, it should be a separate admin inventory connector, not an
attacker-equivalent Active path.

`archive/run-all` remains outside Active because Active capabilities require
explicit target authorization, live-traffic confirmation, and per-capability
operator intent. Batch/archive orchestration would blur that intent.

`tools/runner/main.py` remains outside Active because the project already keeps
passive archive analysis separate from Active target behavior. Active execution
should stay in small, reviewed Active-specific boundaries.

## Recommendation

Choose HTTP basic/header review v1 as the next Active capability, but only as a
narrowly bounded, disabled-by-default, authorization-confirmed, single-request
review-indicator capability.

This path has the best balance:

- strong product value for web-edge review;
- lower complexity than Nmap deeper v1;
- narrower risk than broad fingerprinting or DNS/source expansion;
- straightforward fake-transport testing;
- clear redaction and report language;
- reuse of existing Active authorization and one-request thinking without
  turning the product into a hosted scanning service.

Operational/release polish remains a good parallel or follow-up path, but it
does not answer the product question of the next small Active capability.

## Suggested Next Microphase

```text
ACTIVE_HTTP_BASIC_HEADER_REVIEW_01_DESIGN
```

Suggested scope: docs-only design for a future disabled-by-default
`active_http_basic_header_review` capability. The design should freeze the
request model, authorization confirmations, target policy, one-request limit,
redaction boundary, report wording, fake-transport tests, and no-go boundaries
before any implementation.

## No-Go Boundaries For The Chosen Path

HTTP basic/header review v1 must not include:

- more than one authorized URL or host per accepted job;
- crawling;
- JavaScript execution;
- request bodies;
- custom headers;
- authentication inputs;
- cookies;
- credential validation;
- response body analysis beyond a separately designed minimal allowance;
- automatic target expansion;
- DNS OSINT, passive DNS, or provider import;
- archive/run-all handoff;
- `tools/runner/main.py` handoff;
- Nmap or port scanning;
- version-to-CVE mapping;
- exploit checks;
- claims that a target is safe;
- claims that findings prove vulnerabilities or exploitability;
- hosted scanning product behavior.

## Final Decision

```text
ACTIVE_POST_DNS_ROADMAP_DECISION_ACCEPTED
```

The next recommended Active path is HTTP basic/header review v1, starting with
`ACTIVE_HTTP_BASIC_HEADER_REVIEW_01_DESIGN` as a docs-only design phase.
