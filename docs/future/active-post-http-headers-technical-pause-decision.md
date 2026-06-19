# Active Post-HTTP Headers Technical Pause Decision

Decision: `ACTIVE_POST_HTTP_HEADERS_TECHNICAL_PAUSE_DECISION_ACCEPTED`

This docs-only decision pauses after the accepted
`active_http_basic_header_review` v1 closeout and chooses the next Active path.
It adds no endpoint, flag, contract, storage, transport, report, UI, test,
runtime behavior, Docker behavior, Nmap behavior, network request, release,
tag, or push state.

## Context

The current Active blocks are closed:

- Active / Nmap basic v0;
- Active / TLS basic v0;
- Active DNS inventory v0, including authorized AXFR;
- Active DNS OSINT CT v0;
- Active DNS v0 operational guidance;
- Active HTTP basic/header review v1, closed by
  `ACTIVE_HTTP_BASIC_HEADER_REVIEW_11_FUNCTIONAL_CLOSEOUT_ACCEPTED` in commit
  `dff3b6f fix(active): close http header review v1`.

After HTTP basic headers, the project should pause before adding another Active
runtime surface. The next phase should improve operator confidence, product
positioning, and alpha readiness while keeping the closed Active boundaries
intact.

## Options

| Option | Product value and user usefulness | Complexity | Abuse/risk surface | Testing burden | Redaction/reporting implications | Alpha readiness |
| --- | --- | --- | --- | --- | --- | --- |
| Operational/pre-alpha polish | High near-term value: operators get clearer usage docs, screenshots, smoke checklists, README/product positioning, and a safe local/private deployment guide. | Low if it stays docs and checklist work. | Low because it adds no runtime behavior and no target interaction. | Low to moderate: validate links, commands, status wording, screenshots if added, and consistency with accepted closeouts. | Clarifies existing redaction and review-indicator language without changing stored results or reports. | Strong. It turns closed capabilities into a more understandable alpha package. |
| Technology fingerprint ultra-bounded | Useful later as a conservative summary over already approved bounded signals from HTTP headers, TLS, DNS, and Nmap outputs. | Moderate: signal taxonomy, confidence labels, ambiguity handling, and sparse-result behavior need a careful design. | Moderate if labels drift into scanner-like interpretation or unsupported inference. | Moderate to high: many fixtures are needed for sparse, conflicting, and noisy signals. | Must use conservative labels, source attribution, redacted target display, and no version-to-CVE mapping unless separately designed. | Helpful later, but should follow a product consolidation pass. |
| HTTP security policy deeper v1 | Useful for richer interpretation and grouping of the already collected HTTP header indicators. | Low to moderate if it adds only copy/report grouping. | Low to moderate if it preserves one HEAD, no extra requests, no body reads, no redirects, and no crawler behavior. | Focused report/copy tests plus regression coverage for no-live and live results. | Could improve report readability, but must not add raw header values or stronger conclusions. | Helpful, but less urgent than making the whole Active set easier to operate. |
| TLS deeper v1 | Useful for certificate/protocol/cipher posture review within the existing TLS basic shape. | Moderate because certificate and protocol interpretation can expand quickly. | Moderate: must preserve one authorized host, disabled-by-default gates, bounded timeout, no HTTP, and redacted certificate material. | Moderate to high: certificate fixtures, failure modes, protocol/cipher edge cases, and reporting tests. | More public-result shaping and careful certificate redaction would be required. | Useful after alpha consolidation, not the immediate next step. |
| Nmap deeper v1 | Potential value for operators who already use Nmap v0. | High compared with current needs. | Higher: scan profiles, ports, service/version temptation, output size, and broader authorization boundaries. | High across active-tools, backend, parser, report, frontend, and smoke coverage. | Must preserve Nmap v0 redaction and observed-exposure review wording. | Defer unless a specific product need outweighs the larger review surface. |
| Passive/provider/import/connectors | Potentially valuable for administrative inventory and enrichment. | High: source-specific contracts, credentials, retention, and account/zone identity rules. | High: credentials, source terms, quota behavior, authorization proof, and data-retention expectations. | High across connector mocks, source failures, owner scope, secret redaction, and export behavior. | Would require separate secret handling and source-specific redaction rules. | Defer. It is not the right next step after closing multiple Active runtime blocks. |

## Deferred Runtime Paths

Passive DNS and provider imports remain deferred because they introduce
third-party source terms, credentials, retention policy, quota behavior,
account identifiers, and authorization boundaries that do not belong inside the
closed Active DNS or HTTP header review paths.

`archive/run-all` remains outside Active because Active work depends on
explicit target authorization, live-traffic confirmation, and per-capability
operator intent. Batch archive orchestration could blur those confirmations.

`tools/runner/main.py` remains outside this decision because it is not the
right place to add a cross-capability Active orchestrator. Active behavior
should stay in reviewed, capability-specific boundaries until a separate
architecture decision says otherwise.

## Recommendation

Choose a short operational/pre-alpha polish phase before adding another Active
runtime feature.

This is the best next step because:

- the project has several closed Active capabilities that now need a coherent
  operator story;
- documentation and smoke checklists improve trust without widening runtime
  behavior;
- README/product positioning can explain what Active results mean and what
  they do not mean;
- safe local/private deployment guidance helps prevent misuse of disabled-by-
  default features;
- it gives the team a clean checkpoint before deciding whether the next runtime
  feature should be technology fingerprinting, HTTP policy grouping, TLS
  deeper review, or something else.

Technology fingerprint ultra-bounded remains the strongest candidate for the
next feature after consolidation, but only as a conservative summary layer over
already approved bounded signals. It should not become a new scanner, a
crawler, a JavaScript executor, a body reader, a redirect follower, or a
version-to-CVE mapper.

## Suggested Next Microphase

```text
ACTIVE_PRE_ALPHA_OPERATIONAL_POLISH_01
```

Suggested scope: docs/checklist-only polish for the existing closed Active
capabilities. The phase should improve README/product positioning, usage docs,
safe local/private deployment guidance, smoke checklists, and optional static
screenshots or screenshot instructions without adding runtime behavior.

## No-Go Boundaries For The Recommended Path

The recommended operational/pre-alpha polish phase must not include:

- backend runtime changes;
- frontend runtime changes;
- tools runtime changes;
- new endpoints, flags, transports, storage, reports, UI, or tests;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- Docker execution;
- Nmap execution;
- HTTP, DNS, TLS, CT, or other network requests;
- real targets;
- crawling;
- JavaScript execution;
- passive DNS runtime;
- provider import runtime;
- version-to-CVE mapping;
- exploit checks;
- binary target verdicts;
- completeness claims;
- release, tag, or push actions.

## Final Decision

```text
ACTIVE_POST_HTTP_HEADERS_TECHNICAL_PAUSE_DECISION_ACCEPTED
```

The next recommended path is operational/pre-alpha polish, starting with
`ACTIVE_PRE_ALPHA_OPERATIONAL_POLISH_01` as a docs/checklist-only phase.
