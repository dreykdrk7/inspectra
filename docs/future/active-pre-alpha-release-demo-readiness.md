# Active Pre-Alpha Release Demo Readiness

Decision: `ACTIVE_PRE_ALPHA_RELEASE_DEMO_READINESS_02_ACCEPTED`

This docs/checklist-only package prepares the current Active pre-alpha set for
release and demo planning. It does not run the app, capture screenshots, use
real targets, add runtime behavior, change backend code, change frontend code,
change tools code, change archive/run-all behavior, change
`tools/runner/main.py`, create a release, create a tag, or push.

## Demo Narrative

Inspectra Active can be demonstrated as a local/private/self-hosted security
review assistant for explicitly authorized targets. The technical alpha shows
that Active capabilities are feature-gated, redaction-first, scoped to one
target/domain/URL shape at a time, and presented as review indicators that
require manual validation.

Recommended demo order:

1. Passive project/archive analysis overview, if relevant, to show the broader
   Inspectra workflow before target-aware Active features.
2. Active capability catalog:
   - Active / Nmap basic v0;
   - Active / TLS basic v0;
   - Active DNS inventory v0 with authorized AXFR;
   - Active DNS OSINT CT v0;
   - Active HTTP basic/header review v1.
3. Disabled-by-default behavior, emphasizing that Active capabilities require
   operator configuration and explicit confirmations.
4. HTTP basic/header review no-live record using placeholder
   `https://example.com/`, showing zero requests, fixed `HEAD`, and
   `[REDACTED_TARGET]`.
5. DNS, TLS, Nmap, and DNS OSINT result interpretation using placeholders,
   synthetic fixtures, or previously accepted safe local/lab evidence.
6. Report/export/Raw JSON redaction explanation, including why raw targets,
   names, headers, cookies, CT payload material, resolver context, exception
   text, credentials, tokens, and secrets are absent.

Demo narration should use phrases such as review indicator, observed exposure,
bounded, best effort, redaction-first, and manual validation required. It
should not claim that the result proves a vulnerability, proves exploitability,
establishes that a target is safe, finds every issue, or replaces a human-led
security review.

## Screenshot Plan

Do not capture screenshots in this phase. Suggested screenshots for a later
explicitly approved documentation phase:

- dashboard overview;
- Active panels and capability catalog;
- HTTP basic/header review no-live panel;
- HTTP basic/header review report showing `[REDACTED_TARGET]`;
- DNS inventory report showing `[REDACTED_DOMAIN]` and
  `[REDACTED_DNS_VALUE]`;
- DNS OSINT CT report showing `[REDACTED_DNS_NAME]`;
- report/export or Raw JSON view showing redaction-first output;
- security scope or usage guidance section that explains authorization,
  redaction, and manual validation.

Screenshot rules for the later phase:

- use placeholders, local fixtures, synthetic data, or owned lab targets only;
- no secrets, cookies, tokens, provider data, account IDs, raw headers, raw
  domains, raw CT payloads, or third-party target names;
- crop or redact browser chrome if it contains local secrets, paths, usernames,
  tokens, or private hostnames;
- record the fixture/source used for each image in the docs phase notes.

## Alpha Release Checklist

Before any tag or release decision:

- confirm `git status --short --branch` is clean or intentionally documented;
- run the full backend test suite;
- run the full frontend test suite;
- run the frontend production build;
- perform a manual docs link/path review if no automated link checker exists;
- run wording guardrails for unsupported claims and unsafe positioning;
- confirm no pending backend, frontend, tools, archive/run-all, or runner
  changes;
- confirm docs and examples contain no secrets, cookies, tokens, provider data,
  raw targets, or real third-party target examples;
- confirm the current branch and ahead/behind state before any tag planning;
- prepare release notes before any tag is created;
- confirm the release notes repeat the disabled-by-default and
  manual-validation posture.

## Later Safe Smoke Checklist

This checklist is for a later explicit phase. It was not executed here.

Disabled-state smoke:

- start from an environment where Active flags are off;
- confirm Active routes or panels show controlled disabled/unavailable states;
- confirm disabled submissions create no job and no target traffic.

Auth-required surface smoke:

- confirm anonymous access to sensitive job/detail/export routes is denied;
- confirm wrong-owner detail, delete, Raw JSON, and export access returns
  generic not-found behavior.

No-live HTTP header review smoke:

- enable only the HTTP basic/header review capability gate;
- use an authorized placeholder/lab URL shape such as `https://example.com/`
  only in the later approved phase;
- confirm a no-live job stores `[REDACTED_TARGET]`, method `HEAD`, zero
  requests, no redirect followed, no body read, and manual validation copy;
- confirm lifecycle status is not presented as HTTP success.

Report/export/Raw JSON redaction smoke:

- review Markdown, HTML, XML, PDF, Raw JSON, list, and detail surfaces;
- confirm placeholders appear where expected;
- confirm raw targets, headers, cookies, resolver context, CT payload material,
  response bodies, exception text, credentials, tokens, and secrets are absent.

Optional live smoke:

- run only in a separate explicitly authorized phase;
- use owned lab targets or local fixtures only;
- do not use third-party public targets;
- document flags, target authorization, expected traffic, and cleanup before
  execution.

## Release Note Skeleton

Title:

```text
Inspectra Active Technical Alpha - release candidate notes
```

Included:

- Active / Nmap basic v0;
- Active / TLS basic v0;
- Active DNS inventory v0 with authorized AXFR;
- Active DNS OSINT CT v0;
- Active HTTP basic/header review v1;
- redaction-first reports, exports, Raw JSON, list, and detail views;
- owner-scoped job surfaces in auth-required deployments;
- operational guidance and smoke checklists.

Disabled by default:

- Active capability flags remain off until an operator enables them in a
  trusted local/private deployment.
- HTTP basic/header review live HEAD requires its second explicit live flag.
- DNS OSINT CT source requires both the OSINT capability gate and CT source
  gate.

Intentionally not included:

- open-target internet service positioning;
- hosted multi-tenant target intake;
- broad target discovery;
- provider administration or credential-based imports;
- passive DNS sources;
- content traversal;
- browser-side target traffic;
- technology-to-CVE mapping;
- automated remediation;
- a binary pass/fail target verdict.

Safety and redaction note:

```text
Active results are review indicators for authorized local/private use.
Reports intentionally redact raw targets, domains, names, values, cookies,
headers, resolver details, CT payload material, exception text, credentials,
tokens, and secrets. Manual validation is required.
```

Known limitations:

- results are bounded and source-specific;
- redaction prevents raw-target inspection in shared reports by design;
- live behavior requires careful operator configuration;
- technology fingerprinting, HTTP policy grouping, TLS deeper review, Nmap
  deeper review, passive DNS, and provider imports remain deferred.

Validation summary placeholder:

```text
Validation: backend tests [pending], frontend tests [pending], frontend build
[pending], docs review [pending], guardrail wording search [pending].
```

## Positioning Guidance

Safe ways to describe Inspectra Active:

- local/private/self-hosted security review assistant;
- authorized-target review workflow;
- review indicators with manual validation;
- redaction-first reporting;
- disabled-by-default Active capabilities;
- bounded DNS, TLS, Nmap, CT, and HTTP header review surfaces.

Avoid saying that Inspectra Active:

- proves the existence of vulnerabilities;
- proves exploitability;
- establishes a target as safe;
- finds every issue;
- acts as an open internet scanning product;
- acts as a hosted target-intake scanning product;
- replaces a human-led penetration test.

## Next-Step Decision

Recommended next step:

```text
ACTIVE_PRE_ALPHA_RELEASE_NOTES_03
```

Scope: docs-only release notes for the current closed Active capability set,
using the skeleton above and validation placeholders until a separate release
candidate phase runs the required checks.

Acceptable alternatives:

- `ACTIVE_PRE_ALPHA_LOCAL_SMOKE_PLAN_03`: docs-only smoke plan for owned lab
  targets and local fixtures.
- A separate explicitly authorized local smoke execution phase, only if the
  operator chooses to run the app against owned/lab fixtures.

Do not choose a new Active runtime feature yet.

## Decision

```text
ACTIVE_PRE_ALPHA_RELEASE_DEMO_READINESS_02_ACCEPTED
```
