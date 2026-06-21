# App-Level Auth Staging Alpha Sharing Readiness

Decision: `APP_LEVEL_AUTH_STAGING_ALPHA_SHARING_READINESS_06_ACCEPTED`

Status: staging is acceptable for operator-only use and very narrow private
alpha sharing with one or two trusted technical users. It is not ready for
broader sharing, public promotion, open uploads, or open target intake.

## Scope

This is a docs-only readiness decision. It does not change backend runtime,
frontend runtime, tools runtime, Caddy configuration, credentials, deploy
state, `archive/run-all`, or `tools/runner/main.py`. It does not create a
release, create a tag, push, enable Active capabilities, run Nmap, submit live
Active jobs, use outside targets, or take screenshots.

## Current Access Posture

- Staging URL: `https://inspectra-alpha.urlbreve.es`
- Outer access layer: Caddy Basic Auth
- Inner app layer: `self_hosted_single_admin`
- Auth state store: SQLite
- Active capabilities: disabled by default
- Staging URL: not publicly promoted
- Dedicated Inspectra domain: deferred

This is a private-alpha staging posture, not a public intake posture.

## Readiness Decision

| Audience | Decision |
| --- | --- |
| Operator-only use | Ready |
| One or two trusted technical testers | Ready with rules below |
| Broader private sharing | Not ready |
| Public or social promotion | Not ready |
| Open upload or target intake | Not ready |

The current staging instance is suitable for focused operator-led validation
and a very small trusted tester loop. The product still needs clearer tester
guidance, a more deliberate data-handling policy, better visual polish, and a
future access model before it should be shared more broadly.

## Sharing Rules

Trusted testers must follow these rules:

- upload only owned code or explicitly authorized project archives;
- sanitize archives before upload;
- do not include `.env` files;
- do not include private keys;
- do not include API keys;
- do not include tokens;
- do not include browser cookies;
- do not include production database dumps;
- do not include client records or regulated personal/business records;
- do not include invoices, media, or private business documents;
- do not upload third-party projects without explicit authorization;
- do not request Active scans unless a separate phase approves them.

The intended tester workflow is Passive project archive review with sanitized,
owned, non-production sample material.

## Operator And Tester Expectations

- Results are review indicators that require manual validation.
- Redaction is intentional and may hide raw source details.
- The UI is visually rough but functionally usable for current alpha goals.
- Passive project archive reports are the main tested workflow.
- Exports are available for review.
- Active capability surfaces may exist but remain disabled unless separately
  configured.
- This staging line prioritizes the audited data and report usefulness over
  polished onboarding.

## Access-Control Notes

Caddy Basic Auth plus app-level `self_hosted_single_admin` is acceptable for
the current narrow private-alpha scope. It is not a scalable access model.

Important constraints:

- keep Basic Auth in front while the alpha remains private;
- `self_hosted_single_admin` is a single-admin/private-alpha mode, not
  multi-user tenancy;
- sharing the same app-admin access path is only acceptable for a tiny trusted
  loop;
- before multiple external testers, decide whether to implement multi-user or
  per-tester access;
- do not remove either access layer without a separate decision.

## Product Readiness Notes

Strong points:

- staging deployment is live and protected;
- passive dogfood succeeded;
- report readability improved;
- app-level auth signoff passed;
- exports work;
- Caddy unauthenticated `/` returns `401`;
- backend and audit-tools are healthy;
- frontend is running;
- Inspectra services have no public host port bindings;
- Docker socket mount is absent for Inspectra services;
- Active flags were confirmed disabled.

Weak points:

- UI is visually rough;
- sanitizer source and fixture classification remains deferred;
- no public onboarding exists;
- no dedicated Inspectra domain is configured yet;
- no multi-user model exists;
- Active live use is outside this sharing decision.

## Recommended Next Product Step

If the product remains operator-led, the recommended next step is:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_01
```

Reason: the most useful next improvement is to clarify safe fixture/source
handling and strengthen confidence in what can be uploaded during private
alpha review.

If the operator wants to invite one trusted tester soon, use this instead:

```text
PRIVATE_ALPHA_TESTER_GUIDE_01
```

Reason: a short tester guide should define allowed material, login flow,
expected rough edges, report interpretation, export handling, and support
feedback format before any invitation is sent.

Use this only if broader sharing becomes a near-term goal:

```text
APP_MULTI_USER_AUTH_DESIGN_01
```

Reason: broader sharing should not depend on a shared single-admin access path.

## No-Go Boundaries

- no public launch;
- no social promotion yet;
- no open uploads;
- no scanner-style public positioning;
- no unauthenticated access;
- no Active enablement by default;
- no third-party target scanning;
- no weakening sanitizer behavior;
- no version-to-CVE claims;
- no exploitability claims;
- no safe-to-test claims.

## Decision

```text
APP_LEVEL_AUTH_STAGING_ALPHA_SHARING_READINESS_06_ACCEPTED
```
