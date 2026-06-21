# App-Level Auth Staging Private Operator Signoff

Decision: `APP_LEVEL_AUTH_STAGING_PRIVATE_OPERATOR_SIGNOFF_05_ACCEPTED`

Status: the operator manually verified the staging auth posture through the
normal browser flow behind Caddy Basic Auth.

## Scope

This phase records private operator signoff for the current staging auth
posture. It did not change backend runtime, frontend runtime, tools runtime,
Caddy configuration, credentials, `archive/run-all`, or `tools/runner/main.py`.
It did not create a release, create a tag, push, enable Active capabilities,
run Nmap, submit live Active jobs, use outside targets, or take screenshots.

## Staging Target

- Staging URL: `https://inspectra-alpha.urlbreve.es`
- Target posture: Caddy Basic Auth plus app-level
  `self_hosted_single_admin`
- Auth state store: SQLite
- Operator-held app access: configured in the prior rotation phase
- Active posture: disabled

## Non-Secret Status Checks

Codex performed allowed non-secret checks before this signoff record:

| Check | Result |
| --- | --- |
| Caddy unauthenticated `/` | `401` |
| backend service | running, healthy |
| audit-tools service | running, healthy |
| frontend service | running |
| app auth mode | `self_hosted_single_admin` |
| auth state store | `sqlite` |
| app auth configured | true |
| backend host ports | absent |
| frontend host ports | absent |
| audit-tools host ports | absent |
| backend Docker socket mount | absent |
| frontend Docker socket mount | absent |
| audit-tools Docker socket mount | absent |

The first non-secret status check had a local reporting typo in the helper
script and was rerun without changing staging configuration.

## Operator Manual Signoff

The operator manually verified the normal browser flow:

| Check | Operator result |
| --- | --- |
| Overall signoff | yes |
| Dashboard loads | yes |
| Passive upload/project surfaces reachable | yes |
| Report/export navigation accessible | yes |
| Logout works and requires login again | yes |

The operator passed Caddy Basic Auth, reached the Inspectra app login screen,
logged in with the operator-held app access material, navigated the passive
workflow surfaces, confirmed audit results and exports were accessible, and
confirmed logout returned the app to a login-required state.

## Optional Passive Check

No optional synthetic passive upload was performed in this phase.

This was intentional: previous staging smoke already validated a small
synthetic archive workflow, and this phase focused on human browser signoff for
the layered auth posture.

## Logout And Denial Observation

Operator observation:

- logout was visible and worked;
- after logout, the app required login again.

The prior automated rotation smoke also verified a post-logout export request
returned `401`; this signoff did not repeat that automated route check.

## Active Disabled

Checked during this phase:

- `INSPECTRA_ACTIVE_DRY_RUN_ENABLED`: disabled
- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED`: disabled
- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED`: disabled
- `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED`: disabled
- `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED`: disabled
- `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED`: disabled
- `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED`: disabled
- `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED`: disabled

No Active jobs were submitted.

## UX And Blockers

Operator note:

- UI is visually rough, but there is no functional blocker for the current
  alpha.
- Audit results and exports are accessible.
- Current product focus remains the data audited.

No functional auth blocker was found.

## Sensitive Material Handling

This signoff record does not include private auth material, verifier material,
browser session material, CSRF material, Caddy access material, private config
contents, production files, outside target lists, or screenshots.

## Recommendation

Recommended next product step:

```text
APP_LEVEL_AUTH_STAGING_ALPHA_SHARING_READINESS_06
```

Suggested scope: document whether the staging instance is ready for narrow
private-alpha sharing, including operator-facing expectations, known visual UX
roughness, allowed data types, and continued Active-disabled boundaries.

## Decision

```text
APP_LEVEL_AUTH_STAGING_PRIVATE_OPERATOR_SIGNOFF_05_ACCEPTED
```
