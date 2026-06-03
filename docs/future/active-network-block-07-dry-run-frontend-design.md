# Active Network Block 07 Dry-Run Frontend Design

Status: `HISTORICAL_DESIGN_IMPLEMENTED_IN_BLOCK_08`.

Implementation record: `docs/future/active-network-block-08-dry-run-frontend-implementation-no-network.md`

Base backend integration: `docs/future/active-network-block-06-dry-run-backend-integration-no-network.md`

Base backend contract: `docs/future/active-network-block-05-dry-run-backend-contract-design.md`

Base runbook/threat model: `docs/future/active-network-block-02-runbook-and-threat-model.md`

Commit scope: frontend UX design only.

This document designs the future frontend integration for Active network dry-run jobs. It does not implement UI, add buttons, call `POST /active/network/dry-run`, modify frontend runtime code, modify backend/runner code, touch `tools/runner/main.py`, execute network behavior, resolve DNS, perform HTTP requests, open sockets, run subprocess probes, run Nmap, create tags, push releases, or mutate the Passive Alpha release line.

## A. Starting State

Implemented backend surface:

```text
POST /active/network/dry-run
```

Implemented audit/job type:

```text
active_network_dry_run
```

Implemented backend flag:

```text
INSPECTRA_ACTIVE_DRY_RUN_ENABLED=false
```

Current behavior at design time:

- The endpoint is disabled by default.
- Disabled endpoint calls return `403` and do not create jobs.
- Enabled endpoint creates target-based jobs with `file_id: null`.
- The backend calls `run_active_network_dry_run`.
- `GET /jobs` includes active dry-run summaries.
- `GET /jobs/{job_id}` returns redacted active dry-run results.
- Markdown, HTML, XML, and PDF exports are integrated.
- Frontend had no Active dry-run form, action, report component, catalog entry, or filter entry yet.
- No network behavior exists.
- Dry-run only.

This document designs the future UI and tests.

## B. UX Placement Options

| Option | Description | Pros | Cons |
| --- | --- | --- | --- |
| Option 1: dashboard section | Add a small, visually separate `Active / Network dry-run` panel near the existing target-based Web Audit, Domain Baseline, and Subdomain Inventory panels. | Fits the current single-page dashboard. Keeps job creation visible without adding routing. Can be visually separated from Upload and archive actions. | Needs careful copy so it does not feel like another passive upload analyzer. |
| Option 2: future route/page | Add a separate Active page or route. | Strong separation from passive/archive work. Better if future Active features become larger. | More navigation work and heavier than the current dry-run-only scope. |
| Option 3: action inside jobs/dashboard | Add a job-table action or dashboard-only command. | Minimal visual surface. | Poor fit because dry-run creation is target-based and needs explicit authorization before job creation. Easy to confuse with rerun/export actions. |

Recommended first implementation:

```text
Use Option 1: a small, separate dashboard section.
```

Placement guidance:

- Place it near other target-based panels, not inside file upload or archive action groups.
- Use a panel title such as `Active / Network dry-run`.
- Make it visually distinct from `Files` and archive-only config actions.
- Do not add an action to uploaded file rows.
- Do not run automatically on page load, file upload, target typing, or job selection.
- Do not use the archive action menu.

## C. Form Fields

Future form fields:

- `target` input:
  - text input;
  - placeholder: `https://example.test`;
  - required;
  - warning if query string or userinfo appears;
  - never claim the target has been contacted.
- `profile` select:
  - only option for v0: `http_header_probe_preview`;
  - label: `HTTP header preview plan`;
  - disabled or single-option select is acceptable.
- `mode` display:
  - read-only;
  - value: `dry_run`;
  - copy: `Dry-run only`.
- `authorization` checkbox:
  - required before submit;
  - see Section D.
- `authorization.statement` display:
  - fixed statement text;
  - not user-editable in v0.
- `authorization.scope` display:
  - value: `single-target`;
  - read-only.
- `limits` display:
  - `max_requests: 0`;
  - `timeout_seconds: 0`;
  - `max_redirects: 0`;
  - `response_size_bytes: 0`;
  - read-only in v0.
- submit button:
  - label: `Create dry-run plan`;
  - disabled until target is present and authorization is checked;
  - loading label: `Creating plan`.

Do not use these labels:

- `Scan`;
- `Run Nmap`;
- `Probe target`;
- `Attack`;
- `Exploit`;
- `Validate vulnerability`.

## D. Authorization UX

The form must show these confirmations:

```text
I confirm I own or am authorized to test this target.
```

```text
I understand this dry-run sends no network traffic.
```

```text
Do not scan third-party systems without permission.
```

Future request body should send:

```json
{
  "authorization": {
    "confirmed": true,
    "statement": "I confirm I own or am authorized to test this target.",
    "scope": "single-target"
  }
}
```

UX requirements:

- The checkbox is required.
- The submit button remains disabled until target and authorization are present.
- Target text alone never implies authorization.
- The confirmation should be near the submit button, not hidden in help text.
- Do not store the raw target in local storage.
- Do not repeat raw sensitive target text in toast messages.

## E. Active Disabled State

When the backend returns `403`, the UI should show:

```text
Active dry-run checks are disabled in this environment.
```

Optional supporting copy:

```text
Ask an administrator to enable the Active dry-run backend flag for this deployment.
```

Disabled-state requirements:

- Show a calm controlled state, not a scary failure.
- Do not retry automatically.
- Do not encourage repeated submissions.
- Do not claim the target was processed.
- Do not mention `.env` file editing.
- Do not provide bypass guidance.
- Do not show the raw target if it contains URL credentials or sensitive query values.

## F. Copy Rules

Preferred controlled copy:

- `dry-run`;
- `plan`;
- `preview`;
- `no network traffic was sent`;
- `authorization required`;
- `review indicator`;
- `target blocked by safety policy`;
- `planned checks were not executed`;
- `network requests sent: 0`.

Avoid in action labels, status messages, report headings, and empty states:

- `scan`;
- `attack`;
- `exploit`;
- `vulnerability confirmed`;
- `target is safe`;
- `credential valid`;
- `bypass`;
- `evade`;
- `Nmap`;
- `port scan`;
- `live probe`.

The word `Active` is allowed as a product category, but every action surface must clarify dry-run and no-network behavior.

## G. Target Summary UX

Before submit:

- Show the raw target as typed only in the input field.
- If query string is present, show a warning that sensitive parameters will be redacted.
- If URL userinfo appears, warn that credentials are not accepted and should not be entered.
- Do not normalize or validate as if the backend has accepted it.

After result:

- Show `target.raw` only after backend redaction.
- Show `target.normalized` if present.
- Show target type/classification if present.
- Show `local_lab` when present; v0 should normally show `false` or unavailable.
- Show `policy.allowed`.
- Show `blocked_reasons` when present.
- Show `network_requests_sent: 0`.

Target display rules:

- Do not show raw userinfo.
- Do not show sensitive query values.
- Prefer backend-redacted `target_url`, `summary.target_display`, or redacted result fields.
- Use `[REDACTED]` consistently.

## H. Report UX

Question: should future Active dry-run reports use `PassiveReportShell` or a new shell?

| Option | Pros | Cons |
| --- | --- | --- |
| Reuse `PassiveReportShell` | Existing layout, status handling, raw JSON slot, and archive-report visual language. | It renders `Passive review` and archive/static-copy defaults, which are wrong for Active dry-run. |
| Create `ActiveReportShell` | Clear Active category, dry-run badge, no-network copy, target-based metadata, no archive assumptions. | Adds a new shell component. |
| Generalize to `ReportShell` | Shared shell with mode/category badges. Could support passive, web/domain, and active reports. | Larger refactor than a first Active UI should need. |

Recommended first implementation:

```text
Create ActiveDryRunJobReport with either a small local shell or a new ActiveReportShell.
```

Do not use `PassiveReportShell` unchanged.

Required report surface:

- `Active / Network` category.
- `Dry-run` badge.
- `No network traffic was sent`.
- job status.
- `network_requests_sent: 0`.
- Target Summary.
- Authorization Summary.
- Policy Decision.
- Planned Checks.
- Blocked Reasons.
- Limits.
- Audit Log.
- Errors.
- Redacted Raw JSON.

Status handling:

- `queued`: `Job queued. The dry-run plan will appear when processing starts.`
- `running`: `Dry-run planning is running. No network traffic is sent.`
- `failed`: `The job failed in a controlled state. Review redacted errors below.`
- `completed` with `policy.allowed: true`: show planned checks as preview records only.
- `completed` with `policy.allowed: false`: show blocked reasons as safety-policy decisions.
- sparse/malformed result: show available redacted fields and a controlled sparse-state notice.

Empty states:

- no planned checks: `No planned checks were returned.`
- no blocked reasons: `No blocked reasons were returned.`
- no errors: `No controlled errors were reported.`
- no audit log: `No audit log entries were returned.`

## I. Job Table And Filter Expectations

Future `auditCatalog.ts` expectations:

- Add audit type:
  - `active_network_dry_run`
- Label:
  - `Active network dry-run`
- Category:
  - `Active / Network`
- Source family:
  - `target`
- Description:
  - `Dry-run planning for explicitly authorized targets; no network traffic.`

Implementation detail:

- The current catalog uses `authorized_target` for web/domain/subdomain flows.
- Future implementation may add a new `target` or `active_target` source family to avoid treating Active dry-run as a file/archive analyzer.
- If the existing source-family union is kept, the metadata should still distinguish category `Active / Network`.

Job table behavior:

- Target column should show the redacted `target_url` or `summary.target_display`.
- File ID should remain `N/A` because the job is target-based.
- Summary should prefer:
  - `allowed`;
  - `planned_checks_count`;
  - `blocked_reasons_count`;
  - `network_requests_sent`;
  - first few `blocked_reason_codes`.
- Filters should include `active_network_dry_run`.
- Search should match audit label, category, target display, status, and blocked reason codes where practical.
- It must not appear in archive action groups.

## J. API Frontend Helper Future

Future helper:

```ts
createActiveNetworkDryRun(request)
```

Endpoint:

```text
POST /active/network/dry-run
```

API helper requirements:

- Use `content-type: application/json`.
- Reuse `parseJsonResponse`.
- Return `JobRecord`.
- Surface `403` as the controlled disabled state.
- Do not send unknown fields.
- Do not infer missing authorization.
- Do not read environment files or browser storage for targets.

## K. Request Object Frontend

Future request body:

```json
{
  "target": "https://example.test",
  "authorization": {
    "confirmed": true,
    "statement": "I confirm I own or am authorized to test this target.",
    "scope": "single-target"
  },
  "mode": "dry_run",
  "profile": "http_header_probe_preview",
  "limits": {
    "max_requests": 0,
    "timeout_seconds": 0,
    "max_redirects": 0,
    "response_size_bytes": 0
  }
}
```

Frontend should not send:

- unknown top-level fields;
- unknown authorization fields;
- unknown limits fields;
- editable live mode;
- editable nonzero limits;
- Nmap-like profile names;
- archive `file_id`.

## L. Error States

Future controlled error states:

- disabled backend:
  - `Active dry-run checks are disabled in this environment.`
- validation error:
  - show backend detail if safe and redacted;
  - do not include raw secret-bearing target text.
- target blocked:
  - `Target blocked by safety policy.`
  - show reason codes and safe messages.
- authorization missing:
  - `Authorization confirmation is required.`
- network disabled by policy:
  - `Dry-run limits keep network requests at zero.`
- job failed controlled:
  - `The job failed in a controlled state.`
- sparse/malformed result:
  - `Some result fields are unavailable; showing available redacted data.`

Do not provide remediation that teaches how to reach blocked target classes.

## M. Redaction UX

Required redaction surfaces:

- target input warnings;
- created job response;
- job table target display;
- report sections;
- errors;
- audit log;
- Redacted Raw JSON.

Required copy:

```text
Sensitive-looking target values are redacted in results, exports, and raw JSON. Redacted values use [REDACTED].
```

Redaction behaviors:

- URL credentials are rejected and must not be displayed raw.
- Sensitive query parameters are redacted.
- Authorization headers, bearer/basic tokens, passwords, API keys, client secrets, and private key blocks are redacted.
- The original typed input may contain sensitive data; users should not enter secrets.
- Do not show raw userinfo.
- Do not show prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers.

## N. Future Tests

Future frontend tests:

- form renders with dry-run/no-network copy;
- submit disabled without target;
- submit disabled without authorization;
- request body has `mode: dry_run`;
- request body has `profile: http_header_probe_preview`;
- request body has zero limits;
- endpoint `POST /active/network/dry-run` is called when form is valid;
- disabled `403` state is shown safely;
- `active_network_dry_run` appears in audit catalog and filters;
- job table renders active target summary without file/archive source;
- report renders `No network traffic was sent`;
- report renders target summary, authorization summary, policy decision, planned checks, blocked reasons, limits, audit log, errors, and Redacted Raw JSON;
- blocked target report shows safe reason codes;
- queued/running/failed/sparse/malformed states do not break;
- Raw JSON is redacted;
- DOM does not contain fixture secrets such as URL userinfo, bearer token, password, API key, private key text, or sensitive query values;
- controlled copy does not contain forbidden product-action words;
- no archive actions are involved;
- no Nmap wording appears except no-scope documentation when necessary.

Suggested test files:

- `frontend/src/ActiveDryRunJobReport.test.tsx`
- `frontend/src/App.test.tsx`
- `frontend/src/dashboardFilters.test.ts`
- `frontend/src/reportHelpers.test.ts` or the future active report helper test file

## O. No-Scope

This design phase does not:

- implement frontend UI;
- add an API helper;
- call the backend endpoint;
- create jobs;
- change backend behavior;
- change runner behavior;
- modify `tools/runner/main.py`;
- execute live probes;
- resolve DNS;
- perform HTTP requests;
- open sockets;
- run Nmap;
- run port checks;
- add file/archive actions;
- read `.env`, `.env.*`, or `.envrc`;
- add real network runtime;
- add bypass guidance;
- claim exploitability, compromise, target safety, or credential validity.

## P. Decision

Final decision:

```text
ACTIVE_DRY_RUN_FRONTEND_DESIGNED_NO_UI_RUNTIME
```

Meaning:

- UI placement is designed.
- Form and authorization UX are designed.
- Disabled-state UX is designed.
- Copy rules are designed.
- Target summary UX is designed.
- Report UX is designed.
- Job table/filter/catalog expectations are designed.
- API helper and request object shape are designed.
- Error and redaction UX are designed.
- Future tests are listed.
- No frontend runtime was implemented.
- No backend or runner code changed.
- No network behavior exists.

Next recommended microphase:

```text
ACTIVE-NETWORK-BLOCK-08-DRY-RUN-FRONTEND-IMPLEMENTATION-NO-NETWORK
```

Alternative if product wants another design review first:

```text
ACTIVE-NETWORK-BLOCK-08-DRY-RUN-FRONTEND-CONTRACT-REVIEW
```
