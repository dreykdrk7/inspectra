# Active Nmap Basic No-Live E2E Product Smoke

Decision:

`ACTIVE_NMAP_BASIC_53_ACTIVE_NMAP_NO_LIVE_E2E_PRODUCT_SMOKE_PASSED`

## Objective

Validate the integrated Active / Nmap basic product flow while it remains
strictly no-live:

1. frontend submits the bounded `active_nmap_basic` contract;
2. backend `POST /active/network/nmap-basic` accepts only the gated,
   confirmed request;
3. backend creates an owner-scoped `JobRecord` with `file_id: null`;
4. frontend refreshes the job list and selects the returned job;
5. detail, report, and Raw JSON rendering keep no-live caveats and redaction;
6. wrong-owner backend surfaces remain generic.

This smoke does not approve live execution. It validates the product wiring for
the no-live lifecycle record only.

## Scope

- Backend API smoke with in-process `ASGITransport`.
- Frontend App flow smoke with mocked `fetch`.
- Contract alignment for:
  - `mode: live_nmap_basic`;
  - `profile: tcp_connect_small`;
  - one synthetic target fixture;
  - bounded integer TCP ports;
  - all three confirmations set to `true`.
- Existing backend job detail, list, Raw JSON-style API output, and existing
  report/export routes.
- Existing frontend panel, job list refresh, selected job report, and defensive
  Raw JSON rendering.
- Documentation of this microphase.

## No-Scope

- No Nmap execution or local version probe.
- No Docker or Compose.
- No real `active-tools` call.
- No real backend-to-`active-tools` `/active/nmap-basic` call.
- No probes, DNS checks, external HTTP, VPS, LAN, or real-domain activity.
- No real targets beyond synthetic fixtures in mocked/in-process tests.
- No backend runtime expansion beyond already integrated no-live behavior.
- No frontend product expansion beyond existing no-live rendering.
- No new exports, archive/run-all integration, `tools/runner/main.py`
  integration, migrations, release, tag, or push.

## Backend Smoke Evidence

The focused backend product smoke asserts:

- feature disabled rejects without creating a job;
- valid enabled synthetic request returns `202 JobRecord`;
- `audit_type` is `active_nmap_basic`;
- `file_id` is `null`;
- `target_url` is `[REDACTED_TARGET]`;
- result status is `not_executed`;
- lifecycle state is `completed_no_live`;
- Nmap execution, subprocess, network requests, DNS queries, target expansion,
  evidence, and observations are all absent or zero;
- list/detail/report surfaces include:
  - `No Nmap executed`;
  - `No network requests`;
  - `No DNS queries`;
  - `No evidence collected`;
  - `No observations available`;
  - `Manual validation required`;
  - `No-live lifecycle record, not a target finding`;
- raw target, raw payload, command/argv, stdout/stderr, XML, PTR/resolved IP,
  banner/version/service details, credentials, headers, cookies, tokens,
  observations, evidence, and port observations are omitted from public no-live
  result rendering;
- wrong-owner list/detail/delete/export access remains generic and does not
  disclose the wrong-owner job.

## Frontend Smoke Evidence

The frontend App smoke asserts:

- the user can enter a synthetic target and bounded TCP ports;
- all three confirmations are required before submit;
- submit sends exactly the backend contract body;
- the `202 JobRecord` response is selected;
- jobs are refreshed after creation;
- the Active / Nmap basic report renders the no-live lifecycle state;
- Raw JSON rendering is redacted-first;
- raw target, raw payload, command, output, XML, service details, credential,
  header, cookie, token, observation, and evidence fixture values are not shown;
- no-live caveats remain visible.

The UI treats `completed_no_live` as lifecycle completion only, not live
execution. `not_executed`, `client_error_controlled`, and
`unsafe_lifecycle_result` remain controlled states.

## Validation Commands

The microphase validation set is:

```text
git status --short --branch
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap_basic_no_live_product_smoke or active_nmap_basic_no_live_job_surfaces or active_nmap_basic_enabled_route_persists or active_nmap_basic_route_returns_job_id_and_redacted_raw_json or active_nmap_basic_wrong_owner"
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic"
.venv/bin/python -m pytest backend/tests/test_active_nmap_policy.py
.venv/bin/python -m pytest backend/tests
npm run test -- --run ActiveNmapBasicPanel ActiveNmapBasicJobReport App
npm run test:run
npm run build
git diff --check
git diff --cached --check
guardrail source searches for execution, Docker/Compose, active-tools real calls,
DNS/probe/external HTTP behavior, archive/run-all, tools-runner integration, raw
target/output/evidence leakage, and prohibited live-execution wording
git status --short --branch
```

## Acceptance

The no-live product flow is accepted when backend and frontend focused smokes,
related active-nmap tests, full backend tests, full frontend tests, build,
diff checks, and guardrail searches pass without live execution or external
traffic.

This decision freezes the current state as:

`ACTIVE_NMAP_BASIC_53_ACTIVE_NMAP_NO_LIVE_E2E_PRODUCT_SMOKE_PASSED`
