# Active Nmap Basic Real Minimal Integration

Decision:

```text
ACTIVE_NMAP_BASIC_54_ACTIVE_TOOLS_REAL_NMAP_MINIMAL_INTEGRATION_PASSED
```

## Objective

Complete the minimal functional `active_nmap_basic` path:

1. frontend submits the bounded `live_nmap_basic` / `tcp_connect_small`
   contract;
2. backend validates auth, owner scope, request shape, target policy, and
   internal approval;
3. backend calls the configured internal `active-tools` service;
4. `active-tools` runs the bounded Nmap executor only when explicitly enabled;
5. backend persists a redacted owner-scoped `JobRecord`;
6. frontend renders observations only as observed TCP exposure / review
   indicators requiring manual validation.

The default backend feature flag remains disabled. The default `active-tools`
ASGI app remains disabled for Nmap execution unless
`INSPECTRA_ACTIVE_TOOLS_NMAP_BASIC_EXECUTION_ENABLED` is explicitly enabled
inside the active-tools runtime.

## Implemented Path

Backend:

- `POST /active/network/nmap-basic` still requires
  `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=true`.
- The route validates the existing bounded request contract and target policy
  before lifecycle invocation.
- Runtime uses an internal `active_tools_real` lifecycle client by default
  when configured, while tests can still inject the legacy no-live client.
- Backend does not invoke subprocesses, import the active runner executor, run
  Docker, or execute Nmap.
- Persisted jobs remain owner-scoped, target-redacted, `file_id: null`, and
  bounded.

Active-tools:

- `GET /health` remains targetless and reports either `disabled_no_scan` or
  `ready_bounded_execution`.
- `POST /active/nmap-basic` stays no-live by default.
- When explicitly enabled inside active-tools, it accepts only the backend
  boundary payload, builds the allowlisted `tcp_connect_small` command, invokes
  Nmap with `shell=False`, parses bounded XML output, and returns only minimal
  structured TCP observations.
- It does not accept raw flags, scripts/NSE, credentials, headers, cookies,
  tokens, target files, custom profiles, shell commands, broad ranges, target
  expansion, DNS expansion, service/version detection, OS detection, UDP/SYN,
  brute force, exploit scripts, crawling, or public-scanner behavior.

Frontend:

- The Active / Nmap basic panel now treats a returned real-minimal job as a
  bounded lifecycle record, not as a vulnerability finding.
- The UI displays `completed_real_minimal` as "Observed TCP exposure / review
  indicator" with manual validation required.
- No raw target, command, XML, stdout/stderr, PTR/resolved IP, banner, version,
  service detail, credential, header, cookie, token, or evidence blob is
  displayed.

## Storage And Reporting

Real-minimal jobs may persist:

- capability/mode/profile;
- lifecycle state `completed_real_minimal`;
- target kind;
- bounded counts;
- execution flags that distinguish backend from active-tools subprocess use;
- minimal `port_observations` with `port`, `protocol`, `state`, optional
  controlled `reason`, `manual_validation_required`, and
  `result_interpretation: observed_exposure_review_indicator`;
- controlled warnings/errors.

They do not persist raw target, raw payload, argv, command string, stdout,
stderr, XML, PTR hostname, resolved IP, banners, versions, service details,
credentials, headers, cookies, tokens, or vulnerability claims.

Report/export/Raw JSON surfaces keep target display as `[REDACTED_TARGET]` and
word observations as review indicators. `completed_real_minimal` is not a
confirmed vulnerability, exploitability claim, target-safety statement,
complete-coverage statement, full scan, or all-ports-found claim.

## Guardrails Preserved

- disabled by default;
- explicit opt-in;
- local/private/self-hosted scope only;
- authorized targets only;
- no arbitrary internet scanning;
- no broad ranges, CIDR expansion, wildcards, target files, or fanout;
- no stealth/evasion;
- no raw user flags;
- no NSE or `--script`;
- no service/version detection or OS detection;
- no UDP/SYN scan;
- no brute force, exploit scripts, credential validation, crawling, or DNS
  expansion;
- no backend subprocess;
- no Docker socket or backend-managed container execution;
- no archive/run-all integration;
- no `tools/runner/main.py` integration;
- bounded backend-to-active-tools timeout;
- bounded active-tools process timeout;
- bounded stdout/stderr/response sizes;
- owner-scoped jobs and generic wrong-owner responses;
- observed exposure / review indicator wording only.

## Tests And Validation Evidence

Focused validations added or updated:

- backend active-tools client accepts real-minimal responses and rejects raw or
  policy-drift responses;
- backend lifecycle requires explicit real-client approval and normalizes
  completed real-minimal results;
- backend route persists real-minimal owner-scoped jobs through an injected
  active-tools client without backend subprocess use;
- backend list/detail/report surfaces expose only redacted review-indicator
  data;
- active-tools ASGI path runs only with an explicit execution flag and a fake
  subprocess runner in tests;
- active-tools maps missing Nmap to a controlled `nmap_missing` response;
- frontend panel distinguishes no-live records from real-minimal observation
  records.
- controlled real loopback smoke executed inside the existing active-tools
  image with the current `tools/` source mounted read-only, Docker
  `--network none`, exact target `127.0.0.1`, exact port `65000`, and
  active-tools execution explicitly enabled. The smoke returned one closed TCP
  observation with reason `conn-refused`, `target_input_allowed: false`,
  `job_created: false`, `target_expansion_performed: false`, no DNS expansion,
  and no raw XML/command/stdout/stderr in the response.

Validated commands include focused backend `active_nmap_basic` tests,
active-tools/nmap tests, focused frontend Active Nmap tests, compile checks,
frontend full tests, build checks, Compose config validation with env-file
loading disabled, diff checks, guardrail source searches, and the bounded
`127.0.0.1:65000` active-tools/container loopback smoke.

## Not Approved

This phase does not approve:

- arbitrary public targets;
- SaaS/public scanner behavior;
- broad scanning, top-ports discovery, `-p-`, CIDR/range expansion, or target
  files;
- domains or LAN/VPS targets beyond separately frozen/authorized smokes;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- backend direct subprocess/Nmap execution;
- raw Nmap output storage;
- vulnerability, exploitability, target-safety, complete-coverage,
  full-network-scan, or all-ports-found claims;
- release, tag, or push state.

## Final Decision

```text
ACTIVE_NMAP_BASIC_54_ACTIVE_TOOLS_REAL_NMAP_MINIMAL_INTEGRATION_PASSED
```
