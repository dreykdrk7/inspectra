# Active Nmap Basic Backend Active Tools Boundary Design

Decision:

```text
ACTIVE_NMAP_BASIC_34_BACKEND_ACTIVE_TOOLS_BOUNDARY_DESIGN_ACCEPTED
```

This phase designs the future backend to `active-tools` boundary for
`active_nmap_basic`. It is documentation-only. It does not run Docker, run
Nmap, run `nmap --version`, perform probes, perform DNS checks, send external
HTTP traffic, run `curl`, open a browser, use Compose, change backend runtime,
change frontend runtime, change runner runtime, create migrations, create a tag,
create a release, add a runner HTTP endpoint, add backend-to-active-tools live
calls, create real jobs, create real exports, integrate archive/run-all,
integrate Active into `tools/runner/main.py`, approve new targets, approve
`www.vildek.es`, approve `app.vildek.es`, approve port `80`, or approve public
scanner behavior.

## Source Decisions

Accepted prior decisions:

```text
ACTIVE_NMAP_BASIC_30_ACTIVE_NMAP_V0_TECHNICAL_SMOKE_CLOSEOUT_ACCEPTED
ACTIVE_NMAP_BASIC_31_REAL_OUTPUT_REDACTION_HARDENING_DESIGN_ACCEPTED
ACTIVE_NMAP_BASIC_32_REAL_OUTPUT_PARSER_REDACTION_TESTS_NO_RUNTIME_ACCEPTED
ACTIVE_NMAP_BASIC_33_BACKEND_REPORT_REDACTION_REAL_SHAPE_NO_LIVE_ACCEPTED
```

Reference prior commit:

```text
60b170f test(active): harden backend nmap report redaction
```

## Boundary Objective

The future boundary must keep authority in the backend and execution in
`active-tools`.

Backend responsibilities:

- authentication and anonymous denial in auth-required modes;
- owner-scoped job creation, reads, reports, exports, and Raw JSON;
- request contract validation;
- target policy validation;
- feature flag gating;
- job lifecycle and storage;
- handoff shaping into bounded target units;
- response validation;
- redaction before storage, API, reports, exports, and Raw JSON;
- user-facing wording as observed exposure / review indicator only.

`active-tools` responsibilities:

- execute only the bounded `active_nmap_basic` executor;
- enforce its own defensive input contract even after backend validation;
- enforce process timeout, output limits, and resource bounds;
- return structured minimal results;
- avoid storing persistent artifacts by default;
- keep logs redacted.

`active-tools` must not:

- decide authorization or ownership;
- expand targets;
- expose a public scanner;
- integrate archive/run-all;
- integrate `tools/runner/main.py`;
- accept raw user flags, scripts, credentials, headers, cookies, tokens, or
  target files.

## Boundary Options

### Option A: Internal HTTP Service In A Private Docker Network

The backend calls an `active-tools` internal service over a private Docker
network. The service has no public host port, no host network, no Docker socket,
and no scanner-facing route beyond a small allowlisted contract.

Pros:

- clear process and dependency separation from backend;
- no Nmap package inside backend;
- easy to validate request/response schema at the boundary;
- easier to add health/readiness without running a scan;
- fits existing separate `active-tools` packaging direction;
- lets backend keep ownership, jobs, storage, reporting, and redaction.

Cons:

- requires future internal service code and runtime wiring;
- needs private-network and no-public-port review;
- requires timeout coordination across backend and `active-tools`;
- requires careful logging and response-size limits in two processes.

Recommendation: preferred future direction, provided all guardrails below are
met and a separate no-run skeleton phase lands before any live execution.

### Option B: CLI Or Container Job Invocation

The backend starts a container or CLI process for each unit and reads a
structured result.

Pros:

- simple conceptual lifecycle for one-shot jobs;
- can keep the process short-lived;
- avoids long-running service readiness concerns.

Cons:

- tempts backend Docker socket access or `docker exec`;
- couples backend to container runtime details;
- makes concurrency and cancellation harder;
- increases risk of leaking commands/stdout/stderr into backend logs;
- complicates local deployment and permissions.

Recommendation: not preferred for backend-managed execution. It may remain a
manual smoke pattern, but not a backend runtime boundary.

### Option C: Backend Direct Subprocess Or Import

The backend imports the executor or spawns Nmap directly.

Pros:

- smallest number of moving parts.

Cons:

- puts Nmap and active execution inside backend trust boundary;
- weakens dependency isolation;
- increases subprocess and shell-safety risk;
- makes resource controls harder to reason about;
- contradicts the separate `active-tools` direction;
- risks accidental integration with passive backend/runtime concerns.

Recommendation: rejected for real execution.

### Option D: Queue Or Internal Worker

The backend enqueues a bounded request for a private worker that owns
`active-tools` execution.

Pros:

- good future shape for backpressure, retries, and cancellation;
- can keep backend request latency low;
- can preserve process separation.

Cons:

- adds queue infrastructure and operational complexity;
- broadens failure modes;
- should not be introduced before the minimal boundary is understood.

Recommendation: possible later evolution after the internal service contract is
stable. It is not the first implementation path.

## Recommendation

Prefer an internal HTTP service, or equivalent private internal service boundary,
only if these conditions are true:

- disabled by default through the backend feature flag;
- no public host port;
- private internal network only;
- no host network;
- no privileged container;
- no Docker socket mounted into backend or `active-tools`;
- backend validates auth, ownership, request shape, confirmations, target
  policy, target count, port count, and target-port count before handoff;
- `active-tools` revalidates the bounded executor contract;
- backend and `active-tools` both enforce timeouts;
- backend and `active-tools` both enforce response/output byte limits;
- response is structured and minimal;
- logs are redacted;
- raw XML, raw args, stdout, stderr, PTR hostnames, FQDN resolved IPs, local
  paths, service/banner/version details, and script output are not returned to
  public backend surfaces.

Reject for real execution:

- backend direct subprocess execution;
- backend importing the active runner executor;
- backend invoking `docker exec`;
- backend controlling Docker through a mounted Docker socket;
- any public scanner style endpoint.

## Future Request Contract

The future backend to `active-tools` request should be one target unit per call.
Backend may create one owner-scoped job and split it into bounded units, but each
boundary request is a single target unit.

Required conceptual fields:

```json
{
  "mode": "live_nmap_basic",
  "profile": "tcp_connect_small",
  "request_id": "opaque-internal-id",
  "job_id": "opaque-internal-job-id",
  "correlation_id": "neutral-redacted-id",
  "target_unit": {
    "target": "backend-validated-target",
    "target_kind": "authorized_fqdn_or_container_loopback_or_private_ip",
    "accepted_ports": [443]
  },
  "confirmations_verified_by_backend": true,
  "limits": {
    "process_timeout_seconds": 20,
    "stdout_max_bytes": 131072,
    "stderr_max_bytes": 8192,
    "response_max_bytes": 32768
  }
}
```

The request must not include:

- raw flags;
- extra args;
- custom profiles;
- custom scripts;
- NSE options;
- credentials;
- headers;
- cookies;
- tokens;
- target files;
- target ranges or expansion requests;
- shell commands;
- user-facing authorization evidence.

Confirmations are already verified by backend. `active-tools` must not treat
confirmations as proof of ownership.

## Future Response Contract

The response should be structured, small, and safe to validate before storage.

Allowed statuses:

- `completed`;
- `failed`;
- `timed_out`;
- `nmap_missing`;
- `malformed`;
- `unsupported_shape`;
- `blocked`.

Conceptual shape:

```json
{
  "status": "completed",
  "profile": "tcp_connect_small",
  "target_kind": "authorized_fqdn",
  "manual_validation_required": true,
  "result_interpretation": "observed_exposure_review_indicator",
  "observations": [
    {
      "port": 443,
      "protocol": "tcp",
      "state": "open",
      "reason": "syn-ack",
      "manual_validation_required": true,
      "result_interpretation": "observed_exposure_review_indicator"
    }
  ],
  "output_truncated": false,
  "execution_metadata": {
    "executor": "active_nmap_basic",
    "nmap_invoked": true,
    "subprocess_invoked_inside_active_tools": true,
    "duration_ms": 1200
  },
  "warnings": [],
  "errors": []
}
```

The response must not include:

- raw XML;
- raw stdout;
- raw stderr;
- raw args;
- raw command;
- PTR hostnames;
- default visible resolved IP for FQDN targets;
- local paths;
- service/banner/version fields;
- script or NSE output;
- credentials, headers, cookies, or tokens;
- vulnerability, exploitability, target-safety, full-scan, or all-ports-found
  claims.

Backend must reject or redact unexpected fields before storage.

## Security Controls

`active-tools` runtime guardrails for future implementation:

- no public host port;
- private internal network only;
- no host network;
- non-root user;
- no privileged mode;
- no Docker socket;
- no unnecessary Linux capabilities;
- `no-new-privileges`;
- read-only filesystem where viable;
- tmpfs for temporary files;
- bounded memory and CPU;
- request body size limit;
- stdout and stderr byte limits;
- process timeout inside `active-tools`;
- host/backend timeout outside `active-tools`;
- response byte limit;
- no persistent artifacts by default;
- redacted structured errors;
- no shell execution;
- no raw user flags;
- no NSE or `--script`;
- no brute force, exploit scripts, credential validation, crawling, DNS
  expansion, or broad ranges.

## Logging

Backend and `active-tools` logs should use neutral correlation metadata:

- correlation id;
- request id;
- job id only if owner-safe in that log context;
- controlled status;
- duration and bounded counters;
- redacted error code.

Logs must not include:

- raw targets where avoidable;
- raw command;
- raw args;
- stdout or stderr;
- XML;
- PTR hostnames;
- resolved IP for FQDN targets;
- service/banner/version details;
- headers, cookies, tokens, or credentials;
- local paths from runtime internals.

Errors should be controlled codes such as `active_tools_unavailable`,
`active_tools_timeout`, `nmap_missing`, `malformed_output`,
`unsupported_shape`, `policy_drift`, `result_too_large`,
`unexpected_fields`, `network_failure`, or `fqdn_resolution_failed`.

## Job Lifecycle

Future lifecycle:

1. Backend receives `POST /active/network/nmap-basic`.
2. Backend checks feature flag, auth mode, owner context, request shape,
   confirmations, target policy, ports, and limits.
3. Backend creates an owner-scoped target job with `file_id: null` only after
   validation succeeds.
4. Backend builds one bounded handoff unit per allowed target.
5. Backend sends a single target unit to the private `active-tools` boundary.
6. `active-tools` executes only the bounded executor and returns structured
   minimal output.
7. Backend validates response status, fields, observation count, ports, and
   limits.
8. Backend redacts again before storage.
9. Backend exposes only redacted API, report, export, and Raw JSON surfaces.

Archive/run-all must never trigger Active Nmap. `tools/runner/main.py` remains
outside this path.

## Error Handling

Future controlled states:

- `active-tools unavailable`: backend marks controlled failure without leaking
  target details.
- `timeout`: backend and `active-tools` both enforce deadlines; result may be
  `timed_out` with bounded counters only.
- `nmap_missing`: returned when the tool is unavailable inside `active-tools`.
- `malformed output`: parser could not safely consume the output.
- `unsupported shape`: parser found multi-host, unexpected port, script/OS
  section, or other non-v0 shape.
- `policy drift`: `active-tools` rejects a unit that backend should not have
  sent, and backend records a controlled internal mismatch.
- `result too large`: backend rejects oversized responses and stores a bounded
  controlled state.
- `unexpected fields`: backend redacts or rejects fields outside the response
  allowlist.
- `network failure`: returned only as a controlled execution error, not as a
  vulnerability signal.
- `DNS failure for exact FQDN`: allowed only for the exact target when a future
  target freeze permits minimum FQDN resolution; no expansion follows.

All errors remain review indicators and must not imply target safety,
exploitability, or complete coverage.

## Target And DNS Policy

Backend remains the authority for target policy.

Still blocked:

- target expansion;
- CIDR or broad ranges;
- target files;
- arbitrary public targets;
- subdomain discovery;
- reverse-DNS sweep;
- DNS expansion;
- crawling;
- service/version detection;
- OS detection;
- scripts/NSE;
- brute force;
- credential validation.

An exact FQDN may require minimum DNS resolution only if a separately frozen
future target decision permits it. IP-freeze plus `-n` remains a future option
to avoid PTR output at source. This phase approves no new domains, does not
approve `www.vildek.es`, does not approve `app.vildek.es`, and does not approve
port `80`.

## Testing Roadmap

Recommended next phases:

1. No-live mocked boundary contract tests in backend only.
2. Internal service skeleton in `active-tools`, no scan and no Nmap execution.
3. Active-tools health/readiness endpoint that reports capability readiness
   without target input and without running Nmap.
4. Fake execution through the private boundary with synthetic structured
   responses.
5. Response allowlist and redaction regression tests across API, reports,
   exports, and Raw JSON.
6. One live execution behind explicit feature flags only, with a separately
   frozen target and no archive/run-all integration.

Each phase must keep Docker/Nmap/live behavior out of scope until explicitly
approved by that phase.

## Still Blocked

Still blocked after this design:

- implementing the `active-tools` endpoint;
- backend live calls to `active-tools`;
- Docker Compose runtime wiring;
- live Inspectra jobs from `active-tools`;
- exports from live execution;
- frontend live UX changes;
- new domains;
- `www.vildek.es`;
- `app.vildek.es`;
- port `80`;
- archive/run-all;
- `tools/runner/main.py` integration;
- public scanner behavior;
- release or tag state.

## Acceptance Criteria

This design is accepted when:

- the preferred boundary is documented as private internal service first;
- backend responsibilities and `active-tools` responsibilities are separated;
- backend direct subprocess/import and Docker socket control are rejected;
- request and response contracts are bounded and redaction-first;
- security, logging, job lifecycle, error handling, target/DNS policy, and test
  roadmap are documented;
- no runtime, Docker, Nmap, DNS, HTTP, Compose, backend live call, runner
  endpoint, job, export, archive/run-all, `tools/runner/main.py`, migration,
  tag, release, target approval, or public scanner behavior is added.

## Final Decision

```text
ACTIVE_NMAP_BASIC_34_BACKEND_ACTIVE_TOOLS_BOUNDARY_DESIGN_ACCEPTED
```
