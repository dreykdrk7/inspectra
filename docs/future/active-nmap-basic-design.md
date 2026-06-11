# Active Nmap Basic Design

Status: `ACTIVE_NMAP_BASIC_DESIGN_FROZEN`

This document freezes a docs-only design for a possible future
`active_nmap_basic` capability. It does not implement backend runtime,
frontend runtime, runner behavior, Docker changes, migrations, tags, releases,
live probes, DNS checks, external HTTP checks, or Nmap execution.

The purpose of this design is to decide whether Inspectra can ever expose a
small Nmap-backed workflow without turning into an arbitrary internet scanner
or scan-as-a-service product. Any future implementation must be separately
scoped, reviewed, tested, and closed before it can ship.

## Background

Passive Alpha `v0.1.0-alpha.1` is published. The post-release pause is recorded
as `PASSIVE_ALPHA_POST_RELEASE_TECHNICAL_PAUSE_RECORDED` in
`docs/future/passive-alpha-post-release-technical-pause.md`.

The existing Active line is intentionally narrow:

- `active_network_dry_run` performs no network traffic.
- `active_http_header_probe` is opt-in, disabled by default, explicitly
  authorized, double-confirmed, and capped to one HTTP `HEAD` request.
- Nmap, port scanning, crawling, credential validation, exploitation, and
  broader Active behavior remain unimplemented.

This document keeps that separation. It designs a future capability only; it
does not approve runtime work.

## Objective

`active_nmap_basic` would provide a bounded, defensive, local/private/self-hosted
port exposure review for explicitly authorized targets. The intended output is a
small set of observed TCP port-state indicators, suitable for manual review by a
trusted operator.

The capability is not intended to prove exploitability, validate credentials,
identify confirmed vulnerabilities, inventory the internet, discover unknown
assets, or replace a professional network assessment.

## Docs-Only Scope

This microphase allows only:

- this design document;
- optional references from `README.md`, `docs/architecture.md`, and
  `docs/security-scope.md`;
- docs-only validation commands;
- one final docs commit.

This microphase does not:

- run Nmap;
- run Docker;
- run probes;
- run DNS checks;
- run external HTTP checks;
- read or print `.env`, `.env.*`, or `.envrc` contents;
- modify backend runtime;
- modify frontend runtime;
- modify runners;
- create migrations;
- create a tag;
- create a release;
- add functional behavior.

## Allowed Future Scope

A future `active_nmap_basic` implementation may be considered only if all of
these remain true:

- The feature is disabled by default.
- The feature requires explicit operator opt-in.
- The feature is limited to local/private/self-hosted use.
- Every target is explicitly supplied by the operator.
- Every target requires an explicit authorization assertion.
- The target set is small and bounded.
- The port set is small and bounded.
- The command is generated from a server-side allowlist.
- The runner executes Nmap without a shell.
- Output is parsed into bounded structured observations.
- Reports use review-indicator wording, not confirmed-vulnerability wording.
- Redaction is applied before storage, API responses, reports, exports, UI, and
  Raw JSON.

The first acceptable profile is a TCP connect exposure review for a small port
set. It may report that Nmap observed a TCP port as open, closed, or filtered.
It must not add service-version detection, OS detection, NSE scripts, UDP scans,
credential checks, brute-force checks, exploit checks, crawling, discovery
sweeps, or target expansion.

## Explicit No-Scope

`active_nmap_basic` must not include:

- arbitrary internet scanning;
- scan-as-a-service or public scanner behavior;
- public/community hosted scanner operation;
- SaaS, billing, quotas, subscriptions, paid plans, or tenant billing;
- broad ranges;
- CIDR blocks;
- IP ranges such as `192.0.2.1-254`;
- wildcard targets;
- target files such as Nmap `-iL`;
- generated targets;
- DNS expansion;
- reverse DNS sweeps;
- subdomain discovery;
- Certificate Transparency lookup;
- AXFR or zone-transfer attempts;
- crawling;
- web spidering;
- URL discovery;
- UDP scans;
- SYN/stealth scans;
- FIN, NULL, Xmas, ACK, window, Maimon, idle, SCTP, or IP protocol scans;
- OS detection;
- service/version detection in v0;
- traceroute;
- packet tracing;
- decoys;
- spoofed source addresses;
- spoofed MAC addresses;
- source-port tricks;
- fragmentation;
- payload padding;
- timing modes intended for stealth or evasion;
- aggressive Nmap mode;
- default NSE scripts;
- custom NSE scripts;
- custom script arguments;
- exploit scripts;
- brute force;
- fuzzing;
- password spraying;
- credential validation;
- token, cookie, key, or session validation;
- authentication attempts;
- exploit payloads;
- destructive checks;
- denial-of-service or stress behavior;
- long-running reconnaissance;
- custom raw Nmap flags;
- shell command entry by the user;
- upload-driven target extraction;
- archive action integration;
- run-all integration;
- passive runner integration in `tools/runner/main.py`.

If a future use case needs any item above, it requires a separate docs-first
design and a separate safety review.

## Authorization Model

Authorization must be treated as a runtime precondition, not copy alone.

Minimum future requirements:

- `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=false` by default.
- A future implementation may create jobs only when the flag is explicitly
  enabled by the operator.
- Auth-required modes must deny anonymous requests before target validation or
  runner calls.
- Jobs must be owner-scoped like other target-based jobs.
- The request must include an explicit authorization confirmation.
- The request must include an explicit local/private/self-hosted scope
  confirmation.
- The request must include an explicit live-traffic confirmation.
- The UI must require separate controls for authorization and live traffic.
- The stored job metadata must record that confirmations were supplied, without
  treating them as proof of ownership.
- Blocked targets must fail closed before Nmap is invoked.

Recommended confirmation fields:

```json
{
  "authorization_confirmed": true,
  "local_private_scope_confirmed": true,
  "live_traffic_confirmed": true
}
```

Reports must still state that authorization is a user assertion and that target
logs may record the scan traffic.

## Target Limits

The future target model must be explicit-host only. It must not accept ranges,
CIDR blocks, wildcards, lists pasted into one field, or uploaded target files.

Recommended v0 limits:

- maximum targets per job: `3`;
- default targets per job: `1`;
- maximum normalized target length: `253` characters;
- maximum explicit ports per target: `32`;
- maximum total target-port checks per job: `96`;
- maximum concurrent target executions per job: `1`;
- maximum active Nmap jobs per owner: `1`;
- no target expansion after submission;
- no generated hostnames;
- no generated IP addresses.

Allowed target classes should be limited to explicitly authorized
local/private/self-hosted systems. Public IP/FQDN scanning must not be enabled
as arbitrary internet scanning. If a future implementation ever supports an
operator-owned public host, it should require an explicit deployment allowlist or
a separate design; it must not be available through free-form public targets.

Targets that must fail closed:

- cloud metadata endpoints;
- multicast, broadcast, benchmark, documentation, and other special-purpose
  ranges that are not meaningful operator-owned targets;
- userinfo-bearing values;
- URLs with paths, queries, or fragments;
- root domains submitted for discovery;
- hostnames containing wildcards;
- comma-separated or whitespace-separated target lists;
- any target whose validation is ambiguous.

Forward resolution for exact host validation, if needed, must not become DNS
expansion. Reverse DNS, sibling lookup, search suffix expansion, and discovery
queries are out of scope. The generated Nmap command should suppress reverse DNS
where supported.

## Command And Flag Limits

The future backend and runner must not expose raw Nmap arguments. A structured
profile must be converted into a fixed argv list by trusted code.

The only acceptable v0 profile is conceptually:

```text
profile: tcp_connect_small
scan family: TCP connect
host discovery: disabled
reverse DNS: disabled
ports: built-in small top-port set or explicit allowlisted small port list
output: machine-readable stdout for parser consumption
```

A conceptual argv shape may look like:

```text
nmap -sT -Pn -n --max-retries 1 --host-timeout 30s --top-ports 20 -oX - -- <target>
```

That example is not an implementation contract. The future implementation must
choose exact flags during implementation review, but the allowlist must preserve
these principles:

- use an argv array, not a shell;
- pass targets after an end-of-options marker where supported;
- reject user-supplied raw flags;
- reject user-supplied script paths;
- reject user-supplied command templates;
- reject user-supplied environment overrides;
- reject any option that enables stealth, evasion, brute force, exploitation,
  credential validation, crawling, broad discovery, or output bloat.

Forbidden Nmap features include, at minimum:

- `-A`;
- `-O`;
- `-sV`;
- `-sC`;
- `-sS`;
- `-sU`;
- `-sN`;
- `-sF`;
- `-sX`;
- `-sA`;
- `-sW`;
- `-sM`;
- `-sI`;
- `-sY`;
- `-sZ`;
- `-sO`;
- `-sn`;
- `--script`;
- `--script-args`;
- `--script-updatedb`;
- `--traceroute`;
- `--packet-trace`;
- `-iL`;
- `--exclude-file`;
- `--randomize-hosts`;
- `-D`;
- `-S`;
- `--spoof-mac`;
- `-f`;
- `--mtu`;
- `--data-length`;
- `--source-port`.

Port selection must be bounded by trusted code:

- default to a small built-in top-port profile;
- optionally allow an explicit list of numeric TCP ports;
- reject port ranges such as `1-65535`;
- reject service names;
- reject protocols other than TCP;
- reject duplicate-expanded lists over the configured maximum.

## Time Limits

Timeouts must be short and layered.

Recommended v0 limits:

- per-target Nmap host timeout: `30` seconds;
- overall runner deadline: `120` seconds;
- backend call timeout: runner deadline plus a small fixed margin;
- subprocess kill grace period: `2` seconds;
- max retries: `1`;
- no scan-delay values that intentionally slow a scan for stealth;
- no retry or resume behavior after a timed-out job.

Timeouts should produce controlled `blocked`, `failed`, or `completed_truncated`
states with structured limits metadata. They must not leak raw command lines,
environment values, host paths, or unbounded stderr.

## Output Limits

Output must be bounded before and after parsing.

Recommended v0 limits:

- maximum raw stdout bytes accepted from Nmap: `128 KiB`;
- maximum stderr bytes retained after redaction: `8 KiB`;
- maximum parsed port observations per job: `96`;
- maximum findings or review indicators: `50`;
- maximum audit-log entries: `50`;
- maximum report table rows for port observations: `96`;
- maximum Raw JSON display for Nmap-specific output: bounded and redacted;
- no unbounded raw Nmap XML in reports.

If Nmap output exceeds limits, the future runner must truncate, mark
`output_truncated=true`, and avoid partial parsing that creates misleading
certainty.

## Storage Limits

`active_nmap_basic` results are sensitive network inventory. A future
implementation must reuse owner-scoped job storage and deletion behavior.

Minimum storage rules:

- create target-based jobs with `file_id: null`;
- store `audit_type: active_nmap_basic`;
- store normalized target display values only as needed for the job and UI;
- store profile name and effective limits, not a free-form command string;
- store parsed port observations and bounded audit metadata;
- avoid storing full raw Nmap output by default;
- redact and truncate any retained stdout/stderr snippets;
- do not create target history unless separately designed;
- do not create migrations without a separate implementation phase;
- do not store secrets, credentials, cookies, tokens, or authorization material.

Manual downloads, browser caches, backups, snapshots, and target-side logs remain
outside app-side cleanup control and must be called out in operator copy.

## Evidence Redaction

Evidence should be useful without becoming a data leak.

Redaction must cover:

- target display in job lists;
- raw target strings in errors;
- command-line fragments;
- stderr;
- XML parse errors;
- hostnames or addresses embedded in Nmap messages;
- service banners if they ever appear accidentally;
- credentials, tokens, cookies, userinfo, private keys, and sensitive query-like
  values in any malformed payload;
- backend summaries;
- `GET /jobs`;
- `GET /jobs/{job_id}`;
- Markdown, HTML, XML, and PDF exports;
- frontend report DOM;
- frontend Raw JSON.

The fixed placeholder remains:

```text
[REDACTED]
```

The future implementation must not intentionally emit secret prefixes, suffixes,
hashes, fingerprints, or reversible identifiers.

## Safe Report Wording

Reports must describe results as observations and review indicators.

Preferred wording:

- "Observed exposure"
- "Review indicator"
- "Nmap reported this TCP port as open during a bounded authorized scan."
- "This may be expected for the service. Review whether it matches your intended
  exposure."
- "Manual validation is required."
- "No confirmed vulnerability is asserted."

Forbidden wording:

- "confirmed vulnerability";
- "exploitable";
- "compromised";
- "breached";
- "credential is valid";
- "target is safe";
- "secure";
- "Nmap found all open ports";
- "full network scan";
- "internet scan";
- "attack path confirmed";
- "proof of exploitability".

Open ports must not automatically map to high severity. The initial severity
model should default to informational or review-needed unless a separate passive
policy layer is designed.

## Abuse Threats

Primary abuse risks:

- arbitrary internet scanning from a self-hosted instance;
- internal reconnaissance against networks the operator does not own;
- cloud metadata or infrastructure control-plane probing;
- target expansion through CIDR, ranges, wildcards, DNS, or target files;
- stealth or evasion flag abuse;
- NSE script abuse;
- brute-force or credential-validation misuse;
- resource exhaustion through many targets, ports, jobs, or long timeouts;
- report overclaiming that turns observations into vulnerability claims;
- sensitive network inventory leaking through logs, Raw JSON, exports, or
  screenshots.

Required mitigations:

- disabled-by-default feature flag;
- authenticated and owner-scoped access in auth-required modes;
- explicit authorization and live-traffic confirmations;
- local/private/self-hosted framing;
- target-policy fail closed;
- small target and port limits;
- one active job per owner;
- no raw flags;
- Nmap command allowlist;
- no shell execution;
- no NSE scripts;
- no stealth, evasion, brute force, exploit, or credential features;
- short timeouts;
- output truncation;
- layered redaction;
- conservative wording;
- focused tests and no-scope searches before closeout.

## Expected UX

The future UI should be separate from passive archive/file actions and separate
from the existing Active dry-run and HTTP header probe panels.

Expected behavior:

- show disabled-state copy when the feature flag is off;
- identify the feature as `Active / Nmap basic`;
- present a single small target form by default;
- allow adding targets only up to the configured maximum;
- provide only approved profile choices;
- show the effective target count, port count, timeout, and output limits before
  submission;
- require an authorization checkbox;
- require a local/private/self-hosted scope checkbox;
- require a live-traffic checkbox;
- avoid "scan the internet", "find assets", or "full vulnerability scan" copy;
- exclude the action from archive cards and run-all flows;
- display target values conservatively in job tables;
- render reports as observed exposure and review indicators;
- show truncation, timeout, blocked, sparse, and malformed states clearly;
- keep Raw JSON redacted and labeled as sensitive diagnostic data.

## Conceptual API Shape

This is a design shape only. It does not create an endpoint.

Possible future backend endpoint:

```text
POST /active/network/nmap-basic
```

Possible request body:

```json
{
  "mode": "live_nmap_basic",
  "profile": "tcp_connect_small",
  "targets": ["192.168.56.10"],
  "ports": [22, 80, 443],
  "authorization_confirmed": true,
  "local_private_scope_confirmed": true,
  "live_traffic_confirmed": true
}
```

Possible job metadata:

```json
{
  "audit_type": "active_nmap_basic",
  "file_id": null,
  "target_kind": "host",
  "target_count": 1,
  "profile": "tcp_connect_small",
  "limits": {
    "max_targets": 3,
    "max_ports_per_target": 32,
    "max_total_target_port_checks": 96,
    "host_timeout_seconds": 30,
    "runner_deadline_seconds": 120,
    "max_stdout_bytes": 131072
  }
}
```

Possible result shape:

```json
{
  "tool": "nmap",
  "capability": "active_nmap_basic",
  "profile": "tcp_connect_small",
  "network_requests_sent": null,
  "targets_reviewed": 1,
  "port_observations": [
    {
      "target": "[REDACTED]",
      "port": 443,
      "protocol": "tcp",
      "state": "open",
      "evidence": "Nmap reported 443/tcp open during bounded TCP connect review."
    }
  ],
  "findings": [
    {
      "severity": "info",
      "title": "Observed TCP exposure",
      "description": "Review whether the observed open TCP port matches intended exposure."
    }
  ],
  "limits": {
    "output_truncated": false,
    "timed_out": false
  }
}
```

`network_requests_sent` may be hard to count accurately for Nmap. A future
implementation should either omit it or report an explicitly approximate
bounded-probe metric. It must not invent precise request counts.

## Conceptual Runner Shape

The future runner work must stay in the separate Active runner line, not in the
passive runner monolith.

Required runner principles:

- live under `tools/active_runner/` or a separately reviewed Active runner
  location;
- expose a structured internal handler, not a raw shell command endpoint;
- validate feature profile, target policy, limits, and confirmations before
  invoking Nmap;
- generate argv from an allowlist;
- execute without a shell;
- apply subprocess timeouts;
- parse machine-readable output;
- redact before returning JSON;
- return controlled blocked/failed/truncated results;
- never call passive archive/file analyzer code paths;
- never read `.env`, `.env.*`, or `.envrc` contents.

## Future Tests

A future implementation must include focused tests before any closeout.

Backend/API tests:

- disabled flag rejects without creating a job;
- enabled flag creates `active_nmap_basic` only with all confirmations;
- anonymous requests in auth-required modes fail before target validation;
- owner metadata is written;
- owner-scoped reads, reports, exports, and Raw JSON are enforced;
- broad ranges, CIDR, wildcards, target files, URLs, public scanner patterns, and
  ambiguous targets are rejected;
- excessive targets and ports are rejected;
- request bodies cannot pass raw Nmap flags;
- no archive action or run-all path can launch the job;
- summaries, job detail, and exports are redacted.

Runner tests:

- command builder emits only allowlisted argv;
- command builder uses no shell;
- forbidden flags and profiles are rejected;
- NSE, stealth, evasion, UDP, OS detection, service detection, brute force,
  exploit scripts, credential validation, crawling, and DNS expansion are absent;
- target policy fails closed before subprocess execution;
- timeout handling kills the subprocess and returns controlled output;
- stdout/stderr byte limits truncate safely;
- XML parse failures return controlled errors;
- redaction covers target strings, command fragments, errors, and malformed
  payloads.

Frontend tests:

- disabled-state copy renders;
- separate Active / Nmap basic panel exists;
- confirmations gate submit;
- exact request body is sent;
- target/port limit copy is visible;
- job catalog and filters label `active_nmap_basic` without archive integration;
- report renders completed, blocked, failed, timed-out, truncated, sparse, and
  malformed payloads;
- Raw JSON and report DOM are redacted;
- forbidden wording is absent.

Validation searches:

- no "confirmed vulnerability" wording for Nmap reports;
- no "exploit", "brute force", "credential valid", "crawl", "public scanner",
  "scan the internet", or "full network scan" promises;
- no runtime Nmap command outside the reviewed Active runner path;
- no passive runner integration for Nmap.

## Future Implementation Acceptance Criteria

A future implementation may be accepted only when:

- docs are updated before runtime expansion;
- the feature remains disabled by default;
- explicit opt-in is required;
- local/private/self-hosted use is clear;
- target authorization is explicitly confirmed;
- target policy blocks arbitrary internet scanning;
- target count is bounded;
- port count is bounded;
- timeouts are bounded;
- output is bounded;
- storage is bounded and owner-scoped;
- command construction is allowlisted;
- raw user flags are impossible;
- no stealth, evasion, aggressive NSE defaults, brute force, exploit scripts,
  credential validation, crawling, DNS expansion, or custom scripts are present;
- report wording uses observed exposure and review indicator language;
- API, exports, UI, Raw JSON, errors, and logs are redacted;
- tests cover disabled/enabled behavior, rejection paths, command generation,
  timeout/output handling, redaction, and report copy;
- validation confirms no broad scanning, exploit, brute-force, credential
  validation, crawling, SaaS, or public scanner claims were introduced;
- a separate closeout records evidence without running external unauthorized
  traffic.

## Final Decision

```text
ACTIVE_NMAP_BASIC_DESIGN_FROZEN
```

`active_nmap_basic` is accepted as a bounded docs-first design only. Runtime,
backend, frontend, runner, migration, Docker, tag, release, Nmap execution,
probes, DNS checks, external HTTP checks, public scanner behavior, arbitrary
internet scanning, and broad Active expansion remain out of scope until a
separate implementation microphase is explicitly approved.
