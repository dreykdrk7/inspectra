# Active Nmap Basic V0 Technical Smoke Closeout

Decision:

```text
ACTIVE_NMAP_BASIC_30_ACTIVE_NMAP_V0_TECHNICAL_SMOKE_CLOSEOUT_ACCEPTED
```

This closeout consolidates the bounded technical smoke block for
`active_nmap_basic` after the `active-tools` packaging, no-target readiness,
Nmap version check, container-loopback smoke, and first own-domain authorized
smoke. It is documentation-only. It does not run Docker, run Nmap, perform DNS
checks, send HTTP traffic, probe targets, start Compose, wire backend calls,
create jobs, export results, add a runner HTTP endpoint, integrate
`tools/runner/main.py`, create migrations, create a tag, or create a release.

## Source Decisions

Accepted decisions consolidated here:

- `ACTIVE_NMAP_BASIC_23_ACTIVE_TOOLS_DOCKER_BUILD_ONLY_PASSED`
- `ACTIVE_NMAP_BASIC_24_ACTIVE_TOOLS_RUN_NO_TARGET_READINESS_PASSED`
- `ACTIVE_NMAP_BASIC_25_ACTIVE_TOOLS_NMAP_VERSION_NO_TARGET_PASSED`
- `ACTIVE_NMAP_BASIC_26_ACTIVE_TOOLS_LOCAL_SMOKE_TARGET_FREEZE_ACCEPTED`
- `ACTIVE_NMAP_BASIC_27_ACTIVE_TOOLS_CONTAINER_LOOPBACK_SMOKE_PASSED`
- `ACTIVE_NMAP_BASIC_28_OWN_DOMAIN_AUTHORIZED_SMOKE_TARGET_FREEZE_ACCEPTED`
- `ACTIVE_NMAP_BASIC_29_OWN_DOMAIN_AUTHORIZED_SMOKE_EXECUTION_PASSED`

Reference smoke image:

```text
inspectra-active-tools:build-smoke
```

Observed Nmap version:

```text
7.95
```

## Validated Summary

The completed smoke block validated these narrow technical milestones:

- Docker build-only validation of the separate `active-tools` image.
- No-target container readiness under strict local runtime flags.
- Nmap version no-target readiness, observing Nmap `7.95`.
- One container-loopback smoke inside `active-tools` against
  `127.0.0.1:65000` with Docker `--network none`.
- One own-domain authorized smoke against `www.urlbreve.es:443`.

These milestones show that a very small Active Nmap v0 technical path is
possible when it is separated, manually gated, bounded, and interpreted
conservatively. They do not make `active_nmap_basic` a released user-final
feature or a public scanner.

## Evidence Summary

Recorded evidence:

- image tag: `inspectra-active-tools:build-smoke`;
- Nmap version: `7.95`;
- container-loopback target: `127.0.0.1`;
- container-loopback port: `65000/tcp`;
- container-loopback result: `closed`, reason `conn-refused`;
- own-domain target: `www.urlbreve.es`;
- own-domain port: `443/tcp`;
- own-domain result: `open`, reason `syn-ack`;
- own-domain XML included a PTR hostname emitted by Nmap default DNS behavior.

The PTR hostname is a hardening gap, not a failure of the executed smoke. No
manual DNS check, DNS expansion, subdomain discovery, or reverse-DNS sweep was
run as part of the own-domain execution. Future live paths should decide
whether to use IP-freeze plus `-n` to avoid PTR output.

The `open` state for `www.urlbreve.es:443` is only an observed TCP exposure /
review indicator for that exact authorized FQDN at that moment. It is not a
confirmed vulnerability, exploitability finding, target-safety statement,
full-scan result, all-ports-found claim, production-readiness claim, or general
permission to scan other targets.

## Approved

This closeout approves only:

- `active-tools` as viable technical packaging for a future separated Active
  Nmap boundary.
- Manual one-shot controlled execution from local Docker for the already
  recorded smoke block.
- The minimal `tcp_connect_small` shape for separately frozen targets only.
- Report and documentation wording as observed exposure / review indicator.
- `www.urlbreve.es:443` as a historical executed smoke target only, not a
  permanent general permission.

The product value demonstrated here is that Inspectra can add a tightly
controlled Active capability beside the passive suite. The value is not general
scanning, internet enumeration, vulnerability confirmation, or a scan service.

## Not Approved

This closeout does not approve:

- backend integration to `active-tools`;
- backend-to-active-tools live calls;
- a runner HTTP endpoint;
- real Inspectra jobs from live Nmap output;
- exports or Raw JSON/backend reports with real live Nmap results;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- a public scanner;
- SaaS or scan-as-a-service positioning;
- `www.vildek.es`;
- `app.vildek.es`;
- port `80`;
- multi-domain scans;
- LAN targets;
- generic VPS targets;
- arbitrary public targets;
- arbitrary internet scanning;
- broad ranges, CIDR expansion, `-p-`, top-ports discovery, or target files;
- raw user flags;
- custom profiles;
- shell execution;
- NSE or `--script`;
- custom scripts;
- service/version detection;
- OS detection;
- UDP or SYN scans;
- stealth or evasion behavior;
- brute force;
- exploit scripts or exploitation;
- credential validation;
- credentials, cookies, tokens, or headers;
- crawling;
- DNS expansion;
- subdomain discovery;
- reverse-DNS sweep;
- vulnerability, exploitability, target-safety, full-scan, or all-ports-found
  claims.

## Residual Risks

Known residual risks and gaps:

- PTR hostname appeared in XML because the own-domain FQDN smoke allowed Nmap's
  default DNS behavior.
- The base image and Nmap package are not pinned by immutable digest/version in
  the current scaffold.
- No backend-to-active-tools boundary API is designed or implemented.
- No redaction review has covered real own-domain output flowing through backend
  reports.
- No real job lifecycle exists for live `active_nmap_basic` execution.
- No active-tools rate limit or backpressure policy exists.
- No retention policy exists for real live Nmap outputs.
- No final Active live result UX exists for real own-domain output.
- No operator cleanup or rollback runbook exists for live `active-tools`
  execution.

These gaps must stay visible before any future live integration or release
decision.

## Roadmap

Recommended next path, in order:

1. Redaction and parser hardening for real own-domain output, especially PTR
   hostnames and any embedded host/address fields.
2. IP-freeze plus `-n` option design if future runs should avoid PTR output.
3. Backend-to-active-tools boundary design, docs-first, before any live call.
4. Runner HTTP or internal service design only if a separate service boundary is
   still the preferred architecture.
5. Job lifecycle integration using fake/live adapters with tight default-off
   controls and no archive/run-all integration.
6. A second own-domain target freeze, likely `www.vildek.es:443`, only after a
   separate approval.
7. `app.vildek.es` only after lower-risk domains and its own explicit freeze.
8. Public release or tag only after a separate security closeout.

## Product Decision

The technical smoke block shows that Inspectra can support a very limited
`active_nmap_basic` v0 path under explicit local/private/self-hosted operation,
separate Active packaging, exact target freezes, bounded execution, and cautious
evidence language.

It does not make `active_nmap_basic` a user-final feature, a production-ready
Active workflow, a public scanner, or a broad target-scanning capability. Future
work must continue to preserve disabled-by-default activation, explicit opt-in,
authorized targets only, bounded target/port/time/output/storage limits,
redaction-first reporting, and observed exposure / review indicator wording.

## Acceptance Criteria

This closeout is accepted when:

- the final decision is recorded as
  `ACTIVE_NMAP_BASIC_30_ACTIVE_NMAP_V0_TECHNICAL_SMOKE_CLOSEOUT_ACCEPTED`;
- evidence from build-only, no-target readiness, Nmap version, container
  loopback, and own-domain smoke phases is summarized;
- approved scope and not-approved scope are explicit;
- PTR output is recorded as a gap/hardening item;
- residual risks and roadmap are documented;
- README, architecture, security scope, and implementation plan references are
  updated without runtime changes;
- no Docker, Nmap, DNS check, probe, HTTP request, Compose command, backend
  integration, runner endpoint, job, export, tag, or release is added in this
  phase.

Final decision:

```text
ACTIVE_NMAP_BASIC_30_ACTIVE_NMAP_V0_TECHNICAL_SMOKE_CLOSEOUT_ACCEPTED
```
