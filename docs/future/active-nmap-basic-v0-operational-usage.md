# Active / Nmap Basic v0 Operational Usage

Decision: `ACTIVE_NMAP_BASIC_57_OPERATIONAL_USAGE_POLISH_ACCEPTED`

This guide documents how an operator can configure and use Active / Nmap basic
v0 as a bounded local/private/self-hosted capability. It adds operational
guidance only. It does not add runtime behavior, start Docker, execute Nmap,
probe targets, perform DNS checks, send external HTTP traffic, change backend
or frontend code, integrate archive/run-all, integrate `tools/runner/main.py`,
create a release, create a tag, or push state.

## Approved Use

Active / Nmap basic v0 is approved only for explicitly authorized targets in a
local, private, or self-hosted environment. It is disabled by default and needs
two separate opt-ins before real minimal execution can happen:

- the backend feature gate must allow the `POST /active/network/nmap-basic`
  contract;
- the internal `active-tools` service must explicitly allow bounded Nmap
  execution.

The backend remains the authority for authentication, owner scope, request
validation, target policy, lifecycle normalization, storage, reporting, and
redaction. The backend never executes Nmap directly. Nmap execution is isolated
to the internal `active-tools` service when the deployment enables that service
and its execution flag.

## Required Configuration

Backend variables:

- `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED`: default `false`. Set to `true` only
  for trusted local/private/self-hosted operation.
- `INSPECTRA_ACTIVE_TOOLS_URL`: default empty. Set only to an internal/local
  base URL such as `http://active-tools:8080` in Compose or a loopback URL in a
  controlled local setup.
- `INSPECTRA_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS`: default `2`. Bounds the
  backend `/health/active-tools` helper.

Active-tools variable:

- `INSPECTRA_ACTIVE_TOOLS_NMAP_BASIC_EXECUTION_ENABLED`: default `false`. Set to
  `true` only inside the internal `active-tools` service when bounded execution
  is approved for the local/private/self-hosted deployment.

`INSPECTRA_ACTIVE_TOOLS_URL` must be an internal/local service URL without
credentials, path, query, or fragment. Empty means unconfigured and should map
to controlled unavailable/no-live behavior. Values outside that internal/local
boundary fail closed.

To disable Active / Nmap basic v0, set
`INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=false`, unset `INSPECTRA_ACTIVE_TOOLS_URL`,
or set `INSPECTRA_ACTIVE_TOOLS_NMAP_BASIC_EXECUTION_ENABLED=false` inside
`active-tools`.

## Compose Active-Tools

The optional active-tools service is described by
`docker-compose.active-tools.example.yml` behind profile `active`. The example
service publishes no host ports by default, uses an internal network, avoids
host networking, avoids privileged mode, mounts no Docker socket, drops
capabilities, runs read-only with a tmpfs `/tmp`, and sets `no-new-privileges`.

Review the static Compose shape before choosing to run it:

```bash
COMPOSE_DISABLE_ENV_FILE=1 docker compose -f docker-compose.active-tools.example.yml --profile active config --no-interpolate
```

An operator-controlled deployment should wire the backend to the service with
an internal URL such as:

```text
INSPECTRA_ACTIVE_TOOLS_URL=http://active-tools:8080
```

This documentation phase does not run Compose or Nmap.

## Health Check

After the backend is configured, `GET /health/active-tools` is the targetless
readiness surface for the internal service. It accepts no targets and does not
call the active-tools `/active/nmap-basic` endpoint. If
`INSPECTRA_ACTIVE_TOOLS_URL` is empty, malformed, unavailable, or points outside
the allowed internal/local boundary, the backend should return controlled
health metadata and continue operating.

Expected operational states include:

- unconfigured: backend URL is empty or disabled;
- unavailable/timeout: backend cannot reach the configured internal service
  within the bounded timeout;
- ready with `active_nmap_basic` disabled: active-tools is reachable but still
  no-live for Nmap basic;
- ready with bounded execution enabled: active-tools is reachable and explicitly
  configured for the bounded v0 execution path.

## Target Policy

The approved v0 target policy is intentionally narrow:

- authorized targets only;
- local/private/self-hosted targets only;
- one bounded target request shape through the backend contract;
- bounded integer TCP ports accepted by policy.

The following remain outside approved v0 operation and require a separate
design/freeze/smoke phase before any change:

- arbitrary public target scanning or SaaS-style scanning;
- LAN/VPS/domain targets that have not been separately frozen;
- port `80`;
- ranges, CIDR, wildcards, pasted lists, target files, top ports, or `-p-`;
- raw flags, custom profiles, shell commands, extra args, or custom scripts;
- NSE/scripts, service/version detection, OS detection, UDP/SYN modes, stealth,
  or evasion;
- brute force, exploit scripts, credential validation, credentials, cookies,
  headers, tokens, crawling, DNS expansion, or subdomain discovery.

## Safe Local Example

Use loopback-only examples for operator education. The following request shape
is illustrative and is not executed by this documentation phase:

```json
{
  "mode": "live_nmap_basic",
  "profile": "tcp_connect_small",
  "targets": ["127.0.0.1"],
  "ports": [65000],
  "authorization_confirmed": true,
  "local_private_scope_confirmed": true,
  "live_traffic_confirmed": true
}
```

The frontend sends the same bounded contract through its Active / Nmap basic
panel after the operator enters the target, ports, and confirmations. Backend
validation and target policy remain authoritative.

## Result Semantics

Active / Nmap basic v0 creates owner-scoped `active_nmap_basic` jobs with
`file_id: null`. Stored job data is redaction-first:

- targets render as `[REDACTED_TARGET]`;
- raw payloads, raw commands, argv, stdout, stderr, XML, PTR names, resolved IPs,
  banners, versions, service details, credentials, headers, cookies, and tokens
  are not public result fields;
- Raw JSON and reports preserve the same redaction boundary;
- minimal TCP observations, when present, are only observed TCP exposure /
  review indicators;
- manual validation is required.

`completed_real_minimal` means the bounded internal active-tools execution path
returned a structured minimal result. It is not a vulnerability claim, not a
target-safety statement, and not complete coverage.

## Troubleshooting

- `active_nmap_basic is disabled in this environment`: enable
  `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=true` only for trusted local/private use.
- `/health/active-tools` reports unconfigured: set an internal/local
  `INSPECTRA_ACTIVE_TOOLS_URL` or keep the capability disabled.
- `/health/active-tools` reports unavailable or timeout: check that the internal
  service is reachable on the private Compose network and that the health
  timeout is appropriate.
- active-tools reports disabled/no-live: set
  `INSPECTRA_ACTIVE_TOOLS_NMAP_BASIC_EXECUTION_ENABLED=true` inside active-tools
  only when bounded execution is approved.
- request validation fails: review the fixed `live_nmap_basic` /
  `tcp_connect_small` contract, bounded target list, bounded port list, and the
  three required confirmations.
- policy rejects a target: keep the target local/private/self-hosted and avoid
  ranges, wildcards, URL-shaped values, files, or broad scans.
- report or Raw JSON hides target details: this is intentional redaction, not a
  rendering error.

## Final Decision

```text
ACTIVE_NMAP_BASIC_57_OPERATIONAL_USAGE_POLISH_ACCEPTED
```

Active / Nmap basic v0 has operational usage guidance for local/private/
self-hosted deployments. The guide preserves disabled-by-default posture,
explicit opt-in, internal active-tools execution only, backend authority,
bounded target policy, redaction-first storage/reporting/Raw JSON/frontend
behavior, observed exposure / review-indicator wording, and manual validation.
