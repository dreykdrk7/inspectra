# Active Pre-Alpha VPS Deploy Smoke

Decision: `ACTIVE_PRE_ALPHA_VPS_DEPLOY_SMOKE_10_ACCEPTED`

Status: the published Inspectra Active Technical Alpha was deployed to the
existing controlled VPS staging environment and smoke checked with Active
capabilities disabled.

## Release And Source

- Release/tag deployed: `v0.2.0-alpha.1`
- Release URL:
  `https://github.com/dreykdrk7/inspectra/releases/tag/v0.2.0-alpha.1`
- Source commit deployed:
  `45a50b8738dd54e43973d6a7568620095cf7f0aa`
- Deployed tag description on VPS: `v0.2.0-alpha.1`
- Deployed path: `/opt/apps/inspectra`
- Chosen staging subdomain: `inspectra-alpha.urlbreve.es`

Local `origin/main` was already at `a5aaede`, so the publication record and VPS
deploy plan were visible remotely. No push was performed in this phase.

## Local Preflight

Preflight checks:

- `git status --short --branch`: clean at `main...origin/main`
- `git log -5 --oneline`: included `a5aaede`,
  `38ff4fc`, `45a50b8`, `7d6ee46`, and `1dd86cc`
- local tag `v0.2.0-alpha.1`: present
- local tag target:
  `45a50b8738dd54e43973d6a7568620095cf7f0aa`
- remote `origin/main`: `a5aaede`
- GitHub prerelease: visible and marked prerelease
- `git diff --check`: passed
- `git diff --cached --check`: passed

The staging subdomain resolved to the expected VPS address before Caddy was
changed.

## VPS Preflight

VPS inspection used the existing deploy access for the current multi-app
environment. The record intentionally omits private host details.

Observed deployment surface:

- app convention: `/opt/apps`
- Inspectra app path: `/opt/apps/inspectra`
- Docker: `29.1.4`
- Docker Compose: `v5.0.1`
- Caddy: Dockerized `caddy:2.8-alpine` container on the external `web` network
- Caddy config path: `/opt/apps/shared/proxy/Caddyfile`
- existing public proxy ports: `80`, `443`, and `443/udp`
- unrelated app containers were running before and after the deploy

## VPS Deploy Configuration

The repository runtime files were not changed. VPS-local deploy configuration
was added under `/opt/apps/inspectra`:

- `docker-compose.vps.yml` joins backend and frontend to the existing `web`
  network for Caddy routing.
- direct backend/frontend host port publishing is reset.
- backend CORS origin is set to `https://inspectra-alpha.urlbreve.es`.
- frontend build arg `VITE_API_BASE_URL` is set to `/api`.
- backend Active gates are explicitly set to `false`.
- `INSPECTRA_ACTIVE_TOOLS_URL` is empty.
- backend runs as the non-root VPS deploy UID so the bind-mounted app data
  directory is writable without container-root ownership changes.

No app credential-bearing runtime values or private Caddy hash values are
recorded here.

## Compose Results

Compose validation:

- combined Compose config validation passed.
- Docker socket was not mounted into Inspectra containers.
- direct host port bindings for `inspectra-backend`, `inspectra-frontend`, and
  `inspectra-audit-tools` were `{}`.

Build:

- `inspectra-backend`: built.
- `inspectra-frontend`: built.
- `inspectra-audit-tools`: built.
- frontend build emitted the existing large-chunk warning but completed.

Start:

- first `up -d` attempt created the Inspectra networks and containers, but the
  backend exited because the VPS bind-mounted data directory was owned by the
  host deploy user while the container app user could not create
  `/app/data/results/jobs`.
- deploy-only fix: create the app data subdirectories under
  `/opt/apps/inspectra/data` and run the backend container as the non-root host
  deploy UID in the VPS-local override.
- second `up -d --force-recreate` completed.

Final Compose status:

- `inspectra-audit-tools`: up and healthy.
- `inspectra-backend`: up and healthy.
- `inspectra-frontend`: up.

## Caddy Results

Caddy route summary:

- site: `inspectra-alpha.urlbreve.es`
- whole-site access control: existing Caddy Basic Auth convention
- `/api` and `/api/*`: strip `/api` and reverse proxy to `inspectra-backend:8000`
- `/health`: reverse proxy to `inspectra-backend:8000`
- default route: reverse proxy to `inspectra-frontend:5173`

Caddy validation and reload:

- Caddy config validation passed.
- Caddy reload exited successfully.
- Caddy reported only a formatting warning for the Caddyfile style.

Unauthenticated public checks:

- `https://inspectra-alpha.urlbreve.es/`: `401` with Basic Auth challenge.
- `https://inspectra-alpha.urlbreve.es/api/health`: `401` with Basic Auth
  challenge.

Authenticated browser/UI smoke was not run because access material was not
recorded in the phase transcript.

## Smoke Results

Disabled-state smoke:

- backend healthcheck passed with repeated `GET /health` `200` responses.
- frontend served the built `index.html` internally.
- public staging route is protected before the app is reachable.
- all checked backend Active gates were `false`:
  - `INSPECTRA_ACTIVE_DRY_RUN_ENABLED`
  - `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED`
  - `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED`
  - `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED`
  - `INSPECTRA_ACTIVE_TLS_BASIC_ENABLED`
  - `INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED`
  - `INSPECTRA_ACTIVE_DNS_OSINT_ENABLED`
  - `INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED`

Passive/project analysis smoke:

- Not run in this phase.
- Deferred to an authenticated operator smoke because the public route is now
  Basic Auth protected and this record intentionally does not store credential
  material.

No-live HTTP header review smoke:

- Not run in this phase.
- The HTTP header review gates and live HEAD gate remained disabled.

## Logs And Exposure Review

Recent logs after the corrected restart:

- backend: startup complete, healthcheck `200` entries, no tracebacks observed.
- frontend: no error output observed.
- audit-tools: startup complete, healthcheck `200` entries, no tracebacks
  observed.

Exposure checks:

- Caddy is the only public entrypoint for Inspectra.
- Inspectra backend, frontend, and audit-tools have no direct host port
  bindings.
- Docker socket is not mounted into Inspectra containers.
- unrelated containers remained running after the deploy.

## Blockers, Fixes, And Rollback

Resolved deploy blockers:

- An initial internet-facing no-auth app configuration was rejected during
  execution review. The final route uses the existing Caddy Basic Auth pattern
  and no direct host port exposure.
- Backend startup initially failed on the VPS data bind mount. The final
  VPS-local override runs backend as the non-root deploy UID and uses
  app-specific data directories under `/opt/apps/inspectra/data`.

Rollback actions performed: none.

Available rollback:

- stop the Inspectra Compose project under `/opt/apps/inspectra`;
- remove or revert the Inspectra Caddy route from the backed-up Caddyfile;
- reload Caddy;
- keep unrelated apps untouched.

## Avoided Actions

This phase did not:

- run Nmap;
- submit live Active jobs;
- enable live Active capability flags;
- use third-party targets;
- take screenshots;
- create a tag;
- create a release;
- modify `archive/run-all`;
- modify `tools/runner/main.py`;
- push commits;
- publish or promote the app.

## Recommended Next Step

Run an authenticated operator smoke through the protected staging subdomain,
using only safe owned fixtures, then decide whether the alpha should keep
Caddy-only access control or add app-level auth for this deployment.

Suggested next microphase:

```text
ACTIVE_PRE_ALPHA_AUTHED_UI_PASSIVE_SMOKE_11
```

## Decision

```text
ACTIVE_PRE_ALPHA_VPS_DEPLOY_SMOKE_10_ACCEPTED
```
