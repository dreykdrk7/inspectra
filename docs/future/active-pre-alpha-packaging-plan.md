# Active Pre-Alpha Packaging Plan

Decision: `ACTIVE_PRE_ALPHA_PACKAGING_PLAN_05_ACCEPTED`

Status: docs-only Docker and release packaging plan for the validated
Inspectra Active technical alpha candidate. This phase inspected existing
packaging files and planning docs only. It did not change runtime behavior,
build images, start containers, run the app, invoke Nmap, contact targets,
capture screenshots, create a tag, publish a release, deploy, or push.

## Packaging Objective

Prepare the validated Active technical alpha for a later Docker packaging
validation phase while preserving the RC-validated runtime behavior.

The packaging path must:

- use existing repository packaging files before proposing changes;
- preserve disabled-by-default Active feature gates;
- preserve local/private/self-hosted operator positioning;
- preserve redaction-first review indicators and manual validation wording;
- avoid adding another Active capability before alpha publication;
- document packaging gaps instead of fixing them in this planning phase.

## Inputs

Current branch state inspected before this document:

```text
## main...origin/main
```

Current head inspected:

```text
ace71a7 docs(active): validate pre-alpha release candidate
```

Planning and release-candidate inputs:

- `docs/future/active-pre-alpha-rc-validation.md`;
- `docs/future/active-pre-alpha-release-notes.md`;
- `docs/future/active-pre-alpha-operational-polish.md`;
- `docs/future/active-pre-alpha-release-demo-readiness.md`;
- `README.md`;
- `docs/architecture.md`;
- `docs/security-scope.md`.

The RC validation record shows Python compile, focused Active backend tests,
full backend tests, full frontend tests, focused Active frontend tests,
frontend production build, and guardrails passing. That validation did not run
Docker, Nmap, an app server, live Active jobs, protocol traffic, screenshots,
tagging, release publication, deployment, or push steps.

## Packaging Files Inspected

Existing Docker and Compose artifacts:

| File | Current packaging role |
| --- | --- |
| `docker-compose.yml` | Main local Compose app with `backend`, `audit-tools`, and `frontend` services. |
| `backend/Dockerfile` | Builds the FastAPI backend image from `backend/requirements.txt` and `backend/app`. |
| `tools/Dockerfile` | Builds the existing audit-tools runner image from `tools/requirements.txt` and `tools/runner`. |
| `frontend/Dockerfile` | Builds the frontend development-service image and runs Vite dev mode. |
| `frontend/.dockerignore` | Excludes frontend local build/cache/log artifacts. |
| `docker-compose.active-tools.example.yml` | Example-only Active tools Compose file behind profile `active`; separate from normal app startup. |
| `docker/active-tools/Dockerfile` | Existing Active tools scaffold image for the Nmap boundary. |
| `docker/active-tools/Dockerfile.dockerignore` | Repo-root ignore file for the Active tools Dockerfile path. |

Dependency files inspected:

- `pyproject.toml`;
- `backend/requirements.txt`;
- `backend/requirements-dev.txt`;
- `tools/requirements.txt`;
- `docker/active-tools/requirements.txt`;
- `frontend/package.json`;
- `frontend/package-lock.json`.

Fixture Docker files under `tests/fixtures/demo/passive-alpha/` were observed
as test data, not as release packaging artifacts.

## Existing Artifact Strategy

Use the root Compose packaging path first because it is already documented in
`README.md` and builds the three normal services:

- `backend`;
- `audit-tools`;
- `frontend`.

The later validation phase should treat `docker-compose.yml` as the primary
candidate for local/private technical-alpha packaging. It should not invent a
new deployment architecture or move Active behavior into archive/run-all,
`tools/runner/main.py`, or the passive audit-tools runner.

The optional Active tools files are already present, but they remain a separate
example/scaffold path:

- `docker-compose.active-tools.example.yml` is profile-gated and example-only;
- `docker/active-tools/Dockerfile` keeps Active tools separate from backend,
  frontend, and audit-tools;
- the example service publishes no host port and is intended for separately
  approved Active tools validation.

For this Active technical alpha packaging plan, the safest first path is:

1. validate the root Compose app as packaged today;
2. confirm all Active flags remain disabled unless intentionally configured;
3. treat Active tools packaging as optional, separately approved validation
   for the Nmap boundary, not as required root Compose startup.

## Packaging Gaps

The plan found no blocker that requires changing packaging files before a
planning decision, but these gaps should be handled deliberately:

- The frontend Dockerfile currently runs `npm run dev`; no production static
  serving container is defined.
- The root Compose file does not wire the separate Active tools service.
- The Active tools Compose file is example-only and not part of normal startup.
- No release artifact naming, image tag naming, or image provenance record is
  frozen for the Active technical alpha.
- Root Compose validation has not yet been rerun after the RC validation commit.
- Docker build and startup behavior have not been validated for this exact RC
  candidate.
- The frontend production build passed outside Docker, but a production-style
  frontend container path is not currently defined.

These are not reasons to add runtime behavior in this phase. They are inputs
for the next validation phase and, if needed, a small packaging-fix phase.

## Proposed Next Execution Phase

Suggested next microphase:

```text
ACTIVE_PRE_ALPHA_DOCKER_PACKAGING_VALIDATION_06
```

That later phase may run Docker build and Compose validation only if explicitly
approved. This document only plans the commands and acceptance criteria.

## Later Docker Validation Checklist

Preflight:

- confirm `git status --short --branch`;
- confirm the target commit is the intended RC packaging commit;
- confirm no uncommitted backend, frontend, tools, archive, or runner changes;
- confirm no real `.env` values or secrets are read into release notes or
  documentation.

Root Compose config validation, based on existing docs:

```text
docker compose config
```

Root Compose build candidate, based on existing `docker-compose.yml`:

```text
docker compose build
```

Root app startup candidate, based on `README.md`:

```text
mkdir -p data/uploads data/results
docker compose up --build
```

Readiness candidate, based on the documented backend health endpoint:

```text
curl http://localhost:8000/health
```

Acceptance criteria for the later phase:

- backend health returns the existing healthy response;
- frontend is reachable through the existing local port mapping;
- `audit-tools` remains internal and healthy;
- the Docker socket is not mounted into services;
- root Compose startup does not require Active features to be enabled;
- Active flags remain disabled by default;
- no live Active job is submitted;
- no Nmap command is invoked;
- no real network target is used;
- no screenshots are captured unless a separate docs phase approves them;
- any build/download network used by Docker is recorded separately from target
  traffic.

Optional Active tools validation, only if separately approved:

```text
COMPOSE_DISABLE_ENV_FILE=1 docker compose -f docker-compose.active-tools.example.yml --profile active config --no-interpolate
```

If Active tools runtime validation is approved later, it should start with
targetless health/readiness only. Any target-bearing Nmap smoke must remain a
separate explicit phase with owned/lab target rules.

## Backend And Frontend Validation In Packaging Phase

If practical, the later phase should preserve the RC validation baseline:

- run backend tests outside containers before packaging checks;
- optionally run backend tests inside a container only if the existing image can
  support that without editing runtime files;
- run the frontend test suite outside containers before packaging checks;
- run `npm run build` from `frontend/` as the production-build evidence unless
  a production container path is separately added;
- confirm the existing Vite large-chunk warning is still non-blocking or track
  it as a packaging note.

## Release And Tag Planning Checklist

After Docker packaging validation passes:

- update `docs/future/active-pre-alpha-release-notes.md` with final validation
  evidence;
- choose an alpha version consistent with project history, such as
  `v0.2.0-alpha.1`, or document why another version is better;
- confirm `git status --short --branch` is clean;
- confirm the exact commit intended for the alpha tag;
- confirm release notes keep disabled-by-default, authorization, redaction, and
  manual-validation wording;
- confirm release notes do not overclaim capability, completeness, ownership,
  safety, or replacement of human review;
- keep tag creation and release publication out of this planning phase.

## Later VPS Deploy And Smoke Planning Checklist

Use existing deployment conventions only. Do not add secrets, real `.env`
values, or new deployment architecture in release docs.

Later deploy/smoke planning should:

- document the expected VPS path only if already known or already recorded;
- start with Active flags disabled;
- confirm auth/deployment mode choices before exposure;
- confirm logs avoid cookies, tokens, request bodies, Raw JSON, reports, and
  secrets;
- confirm backend and frontend URLs are explicit;
- avoid public targets;
- keep optional live Active smoke as a later explicit phase on owned/lab
  targets only.

## No-Go Boundaries

This packaging path does not approve:

- new runtime features;
- broad scanning product positioning;
- passive DNS sources or provider imports;
- archive/run-all Active orchestration;
- `tools/runner/main.py` Active orchestration;
- automatic version matching to vulnerability databases;
- exploit checks;
- public/open target intake claims;
- custom scanner profiles, raw flags, scripts, brute force, credential checks,
  content traversal, target expansion, or unattended target discovery.

## Release Readiness Recommendation

Proceed to:

```text
ACTIVE_PRE_ALPHA_DOCKER_PACKAGING_VALIDATION_06
```

The next phase should validate the existing root Compose packaging first. If it
finds that the frontend development-service container, missing production
frontend container path, or optional Active tools separation blocks the desired
alpha package, choose a small packaging-fix phase before release/tag planning.

Do not add another Active runtime capability before alpha publication.

## Decision

```text
ACTIVE_PRE_ALPHA_PACKAGING_PLAN_05_ACCEPTED
```
