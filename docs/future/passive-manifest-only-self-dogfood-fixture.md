# Passive Manifest-Only Self Dogfood Fixture

Decision: `PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_01_ACCEPTED`

Status: accepted. A small, deterministic Inspectra self-dogfood fixture now
exists for later passive project archive smoke phases.

## Fixture Path

```text
tests/fixtures/project_archives/inspectra_manifest_only_self_dogfood/
```

The fixture is directory-based in this phase. Later smoke work may package it as
an archive from that directory.

## Included Files

```text
README.md
backend/requirements.txt
docker-compose.yml
frontend/package.json
tools/requirements.txt
```

The fixture includes only:

- Python dependency manifests for backend and local tool surfaces;
- a frontend package manifest with safe script declarations and non-exact
  dependency ranges;
- a sanitized Compose excerpt showing service topology and hardening-oriented
  service settings;
- a README explaining the narrow fixture purpose.

## Excluded Categories

The fixture intentionally excludes:

- application source files;
- test files;
- broad docs;
- generated uploads, results, exports, and reports;
- deployment-local override files;
- VPS or reverse-proxy config;
- live host values or outside target examples;
- operator auth material, session material, and client records;
- package lockfiles and vendored dependency trees.

## Sanitizer Helper Result

Command:

```text
.venv/bin/python tools/sanitizer_fixture_classifier.py tests/fixtures/project_archives/inspectra_manifest_only_self_dogfood --pretty
```

Result:

```json
[]
```

The helper returned no records for this fixture, which means it found no marker
terms requiring a blocked or unknown classification. No raw marker values were
printed.

## Expected Later Use

This fixture is intended for a later passive smoke or dogfood phase that needs a
small project archive input without broad repository content. Expected useful
signals include:

- multi-ecosystem inventory from frontend, backend, and tools manifests;
- dependency hygiene findings from intentionally non-exact package ranges;
- package script reporting from the frontend manifest;
- Compose service topology and hardening setting reporting.

Executable dogfood is deferred. This phase did not upload the fixture, start any
service, run a container engine, run network probes, or invoke package managers.

## No-Go Boundaries

Future edits to this fixture should not add:

- runtime behavior or upload-flow wiring;
- server routes or browser app code;
- Active capability wiring;
- batch archive automation or runner entrypoint orchestration;
- broad source snapshots;
- deployment-local material;
- generated data/results/uploads;
- live target examples.

## Next Recommended Phase

```text
PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_02_LOCAL_ARCHIVE_DRY_RUN
```

Suggested scope: create a temporary local archive from this directory, run only
existing local passive project-archive analysis paths if already available, and
record results without staging upload or deployment.

## Decision

```text
PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_01_ACCEPTED
```
