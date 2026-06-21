# Passive Sanitizer Tier 1 Policy Closeout

Decision: `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_10_TIER1_POLICY_CLOSEOUT_ACCEPTED`

Status: accepted. This closes the Tier 1 narrow-source sanitizer experiment
after two one-file owned-source candidates passed the local helper with zero
records.

## Scope

This phase closes the Tier 1 source dogfood policy thread. It records accepted
facts, future rules, deferred items, and the recommended next product step.

No runtime, upload, staging, helper, analyzer, UI, endpoint, storage, runner,
dashboard, or Active behavior changed.

## Lineage

- Broad owned-source dry-run: safe-blocked.
- Narrow source snapshot policy: accepted.
- First Tier 1 candidate: accepted.
- Second Tier 1 candidate: accepted.

Related commits:

```text
39dbf2a docs(passive): dry-run sanitizer classifier on owned source
717f28e docs(passive): define narrow source snapshot policy
6be687c docs(passive): dry-run narrow source sanitizer snapshot
ac65224 docs(passive): close tier1 sanitizer candidate
331d844 docs(passive): dry-run second tier1 sanitizer candidate
```

## Accepted Facts

Broad source snapshots remain blocked by default. The broad Inspectra dry-run
produced many blocked and unknown records, which correctly prevented upload or
broader dogfood.

Manifest/config-only fixtures remain the preferred routine smoke baseline.

Tier 1 source dogfood can work only when the candidate is:

- tiny;
- marker-free;
- local-only;
- path-specific;
- reviewed as one narrow path family;
- still separate from upload or staging workflows.

Two one-file candidates passed with helper output `[]`:

| Candidate | Family | Boundary |
| --- | --- | --- |
| `backend/app/project_archive_findings.py` | project archive finding metadata catalog | local-only and path-specific |
| `frontend/src/archiveReport.ts` | frontend archive report formatter/helper | local-only and path-specific |

No automatic allowlist exists. No staging upload approval exists. No broad
source snapshot approval exists.

## Future Tier 1 Rules

Future Tier 1 work must follow these rules:

- one path family per phase;
- `1` to `5` files maximum unless separately justified;
- local helper execution only;
- zero blocked records required;
- zero unknown records required;
- any marker record stops expansion;
- no raw values or snippets recorded;
- no source upload without separate approval;
- no broad tree promotion;
- no helper change to force a candidate to pass.

The accepted Tier 1 candidates are useful as local policy data points, not as a
route to broad source upload.

## Product Decision

Recommended next phase:

```text
PRIVATE_ALPHA_TESTER_GUIDE_01
```

Reason:

- lower development cost than dashboard rollups;
- prepares controlled feedback from one trusted technical tester;
- reinforces upload and no-go rules;
- does not require runtime changes;
- should happen before deeper dashboard UX work.

Valuable follow-up:

```text
DASHBOARD_CATEGORY_ECOSYSTEM_ROLLUPS_01
```

Dashboard category and ecosystem rollups remain valuable, but they should follow
the tester guide or tester feedback.

## Deferred Items

- dashboard category and ecosystem rollups;
- private alpha tester execution;
- staging replay with the accepted manifest-only fixture;
- app-side upload preflight;
- broad source snapshots, still blocked by default.

## No-Go Boundaries

- no automatic source allowlist;
- no source snapshot upload;
- no staging replay with source snapshots;
- no sanitizer weakening;
- no marker-value storage;
- no snippets;
- no runtime behavior change.

## Decision

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_10_TIER1_POLICY_CLOSEOUT_ACCEPTED
```
