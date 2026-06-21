# Passive Sanitizer Tier 1 Candidate Closeout

Decision: `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_08_TIER1_CANDIDATE_CLOSEOUT_ACCEPTED`

Status: accepted. This closes the Tier 1 one-file owned-source candidate
experiment after the selected source metadata catalog passed the local helper
dry-run with zero records.

## Scope

This closeout records the result and future policy for Tier 1 source dogfood.
It does not change runtime, upload, staging, helper, analyzer, UI, endpoint,
storage, runner, or Active behavior.

No helper run, source snapshot, staging upload, deployment, container execution,
port scan, Active job, network probe, screenshot, version mark, or publication
step was performed in this phase.

## Lineage

- `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_05_OPERATOR_DOGFOOD_DRY_RUN_BLOCKED_SAFE`
- `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_06_NARROW_SOURCE_SNAPSHOT_POLICY_ACCEPTED`
- `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_07_NARROW_SOURCE_DRY_RUN_ACCEPTED`

Latest accepted dry-run commit:

```text
6be687c docs(passive): dry-run narrow source sanitizer snapshot
```

## Result Summary

- Broad owned-source snapshot: safe-blocked.
- Narrow owned-source snapshot policy: accepted.
- One-file Tier 1 candidate: accepted locally.
- Manifest/config-only fixture: remains the preferred routine smoke baseline.

The result validates that a carefully chosen, tiny source path family can pass
the local helper, but it does not approve broad source snapshots.

## Accepted Tier 1 Candidate

Family:

```text
project archive finding metadata catalog
```

Accepted path:

```text
backend/app/project_archive_findings.py
```

Dry-run result:

- helper output: `[]`;
- total records: `0`;
- block decisions: `0`;
- unknown sensitive-marker records: `0`;
- blocked private-material records: `0`;
- no upload performed.

Approval boundary:

- local-only;
- path-specific;
- no automatic source allowlist;
- no staging upload approval;
- no broad source approval;
- no app upload preflight approval.

## Future Tier 1 Policy

Tier 1 source candidates must stay tiny and reviewable:

- prefer one path family per phase;
- prefer `1` to `5` files, not broad trees;
- preserve relative paths in temporary snapshots;
- run the helper locally only;
- record only counts and path/category/classification/decision/reason summaries;
- accept only when blocked and unknown counts are zero;
- treat any marker record as a stop condition unless a later phase explicitly
  reviews it as an already-approved fixture-bound context;
- keep source dogfood operator-only and local-only;
- keep manifest/config-only archives as the preferred routine smoke input.

The accepted one-file candidate should not be generalized to neighboring app
surfaces without a separate dry-run and closeout.

## Product Decision

Recommended next step:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_09_SECOND_TIER1_CANDIDATE_DRY_RUN
```

Reason: if technical hardening continues, the next useful move is one additional
tiny Tier 1 candidate family, preferably a marker-free report formatter/helper.
That gives the policy one more data point without drifting toward broad source
snapshots.

Alternative:

```text
PRIVATE_ALPHA_TESTER_GUIDE_01
```

Use this if sharing with a trusted tester is imminent.

Do not continue toward broad source snapshots yet.

## Deferred Items

- staging replay using the accepted manifest-only fixture;
- app-side upload preflight classification;
- dashboard-level category and ecosystem rollups;
- broad source snapshot policy, still blocked by default;
- private-alpha tester guide.

## No-Go Boundaries

- no automatic source allowlist;
- no upload of source snapshots;
- no staging replay with source snapshots;
- no sanitizer weakening;
- no marker-value storage;
- no snippets;
- no runtime behavior change.

## Decision

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_08_TIER1_CANDIDATE_CLOSEOUT_ACCEPTED
```
