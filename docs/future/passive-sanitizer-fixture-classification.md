# Passive Sanitizer Fixture Classification

Decision: `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_01_ACCEPTED`

Status: design accepted for classifying synthetic fixture and source-test
marker hits before future passive project archive dogfood. This does not change
sanitizer runtime behavior.

## Scope

This is a docs-only design and decision record. It does not change backend
runtime, frontend runtime, tools runtime, analyzer behavior, sanitizer runtime,
storage, endpoints, UI, tests, `archive/run-all`, or `tools/runner/main.py`.
It does not run Docker, run Nmap, submit Active jobs, perform network requests,
upload archives, use outside targets, deploy, create a release, create a tag,
or push.

## Problem Statement

The current sanitizer posture is fail-closed. When a project archive scan finds
secret-like markers that cannot be confidently classified, the upload should
remain blocked or the snapshot should be narrowed.

Broader source snapshots can include intentionally fake strings in tests,
fixtures, docs, demo material, or redaction examples. During Inspectra
dogfood, broader source snapshots were avoided because marker scans found
source/test/docs hits. The accepted self-analysis used a narrower
manifest/config snapshot instead.

That approach is safe, but it limits self-dogfood coverage. Inspectra needs a
design that can classify clearly synthetic marker hits without making real
upload sanitizer behavior weaker.

## Desired Outcome

The desired model should:

- preserve fail-closed behavior for real uploads;
- allow future operator tooling or tests to classify clearly synthetic fixture
  hits;
- avoid printing, storing, or documenting raw marker strings;
- prefer path-level and category-level reporting;
- keep real project, client, and business material excluded;
- keep manifest/config-only snapshots available as the conservative fallback.

## Classification Model

| Class | When It Applies | Upload May Proceed? | May Be Recorded | Must Remain Blocked |
| --- | --- | --- | --- | --- |
| `real_or_unknown_sensitive_marker` | Marker appears in normal source, config, deploy material, or any uncertain context. | No. Remove the file, narrow the snapshot, or skip upload. | Path, marker category, blocked status. | Raw marker strings, surrounding source snippets, private config contents. |
| `synthetic_test_fixture_marker` | Marker appears in test or fixture paths and local inspection confirms it is intentionally fake. | Yes, only after classification and only for operator-owned dogfood. | Path, category, synthetic-test classification. | Raw marker strings, real secrets, ambiguous fixture content. |
| `redaction_example_marker` | Marker appears in redaction test material or examples built to prove masking behavior. | Yes, only when the file is clearly part of redaction validation. | Path, category, redaction-example classification. | Raw marker strings and any file that mixes examples with private material. |
| `documentation_example_marker` | Marker appears in docs as a fake placeholder or redacted sample. | Usually no for broad archives; yes only for controlled self-dogfood after review. | Path, category, docs-example classification. | Real-looking values, copied production snippets, private operational docs. |
| `generated_demo_fixture_marker` | Marker appears in generated demo material with a known synthetic source. | Yes for controlled demos if the generator and path are known. | Path, category, demo-fixture classification. | Any generated file that includes private source material or real external data. |
| `blocked_private_material` | File type or location is inherently outside safe dogfood scope. | No. | Path and blocked category only. | Environment files, key files, dumps, backups, media, invoices, private business files. |
| `manifest_only_safe_snapshot` | Snapshot contains only dependency manifests or selected config files with no unresolved hits. | Yes. | Included file list and snapshot category. | Broad source trees with unresolved markers. |

## Safe Allowlisting Rules

Allowlisting should be path/category based, not value based.

Candidate synthetic contexts include:

- `tests/`
- `fixtures/`
- `demo/`
- `examples/`
- known redaction-test fixture names
- generated fixture directories with a documented source

Rules:

- require explicit synthetic context;
- require local inspection when a marker is not obviously fake from file
  purpose;
- record only path and marker category;
- do not allow environment files;
- do not allow private key files;
- do not allow API keys, tokens, or browser cookie material;
- do not allow production database dumps;
- do not allow client records or private business documents;
- do not allow backups, invoices, or media collections;
- do not allow third-party projects without explicit authorization;
- if uncertain, keep blocked.

Filename or directory alone is not sufficient. Contents and project context
must be consistent with the classification.

## Operator Workflow

1. Run a local pre-upload scan that produces path-level findings.
2. Choose one of these outcomes:
   - narrow the snapshot;
   - build a manifest/config-only snapshot;
   - classify synthetic fixture hits;
   - skip the project.
3. Record classification categories without raw marker strings.
4. Remove or exclude all unresolved files.
5. Upload only if every remaining hit is classified as safe for the chosen
   dogfood scope.

Classification records should include:

- project or snapshot label;
- file path;
- marker category;
- classification class;
- operator decision;
- whether the file was retained or excluded.

Classification records should not include raw marker strings, surrounding
source snippets, private config contents, session material, or access material.

## Implementation Options

| Option | Safety | Complexity | Test Burden | Product Value |
| --- | --- | --- | --- | --- |
| Docs-only operator checklist | Highest initially; no runtime behavior changes. | Low. | Low; review docs and use manual dogfood. | Good immediate guidance, but manual and easy to apply inconsistently. |
| Local pre-upload sanitizer helper | High if it only emits path/category records and never uploads. | Medium. | Medium; needs synthetic fixture tests and unsafe-file tests. | Strong value for operator-led dogfood while preserving app fail-closed behavior. |
| App-side upload preflight classification | Riskier because it sits near real upload behavior. | High. | High; requires negative cases, UI/API contracts, and storage decisions. | Useful later, but premature before local model proves itself. |
| Reusable manifest-only self-dogfood fixture | High; keeps source scope narrow. | Low to medium. | Medium; fixture maintenance and expected report review. | Good stable smoke path, but does not solve broad-source classification. |

## Recommended Next Implementation

Start with a local pre-upload sanitizer classification helper or a strict
operator checklist. Do not add app-side automatic weakening.

Recommended implementation order:

1. Define synthetic fixture examples and unsafe counterexamples.
2. Build a local helper that reads an archive or directory and emits only
   path/category/classification output.
3. Add synthetic-only tests for the helper.
4. Keep app upload sanitizer fail-closed until the classification model has
   enough evidence.
5. Add a reusable manifest/config self-dogfood fixture for Inspectra.

## No-Go Boundaries

- do not weaken sanitizer behavior globally;
- do not allow environment files;
- do not allow private keys;
- do not allow API keys;
- do not allow tokens;
- do not allow browser cookies;
- do not allow production database dumps;
- do not allow client records or private business documents;
- do not store raw marker strings;
- do not upload broad source snapshots when marker hits remain unresolved;
- do not rely on filename alone when contents are suspicious;
- do not add network or package-manager behavior.

## Future Acceptance Criteria

A future implementation phase should be accepted only if:

- real or unknown markers remain blocked;
- synthetic fixtures can be classified without raw marker leakage;
- manifest-only self-dogfood remains supported;
- tests cover:
  - safe fixture paths;
  - unsafe environment-file paths;
  - unsafe key-file paths;
  - docs examples;
  - unknown source hits;
- no Active runtime behavior is added;
- no network, package install, deployment, release, or tag behavior is added.

## Suggested Next Microphase

Recommended next microphase:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_02_TEST_FIXTURES
```

Reason: define the synthetic and unsafe fixture set first, so any later helper
or checklist can be tested against agreed examples.

Alternative if the operator wants immediate manual dogfood guidance:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_02_LOCAL_HELPER
```

Alternative if the immediate need is stable self-dogfood rather than broad
source classification:

```text
PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_01
```

## Decision

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_01_ACCEPTED
```
