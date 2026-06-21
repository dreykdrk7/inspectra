# Passive Sanitizer Fixture Classification Test Fixtures

Decision: `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_02_TEST_FIXTURES_ACCEPTED`

Status: fixture set and expected classifications are defined for a future local
sanitizer classification helper. No helper, runtime behavior, upload behavior,
or analyzer behavior was added in this phase.

## Scope

This phase adds small synthetic fixtures and a docs record only. It does not
change backend runtime, frontend runtime, tools runtime, sanitizer runtime,
upload behavior, endpoints, UI, storage, `archive/run-all`, or
`tools/runner/main.py`. It does not run Docker, run Nmap, submit Active jobs,
perform network requests, upload archives, use outside targets, take
screenshots, deploy, create a release, create a tag, or push.

## Fixture Paths

Safe synthetic fixture paths:

| Path | Expected classification | Expected decision |
| --- | --- | --- |
| `tests/fixtures/sanitizer/safe_synthetic/tests/example_token_fixture.txt` | `synthetic_test_fixture_marker` | retain only for controlled synthetic tests |
| `tests/fixtures/sanitizer/safe_synthetic/redaction/example_redacted_secret.txt` | `redaction_example_marker` | retain only for redaction/example tests |
| `tests/fixtures/sanitizer/safe_synthetic/docs/example_placeholder.md` | `documentation_example_marker` | retain only when docs-example context is explicit |
| `tests/fixtures/sanitizer/safe_synthetic/demo/generated_demo_config.txt` | `generated_demo_fixture_marker` | retain only for generated demo fixture tests |

Unsafe counterexample paths:

| Path | Expected classification | Expected decision |
| --- | --- | --- |
| `tests/fixtures/sanitizer/unsafe_counterexamples/.env` | `blocked_private_material` | block by path/type even though fixture text is fake |
| `tests/fixtures/sanitizer/unsafe_counterexamples/private.key` | `blocked_private_material` | block by path/type even without PEM-shaped content |
| `tests/fixtures/sanitizer/unsafe_counterexamples/config_with_token.txt` | `real_or_unknown_sensitive_marker` | block unless removed or narrowed out |
| `tests/fixtures/sanitizer/unsafe_counterexamples/customer_record.txt` | `blocked_private_material` | block record-shaped material even when synthetic |

Manifest-only safe snapshot fixture:

| Path | Expected classification |
| --- | --- |
| `tests/fixtures/sanitizer/manifest_only_safe_snapshot/package.json` | `manifest_only_safe_snapshot` |
| `tests/fixtures/sanitizer/manifest_only_safe_snapshot/requirements.txt` | `manifest_only_safe_snapshot` |
| `tests/fixtures/sanitizer/manifest_only_safe_snapshot/docker-compose.yml` | `manifest_only_safe_snapshot` |

## Why The Values Are Safe

All fixture values are intentionally fake, bracketed or obviously local, and
non-operational. They are designed to exercise path/category expectations
without resembling usable access material.

The unsafe counterexamples are unsafe because of path, file type, or record
shape, not because they contain real material. This keeps future tests honest:
classification must continue to block risky contexts even when examples are
synthetic.

The manifest-only snapshot contains a minimal package manifest, a minimal
requirements file, and a local Compose snippet. It includes no private URLs, no
production names, and no access material.

## Expected Future Test Assertions

A future helper test boundary should assert:

- safe synthetic paths classify only when path and category are both allowed;
- the environment-file counterexample remains blocked;
- the key-file counterexample remains blocked;
- docs examples classify as docs examples only when clearly fake or redacted;
- unknown source paths with marker categories remain blocked;
- output includes paths, marker categories, classifications, and decisions;
- output excludes raw marker strings and source snippets.

No such helper exists yet, so this phase does not add executable tests.

## No-Go Boundaries

- do not weaken sanitizer behavior globally;
- do not permit environment-file uploads because examples are fake;
- do not permit key-file uploads because examples are fake;
- do not permit token-like config files because examples are fake;
- do not permit dump, backup, media, invoice, or record-shaped material;
- do not store raw marker strings;
- do not rely on filename alone when content is suspicious;
- do not upload broad source snapshots while marker hits remain unresolved;
- do not add network, package-manager, deployment, Active, or Nmap behavior.

## Next Recommended Phase

Recommended next microphase:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_03_LOCAL_HELPER
```

Goal: build a local-only helper that scans a directory or archive and emits
path/category/classification records for these fixtures without printing raw
marker strings or changing app upload behavior.

## Decision

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_02_TEST_FIXTURES_ACCEPTED
```
