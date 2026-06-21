# Passive Sanitizer Narrow Owned-Source Snapshot Policy

Decision: `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_06_NARROW_SOURCE_SNAPSHOT_POLICY_ACCEPTED`

Status: accepted as a docs-only policy. This phase defines how Inspectra may
approach future owned-source snapshot dogfood after the broad source dry-run was
safe-blocked.

## Why This Policy Is Needed

The broad filtered Inspectra source dry-run was safe-blocked:

- files scanned: `515`;
- helper records: `412`;
- allowed manifest/synthetic records: `7`;
- block decisions: `405`;
- unknown sensitive-marker records: `400`;
- blocked private-material records: `5`.

That result is expected and useful. Large source snapshots contain many
references that look like access handling, browser-session handling, redaction
contexts, auth flows, and record-shaped material. The local helper cannot safely
treat those references as approved fixture contexts without a narrower policy.

Until this policy is validated, manifest/config-only inputs remain the accepted
dogfood baseline.

## Snapshot Tiers

### Tier 0: Manifest/Config-Only

Status: accepted.

Tier 0 includes dependency manifests and bounded config-shape files only. The
accepted self-dogfood fixture lives here:

```text
tests/fixtures/project_archives/inspectra_manifest_only_self_dogfood/
```

Allowed use:

- local passive project archive smoke;
- local report/export regression checks;
- separately approved staging replay using only the accepted archive.

### Tier 1: Narrow Source-Safe Candidate

Status: future local dry-run only.

Tier 1 may include tiny, reviewed source path families that are unlikely to
contain access handling, browser-session handling, private records, generated
output, or live environment details.

Tier 1 is not pre-approved for upload. It must pass a future local helper
dry-run before any follow-up phase can consider it further.

### Tier 2: Broad Source Snapshot

Status: blocked by default.

Tier 2 includes broad source trees, broad docs, mixed app surfaces, full test
trees, and repository-wide snapshots. The broad Inspectra source dry-run showed
that this tier creates too many unknown marker contexts for safe dogfood.

Tier 2 remains blocked unless a later design splits it into Tier 1-sized path
families and validates them locally.

### Tier 3: Private/Runtime/Business Material

Status: always excluded.

Tier 3 includes local runtime state, private deployment material, generated app
data, business records, and files that may encode account, session, or access
state. Tier 3 is never eligible for owned-source dogfood snapshots.

## Tier 1 Candidate Path Families

Tier 1 should stay conservative. Candidate path families may include:

- parser-only modules that do not touch auth, browser-session, access-material,
  private-record, or live-target logic;
- report rendering modules when marker categories are absent or clearly bounded
  to report metadata;
- static fixture-independent formatters;
- metadata catalog files;
- carefully selected tests that use already-approved synthetic fixtures;
- tiny helper modules with deterministic local-only behavior and no app upload
  integration.

Candidate files remain subject to path/category rules. A candidate path is not
enough to allow a file.

## Always-Excluded Path Families

The following path families remain excluded from owned-source snapshots:

- repository metadata directories;
- environment override files such as `.env*`;
- local access-material config overrides;
- private key or certificate files;
- auth, browser-session, request-forgery, bearer-value, or API-value handling
  files;
- basic-auth verifier material;
- database files, dumps, backups, and restore artifacts;
- uploads, results, exports, reports, and generated app output;
- logs and cache directories;
- build output, distribution output, static asset builds, and staticfiles;
- vendored dependencies and local virtual environments;
- VPS, reverse-proxy, and deploy-local config;
- client or business records;
- broad docs that contain redaction/security marker wording;
- Active live-target lists or live-target examples.

For business apps, additional exclusions should cover media, invoices, quotes,
orders, payments, PDFs, and private business documents.

## Path/Category Decision Rules

Rules for future owned-source dry-runs:

- path alone is never enough to allow a file;
- any suspicious marker category in a candidate path blocks the file;
- approved synthetic fixture contexts remain allowed only under their approved
  fixture paths;
- manifest-only contexts remain accepted only under manifest/config-only
  boundaries;
- auth, browser-session, access-material, bearer-value, API-value, and local
  account-material categories remain blocked unless separately approved as
  synthetic fixture-bound examples;
- record-shaped material remains blocked;
- unknown marker contexts remain blocked;
- helper output should record only path, marker category, classification,
  decision, reason code, and summary counts.

## Future Dry-Run Design

Recommended next executable phase:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_07_NARROW_SOURCE_DRY_RUN
```

That phase should:

- build a tiny Tier 1 candidate snapshot in `/tmp`;
- run the helper locally only;
- record counts and path/category decisions only;
- perform no upload;
- accept the candidate only if blocked and unknown counts are zero, or if every
  non-zero record is clearly understood as fixture-bound and already approved;
- otherwise record another safe-block result.

## Product Decision

Do not pursue broad source upload now.

Keep public/private alpha dogfood on manifest/config-only archive inputs. Treat
source-snapshot dogfood as operator-only and local-only until this policy is
validated by a narrow Tier 1 dry-run.

## No-Go Boundaries

- no sanitizer weakening;
- no runtime preflight in this phase;
- no upload of source snapshots;
- no staging replay with source snapshots;
- no automatic allowlist for source paths;
- no stored marker strings or snippets;
- no app upload behavior, analyzer behavior, UI, storage, endpoint, runner, or
  Active behavior changes.

## Decision

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_06_NARROW_SOURCE_SNAPSHOT_POLICY_ACCEPTED
```
