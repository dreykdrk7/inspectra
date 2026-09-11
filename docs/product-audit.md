# Product action audit

Inspectra keeps a minimal, append-only history of high-value product actions so
an administrator can answer who changed or exported something without turning
the audit log into another copy of customer data. The contract version is
`2026-09-06.1`.

## Recorded data

Each event contains an opaque event ID, active organization ID, actor ID and
role, action, opaque resource type/ID, result, request correlation ID, UTC time
and a small allowlist of scalar operational fields. Supported context includes
opaque project/job/analysis IDs, analysis contract/profile, provider name,
source state, finding count, decision status, report format and target role.

The store never accepts usernames, workspace or project names, request/response
bodies, code, finding evidence, filenames, filesystem paths, URLs, package
identities, source hashes, cookies, CSRF/session/invitation tokens, passwords or
provider credentials. Unknown metadata keys and strings outside the restricted
identifier vocabulary are discarded before persistence.

Covered actions include successful login/logout and invitation acceptance;
workspace creation/selection, invitation creation, role changes and revocation;
project creation, snapshots, analyses, cancellation, baselines, finding
decisions, public-intelligence refreshes, report exports, source deletion and
reads or denied reads of the audit history.

## Authorization and isolation

`GET /audit/events` derives the organization exclusively from the authenticated
session; there is no organization parameter. In team mode only an
`administrator` can read it. Maintainer and reader attempts are denied and
recorded in their own organization. Trusted-local and self-hosted single-admin
modes use the existing `local-admin` boundary.

The endpoint accepts an exact `action` filter, a page size of 1–100 and an
opaque cursor returned by the previous page. Events are ordered newest first by
UTC time and event ID. A missing, malformed, foreign or expired cursor returns
a generic error and never falls through to another organization.

## Retention, capacity and failure behavior

- `INSPECTRA_PRODUCT_AUDIT_RETENTION_DAYS` defaults to 90 and is bounded to
  1–3650 days. Expired events are removed at application startup and before
  reads/writes.
- `INSPECTRA_PRODUCT_AUDIT_MAX_EVENTS` defaults to 50,000 and is bounded to
  1–1,000,000. It is a global hard cap across organizations.
- Events live under `data/results/product_audit/<organization-id>/` with opaque
  filenames and the same private storage boundary as other product results.
- Writes use an atomic replacement and a process/file lock. A corrupt record
  makes that organization's query fail closed rather than hiding the integrity
  problem.
- If an audit write fails after the primary action commits, Inspectra emits only
  `product_audit.persist_failed` to operational telemetry. It does not include
  the action, actor, resource, path or exception. The primary product action is
  not rolled back by an unavailable audit store.

## Chained integrity

Contract `2026-09-10.1` keeps a private ledger beside each organization's event
files. Every ledger entry has a monotonically increasing sequence, SHA-256 of
the exact event, the previous chain digest and its own domain-separated digest.
A private head records generation, retained anchor, head and exact count. A
strict verifier detects a changed event/entry/head, a missing tail or middle,
an inserted event and reordered entries. Reads, exports and new writes fail
closed when that organization's chain is invalid.

`GET /audit/integrity` is administrator-only and returns only `valid`, `empty`
or `invalid`, counts, sequences and the current head digest. It never returns
event IDs, actor/resource IDs, paths or failure detail. The UI tells an operator
to stop relying on an invalid history. A successful check creates the minimal
`audit.integrity_verified` event after the checked snapshot.

Existing unchained records are bootstrapped once in deterministic time/ID order
when first accessed; the response says `bootstrap_performed=true`. This proves
integrity only from that local bootstrap forward. Retention removes only an
expired leading prefix and advances the retained anchor before deleting files,
so the remaining segment stays verifiable. Authorized Active deletion that
anonymizes retained events creates a new generation linked to the previous head.

Backup validation verifies the complete event/ledger relationship before copy
or restore. If verification fails, stop the application, preserve the suspect
volume read-only for incident handling and restore a previously verified backup
into a new empty location. Do not delete a damaged entry or regenerate the
ledger: doing so destroys evidence of the integrity failure.

## Operator checks

1. Configure positive retention and capacity values before starting the private
   deployment.
2. Perform one synthetic high-value action and query `/audit/events` as an
   administrator. Confirm the action, actor role, resource and correlation are
   present without user/source content.
3. Query as a reader or maintainer and confirm `403`; query again as admin and
   confirm the denied event exists only in the active organization.
4. Inspect storage and logs for known synthetic markers representing passwords,
   invitation/session tokens, private paths, URLs, package identities and source
   content.
5. Call `/audit/integrity`, record the head outside the application if your
   custody policy requires it, and include the complete
   `results/product_audit` tree in encrypted backup/restore and expiry tests.

This log is operational evidence, not a SIEM or legal archive. The unkeyed
SHA-256 chain detects changes relative to its retained local head; it does not
protect against an attacker who can rewrite events, ledger and head together.
Clock trust, external anchoring/signing and transactional coupling to every
product store are not claimed.

## General redacted export

An administrator can export the same bounded activity domain for offline
investigation without copying the stored identifiers or metadata:

1. `GET /audit/export/preflight` accepts only `7d`, `30d`, `90d` or `365d`
   plus an optional exact, lowercase action. The organization always comes
   from the authenticated session.
2. The response contract `2026-09-10.1` declares the UTC window, total and
   included counts, truncation, retention, fixed privacy exclusions, expiry
   and a SHA-256 digest of the exact projected snapshot.
3. `POST /audit/export` requires the same period/filter, preflight time and
   digest, a closed JSON/CSV format and literal confirmation. A preflight is
   valid for five minutes. Changed, expired or empty snapshots fail closed and
   require a new preflight.

At most the newest 1,000 matching events and 1 MiB are emitted. Event, actor
and resource identifiers become stable organization-bound pseudonyms. Only
time, actor role, action, result and resource type remain; organization IDs,
original identifiers, correlations, all metadata, names, paths, targets,
source, evidence, bodies and credentials are excluded. JSON and CSV carry the
same fixed projection and snapshot digest, responses are `private, no-store`,
and the client verifies `X-Inspectra-Snapshot-SHA256` before offering the file.

The generated file is not stored by Inspectra. A successful export records
only `audit.events_exported`, format, period, bounded count and whether an
exact-action filter was used. Browser, proxy and downstream copies become the
operator's responsibility. This digest detects a changed selection; it is not
a signature or a tamper-proof custody chain (`PROD-110`).

## Bounded Active operational export

Workspace administrators can review and download a target-free projection of
Active audit activity without reading the audit store directly:

- `GET /audit/active-export/preflight` accepts only a fixed `7d`, `30d`, `90d`
  or `365d` period and an optional owner-scoped opaque Active asset ID;
- `GET /audit/active-export` accepts the same scope and only `json` or `csv`;
- both routes derive the organization from the authenticated session and remain
  administrator-only in team mode;
- the contract `2026-09-08.1` returns at most the newest 1,000 matching events,
  reports the pre-limit total and makes truncation explicit; and
- an empty preflight produces no download affordance in the UI.

The projection uses stable organization-bound pseudonyms for actors, events and
resources. It retains only UTC time, actor role, closed Active action/result,
closed resource type and a valid authorization revision ID/sequence when that
metadata exists. It excludes exact targets, authorization references, notes,
responsible identities, client IPs, correlation IDs, raw metadata, evidence,
job error text and runner results. Neither format is retained by Inspectra;
download custody and deletion are the operator's responsibility.

CSV begins with one `manifest` row containing the reviewed scope, counts and
truncation state, followed by fixed-schema `event` rows. JSON contains the same
preflight and events. Responses are `private, no-store` and capped at 1 MiB;
generation fails closed if that limit is exceeded. A successful download adds
`active_asset.audit_exported` to the underlying audit history, so a later export
can explain the earlier one without embedding its contents.

This is a convenient operational export, not signed evidence, an immutable
ledger or proof that every business action committed transactionally with its
audit record. Use the deterministic Active evidence bundle for bounded posture
artifacts and an approved external system if a cryptographic custody chain is
required.
