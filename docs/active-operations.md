# Active operations

Active is a separate, defensive observation workflow for assets that an operator
is explicitly authorized to assess. It is disabled by default at deployment and
does not turn observations into confirmed vulnerabilities.

In the local unpublished `0.3.0-beta.1` candidate, Active remains experimental:
its registry, authorization, operations and reporting flows are available, but
every live capability and its runner gate must be enabled independently. This
document does not authorize a target or a public deployment.

## Asset registry contract

Contract `2026-09-09.1` accepts one exact `domain`, `host`, IP address or HTTP
origin. Wildcards, CIDR/ranges, URL credentials, paths, queries and fragments
are rejected. Registration records:

- the canonical value and exact type;
- organization, registering owner and optional responsible member IDs;
- an allowlist of capabilities, protocols and explicit ports;
- a structured authorization method, short non-sensitive reference, start and
  expiry (at most 366 days);
- structured notes with a conservative secret-pattern guard; and
- a bounded append-only event history; and
- an immutable authorization revision with an opaque ID, sequence and SHA-256
  digest bound to the exact asset identity and structured scope.

The public revision object deliberately omits the exact target, organization,
authorization reference, notes and responsible identities. Its digest binds
the server-side exact target and organization plus the structured authorization
scope; references, notes and responsibilities remain current operational
metadata outside the revision. The digest is still sensitive owner-scoped
evidence and is not a safe replacement for publishing the target. Records
created before this contract load with an
explicitly empty revision history: they are shown as `legacy / unknown` and
cannot execute until the renewal flow re-attests them; Inspectra never invents
historical revision evidence.

Only the current organization can list or read its assets. Interactive
administrators and maintainers can register and revoke; readers are read-only
and automation credentials cannot access Active. Revocation is immediate and
idempotent. Expiration is evaluated at read/admission time, so a stale stored
`active` value cannot keep an expired authorization executable.

### Bounded portfolio listing

The operations center uses `POST /active/assets/search`, contract
`2026-09-08.1`,
instead of loading the complete registry. A page contains 24 records by default
and at most 100. Status, capability, a 7/30-day update window, and canonical
target prefix or exact match are evaluated by the backend within the current
organization. The response reports only the returned page and whether another
page exists; it does not expose another organization's records or counts.
The closed JSON body carries filters and cursor so an exact or partial asset
identity never enters the URL/access log; authenticated browser sessions apply
the normal CSRF control to this read-only POST.

Continuation uses a URL-safe, authenticated cursor bound to the organization,
the complete filter set, the update-window cutoff, and the last stable
`updated_at`/opaque-ID sort key. A modified, cross-organization or
different-filter cursor fails with the same generic validation response. Newer
records inserted after page one do not appear in an older continuation, which
prevents duplicates while an operator is paging. Changing a filter starts a new
view and an older in-flight response is discarded rather than replacing the
newer result. Loading another page preserves the selected filters, already
loaded records and the button's keyboard position. A failed continuation leaves
the current page usable and offers a safe refresh.

The browser renders at most 96 matching assets (four default pages) in one
view. If more records exist, the page status explains that the safe display
window has been reached and requires a narrower server-side filter; exact
search can still retrieve a record outside the initial window. This is a DOM
and perceived-performance boundary; the first 96 records do not represent the
complete portfolio. The
section exposes loading state through `aria-busy`, partial summaries are
labelled explicitly, and expanding a card changes the control name to
`Close details` while linking it to the controlled panel.

Cursors are deliberately short-lived process capabilities: the current
single-backend-process deployment rotates their in-memory signing key on
restart, so a saved cursor must restart at page one after a backend restart.
They are not durable bookmarks. A private `active_asset_index.sqlite3`
projection resolves pages and exact portfolio aggregates without opening the
complete owner registry. JSON records remain authoritative: every selected row
is loaded and matched to its digest before return. The projection is
owner-scoped, limited to 256 MiB, mode `0600`, checked by readiness and backup,
and rebuilt from validated JSON after process change, schema mismatch or
recoverable corruption. Invalid authoritative JSON or unsafe filesystem
topology fails closed rather than silently omitting an asset.

The legacy unbounded `GET /active/assets` array was retired on 2026-09-08 after
the repository consumer inventory found no remaining product caller. An
authenticated call now returns target-free `410 Gone`, `Deprecation`, `Sunset`,
`Link: </active/assets/search>; rel="successor-version"` and `Cache-Control:
no-store`; it never evaluates legacy query parameters. The tombstone is retained
through 2026-12-01 so integrations receive an explicit migration error instead
of a shape mismatch. Do not place an asset identity in that old URL: clients,
proxies or access logs may record any URL before Inspectra rejects it.

Integrations must send filters in the JSON body of `POST /active/assets/search`
and follow its opaque cursor. A minimal first-page request is
`{"page_size":24,"query_mode":"prefix"}`; an exact identity lookup adds
`"query":"…","query_mode":"exact"`. Browser sessions must also send their
normal CSRF header. Responses are bounded pages and never reveal another
organization's total.

Inspectra stores neither authorization documents nor DNS/HTTP responses, tokens,
commands, raw tool output or credentials in this registry. The authorization
reference is a label such as a change-ticket identifier, not proof of legal
ownership. Operators remain responsible for establishing permission outside
Inspectra.

### Identity uniqueness and deletion exclusion

The registration key is `(organization, asset_type, canonical_value)`. Individual
and batch registration evaluate that same key under the shared storage lock and
include records already hidden by an in-progress deletion. Two backend/store
instances racing to add the same identity admit exactly one; a duplicate in a
different organization is unrelated and remains allowed. The API returns a
workspace-local `409` without echoing the submitted target or revealing another
organization.

Deletion uses a conservative owner-level exclusion after its write-ahead marker
exists. Until all derived artifacts are removed and that marker is cleared, no
new Active identity is admitted for the same organization. This short block
prevents a registration after the old asset file disappears but before cleanup
has been proved complete. Recovery clears the marker only after the existing
orphan checks pass; the identity can then be registered again with a new opaque
asset ID and fresh authorization revision.

Existing duplicate records are never merged, rewritten or deleted during
migration. The operations summary reports only the count of duplicate identity
groups and records, never their identity. The UI asks the operator to review
them while blocking any third registration. Unrelated identities remain usable;
the operator must compare retained authorization/history and explicitly delete
the superseded record through the normal preflight flow.

## Responsible accounts

An asset may be unassigned or name up to 20 responsible accounts. In private
team mode, every supplied opaque account ID is checked against the current,
active membership of the selected workspace on both registration and renewal.
Administrators, maintainers and readers may all be responsible; assignment is
operational metadata and never grants write or execution permission. The
bootstrap administrator is represented by its account ID (`team-admin`), not
the bootstrap organization boundary (`local-admin`). Trusted-local and
single-administrator modes accept only the current local operator.

The same generic validation error is returned for inactive, revoked, unknown
or other-workspace IDs and never echoes the submitted identifier. Membership
validation and the asset write are serialized so a concurrent departure cannot
reintroduce an orphan assignment. The UI loads the current workspace directory,
displays usernames only to existing members of that workspace, and preserves an
existing assignment if the directory is temporarily unavailable.

`POST /active/assets/{id}/responsibles` changes only operational assignment. It
requires an explicit confirmation and the asset's last `updated_at` value; a
concurrent edit returns `409` and requires a reload. It does not append or alter
an authorization revision. Its Active history event records only the generic
assigned/unassigned reason and actor, never the selected account IDs, usernames
or target. Markdown reports likewise omit responsible identities.

Before removing a workspace member, an administrator reviews aggregate impact:
assets affected, assets that will become `unassigned`, and assets retaining
another responsible. The response contains no asset names or targets. On
confirmation Inspectra invalidates all sessions of the departing member first,
then revokes membership and removes that account from every affected asset under
a serialized transaction/lock order. Active history remains append-only with a
generic `membership_revoked` event. If reconciliation fails, membership is
rolled back while sessions stay invalidated; the administrator can safely retry.
An interruption during the multi-file asset phase may conservatively remove
some assignments while leaving membership active, but cannot preserve access
for a departed account; a retry is idempotent and completes reconciliation.

## Renewal and re-attestation

`POST /active/assets/{id}/renew` appends a new revision for the same exact
asset. It requires the expected current revision (or explicit `null` for a
legacy record), a private 128-bit idempotency key, a complete replacement
scope and a fresh authorization attestation. The exact target and asset type
cannot be changed through renewal. A duplicate request with the same key and
identical normalized content returns the existing revision; reusing that key
for different content or after a later revision fails closed.

Adding any capability, protocol or explicit port requires the separate
`scope_expansion_confirmed` confirmation. Removing scope or renewing it without
expansion does not. The backend remains authoritative and enforces a maximum
366-day authorization window, the expected revision under the storage lock and
the 64-revision/500-event bounds. Expired records can return to `active` only
through a new revision; revoked records can never be renewed or reactivated.

The UI shows the append-only revision history, highlights expansion and asks
for both the general re-attestation and the expansion-specific confirmation.
Product audit records only opaque revision ID/sequence plus closed replay and
expansion booleans—never target, reference, responsible identity or request
body. Markdown reports likewise omit the exact target and list only structured,
target-free revision evidence.
The expansion decision is stored on the immutable revision itself, so an
idempotent replay remains explainable even after later verification or
execution events are appended.

## Optional four-eyes approval

`INSPECTRA_ACTIVE_FOUR_EYES_ENABLED=false` is the safe default. Enabling it is
supported only with `private_team_lightweight_users`; any other authentication
mode fails closed for critical changes. A maintainer or administrator requests
one individual registration, renewal (including scope expansion/reduction) or
ordinary revocation. A different, current administrator must approve it, and
only the original requester can apply the exact reviewed change. Approval is
bound to organization, change kind, existing asset when applicable, and a
SHA-256 digest of the closed security-relevant fields. Changed scope, target,
expiry or expected revision requires a new review.

Requests expire after 24 hours and are one-use. A process interruption after a
claim marks the request `interrupted`, scrubs a proposed registration target and
requires a fresh request; Inspectra never guesses whether replay is safe. A
rejected, expired or consumed registration likewise loses its target. Closed
metadata is retained for at most 90 days and is purged per organization; an
explicit Active asset deletion also removes its related approvals. Backup and
restore validate tenant and asset references before accepting this store.

The approval record deliberately excludes authorization references, notes,
responsible identities, idempotency keys and the complete mutation payload.
Only maintainers/administrators in the same workspace can list actionable
reviews. Product-audit events contain opaque approval IDs and closed reason
codes, never the target or actor digests. The browser exposes loading, empty,
error, pending, approved, terminal and interrupted states without weakening the
backend check.

Batch registration is unavailable while four-eyes is enabled because one
approval must correspond to one exact identity and diff. This version has no
bulk quorum workflow. To contain an urgent incident, a current administrator
may revoke an asset immediately with the closed reason `security_hold`; that
bypass is recorded explicitly. Ordinary revocation still requires separation
of requester and approver.

## Product flow

The **Active operations** center lists exact assets, status, expiry, authorized
capabilities and the minimal timeline. Search and status filters are scoped to
the current organization. Registration derives protocols from selected
capabilities, makes expiry visible and requires a final authorization
attestation. Revocation requires an explicit confirmation and blocks later
admission.

### Weekly action inbox

`GET /active/operations/summary`, contract `2026-09-09.4`, includes a bounded
owner-scoped `action_queue`. Each item contains only an opaque action ID, closed
kind/urgency/action code, opaque asset and optional job IDs, recorded timestamps
and an occurrence count. It never includes the target, authorization reference,
notes, raw result, secret, path or user-supplied explanation.

The backend derives actions from current state: expired or soon-expiring
authorization, failed/expired optional verification, the latest failed or
degraded execution per asset and capability, and comparable observation changes
that have no decision or remain explicitly `needs_review`. A closed triage
decision clears only its matching signal from the action while preserving the
historical comparison. A later successful execution clears an earlier failure
from the queue. Ordering is deterministic: `immediate`, `high`, `scheduled`,
then `review`, followed by due/reference time and opaque IDs. At most 100 items
are returned; `items_truncated` and `source_incomplete` prevent the UI from
presenting a bounded window as complete.

For portfolios above 500 assets, candidate selection is also priority-aware:
expired authorizations are selected first, followed by assets whose latest
verification or latest execution per capability is failed, authorizations due
within 14 days, degraded latest executions, and finally the most recently
updated remaining assets. The job and verification signals come from their
validated owner-scoped projections; an older successful execution supersedes
an older failure. Selection never widens beyond 500 assets, 2,000 jobs and one
verification per asset. `limits.selection_strategy` is
`priority_then_recency`, while `limits.priority_candidates` reports how many
selected assets entered before the recency fill. Comparable observation changes
still require materializing bounded job evidence, so `source_incomplete` remains
true whenever the portfolio/history exceeds the window; priority selection is
not a claim of exhaustive posture or an SLA.

Resolution controls also follow current authorization. An expired asset exposes
the renewal action and suppresses retry/reverification until a new revision is
valid; a revoked asset never advertises either operation. A removed capability
likewise suppresses retry for its historical failed job. Retained evidence stays
reviewable, but the weekly inbox does not offer an action the admission boundary
will reject.

The browser translates only those closed codes into explanatory copy, can
filter priority and recorded-state age, and keeps those two preferences in
local browser storage. These filters do not mutate server state. Dates explain
why an item is ordered, but Inspectra does **not** infer an organizational SLA,
a vulnerability, or successful remediation. Selecting an item resolves the
owner-scoped asset through `GET /active/assets/{opaque-id}`, pins it when it is
outside the current portfolio filters, updates a bookmarkable fragment, opens
the existing detail and moves keyboard focus there. Resolution continues to use
the existing renewal, verification, retry, review and triage controls; their
successful mutations refresh the summary rather than dismissing work only in
the browser.

Known limit: this is a current bounded operational inbox, not durable work-item
assignment or SLA tracking. Its age uses the summary's UTC `generated_at`, not
the browser clock, so a response and its UI remain reproducible across local
time zones. An inaccessible or deleted deep link returns the same workspace-
scoped error and does not reveal the target.

## Asset-bound executions

`POST /active/assets/{id}/executions` accepts only a capability, an optional
port selector for TLS, a literal authorization reconfirmation and a private
128-bit idempotency key. It accepts no
target, URL, host, domain, port list, command or profile. The server derives the
exact target and immutable bounded profile from the registry, validates the
capability and port, and reads current authorization both at admission and
immediately before crossing the capability boundary.

Admission persists a `queued` job before any capability traffic. The public
response never returns the idempotency key or its stored SHA-256 digest. An
exact replay returns the existing job and does not append another asset event
or contact the runner; reuse for different work returns `409`. A persisted
compare-and-set moves one job from `queued` to `running`, preventing two
backend workers from executing the same attempt. Progress uses the closed
phases `admitted`, `waiting_for_runner`, `executing`, `normalizing` and
`terminal`; the UI polls only while a job is in flight.

`POST /active/assets/{asset}/executions/{job}/cancel` first persists
`cancelling`, then signals only that owner- and asset-bound runner call. Partial
output is discarded. `POST .../{job}/retry` accepts only a failed or cancelled
attempt, requires a fresh authorization reconfirmation and idempotency key,
rechecks both runner gates and creates a linked job through `retry_of_job_id`;
it never rewrites the prior attempt.

At startup, never-started queued Active work is revalidated against the exact
authorization revision, capability gate, port and execution profile before it
is dispatched. Changed or incomplete bindings fail with `recovery_rejected`
and no runner traffic. Work interrupted after reaching `running` or
`cancelling` is closed as failed because Inspectra cannot prove that replaying
it would avoid duplicate traffic. Shutdown cancels tracked tasks and persists
the controlled interruption state.

Jobs persist the opaque asset ID, contract version and the immutable revision
ID, sequence and digest captured at admission. A second registry read immediately
before crossing the runner boundary must resolve to that same revision; a
concurrent authorization change fails closed. Later lifecycle updates cannot
replace this evidence. Target fields and results retain the established redacted representations. DNS inventory disables
subdomain discovery and AXFR in this flow. Redirects and observed DNS/CT names
never produce a second target. A concurrent revocation cancels the internal
runner request for Nmap, DNS, CT, HTTP or TLS and persists a terminal
`cancelled` job without the target.

All five live capabilities cross an internal `active-tools` boundary. The
backend never performs their DNS, CT, HTTP, TLS or Nmap network operation and
has no direct-network fallback. For the four non-Nmap capabilities it sends
only the exact registry-derived target, one fixed capability/profile pair, the
authorized TLS port when applicable, a contract version and a backend
confirmation bit. The runner exposes only fixed relative routes, requires its
own per-capability opt-in, and returns a capability-specific bounded result.
The backend client accepts only a configured private/local service URL without
userinfo, path, query or fragment; it follows no redirects, waits at most eight
seconds, accepts at most 256 KiB and rejects target reflection, command/output,
credential, token or raw-response keys. At most four of these requests run
concurrently per backend process.

Enabling a capability therefore requires both its existing backend flag and the
matching runner flag. `active-tools` is internal, publishes no host port, uses a
read-only filesystem, drops capabilities and is the only Active execution
service attached to the dedicated egress network. The Compose egress network is
not a destination firewall: professional deployments must additionally enforce
their authorized network policy at the host/orchestrator boundary.

Free-target live routes are retired by default. An isolated compatibility flag,
`INSPECTRA_ACTIVE_LEGACY_FREE_TARGETS_ENABLED`, exists only for migration and
test-contract review; enabling it reopens the older risk boundary and is not a
supported professional product configuration. The no-network dry-run remains a
separate planning aid.

## Threats and limits

- Canonicalization prevents wildcard/range expansion and embedded URL secrets.
- The organization directory and record identity are checked on every read.
- Events store only actor ID, time, closed kind and optional closed reason code.
- No discovered DNS name, redirect location or observed address becomes an
  authorized target.
- Manual attestation is intentionally distinct from optional control
  verification. Verification never establishes legal ownership.
- Targets are sensitive operational metadata. Access to data storage and backups
  must be restricted even though responses are organization-scoped.

All ordinary tests use synthetic `.test` targets, fixtures or simulated local
adapters; the suite does not send network traffic.

## History, posture and team decisions

The asset detail keeps authorization events and asset-bound executions in one
timeline. Posture compares only terminal executions produced by the same
capability and authorization contract. An operator can select a compatible
execution as baseline; without one, Inspectra uses the latest two compatible
executions. Different capabilities are never merged into a trend.

Execution history is loaded through
`POST /active/assets/{asset_id}/executions/search`, with 50 rows by default and
100 at most. The response total belongs to the immutable first-page cutoff;
continuation uses an opaque HMAC cursor bound to the owner, asset, filters,
cutoff and last row. Newer concurrent executions do not move that snapshot.
An explicitly selected retained execution is resolved through
`GET /active/assets/{asset_id}/executions/{job_id}` and returns only the safe
summary projection, never the raw result. Missing, foreign-owner and
foreign-asset selections share the same `404` response.

Every execution row displays its authorization revision. Comparisons identify
whether both observations used the same revision; legacy evidence is labelled
`unknown` and makes the comparison inconclusive rather than synthesizing a
revision. Markdown export uses only an opaque asset reference, withholds the
exact target and includes the revision label for current and historical work.

Normalized posture is deliberately small and source-specific: TCP port states,
DNS record counts and selected policy-presence flags, HTTP security-header
presence, or basic TLS protocol/certificate availability. It includes explicit
coverage, truncation and error reasons. New, persistent, changed and disappeared
signals are observations: a disappeared port is not proof of remediation, and
an observed DNS name never becomes authorized scope.

Triage is a closed asset-level decision (`needs_review`, `acknowledged`,
`expected_change` or `dismissed`) rather than a free-text evidence store. Markdown
export contains the same bounded facts, authorization state and comparison
limits; it does not include raw tool output, commands or unredacted target
fields.

The visible posture computation uses at most the newest 500 asset executions
and declares that boundary. A saved baseline outside that window is resolved
directly and checked for capability and authorization-contract compatibility.
Reports and evidence selection use the complete indexed owner/asset aggregate;
revocation independently selects every in-flight execution for the asset. A UI
page or posture window is therefore never an authority for export or control.

## Optional control verification

Control verification is a separate contract (`2026-09-09.1`) and remains off
unless the operator sets `INSPECTRA_ACTIVE_ASSET_VERIFICATION_ENABLED=true`.

The UI and `GET /active/verification/configuration` expose the effective state
without revealing infrastructure details. Disabling it blocks challenge
creation and checking; revocation stays available so an operator can invalidate
previous evidence after the flag is turned off.

Each challenge is displayed once, expires after 15 minutes and is limited to
five creations per asset and hour. Inspectra stores only its SHA-256 digest,
method, closed state/reason, timestamps and opaque asset/organization IDs. A
successful control signal lasts at most 90 days and never beyond the underlying
authorization. Reuse, wrong tokens, other organizations, expired assets and
incompatible asset/method combinations fail closed.

Challenge history, supersession, rate limiting and explicit asset deletion use
an exhaustive owner/asset lookup in the private verification index rather than
scanning every verification JSON in the organization. Selected records are
loaded in stable order and must match owner, asset and full-record digest. Index
schema v3 persists only a closed filesystem-state marker in addition to opaque
IDs, statuses, timestamps and digests. A restart adopts the `0600` SQLite only
after schema, integrity and source-marker checks; mismatch rebuilds from
authoritative JSON and malformed source data fails closed.

Supported methods are:

- structured manual attestation, explicitly labelled as an assertion rather
  than proof of legal ownership;
- one TXT lookup, executed only by `active-tools`, at
  `_inspectra-verification.<exact-asset>` with at most eight answers;
- one GET, executed only by `active-tools`, to the exact public origin at
  `/.well-known/inspectra-verification`, pinned to a prevalidated global IP,
  with a three-second timeout and 512-byte body limit; redirects are returned
  as a failed status and never followed; and
- an operator-supplied managed-private checker. It is reported unavailable
  unless the deployment installs that adapter; private/loopback addresses are
  never sent through the public HTTP verifier.

Remote verification needs two independent opt-ins:
`INSPECTRA_ACTIVE_ASSET_VERIFICATION_ENABLED=true` in the backend and
`INSPECTRA_ACTIVE_TOOLS_ASSET_VERIFICATION_EXECUTION_ENABLED=true` in the
isolated runner. The UI offers DNS/HTTP only when the targetless runner health
attestation confirms the second gate. The backend derives the exact record or
origin from the immutable asset and sends it with the one-time token through the
single fixed internal `/active/asset-verification` route. It has no DNS, socket,
TLS or HTTP fallback for these methods.

No public request accepts a URL, hostname, path, resolver, port or redirect
target for verification. The internal request schema is closed; the runner
response is only `matched` plus a reason code and never echoes target or token.
DNS/HTTP result bodies, complete answers, response
headers and the challenge token are never persisted or written to product-audit
metadata. The product audit stores only closed method and outcome codes. DNS
resolution still reveals the exact verification record to the deployment's
configured resolver; operators must account for that in their privacy model.
Revocation cancels an in-flight internal request through a process-local signal
or persisted polling across backend workers. All ordinary tests use fake
transports and synthetic targets, with no Internet.

## Recurring authorized reviews

Recurring Active review is a separate operator opt-in and remains disabled by
default. Enable it only with the isolated Active runner already configured and
healthy:

```env
INSPECTRA_ACTIVE_RECURRENCE_ENABLED=true
```

An administrator or maintainer may create at most one policy for each exact
asset/capability/port tuple, with a cadence of 7, 14 or 30 elapsed UTC days and
one explicit weekly civil-time window. The request accepts only an installed
IANA timezone, one or more distinct weekdays, a whole-hour start and a 1–12
hour duration that cannot cross local midnight. It accepts no cron expression,
URL, target or free-form scheduling input. Each next eligibility time adds a
stable schedule-specific jitter of 1–900 seconds so policies created together
do not form a dispatch herd.
The policy stores opaque identifiers plus the immutable authorization revision
and verification identifiers; it never stores another target, a challenge,
runner output or a free-form schedule. Each due occurrence re-checks asset
status, scope, the exact authorization revision, verification state, capability
gate and isolated-runner readiness before creating an idempotent job. Revoking
authorization or verification suspends future runs immediately. Pausing and
deleting are explicit; resuming rebinds to the then-current revision and
verification. Readers may inspect policies but cannot mutate them.

Missed cadences collapse into one pending occurrence and never create a catch-up
storm. Temporary runner unavailability, saturated capacity and dispatch
conflicts leave that occurrence pending without claiming success. They use a
persisted exponential retry delay beginning at five minutes, capped at six
hours, plus a stable 0–60 second retry jitter. If that time falls outside the
weekly window it advances to the next valid window; it never executes early or
replays every missed interval. After restart the same counter and eligibility
time are loaded from disk. Atomic compare-and-swap on `updated_at` ensures two
scheduler instances cannot both advance the same policy; the durable Active job
idempotency/claim remains the execution guard.

Daylight-saving behavior is part of contract `2026-09-08.2`. A window whose
start or end is a nonexistent local instant is skipped for that week. At an
ambiguous fall-back boundary Inspectra uses the earliest real start and latest
real end, so both occurrences of the repeated local hour are inside one bounded
window. The UI displays the selected timezone, window, next eligible instant,
retry attempt/outcome and authorization expiry. No next execution or retry is
advertised once the current authorization cannot contain it.

Policies stored under legacy contract `2026-09-08.1` did not retain an
authorization expiry. They load suspended and require an explicit resume to
bind the current immutable authorization and verification; Inspectra does not
infer a missing permission boundary. Structured operational telemetry records
only opaque policy correlation, closed outcome, attempt count and whether a
retry remains scheduled—never target, authorization reference, runner output,
path, secret or code. This recurrence contract is scheduling behavior, not an
availability SLA.

Scheduler discovery uses a private schema-v1 SQLite projection while the JSON
policy remains authoritative. The index contains only opaque organization,
asset and schedule IDs, closed status, next-run/retry timestamps and a complete
record digest. It does not retain target, capability/port, actor, verification
ID, authorization ID/digest/reference, token or runner data. A tick selects no
more than 16 timestamp candidates in stable order and reloads each JSON to
validate owner, asset, state, timestamps, digest and civil-time window before
the existing authorization and runner gates are evaluated. Asset-scoped list,
count, suspension and deletion use the same validated aggregate. Restart may
adopt the projection only when its private permissions, schema, integrity and
source-directory marker match; otherwise it is rebuilt exclusively from JSON.
This optimization does not widen scope or make the index an authorization
source.

## Organization operations summary

`GET /active/operations/summary` is the bounded, organization-scoped read model
used by the Active operations center. It reports authorization state and
expiry, optional verification state, execution lifecycle, comparable changes,
pending attention and the effective capability gates. It deliberately returns
counts and closed status codes only: exact targets, asset/job identifiers,
authorization references, raw observations and verification evidence are not
part of this response.

The read model obtains exact owner-scoped asset/status/expiry/duplicate totals
from the validated asset projection, then materializes at most 500 asset JSON
records. A separate private job projection reports the exact number of Active
jobs while loading at most 2,000 candidates for those assets. It also indexes
closed metadata for every job so general and Active admission can count in-flight
work without reading historical JSON. A third projection
selects at most the latest verification JSON for each considered asset. Every
selected record must match owner, relation and full-record digest. All three
SQLite files are rebuildable derivatives, mode `0600`, capped at 256 MiB and
covered by readiness plus backup validation; their tables contain only opaque
identifiers, closed state, timestamps and digests. The job projection stores
only the already-hashed Active idempotency key when one exists. None stores
targets, authorization references, raw keys, raw observations or challenge
material.

The same job projection backs the general analysis history. `POST /jobs/search`
accepts only a closed status, audit type, optional opaque project ID, page size
up to 100 and an authenticated cursor in the JSON body. It orders by immutable
creation time plus job ID, reports the exact filtered total and loads only the
selected page's authoritative JSON records. The cursor is bound to owner and
filters and intentionally expires on backend restart; clients restart at page
one after the generic cursor error. `GET /jobs` remains a deprecated transition
surface, returns at most 100 recent records and advertises the POST successor;
it no longer materializes the full history.

Project timelines use the same contract through
`POST /projects/{project_id}/analyses/search`; the project identity is resolved
from the authenticated owner's store rather than trusted from the request body.
The deprecated project `GET` is likewise capped at 100 and advertises its POST
successor. Both interfaces keep cursors in closed JSON request bodies so access
logs and intermediary URLs do not acquire pagination state.

Findings, component inventory, public-intelligence and comparison selectors do
not auto-fetch the complete project history. Each begins with the recent page,
discloses loaded versus exact total and offers bounded continuation. A saved
baseline outside that page is resolved through the owner/project-scoped
`GET /projects/{project_id}/analyses/{analysis_id}`, which returns only the
list-item summary rather than the retained result. A missing or foreign
analysis is indistinguishable from any other not-found record.

The job projection also serves internal steady-state control paths. Global
admission/readiness and owner/project in-flight checks use exact indexed counts;
recovery readiness obtains only opaque in-flight project job IDs. A project
view without an explicit analysis loads and digest-validates only its newest
completed record. Active asset history selects at most 500 owner/asset rows and
validates every authoritative JSON before use. These queries do not project or
return targets, source identities, authorization material or result content.
Job records must only be mutated through `JobStore`. An approved offline
restore or legacy migration that replaces authoritative JSON must stop writers
and rebuild/resynchronize the derived index before serving admission or history;
a digest/status mismatch fails closed instead of trusting stale projection data.
The job index persists a closed filesystem-state marker. A new backend process
may adopt the existing `0600` index without parsing terminal history only after
schema, SQLite integrity and that marker match the current jobs directory.
Mutation through `JobStore` advances the record and marker under the common
storage lock. A missing/old marker, schema change, restore onto a different
filesystem or directory-state mismatch triggers a rebuild from authoritative
JSON; insecure index/source metadata or invalid JSON still fails closed.

The response publishes exact asset totals, exact total Active jobs, considered
counts and `limits.incomplete`. Verification/job status, capability, comparison
and action counts remain bounded operational detail when that flag is true; the
UI says so explicitly and must not present those windowed counts as a complete
portfolio assessment. A failed summary request degrades independently:
the owner-scoped asset list and its registration, execution, triage, export and
revocation actions remain usable.

The center provides server-side prefix/exact-target, status, capability and
recency filtering, plus explicit initial loading, empty, partial, continuation
and error states. Its portfolio changes remain observations rather than vulnerability
findings. Operator flags are exposed only as booleans, never with resolver,
runner, network or credential details. Readers can inspect the center but all
mutating controls remain restricted to maintainers/admins under the existing
organization policy.

### Effective runner readiness

The operations summary never treats a backend feature flag as proof that a
capability can run. For each of the five Active capabilities it combines the
backend policy with a targetless `GET /health` attestation from the isolated
`active-tools` service:

- `disabled`: the backend operator policy is off, irrespective of the runner;
- `ready`: both backend and runner gates are on and the complete health
  contract is valid;
- `degraded`: backend is on but the runner gate is off or its attestation is
  malformed, incomplete or internally inconsistent; and
- `unavailable`: backend is on but no runner is configured, the runner cannot
  be reached, or the bounded request times out.

Health is deliberately not an analysis operation. It accepts no target or
request body, invokes no capability, follows no redirects, is capped at two
seconds and 4 KiB, and must report all five fixed capability identities with
`target_input_allowed: false`. The backend rejects a different service
identity, missing/extra fields, status/gate mismatches, analysis traffic or
Nmap execution. Responses and logs expose only closed states and reason codes;
the configured internal URL, host and path are never returned.

If health fails, only the aggregate summary degrades: the owner-scoped asset
registry remains readable. The UI nevertheless fails closed for execution and
labels the selected capability `Unavailable` or `Degraded`; a reconfirmation
checkbox cannot enable the run button until effective readiness is `ready`.
Operators must enable the matching backend and runner flags independently and
should verify the off/on states with the internal-only Compose example before
allowing weekly use.

### Atomic admission quotas

Registered-asset execution has a second, Active-specific admission boundary on
top of the general job queue. The defaults permit at most 16 Active executions
instance-wide, four per organization, two per exact asset and four for any one
capability. Operators may lower these values with
`INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS`,
`INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_ORGANIZATION`,
`INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_ASSET` and
`INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_CAPABILITY`; their relationships are
validated at startup.

Admission and idempotency replay run under the same persisted storage lock, so
concurrent backend workers cannot over-admit the same bounded scopes. A rejected
request returns the same retryable `429` and `Retry-After: 5` for every saturated
scope. Neither the API nor the UI exposes quota values, competing organization
activity, exact targets or retained queue counts. The organization summary only
publishes `capacity.admission` as `ready` or `saturated`.

The admission boundary uses the validated private job projection rather than
scanning the retained history. General global/owner quotas and the four Active
quota dimensions are exact index aggregates. A replay lookup is scoped by owner
and the already-derived SHA-256 key, loads at most the single matching JSON, and
checks its owner and full-record digest before returning it. Corruption,
insecure index permissions or invalid authoritative JSON fail admission closed
with a generic recoverable error; a structurally stale derivative is rebuilt
from authoritative records under the same lock.

Queued, running and cancelling jobs consume capacity. Completed, failed and
cancelled jobs do not. Owner cancellation is persisted before the local signal;
a running job remains `cancelling` until its worker observes the request and
discards partial results. Authorization revocation immediately closes queued
work and persistently requests running work to stop, including when the request
and runner are handled by different backend workers.

## Bounded batch registration

Maintainers and administrators can open **Import batch** in the Active
operations center and upload either a JSON array of the existing single-asset
contract or CSV with the exact documented header. Admission is deliberately
small: at most 50 rows and 128 KiB. Wildcards, CIDR expansion, URL credentials,
HTTP paths, unknown fields, invalid members and unsupported capability/scope
combinations are rejected by the same strict validators as individual
registration.

`POST /active/assets/batch/preflight` parses the bytes in memory and returns an
explicit result for every row: ready, invalid, duplicate in this file or
already registered in the current organization. No row is silently skipped.
Only a completely ready review receives a five-minute, actor-and-organization
bound token. The token retains digests only; neither the source bytes nor its
filename is durable. Changing one byte requires another preflight.

After the user reviews all exact identities/scopes and confirms the whole
batch, `POST /active/assets/batch` revalidates the same bytes and current team
membership. Publication occurs under the persistent storage lock with a
target-free write-ahead journal, deterministic opaque record IDs and an
idempotency receipt. A normal failure rolls back all records; startup recovery
either removes a partial batch or finalizes one whose complete records were
already committed. Repeating an uncertain request with the same source, token
and idempotency key returns the same records. A changed source/key combination,
new conflict or missing member fails closed without a partial registration.

The durable receipt contains only organization ID, opaque batch/record IDs,
normalized digest and commit time—never target, filename, authorization
reference, notes or idempotency key. It is included in offline backup and its
owner/reference integrity is validated on restore. Explicitly deleting any
asset from the batch removes the whole replay receipt so an old retry cannot
recreate deleted scope. Batch registration executes no capability and performs
no egress.

## Durable portfolio index

The owner-scoped search endpoint is backed by
`results/active_asset_index.sqlite3`. This file is a private, derived index;
the validated JSON aggregate under `results/active_assets/<organization>/`
remains the only source of truth. The index contains canonical targets and must
therefore receive the same `0600`, encrypted-volume and backup protections as
the aggregate. It is capped at 256 MiB, uses no network, and is never returned
by an API or included in an evidence/report export.

The first readiness check or Active index operation in each backend process
rebuilds the complete index from the JSON records after startup has recovered
batch journals. This lazy boundary avoids filesystem/database work for
installations that keep Active disabled. Normal create, renewal, revocation, assignment, triage,
baseline and deletion mutations update the aggregate and index under the same
cross-process storage lock. A page query asks SQLite only for a bounded set of
opaque IDs, then reloads and digest-checks those selected JSON records before
returning them. Status expiry is evaluated at request time rather than trusted
from the index. Exact/prefix, status, capability, recency and cursor boundaries
remain organization-bound parameters; no SQL fragment is user-controlled.

File or directory state changes from another Inspectra worker trigger a safe
rebuild. A malformed/stale index is rebuilt from JSON; malformed authoritative
JSON fails closed as `asset_store_invalid` and must not be deleted or edited by
the application. `/ready` includes index integrity in its existing `storage`
gate. Direct/manual edits to either store are unsupported: stop all instances,
preserve the original data, repair the authoritative JSON through an approved
recovery procedure, and restart to rebuild the derivative. This is repair, not
silent omission or automatic deletion of an asset.

The reproducible scale regression uses 10,005 synthetic records across two
owners, proves that one 100-item page reads at most 101 JSON aggregates, and
requires local p95 below 500 ms after warm-up with bounded memory. This is a
regression budget on the project test environment, not a customer SLA.

CSV list fields use `|`; optional `notes` is a JSON array. The exact header is:

```text
asset_type,value,responsible_user_ids,capabilities,allowed_ports,allowed_protocols,authorization_method,authorization_reference,authorized_at,expires_at,notes
```

## Explicit asset deletion

Maintainers and administrators can request a target-free deletion preflight at
`GET /active/assets/{asset_id}/deletion`. It reports only closed data classes,
counts and blocker codes. Queued, running or cancelling executions and pending
control challenges block deletion; the caller must resolve or cancel them and
refresh the preflight. The UI never repeats the asset target in this destructive
flow and requires the exact structured confirmation before calling `DELETE`.

Deletion creates a private write-ahead marker under
`runtime/active_asset_deletions`. While that marker exists, the asset is hidden
and every mutation, new execution and new verification fails closed. Startup
recovery resumes the same idempotent cascade: verification records, terminal
jobs and results, product-audit anonymization, authorization revisions and the
asset aggregate. The marker is removed only after a final orphan check. Pending
markers block offline backup; restore validates that Active jobs and verification
records reference an asset in the same organization.

Deletion does not reuse the 500-job history window shown by the UI. After the
asset's organization boundary is established, the private job index selects the
complete opaque job-ID/digest set for that asset in stable order. Every selected
JSON must still match asset, owner and digest before a preview or journal can be
created. The final orphan check repeats the same indexed lookup after deletion;
it never scans unrelated job JSON. A cross-organization reference collision,
index divergence or invalid authoritative record fails the operation closed and
leaves the asset available for controlled recovery.

The retained audit deliberately cannot reconstruct the target, authorization
reference, notes, challenge digest, result evidence or original asset/job IDs.
It keeps only actor, action, result, timestamp and an opaque deletion receipt.
Operators should export any permitted evidence before confirming deletion. The
retention contract `2026-09-10.7` documents all 25 data classes and the explicit
Active deletion trigger in `docs/data-retention.md`.

## Verifiable Active evidence bundle

`GET /active/assets/{asset_id}/evidence-bundle?period=90d` exports a bounded,
organization-scoped `application/x-tar` artifact. The UI offers fixed periods of
30, 90 or 365 days, or all retained history. A period ends at the latest
persisted asset/job timestamp rather than wall-clock download time; rebuilding
the same retained state therefore produces identical bytes and SHA-256.

Contract `2026-09-08.1` permits exactly six regular files, in fixed order, with
UID/GID/mtime zero and mode `0644`:

- `manifest.json`: contract, opaque asset reference, state-based period, closed
  counts, redaction declarations and hashes/sizes of evidence entries;
- `active-asset.json`: status, dates, target-free scope, authorization revision
  projections and triage without actors;
- `executions.json`: at most the latest 100 terminal executions in the period,
  containing only closed lifecycle fields and normalized posture signals;
- `posture.json`: counts, capability history and the latest safe comparison;
- `report.md`: the existing target-free human-readable report; and
- `SHA256SUMS`: SHA-256 for the manifest and every evidence entry.

The archive never includes the exact target, authorization reference, notes,
responsible accounts, event actors, challenge material, job error text, raw
runner results, commands, responses or internal owner/project paths. The full
indexed owner/asset aggregate is selected before applying the requested period
and export cap. The manifest therefore declares the exact terminal count in the
period; when more than 100 executions match, it and `executions.json` mark
truncation and retain the newest bounded set. `source_selection_incomplete` is
`false` for this complete indexed selection and must never be inferred from the
separate 500-record posture window. Each entry is capped at 512 KiB and the
complete TAR at 4 MiB; generation fails closed rather than silently widening
those limits.

Validate without extracting files:

```bash
PYTHONPATH=backend python3 -m app.active_evidence_bundle inspectra-active-evidence-<opaque>.tar
```

The validator rejects unexpected/duplicate entries, links, non-canonical
metadata, oversized data, malformed schemas and checksum differences. A valid
result prints only contract, opaque reference, retained-state timestamp, entry
count and bundle SHA-256. This proves internal consistency and reproducibility,
not signer identity: record the HTTPS response header
`X-Inspectra-Evidence-SHA256` in an approved external evidence system if chain
of custody is required. Inspectra does not sign bundles in this version.

## Operational audit export

The administration view provides a separate preflight for Active action
history. An administrator chooses a fixed period (7, 30, 90 or 365 days) and
optionally one current owner-scoped asset, reviews matching/included counts and
truncation, then downloads JSON or CSV. The bounded contract, privacy projection
and exact endpoint behavior are documented in
[Product action audit](product-audit.md#bounded-active-operational-export).

This export deliberately does not repeat the exact target shown in the private
asset selector. It uses pseudonymous actor/resource references and omits
authorization references, notes, client IPs, correlations, raw metadata and
evidence. It is generated on demand, capped at 1,000 events and 1 MiB, and is
not retained or signed by Inspectra. It complements rather than replaces the
deterministic evidence bundle: the bundle captures normalized posture, while
the audit export explains closed operational actions.

## Weekly portfolio report

The operations center can prepare an on-demand portfolio snapshot for a fixed
7- or 30-day review window. `GET /active/operations/weekly-report/preflight`
is available to readers, maintainers and administrators in the current
workspace. It returns only counts, coverage, state, cutoff, a SHA-256 digest and
the privacy declaration; it never returns an asset target. The preflight is not
persisted and is served with `Cache-Control: private, no-store`.

The report contract is `2026-09-09.1`. It includes at most 500 authorized
assets, 2,000 source execution records, 100 current actions and 100 recurrence
records requiring attention, with an absolute response limit of 1 MiB. It
declares included and total denominators, the priority-first selection strategy
and `partial` whenever any source is truncated. The current action queue,
authorized asset inventory, recent execution counts, comparable changes and
paused, suspended or retrying recurrences all come from the same canonical
snapshot. Markdown and JSON render that same document and identify it with the
same digest.

Unlike the per-asset technical report and evidence bundle, this team report
contains the **exact targets** of included authorized assets when present. It therefore
requires a maintainer or administrator to acknowledge that sensitivity and
submit `POST /active/operations/weekly-report` with the preflight period,
cutoff, digest and a literal confirmation. Readers can review the bounded
preflight but cannot export. A preflight is valid for five minutes and at most
five seconds of future clock skew; if retained state changes, the digest no
longer matches and the export fails with a generic `409` rather than silently
mixing two portfolio states.

Both formats exclude notes, authorization references and digests, responsible
or actor identities, verification/challenge material, raw job output, runner
responses, paths, commands and credentials. Responses are attachments with
`Cache-Control: private, no-store`, `X-Content-Type-Options: nosniff` and
`X-Inspectra-Snapshot-SHA256`. A successful export records only the closed
action `active_asset.weekly_report_exported`, review period and format in the product
audit trail; it does not record targets or the report body. The downloaded file
is sensitive external data under the operator's storage, sharing and deletion
policy. Inspectra neither persists nor signs it.

Validation must cover two organizations, reader/maintainer boundaries, both
formats, stale and modified preflights, a portfolio above 500 assets, explicit
empty/partial/error UI states and absence of every excluded canary. This is a
bounded operational review, not a vulnerability assessment, SLA report or
proof that unobserved assets are safe.

### Target-free weekly review receipt

After preparing a current preflight, a maintainer or administrator may record
one closed outcome (`reviewed` or `follow_up_required`) for that exact snapshot.
`POST /active/operations/weekly-review-receipts` requires the report period,
cutoff, raw snapshot digest, current receipt revision, a one-operation
idempotency key and explicit review confirmation. Snapshot reconstruction and
receipt publication share one storage lock: a concurrent portfolio change or
stale receipt revision returns `409` and requires a new preflight.

Contract `2026-09-10.1` retains at most 52 receipts per organization for 400
days. A receipt contains the report contract, period/window, closed coverage,
outcome, review time and a domain-separated HMAC of the snapshot binding. It
never stores or returns the raw digest, report body, target, note, authorization
data, actor/reviewer identity, comment or runner result. It is evidence that a
bounded snapshot was acknowledged; it does not close actions or prove
remediation. Reusing an idempotency key with the same request returns the same
receipt; a different request fails closed.

All workspace roles may list bounded history with
`GET /active/operations/weekly-review-receipts`. Readers may also submit a raw
digest to `POST /active/operations/weekly-review-receipts/verify`; verification
uses the local private HMAC key and contacts no external provider. Only
maintainers and administrators may create a receipt. Responses are
`private, no-store`; the audit event records only opaque receipt ID, role-bound
actor, period, closed outcome and replay state. The key and signed collections
are private durable backup material, so restored instances must retain both.
