# Active weekly enterprise adoption review

Review date: 2026-09-09. Scope: the registered-asset Active product only. All
executions used `.test` identities, fixture results and simulated adapters with
container networking disabled. No external domain, IP, service or provider was
contacted.

## Product state reviewed

The usable path is now: organization session → exact asset registration →
optional control challenge → capability execution through `active-tools` →
asset timeline and compatible comparison → baseline → structured triage →
bounded Markdown report → immediate revocation. The operations center integrates
this path while remaining separate from Archive, CI and SBOM.

The review exercised two consecutive DNS-inventory cycles on one registered
asset. An administrator registered and manually verified it; a maintainer ran
both cycles, selected a baseline, triaged one observation and exported the
report; a reader could inspect the center, posture and report but received 403
for mutation; revocation by the administrator made the next admission fail 409.
The deterministic API scenario completed in 0.79 seconds before the subsequent
full-suite validation. No password or one-time challenge appeared in persisted
JSON.

## Control matrix

| Concern | Evidence observed | Result |
| --- | --- | --- |
| Organization isolation | Stores and routes require organization context; tests use two organizations and wrong-owner not-found behavior. | Pass for the current file-backed design. |
| Roles | Admin/maintainer write, reader read-only, automation credentials denied. | Pass; bootstrap `team-admin` incompatibility was found and fixed as PROD-174. |
| Scope | Exact canonical target, explicit capabilities/protocols/ports, no wildcard/CIDR/path/query or derived targets. | Pass. |
| Execution boundary | Nmap, DNS inventory, CT, HTTP and TLS use fixed internal runner routes/profiles; backend has no asset-bound live fallback. | Pass after the P0 defect found and fixed as PROD-175. |
| Concurrent revocation | Nmap and the four standard runner requests are cancelled and produce terminal redacted jobs. | Pass with simulated slow runners. |
| Reproducibility | Job records keep capability, asset ID and contract, and comparison accepts only compatible terminal executions. | Partial: an immutable authorization revision is not yet snapshotted. |
| Operational visibility | Center reports bounded asset/job/change counts, partial state and effective backend feature gates. | Partial: it does not attest actual per-capability runner readiness. |
| Lifecycle | Expiration and revocation are enforced; verification challenge and evidence expire. | Partial: authorization renewal and Active data retention/deletion are absent. |
| Scale and abuse resistance | Process semaphore limits standard runner calls to four; summary caps 500 assets/2,000 jobs. | Partial: no per-organization quotas and asset list/rendering are unpaginated. |
| Durable operation | Execution results, baseline, triage and reports persist. | Partial: the HTTP execution request is synchronous and there is no durable queued/running recovery path for Active. |
| Verification egress | DNS/HTTP verification has fixed destinations, pinning/limits and default-off gating. | Partial: the transport still runs in the backend process rather than `active-tools`. |
| Accessibility and responsive UX | Keyboard/axe component tests and real 320/768/1440 review; no overflow and controls at least 44 px. | Pass for current fixtures; larger portfolios and long localized content remain unvalidated. |

## Confirmed weekly-use blockers and follow-up

The current product can support a controlled manual synthetic cycle, but should
not be presented as a mature weekly enterprise service yet. The blocking gaps
are concrete rather than generic:

1. Active jobs are created only after a synchronous runner response, so a user
   cannot reliably observe queue/progress, cancel from the UI or recover work
   after backend interruption (`PROD-183`).
2. Authorization cannot be renewed through a re-attested, append-only flow
   (`PROD-176`), and the exact authorization revision used by a job is not
   immutable evidence (`PROD-185`).
3. Responsible-user IDs are structurally valid but are not proven to be active
   members of the organization (`PROD-177`), nor is member departure reconciled
   with assigned Active assets (`PROD-191`).
4. There is no owner-scoped Active retention/deletion/export lifecycle
   (`PROD-178`) and no per-organization execution quota (`PROD-184`).
5. The center reports backend flags rather than end-to-end runner readiness
   (`PROD-179`), and large asset portfolios lack cursor pagination
   (`PROD-188`).
6. DNS/HTTP control verification remains a separately bounded backend transport;
   moving it to the Active runner will reduce the privileged egress surface
   (`PROD-187`).

Optional recurrence remains explicitly out of the completed product line as
`PROD-172`; it depends on the durable lifecycle, quotas and renewal controls.
Four-eyes approval and bulk admission are useful later, but are not substitutes
for the P1 lifecycle and isolation work.

## Validation record

- Directed isolation/cancellation contracts: 29/29 passed.
- Complete tools suite: 427/427 passed in a container with `--network none`.
- Complete backend suite: 1,150/1,150 passed in a container with
  `--network none`; it reached 93% within 30 seconds and completed in the same
  tracked session rather than being inferred from the timeout.
- Both default and standalone Active Compose models passed configuration
  rendering.
- The locally built Active image imported its ASGI app read-only, without Linux
  capabilities and with `--network none`; route enumeration contained only the
  fixed health/capability paths and the closed catch-all. Image ID:
  `sha256:7f1d04b3fc4898123b0f45fcea909ba7074ee31977f26f19e4686e0b5e288b56`.
- Frontend final pass: 49/49 files and 320/320 tests, including 8/8 center
  tests and axe, plus TypeScript and a production Vite build. The initial npm
  command could not write a root-owned pre-existing `.vite-temp`; a second
  command ran from the wrong working directory and therefore lacked `jsdom`.
  Re-running the local binary from `frontend/` with Vite's direct config loader
  isolated one stale App request-count expectation (7 versus the 9 intended
  calls after the summary/configuration additions); the regression now asserts
  those three Active URLs and the full suite passes. The immediately preceding
  320/768/1440 visual inspection showed no horizontal overflow.
- `compileall` passed with bytecode redirected to an ephemeral tmpfs; the first
  read-only attempt failed only while trying to write repository `__pycache__`.
  `pip-audit` found no known vulnerability in the Active image lock and
  `npm audit --package-lock-only --audit-level=high` found zero vulnerabilities.
- Default, private and Active Compose renderings, the pinned Gitleaks canary,
  backlog state synchronization and `git diff --check` passed.
- Cleanup removed the exact visual backend container, Vite process, local
  `prod175-local` image and both temporary review/build directories; a final
  inventory found none of those resources. Repository source/data were not
  removed or reset.

This review is backlog input, not a release, deployment or authorization to
work on `SEC-012`, `PROD-129`, `PROD-130` or `PROD-167`.

## Follow-up scale and integrity re-audit — 2026-09-08

The six requested Active verticals have subsequently reached completed task
states through `PROD-172`–`PROD-192`: immutable authorization revisions,
durable execution and quotas, runner-isolated verification, deletion/retention
and evidence, cursor pagination/bulk admission, recurrence and the action inbox.
This follow-up did not repeat external scans and does not change any release or
blocked-task decision.

The first scale pass found that `POST /active/assets/search` bounded its HTTP
response but still parsed every owner JSON before slicing. `PROD-193` now uses a
private SQLite derivative while retaining JSON as authoritative data. A
10,005-asset/two-owner fixture enforces at most 101 aggregate reads for a
100-item page, p95 below 500 ms after warm-up and memory below 128 MiB. It also
exercises exact/prefix/status/capability/recency filters, concurrent insertion,
foreign cursors, all aggregate mutations, deletion, restart, interrupted write,
schema drift, corrupt DB, insecure permissions and corrupt authoritative JSON.
The index is checked by readiness and backup/restore; repairs never invent or
delete an authoritative asset.

Reauditing the result exposed the next concrete bottleneck: the operations
summary called the unbounded internal `ActiveAssetStore.list`, listed all owner
jobs and performed one full verification-directory scan per considered asset
before applying its 500/2,000 limits. `PROD-196` replaces those paths with
validated owner-scoped projections: exact asset and Active-job totals, at most
500 asset records, 2,000 job records and one latest verification per asset are
materialized. The UI distinguishes exact asset totals from bounded operational
detail. Deterministic 10,005-asset, 20,000-job and 10,000-verification fixtures
exercise latency, memory, source-read bounds, owner isolation, synchronization,
corruption and rebuild; backup/readiness cover all three derived stores.
`SEC-012`, `PROD-129`, `PROD-130` and `PROD-167` remain blocked and untouched.

The post-`PROD-196` review found a semantic rather than latency defect: the 500
assets were selected only by `updated_at`, so an old expired authorization or
latest failed execution could remain outside the weekly action inbox. `PROD-197`
changes candidate selection to `priority_then_recency` using only closed,
owner-scoped index fields. Old expired, failed-verification and latest-failed
job fixtures precede the recency fill; recovery suppresses an older failure,
and overload ordering is stable. The response continues to label comparison
and action detail as partial because normalized observation changes outside the
bounded evidence window are not inferred from index metadata.

Reauditing the action path after `PROD-197` found a remaining linear cost:
Active replay and both general and Active admission quotas still opened every
retained job JSON. `PROD-198` extends the already validated private job
projection to all jobs with only closed quota fields and the pre-hashed Active
idempotency key. Warm quota checks load no JSON; a replay loads and validates at
most its one authoritative record. A deterministic 20,000-job/two-owner fixture
checks exact general and Active counts, owner isolation and a p95 below 250 ms;
the existing multi-store races remain the authority for atomic quota semantics.

The next review followed the browser's initial data load rather than only the
Active inbox. It found that `GET /jobs` still opened and returned every retained
job, so a long history could dominate startup despite the bounded Active
summary. `PROD-199` adds keyset pagination to the same validated projection:
50 records by default, 100 maximum, exact filtered totals, owner/filter-bound
cursor in a POST body and a legacy GET capped at 100. The UI discloses loaded
versus total history, retains existing rows on continuation failure and never
places the cursor or a search term in the URL.

Reauditing the specialized project views after that migration found a semantic
gap: their compatibility wrapper returned only the first 50 analyses. An older
saved baseline could therefore be retained server-side yet described as no
longer available. `PROD-200` gives findings, inventory, intelligence and
comparison independent bounded continuation and resolves only explicitly
retained selections through a project/owner-scoped summary endpoint. It never
auto-downloads the remaining history or returns the full job result merely to
populate a selector.

The next internal call-site audit found that pagination did not cover control
helpers: global readiness, project admission, default result selection and
per-asset history still walked every job JSON. `PROD-201` reuses the private
projection for exact in-flight counts, opaque recovery IDs, newest completed
project selection and a 500-record Active history window. The authoritative JSON
is still verified where content is consumed; count-only decisions perform no
record reads. The 20,000-job fixture also exposed two concrete regressions: a
nested acquisition of the storage lock in project admission and a legacy test
that changed authoritative JSON without resynchronizing the derived index. The
former now uses an explicit lock-owned helper; approved restore/migration paths
must rebuild the projection before service, while arbitrary direct edits remain
unsupported and fail closed.

Reauditing restart and retention paths after that change found the next bounded
piece of work: startup recovery still discovered queued/running candidates and
active source references by opening the full retained history. `PROD-202`
therefore uses index-backed recovery candidate selection and derives source
liveness only from digest-validated in-flight records. Its first implementation
review caught a subtler restart cost: a new process always rebuilt the durable
index. Schema v5 now persists a closed directory-state marker, allowing adoption
only after permission, schema, integrity and marker checks; mismatch rebuilds or
fails closed. Terminal-retention selection and legacy SBOM scans remain
separately visible rather than being folded into an unbounded refactor.

The next Active-specific review followed the irreversible deletion path. Both
preview and its final orphan check scanned every retained job even though only
one asset aggregate was relevant. `PROD-203` adds a distinct exhaustive
owner/asset query: unlike the 500-row UI history it has no truncation, but its
cost is proportional only to the aggregate being deleted. Every candidate is
digest-validated and any cross-owner reference fails closed before journaling.
Deterministic tests forbid a global jobs glob and cover interrupted recovery,
more than 500 records, another organization and zero residual jobs.

Reauditing the rest of that aggregate found the equivalent organization-wide
scan in control verification. `PROD-204` moves challenge history, rate-limit,
pending supersession and deletion to an exhaustive owner/asset query over
verification-index schema v3. A persisted closed source marker permits safe
adoption after restart only when permissions, schema, integrity and filesystem
state agree. The 10,000-record/two-owner fixture restarts the store, forbids an
organization glob and proves that a 101-record asset reads only those 101 JSON
records with p95 below 500 ms.

The following review found a user-visible coverage boundary: posture, baseline,
report, evidence export and revocation share a newest-500 execution helper.
Although evidence export marks that source pessimistically, the normal posture
and baseline flow cannot navigate older retained executions, and control paths
must not depend on a presentation window. `PROD-205` therefore owns paginated
Active history, direct owner/asset-scoped selection, exact coverage disclosure
and exhaustive in-flight revocation as one vertical.

`PROD-205` completed that vertical. The execution API now pages an immutable
owner/asset snapshot with an HMAC cursor; direct summary lookup recovers an old
baseline without exposing the result payload. Posture discloses its newest-500
calculation window, while reports/evidence use the full indexed aggregate and
revocation selects every in-flight job independently. Scale fixtures covered
20,000 jobs, 1,001 executions on one asset, a concurrent newer insertion, 505
terminal executions, 501 live executions, two owners and manipulated/transferred
cursors. The local UI review loaded 50 then 52 rows, preserved focus at the end,
covered the empty state and removed a 16 px mobile page overflow.

The mandatory re-review then followed weekly startup and maintenance. Terminal
retention still parses every retained job under the global store lock before it
can identify expired candidates. This is now `PROD-206`: select expired terminal
records from the private index in stable bounded batches, revalidate their JSON
and digest immediately before cleanup, preserve failed callbacks for retry and
prove proportional reads plus safe restart/concurrent-change behavior. The
retention change is deliberately separate from visible history and does not
widen Active network authority.

`PROD-206` completed that retention boundary with active-job-index schema v6.
Expired terminal candidates are selected by owner/cutoff through partial SQL
indexes in stable batches of 100, then their authoritative JSON is validated by
owner, status, timestamp and digest. Callback failure leaves the job intact;
the post-callback digest check prevents a concurrent live or recent update from
being deleted. A restarted store with 20,000 jobs and two owners prohibited the
jobs-directory glob, kept a foreign expired job, a live old job and a concurrent
newer insert, and removed the remaining 136 eligible owner records in batches
100+37. The fixture enforces p95 below 500 ms per 100-record selection and less
than 32 MiB peak allocation.

Reauditing the next step of the same maintenance flow found a separate global
scan: after source expiration, `mark_file_deleted`/`mark_files_deleted` still
parse every retained job to locate a small set of source references. This can
again hold the shared storage lock after terminal cleanup. `PROD-207` will add a
privacy-preserving indexed source-reference projection and update only validated
matching jobs in bounded batches; raw source IDs must not be added to the index.

`PROD-207` completed that projection in active-job-index schema v7. The index
stores a domain-separated SHA-256 reference and `source_deleted` bit, never raw
`file_id`; owner-scoped queries accept at most 500 references and return 100
validated jobs per batch. The 20,000-job fixture resolved 137 related jobs as
100+37 with exactly two authoritative reads each, preserved the matching job of
the other owner, prohibited a jobs glob and asserted that none of four raw
source IDs occurs in SQLite. An injected interruption after the first of three
writes resumed with exactly the two outstanding jobs.

The next re-review exposed the remaining half of the retention callback:
`ProjectStore.clear_baselines_for_analysis_ids` and
`mark_source_file_deleted` still scan every project, potentially once for each
expired analysis or source. `PROD-208` will index baseline and source-snapshot
relationships with domain-separated digests, validate the authoritative project
before mutation and eliminate the steady-state project-directory scan.

`PROD-208` completed this project-side boundary with a dedicated schema-v1
SQLite projection. Baseline and source references are domain-separated digests;
project/source names, content hashes and raw analysis/source IDs are absent.
Cleanup selects 100 records per owner-scoped batch, validates the project digest
and exact relationship under the shared lock, and synchronizes each mutation.
The 5,000-project/two-owner fixture cleared and marked 137 records as 100+37,
kept the foreign project unchanged, prohibited the projects glob, enforced p95
below 500 ms and peak allocation below 32 MiB, and resumed two outstanding
updates after an injected interruption. Backup validation rejected both new
job-index fields and a tampered project relationship before rebuilding from
authoritative JSON.

Following the maintenance flow one step further identifies the remaining
unbounded selector: `FileStore.purge_expired` still scans every upload metadata
record and retains all candidates in memory before callbacks begin. `PROD-209`
will introduce a private source-retention index and bounded, revalidated batches
so startup/manual cleanup costs follow expired sources rather than total files.

`PROD-209` completed that final source-retention selector with a dedicated
schema-v1 SQLite projection. It stores only opaque file/owner IDs, creation
time, the closed stored filename and an authoritative metadata digest; original
filename, content hash and source bytes are absent. The cleanup selects stable
owner/cutoff batches of 100, performs the final live-source check, derived
reference callback, post-callback metadata validation and deletion while holding
the shared storage lock, and uses explicit lock-owned job/project helpers rather
than nested acquisition. A callback failure retains the source and a source
that becomes protected after selection is excluded without a retry loop.

The restarted 10,000-file/two-owner fixture prohibited an uploads-directory
glob, retained static and dynamically protected sources plus the foreign owner,
and deleted 135 eligible records in batches of 100 and 36. It enforced p95
below 500 ms, peak allocation below 32 MiB and absence of original filename and
content SHA in SQLite. Backup validation rejects a semantically altered row and
the store rebuilds it only from authoritative metadata. Directed retention,
index and backup tests passed 32/32; the complete backend suite passed
1,260/1,260 with an explicit zero exit code, followed by compileall and
diff-check, all without network access.

The mandatory next review followed the weekly scheduler rather than retention.
`ActiveRecurrenceStore.list_due` still traverses every organization directory
and parses every recurrence before returning at most 16 due policies; its
asset-scoped list, count and delete helpers similarly scan every policy in the
organization. `PROD-210` will add a private, digest-validated recurrence
projection for due selection and exact asset aggregates, preserving JSON as the
authority and keeping target, authorization references and verification data
out of the index.

`PROD-210` completed that scheduler boundary with a schema-v1 recurrence
projection. Global due selection is ordered and capped at 16; asset list/count,
suspension and deletion use the exact owner/asset aggregate. Every selected
record is loaded from authoritative JSON and checked against owner, asset,
status, due/retry timestamps, digest and the existing civil-time eligibility
function. All create, pause, resume, suspend, failure, dispatch and deletion
paths synchronize the index, whose exact closed columns are also checked by
readiness and backup/restore.

The restart fixture created 10,000 schedules across 20 organizations, including
16 due policies and 101 policies on one asset. It prohibited organization-level
directory traversal in steady-state, retained owner isolation, deleted exactly
the 101-record aggregate and enforced p95 below 500 ms plus peak allocation
below 32 MiB. Authorization digest and verification-ID canaries were absent
from SQLite. A two-tick barrier demonstrated one durable idempotent job and one
CAS advance for the same occurrence. Directed tests passed 38/38; the complete
backend suite passed 1,262/1,262 with exit zero, plus compileall and diff-check,
without external network access.

The next product review returned to the weekly meeting rather than another
storage projection. Inspectra offers per-asset technical reports and a redacted
administrative audit export, but no single reproducible portfolio report that
combines current actions, expiring authorizations, failed/degraded executions,
material comparable changes, recurrence health and explicit coverage. This is
now `PROD-211`; it must remain owner-scoped, bounded, downloadable on demand and
honest about partial evidence.

`PROD-211` closes that operational reporting gap with one canonical on-demand
snapshot and two renderers. A target-free preflight exposes 7/30-day cutoff,
coverage, limits and digest; only maintainers and administrators can confirm and
download the target-bearing Markdown or JSON. Both formats include the bounded
authorized inventory, current action queue, recent execution states, comparable
changes and recurrence attention while excluding notes, authorization material,
identities, challenges and raw runner data. A five-minute cutoff/digest check
rejects changed state rather than silently mixing observations.

The real localhost flow found and corrected three defects that isolated tests
did not reveal: the digest response header was not exposed through credentialed
CORS, the consent label wrapped away from its checkbox, and a stopped backend
showed `Failed to fetch` instead of an actionable retry. The final matrix at
320/768/1440 had no page or panel overflow and all report controls were at least
44 px. Ready/download, empty and connection-error states were exercised in the
browser; partial 501/500 and reader-only states remain deterministic fixtures.
All Active/provider gates stayed disabled and no target outside `.test` was
contacted.

The closing re-audit distinguishes an export from a completed team review. The
audit event proves only that a maintainer or administrator downloaded a format;
it must not be presented as acknowledgement, remediation or an SLA. `PROD-212`
subsequently added a bounded, target-free weekly review receipt: it records only
the closed outcome, period, cutoff and a domain-separated HMAC of the report
digest. It does not resolve or re-prioritize actions, and keeps targets, notes,
identities and report contents out of the receipt. `PROD-180` separately provides
optional four-eyes approval for critical mutations. Release/CI tasks remain
deliberately outside this product-development goal and blocked as instructed.
