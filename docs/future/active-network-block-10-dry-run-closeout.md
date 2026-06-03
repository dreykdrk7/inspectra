# Active Network Block 10 Dry-Run Closeout

Status: `ACTIVE_DRY_RUN_V0_CLOSED_NO_NETWORK`.

Base review: `docs/future/active-network-block-09-end-to-end-dry-run-contract-redaction-review.md`

Commit scope: documentation closeout, smoke checklist, final product decision, and handoff guidance.

## Final State

`active_network_dry_run` v0 is closed and ready as a no-network dry-run capability.

The capability is dry-run planning only. It is not an Active scanner, not Nmap, not a live validator, and not a reachability check. It records a policy decision and planned check metadata without contacting the target.

Decision field:

```text
ACTIVE_DRY_RUN_V0_CLOSED_NO_NETWORK
```

## Commit Series

Relevant Active dry-run series:

- `7437758 docs(active): decide post-passive alpha active block scope`
- `3744a7e docs(architecture): decide active runner boundary after passive alpha`
- `16f886e docs(active): freeze network block scope`
- `44f1f42 docs(active): define network runbook threat model`
- `f384661 docs(active): design network dry-run contracts`
- `a6c66d6 feat(active): add no-network dry-run skeleton`
- `eaa3b57 docs(active): design dry-run backend contracts`
- `c7fc01a feat(active): integrate dry-run backend no-network`
- `bff7078 docs(active): design dry-run frontend UX`
- `e5cab61 feat(active): add dry-run frontend no-network`
- `e19dcb6 test(active): validate dry-run e2e no-network`

## Implemented Surfaces

- Separate Active runner package under `tools/active_runner/`.
- `run_active_network_dry_run`.
- Backend endpoint `POST /active/network/dry-run`.
- Feature flag `INSPECTRA_ACTIVE_DRY_RUN_ENABLED`, default `false`.
- Job type `active_network_dry_run`.
- Target-based jobs with `file_id: null`.
- Compact summaries through `GET /jobs`.
- Full results through `GET /jobs/{job_id}`.
- Markdown, HTML, XML, and PDF exports.
- Frontend `Active / Network dry-run` panel.
- Frontend API helper for `POST /active/network/dry-run`.
- Audit catalog and dashboard filter metadata for `active_network_dry_run`.
- `ActiveDryRunJobReport`.
- Redacted Raw JSON.

## Safety Guarantees

The v0 dry-run capability preserves:

- no DNS resolution;
- no HTTP requests;
- no sockets;
- no subprocess probes;
- no Nmap;
- no live probes;
- no local-lab mode;
- no passive runner modification;
- `network_requests_sent: 0`;
- endpoint disabled by default;
- explicit authorization required;
- dry-run mode only;
- request limits set to zero;
- blocked targets stored as completed dry-runs with `policy.allowed: false`.

Active code remains separate from `tools/runner/main.py`. Future Active work must not weaken the passive archive/file no-network guarantee.

## Redaction Guarantees

Defensive redaction covers current and legacy Active dry-run payload surfaces:

- URL userinfo;
- sensitive query parameters;
- Authorization headers;
- Bearer and Basic credentials;
- tokens, passwords, API keys, and client secrets;
- private key blocks;
- malformed or legacy payload fields;
- `GET /jobs`;
- `GET /jobs/{job_id}`;
- Markdown, HTML, XML, and PDF exports;
- frontend job table and report DOM;
- frontend Redacted Raw JSON.

The fixed placeholder is:

```text
[REDACTED]
```

The implementation does not intentionally emit secret prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

## Tests And Validations

The end-to-end review validated:

- active runner dry-run behavior;
- backend disabled-state handling;
- backend job creation, summaries, result retrieval, and exports;
- frontend form contract and report rendering;
- blocked private, loopback, URL-userinfo, and unsupported profile cases;
- sensitive query and legacy payload redaction;
- AST/source-level no-network import checks for `tools/active_runner/`;
- safety grep review for forbidden network/probe terms;
- frontend build.

Reference validation commands from the review:

```text
python3 -m compileall backend tools/active_runner
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools/active_runner
.venv/bin/python -m pytest tools/tests/test_active_runner.py
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_network or dry_run"
.venv/bin/python -m pytest backend/tests/test_backend.py
npm run test -- --run ActiveDryRunJobReport App dashboardFilters reportHelpers
npm run test -- --run
npm run build
git diff --check
git diff --cached --check
```

This closeout is docs-only, so no pytest or npm suite is required for the closeout commit unless runtime files change.

## Known Limitations

- Dry-run only.
- No live target truth.
- No reachability validation.
- No DNS resolution.
- No HTTP headers are fetched.
- No Nmap.
- No local-lab mode.
- Authorization is a user assertion, not proof.
- Endpoint remains disabled by default.
- No production or external-user readiness claim.

## Smoke Checklist

Manual/API smoke for trusted local validation:

1. Enable `INSPECTRA_ACTIVE_DRY_RUN_ENABLED=true` in the backend runtime environment.
2. Submit a valid target such as `https://example.test`.
3. Confirm `POST /active/network/dry-run` creates an `active_network_dry_run` job.
4. Confirm the job is target-based with `file_id: null`.
5. Confirm `network_requests_sent` remains `0`.
6. Submit a blocked private target such as `10.0.0.1` and confirm `policy.allowed: false`.
7. Submit a URL credentials target such as `http://user:pass@example.com` and confirm credentials are redacted.
8. Submit an unsupported Nmap-like profile and confirm it is blocked as policy, not executed.
9. Check `GET /jobs` and `GET /jobs/{job_id}` summaries/results.
10. Export Markdown, HTML, XML, and PDF reports.
11. Check the frontend `Active / Network dry-run` report and Redacted Raw JSON.
12. Confirm no DNS, HTTP, socket, subprocess, Nmap, or live probe behavior occurred.

## Product Decision

`active_network_dry_run` v0 is closed.

Do not proceed to live HTTP probing without a separate docs-first design. Do not proceed to Nmap without a separate docs-first design. Any future Active capability must keep explicit authorization, fail-closed target policy, bounded limits, audit logging, redaction, and clear no-scope copy.

Recommended next microphase:

```text
ACTIVE-NETWORK-BLOCK-11-AUTHORIZED-HTTP-HEADER-PROBE-DESIGN-DOCS-FIRST
```

If the product priority is hardening instead of Active expansion, use:

```text
POST_ALPHA_READINESS_BACKLOG_EXECUTION-01-DOCS-FIRST-PLAN
```
