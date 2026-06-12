# Active Nmap Basic Backend Report Redaction Real Shape No Live

Decision:

```text
ACTIVE_NMAP_BASIC_33_BACKEND_REPORT_REDACTION_REAL_SHAPE_NO_LIVE_ACCEPTED
```

This phase adds backend/report/export/Raw JSON coverage for the hardened
`active_nmap_basic` result shape derived from real-output parser hardening. It
uses synthetic, already-structured payloads only and does not run Docker, run
Nmap, run `nmap --version`, perform probes, perform DNS checks, send external
HTTP traffic, run `curl`, open a browser, use Compose, add
backend-to-active-tools live calls, add a runner HTTP endpoint, create real
jobs from `active-tools`, create exports from live execution, integrate
archive/run-all,
integrate Active into `tools/runner/main.py`, approve new targets, approve
`www.vildek.es`, approve `app.vildek.es`, approve port `80`, approve public
scanner behavior, create migrations, create a tag, or create a release.

## Source Decisions

Accepted prior decisions:

```text
ACTIVE_NMAP_BASIC_31_REAL_OUTPUT_REDACTION_HARDENING_DESIGN_ACCEPTED
ACTIVE_NMAP_BASIC_32_REAL_OUTPUT_PARSER_REDACTION_TESTS_NO_RUNTIME_ACCEPTED
```

Reference prior commit:

```text
d5f73a8 test(active): harden nmap output redaction parser
```

## Objective

Confirm that backend public surfaces keep the hardened `active_nmap_basic`
payload minimal and defensively redacted when legacy or malformed result fields
contain real-output-like data. The only intended visible signal is a bounded TCP
observation with conservative wording:

```text
observed_exposure_review_indicator
manual_validation_required: true
```

## Synthetic Payload

The backend test creates an owner-scoped `active_nmap_basic` `JobRecord` with
`file_id: null`, `target_kind: authorized_fqdn`, and one minimal observation:

```text
443/tcp open syn-ack
```

The payload also includes deliberately rich legacy/malformed fields that must
not appear in public backend surfaces:

- `raw_xml`;
- `stdout`;
- `stderr`;
- `args`;
- `command`;
- `resolved_ip: 203.0.113.10`;
- `ptr_hostname: redacted-ptr.example.internal`;
- extra hostnames;
- service, banner, and version strings;
- local stylesheet path;
- script/NSE-like output;
- credentials, headers, cookies, and tokens;
- nested copies of the same sensitive values.

The values are synthetic or documentary. They do not copy the real own-domain
PTR hostname or real resolved IP observed in the earlier technical smoke.

## Tests Added

`backend/tests/test_backend.py` now includes
`test_active_nmap_basic_real_shape_backend_surfaces_redact_without_live_runtime`.

It covers:

- job detail API redaction;
- job list summary redaction;
- Markdown, HTML, XML, and PDF exports;
- backend Redacted Raw JSON report section;
- preservation of `manual_validation_required`;
- preservation of `result_interpretation`;
- preservation of allowed `port`, `protocol`, `state`, and `reason`;
- conservative observed exposure / review indicator / manual validation
  wording;
- forbidden wording absence for vulnerability, exploitability, target-safety,
  full-scan, and all-ports-found claims;
- wrong-owner detail/export responses returning generic `404`.

## Backend Helper Hardening

`backend/app/reporting.py` now treats the following additional
`active_nmap_basic` keys as sensitive:

- `resolved_ip`, `resolved_ips`, `resolved_address`, `resolved_addresses`;
- `ptr_hostname`, `ptr_hostnames`;
- `stylesheet`, `stylesheet_path`;
- `script_output`, `nse`, `nse_output`.

This is defensive reporting/redaction behavior only. It does not add execution,
live service wiring, runner calls, subprocess use, endpoint expansion, or
frontend runtime behavior.

## Surfaces Covered

Covered in this phase:

- `GET /jobs/{job_id}` public result payload;
- `GET /jobs` summary payload;
- Markdown export;
- HTML export;
- XML export;
- PDF export;
- Redacted Raw JSON section embedded in backend reports;
- owner-scope denial for wrong-owner detail and export reads.

Not covered because they remain future work:

- backend-to-`active-tools` live calls;
- real live jobs created from `active-tools`;
- exports from live execution;
- runner HTTP endpoint behavior;
- archive/run-all integration;
- frontend runtime rendering changes.

## Validation Evidence

Initial focused validation:

```text
.venv/bin/python -m pytest backend/tests/test_backend.py -k "real_shape_backend_surfaces"
```

Result:

```text
1 passed, 370 deselected in 1.97s
```

Backend active Nmap/redaction-focused regression:

```text
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or redaction"
```

Result:

```text
64 passed, 307 deselected in 1.43s
```

Parser redaction regression:

```text
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_parser_redaction.py
```

Result:

```text
7 passed in 0.02s
```

Parser regression:

```text
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_parser.py
```

Result:

```text
15 passed in 0.03s
```

Final validation for the commit workflow also includes the required git checks
and source searches.

## No-Run Confirmation

Confirmed for this phase:

- no Docker execution;
- no Nmap execution;
- no `nmap --version`;
- no DNS checks;
- no probes;
- no external HTTP checks;
- no `curl`;
- no browser;
- no Compose;
- no backend-to-`active-tools` live calls;
- no runner HTTP endpoint;
- no real jobs from `active-tools`;
- no real exports from live execution.

## Remaining Gaps

Still pending for separately scoped future phases:

- final backend-to-`active-tools` boundary design;
- live job lifecycle integration;
- live-output export review after a separately approved live boundary exists;
- frontend runtime review for hardened real-shape payloads;
- IP-freeze plus `-n` decision if future execution should avoid PTR at source;
- retention and cleanup policy for real live outputs.

## Final Decision

```text
ACTIVE_NMAP_BASIC_33_BACKEND_REPORT_REDACTION_REAL_SHAPE_NO_LIVE_ACCEPTED
```
