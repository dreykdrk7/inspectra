# Active Nmap Basic Parser Redaction Tests No Runtime

Decision:

```text
ACTIVE_NMAP_BASIC_32_REAL_OUTPUT_PARSER_REDACTION_TESTS_NO_RUNTIME_ACCEPTED
```

This phase adds synthetic fixtures and offline tests for `active_nmap_basic`
real-output parser/redaction hardening. It uses the Microphase 31 design as the
source of truth and does not run Docker, run Nmap, run `nmap --version`, perform
DNS checks, send HTTP traffic, run probes, use Compose, change backend/frontend
runtime, add backend-to-active-tools live calls, add a runner HTTP endpoint,
create real jobs, create real exports, integrate archive/run-all, integrate
Active into `tools/runner/main.py`, approve new targets, approve
`www.vildek.es`, approve `app.vildek.es`, approve port `80`, create a tag, or
create a release.

## Source Decision

Accepted prior decision:

```text
ACTIVE_NMAP_BASIC_31_REAL_OUTPUT_REDACTION_HARDENING_DESIGN_ACCEPTED
```

Reference commit:

```text
757448e docs(active): design real nmap output redaction hardening
```

## Objective

Validate offline that synthetic Nmap XML shaped like the documented smoke output
does not leak PTR hostnames, resolved IPs for FQDN targets, raw args, raw XML,
stdout/stderr, service/banner/version fields, local stylesheet references, or
NSE-like script output into structured parser/result payloads.

The allowed visible result remains a minimal TCP observation with conservative
wording:

```text
observed_exposure_review_indicator
manual_validation_required: true
```

## Fixtures Added

Synthetic XML fixtures were added under
`tools/tests/fixtures/active_nmap_basic/`:

- `fqdn_with_ptr.xml`: authorized FQDN shape for `www.urlbreve.es:443`, with
  documentary IP `203.0.113.10`, synthetic PTR
  `redacted-ptr.example.internal`, raw args, service table label, local
  stylesheet reference, and `443/tcp open syn-ack`.
- `container_loopback_closed.xml`: container loopback shape with
  `127.0.0.1:65000/tcp closed conn-refused` and no hostnames.
- `multiple_hostnames.xml`: one host with multiple hostname entries, including
  synthetic PTR and unexpected alias values.
- `multiple_hosts.xml`: two host nodes to exercise unsupported multi-host
  shape.
- `unexpected_port.xml`: a target output port that is not in the accepted
  request port list.
- `malformed_truncated.xml`: incomplete XML to exercise controlled malformed
  handling.
- `service_version_nse.xml`: service/banner/version-like metadata plus an
  NSE-like script section to exercise unsupported/drop behavior.

The new fixtures use documentary or synthetic data. They do not copy the real
own-domain XML in full, do not use the real PTR hostname, and do not introduce
new sensitive data.

## Tests Added

`tools/tests/test_active_runner_nmap_basic_parser_redaction.py` covers:

- PTR hostnames do not appear in parser/result payloads.
- Documentary resolved IPs for FQDN targets do not appear in visible payloads.
- Raw args and complete Nmap commands do not appear.
- Raw XML, stdout, stderr, stylesheet references, service/version/banner data,
  and script output do not appear.
- Minimal `443/tcp open syn-ack` observations are preserved.
- `manual_validation_required: true` is present.
- `result_interpretation` is `observed_exposure_review_indicator`.
- Container-loopback output keeps `target_kind: container_loopback`, port
  `65000`, state `closed`, and reason `conn-refused` without hostnames or extra
  IP display.
- Multiple hosts return controlled `unsupported_shape` with
  `multiple_hosts_unsupported`.
- Unexpected ports return controlled `unsupported_shape` with `unexpected_port`.
- Malformed/truncated XML returns controlled `malformed_xml`.
- NSE-like sections return controlled `unsupported_live_output_section`.

Existing parser/result expectations were updated where the composed result
payload now includes the conservative observation metadata.

## Pure Helper Changes

Only pure helper behavior was changed:

- `tools/active_runner/nmap_basic/parser.py`
  - accepts optional `accepted_ports`;
  - accepts optional `target_kind`;
  - rejects multiple `<host>` nodes as unsupported shape;
  - rejects script/OS output sections as unsupported live output;
  - rejects ports outside the accepted request set when provided;
  - continues to omit hostnames, addresses, raw XML, raw args, service data, and
    findings from parse results.
- `tools/active_runner/nmap_basic/result.py`
  - adds `manual_validation_required: true`;
  - adds `result_interpretation: observed_exposure_review_indicator`;
  - propagates safe `target_kind`;
  - keeps raw XML, command, target, stdout, and stderr return flags false.

No endpoint, backend-to-runner call, live runner behavior, Docker/Compose file,
feature flag, archive/run-all path, frontend runtime, or `tools/runner/main.py`
integration was changed.

## Validation Evidence

Executed validations:

```text
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_parser_redaction.py
```

Result:

```text
7 passed in 0.02s
```

Additional parser regression:

```text
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_parser.py
```

Result:

```text
15 passed in 0.03s
```

Active runner Nmap-focused regression:

```text
.venv/bin/python -m pytest tools/tests/test_active_runner.py -k "nmap"
```

Result:

```text
1 passed, 29 deselected in 0.02s
```

Backend active Nmap/redaction-focused regression:

```text
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or redaction"
```

Result:

```text
63 passed, 307 deselected in 2.34s
```

The final validation set also includes the required git checks and source
searches recorded in the commit workflow.

## No-Run Confirmation

Confirmed for this phase:

- no Docker execution;
- no Nmap execution;
- no `nmap --version`;
- no DNS checks;
- no probes;
- no HTTP checks;
- no `curl`;
- no browser;
- no Compose;
- no real jobs;
- no real exports;
- no live backend-to-active-tools calls.

## No Runtime Integration

Confirmed:

- no backend live endpoint changes;
- no frontend runtime changes;
- no runner HTTP endpoint;
- no archive/run-all integration;
- no `tools/runner/main.py` integration;
- no new target approval;
- no `www.vildek.es`;
- no `app.vildek.es`;
- no port `80`;
- no public scanner behavior.

## Remaining Gaps

Still pending for future separately scoped phases:

- backend/report/export/Raw JSON integration tests against the hardened shape;
- final policy for whether any internal resolved-target marker is needed;
- IP-freeze plus `-n` design if future execution should avoid PTR at source;
- backend-to-active-tools boundary design;
- live job lifecycle integration;
- final Active live UX review;
- retention and cleanup policy for real live outputs.

## Final Decision

```text
ACTIVE_NMAP_BASIC_32_REAL_OUTPUT_PARSER_REDACTION_TESTS_NO_RUNTIME_ACCEPTED
```
