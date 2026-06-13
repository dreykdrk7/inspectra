# Active Nmap Basic: Backend No-Live Job Surfaces Hardening

Status:

`ACTIVE_NMAP_BASIC_51_BACKEND_ACTIVE_NMAP_NO_LIVE_JOB_SURFACES_HARDENED_PASSED`

## Objective

Harden existing backend job surfaces for persisted `active_nmap_basic` no-live
jobs. The goal is to make detail, list, Raw JSON-style API output, and existing
Markdown/HTML/XML/PDF report routes show conservative no-live caveats without
leaking target, payload, command, process output, service, credential, header,
cookie, token, observation, or evidence data.

This phase does not add frontend runtime behavior, new export routes,
archive/run-all integration, `tools/runner/main.py` integration, real
`active-tools` calls, Nmap execution, Docker/Compose use, probes, DNS checks, or
external HTTP traffic.

## Surface Behavior

For results with a no-live `lifecycle_state`, backend public job surfaces now
include explicit caveats:

- No Nmap executed;
- No network requests;
- No DNS queries;
- No evidence collected;
- No observations available;
- Manual validation required;
- No-live lifecycle record, not a target finding.

`JobStatus.completed` is not used as scan semantics for this audit type.
Surfaces read `result.status` and `result.lifecycle_state` before describing
meaning. `completed_no_live` means the lifecycle completed without live
execution.

## Redaction And Omission

No-live public result rendering omits fields that are incompatible with no-live
job semantics, including raw targets, raw payloads, commands, argv, stdout,
stderr, XML, PTR data, resolved IP values, banners, versions, service details,
credentials, headers, cookies, tokens, observations, evidence, and findings.

List summaries expose only controlled no-live state, count-only metadata,
execution flags set to false/zero, and the no-live interpretation. Target
display remains `[REDACTED_TARGET]`.

## Tests

Backend tests cover:

- owner detail, list, and Raw JSON-style job detail caveats;
- Markdown, HTML, XML, and PDF caveats through existing export routes;
- omission/redaction of malicious legacy fields on no-live jobs;
- wrong-owner detail/export/delete generic not-found behavior;
- compatibility with existing synthetic active Nmap reporting/redaction tests;
- source guardrails excluding real active-tools, Nmap, subprocess, Docker, DNS,
  probes, external HTTP, frontend runtime, archive/run-all, and
  `tools/runner/main.py` integration.

## Acceptance

This phase is accepted when focused surface/redaction tests, active/nmap backend
tests, the full backend suite, whitespace checks, and guardrail searches pass,
and only backend/reporting/storage/tests plus documentation are changed.
