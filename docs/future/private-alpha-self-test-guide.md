# Private Alpha Self-Test Guide

Decision: `PRIVATE_ALPHA_SELF_TEST_GUIDE_01_ACCEPTED`

Status: accepted as an internal operator guide. This guide is not for external
sharing yet.

## Purpose

Use this guide to test Inspectra from another browser or another PC as if the
operator were a trusted technical tester.

Goals:

- identify GUI and UX friction before inviting friends or external testers;
- test the current staging/private-alpha experience through protected access;
- keep the test passive and controlled;
- validate upload, report, export, logout, and cleanup flows;
- avoid expanding scope into runtime changes, Active work, or public sharing.

## Current Sharing Decision

Do not share Inspectra externally yet.

Do not:

- invite friends yet;
- promote the app publicly;
- buy or configure a final domain yet;
- treat staging as a public demo;
- enable Active capabilities for this self-test.

Use protected staging only for internal validation.

## Simulated Tester Persona

The simulated tester is:

- technically competent;
- comfortable with alpha limitations;
- willing to use only authorized and safe files;
- focused on clear results rather than visual polish;
- aware that Inspectra is not a polished hosted product;
- expected to report confusing flows, missing context, scary copy, unclear
  report output, and unsafe-feeling moments.

## Access Precheck

Before testing, confirm these checks without writing any access material into
notes or docs:

- protected staging URL is known to the operator;
- protected access boundary works;
- app login works;
- logout works;
- unauthenticated access is denied;
- Active controls remain disabled unless a later phase explicitly approves
  them;
- no usernames, passwords, protected-access values, browser session values,
  request-forgery values, or private config are recorded.

## Allowed Test Inputs

Strongly recommended:

- accepted manifest/config-only self-dogfood fixture;
- tiny synthetic archives;
- operator-owned sanitized archives;
- no broad source snapshots unless separately approved.

Accepted fixture path:

```text
tests/fixtures/project_archives/inspectra_manifest_only_self_dogfood/
```

## Disallowed Test Inputs

Do not upload:

- environment override files;
- key or certificate files;
- API access values;
- browser session exports;
- session material;
- database dumps or backups;
- production configs;
- client or business records;
- invoices, quotes, payments, or private PDFs;
- broad source snapshots;
- third-party target material without authorization.

## Self-Test Flow

Use this checklist in a later smoke phase:

1. Open protected staging from another browser or another PC.
2. Verify protected access prompts or blocks as expected.
3. Log in to the app.
4. Find the upload/analyze flow without using existing notes.
5. Upload only the accepted safe fixture/archive.
6. Start passive project archive analysis.
7. Wait for completion.
8. Read the dashboard or list entry.
9. Open the report.
10. Inspect summary, categories, ecosystems, and dependency pinning summary.
11. Verify individual findings are still visible.
12. Export Markdown, HTML, XML, and PDF.
13. Review Raw JSON and export surfaces for obvious marker leakage.
14. Delete the uploaded source if staging is used.
15. Log out.
16. Verify app access is denied after logout.

## GUI/UX Feedback Checklist

Record observations about:

- first impression;
- whether the dashboard explains what to do;
- whether upload restrictions are clear;
- whether the disabled Active state is clear;
- whether findings are understandable;
- whether category and ecosystem labels help;
- whether the dependency pinning summary is useful;
- whether exports are easy to find;
- whether errors and empty states are confusing;
- whether anything looks frightening, unfinished, or misleading;
- whether the tester would trust the tool enough to upload an archive.

## Report Quality Checklist

Check whether:

- the report has a clear top summary;
- severity or level is understandable;
- evidence is readable;
- recommendations are concrete enough;
- categories and ecosystems reduce noise;
- individual findings remain accessible;
- export content matches the UI closely enough.

## Safety Checklist

Confirm:

- no Active work;
- no live targets;
- no Nmap;
- no outside hosts;
- no sensitive uploads;
- uploaded source is cleaned up after the test;
- no screenshots containing private data;
- no access material recorded in docs or notes.

## Internal Feedback Template

```text
Date:
Browser/device:
Test input used:
Completed flows:
Confusing moments:
GUI polish issues:
Report issues:
Safety concerns:
Must-fix before external tester:
Nice-to-have later:
```

## Next Recommended Phase

```text
PRIVATE_ALPHA_SELF_TEST_SMOKE_02
```

Goal: execute this guide manually from another browser or another PC and record
observations without external sharing.

## Later Phase Candidates

After self-test smoke:

- `ALPHA_GUI_POLISH_TRIAGE_01`
- `ALPHA_GUI_POLISH_IMPLEMENTATION_01`
- `PRIVATE_ALPHA_TESTER_GUIDE_EXTERNAL_01`

## Decision

```text
PRIVATE_ALPHA_SELF_TEST_GUIDE_01_ACCEPTED
```
