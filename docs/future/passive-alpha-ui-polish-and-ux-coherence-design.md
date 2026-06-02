# Passive Alpha UI Polish and UX Coherence Design

Status: docs-first design for a future UI polish phase. This document does not implement frontend, backend, runner, reporting, or analyzer changes.

Inspectra Passive technical alpha is closed for module expansion as recorded in `docs/future/passive-suite-alpha-transversal-closeout.md`. The next product step is not another analyzer; it is making the existing passive suite feel coherent, explainable, and safe to use during alpha smoke and demos.

## 1. Objective

Design a small, focused UI/UX polish pass for the passive alpha so users can understand what Inspectra can review, which actions apply to each source, what each job means, and why findings are heuristic review indicators rather than confirmed vulnerabilities.

The polish should:

- Group the now-large set of archive actions into a clearer mental model.
- Improve audit labels, filters, and report navigation without changing audit contracts.
- Standardize report headers, passive-scope copy, empty states, running/failed states, and redaction messaging.
- Keep raw JSON available but clearly secondary and defensively redacted.
- Preserve the existing archive-only and passive security boundaries.

This design is intentionally transversal. It should make `django_config_basic`, `docker_config_basic`, `secrets_review_basic`, `node_package_config_basic`, `ci_cd_config_basic`, `k8s_config_basic`, `terraform_config_basic`, `nginx_config_basic`, `compose_config_basic`, `database_config_basic`, `redis_config_basic`, and `sql_database_config_basic` feel like one product family instead of unrelated buttons.

## 2. Current Problem

The implemented module set is broad enough for a technical alpha, but the UI risks feeling like a flat inventory of tools:

- Archive files expose many actions at once.
- Audit type labels are not consistently humanized.
- Dashboard filters are useful but dense as the audit list grows.
- Report pages contain good information, but sections, scope reminders, redaction notes, and empty states vary by module.
- Users can miss that passive config analyzers do not execute tools, contact services, validate credentials, download artifacts, or prove exploitability.
- Raw JSON is useful for technical users, but it needs consistent placement and explicit redaction messaging.

The goal is not visual novelty. The goal is confidence, scannability, and a calmer product shape.

## 3. Non-Goals

This UI polish line must not:

- Add new analyzers.
- Add new findings.
- Change runner parsing behavior.
- Change backend endpoints or job contracts.
- Change export formats except for later presentation polish that reuses stored results.
- Execute tools, package managers, Docker, Terraform, Nginx, Redis, SQL clients, Kubernetes, CI workflows, or uploaded files.
- Add network calls for passive config analyzers.
- Validate credentials, tokens, certificates, registries, CVEs, advisories, live services, cloud state, or runtime exposure.
- Reclassify heuristic findings as confirmed vulnerabilities.
- Rewrite the frontend architecture globally.
- Hide raw JSON from technical users.

## 4. UX Principles

- **Passive by default:** Every passive config report should visibly communicate that it is local, bounded, archive-based, and non-executing.
- **Review indicators, not verdicts:** Findings should be framed as signals for human review, not proof of compromise, breach, exploitability, live exposure, or valid credentials.
- **Group before listing:** Large action sets should be grouped by user intent and system surface before exposing every action.
- **Use source-aware actions:** Files, archives, URLs, domains, and explicit inventory inputs should each show only relevant actions.
- **Prefer progressive disclosure:** Summary, scope, and findings should be first; raw JSON, detailed directives, and long detected-file lists should be secondary.
- **Keep redaction visible:** Users should know results are redacted, originals may still contain secrets, and `[REDACTED]` is a protective placeholder.
- **Make sparse data acceptable:** Queued, running, failed, sparse, malformed, and empty-result payloads should remain readable product states.
- **Do not overclaim precision:** Missing-header, missing-probe, missing-resource, include-not-resolved, and no-read-file signals should show confidence and context.
- **Demo readiness matters:** The alpha should be easy to smoke manually with a small archive fixture and representative exports.

## 5. User Mental Model

The frontend should teach three source families:

- **Uploaded files:** PDF, image, manifest, and general file reviews.
- **Uploaded archives:** Passive configuration reviews across application, containers, infrastructure, workflows, web edge, service wiring, databases, cache, and secrets.
- **Authorized targets:** Explicit web/domain/subdomain workflows with their own authorization and network/DNS boundaries.

For archives, users should see module families:

- **Application config:** Django config and Node package config.
- **Containers and service wiring:** Docker config and Compose config.
- **Infrastructure and deployment:** CI/CD config, Kubernetes config, and Terraform config.
- **Web edge:** Nginx config.
- **Data layer:** Database config, Redis config, and SQL database config.
- **Secrets and sensitive files:** Secrets review.
- **Archive structure:** Analyze archive and Analyze project manifests.

This grouping should be conceptual first. The initial implementation can be simple labels, grouped menus, or sectioned button rows; it does not require a large navigation rewrite.

## 6. Proposed Dashboard Structure

The dashboard should keep the current single-page simplicity while improving hierarchy:

- **Upload and source area:** Show accepted source types, local storage caveat, and short passive scope reminder.
- **Files table/list:** Show file name, kind, size, upload time, and applicable actions.
- **Archive actions:** Group actions by family and keep common actions visible.
- **Jobs area:** Show status, human audit label, source, category, created/completed time, findings count if available, truncation/errors if available, and quick report access.
- **Report area:** Render the selected job with a consistent passive report shell.

Recommended job categories:

| Category | Audit types |
| --- | --- |
| File basics | `pdf_basic`, `image_basic`, `manifest_basic`, `archive_basic`, `project_archive_basic` |
| Authorized web/domain | `web_basic`, `domain_basic`, `subdomain_inventory_basic` |
| App config | `django_config_basic`, `node_package_config_basic` |
| Containers and wiring | `docker_config_basic`, `compose_config_basic` |
| Infrastructure and deployment | `ci_cd_config_basic`, `k8s_config_basic`, `terraform_config_basic` |
| Web edge | `nginx_config_basic` |
| Data layer | `database_config_basic`, `redis_config_basic`, `sql_database_config_basic` |
| Secrets | `secrets_review_basic` |

Dashboard filters can keep audit-type precision while adding friendlier labels and optional category grouping.

## 7. Source Actions

### Archive Files

Archive source actions should remain archive-only and should be grouped:

- **Start here:** Analyze archive, Analyze project manifests.
- **Secrets:** Analyze secrets review.
- **Application:** Analyze Django config, Analyze Node package config.
- **Container and service wiring:** Analyze Docker config, Analyze Compose config.
- **Deployment and IaC:** Analyze CI/CD config, Analyze Kubernetes config, Analyze Terraform config.
- **Web edge:** Analyze Nginx config.
- **Data layer:** Analyze database config, Analyze Redis config, Analyze SQL DB config.

Future idea, not part of this design-phase implementation: a single "Run recommended passive checks" action for trusted local alpha demos. If implemented later, it must create ordinary jobs through existing endpoints and must not change analyzer scope.

### Non-Archive Files

Non-archive files should not display archive-only config actions. If a kind has no applicable action, show a quiet empty state such as:

`No passive actions are available for this file type.`

### Authorized Target Workflows

Web, domain, and subdomain workflows should stay visually distinct from archive config analyzers because they may involve authorized network/DNS behavior. Their copy should not blur into the no-network posture of archive-based passive config modules.

## 8. Report Shell

Each type-specific report should sit inside a consistent shell:

- Human audit name.
- Audit type.
- Category.
- Job status.
- Source file or target.
- Created/completed timestamps when available.
- Passive scope badge for archive-based config modules.
- Findings count, redaction count, truncation flag, and errors count when available.
- Export actions if available.

Recommended report order:

1. **General Summary:** Status, source, audit type, analyzer, category, timing.
2. **Scope Notice:** Passive behavior and explicit non-scope for the module family.
3. **Summary Metrics:** Compact cards or rows from the job summary.
4. **Findings:** Grouped by level/severity and category, with confidence visible when present.
5. **Module Context Sections:** Files, resources, services, directives, includes, state files, no-read files, or other module-specific context.
6. **Limits and Errors:** Truncation, controlled errors, parser uncertainty.
7. **Redaction Notes:** Redaction count and notes when present.
8. **Raw JSON:** Collapsed by default and defensively redacted.

Report pages should tolerate:

- queued jobs
- running jobs
- controlled failed jobs
- completed jobs with no findings
- sparse summaries
- missing optional fields
- malformed legacy payloads
- empty arrays
- redaction-only results

## 9. Findings Presentation

Findings should show only fields that exist and should avoid blank noise.

Preferred fields:

- level/severity
- confidence
- category
- context
- provider or surface when relevant
- file path
- line
- resource/service/job/container/directive/location as relevant
- code/id
- title
- description
- safe evidence
- recommendation

Recommended grouping:

- First by level/severity: medium, low, info, unknown.
- Then optionally by category/surface.

Copy should avoid alarmist phrasing. Recommended language:

- "Review indicator"
- "Static signal"
- "Detected configuration pattern"
- "May need review"
- "Requires human validation"
- "Not a confirmed vulnerability"

Avoid:

- "Exploitable"
- "Compromised"
- "Breached"
- "Credential is valid"
- "Live exposure confirmed"
- "Malicious"
- "Critical exploit"

## 10. Scope Notice Copy

Each archive-based passive config report should include a short scope notice. The exact wording can vary by module, but the shared structure should be stable:

```text
Passive static review only. Inspectra reads bounded candidate files from the uploaded archive and reports heuristic review indicators. It does not execute tools, contact live services, validate credentials, download dependencies, query CVEs/advisories, or prove exploitability.
```

Module-specific additions:

- CI/CD: no workflow execution, runner emulation, provider APIs, token validation, or remote action/image downloads.
- Kubernetes: no `kubectl`, cluster access, API server validation, Helm rendering, or Kustomize build.
- Terraform: no Terraform/OpenTofu/Terragrunt execution, no init/validate/plan/apply, no provider/module downloads, no cloud APIs, no remote state or drift analysis.
- Nginx: no Nginx execution, no `nginx -t`, no DNS/network/port checks, no live server or certificate validation, no include resolution.
- Compose/Docker: no Docker/Compose execution, no builds, no pulls, no image inspection, no Docker daemon validation.
- Database/Redis/SQL DB: no clients, sockets, server execution, credential validation, query execution, dump/data parsing, or live service truth.
- Secrets review: no credential validation, provider calls, external scanners, Git history scanning, or active-secret claims.

## 11. Redaction UX

The UI should make redaction both visible and reassuring:

- Use the fixed placeholder `[REDACTED]`.
- Explain that results, reports, exports, and raw JSON are defensively redacted.
- Explain that uploaded archive bytes may still contain secrets and are stored locally.
- Do not show secret prefixes, suffixes, hashes, fingerprints, or reversible identifiers.
- Do not imply that redaction validates whether a credential is real.

Suggested redaction note:

```text
Sensitive-looking values are redacted in results and exports. This does not sanitize the original uploaded file.
```

Raw JSON should be:

- Collapsed by default.
- Labeled as redacted.
- Rendered as inert text, not dynamic HTML.
- Covered by tests that assert fixture secrets do not appear.

## 12. Empty and Error States

Recommended states:

- No files uploaded: `Upload a file or archive to start a passive review.`
- Archive uploaded, no jobs yet: `Choose a passive archive review to create a job.`
- No applicable actions: `No passive actions are available for this file type.`
- Queued: `Job queued. Results will appear when processing starts.`
- Running: `Passive analysis is running. No external services are contacted for archive config analyzers.`
- Completed with findings: `Review indicators were reported. Validate them manually before acting.`
- Completed with no findings: `No heuristic findings were reported for this analyzer.`
- Failed: `The job failed in a controlled state. Review errors below; uploaded content was not executed.`
- Truncated: `Limits were reached; results may be partial.`
- Sparse or legacy payload: `Some result fields are unavailable; showing available redacted data.`

## 13. Visual and Interaction Guidance

This is a technical alpha UI, so the preferred feel is quiet, utilitarian, and scan-friendly:

- Use compact grouped action areas rather than hero-style sections.
- Keep cards for repeated report items, not for nesting full page sections inside other cards.
- Prefer badges for category, status, scope, truncation, and context.
- Prefer tables or compact lists for detected files, services, directives, resources, and jobs.
- Keep raw JSON visually secondary.
- Keep button labels action-oriented and specific.
- Avoid dense walls of same-weight buttons for archive actions.
- Avoid marketing language.

## 14. Future Tests

Future UI polish implementation should add or adjust tests for:

- Human labels for all audit types.
- Category labels for all audit types.
- Archive-only actions remain hidden for non-archives.
- Archive actions are grouped without removing existing actions.
- Existing actions still call their current endpoints.
- `redis_config_basic`, `sql_database_config_basic`, `compose_config_basic`, `nginx_config_basic`, `terraform_config_basic`, `k8s_config_basic`, and `ci_cd_config_basic` remain filterable.
- Report shell renders queued, running, failed, completed, sparse, and malformed jobs.
- Report scope notices do not claim active validation.
- Forbidden wording such as compromised/exploitable/confirmed vulnerability is absent from controlled UI copy.
- Redacted raw JSON does not contain fixture passwords, tokens, credential URLs, database URLs, Redis URLs, authorization headers, or private-key markers.
- Empty states are rendered for no findings, no files, no actions, no errors, and missing optional arrays.
- Export links or export buttons remain available where the backend supports them.

Suggested negative fixture strings:

- `super-secret-password`
- `raw-api-key-123456`
- `token_should_never_render`
- `Authorization: Bearer token_should_never_render`
- `postgres://user:pass@example.com/db`
- `redis://:super-secret-password@redis:6379/0`
- `http://user:pass@example.com`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`

## 15. Implementation Microphases

Recommended future microphases:

1. **Dashboard labels and grouping:** Humanize audit labels, introduce category metadata, group archive actions, and preserve existing endpoint calls.
2. **Report shell consistency:** Add a shared report header/scope/summary pattern while keeping module-specific sections intact.
3. **State and empty-state polish:** Normalize queued/running/failed/no findings/sparse/malformed states.
4. **Redaction and scope copy pass:** Standardize `[REDACTED]` notes, raw JSON labels, and passive no-scope wording across reports.
5. **Export/report readability polish:** Align export labels and report section names with frontend copy where possible without changing stored result contracts.
6. **Alpha smoke demo guidance:** Prepare a small manual UI smoke checklist and fixture guidance for trusted local alpha demos.

Each microphase should be small, testable, and reversible. None should add analyzers or runtime behavior.

## 16. Acceptance Criteria For This Design

This design phase is complete when:

- The UI polish scope is documented.
- The design explains the source/action/report mental model.
- The design records no-scope and passive safety boundaries.
- The design includes wording guidance and forbidden claims.
- The design includes redaction UX guidance.
- The design proposes future UI tests and implementation microphases.
- No runtime, backend, frontend, analyzer, export, or test behavior is changed in this docs-first microphase.

## 17. Product Decision

Proceed with UI coherence polish before opening another analyzer family. Inspectra has enough passive module breadth for a technical alpha; the next product value is making the existing breadth easy to understand, safe to present, and smooth to smoke manually.

Recommended next microphase: dashboard labels, category metadata, and grouped archive actions.
