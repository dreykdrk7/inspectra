# Passive Alpha UI Polish: Dashboard Labels, Categories, and Grouped Actions

Status: implemented as the first frontend-only UI coherence polish after `docs/future/passive-alpha-ui-polish-and-ux-coherence-design.md`.

Commit target: `feat(ui): group passive archive actions by category`.

## Scope

This microphase improves how the existing passive alpha modules are presented in the dashboard. It does not add analyzers, endpoints, jobs, findings, report sections, exports, runner behavior, backend behavior, or redaction logic.

Implemented UI surfaces:

- Centralized audit type metadata for human labels and categories.
- Dashboard job filters using human audit labels.
- Job table type display using human label plus category.
- Archive actions grouped by passive module family.
- Brief passive archive review copy near archive actions.

## Audit Type Catalog

The frontend now has centralized metadata for visible alpha audit types:

- `pdf_basic`
- `image_basic`
- `manifest_basic`
- `archive_basic`
- `project_archive_basic`
- `web_basic`
- `domain_basic`
- `subdomain_inventory_basic`
- `django_config_basic`
- `docker_config_basic`
- `secrets_review_basic`
- `node_package_config_basic`
- `ci_cd_config_basic`
- `k8s_config_basic`
- `terraform_config_basic`
- `nginx_config_basic`
- `compose_config_basic`
- `database_config_basic`
- `redis_config_basic`
- `sql_database_config_basic`

Each entry records:

- Human label.
- Category id.
- Category label.
- Source family.
- Short description.

Unknown audit types keep a stable fallback label and `Unknown` category.

## Categories

The first-pass dashboard categories are:

- File basics.
- Archive structure.
- Authorized web/domain.
- App config.
- Containers & wiring.
- Infrastructure & deployment.
- Web edge.
- Data layer.
- Secrets.

These categories are presentation metadata only. They do not change audit type values, backend job types, endpoints, summaries, findings, or report payloads.

## Grouped Archive Actions

Archive-only actions are still shown only for files registered as `kind: "archive"`, but they are no longer presented as one flat list.

Groups:

- **Start here**
  - Analyze archive.
  - Analyze project manifests.
- **Secrets**
  - Analyze secrets review.
- **Application**
  - Analyze Django config.
  - Analyze Node package config.
- **Container & service wiring**
  - Analyze Docker config.
  - Analyze Compose config.
- **Deployment & IaC**
  - Analyze CI/CD config.
  - Analyze Kubernetes config.
  - Analyze Terraform config.
- **Web edge**
  - Analyze Nginx config.
- **Data layer**
  - Analyze database config.
  - Analyze Redis config.
  - Analyze SQL DB config.

No bulk "run all" action was added.

## Endpoint and Contract Preservation

All existing action callbacks and endpoints are preserved:

- `POST /audits/archive/{file_id}`
- `POST /audits/project-archive/{file_id}`
- `POST /audits/django-config/{file_id}`
- `POST /audits/docker-config/{file_id}`
- `POST /audits/secrets-review/{file_id}`
- `POST /audits/node-package-config/{file_id}`
- `POST /audits/ci-cd-config/{file_id}`
- `POST /audits/k8s-config/{file_id}`
- `POST /audits/terraform-config/{file_id}`
- `POST /audits/nginx-config/{file_id}`
- `POST /audits/compose-config/{file_id}`
- `POST /audits/database-config/{file_id}`
- `POST /audits/redis-config/{file_id}`
- `POST /audits/sql-database-config/{file_id}`

The microphase does not touch backend, runner, reporting/export, raw JSON, redaction helpers, findings, severities, summaries, or stored job formats.

## Passive Copy

Archive action UI now includes concise copy:

```text
Archive reviews are passive and bounded. Inspectra reads candidate files from the uploaded archive and reports review indicators; it does not execute the project or contact live services for these config checks.
```

Controlled UI copy avoids claims such as compromised, breached, exploitable, confirmed vulnerability, or credentials valid.

## Tests

Frontend tests cover:

- Catalog metadata for all visible alpha audit types.
- Unknown audit type fallback.
- Human labels for Redis and SQL DB.
- Category labels for Redis and SQL DB.
- Search by human audit label and category.
- Redis and SQL DB still present in filters.
- Archive action groups visible for archive rows.
- Archive action groups not shown for non-archive rows.
- No "Run all recommended passive checks" action.
- Passive copy avoids prohibited wording.
- Existing archive actions still call the same endpoints, including Redis and SQL DB.

## Limitations

- This is not a report shell refactor.
- It does not standardize individual report headers yet.
- It does not change export copy.
- It does not introduce a category filter UI; categories are metadata and display context for now.
- It does not add a bulk run-all action.
- It does not change styling globally.

## Next Microphase

Recommended next step:

`PASSIVE-ALPHA-UI-POLISH-AND-UX-COHERENCE-03-REPORT-SHELL-CONSISTENCY`

That phase should focus on report header/scope/summary consistency while preserving existing module-specific sections and contracts.
