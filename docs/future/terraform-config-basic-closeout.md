# terraform_config_basic Closeout

Status: `terraform_config_basic` is implemented and stable as a v1 passive archive-based IaC audit module.

This closeout records the runtime scope, smoke checks, redaction posture, and product decision for Terraform/OpenTofu/Terragrunt config audits. The original docs-first design remains in `docs/future/terraform-config-basic-design.md`.

## Commit Series

- `4dc957d docs(terraform): design passive iac config audit`
- `4d8bc48 feat(terraform): add passive config runner analysis`
- `3c87132 feat(terraform): add config backend job`
- `39a35e9 feat(terraform): add config report frontend ux`
- `6b1a9c9 fix(terraform): align config contract and redaction`

## Implemented Surfaces

- Runner endpoint: `POST /analyze/terraform-config`.
- Backend endpoint: `POST /audits/terraform-config/{file_id}`.
- Audit type: `terraform_config_basic`.
- Source files: uploaded files registered as `kind: "archive"`.
- Frontend action: `Analyze Terraform config`, shown only for archive files.
- Reporting/export: Markdown, HTML, XML, and PDF sections for Terraform summary data, files, providers, backends, modules, resources, variables, outputs, state files, findings, limits, redaction notes, and errors.
- Frontend raw JSON is defensively redacted before rendering.

## Capabilities

`terraform_config_basic` passively reviews bounded Terraform/OpenTofu-compatible and Terragrunt-related text from uploaded archives. It detects:

- `.tf` and `.tf.json` files.
- `.tfvars`, `.tfvars.json`, `.auto.tfvars`, and `.auto.tfvars.json` files.
- `.terraform.lock.hcl`.
- `terragrunt.hcl` and `terragrunt*.hcl`.
- Terraform state files such as `terraform.tfstate`, `*.tfstate`, and `*.tfstate.backup`.

Terraform state files are detected as sensitive files present and are not read.

The v1 finding model focuses on conservative review indicators for:

- Secret-like tfvars keys, variable defaults, outputs, provider config, backend config, and user data.
- Terraform state file presence.
- Provider, backend, module, lockfile, and required version posture.
- Unpinned provider or module references.
- Basic AWS security group world-ingress signals.
- AWS IAM wildcard action/resource hints.
- AWS S3 public-access hints.

Findings are review indicators for human triage. They are not confirmed vulnerabilities, exploitability claims, live-infrastructure truth, or proof of compromised infrastructure.

## Explicit Scope

- Archive-only.
- Local.
- Bounded.
- Passive.
- Heuristic.
- Redaction-first.
- No execution.
- No external services.
- Controlled errors and truncation instead of broad extraction or best-effort execution.

## Explicit Non-Scope

- No Terraform, OpenTofu, or Terragrunt execution.
- No `terraform`, `tofu`, or `terragrunt` `init`, `validate`, `plan`, `apply`, `destroy`, `state`, `refresh`, `import`, or `output`.
- No provider downloads.
- No module downloads.
- No remote module resolution.
- No expression, variable, local, `count`, `for_each`, output, or effective IAM evaluation.
- No cloud APIs.
- No Kubernetes APIs.
- No remote state access.
- No drift analysis.
- No state content reads.
- No real `.env`, `.env.*`, or `.envrc` reads.
- No registry, CVE, or advisory lookup.
- No exploitability, compromise, or confirmed-vulnerability claims.

## Redaction Guarantees

The module treats Terraform/IaC secrets defensively and best-effort:

- Secret-like tfvars values are redacted.
- Secret-like variable defaults and output values are redacted.
- Provider and backend credentials are redacted.
- User data and startup script secret-like material is redacted.
- Credential-bearing URLs and sensitive query parameters are redacted.
- Access keys, secret keys, session tokens, API keys, client secrets, connection strings, certificates, and private key blocks are redacted.
- Private key material is redacted without preserving `PRIVATE KEY`.
- Terraform state file contents are not read.
- Evidence may show safe context such as file path, resource type, resource name, provider, block type, attribute/key name, line number, or `[REDACTED]`.
- The implementation does not intentionally emit prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers.

Uploaded archive bytes may still contain secrets and are stored locally; redaction protects Inspectra results and reports, not the original uploaded archive.

## Smoke Checklist

Recommended manual smoke before opening the next module:

1. Upload a small `.zip` or `.tar.gz` archive containing Terraform/OpenTofu-compatible config files.
2. Confirm the uploaded file is registered as `kind: "archive"`.
3. Confirm `Analyze Terraform config` appears for the archive file.
4. Launch the analysis from the UI or call `POST /audits/terraform-config/{file_id}`.
5. Confirm the job appears as `terraform_config_basic` and transitions through queued/running to completed or a controlled failed state.
6. Open the frontend report and confirm summary, files, providers/backends, modules, resources, variables/outputs, state files, findings, limits/errors, redaction notes, and raw JSON render clearly.
7. Export the job as Markdown, HTML, XML, and PDF.
8. Confirm Terraform state files are shown as detected but not read.
9. Confirm fixture secrets do not appear in UI, raw JSON, API responses, exports, or controlled errors.
10. Upload a non-archive file and confirm the Terraform action is not shown or is rejected by the backend according to the standard archive-only pattern.
11. Confirm the smoke does not run Terraform, OpenTofu, Terragrunt, provider downloads, module downloads, cloud APIs, remote state access, drift analysis, registry lookups, CVE/advisory lookups, or external services.

Suggested fixture secret strings for negative checks:

- `super-secret-password`
- `raw-api-key-123456`
- `token_should_never_render`
- `PRIVATE KEY`
- `db_password_plaintext`
- `AKIAIOSFODNN7EXAMPLE`
- `aws_secret_access_key_should_not_render`
- `postgres://user:pass@example.com/db`
- `registry-user:registry-pass`
- `-----BEGIN RSA PRIVATE KEY-----`

## Reference Validations

The end-to-end closeout series used focused runner, backend, frontend, build, and redaction checks, including:

```bash
.venv/bin/python -m pytest tools/tests/test_runner.py -k terraform_config
.venv/bin/python -m pytest backend/tests/test_backend.py -k terraform_config
.venv/bin/python -m pytest backend/tests/test_backend.py
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
npm run test -- --run TerraformConfigJobReport reportHelpers App dashboardFilters
npm run test -- --run
npm run build
git diff --check
git diff --cached --check
```

For docs-only changes, the minimum validation is:

```bash
git status --short
git diff --check
git diff --cached --check
```

## Residual Risks

- HCL-like heuristics can produce false positives and false negatives.
- Expressions, locals, variables, `count`, `for_each`, and outputs are not evaluated.
- Remote modules are not resolved.
- Provider schemas are not downloaded.
- Cloud state is not queried.
- Effective IAM is not evaluated.
- Drift is not analyzed.
- Terraform state files are detected but not inspected.
- Azure, GCP, and Kubernetes provider support remains future backlog, not v1 runtime scope.
- Basic AWS checks are static and heuristic.
- Redaction is best-effort and may miss uncommon secret formats.

## Product Decision

`terraform_config_basic` v1 is ready to close. It fits the Inspectra passive module pattern: docs-first scope, bounded runner analysis, backend job/reporting, frontend report UX, and end-to-end contract/redaction review.

Do not add more Terraform implementation now. Future Terraform expansions should be separate docs-first modules or microphases after broader Inspectra module coverage improves. Potential Terraform backlog includes deeper Azure/GCP/Kubernetes provider signals, richer HCL parsing, policy-as-code context, and additional cloud resource posture hints, but those are intentionally outside v1.

Recommended next docs-first module: `nginx_config_basic` or the broader `reverse_proxy_config_basic`.

Rationale: reverse proxy and web edge configuration has high practical value in real deployments, a small bounded config surface, and a strong fit with passive archive-only analysis. It complements Django, Docker, CI/CD, Kubernetes, and Terraform by reviewing the web edge layer without requiring live infrastructure access.

Alternative future candidates:

- `cloudflare_config_basic`, if users provide exported/static configuration.
- `compose_config_basic`, if Docker Compose deserves a focused module separate from Docker config v1.
- `database_config_basic`, for PostgreSQL/MySQL configuration files.
