# terraform_config_basic Design

Status: proposed docs-first design. No runtime endpoint, runner analyzer, backend job, frontend UI, or exports are implemented by this document.

## 1. Module Objective

`terraform_config_basic` is a future passive archive audit for Terraform, OpenTofu-compatible Terraform syntax, Terragrunt, and related IaC configuration files.

The module should help users review infrastructure-as-code posture before changes are initialized, planned, applied, or deployed. It should look for static review indicators around secrets, provider/backend configuration, modules, cloud networking, storage exposure, IAM breadth, databases, Kubernetes provider resources, reliability controls, and Terraform state handling.

It should not execute Terraform/OpenTofu/Terragrunt, contact cloud providers, evaluate real infrastructure state, resolve modules, download providers, query registries, or prove exploitability. Findings must remain conservative review indicators that require human validation.

This is useful for Inspectra because Terraform often defines the cloud, network, IAM, storage, database, Kubernetes, and service resources that later appear in deployment and runtime environments. A bounded, local, archive-only review gives defenders early signal without provider credentials or external services.

## 2. Allowed Scope

The module should only analyze archives uploaded by the user and registered as `kind: archive`.

Allowed behavior:

- Bounded reads of candidate Terraform, OpenTofu-compatible, Terragrunt, and IaC context files inside uploaded archives.
- Detection of Terraform state files as sensitive files present, without reading their content in v1.
- Textual, HCL-like, JSON-like, and line-oriented heuristic analysis.
- Safe local HCL parsing only if a suitable parser already exists in the runtime and can be used without executing code or resolving modules.
- Best-effort block, resource, provider, backend, module, variable, and output detection.
- Redaction-first handling of secret-like values in evidence, errors, raw results, and future exports.
- Recording parse uncertainty, unsupported syntax, truncation, and controlled errors.

Disallowed behavior in v1:

- No Terraform, OpenTofu, or Terragrunt execution.
- No `terraform init`, `validate`, `plan`, `apply`, or `destroy`.
- No `tofu init`, `validate`, `plan`, `apply`, or `destroy`.
- No provider download.
- No module download or remote module resolution.
- No interpolation, expression evaluation, variable resolution, or effective IAM evaluation.
- No cloud, Kubernetes, DNS, CDN, database, identity, or SaaS provider API calls.
- No network calls.
- No dependency installation.
- No reading real `.env`, `.env.*`, or `.envrc` files.
- No remote state access.
- No drift analysis.
- No CVE or advisory lookups.
- No exploitability, compromise, or confirmed-vulnerability claims.

## 3. Candidate Files

Terraform and OpenTofu-compatible files:

- `*.tf`
- `terraform.tf`
- `main.tf`
- `variables.tf`
- `outputs.tf`
- `providers.tf`
- `versions.tf`
- `backend.tf`
- `*.tf.json`
- `.terraform.lock.hcl`

Variable files:

- `*.tfvars`
- `*.tfvars.json`
- `*.auto.tfvars`
- `*.auto.tfvars.json`

Terragrunt:

- `terragrunt.hcl`
- `terragrunt*.hcl`

Terraform state files:

- `terraform.tfstate`
- `*.tfstate`
- `*.tfstate.backup`

State files should be detected as `terraform_state_file_present` and not read in v1 because Terraform state can contain plaintext secrets, provider tokens, generated passwords, private keys, and rendered resource attributes.

Candidate folders and path contexts:

- `terraform/**`
- `infra/**`
- `infrastructure/**`
- `iac/**`
- `deploy/**`
- `environments/**`
- `envs/**`
- `modules/**`

OpenTofu compatibility should be treated passively: the same HCL-oriented file patterns can be reviewed without running `tofu` or resolving OpenTofu-specific runtime behavior.

## 4. Out of Scope

`terraform_config_basic` v1 must not perform:

- Terraform, OpenTofu, or Terragrunt execution.
- `init`, `validate`, `plan`, `apply`, `destroy`, state inspection, import, refresh, or output commands.
- Provider installation or provider schema download.
- Remote module resolution from registries, Git, HTTP, object storage, or local outside-archive paths.
- Full HCL evaluation if no safe parser exists.
- Expression interpolation, variable interpolation, locals evaluation, or conditional evaluation.
- Cloud/provider API calls for AWS, Azure, GCP, Cloudflare, DigitalOcean, Kubernetes, or any other provider.
- Network calls.
- Dependency installation.
- Reading real `.env`, `.env.*`, or `.envrc` files.
- Remote state download or backend access.
- Analysis of real infrastructure state, drift, runtime exposure, reachability, or effective IAM.
- Git history scanning.
- CVE, advisory, reputation, or registry lookup.
- Claims that a configuration is exploitable, compromised, or a confirmed vulnerability.

Findings must remain heuristic review indicators.

## 5. Initial Finding Model

Secrets and sensitive data:

- `terraform_tfvars_secret_like_key`
- `terraform_variable_default_secret_like`
- `terraform_output_sensitive_false_secret_like`
- `terraform_state_file_present`
- `terraform_backend_credentials_hint`
- `terraform_provider_credentials_hint`
- `terraform_plaintext_private_key_hint`
- `terraform_secret_in_user_data_hint`

Providers, backend, modules, and versioning:

- `terraform_required_version_missing`
- `terraform_provider_version_unpinned`
- `terraform_remote_backend_missing`
- `terraform_backend_config_secret_like`
- `terraform_lockfile_missing`
- `terraform_module_source_unpinned`

AWS signals:

- `aws_s3_bucket_public_access_risk`
- `aws_s3_bucket_encryption_missing`
- `aws_s3_bucket_versioning_missing`
- `aws_security_group_ingress_any_ipv4`
- `aws_security_group_ingress_any_ipv6`
- `aws_security_group_ssh_open_world`
- `aws_security_group_rdp_open_world`
- `aws_iam_policy_wildcard_action`
- `aws_iam_policy_wildcard_resource`
- `aws_iam_admin_policy_attachment_hint`
- `aws_kms_key_rotation_missing`
- `aws_db_publicly_accessible`
- `aws_ebs_encryption_missing`
- `aws_cloudtrail_disabled_or_missing_hint`

Azure signals:

- `azure_storage_public_access_hint`
- `azure_storage_https_only_missing`
- `azure_network_security_rule_open_world`
- `azure_key_vault_soft_delete_missing`
- `azure_key_vault_purge_protection_missing`
- `azure_sql_public_network_access_hint`

GCP signals:

- `gcp_storage_bucket_public_access_hint`
- `gcp_storage_uniform_access_missing`
- `gcp_firewall_open_world`
- `gcp_firewall_ssh_open_world`
- `gcp_firewall_rdp_open_world`
- `gcp_iam_wildcard_role_hint`
- `gcp_service_account_key_created_hint`

Kubernetes provider signals:

- `terraform_kubernetes_secret_plaintext_hint`
- `terraform_kubernetes_service_loadbalancer_hint`
- `terraform_kubernetes_privileged_container_hint`

Generic reliability, cost, and posture:

- `terraform_resource_without_tags_hint`
- `terraform_deletion_protection_missing`
- `terraform_backup_retention_missing`
- `terraform_logging_disabled_hint`
- `terraform_public_ip_assigned_hint`

## 6. Severity and Confidence

Default severity should be conservative and context-aware.

Medium indicators:

- Terraform state files present in uploaded archives.
- Secret-like `.tfvars`, variable defaults, backend config, provider config, outputs, or `user_data` values.
- Outputs with secret-like names where `sensitive = false` or no sensitive flag is observed.
- SSH or RDP ingress from `0.0.0.0/0` or `::/0`.
- IAM wildcard action or resource indicators.
- Public bucket/storage hints.
- Public database exposure hints.
- Plaintext private key or credential material indicators.

Low indicators:

- Provider or module versions that appear unpinned.
- Missing lockfile in likely root Terraform projects.
- Missing encryption, versioning, logging, backup retention, deletion protection, or tags when statically detectable but context is unclear.
- Remote backend missing or local backend implied in production-like context.

Info indicators:

- Provider detected.
- Module detected.
- Backend detected.
- State file detected but not read, when presented as context with a clear warning.
- Unsupported syntax, parser uncertainty, or skipped files.

Path context should affect severity:

- `production`, `prod`, `live`, `deploy`, and `environments/prod` preserve default severity.
- `dev`, `test`, `local`, `example`, `sample`, `docs`, and `sandbox` degrade severity.
- Ambiguous shared modules should keep cautious severity but avoid deployment-specific claims.

Findings may include confidence (`high`, `medium`, `low`) when useful, but must not claim exploitability or cloud-state truth.

## 7. Redaction and Safe Evidence

The module must reuse the defensive redaction posture established by `secrets_review_basic`, `k8s_config_basic`, and other passive config modules.

Never show raw values for:

- Secret-like keys in `.tfvars`, variables, provider blocks, backend blocks, outputs, locals, tags, metadata, `user_data`, and startup scripts.
- Access keys, secret keys, session tokens, passwords, API keys, private keys, client secrets, certificates, connection strings, or credential URLs.
- Terraform state file contents.
- Private key blocks.

Evidence may safely include:

- File path.
- Resource type.
- Resource name.
- Provider.
- Block type.
- Attribute or key name.
- Line number when available.
- Fixed `[REDACTED]` placeholder.

Evidence must not include prefixes, suffixes, hashes, fingerprints, or reversible identifiers for secrets. Raw JSON, future backend exports, frontend reports, and errors must be defensively redacted even for legacy or malformed payloads.

## 8. Comments, HCL, and Parsing Strategy

Prefer safe local HCL parsing only if an appropriate parser is already available in the runtime and can operate without executing code, loading plugins, resolving providers, or fetching modules.

If no safe HCL parser exists, v1 may use bounded text heuristics:

- Comment-aware line scanning for `#`, `//`, and `/* ... */` style comments.
- Block scanning for `resource`, `provider`, `terraform`, `backend`, `module`, `variable`, `output`, `locals`, and `data`.
- Attribute scanning for simple `key = value` forms.
- Basic heredoc awareness for `user_data`, startup scripts, policy JSON, and secret-like values.
- Best-effort JSON scanning for `.tf.json`, `.tfvars.json`, and policy-like strings.

The analyzer must not evaluate expressions, interpolate variables, resolve `count`/`for_each`, expand modules, evaluate locals, or determine effective resource state. Parse uncertainty should be recorded as controlled errors or info-level signals rather than raising unhandled exceptions.

## 9. Proposed JSON Result

The result should follow passive audit conventions used by existing Inspectra modules:

```json
{
  "analyzer": "terraform_config_basic",
  "archive_type": "zip",
  "summary": {
    "files_considered": 0,
    "files_reviewed": 0,
    "terraform_files_detected": 0,
    "tfvars_files_detected": 0,
    "state_files_detected": 0,
    "providers_detected": 0,
    "backends_detected": 0,
    "modules_detected": 0,
    "resources_detected": 0,
    "findings_count": 0,
    "redacted_values_count": 0,
    "truncated": false
  },
  "limits": {
    "max_files": 100,
    "max_file_bytes": 524288,
    "max_total_bytes": 2097152
  },
  "files_detected": [],
  "files_reviewed": [],
  "providers": [],
  "backends": [],
  "modules": [],
  "resources": [],
  "variables": [],
  "outputs": [],
  "state_files": [],
  "findings": [],
  "redaction_notes": [],
  "errors": [],
  "truncated": false
}
```

Candidate future limits:

- `INSPECTRA_TERRAFORM_CONFIG_MAX_FILES`, default `100`.
- `INSPECTRA_TERRAFORM_CONFIG_MAX_FILE_BYTES`, default `524288`.
- `INSPECTRA_TERRAFORM_CONFIG_MAX_TOTAL_BYTES`, default `2097152`.

## 10. UX and Reporting Expected

The future UI and exports should present `terraform_config_basic` as a passive static IaC review, not a vulnerability scanner.

Expected sections:

- Summary.
- Files reviewed and skipped.
- Providers and backend.
- Modules.
- Resources overview.
- Variables and outputs safety signals.
- State files detected but not read.
- Findings grouped by severity, category, provider, and context.
- Limits, truncation, controlled errors, and parser uncertainty.
- Redaction notes.
- Raw JSON as a secondary, redacted debugging view.

Reports should clearly state that Inspectra does not run Terraform/OpenTofu/Terragrunt, initialize providers, render plans, contact cloud APIs, validate live infrastructure, analyze drift, query CVEs/advisories, or confirm exploitability.

## 11. Future Tests

Runner tests:

- `.tfvars` secret-like key generates `terraform_tfvars_secret_like_key` with redacted evidence.
- Variable default password generates `terraform_variable_default_secret_like` with redacted evidence.
- Output with secret-like name and `sensitive = false` generates `terraform_output_sensitive_false_secret_like`.
- `terraform.tfstate` is detected as `terraform_state_file_present` and not read.
- AWS security group ingress from `0.0.0.0/0` to port `22` generates `aws_security_group_ssh_open_world`.
- AWS security group ingress from `::/0` generates `aws_security_group_ingress_any_ipv6`.
- AWS S3 public access hints generate `aws_s3_bucket_public_access_risk`.
- IAM wildcard action/resource generate wildcard findings.
- Provider or module unpinned references generate version/source findings.
- Backend secret-like config is redacted.
- `user_data` secret-like material is redacted.
- Comments do not generate strong findings.
- Path traversal, absolute paths, symlinks, hardlinks, and non-regular archive entries are not read.
- File count, per-file byte, total-byte, and archive-entry limits produce truncation/errors without leaking data.
- Serialized JSON does not contain fixture secrets.

Backend/reporting tests:

- Endpoint accepts only archives.
- Runner call targets `/analyze/terraform-config` if that becomes the final runner path.
- Job type is `terraform_config_basic`.
- Summary tolerates sparse and malformed payloads.
- Markdown, HTML, XML, and PDF exports render sparse payloads without breaking.
- Legacy payloads with raw secrets in findings, errors, resources, variables, outputs, backends, or state-file metadata are redacted.

Frontend tests:

- Action appears only for archives.
- Report renders summary, providers, backends, modules, resources, variables/outputs, findings, state files, limits, errors, and redaction notes.
- Queued, running, failed, sparse, legacy, and malformed payloads do not break rendering.
- Raw JSON remains available where the pattern exists and is defensively redacted.

## 12. Implementation Plan

1. Docs-first design and scope freeze.
2. Runner/parser passive analysis plus redaction and tests.
3. Backend endpoint, job storage, reporting/export, and tests.
4. Frontend action, report UX, raw JSON redaction, and tests.
5. End-to-end contract and redaction review.
6. Docs/smoke closeout.

Each phase should remain bounded, passive, archive-only, and redaction-first.

## 13. Future Documentation Changes

When runtime is implemented, update:

- `README.md` with the endpoint, UI action, limits, passive scope, and no-execution guardrails.
- `docs/architecture.md` with the backend to runner to storage to reporting to frontend flow.
- `docs/security-scope.md` with allowed Terraform/OpenTofu/Terragrunt config review scope and explicit out-of-scope provider/runtime behavior.
- `docs/future/k8s-config-basic-closeout.md` or a new passive IaC closeout document to record the module as implemented.

Documentation must continue to state that Inspectra does not run Terraform/OpenTofu/Terragrunt, contact providers, download modules/providers, inspect remote state, query CVEs/advisories, or confirm exploitability.
