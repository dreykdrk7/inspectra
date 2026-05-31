# ci_cd_config_basic Design

Status: historical design reference. `ci_cd_config_basic` v1 is now implemented end to end with a passive runner analyzer, backend job/reporting, exports, and frontend report UX. This document remains the design baseline and does not expand the implemented runtime scope.

## 1. Module Objective

`ci_cd_config_basic` is a future passive archive-based audit type for reviewing CI/CD configuration supplied by the user. It should help Inspectra users identify workflow, permission, publish/deploy, secret-handling, and supply-chain hygiene indicators that deserve manual review before running pipelines or sharing a project archive.

The module should detect review signals such as broad triggers, `pull_request_target` usage, broad GitHub permissions, unpinned actions or images, inline secret-like environment values, curl-pipe-shell patterns, publish/deploy jobs, self-hosted runner usage, and cache/artifact behaviors that deserve a human look.

The module should not prove exploitability, validate credentials, emulate CI providers, execute workflows, run scripts, resolve remote actions, download images, query providers, or call advisory/CVE services. Findings must remain heuristic indicators for manual validation.

This module is useful for Inspectra because CI/CD files often decide how code reaches package registries, containers, infrastructure, and production environments. A bounded local review can surface risky configuration patterns while preserving Inspectra's passive, no-execution, no-network MVP model.

## 2. Allowed Scope

The initial module should accept only uploaded archives already registered as `kind: "archive"`. It should reuse the same archive safety posture as existing archive-based modules:

- open ZIP/TAR/TAR.GZ/TGZ archives with Python standard library parsers;
- inspect archive metadata defensively;
- read only bounded candidate CI/CD text files into memory;
- avoid broad extraction to the filesystem;
- skip path traversal entries, absolute paths, symlinks, hardlinks, non-regular files, oversized files, entry-heavy archives, and files beyond configured limits;
- detect real `.env`, `.env.*`, and `.envrc` files if encountered, but do not read their content;
- analyze text, YAML-like, and JSON-like configuration heuristically;
- never execute workflows, provider expressions, runner logic, scripts, package-manager commands, deploy commands, or config files;
- never call GitHub, GitLab, Bitbucket, Azure, npm, Docker Hub, cloud providers, CVE feeds, advisory services, or any external API;
- never validate whether tokens or secrets work.

The analysis can use local structured parsing where safe:

- safe YAML parsing only if a parser is already available and configured for non-executing safe loads;
- JSON parsing for release/deploy helper files when bounded and valid;
- line-oriented text parsing for provider files, scripts, and unknown formats;
- conservative fallback behavior when syntax is invalid, truncated, or uses provider-specific extensions.

## 3. Candidate Files

The module should classify candidate files conservatively and keep reads bounded.

GitHub Actions:

- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`
- `action.yml`
- `action.yaml`
- `.github/actions/**/action.yml`
- `.github/actions/**/action.yaml`

GitLab CI:

- `.gitlab-ci.yml`
- `.gitlab-ci.yaml`
- `.gitlab/ci/*.yml`
- `.gitlab/ci/*.yaml`

Bitbucket Pipelines:

- `bitbucket-pipelines.yml`
- `bitbucket-pipelines.yaml`

Azure Pipelines:

- `azure-pipelines.yml`
- `azure-pipelines.yaml`
- `.azure-pipelines/*.yml`
- `.azure-pipelines/*.yaml`

CircleCI:

- `.circleci/config.yml`
- `.circleci/config.yaml`

Jenkins and generic CI:

- `Jenkinsfile`
- `Jenkinsfile.*`
- `buildkite.yml`
- `.buildkite/pipeline.yml`
- `drone.yml`
- `.drone.yml`
- `woodpecker.yml`
- `.woodpecker.yml`

Release and deploy helper context:

- `.releaserc`
- `.releaserc.json`
- `release.config.*`
- semantic-release configuration files
- Changesets configuration files
- deploy script references as text only, never executed

The exact first implementation can start with a smaller subset, but it should keep the same contract: explicit archive input, bounded reads, no execution, no provider calls, no remote resolution, and defensive redaction.

## 4. Out Of Scope

`ci_cd_config_basic` v1 should not perform:

- workflow execution;
- CI runner emulation;
- dynamic evaluation of GitHub/GitLab/Azure/Bitbucket expressions;
- remote reusable workflow resolution;
- GitHub Action downloads;
- Docker image downloads;
- GitHub, GitLab, Bitbucket, Azure, Docker Hub, cloud, npm, or package registry API calls;
- token or credential validation;
- CVE or advisory lookup;
- dependency installation;
- package publish simulation;
- cloud deployment validation;
- exploitability determination;
- claims that a CI/CD posture is compromised;
- Git history scanning;
- broad archive extraction;
- recursive archive expansion beyond the primary uploaded archive;
- deep source-code security review.

No finding should call itself a confirmed vulnerability, compromised pipeline, leaked credential, malicious action, or exploitable deployment issue by default.

## 5. Initial Finding Model

Finding IDs should remain stable, conservative, and easy to map to UI/reporting groups.

Triggers:

- `broad_push_trigger`: workflow appears to run on broad push branches or all pushes.
- `broad_pull_request_trigger`: workflow appears to run on broad pull request events.
- `pull_request_target_used`: GitHub `pull_request_target` trigger is present.
- `workflow_dispatch_with_inputs`: manual dispatch with inputs is present.
- `schedule_trigger_present`: scheduled workflow trigger is present.
- `tag_publish_trigger`: tag trigger appears to publish or release.
- `release_publish_trigger`: release trigger appears to publish or deploy.

Permissions:

- `github_permissions_write_all`: GitHub permissions appear to use `write-all`.
- `github_permissions_broad_write`: broad write permissions are declared.
- `github_permissions_missing`: no explicit permissions block was observed in a GitHub workflow.
- `id_token_write_permission`: OIDC `id-token: write` is present.
- `contents_write_permission`: `contents: write` is present.
- `packages_write_permission`: `packages: write` is present.

Actions and images pinning:

- `github_action_unpinned_ref`: an action reference is not pinned to a full commit SHA.
- `github_action_uses_branch_ref`: an action reference appears to use a branch-like ref.
- `github_action_uses_latest_or_master`: an action reference uses `latest`, `master`, or `main`.
- `docker_image_unpinned`: a Docker image reference has no tag or digest.
- `docker_image_latest_tag`: a Docker image reference uses `latest`.
- `reusable_workflow_unpinned`: a reusable workflow reference is not pinned to a full commit SHA.

Secrets and environment:

- `inline_secret_like_env`: an inline environment value uses a secret-like key and non-placeholder value.
- `secret_in_ci_variable`: provider variable text appears to contain a secret-like inline value.
- `secret_in_ci_script`: a CI script line appears to assign or echo a secret-like value.
- `ci_env_file_reference`: workflow references an env file; real env file content is not read.
- `ci_secret_store_reference`: workflow references provider secret stores, recorded as an informational signal.
- `ci_secret_reference_present`: `${{ secrets.* }}` or equivalent secret reference is present.
- `ci_secret_context_exposed_to_fork_hint`: secret context appears near fork-prone or pull-request-triggered workflows.

Scripts and remote code:

- `ci_curl_pipe_shell`: CI script appears to pipe curl/wget output to shell.
- `ci_remote_script_execution`: CI script appears to fetch and execute remote code.
- `ci_install_and_execute_global_tool`: CI script installs and immediately executes a global tool.
- `ci_script_references_secret_name`: CI script references secret-like variable names.

Publish and deploy:

- `npm_publish_job_detected`: job or step appears to publish npm packages.
- `docker_push_job_detected`: job or step appears to push container images.
- `cloud_deploy_job_detected`: job or step appears to deploy to cloud or infrastructure.
- `production_environment_deploy`: job references a production environment.
- `deploy_on_pull_request_hint`: deploy-like job appears reachable from pull-request events.
- `release_token_usage_hint`: release/publish job references token-like settings.

Supply-chain hygiene:

- `dependency_install_without_lockfile_hint`: workflow installs dependencies but no lockfile signal is obvious.
- `ci_uses_install_without_frozen_lockfile`: workflow install command does not appear to use frozen/immutable lockfile mode.
- `ci_cache_key_broad`: cache key appears broad or not tied to dependency lockfiles.
- `ci_artifact_upload_present`: artifact upload is present.
- `ci_artifact_download_present`: artifact download is present.

Miscellaneous:

- `self_hosted_runner_used`: workflow uses a self-hosted runner.
- `privileged_service_container_hint`: service container appears privileged or equivalent.
- `service_container_with_default_credentials_hint`: service container appears to use default credentials.

## 6. Severity And Confidence

Severity should be conservative and context-aware.

Medium examples:

- `pull_request_target_used` combined with checkout or script execution patterns.
- `github_permissions_write_all`.
- `id_token_write_permission` in deploy/release/production context.
- unpinned third-party actions in production/deploy workflows.
- inline secret-like values.
- `ci_curl_pipe_shell`.

Low examples:

- broad push or pull-request triggers.
- scheduled or manual dispatch triggers.
- missing explicit permissions block.
- branch/master action refs.
- publish/deploy job indicators without stronger risky context.
- broad cache keys.

Info examples:

- secret store references.
- artifact upload/download usage.
- self-hosted runner usage unless combined with stronger risky patterns.
- release/publish triggers as review indicators.
- environment references that need manual interpretation.

Context should adjust severity:

- production, deploy, release, and publish workflows preserve the default severity.
- development, test, local, example, sample, template, and docs contexts degrade severity.
- ambiguous paths should use cautious wording and avoid production assumptions.
- findings should include `confidence` (`high`, `medium`, or `low`) where useful.

Recommendations should say "review", "confirm", "consider", or "validate manually"; they should not assert confirmed compromise.

## 7. Redaction And Safe Evidence

The module should reuse or adapt defensive redaction from `secrets_review_basic` and `node_package_config_basic`.

Never store or display full secret-like values. Redact:

- `TOKEN`, `PASSWORD`, `SECRET`, `API_KEY`, `PRIVATE_KEY`, `CLIENT_SECRET`, and related names;
- URLs with userinfo;
- sensitive query parameters such as `token`, `api_key`, `key`, `secret`, `password`, `code`, and `state`;
- cloud credential-looking names and inline values;
- npm, PyPI, Docker, cloud, and provider tokens;
- private key blocks if present in CI config text.

Safe evidence can include:

- workflow file path;
- provider type;
- job name;
- step name;
- action name;
- permission key;
- trigger name;
- environment name;
- script excerpt after redaction;
- image/action reference after redaction if no credentials are present.

Avoid prefixes, suffixes, fingerprints, or hashes of secret values in v1. Raw JSON, backend exports, frontend reports, and controlled errors should all apply defensive redaction.

## 8. YAML And Parsing Strategy

The first implementation should prefer simple, safe parsing over completeness:

- use a safe local YAML parser only if one is already available and configured for safe loads;
- otherwise use conservative line-oriented parsing with bounded text;
- parse JSON helper files locally when bounded and valid;
- do not evaluate `${{ ... }}`, GitLab variable interpolation, Azure expressions, Jenkins Groovy, or shell expansions;
- do not fetch or resolve remote `include`, `uses`, reusable workflow, template, or action references;
- detect references to remote includes/actions as references only;
- strip full-line comments before stronger findings;
- treat inline comments conservatively and avoid strong findings when evidence appears only in comments;
- record parse errors as controlled errors without stack traces or absolute paths.

Provider-specific syntax should be treated best-effort. Sparse or malformed files should still produce a controlled result.

## 9. Proposed JSON Result

The result should follow Inspectra's existing archive-based contract style:

```json
{
  "analyzer": "ci_cd_config_basic",
  "archive_type": "zip",
  "hashes": {
    "sha256": "..."
  },
  "summary": {
    "files_considered": 0,
    "files_reviewed": 0,
    "workflow_files_detected": 0,
    "jobs_detected": 0,
    "steps_detected": 0,
    "triggers_detected": 0,
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
  "workflows": [],
  "jobs": [],
  "triggers": [],
  "permissions": [],
  "actions": [],
  "service_containers": [],
  "publish_deploy_signals": [],
  "findings": [],
  "redaction_notes": [],
  "errors": [],
  "truncated": false
}
```

Candidate workflow records can include:

- `path`
- `provider`
- `context`
- `name`
- `jobs_count`
- `triggers`
- `read`
- `skip_reason`

Finding records should include:

- `id`
- `title`
- `level`
- `confidence`
- `category`
- `context`
- `provider`
- `file_path`
- `job`
- `step`
- `line`
- `description`
- `evidence`
- `recommendation`

## 10. Expected UX And Reporting

The future frontend report should make the review understandable without opening raw JSON:

- General Summary.
- Workflow overview.
- Triggers.
- Permissions.
- Jobs and steps overview.
- Actions/images pinning signals.
- Secrets/env signals.
- Publish/deploy signals.
- Findings grouped by severity, category, and context.
- Files reviewed/skipped.
- Redaction notes.
- Limits, truncation, and errors.
- Raw JSON at the end, always redacted.

Markdown and HTML exports should include confidence, category, context, provider, file path, job/step, line number when available, safe evidence, and recommendation. XML and PDF should tolerate queued/running/failed/sparse jobs through the generic reporting model. All formats should apply defensive redaction even if a legacy or malformed result contains raw token-like values.

## 11. Future Tests

Runner tests:

- GitHub workflow with `pull_request_target` produces `pull_request_target_used`.
- `permissions: write-all` produces `github_permissions_write_all`.
- missing GitHub permissions block produces `github_permissions_missing`.
- `uses: actions/checkout@main` produces `github_action_uses_branch_ref`.
- `uses: owner/action@v1` produces `github_action_unpinned_ref` or the final agreed review finding.
- `uses: owner/action@<full_sha>` avoids the unpinned finding.
- Docker image `node:latest` produces `docker_image_latest_tag`.
- inline `SECRET_KEY=fixture-secret` is redacted.
- script `curl ... | sh` produces `ci_curl_pipe_shell`.
- npm publish step produces `npm_publish_job_detected`.
- Docker push step produces `docker_push_job_detected`.
- cloud deploy command produces `cloud_deploy_job_detected`.
- self-hosted runner produces `self_hosted_runner_used`.
- dev/example workflow path degrades severity.
- full-line comments do not generate strong findings.
- path traversal, symlink, hardlink, and non-regular entries are not read.
- file count, per-file byte, total byte, and archive entry limits mark truncation predictably.
- serialized JSON result does not contain fixture secrets.

Backend/reporting tests:

- endpoint accepts only archive files and creates `ci_cd_config_basic` jobs;
- runner endpoint contract is `/analyze/ci-cd-config` or final agreed path;
- compact summaries tolerate sparse or missing result fields;
- Markdown/HTML/XML/PDF exports render workflow overview, findings, redaction notes, limits, and errors without leaking secrets;
- queued/running/failed/sparse jobs export without crashing.

Frontend tests:

- archive action appears only for archive files;
- report renders complete and sparse payloads;
- findings without file path, line, level, confidence, job, or step render safely;
- sensitive legacy payload values are redacted in visible report and raw JSON;
- empty states are clear.

## 12. Implementation Microphases

Suggested implementation path:

1. Runner/parser passive analysis plus redaction and tests.
   - add candidate detection, bounded reads, context classification, comment stripping, initial findings, redaction-first evidence, and serialization no-secret tests.
2. Backend job and reporting.
   - add audit type, `POST /audits/ci-cd-config/{file_id}` or final endpoint, archive-only validation, runner call, summaries, exports, and backend redaction tests.
3. Frontend report UX.
   - add archive action, API client call, CI/CD report helper/component, grouped findings, redacted raw JSON, and frontend tests.
4. End-to-end review.
   - align runner/backend/frontend contracts, sparse payloads, exports, wording, and redaction.
5. Docs/smoke closeout.
   - update runtime docs and create a closeout once v1 is fully implemented.

## 13. Future Documentation Updates

When `ci_cd_config_basic` is implemented, update:

- `README.md`
  - endpoint and UI usage;
  - supported archive source;
  - limits and variables;
  - passive/no-runner/no-provider/no-CVE scope;
  - redaction and local storage caveats.

- `docs/architecture.md`
  - archive-based flow;
  - runner parsing model;
  - result schema;
  - relationship to `secrets_review_basic`, `node_package_config_basic`, `docker_config_basic`, and archive safety helpers.

- `docs/security-scope.md`
  - allowed scope for passive CI/CD config review;
  - explicitly keep workflow execution, runner emulation, provider API calls, token validation, package installs, image downloads, advisory/CVE lookups, and exploitability claims out of scope;
  - document best-effort redaction and uploaded archive storage sensitivity.

- `docs/future/passive-package-config-audits-v2-closeout.md`
  - leave as historical closeout or create a v3 closeout after CI/CD v1 is implemented and reviewed end-to-end.

No runtime docs should claim that `ci_cd_config_basic` exists until the endpoint, runner, backend, reporting, and frontend are implemented.
