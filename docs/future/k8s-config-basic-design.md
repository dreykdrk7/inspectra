# k8s_config_basic Design

Status: proposed docs-first design. No runtime endpoint, runner analyzer, backend job, frontend UI, or exports are implemented by this document.

## 1. Module Objective

`k8s_config_basic` is a future passive archive audit for Kubernetes manifests. It should help users review workload, service, RBAC, image, secret-handling, and deployment posture signals before manifests reach a cluster.

The module is intended to detect review indicators such as privileged containers, broad service exposure, plaintext secret material, missing resource controls, permissive RBAC, unpinned images, and Helm/Kustomize files that require manual context. It should not prove exploitability, validate runtime state, or claim that a workload is compromised.

This is useful for Inspectra because Kubernetes deployment posture often sits downstream of Docker, CI/CD, package configuration, and secret handling. A bounded, local, archive-only review gives defenders early signal without requiring cluster credentials or external services.

## 2. Allowed Scope

The module should only analyze archives uploaded by the user and registered as `kind: archive`.

Allowed behavior:

- Bounded reads of candidate Kubernetes manifest files inside the uploaded archive.
- Textual and YAML-oriented heuristic analysis.
- Safe local parsing only if a safe parser is already available in the runtime.
- Best-effort multi-document YAML handling.
- Detection of Helm and Kustomize inputs as context without rendering or building them.
- Redaction-first handling of secret-like values in evidence and raw result data.

Disallowed behavior in v1:

- No `kubectl`.
- No cluster access.
- No API server validation.
- No manifest apply, dry-run against a cluster, or admission simulation.
- No Helm rendering by default.
- No Kustomize build.
- No remote base, chart, CRD, or include resolution.
- No image download.
- No registry, CVE, or advisory lookups.

## 3. Candidate Files

Kubernetes manifests:

- `*.yaml`
- `*.yml`
- `*.k8s.yaml`
- `*.k8s.yml`
- `k8s/**/*.yaml`
- `k8s/**/*.yml`
- `kubernetes/**/*.yaml`
- `kubernetes/**/*.yml`
- `manifests/**/*.yaml`
- `manifests/**/*.yml`
- `deploy/**/*.yaml`
- `deploy/**/*.yml`

Common resource filenames:

- `deployment.yaml`
- `deployment.yml`
- `service.yaml`
- `service.yml`
- `ingress.yaml`
- `ingress.yml`
- `secret.yaml`
- `secret.yml`
- `configmap.yaml`
- `configmap.yml`
- `cronjob.yaml`
- `job.yaml`
- `daemonset.yaml`
- `statefulset.yaml`
- `role.yaml`
- `rolebinding.yaml`
- `clusterrole.yaml`
- `clusterrolebinding.yaml`
- `serviceaccount.yaml`

Helm and Kustomize context files:

- `Chart.yaml`
- `values.yaml`
- `values*.yaml`
- `templates/*.yaml`
- `kustomization.yaml`
- `kustomization.yml`

Helm templates should be detected as templates/context and not rendered. Kustomize files should be detected as configuration/context and not built. CRDs may be detected as Kubernetes resources, but v1 should not attempt deep schema validation.

## 4. Out of Scope

`k8s_config_basic` v1 must not perform:

- `kubectl` execution.
- Cluster connection.
- Admission controller simulation.
- Policy engine execution such as OPA, Kyverno, or Conftest.
- Helm rendering.
- Kustomize build.
- CRD schema validation.
- Image pull or registry lookup.
- CVE or advisory lookup.
- Runtime posture validation.
- Network reachability testing.
- Exploitability determination.
- Claims that a workload is exploitable, compromised, or confirmed vulnerable.

Findings must remain heuristic review indicators.

## 5. Initial Finding Model

Secrets and config:

- `k8s_secret_plaintext_data`
- `k8s_secret_stringdata_present`
- `k8s_configmap_secret_like_key`
- `env_secret_like_value`
- `env_from_secret_reference`
- `image_pull_secret_present`
- `service_account_token_automount_default`

Pod and container security:

- `privileged_container`
- `allow_privilege_escalation_true`
- `run_as_root_or_missing`
- `run_as_non_root_missing`
- `read_only_root_filesystem_missing`
- `capabilities_added`
- `host_network_enabled`
- `host_pid_enabled`
- `host_ipc_enabled`
- `host_path_volume_present`
- `docker_socket_mount`
- `seccomp_profile_missing`
- `apparmor_profile_missing`

Images:

- `image_latest_tag`
- `image_unpinned_tag`
- `image_missing_digest`
- `image_pull_policy_always`
- `private_registry_image_hint`

Resources:

- `resource_limits_missing`
- `resource_requests_missing`
- `cpu_limit_missing`
- `memory_limit_missing`

Services and ingress exposure:

- `service_type_loadbalancer`
- `service_type_nodeport`
- `ingress_host_wildcard`
- `ingress_tls_missing`
- `ingress_all_hosts_hint`

RBAC:

- `clusterrole_wildcard_verbs`
- `clusterrole_wildcard_resources`
- `cluster_admin_binding_hint`
- `rolebinding_to_default_serviceaccount`
- `serviceaccount_with_broad_binding_hint`

Workload and reliability:

- `replicas_singleton_hint`
- `liveness_probe_missing`
- `readiness_probe_missing`
- `cronjob_concurrency_policy_missing`
- `namespace_missing_or_default`

Helm and Kustomize:

- `helm_template_detected_not_rendered`
- `kustomize_detected_not_built`
- `values_secret_like_key`

## 6. Severity and Confidence

Default severity should be conservative and context-aware.

Medium indicators:

- Privileged containers.
- Host namespace usage.
- Docker socket mounts.
- Broad `hostPath` mounts.
- Plaintext Secret `data` or `stringData` values.
- Wildcard ClusterRole rules or cluster-admin-like bindings.
- `LoadBalancer` or `NodePort` services in production/deploy context.

Low indicators:

- Missing `runAsNonRoot`, `readOnlyRootFilesystem`, or seccomp settings.
- `latest` or otherwise unpinned images.
- Missing resources or probes.
- Default service account token automount behavior.
- Ingress without TLS.

Info indicators:

- `imagePullSecrets` present.
- `envFrom` secret references.
- Helm or Kustomize files detected but not rendered/built.
- Private registry image hints.

Path context should affect severity:

- `production`, `deploy`, and release-like paths preserve the default severity.
- `development`, `test`, `local`, `example`, `sample`, `template`, and `docs` contexts degrade severity.
- Ambiguous or shared contexts should keep cautious defaults.

Findings should include confidence when useful, but must not claim exploitability.

## 7. Redaction and Safe Evidence

The module must reuse the defensive redaction posture established by `secrets_review_basic`, `docker_config_basic`, and `ci_cd_config_basic`.

Never show plaintext secret values in findings, evidence, errors, raw JSON, or exports. Redact:

- Kubernetes Secret `data` and `stringData` values.
- Environment values with secret-like names.
- ConfigMap values with secret-like names.
- Registry URLs with credentials.
- Tokens, passwords, API keys, private keys, and client secrets.
- Private key blocks.

Safe evidence may include:

- Kubernetes `kind`.
- `metadata.name`.
- `metadata.namespace`.
- Container name.
- Field path.
- Key name.
- A fixed `[REDACTED]` placeholder.

Do not add prefixes, suffixes, fingerprints, hashes, or reversible identifiers for secret values in v1.

## 8. YAML and Parsing Strategy

The implementation should prefer a safe local YAML parser only if one is already available and appropriate for the runtime. If no safe parser is available, line-oriented and document-split heuristics are acceptable for v1.

Parsing rules:

- Support multi-document YAML best-effort.
- Ignore full-line comments for strong findings.
- Record parse failures as controlled errors.
- Do not render Helm templates.
- Do not build Kustomize overlays.
- Do not resolve `envFrom`, `secretKeyRef`, or `configMapKeyRef` values.
- Do not evaluate template expressions.
- Do not validate manifests against a cluster schema.

When parsing confidence is low, findings should be lower severity or marked for review.

## 9. Proposed JSON Result

The result should follow the passive audit conventions used by existing Inspectra modules:

```json
{
  "analyzer": "k8s_config_basic",
  "archive_type": "zip",
  "summary": {
    "files_considered": 0,
    "files_reviewed": 0,
    "manifest_files_detected": 0,
    "resources_detected": 0,
    "workloads_detected": 0,
    "services_detected": 0,
    "secrets_detected": 0,
    "rbac_resources_detected": 0,
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
  "resources": [],
  "workloads": [],
  "containers": [],
  "services": [],
  "ingress": [],
  "rbac": [],
  "secrets": [],
  "helm_kustomize_signals": [],
  "findings": [],
  "redaction_notes": [],
  "errors": [],
  "truncated": false
}
```

Finding objects should support:

- `id` or `code`
- `title`
- `level`
- `confidence`
- `category`
- `context`
- `file_path`
- `line`
- `kind`
- `resource_name`
- `namespace`
- `container`
- `field_path`
- `description`
- `evidence`
- `recommendation`

Fields may be absent for sparse or legacy payloads, and backend/frontend/reporting should tolerate that.

## 10. Expected UX and Reporting

The future UI and exports should present `k8s_config_basic` as a review-oriented posture report, not a vulnerability scanner.

Recommended sections:

- Summary.
- Resource overview.
- Workloads and containers.
- Services and ingress.
- Secrets and config references.
- RBAC.
- Helm and Kustomize signals.
- Findings grouped by severity, category, and context.
- Files reviewed and skipped.
- Redaction notes.
- Limits, truncation, and errors.
- Secondary raw JSON with defensive redaction.

Reports should highlight that Helm templates are not rendered, Kustomize overlays are not built, cluster state is not queried, and findings require human review.

## 11. Future Tests

Runner tests:

- Secret `stringData.password` generates `k8s_secret_stringdata_present` with redacted evidence.
- ConfigMap with `API_KEY` generates `k8s_configmap_secret_like_key` with redacted evidence.
- Pod or Deployment with `privileged: true` generates `privileged_container`.
- `allowPrivilegeEscalation: true` generates `allow_privilege_escalation_true`.
- `hostNetwork: true` generates `host_network_enabled`.
- `hostPath` mount for `/var/run/docker.sock` generates `docker_socket_mount`.
- Image `nginx:latest` generates `image_latest_tag`.
- Image without digest generates `image_missing_digest` or `image_unpinned_tag`, depending on final policy.
- Container without resources generates `resource_limits_missing` and/or `resource_requests_missing`.
- Service `type: LoadBalancer` generates `service_type_loadbalancer`.
- Ingress without TLS generates `ingress_tls_missing`.
- ClusterRole with wildcard verbs/resources generates wildcard RBAC findings.
- Missing namespace or `default` namespace generates `namespace_missing_or_default`.
- Helm template files generate `helm_template_detected_not_rendered`.
- Kustomize files generate `kustomize_detected_not_built`.
- Comments do not generate strong findings.
- Path traversal, absolute paths, symlinks, hardlinks, and non-regular archive entries are not read.
- File count, per-file byte, and total byte limits set truncation flags.
- Serialized JSON does not contain fixture secrets.

Backend/reporting tests:

- Endpoint accepts only archive files.
- Runner call targets `/analyze/k8s-config`.
- Summary tolerates sparse payloads.
- Markdown/HTML/XML/PDF exports redact legacy payloads containing raw secrets.
- Findings without file path, namespace, container, field path, confidence, or level render safely.

Frontend tests:

- Archive action appears only for archives.
- Report renders summary, resources, workloads, services, ingress, RBAC, Helm/Kustomize signals, and findings.
- Sparse, queued, running, failed, and malformed payloads do not break rendering.
- Raw JSON is available and defensively redacted.

## 12. Implementation Microphases

1. Runner/parser passive analysis plus redaction and tests.
2. Backend endpoint, job execution, storage summary, reporting, and tests.
3. Frontend action and report UX with defensive redaction tests.
4. End-to-end contract and redaction review.
5. Docs/smoke closeout for passive Kubernetes config audits.

Each phase should remain bounded, passive, and archive-only.

## 13. Future Documentation Updates

When runtime support is implemented, update:

- `README.md` with the new endpoint, UI action, limits, and passive scope.
- `docs/architecture.md` with the backend-to-runner flow and result sections.
- `docs/security-scope.md` with allowed Kubernetes config review scope and explicit out-of-scope cluster/runtime behavior.
- `docs/future/passive-ci-cd-config-audits-v3-closeout.md` or a new v4 closeout document to record the module as implemented.

Documentation must continue to state that Inspectra does not run `kubectl`, contact clusters, render Helm/Kustomize by default, query registries/CVEs, or confirm exploitability.
