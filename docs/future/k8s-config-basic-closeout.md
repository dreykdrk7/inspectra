# k8s_config_basic Closeout

Status: `k8s_config_basic` is implemented and stable as a v1 passive archive-based audit module.

This closeout records the runtime scope, smoke checks, and residual risks for Kubernetes config audits. The original docs-first design remains in `docs/future/k8s-config-basic-design.md`.

## Commit Series

- `5523d89 docs(k8s): design passive kubernetes config audit`
- `02a4ff0 feat(k8s): add passive config runner analysis`
- `16668ee feat(k8s): add config backend job`
- `a093453 feat(k8s): add config report frontend ux`
- `a026b7d fix(k8s): align config contract and redaction`

## Implemented Surfaces

- Runner endpoint: `POST /analyze/k8s-config`.
- Backend endpoint: `POST /audits/k8s-config/{file_id}`.
- Audit type: `k8s_config_basic`.
- Source files: uploaded files registered as `kind: "archive"`.
- Frontend action: `Analyze Kubernetes config`, shown only for archive files.
- Reporting/export: Markdown, HTML, XML, and PDF sections for Kubernetes summary data, resources, workloads, services/ingress, RBAC, Helm/Kustomize signals, findings, limits, redaction notes, errors, and raw JSON where the UI exposes it.

## Capabilities

`k8s_config_basic` passively reviews bounded Kubernetes-related text from uploaded archives. It detects Kubernetes manifests, Helm context files, and Kustomize context files, then returns heuristic review indicators for:

- Kubernetes resources, workloads, and containers.
- Pod/container posture such as privileged containers, host namespaces, hostPath, Docker socket mounts, probes, resources, and image tag/digest signals.
- Services and Ingress exposure signals.
- RBAC wildcard rules.
- Secret and config references, including Kubernetes Secret `data`/`stringData`, secret-like ConfigMap keys, and secret-like environment values.
- Helm templates detected but not rendered.
- Kustomize files detected but not built.

Findings are review indicators for human triage. They are not confirmed vulnerabilities, exploitability claims, or proof of compromised workloads.

## Explicit Scope

- Archive-only, local, bounded, and passive.
- Reads only candidate Kubernetes/Helm/Kustomize text within configured limits.
- Detects real `.env`, `.env.*`, and `.envrc` files as sensitive entries where applicable, without reading their content.
- Records controlled errors and truncation instead of broad extraction or best-effort execution.
- Applies defensive redaction in runner results, backend storage, API responses, exports, frontend reports, and frontend raw JSON.

## Explicit Non-Scope

- No `kubectl`.
- No cluster access.
- No Kubernetes API server validation.
- No manifest apply or dry-run against a cluster.
- No admission-controller, OPA, Kyverno, Conftest, or policy-engine execution.
- No Helm rendering.
- No Kustomize build.
- No remote base, chart, CRD, or include resolution.
- No image pull or registry lookup.
- No CVE or advisory lookup.
- No network reachability testing.
- No runtime posture validation.
- No exploitability, compromise, or confirmed-vulnerability claims.

## Redaction Guarantees

The module treats secret exposure defensively and best-effort:

- Kubernetes Secret `data` and `stringData` values are not rendered as raw values.
- Secret-like environment and ConfigMap values are redacted.
- Credential-bearing URLs, sensitive query parameters, tokens, passwords, API keys, client secrets, and private key blocks are redacted.
- Evidence may show safe context such as kind, resource name, namespace, container name, field path, or key name with `[REDACTED]`.
- The implementation does not intentionally emit prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers.

Uploaded archive bytes may still contain secrets and are stored locally; redaction protects Inspectra results and reports, not the original uploaded archive.

## Smoke Checklist

Recommended manual smoke before opening the next module:

1. Upload a small `.zip` or `.tar.gz` archive containing Kubernetes manifests.
2. Confirm the file is registered as `kind: "archive"`.
3. Confirm `Analyze Kubernetes config` appears for the archive file.
4. Launch the analysis from the UI or call `POST /audits/k8s-config/{file_id}`.
5. Confirm the job appears as `k8s_config_basic` and transitions through queued/running to completed or a controlled failed state.
6. Open the frontend report and confirm summary, resources, workloads/containers, services/ingress, RBAC, secrets/config references, Helm/Kustomize signals, findings, limits/errors, redaction notes, and raw JSON render clearly.
7. Export the job as Markdown, HTML, XML, and PDF.
8. Confirm raw Kubernetes Secret values, env/config secret-like values, credential-bearing URLs, and private key material do not appear in UI, raw JSON, API responses, exports, or controlled errors.
9. Upload a non-archive file and confirm the Kubernetes action is not shown or is rejected by the backend according to the standard archive-only pattern.
10. Confirm the smoke does not run `kubectl`, render Helm, build Kustomize, pull images, query registries, query CVEs/advisories, or call external services.

## Reference Validations

The closeout series used focused runner, backend, frontend, build, and redaction checks, including:

```bash
.venv/bin/python -m pytest tools/tests/test_runner.py -k k8s_config
.venv/bin/python -m pytest backend/tests/test_backend.py -k k8s_config
.venv/bin/python -m pytest backend/tests/test_backend.py
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
npm run test -- --run K8sConfigJobReport reportHelpers App dashboardFilters
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

- YAML-like heuristics can produce false positives and false negatives.
- Helm templates are detected but not rendered, so generated resources may not be visible.
- Kustomize overlays are detected but not built.
- CRDs are not deeply validated against schemas.
- There is no cluster, admission-controller, policy, runtime, or network context.
- Images are not checked against registries, digests, vulnerabilities, advisories, or runtime state.
- Severity is based on static signals and path context, not real deployment exposure.
- Redaction is best-effort and may miss uncommon secret formats.

## Product Decision

`k8s_config_basic` v1 is ready to close. It fits the Inspectra passive module pattern: docs-first scope, bounded runner analysis, backend job/reporting, frontend report UX, and end-to-end contract/redaction review.

Recommended next docs-first module: `terraform_config_basic`.

Rationale: Terraform and related IaC files often define the cloud and Kubernetes resources that downstream modules observe. A passive, archive-only Terraform config review can extend the same bounded-read and redaction model without contacting providers, applying plans, validating cloud state, or claiming exploitability.
