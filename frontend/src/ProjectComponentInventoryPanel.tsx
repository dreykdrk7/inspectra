import { useEffect, useMemo, useState } from "react";
import { Box, RefreshCw } from "lucide-react";

import { ApiError, api } from "./api";
import { analysisSourceReference } from "./sourcePresentation";
import { ProjectAnalysisAvailabilityNotice } from "./ProjectAnalysisAvailabilityNotice";
import { ProjectAnalysisHistoryStatus, mergeProjectAnalyses } from "./ProjectAnalysisHistoryStatus";
import type { JobListItem, ProjectComponent, ProjectComponentCoverage, ProjectComponentInventoryResponse, ProjectSummary } from "./types";

type LoadState = { loading: boolean; error: string | null };

const initialLoadState: LoadState = { loading: false, error: null };

export function ProjectComponentInventoryPanel({ project }: { project: ProjectSummary }) {
  const [analyses, setAnalyses] = useState<JobListItem[]>([]);
  const [result, setResult] = useState<ProjectComponentInventoryResponse | null>(null);
  const [selectedAnalysisId, setSelectedAnalysisId] = useState<string | null>(project.latest_job?.id ?? null);
  const [state, setState] = useState<LoadState>(initialLoadState);
  const [analysisTotalCount, setAnalysisTotalCount] = useState(0);
  const [analysisNextCursor, setAnalysisNextCursor] = useState<string | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState<"all" | "direct" | "transitive" | "optional">("all");

  const filteredComponents = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return (result?.components ?? []).filter((component) =>
      (scope === "all" || component.dependency_scope === scope)
      && (!needle || [component.name, component.ecosystem, component.dependency_group, component.declared_version ?? ""]
        .join(" ")
        .toLocaleLowerCase()
        .includes(needle))
    );
  }, [query, result?.components, scope]);

  useEffect(() => {
    let disposed = false;
    async function load() {
      setState({ loading: true, error: null });
      try {
        const history = await api.listProjectAnalysisPage(project.project.id);
        const nextAnalyses = history.items;
        const preferredId = nextAnalyses.find((analysis) => analysis.status === "completed")?.id ?? project.latest_job?.id;
        const nextResult = await api.getProjectComponentInventory(project.project.id, preferredId);
        if (disposed) {
          return;
        }
        setAnalyses(nextAnalyses);
        setAnalysisTotalCount(history.total_count);
        setAnalysisNextCursor(history.next_cursor);
        setHistoryError(null);
        setSelectedAnalysisId(nextResult.analysis?.id ?? preferredId ?? null);
        setResult(nextResult);
        setState(initialLoadState);
      } catch (error) {
        if (!disposed) {
          setState({ loading: false, error: inventoryErrorMessage(error) });
        }
      }
    }
    void load();
    return () => {
      disposed = true;
    };
  }, [project.latest_job?.id, project.project.id]);

  async function loadAnalysis(analysisId?: string) {
    setState({ loading: true, error: null });
    try {
      const nextResult = await api.getProjectComponentInventory(project.project.id, analysisId);
      setSelectedAnalysisId(nextResult.analysis?.id ?? analysisId ?? null);
      setResult(nextResult);
      setState(initialLoadState);
    } catch (error) {
      setState({ loading: false, error: inventoryErrorMessage(error) });
    }
  }

  async function refresh() {
    try {
      const history = await api.listProjectAnalysisPage(project.project.id);
      const retainedSelection = selectedAnalysisId && !history.items.some((analysis) => analysis.id === selectedAnalysisId)
        ? await api.getProjectAnalysisSummary(project.project.id, selectedAnalysisId)
        : null;
      const nextAnalyses = mergeProjectAnalyses(history.items, retainedSelection ? [retainedSelection] : []);
      setAnalyses(nextAnalyses);
      setAnalysisTotalCount(history.total_count);
      setAnalysisNextCursor(history.next_cursor);
      setHistoryError(null);
      await loadAnalysis(selectedAnalysisId ?? nextAnalyses.find((analysis) => analysis.status === "completed")?.id);
    } catch (error) {
      setState({ loading: false, error: inventoryErrorMessage(error) });
    }
  }

  async function loadOlderAnalyses() {
    if (!analysisNextCursor || historyLoading || state.loading) return;
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const history = await api.listProjectAnalysisPage(project.project.id, analysisNextCursor);
      setAnalyses((current) => mergeProjectAnalyses(current, history.items));
      setAnalysisTotalCount(history.total_count);
      setAnalysisNextCursor(history.next_cursor);
    } catch {
      setHistoryError("Unable to load older analyses. The loaded snapshots remain available; try again.");
    } finally {
      setHistoryLoading(false);
    }
  }

  return (
    <section className="panel project-components-panel" aria-label={`Component inventory for ${project.project.name}`}>
      <div className="panel-header">
        <div>
          <h2><Box size={18} aria-hidden="true" /> Component inventory</h2>
          <p className="muted">
            {result?.summary.resolution === "declared_and_lockfile"
              ? "Declared dependencies with supported lockfile resolutions. Inspectra has not installed packages or queried vulnerability sources."
              : "Declared dependencies only. Inspectra has not resolved packages or queried vulnerability sources."}
          </p>
        </div>
        <button className="secondary-button" onClick={() => void refresh()} disabled={state.loading}>
          <RefreshCw size={16} aria-hidden="true" />
          {state.loading ? "Loading" : "Refresh"}
        </button>
      </div>

      {state.error ? <p className="error-text" role="alert">{state.error}</p> : null}
      {state.loading && !result ? <p className="muted" role="status">Loading component inventory…</p> : null}

      {analyses.length > 0 ? (
        <label className="auth-field project-analysis-picker">
          <span>Analysis snapshot</span>
          <select
            value={selectedAnalysisId ?? ""}
            onChange={(event) => void loadAnalysis(event.target.value)}
            disabled={state.loading}
          >
            {analyses.map((analysis) => <option key={analysis.id} value={analysis.id}>{formatAnalysisOption(analysis)}</option>)}
          </select>
        </label>
      ) : null}

      <ProjectAnalysisHistoryStatus
        analyses={analyses}
        totalCount={analysisTotalCount}
        hasMore={Boolean(analysisNextCursor)}
        loading={historyLoading || state.loading}
        error={historyError}
        onLoadMore={() => void loadOlderAnalyses()}
      />

      {result?.state === "no_completed_analysis" ? <p className="empty-state">No completed project analysis is available for inventory yet.</p> : null}
      {result && (result.state === "analysis_pending" || result.state === "analysis_failed" || result.state === "analysis_cancelled") ? (
        <ProjectAnalysisAvailabilityNotice state={result.state} />
      ) : null}
      {result?.state === "no_component_inventory" ? (
        <p className="empty-state">This retained analysis predates the component inventory contract. Run the retained snapshot again to create one.</p>
      ) : null}

      {result?.state === "ready" ? (
        <>
          <div className="project-component-summary" aria-label="Component inventory coverage">
            <InventoryMetric label="Components" value={result.summary.total_components} />
            <InventoryMetric label="Exact declarations" value={result.summary.exact_registry_components} />
            <InventoryMetric label="Lockfile resolutions" value={result.summary.resolved_registry_components} />
            <InventoryMetric label="Local-only lockfile resolutions" value={result.summary.unverified_lockfile_components ?? 0} />
            <InventoryMetric label="Transitive resolutions" value={result.summary.transitive_registry_components ?? 0} />
            <InventoryMetric label="Relationships reported" value={result.summary.relationship_reported_components ?? result.summary.total_components} />
            <InventoryMetric label="Relationships unknown" value={result.summary.relationship_not_reported_components ?? 0} />
            <InventoryMetric label="Optional dependencies" value={result.summary.optional_registry_components ?? 0} />
            <InventoryMetric label="Matched lockfiles" value={result.summary.matched_lockfile_components ?? 0} />
            <InventoryMetric label="Ambiguous matches" value={result.summary.ambiguous_lockfile_components ?? 0} />
            <InventoryMetric label="Ranges" value={result.summary.declared_range_components} />
            <InventoryMetric label="Not correlatable" value={result.summary.not_correlatable_components} />
          </div>
          <p className="muted inventory-coverage" role="status">
            Parsed {result.summary.parsed_manifest_count} of {result.summary.supported_manifest_count} supported manifests. {result.summary.skipped_manifest_count > 0 ? `${result.summary.skipped_manifest_count} were skipped by a defensive limit or parser condition. ` : ""}
            {result.summary.parsed_lockfile_count > 0 ? `${result.summary.parsed_lockfile_count} supported lockfile${result.summary.parsed_lockfile_count === 1 ? " was" : "s were"} parsed for direct dependency resolution. ` : ""}
            {result.summary.skipped_lockfile_count > 0 ? `${result.summary.skipped_lockfile_count} lockfile${result.summary.skipped_lockfile_count === 1 ? " was" : "s were"} not used because of a defensive limit or unsupported format. ` : ""}
            {result.summary.lockfile_graph_truncated ? "A supported lockfile dependency graph reached a defensive node or edge limit, so transitive coverage is partial. " : ""}
            {(result.summary.relationship_not_reported_components ?? 0) > 0 ? `${result.summary.relationship_not_reported_components} SBOM component relationship${result.summary.relationship_not_reported_components === 1 ? " is" : "s are"} not reported; direct or transitive scope is unknown. ` : ""}
            {(result.summary.relationship_truncated_components ?? 0) > 0 ? `The SBOM relationship graph was truncated, so scope-dependent conclusions are inconclusive for ${result.summary.relationship_truncated_components} component${result.summary.relationship_truncated_components === 1 ? "" : "s"}. ` : ""}
            {(result.summary.ambiguous_lockfile_components ?? 0) > 0 ? `${result.summary.ambiguous_lockfile_components} component${result.summary.ambiguous_lockfile_components === 1 ? " has" : "s have"} an ambiguous lockfile association, so no lockfile version was used. ` : ""}
            {(result.summary.unmatched_lockfile_components ?? 0) > 0 ? `${result.summary.unmatched_lockfile_components} component${result.summary.unmatched_lockfile_components === 1 ? " has" : "s have"} no supported lockfile in the same project root. ` : ""}
            {result.summary.skipped_lockfile_reasons.length > 0 ? `Reason: ${result.summary.skipped_lockfile_reasons.map(humanize).join(", ")}. ` : ""}
            {result.summary.result_truncated ? "This inventory is partial because the project review reached a configured limit. " : ""}
            Only exact registry declarations or supported exact lockfile resolutions are eligible for a future advisory correlation.
          </p>
          {result.dependency_graph ? <GoGraphEvidence evidence={result.dependency_graph} /> : result.components.some((component) => component.ecosystem === "go") ? (
            <section className="inventory-graph-evidence" aria-label="Go dependency graph status">
              <h3>Go relationship evidence not provided</h3>
              <p className="muted">Direct declarations and exact local versions remain available, but transitive scope is not claimed. An authorized CI job can attach the closed, source-bound graph artifact without Inspectra executing Go.</p>
            </section>
          ) : null}
          {result.cargo_dependency_graph ? <CargoGraphEvidence evidence={result.cargo_dependency_graph} /> : result.components.some((component) => component.ecosystem === "cargo") ? (
            <section className="inventory-graph-evidence" aria-label="Cargo dependency graph status">
              <h3>Cargo relationship evidence not provided</h3>
              <p className="muted">Exact crates remain available from the supported lockfile, but dependency scope, enabled features and target coverage are not claimed. Authorized CI can attach the closed artifact without Inspectra executing Cargo.</p>
            </section>
          ) : null}
          {result.composer_dependency_graph ? <ComposerGraphEvidence evidence={result.composer_dependency_graph} /> : result.components.some((component) => component.ecosystem === "composer") ? (
            <section className="inventory-graph-evidence" aria-label="Composer dependency graph status">
              <h3>Composer relationship evidence not provided</h3>
              <p className="muted">Exact locked packages remain local evidence, but dependency scope is not claimed. Authorized CI can attach the closed graph without Inspectra executing Composer; this does not attest Packagist origin.</p>
            </section>
          ) : null}
          {result.gradle_dependency_graph ? <GradleGraphEvidence evidence={result.gradle_dependency_graph} /> : result.components.some((component) => component.ecosystem === "maven" && component.lockfile_type === "gradle_lock") ? (
            <section className="inventory-graph-evidence" aria-label="Gradle dependency graph status">
              <h3>Gradle relationship evidence not provided</h3>
              <p className="muted">Exact locked Maven coordinates remain local evidence, but dependency scope is unknown. Authorized CI can attach a closed source-bound graph without Inspectra executing Gradle; this does not attest Maven Central origin.</p>
            </section>
          ) : null}
          {result.nuget_dependency_graph ? <NugetGraphEvidence evidence={result.nuget_dependency_graph} /> : result.components.some((component) => component.ecosystem === "nuget" && component.lockfile_type === "nuget_packages_lock") ? (
            <section className="inventory-graph-evidence" aria-label="NuGet dependency graph status">
              <h3>NuGet relationship evidence not provided</h3>
              <p className="muted">Exact lockfile versions and any scope shared by every observed target remain local evidence. Authorized CI can attach a closed source-bound multi-target graph without Inspectra running restore or MSBuild; this does not attest NuGet.org origin.</p>
            </section>
          ) : null}
          {result.components.some((component) => component.source_type !== "registry") ? (
            <p className="muted inventory-coverage">
              Aliases, workspaces, VCS, URL, local and editable sources stay local-only. Inspectra shows their category but withholds their reference and never turns them into a public package lookup.
            </p>
          ) : null}
          {(result.coverage_matrix?.length ?? 0) > 0 ? <CoverageMatrix entries={result.coverage_matrix ?? []} /> : null}

          {result.components.length > 0 ? (
            <div className="project-component-filters">
              <label className="auth-field project-component-search">
                <span>Search components</span>
                <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Package, ecosystem, group, or declared version" />
              </label>
              <label className="auth-field project-component-scope">
                <span>Dependency scope</span>
                <select value={scope} onChange={(event) => setScope(event.target.value as typeof scope)}>
                  <option value="all">All captured scopes</option>
                  <option value="direct">Direct</option>
                  <option value="transitive">Transitive</option>
                  <option value="optional">Optional</option>
                </select>
              </label>
            </div>
          ) : null}

          {result.components.length === 0 ? <p className="empty-state">No supported dependency declarations were parsed within this analysis coverage.</p> : null}
          {result.components.length > 0 && filteredComponents.length === 0 ? <p className="empty-state">No components match this search. Clear or broaden it to review the captured inventory.</p> : null}
          {filteredComponents.length > 0 ? (
            <div className="project-component-table-wrap" tabIndex={0} aria-label="Captured project components">
              <table className="project-component-table">
                <thead><tr><th>Component</th><th>Declared / resolved version</th><th>Coverage</th><th>Source</th></tr></thead>
                <tbody>
                  {filteredComponents.map((component) => (
                    <tr key={component.id}>
                      <td>
                        <strong>{component.name}</strong>
                        <span>{component.ecosystem} · {componentScopeLabel(component)} · {component.manifest_path ?? (component.manifest_path_status === "withheld_unsafe_path" ? "manifest path withheld" : "manifest path unavailable")}</span>
                        {component.package_url ? <span className="subtle-id">Canonical package identity: {component.package_url}</span> : null}
                        {component.enabled_feature_count != null ? <span className="subtle-id">Cargo CI evidence: {component.enabled_feature_count} enabled feature{component.enabled_feature_count === 1 ? "" : "s"} · {component.target_variant_count ?? 0} target variant{component.target_variant_count === 1 ? "" : "s"}</span> : component.target_variant_count != null ? <span className="subtle-id">CI relationship evidence: present in {component.target_variant_count} opaque target variant{component.target_variant_count === 1 ? "" : "s"}</span> : null}
                        {component.build_scope_count != null ? <span className="subtle-id">Gradle CI evidence: present in {component.build_scope_count} covered build scope{component.build_scope_count === 1 ? "" : "s"}</span> : null}
                      </td>
                      <td>{component.resolution === "lockfile" ? `${component.declared_version ?? "No declaration retained"} → ${component.exact_version}` : component.exact_version ?? component.declared_version ?? "Not retained for this source"}</td>
                      <td>
                        <span className={`finding-badge ${component.correlation_eligible ? "high" : "info"}`}>{componentCoverageLabel(component)}</span>
                        {component.lockfile_match_status && component.lockfile_match_status !== "not_applicable" ? <span className="subtle-id">Lockfile association: {humanize(component.lockfile_match_status)}</span> : null}
                      </td>
                      <td>{component.lockfile_type === "go_sum" ? "Public origin requires an exact operator attestation" : component.lockfile_type === "cargo_lock" ? "Official crates.io source proven by the supported lockfile" : component.lockfile_type === "composer_lock" ? "Packagist origin requires an exact operator attestation" : component.lockfile_type === "gradle_lock" ? "Maven origin requires an exact operator attestation" : component.lockfile_type === "nuget_packages_lock" ? "NuGet.org origin requires an exact operator attestation" : component.lockfile_type === "pnpm_lock" || component.lockfile_type === "yarn_classic_lock" || component.lockfile_type === "poetry_lock" || component.lockfile_type === "pipfile_lock" ? "Registry origin unverified; never sent to public advisories" : component.source_type === "registry" ? "Registry" : `Not queried (${humanize(component.source_type)})`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

function InventoryMetric({ label, value }: { label: string; value: number }) {
  return <div className="project-finding-metric"><span>{label}</span><strong>{value}</strong></div>;
}

function GoGraphEvidence({ evidence }: { evidence: NonNullable<ProjectComponentInventoryResponse["dependency_graph"]> }) {
  const description = evidence.state === "accepted"
    ? "The complete CI graph matched the retained Go manifest and checksum inventory."
    : evidence.state === "truncated"
      ? "The CI producer declared a truncated graph; represented relationships are retained but scope-dependent conclusions remain partial."
      : "The graph did not agree with the retained source evidence. Inspectra retained only this aggregate receipt and did not use its relationships.";
  return (
    <section className={`inventory-graph-evidence ${evidence.state}`} aria-label="Go dependency graph evidence" aria-live="polite">
      <div className="section-title-row">
        <h3>Go dependency graph</h3>
        <span className={`finding-badge ${evidence.state === "accepted" ? "high" : evidence.state === "truncated" ? "medium" : "critical"}`}>{humanize(evidence.state)}</span>
      </div>
      <p className="muted">{description}</p>
      <dl className="compact-list">
        <dt>Source binding</dt><dd>Verified commit {evidence.source_commit_sha.slice(0, 12)}…</dd>
        <dt>Artifact</dt><dd><code>{evidence.artifact_sha256.slice(0, 12)}…</code> · contract {evidence.contract_version}</dd>
        <dt>Coverage</dt><dd>{evidence.components_matched}/{evidence.nodes_reported} nodes matched · {evidence.edges_reported} edges</dd>
        <dt>Cycles</dt><dd>{evidence.cycles_detected ? "Detected and handled without recursive execution" : "None detected"}</dd>
        {evidence.reason !== "none" ? <><dt>Status reason</dt><dd>{humanize(evidence.reason)}</dd></> : null}
      </dl>
    </section>
  );
}

function CargoGraphEvidence({ evidence }: { evidence: NonNullable<ProjectComponentInventoryResponse["cargo_dependency_graph"]> }) {
  const description = evidence.state === "accepted"
    ? "The complete CI projection matched one retained Cargo manifest and official-registry lock inventory."
    : evidence.state === "truncated"
      ? "The CI producer declared partial evidence; represented relationships remain explicit but scope-dependent conclusions are partial."
      : "The artifact diverged from retained source evidence. Inspectra kept only this aggregate receipt and ignored its relationships.";
  return (
    <section className={`inventory-graph-evidence ${evidence.state}`} aria-label="Cargo dependency graph evidence" aria-live="polite">
      <div className="section-title-row">
        <h3>Cargo dependency graph</h3>
        <span className={`finding-badge ${evidence.state === "accepted" ? "high" : evidence.state === "truncated" ? "medium" : "critical"}`}>{humanize(evidence.state)}</span>
      </div>
      <p className="muted">{description}</p>
      <dl className="compact-list">
        <dt>Source binding</dt><dd>Verified commit {evidence.source_commit_sha.slice(0, 12)}…</dd>
        <dt>Artifact</dt><dd><code>{evidence.artifact_sha256.slice(0, 12)}…</code> · contract {evidence.contract_version}</dd>
        <dt>Coverage</dt><dd>{evidence.components_matched}/{evidence.nodes_reported} nodes matched · {evidence.edges_reported} edges</dd>
        <dt>Dimensions</dt><dd>{evidence.features_reported} enabled feature records · {evidence.targets_reported} opaque target variants</dd>
        <dt>Cycles</dt><dd>{evidence.cycles_detected ? "Detected and handled iteratively" : "None detected"}</dd>
        {evidence.reason !== "none" ? <><dt>Status reason</dt><dd>{humanize(evidence.reason)}</dd></> : null}
      </dl>
    </section>
  );
}

function ComposerGraphEvidence({ evidence }: { evidence: NonNullable<ProjectComponentInventoryResponse["composer_dependency_graph"]> }) {
  const description = evidence.state === "accepted"
    ? "The complete CI projection matched one retained Composer manifest and lock inventory. Registry provenance remains unverified."
    : evidence.state === "truncated"
      ? "The CI producer declared partial evidence; represented relationships remain explicit but scope-dependent conclusions are partial."
      : "The artifact diverged from retained source evidence. Inspectra kept only this aggregate receipt and ignored its relationships.";
  return (
    <section className={`inventory-graph-evidence ${evidence.state}`} aria-label="Composer dependency graph evidence" aria-live="polite">
      <div className="section-title-row">
        <h3>Composer dependency graph</h3>
        <span className={`finding-badge ${evidence.state === "accepted" ? "high" : evidence.state === "truncated" ? "medium" : "critical"}`}>{humanize(evidence.state)}</span>
      </div>
      <p className="muted">{description}</p>
      <dl className="compact-list">
        <dt>Source binding</dt><dd>Verified commit {evidence.source_commit_sha.slice(0, 12)}…</dd>
        <dt>Artifact</dt><dd><code>{evidence.artifact_sha256.slice(0, 12)}…</code> · contract {evidence.contract_version}</dd>
        <dt>Coverage</dt><dd>{evidence.components_matched}/{evidence.nodes_reported} nodes matched · {evidence.edges_reported} edges</dd>
        <dt>Registry provenance</dt><dd>Not attested by relationship evidence</dd>
        <dt>Cycles</dt><dd>{evidence.cycles_detected ? "Detected and handled iteratively" : "None detected"}</dd>
        {evidence.reason !== "none" ? <><dt>Status reason</dt><dd>{humanize(evidence.reason)}</dd></> : null}
      </dl>
    </section>
  );
}

function GradleGraphEvidence({ evidence }: { evidence: NonNullable<ProjectComponentInventoryResponse["gradle_dependency_graph"]> }) {
  const description = evidence.state === "accepted"
    ? "The complete CI projection matched one retained Gradle build and lock inventory. Repository provenance remains unverified."
    : evidence.state === "truncated"
      ? "The CI producer declared partial scope evidence; represented relationships remain explicit but coverage-dependent conclusions are partial."
      : "The artifact diverged from retained lock evidence. Inspectra retained only this aggregate receipt and ignored its relationships.";
  return (
    <section className={`inventory-graph-evidence ${evidence.state}`} aria-label="Gradle dependency graph evidence" aria-live="polite">
      <div className="section-title-row">
        <h3>Gradle dependency graph</h3>
        <span className={`finding-badge ${evidence.state === "accepted" ? "high" : evidence.state === "truncated" ? "medium" : "critical"}`}>{humanize(evidence.state)}</span>
      </div>
      <p className="muted">{description}</p>
      <dl className="compact-list">
        <dt>Source binding</dt><dd>Verified commit {evidence.source_commit_sha.slice(0, 12)}…</dd>
        <dt>Artifact</dt><dd><code>{evidence.artifact_sha256.slice(0, 12)}…</code> · contract {evidence.contract_version}</dd>
        <dt>Coverage</dt><dd>{evidence.components_matched}/{evidence.nodes_reported} nodes matched · {evidence.edges_reported} edges</dd>
        <dt>Build scopes</dt><dd>{evidence.scope_coverage.map(humanize).join(", ")} · {evidence.scope_assignments_reported} node assignments</dd>
        <dt>Relationship origin</dt><dd>Reported by authorized CI; not inferred from the Gradle DSL</dd>
        <dt>Registry provenance</dt><dd>Not attested by relationship evidence</dd>
        <dt>Cycles</dt><dd>{evidence.cycles_detected ? "Detected and handled iteratively" : "None detected"}</dd>
        {evidence.reason !== "none" ? <><dt>Status reason</dt><dd>{humanize(evidence.reason)}</dd></> : null}
      </dl>
    </section>
  );
}

function NugetGraphEvidence({ evidence }: { evidence: NonNullable<ProjectComponentInventoryResponse["nuget_dependency_graph"]> }) {
  const description = evidence.state === "accepted"
    ? "The complete CI projection matched one retained .NET project and lock inventory across every declared opaque target variant. Registry provenance remains unverified."
    : evidence.state === "truncated"
      ? "The CI producer declared partial target evidence; represented relationships remain explicit but target-dependent conclusions are partial."
      : "The artifact diverged from retained lock evidence. Inspectra retained only this aggregate receipt and ignored its relationships.";
  return (
    <section className={`inventory-graph-evidence ${evidence.state}`} aria-label="NuGet dependency graph evidence" aria-live="polite">
      <div className="section-title-row">
        <h3>NuGet dependency graph</h3>
        <span className={`finding-badge ${evidence.state === "accepted" ? "high" : evidence.state === "truncated" ? "medium" : "critical"}`}>{humanize(evidence.state)}</span>
      </div>
      <p className="muted">{description}</p>
      <dl className="compact-list">
        <dt>Source binding</dt><dd>Verified commit {evidence.source_commit_sha.slice(0, 12)}…</dd>
        <dt>Artifact</dt><dd><code>{evidence.artifact_sha256.slice(0, 12)}…</code> · contract {evidence.contract_version}</dd>
        <dt>Coverage</dt><dd>{evidence.components_matched}/{evidence.nodes_reported} nodes matched · {evidence.edges_reported} edges</dd>
        <dt>Targets</dt><dd>{evidence.targets_reported} opaque variants · {evidence.target_assignments_reported} node assignments</dd>
        <dt>Relationship origin</dt><dd>Reported by authorized CI; not inferred from MSBuild or the lockfile</dd>
        <dt>Registry provenance</dt><dd>Not attested by relationship evidence</dd>
        <dt>Cycles</dt><dd>{evidence.cycles_detected ? "Detected and handled per target" : "None detected"}</dd>
        {evidence.reason !== "none" ? <><dt>Status reason</dt><dd>{humanize(evidence.reason)}</dd></> : null}
      </dl>
    </section>
  );
}

function componentScopeLabel(component: ProjectComponent): string {
  if (component.relationship_status === "truncated") return "scope inconclusive; relationship graph truncated";
  if (component.relationship_status === "not_reported") return "scope unknown; relationship not reported";
  if (component.dependency_scope === "transitive") return "transitive dependency";
  if (component.dependency_scope === "optional") return "optional dependency";
  return component.dependency_group;
}

function componentCoverageLabel(component: ProjectComponent): string {
  if (!component.exact_version && component.version_status === "not_correlatable") return "No correlatable exact version";
  if (component.relationship_status === "truncated") return "Exact version; scope inconclusive";
  if (component.relationship_status === "not_reported") return "Exact version; scope unknown";
  if (component.dependency_scope === "transitive") return "Exact transitive resolution";
  if (component.dependency_scope === "optional") return "Optional dependency";
  if (component.lockfile_type === "pnpm_lock") return "Exact local pnpm resolution";
  if (component.lockfile_type === "yarn_classic_lock") return "Exact local Yarn Classic resolution";
  if (component.lockfile_type === "poetry_lock") return "Exact local Poetry resolution";
  if (component.lockfile_type === "pipfile_lock") return "Exact local Pipenv resolution";
  if (component.lockfile_type === "go_sum") return "Exact local Go module resolution";
  if (component.lockfile_type === "cargo_lock") return "Exact Cargo.lock resolution";
  if (component.lockfile_type === "composer_lock") return "Exact local Composer resolution";
  if (component.lockfile_type === "gradle_lock") return "Exact local Gradle lock resolution";
  if (component.lockfile_type === "nuget_packages_lock") return component.relationship_status === "reported" ? "Exact local NuGet lock resolution" : "Exact NuGet version; scope unknown";
  if (component.resolution === "lockfile") return "Exact lockfile resolution";
  return component.correlation_eligible ? "Exact declaration" : humanize(component.version_status);
}

function CoverageMatrix({ entries }: { entries: ProjectComponentCoverage[] }) {
  return (
    <section className="component-coverage-matrix" aria-labelledby="component-coverage-title">
      <h3 id="component-coverage-title">Package manager coverage</h3>
      <p className="muted inventory-coverage">
        This is the retained analysis coverage, not a package-manager detection claim. “Detected, not parsed” means Inspectra saw a known file but did not derive dependency versions from it.
      </p>
      <div className="project-component-table-wrap" tabIndex={0} aria-label="Package manager and lockfile coverage matrix">
        <table className="project-component-table">
          <thead><tr><th>Workflow</th><th>Observed in this analysis</th><th>Current coverage</th><th>Next safe action</th></tr></thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={entry.id}>
                <td>
                  <strong>{entry.manager}</strong>
                  <span>{entry.ecosystem} · manifest {entry.manifest} · lockfile {entry.lockfile === "not_applicable" ? "not applicable" : entry.lockfile}</span>
                  <span className="subtle-id">Parser: {humanize(entry.parser_version)} · contract {entry.coverage_contract_version}</span>
                </td>
                <td>
                  <span className={`finding-badge ${entry.manifest_status === "parsed" || entry.lockfile_status === "parsed" ? "high" : "info"}`}>
                    Manifest: {coverageStatus(entry.manifest_status)}
                  </span>
                  {entry.lockfile_status !== "not_applicable" ? <span className="subtle-id">Lockfile: {coverageStatus(entry.lockfile_status)}</span> : null}
                </td>
                <td>
                  <span>Direct: {humanize(entry.direct_coverage)}</span>
                  <span className="subtle-id">Transitive: {humanize(entry.transitive_coverage)}</span>
                </td>
                <td>{coverageNextAction(entry.exclusion_reason)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function coverageStatus(value: ProjectComponentCoverage["manifest_status"] | ProjectComponentCoverage["lockfile_status"]) {
  if (value === "parsed") return "Parsed";
  if (value === "detected_not_parsed") return "Detected, not parsed";
  if (value === "not_applicable") return "Not applicable";
  return "Not detected";
}

function coverageNextAction(reason: ProjectComponentCoverage["exclusion_reason"]) {
  const actions: Record<ProjectComponentCoverage["exclusion_reason"], string> = {
    none: "Review the matched resolution and its stated scope.",
    not_detected: "Add the intended manifest or lockfile to a future authorized snapshot if applicable.",
    no_lockfile_contract: "Use the declared dependency view; exact lockfile resolution is not available for this workflow yet.",
    unsupported_lockfile_parser: "Use the declared dependency view; this lockfile format is visible but not parsed yet.",
    defensive_limit_or_invalid_input: "Review the retained coverage limits or lockfile syntax before relying on versions.",
    no_same_root_match: "Keep the declaration local until a single same-root supported lockfile is available.",
    ambiguous_root_pair: "Resolve workspace or multiple-lockfile ambiguity before relying on a lockfile version.",
    graph_truncated: "Direct resolution is retained; treat transitive coverage as partial because a defensive graph limit was reached.",
    graph_divergent: "Regenerate the graph from this exact commit and snapshot; Inspectra did not use divergent relationships.",
    relationship_evidence_not_provided: "Generate the closed Go graph artifact in authorized CI and attach it to this exact analysis if transitive scope is needed.",
  };
  return actions[reason];
}

function formatAnalysisOption(analysis: JobListItem) {
  return `${analysis.status} · ${analysisSourceReference(analysis)} · ${new Date(analysis.created_at).toLocaleString()}`;
}

function humanize(value: string) {
  return value.replace(/[_-]/g, " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function inventoryErrorMessage(error: unknown) {
  if (error instanceof ApiError) {
    return error.status === 404 ? "This project analysis is no longer available." : error.message;
  }
  return "Unable to load the component inventory. Refresh the page and try again.";
}
