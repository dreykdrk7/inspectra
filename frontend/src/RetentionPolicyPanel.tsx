import { ChangeEvent, useCallback, useEffect, useState } from "react";

import { ApiError, api } from "./api";
import type { RetentionCleanupResponse, RetentionPolicyClass, RetentionPolicyResponse, SourceMetadataPolicy } from "./types";


type LoadState = { loading: boolean; error: string | null };
const idle: LoadState = { loading: false, error: null };
const policyCategories: Array<{ key: RetentionPolicyClass["category"]; label: string; description: string }> = [
  { key: "project_data", label: "Project data", description: "Sources, results, inventory, reports and decisions." },
  { key: "public_intelligence", label: "Public intelligence", description: "Normalized project evidence and shared provider cache." },
  { key: "identity_and_operations", label: "Identity and operations", description: "Execution recovery, audit and credential-derived state." },
  { key: "external_copies", label: "External copies", description: "Artifacts whose lifecycle remains with the operator." },
];

export function RetentionPolicyPanel() {
  const [policy, setPolicy] = useState<RetentionPolicyResponse | null>(null);
  const [loadState, setLoadState] = useState<LoadState>({ loading: true, error: null });
  const [cleanupState, setCleanupState] = useState<LoadState>(idle);
  const [cleanup, setCleanup] = useState<RetentionCleanupResponse | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const sourceMetadata = Array.isArray(policy?.source_metadata) ? policy.source_metadata : [];

  const load = useCallback(async () => {
    setLoadState({ loading: true, error: null });
    try {
      setPolicy(await api.getRetentionPolicy());
      setLoadState(idle);
    } catch (error) {
      setLoadState({ loading: false, error: messageFor(error, "policy") });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function runCleanup() {
    if (!confirmed) return;
    setCleanup(null);
    setCleanupState({ loading: true, error: null });
    try {
      setCleanup(await api.runRetentionCleanup());
      setConfirmed(false);
      setCleanupState(idle);
    } catch (error) {
      setCleanupState({ loading: false, error: messageFor(error, "cleanup") });
    }
  }

  return (
    <section className="card retention-policy-card" aria-labelledby="retention-policy-title">
      <div className="section-heading-row">
        <div>
          <p className="eyebrow">Privacy controls</p>
          <h2 id="retention-policy-title">Data lifecycle</h2>
          <p className="muted">
            See how this deployment keeps and removes source data, results, public intelligence and activity records.
            No project names, package identities, paths or stored contents are shown here.
          </p>
        </div>
        {policy ? (
          <div className="retention-policy-statuses" aria-label="Lifecycle policy status">
            <span className="status-pill ok">{policy.classes.length} classes classified</span>
            {policy.cleanup_runs_at_startup ? <span className="status-pill ok">Startup cleanup active</span> : null}
          </div>
        ) : null}
      </div>

      {loadState.loading ? <p className="muted" role="status">Loading data policy…</p> : null}
      {loadState.error ? (
        <div className="alert" role="alert">
          {loadState.error} <button className="inline-button" onClick={() => void load()}>Retry</button>
        </div>
      ) : null}

      {policy ? (
        <>
          <div className="retention-policy-notice" role="note">
            <strong>Operator-managed protection</strong>
            <span>
              Inspectra does not provide application-level disk encryption or purge backup copies. Use encrypted
              storage and the offline backup contract {policy.backup_contract_version} with a lifecycle appropriate
              for the data you analyze.
            </span>
          </div>

          <p className="retention-independence-note">
            Lifecycle actions are class-specific: deleting a source does not delete retained results, deleting a
            project does not automatically delete its source upload, and application cleanup never purges backups.
          </p>

          <section className="retention-policy-group" aria-labelledby="source-metadata-policy-title">
            <div>
              <h3 id="source-metadata-policy-title">Source metadata presentation</h3>
              <p className="muted">
                Project screens and exports use a short safe reference. Original filenames and content hashes remain
                restricted to their documented storage purpose.
              </p>
            </div>
            {sourceMetadata.length > 0 ? (
              <div className="retention-policy-grid">
                {sourceMetadata.map((item) => <SourceMetadataRule key={item.key} item={item} />)}
              </div>
            ) : (
              <div className="alert" role="alert">
                Source presentation rules are unavailable because the API returned an older or incomplete policy
                contract. Source metadata remains withheld here; restart the API and interface on matching versions.
              </div>
            )}
          </section>

          <div className="retention-policy-groups">
            {policyCategories.map((category) => {
              const items = policy.classes.filter((item) => item.category === category.key);
              return (
                <section key={category.key} className="retention-policy-group" aria-labelledby={`retention-group-${category.key}`}>
                  <div>
                    <h3 id={`retention-group-${category.key}`}>{category.label}</h3>
                    <p className="muted">{category.description}</p>
                  </div>
                  <div className="retention-policy-grid">
                    {items.map((item) => <PolicyClass key={item.key} item={item} />)}
                  </div>
                </section>
              );
            })}
          </div>

          {policy.manual_cleanup_allowed ? (
            <div className="retention-cleanup-actions">
              <div>
                <h3>Run due cleanup now</h3>
                <p className="muted">
                  Owned data is limited to the active organization; expired shared public-provider cache entries are
                  also removed. Active analysis inputs, downloaded files and operator-managed backups remain outside this action.
                </p>
              </div>
              <label className="confirmation-row">
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(event: ChangeEvent<HTMLInputElement>) => setConfirmed(event.target.checked)}
                />
                I understand that expired source files and terminal results cannot be restored by Inspectra.
              </label>
              <button type="button" disabled={!confirmed || cleanupState.loading} onClick={() => void runCleanup()}>
                {cleanupState.loading ? "Cleaning due data…" : "Run due cleanup"}
              </button>
            </div>
          ) : (
            <p className="muted retention-read-only">Only a workspace administrator can run cleanup. This policy remains visible to all members.</p>
          )}

          {cleanupState.error ? <div className="alert" role="alert">{cleanupState.error}</div> : null}
          {cleanup ? <CleanupResult result={cleanup} /> : null}
        </>
      ) : null}
    </section>
  );
}

function SourceMetadataRule({ item }: { item: SourceMetadataPolicy }) {
  const shared = item.report_disclosure === "shown";
  return (
    <article className="retention-policy-item">
      <div className="retention-policy-item-heading">
        <h4>{item.label}</h4>
        <span className={`status-pill ${shared ? "ok" : ""}`}>{shared ? "Safe to share" : "Withheld"}</span>
      </div>
      <p>{item.description}</p>
      <dl className="summary-list">
        <div><dt>Project view</dt><dd>{disclosureLabel(item.project_view_disclosure)}</dd></div>
        <div><dt>Reports</dt><dd>{disclosureLabel(item.report_disclosure)}</dd></div>
      </dl>
    </article>
  );
}

function disclosureLabel(value: SourceMetadataPolicy["project_view_disclosure"] | SourceMetadataPolicy["report_disclosure"]): string {
  if (value === "shown") return "Shown";
  if (value === "opaque_internal_only") return "API actions only";
  return "Withheld";
}

function PolicyClass({ item }: { item: RetentionPolicyClass }) {
  return (
    <article className="retention-policy-item">
      <div className="retention-policy-item-heading">
        <h4>{item.label}</h4>
        <span className={`status-pill ${item.retention_mode === "bounded" || item.retention_mode === "ephemeral" ? "ok" : ""}`}>
          {retentionLabel(item)}
        </span>
      </div>
      <p>{item.description}</p>
      <p className="muted retention-policy-meta">
        {scopeLabel(item.scope)}
        {item.freshness_seconds !== null ? ` · Fresh for ${formatDuration(item.freshness_seconds)}` : ""}
        {` · ${item.automatic_cleanup ? "Automatic cleanup" : "No automatic cleanup"}`}
      </p>
      <details className="retention-policy-details">
        <summary>Storage, backup and deletion</summary>
        <dl>
          <div><dt>Stored as</dt><dd>{storageLabel(item.storage)}</dd></div>
          <div><dt>Sensitivity</dt><dd>{sensitivityLabel(item.sensitivity)}</dd></div>
          <div><dt>Backup</dt><dd>{backupLabel(item.backup_disposition)}</dd></div>
          <div><dt>Restore</dt><dd>{restoreLabel(item.restore_behavior)}</dd></div>
          <div><dt>Removed by</dt><dd>{item.deletion_triggers.map(deletionLabel).join("; ")}</dd></div>
        </dl>
      </details>
    </article>
  );
}

function CleanupResult({ result }: { result: RetentionCleanupResponse }) {
  const heading = result.state === "completed" ? "Cleanup completed" : result.state === "partial" ? "Cleanup needs attention" : "Cleanup failed";
  return (
    <div className={result.state === "completed" ? "retention-cleanup-result success" : "alert"} role={result.state === "completed" ? "status" : "alert"}>
      <strong>{heading}</strong>
      <span>Checked {new Date(result.ran_at).toLocaleString()}. Each class can be retried safely.</span>
      <ul>
        {result.results.map((item) => (
          <li key={item.key}>
            <strong>{cleanupLabel(item.key)}:</strong> {item.detail}
            {item.removed_items !== null ? ` Removed ${item.removed_items}.` : ""}
          </li>
        ))}
      </ul>
    </div>
  );
}

function retentionLabel(item: RetentionPolicyClass): string {
  if (item.retention_mode === "not_persisted") return "Not stored";
  if (item.retention_mode === "ephemeral") return "Execution only";
  if (item.retention_mode === "follows_parent") return item.follows_class === "analysis_results" ? "Follows result" : item.follows_class === "active_asset_metadata" ? "Follows Active asset" : "Follows project";
  if (item.retention_mode === "external_policy") return "External policy";
  if (item.retention_days !== null && item.retention_days > 0) return `${item.retention_days} days`;
  if (item.retention_seconds !== null) return `${formatDuration(item.retention_seconds)} maximum`;
  return "Until deleted";
}

function formatDuration(seconds: number): string {
  if (seconds % 86400 === 0) {
    const days = seconds / 86400;
    return `${days} ${days === 1 ? "day" : "days"}`;
  }
  if (seconds % 3600 === 0) {
    const hours = seconds / 3600;
    return `${hours} ${hours === 1 ? "hour" : "hours"}`;
  }
  return `${seconds} seconds`;
}

function scopeLabel(scope: RetentionPolicyClass["scope"]): string {
  if (scope === "organization") return "Active organization";
  if (scope === "shared_public_data") return "Shared public provider data";
  if (scope === "execution") return "Isolated execution";
  if (scope === "deployment") return "This deployment";
  if (scope === "operator_external") return "Outside Inspectra";
  return "Current request";
}

function storageLabel(storage: RetentionPolicyClass["storage"]): string {
  const labels: Record<RetentionPolicyClass["storage"], string> = {
    durable_upload_store: "Durable upload store",
    durable_analysis_store: "Durable analysis result",
    embedded_in_analysis_result: "Inside the analysis result",
    durable_public_intelligence_store: "Normalized intelligence snapshot",
    durable_public_cache: "Shared provider cache",
    request_only: "Response/download only",
    durable_remediation_plan_store: "Durable remediation plan store",
    durable_project_store: "Project metadata store",
    durable_finding_decision_store: "Finding decision history",
    durable_project_action_store: "Passive project action state",
    durable_active_asset_store: "Active asset aggregate",
    durable_active_verification_store: "Active verification store",
    durable_active_change_approval_store: "Active change approval store",
    durable_active_weekly_review_receipt_store: "Active weekly review receipt store",
    ephemeral_workspace: "Temporary isolated workspace",
    recoverable_operation_journal: "Temporary recovery journal",
    durable_product_audit_store: "Product activity store",
    durable_auth_state: "SQLite authentication state",
    operator_external: "Operator-managed storage",
  };
  return labels[storage];
}

function sensitivityLabel(sensitivity: RetentionPolicyClass["sensitivity"]): string {
  const labels: Record<RetentionPolicyClass["sensitivity"], string> = {
    project_content: "Project content",
    project_security_metadata: "Project security metadata",
    public_provider_data: "Public provider data",
    credential_derived: "Credential-derived material",
    operational_metadata: "Operational metadata",
  };
  return labels[sensitivity];
}

function backupLabel(disposition: RetentionPolicyClass["backup_disposition"]): string {
  const labels: Record<RetentionPolicyClass["backup_disposition"], string> = {
    included_sensitive: "Included; sensitive",
    included_regenerable: "Included; can be regenerated",
    excluded_ephemeral: "Excluded as ephemeral",
    not_server_persisted: "Not persisted by the server",
    operator_managed: "Managed outside Inspectra",
  };
  return labels[disposition];
}

function restoreLabel(behavior: RetentionPolicyClass["restore_behavior"]): string {
  const labels: Record<RetentionPolicyClass["restore_behavior"], string> = {
    restored: "Restored from backup",
    restored_sessions_revoked: "Restored; sessions and invitations revoked",
    regenerated: "May be regenerated",
    discarded: "Not restored",
    not_applicable: "Not applicable",
    operator_managed: "Operator managed",
  };
  return labels[behavior];
}

function deletionLabel(trigger: RetentionPolicyClass["deletion_triggers"][number]): string {
  const labels: Record<RetentionPolicyClass["deletion_triggers"][number], string> = {
    retention_expiry: "retention expiry",
    explicit_source_deletion: "explicit source deletion",
    explicit_analysis_deletion: "analysis deletion",
    explicit_project_deletion: "project deletion",
    explicit_active_asset_deletion: "Active asset deletion",
    execution_completion: "execution completion",
    startup_recovery: "startup recovery",
    session_expiry_or_revocation: "expiry or revocation",
    membership_revocation: "membership revocation",
    operator_restore: "offline restore",
    operator_external_policy: "external operator policy",
    not_applicable: "not applicable",
  };
  return labels[trigger];
}

function cleanupLabel(key: RetentionCleanupResponse["results"][number]["key"]): string {
  if (key === "source_uploads") return "Source uploads";
  if (key === "analysis_results") return "Analysis results";
  if (key === "public_advisory_cache") return "Public advisory cache";
  if (key === "automation_credentials") return "Automation credentials";
  if (key === "team_invitations") return "Team invitations";
  return "Product activity";
}

function messageFor(error: unknown, kind: "policy" | "cleanup"): string {
  if (error instanceof ApiError && error.status === 403) return "Only a workspace administrator can run cleanup.";
  if (error instanceof ApiError && error.status === 503) return "Storage maintenance is temporarily unavailable. Check deployment health and retry.";
  if (error instanceof Error && error.message) return error.message;
  return kind === "policy" ? "The data lifecycle policy could not be loaded." : "Cleanup could not be started.";
}
