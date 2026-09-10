import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RetentionPolicyPanel } from "./RetentionPolicyPanel";


function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

function policy(manualCleanupAllowed = true) {
  return {
    contract_version: "2026-09-10.6",
    cleanup_scope: "active_organization_plus_shared_public_cache",
    cleanup_runs_at_startup: true,
    manual_cleanup_allowed: manualCleanupAllowed,
    application_encryption_at_rest: "operator_managed",
    backups: "offline_bundle_operator_encrypted_not_automatically_purged",
    data_classification_complete: true,
    backup_contract_version: "2026-09-06.1",
    source_metadata_contract_version: "2026-09-09.2",
    source_metadata: [
      {
        key: "original_filename",
        label: "Original source filename",
        retained_in: ["source_upload", "project_record"],
        sensitivity: "private_source_label",
        project_view_disclosure: "withheld",
        report_disclosure: "withheld",
        integration_disclosure: "withheld",
        retention_relation: "follows_each_parent_record",
        description: "Available only in authorized file management.",
      },
      {
        key: "content_sha256",
        label: "Source content SHA-256",
        retained_in: ["source_upload", "project_record", "analysis_record"],
        sensitivity: "correlatable_content_digest",
        project_view_disclosure: "withheld",
        report_disclosure: "withheld",
        integration_disclosure: "withheld",
        retention_relation: "follows_each_parent_record",
        description: "Retained server-side for reproducibility.",
      },
      {
        key: "source_file_id",
        label: "Internal source identifier",
        retained_in: ["source_upload", "project_record", "analysis_record"],
        sensitivity: "opaque_internal_identifier",
        project_view_disclosure: "opaque_internal_only",
        report_disclosure: "withheld",
        integration_disclosure: "withheld",
        retention_relation: "follows_each_parent_record",
        description: "Used only for authorized API actions.",
      },
      {
        key: "source_reference",
        label: "Safe source reference",
        retained_in: ["derived_projection"],
        sensitivity: "safe_presentation_reference",
        project_view_disclosure: "shown",
        report_disclosure: "shown",
        integration_disclosure: "shown",
        retention_relation: "derived_not_stored",
        description: "Short reference used in project screens and reports.",
      },
      {
        key: "source_channel",
        label: "Attested source admission channel",
        retained_in: ["project_record"],
        sensitivity: "non_sensitive_provenance_enum",
        project_view_disclosure: "shown",
        report_disclosure: "shown",
        integration_disclosure: "shown",
        retention_relation: "follows_each_parent_record",
        description: "Server-derived closed provenance enum.",
      },
    ],
    classes: [
      {
        key: "source_uploads",
        label: "Uploaded source archives",
        category: "project_data",
        scope: "organization",
        storage: "durable_upload_store",
        sensitivity: "project_content",
        retention_mode: "bounded",
        retention_days: 30,
        freshness_seconds: null,
        retention_seconds: null,
        automatic_cleanup: true,
        manual_cleanup: true,
        follows_class: null,
        deletion_triggers: ["retention_expiry", "explicit_source_deletion"],
        backup_disposition: "included_sensitive",
        restore_behavior: "restored",
        description: "Expired source bytes are removed unless an active analysis still needs them.",
      },
      {
        key: "public_advisory_cache",
        label: "Public advisory response cache",
        category: "public_intelligence",
        scope: "shared_public_data",
        storage: "durable_public_cache",
        sensitivity: "public_provider_data",
        retention_mode: "bounded",
        retention_days: null,
        freshness_seconds: 86400,
        retention_seconds: 604800,
        automatic_cleanup: true,
        manual_cleanup: true,
        follows_class: null,
        deletion_triggers: ["retention_expiry"],
        backup_disposition: "included_regenerable",
        restore_behavior: "regenerated",
        description: "Provider responses use a one-way digest and a bounded cache window.",
      },
      {
        key: "report_exports",
        label: "Generated reports",
        category: "project_data",
        scope: "request",
        storage: "request_only",
        sensitivity: "project_security_metadata",
        retention_mode: "not_persisted",
        retention_days: null,
        freshness_seconds: null,
        retention_seconds: null,
        automatic_cleanup: false,
        manual_cleanup: false,
        follows_class: null,
        deletion_triggers: ["not_applicable"],
        backup_disposition: "not_server_persisted",
        restore_behavior: "not_applicable",
        description: "Reports are rendered on demand and are not retained as server-side artifacts.",
      },
      {
        key: "remediation_plan_artifacts",
        label: "Durable remediation plan artifacts",
        category: "project_data",
        scope: "organization",
        storage: "durable_remediation_plan_store",
        sensitivity: "project_security_metadata",
        retention_mode: "bounded",
        retention_days: 7,
        freshness_seconds: null,
        retention_seconds: null,
        automatic_cleanup: true,
        manual_cleanup: false,
        follows_class: null,
        deletion_triggers: ["retention_expiry", "startup_recovery"],
        backup_disposition: "included_sensitive",
        restore_behavior: "restored",
        description: "Owner-scoped remediation snapshots expire after seven days.",
      },
      {
        key: "team_invitations",
        label: "Team invitation records",
        category: "identity_and_operations",
        scope: "organization",
        storage: "durable_auth_state",
        sensitivity: "credential_derived",
        retention_mode: "bounded",
        retention_days: 30,
        freshness_seconds: null,
        retention_seconds: null,
        automatic_cleanup: true,
        manual_cleanup: true,
        follows_class: null,
        deletion_triggers: ["retention_expiry", "operator_restore"],
        backup_disposition: "included_sensitive",
        restore_behavior: "discarded",
        description: "Terminal invitation records expire after thirty days.",
      },
      {
        key: "automation_credentials",
        label: "Automation credential metadata",
        category: "identity_and_operations",
        scope: "organization",
        storage: "durable_auth_state",
        sensitivity: "credential_derived",
        retention_mode: "bounded",
        retention_days: 30,
        freshness_seconds: null,
        retention_seconds: null,
        automatic_cleanup: true,
        manual_cleanup: true,
        follows_class: null,
        deletion_triggers: ["retention_expiry"],
        backup_disposition: "included_sensitive",
        restore_behavior: "restored_sessions_revoked",
        description: "Inactive credential metadata expires independently from product audit.",
      },
    ],
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("RetentionPolicyPanel", () => {
  it("shows configured lifecycle values and completes an organization-scoped cleanup", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.pathname === "/privacy/retention/run") {
        expect(init?.method).toBe("POST");
        return Promise.resolve(response({
          contract_version: "2026-09-10.1",
          state: "completed",
          scope: "active_organization_plus_shared_public_cache",
          ran_at: "2026-09-06T12:00:00Z",
          results: [
            { key: "source_uploads", status: "completed", removed_items: 2, detail: "Expired sources were evaluated." },
            { key: "analysis_results", status: "completed", removed_items: 1, detail: "Expired results were evaluated." },
            { key: "public_advisory_cache", status: "completed", removed_items: 3, detail: "Expired cache entries were evaluated." },
            { key: "automation_credentials", status: "completed", removed_items: 1, detail: "Expired credentials were evaluated." },
            { key: "team_invitations", status: "completed", removed_items: 1, detail: "Expired invitations were evaluated." },
            { key: "product_audit", status: "completed", removed_items: 0, detail: "Expired activity was evaluated." },
          ],
        }));
      }
      return Promise.resolve(response(policy()));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<RetentionPolicyPanel />);
    expect(await screen.findByText("Uploaded source archives")).toBeInTheDocument();
    expect(screen.getAllByText("30 days")).toHaveLength(3);
    expect(screen.getByText("7 days maximum")).toBeInTheDocument();
    expect(screen.getByText(/Fresh for 1 day/)).toBeInTheDocument();
    expect(screen.getByText("Not stored")).toBeInTheDocument();
    expect(screen.getByText("6 classes classified")).toBeInTheDocument();
    expect(screen.getByText("Team invitation records")).toBeInTheDocument();
    expect(screen.getByText("Automation credential metadata")).toBeInTheDocument();
    expect(screen.getByText("Source metadata presentation")).toBeInTheDocument();
    expect(screen.getByText("Safe source reference")).toBeInTheDocument();
    expect(screen.getAllByText("Withheld").length).toBeGreaterThan(1);
    expect(screen.getByText(/deleting a source does not delete retained results/i)).toBeInTheDocument();
    fireEvent.click(screen.getAllByText("Storage, backup and deletion")[0]);
    expect(screen.getByText("Project content")).toBeInTheDocument();
    expect(screen.getAllByText("Included; sensitive").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Run due cleanup" })).toBeDisabled();

    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Run due cleanup" }));
    expect(await screen.findByText("Cleanup completed")).toBeInTheDocument();
    expect(screen.getByText(/Removed 2/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect((await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("keeps policy visible without exposing cleanup controls to a non-administrator", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response(policy(false)))));
    render(<RetentionPolicyPanel />);

    expect(await screen.findByText("Uploaded source archives")).toBeInTheDocument();
    expect(screen.getByText(/Only a workspace administrator/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run due cleanup" })).not.toBeInTheDocument();
  });

  it("fails closed without blanking the application when source metadata rules are missing", async () => {
    const legacyPolicy = policy();
    delete (legacyPolicy as { source_metadata?: unknown }).source_metadata;
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response(legacyPolicy))));

    render(<RetentionPolicyPanel />);

    expect(await screen.findByText("Uploaded source archives")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("older or incomplete policy contract");
    expect(screen.getByRole("alert")).toHaveTextContent("Source metadata remains withheld");
    expect(screen.queryByText("Safe source reference")).not.toBeInTheDocument();
    expect((await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("renders actionable load and partial-maintenance errors", async () => {
    let call = 0;
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      call += 1;
      if (call === 1) return Promise.resolve(response({ detail: "unavailable" }, 503));
      if (new URL(String(input)).pathname === "/privacy/retention/run") {
        return Promise.resolve(response({
          contract_version: "2026-09-10.1",
          state: "partial",
          scope: "active_organization_plus_shared_public_cache",
          ran_at: "2026-09-06T12:00:00Z",
          results: [
            { key: "source_uploads", status: "failed", removed_items: null, detail: "This data class could not be cleaned. Review storage health and retry." },
            { key: "analysis_results", status: "completed", removed_items: 0, detail: "Expired results were evaluated." },
            { key: "public_advisory_cache", status: "completed", removed_items: 0, detail: "Expired cache entries were evaluated." },
            { key: "automation_credentials", status: "completed", removed_items: 0, detail: "Expired credentials were evaluated." },
            { key: "team_invitations", status: "completed", removed_items: 0, detail: "Expired invitations were evaluated." },
            { key: "product_audit", status: "completed", removed_items: 0, detail: "Expired activity was evaluated." },
          ],
        }));
      }
      return Promise.resolve(response(policy()));
    }));

    render(<RetentionPolicyPanel />);
    expect(await screen.findByRole("alert")).toHaveTextContent("temporarily unavailable");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("Uploaded source archives")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Run due cleanup" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Cleanup needs attention"));
  });
});
