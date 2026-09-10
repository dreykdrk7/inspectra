import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProductAuditPanel } from "./ProductAuditPanel";


function event(id: string, action: string) {
  return {
    contract_version: "2026-09-06.1",
    id,
    organization_id: "local-admin",
    actor_id: "team-admin",
    actor_role: "administrator",
    action,
    resource_type: "project",
    resource_id: "a".repeat(32),
    result: "succeeded",
    correlation_id: `request:${"b".repeat(32)}`,
    occurred_at: "2026-09-06T12:00:00Z",
    metadata: { report_format: "markdown" },
  };
}

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

function integrity(state: 'valid' | 'empty' | 'invalid' = 'valid') {
  return {
    contract_version: '2026-09-10.1', state, checked_at: '2026-09-10T12:00:00Z', bootstrap_performed: false,
    generation: state === 'invalid' ? null : 1, retained_events: state === 'valid' ? 3 : state === 'empty' ? 0 : null,
    anchor_sequence: state === 'invalid' ? null : 0, head_sequence: state === 'valid' ? 3 : state === 'empty' ? 0 : null,
    head_digest: state === 'invalid' ? null : 'a'.repeat(64), failure_reason: state === 'invalid' ? 'integrity_check_failed' : null,
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("ProductAuditPanel", () => {
  it("presents minimal activity, filters exact actions and loads older pages", async () => {
    const snapshotDigest = 'f'.repeat(64);
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith('/audit/integrity')) return Promise.resolve(response(integrity()));
      if (url.pathname.endsWith('/audit/export') && init?.method === 'POST') {
        return Promise.resolve(new Response('{"events":[]}\n', { status: 200, headers: { 'content-type': 'application/json', 'x-inspectra-snapshot-sha256': snapshotDigest } }));
      }
      if (url.pathname.endsWith('/audit/export/preflight')) {
        return Promise.resolve(response({
          contract_version: '2026-09-10.1', state: 'ready', period: '30d',
          starts_at: '2026-08-11T12:00:00Z', state_at: '2026-09-10T12:00:00Z', expires_at: '2026-09-10T12:05:00Z',
          action_filter: 'auth.login', total_events: 1, included_events: 1, truncated: false,
          snapshot_digest: snapshotDigest, max_events: 1000, max_bytes: 1048576, retention_days: 90,
          available_formats: ['json', 'csv'],
          privacy: { organization_identifier_included: false, original_actor_identifier_included: false, original_resource_identifier_included: false, correlation_identifier_included: false, metadata_included: false, names_paths_targets_included: false, source_or_evidence_included: false },
        }));
      }
      if (url.pathname.endsWith('/active/assets/search')) {
        return Promise.resolve(response({ contract_version: '2026-09-08.1', items: [{ id: 'a'.repeat(32), canonical_value: 'example.test' }], returned_count: 1, page_size: 100, has_more: false, next_cursor: null }));
      }
      if (url.pathname.endsWith('/audit/active-export/preflight')) {
        return Promise.resolve(response({
          contract_version: '2026-09-08.1', state: 'ready', period: '30d',
          starts_at: '2026-08-07T12:00:00Z', ends_at: '2026-09-06T12:00:00Z', asset_filter_applied: true,
          total_events: 3, included_events: 3, truncated: false, max_events: 1000, retention_days: 90,
          available_formats: ['json', 'csv'],
          privacy: { target_included: false, authorization_reference_included: false, notes_included: false, client_ip_included: false, correlation_id_included: false, raw_metadata_included: false, raw_evidence_included: false },
        }));
      }
      if (url.searchParams.get("action") === "project.report_exported") {
        return Promise.resolve(response({ items: [event("c".repeat(32), "project.report_exported")], next_cursor: null, retention_days: 90 }));
      }
      if (url.searchParams.get("cursor")) {
        return Promise.resolve(response({ items: [event("d".repeat(32), "project.created")], next_cursor: null, retention_days: 90 }));
      }
      return Promise.resolve(response({ items: [event("e".repeat(32), "auth.login")], next_cursor: "e".repeat(32), retention_days: 90 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn(() => 'blob:product-audit') });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);

    const view = render(<ProductAuditPanel />);
    expect(await screen.findByText("Auth Login")).toBeInTheDocument();
    expect(screen.getByText("Retained 90 days")).toBeInTheDocument();
    expect(screen.getByText(/report format markdown/)).toBeInTheDocument();
    expect(await screen.findByText(/Valid chain across 3 retained events/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Exact action (optional)'), { target: { value: 'auth.login' } });
    fireEvent.click(screen.getByRole('button', { name: 'Prepare redacted export' }));
    expect(await screen.findByText('Redacted snapshot ready')).toBeInTheDocument();
    expect(screen.getByText(/Organization identifiers, correlations, metadata, names, paths, targets, source and evidence are excluded/i)).toBeInTheDocument();
    const productDownload = screen.getByRole('button', { name: 'Download JSON' });
    expect(productDownload).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I confirm this bounded, redacted audit snapshot/i));
    fireEvent.click(productDownload);
    expect(await screen.findByText(/JSON audit exported from snapshot ffffffffffff/)).toBeInTheDocument();
    const productExportCall = fetchMock.mock.calls.find(([input, init]) => new URL(String(input)).pathname.endsWith('/audit/export') && init?.method === 'POST');
    expect(JSON.parse(String(productExportCall?.[1]?.body))).toEqual({
      period: '30d', export_format: 'json', action_filter: 'auth.login', state_at: '2026-09-10T12:00:00Z',
      snapshot_digest: snapshotDigest, redacted_export_confirmed: true,
    });

    fireEvent.change(screen.getByLabelText('Active asset'), { target: { value: 'a'.repeat(32) } });
    fireEvent.click(screen.getByRole('button', { name: 'Review export scope' }));
    expect(await screen.findByText('Export ready')).toBeInTheDocument();
    expect(screen.getByText('3 / 1000')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Download JSON' })).toHaveAttribute('href', expect.stringContaining(`asset_id=${'a'.repeat(32)}`));
    expect(screen.getByRole('link', { name: 'Download CSV' })).toHaveAttribute('href', expect.stringContaining('format=csv'));
    expect(screen.getByText(/pseudonymize actors and resources and omit targets/)).toBeInTheDocument();
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);

    fireEvent.click(screen.getByRole("button", { name: "Load older activity" }));
    expect(await screen.findByText("Project Created")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Exact action"), { target: { value: "project.report_exported" } });
    fireEvent.click(screen.getByRole("button", { name: "Filter" }));
    await waitFor(() => expect(screen.queryByText("Auth Login")).not.toBeInTheDocument());
    expect(screen.getByText("Project Report Exported")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("action=project.report_exported"), expect.any(Object));
  });

  it("has actionable error and empty states without accessibility violations", async () => {
    let failing = true;
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith('/audit/integrity')) return Promise.resolve(response(integrity()));
      if (path.endsWith('/active/assets/search')) return Promise.resolve(response({ contract_version: '2026-09-08.1', items: [], returned_count: 0, page_size: 100, has_more: false, next_cursor: null }));
      if (failing) return Promise.resolve(response({ detail: "Product audit history is unavailable." }, 503));
      return Promise.resolve(response({ items: [], next_cursor: null, retention_days: 90 }));
    }));

    render(<ProductAuditPanel />);
    expect(await screen.findByRole("alert")).toHaveTextContent("temporarily unavailable");
    failing = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("No product activity yet")).toBeInTheDocument();
    expect((await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("does not offer an empty Active audit download and invalidates stale preflight on scope change", async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith('/audit/integrity')) return Promise.resolve(response(integrity('empty')));
      if (url.pathname.endsWith('/active/assets/search')) return Promise.resolve(response({ contract_version: '2026-09-08.1', items: [], returned_count: 0, page_size: 100, has_more: false, next_cursor: null }));
      if (url.pathname.endsWith('/audit/export/preflight')) return Promise.resolve(response({
        contract_version: '2026-09-10.1', state: 'no_matches', period: '30d', starts_at: '2026-08-07T12:00:00Z',
        state_at: '2026-09-06T12:00:00Z', expires_at: '2026-09-06T12:05:00Z', action_filter: null,
        total_events: 0, included_events: 0, truncated: false, snapshot_digest: 'f'.repeat(64), max_events: 1000,
        max_bytes: 1048576, retention_days: 90, available_formats: ['json', 'csv'],
        privacy: { organization_identifier_included: false, original_actor_identifier_included: false, original_resource_identifier_included: false, correlation_identifier_included: false, metadata_included: false, names_paths_targets_included: false, source_or_evidence_included: false },
      }));
      if (url.pathname.endsWith('/audit/active-export/preflight')) return Promise.resolve(response({
        contract_version: '2026-09-08.1', state: 'no_matches', period: url.searchParams.get('period'),
        starts_at: '2026-08-07T12:00:00Z', ends_at: '2026-09-06T12:00:00Z', asset_filter_applied: false,
        total_events: 0, included_events: 0, truncated: false, max_events: 1000, retention_days: 90,
        available_formats: ['json', 'csv'],
        privacy: { target_included: false, authorization_reference_included: false, notes_included: false, client_ip_included: false, correlation_id_included: false, raw_metadata_included: false, raw_evidence_included: false },
      }));
      return Promise.resolve(response({ items: [], next_cursor: null, retention_days: 90 }));
    }));

    render(<ProductAuditPanel />);
    await screen.findByText('No product activity yet');
    fireEvent.click(screen.getByRole('button', { name: 'Prepare redacted export' }));
    expect(await screen.findByText('No matching product activity')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Download JSON' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Review export scope' }));
    expect(await screen.findByText('No matching Active activity')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Download JSON' })).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Audit period'), { target: { value: '7d' } });
    expect(screen.queryByText('No matching Active activity')).not.toBeInTheDocument();
  });
});
