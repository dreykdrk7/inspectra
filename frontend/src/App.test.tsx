import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" }
  });
}

describe("App", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(
            jsonResponse([
              {
                id: "file-pdf-1",
                kind: "pdf",
                original_filename: "sample.pdf",
                stored_filename: "file-pdf-1.pdf",
                content_type: "application/pdf",
                size_bytes: 100,
                sha256: "abc1234567890abc",
                created_at: "2026-05-26T10:00:00Z"
              }
            ])
          );
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(
            jsonResponse([
              {
                id: "job-pdf-1",
                audit_type: "pdf_basic",
                file_id: "file-pdf-1",
                status: "completed",
                created_at: "2026-05-26T10:01:00Z",
                updated_at: "2026-05-26T10:02:00Z",
                source_file_deleted_at: null,
                summary: { qpdf_ok: true, warnings: [], timed_out_tools: [] }
              }
            ])
          );
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the main dashboard sections with mocked API data", async () => {
    render(<App />);

    expect(screen.getByRole("heading", { name: "Inspectra" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Backend" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Upload File" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Files" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Jobs" })).toBeInTheDocument();

    expect(await screen.findByText("inspectra-backend")).toBeInTheDocument();
    expect(screen.getByText("sample.pdf")).toBeInTheDocument();
    expect(screen.getAllByText("pdf_basic").length).toBeGreaterThan(0);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledTimes(3);
    });
  });
});
