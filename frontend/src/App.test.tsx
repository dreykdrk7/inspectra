import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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
              },
              {
                id: "file-manifest-1",
                kind: "manifest",
                original_filename: "package.json",
                stored_filename: "file-manifest-1-package.json",
                content_type: "application/json",
                size_bytes: 200,
                sha256: "def1234567890def",
                created_at: "2026-05-26T10:03:00Z"
              },
              {
                id: "file-archive-1",
                kind: "archive",
                original_filename: "django.zip",
                stored_filename: "file-archive-1.zip",
                content_type: "application/zip",
                size_bytes: 300,
                sha256: "fed1234567890fed",
                created_at: "2026-05-26T10:06:00Z"
              }
            ])
          );
        }
        if (url.endsWith("/jobs/job-pdf-1")) {
          return Promise.resolve(
            jsonResponse({
              id: "job-pdf-1",
              audit_type: "pdf_basic",
              file_id: "file-pdf-1",
              target_url: null,
              target_domain: null,
              status: "completed",
              created_at: "2026-05-26T10:01:00Z",
              updated_at: "2026-05-26T10:02:00Z",
              source_file_deleted_at: null,
              result: { analyzer: "pdf_basic", hashes: { sha256: "abc" }, validation: { qpdf_ok: true } },
              error: null
            })
          );
        }
        if (url.endsWith("/jobs/job-manifest-1")) {
          return Promise.resolve(
            jsonResponse({
              id: "job-manifest-1",
              audit_type: "manifest_basic",
              file_id: "file-manifest-1",
              target_url: null,
              target_domain: null,
              status: "completed",
              created_at: "2026-05-26T10:04:00Z",
              updated_at: "2026-05-26T10:05:00Z",
              source_file_deleted_at: null,
              result: {
                analyzer: "manifest_basic",
                manifest_type: "package_json",
                hashes: { sha256: "def" },
                parsed: {
                  project: { name: "demo" },
                  dependencies: { dependencies: [{ name: "react", specifier: "^18.3.1" }] },
                  scripts: {},
                  engines: {}
                },
                summary: { total_dependencies: 1, dependency_groups: ["dependencies"], informational_findings_count: 0 },
                findings: [],
                errors: []
              },
              error: null
            })
          );
        }
        if (url.endsWith("/audits/web/basic")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-web-1",
                audit_type: "web_basic",
                file_id: null,
                target_url: "https://example.test/",
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:06:00Z",
                updated_at: "2026-05-26T10:06:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/domain/basic")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-domain-1",
                audit_type: "domain_basic",
                file_id: null,
                target_url: null,
                target_domain: "example.com",
                status: "queued",
                created_at: "2026-05-26T10:07:00Z",
                updated_at: "2026-05-26T10:07:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/subdomains/basic")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-subdomains-1",
                audit_type: "subdomain_inventory_basic",
                file_id: null,
                target_url: null,
                target_domain: "example.com",
                status: "queued",
                created_at: "2026-05-26T10:08:00Z",
                updated_at: "2026-05-26T10:08:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/django-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-django-1",
                audit_type: "django_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:09:00Z",
                updated_at: "2026-05-26T10:09:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/docker-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-docker-1",
                audit_type: "docker_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:10:00Z",
                updated_at: "2026-05-26T10:10:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/secrets-review/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-secrets-1",
                audit_type: "secrets_review_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:11:00Z",
                updated_at: "2026-05-26T10:11:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/node-package-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-node-1",
                audit_type: "node_package_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:12:00Z",
                updated_at: "2026-05-26T10:12:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(
            jsonResponse([
              {
                id: "job-pdf-1",
                audit_type: "pdf_basic",
                file_id: "file-pdf-1",
                target_url: null,
                target_domain: null,
                status: "completed",
                created_at: "2026-05-26T10:01:00Z",
                updated_at: "2026-05-26T10:02:00Z",
                source_file_deleted_at: null,
                summary: { qpdf_ok: true, warnings: [], timed_out_tools: [] }
              },
              {
                id: "job-manifest-1",
                audit_type: "manifest_basic",
                file_id: "file-manifest-1",
                target_url: null,
                target_domain: null,
                status: "completed",
                created_at: "2026-05-26T10:04:00Z",
                updated_at: "2026-05-26T10:05:00Z",
                source_file_deleted_at: null,
                summary: { manifest_type: "package_json", total_dependencies: 1, informational_findings_count: 0 }
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
    expect(screen.getByRole("heading", { name: "Web Audit" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Domain Baseline" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Subdomain Inventory" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Files" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Jobs" })).toBeInTheDocument();

    expect(await screen.findByText("inspectra-backend")).toBeInTheDocument();
    expect(screen.getByText("sample.pdf")).toBeInTheDocument();
    expect(screen.getByText("django.zip")).toBeInTheDocument();
    expect(screen.getAllByText("pdf_basic").length).toBeGreaterThan(0);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledTimes(3);
    });
  });

  it("shows SBOM export buttons only for completed manifest jobs", async () => {
    render(<App />);

    const viewButtons = await screen.findAllByTitle("View job");
    fireEvent.click(viewButtons[0]);

    expect(await screen.findByText("Export PDF")).toBeInTheDocument();
    expect(screen.queryByText("Export CycloneDX JSON")).not.toBeInTheDocument();

    fireEvent.click(viewButtons[1]);

    const cyclonedxLink = await screen.findByRole("link", { name: /Export CycloneDX JSON/i });
    const spdxLink = screen.getByRole("link", { name: /Export SPDX JSON/i });
    expect(cyclonedxLink).toHaveAttribute("href", "http://localhost:8000/jobs/job-manifest-1/sbom/cyclonedx-json");
    expect(spdxLink).toHaveAttribute("href", "http://localhost:8000/jobs/job-manifest-1/sbom/spdx-json");
  });

  it("starts a web audit from the URL form", async () => {
    render(<App />);

    const inputs = await screen.findAllByPlaceholderText("https://example.com");
    const input = inputs[inputs.length - 1];
    fireEvent.change(input, { target: { value: "https://example.test/" } });
    const checkboxes = screen.getAllByLabelText("Confirmo que tengo autorización para auditar este objetivo");
    fireEvent.click(checkboxes[checkboxes.length - 1]);
    const buttons = screen.getAllByRole("button", { name: /Analyze URL/i });
    fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/web/basic",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ url: "https://example.test/", authorization_confirmed: true })
        })
      );
    });
  });

  it("warns when the web audit URL contains sensitive query parameters", async () => {
    render(<App />);

    const inputs = await screen.findAllByPlaceholderText("https://example.com");
    const input = inputs[inputs.length - 1];
    fireEvent.change(input, { target: { value: "https://example.test/callback?token=supersecret&page=1" } });

    expect(screen.getByText(/Se detectan posibles parametros sensibles/i)).toBeInTheDocument();
    expect(screen.getByText("token")).toBeInTheDocument();
  });

  it("does not start a web audit without authorization confirmation", async () => {
    render(<App />);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalled();
    });
    vi.mocked(globalThis.fetch).mockClear();

    const inputs = screen.getAllByPlaceholderText("https://example.com");
    const input = inputs[inputs.length - 1];
    fireEvent.change(input, { target: { value: "https://example.test/" } });
    const buttons = screen.getAllByRole("button", { name: /Analyze URL/i });
    const button = buttons[buttons.length - 1];

    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("starts a domain audit from the domain form", async () => {
    render(<App />);

    const inputs = await screen.findAllByPlaceholderText("example.com");
    const input = inputs[inputs.length - 2];
    fireEvent.change(input, { target: { value: "example.com" } });
    const checkboxes = screen.getAllByLabelText("Confirmo que tengo autorización para auditar este dominio");
    fireEvent.click(checkboxes[checkboxes.length - 1]);
    const buttons = screen.getAllByRole("button", { name: /Analyze domain/i });
    fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/domain/basic",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ domain: "example.com", authorization_confirmed: true })
        })
      );
    });
  });

  it("starts a subdomain inventory audit from explicit candidates", async () => {
    render(<App />);

    const rootInputs = await screen.findAllByPlaceholderText("example.com");
    const rootInput = rootInputs[rootInputs.length - 1];
    fireEvent.change(rootInput, { target: { value: "example.com" } });
    const candidateInputs = screen.getAllByPlaceholderText(/api\.example\.com/);
    const candidatesInput = candidateInputs[candidateInputs.length - 1];
    fireEvent.change(candidatesInput, { target: { value: "www\napi.example.com" } });
    const checkboxes = screen.getAllByLabelText("Confirmo que tengo autorización para auditar estos subdominios");
    fireEvent.click(checkboxes[checkboxes.length - 1]);
    const buttons = screen.getAllByRole("button", { name: /Analyze subdomains/i });
    fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/subdomains/basic",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            root_domain: "example.com",
            subdomains: ["www", "api.example.com"],
            authorization_confirmed: true
          })
        })
      );
    });
  });

  it("does not start a subdomain inventory audit without authorization confirmation", async () => {
    render(<App />);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalled();
    });
    vi.mocked(globalThis.fetch).mockClear();

    const rootInputs = screen.getAllByPlaceholderText("example.com");
    const rootInput = rootInputs[rootInputs.length - 1];
    fireEvent.change(rootInput, { target: { value: "example.com" } });
    const candidateInputs = screen.getAllByPlaceholderText(/api\.example\.com/);
    const candidatesInput = candidateInputs[candidateInputs.length - 1];
    fireEvent.change(candidatesInput, { target: { value: "www\napi.example.com" } });
    const buttons = screen.getAllByRole("button", { name: /Analyze subdomains/i });
    const button = buttons[buttons.length - 1];

    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("starts a Django config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const buttons = screen.getAllByRole("button", { name: /Analyze Django config/i });
    fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/django-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Docker config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const labels = screen.getAllByText("Analyze Docker config");
    const button = labels[labels.length - 1].closest("button");
    expect(button).not.toBeNull();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/docker-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a secrets review audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze secrets review"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze secrets review");
    expect(pdfRow?.textContent).not.toContain("Analyze secrets review");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze secrets review")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/secrets-review/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Node package config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Node package config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Node package config");
    expect(pdfRow?.textContent).not.toContain("Analyze Node package config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Node package config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/node-package-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });
});
