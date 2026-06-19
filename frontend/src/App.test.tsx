import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

function jsonResponse(payload: unknown, status = 200, headers: HeadersInit = {}): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("content-type", "application/json");
  return new Response(JSON.stringify(payload), {
    status,
    headers: responseHeaders
  });
}

const trustedLocalAuthStatus = {
  auth_mode: "trusted_local_no_auth",
  auth_required: false,
  configured: false,
  trusted_local: true,
  default_operator_id: "local-admin",
  login_available: false,
  authenticated: false,
  operator_id: null,
  csrf_required: false,
  csrf_token: null
};

const selfHostedLoginStatus = {
  auth_mode: "self_hosted_single_admin",
  auth_required: true,
  configured: true,
  trusted_local: false,
  default_operator_id: "local-admin",
  login_available: true,
  authenticated: false,
  operator_id: null,
  csrf_required: true,
  csrf_token: null
};

const selfHostedAuthenticatedStatus = {
  ...selfHostedLoginStatus,
  authenticated: true,
  operator_id: "local-admin",
  csrf_token: "csrf-token-123"
};

function headerValue(init: RequestInit | undefined, name: string): string | null {
  return new Headers(init?.headers).get(name);
}

describe("App", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
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
        if (url.endsWith("/active/network/dry-run")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-active-dry-run-1",
                audit_type: "active_network_dry_run",
                file_id: null,
                target_url: "https://example.test/",
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:08:30Z",
                updated_at: "2026-05-26T10:08:30Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/active/network/http-header-probe")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-active-http-header-1",
                audit_type: "active_http_header_probe",
                file_id: null,
                target_url: "https://example.test/",
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:08:45Z",
                updated_at: "2026-05-26T10:08:45Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/active/web/http-basic-header-review")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-active-http-basic-header-review-1",
                audit_type: "active_http_basic_header_review",
                file_id: null,
                target_url: "[REDACTED_TARGET]",
                target_domain: null,
                status: "completed",
                created_at: "2026-05-26T10:08:50Z",
                updated_at: "2026-05-26T10:08:50Z",
                source_file_deleted_at: null,
                result: { capability: "active_http_basic_header_review", result_status: "not_executed" },
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
        if (url.endsWith("/audits/ci-cd-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-ci-1",
                audit_type: "ci_cd_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:13:00Z",
                updated_at: "2026-05-26T10:13:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/k8s-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-k8s-1",
                audit_type: "k8s_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:14:00Z",
                updated_at: "2026-05-26T10:14:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/terraform-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-terraform-1",
                audit_type: "terraform_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:15:00Z",
                updated_at: "2026-05-26T10:15:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/nginx-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-nginx-1",
                audit_type: "nginx_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:16:00Z",
                updated_at: "2026-05-26T10:16:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/compose-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-compose-1",
                audit_type: "compose_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:17:00Z",
                updated_at: "2026-05-26T10:17:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/database-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-database-1",
                audit_type: "database_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:18:00Z",
                updated_at: "2026-05-26T10:18:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/redis-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-redis-1",
                audit_type: "redis_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:19:00Z",
                updated_at: "2026-05-26T10:19:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/sql-database-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-sql-database-1",
                audit_type: "sql_database_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:20:00Z",
                updated_at: "2026-05-26T10:20:00Z",
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
    cleanup();
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
    expect(screen.getByRole("heading", { name: "Active / Network dry-run" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Authorized HTTP Header Probe" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Active / HTTP header review" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Active / Nmap basic" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Active / TLS basic" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Active / DNS inventory" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Active / DNS OSINT" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Files" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Jobs" })).toBeInTheDocument();
    const demoNote = screen.getByRole("note", { name: "Local alpha demo fixture note" });
    expect(demoNote.textContent).toContain("Local alpha demo");
    expect(demoNote.textContent).toContain("synthetic fixtures");
    expect(demoNote.textContent).toContain("tests/fixtures/demo/passive-alpha/");
    expect(demoNote.textContent).toContain("Do not upload real secrets or production archives");
    expect(demoNote.textContent).toContain("[REDACTED]");
    expect(demoNote.textContent).toContain("does not sanitize the original uploaded file");
    expect(demoNote.textContent).not.toContain("Run all recommended passive checks");
    for (const phrase of [
      "compromised",
      "breached",
      "exploitable",
      "confirmed vulnerability",
      "credentials valid",
      "hacked",
      "safe",
      "secure",
      "live exposure",
      "clean"
    ]) {
      expect(demoNote.textContent?.toLowerCase() ?? "").not.toContain(phrase);
    }

    expect(await screen.findByText("inspectra-backend")).toBeInTheDocument();
    expect(screen.getByText("sample.pdf")).toBeInTheDocument();
    expect(screen.getByText("django.zip")).toBeInTheDocument();
    expect(screen.getAllByText("PDF basic").length).toBeGreaterThan(0);
    expect(screen.getAllByText("File basics").length).toBeGreaterThan(0);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledTimes(4);
    });
  });

  it("shows the self-hosted login gate when auth is required and unauthenticated", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(selfHostedLoginStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Authentication required for this self-hosted instance.")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Upload File" })).not.toBeInTheDocument();
    const rendered = view.container.textContent ?? "";
    expect(rendered).not.toContain(".env");
    expect(rendered).not.toContain("bypass");
    expect(rendered).not.toContain("csrf-token-123");
    expect(vi.mocked(globalThis.fetch).mock.calls.some(([input]) => String(input).endsWith("/files"))).toBe(false);
  });

  it("shows controlled unavailable auth state without configuration guidance", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse({ ...selfHostedLoginStatus, configured: false, login_available: false }));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Authentication is not available for this deployment.")).toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    const rendered = view.container.textContent ?? "";
    expect(rendered).not.toContain(".env");
    expect(rendered).not.toContain("INSPECTRA_ADMIN_PASSWORD_HASH");
    expect(rendered).not.toContain("bypass");
  });

  it("logs in, refreshes auth status, clears the password, and hides the login gate", async () => {
    let authStatusCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          authStatusCalls += 1;
          return Promise.resolve(jsonResponse(authStatusCalls === 1 ? selfHostedLoginStatus : selfHostedAuthenticatedStatus));
        }
        if (url.endsWith("/auth/login")) {
          expect(JSON.parse(String(init?.body))).toEqual({ password: "correct-admin-password" });
          return Promise.resolve(jsonResponse({ authenticated: true, operator_id: "local-admin", auth_mode: "self_hosted_single_admin" }));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files") || url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    const passwordInput = await screen.findByLabelText("Password");
    fireEvent.change(passwordInput, { target: { value: "correct-admin-password" } });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/i }));

    expect(await screen.findByText("Signed in as local-admin")).toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Upload File" })).toBeInTheDocument();
    const rendered = view.container.textContent ?? "";
    expect(rendered).not.toContain("correct-admin-password");
    expect(rendered).not.toContain("csrf-token-123");
    expect(rendered).not.toContain("inspectra_session");
  });

  it("shows generic login failure and clears the password", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(selfHostedLoginStatus));
        }
        if (url.endsWith("/auth/login")) {
          return Promise.resolve(jsonResponse({ detail: "Invalid credentials." }, 401));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    const passwordInput = await screen.findByLabelText("Password");
    fireEvent.change(passwordInput, { target: { value: "wrong-admin-password" } });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/i }));

    expect(await screen.findByText("Invalid credentials.")).toBeInTheDocument();
    expect((screen.getByLabelText("Password") as HTMLInputElement).value).toBe("");
    expect(document.body.textContent ?? "").not.toContain("wrong-admin-password");
  });

  it("shows controlled login rate-limit copy and clears the password", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(selfHostedLoginStatus));
        }
        if (url.endsWith("/auth/login")) {
          return Promise.resolve(
            jsonResponse({ detail: "Too many attempts. Try again later." }, 429, { "Retry-After": "60" })
          );
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    const passwordInput = await screen.findByLabelText("Password");
    fireEvent.change(passwordInput, { target: { value: "super-secret-password" } });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/i }));

    expect(await screen.findByText("Too many attempts. Try again later.")).toBeInTheDocument();
    expect((screen.getByLabelText("Password") as HTMLInputElement).value).toBe("");
    const rendered = document.body.textContent ?? "";
    expect(rendered).not.toContain("super-secret-password");
    expect(rendered).not.toContain("Retry-After");
    expect(rendered).not.toContain("60");
    expect(rendered).not.toContain("client key");
    expect(rendered).not.toContain("threshold");
    expect(rendered).not.toContain("recovery");
    expect(rendered).not.toContain("bypass");
    expect(rendered).not.toContain(".env");
  });

  it("sends CSRF only on mutating requests and keeps it out of the DOM", async () => {
    const manifestRecord = {
      id: "file-manifest-uploaded",
      kind: "manifest",
      original_filename: "package.json",
      stored_filename: "file-manifest-uploaded-package.json",
      content_type: "application/json",
      size_bytes: 48,
      sha256: "1234567890abcdef1234567890abcdef",
      created_at: "2026-05-26T10:20:00Z"
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(selfHostedAuthenticatedStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files/manifest")) {
          return Promise.resolve(jsonResponse(manifestRecord, 201));
        }
        if (url.endsWith("/files") || url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Signed in as local-admin")).toBeInTheDocument();
    await waitFor(() => {
      const filesGetCall = vi.mocked(globalThis.fetch).mock.calls.find(([input]) => String(input).endsWith("/files"));
      expect(headerValue(filesGetCall?.[1] as RequestInit | undefined, "X-CSRF-Token")).toBeNull();
    });
    fireEvent.click(screen.getAllByRole("button", { name: "Manifest" })[0]);
    const input = view.container.querySelector('input[type="file"]');
    fireEvent.change(input as HTMLInputElement, {
      target: {
        files: [new File(['{"name":"demo","version":"1.0.0"}'], "package.json", { type: "application/json" })]
      }
    });
    fireEvent.click(screen.getByRole("button", { name: /Upload/i }));

    await waitFor(() => {
      const uploadCall = vi.mocked(globalThis.fetch).mock.calls.find(([input]) => String(input).endsWith("/files/manifest"));
      expect(headerValue(uploadCall?.[1] as RequestInit | undefined, "X-CSRF-Token")).toBe("csrf-token-123");
    });
    expect(view.container.textContent ?? "").not.toContain("csrf-token-123");
  });

  it("logs out with the CSRF header and returns to login state", async () => {
    let authStatusCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          authStatusCalls += 1;
          return Promise.resolve(jsonResponse(authStatusCalls === 1 ? selfHostedAuthenticatedStatus : selfHostedLoginStatus));
        }
        if (url.endsWith("/auth/logout")) {
          return Promise.resolve(jsonResponse({ authenticated: false, operator_id: null, auth_mode: "self_hosted_single_admin" }));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files") || url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    expect(await screen.findByText("Signed in as local-admin")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Sign out/i }));

    await waitFor(() => {
      const logoutCall = vi.mocked(globalThis.fetch).mock.calls.find(([input]) => String(input).endsWith("/auth/logout"));
      expect(headerValue(logoutCall?.[1] as RequestInit | undefined, "X-CSRF-Token")).toBe("csrf-token-123");
    });
    expect(await screen.findByLabelText("Password")).toBeInTheDocument();
  });

  it("refreshes auth and returns to login state after a global 401", async () => {
    let authStatusCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          authStatusCalls += 1;
          return Promise.resolve(jsonResponse(authStatusCalls === 1 ? selfHostedAuthenticatedStatus : selfHostedLoginStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse({ detail: "Authentication required." }, 401));
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    expect(await screen.findByText("Session expired. Sign in again.")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });

  it("renders clear empty dashboard states for files and jobs", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    expect(await screen.findByText("Upload a file or archive to start a passive review.")).toBeInTheDocument();
    expect(screen.getByText("Choose a passive archive review to create a job.")).toBeInTheDocument();
  });

  it("uploads a manifest and keeps archive-only actions off the non-archive row", async () => {
    const manifestRecord = {
      id: "file-manifest-uploaded",
      kind: "manifest",
      original_filename: "package.json",
      stored_filename: "file-manifest-uploaded-package.json",
      content_type: "application/json",
      size_bytes: 48,
      sha256: "1234567890abcdef1234567890abcdef",
      created_at: "2026-05-26T10:20:00Z"
    };
    let uploaded = false;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse(uploaded ? [manifestRecord] : []));
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/files/manifest")) {
          uploaded = true;
          return Promise.resolve(jsonResponse(manifestRecord, 201));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);
    const scoped = within(view.container);

    expect(await scoped.findByText("Upload a file or archive to start a passive review.")).toBeInTheDocument();
    fireEvent.click(scoped.getAllByRole("button", { name: "Manifest" })[0]);
    const input = view.container.querySelector('input[type="file"]');
    expect(input).not.toBeNull();
    fireEvent.change(input as HTMLInputElement, {
      target: {
        files: [new File(['{"name":"demo","version":"1.0.0"}'], "package.json", { type: "application/json" })]
      }
    });
    fireEvent.click(scoped.getByRole("button", { name: /Upload/i }));

    expect(await scoped.findByText("package.json")).toBeInTheDocument();
    expect(view.container.textContent).not.toContain("Cannot read properties of null");
    expect(globalThis.fetch).toHaveBeenCalledWith("http://localhost:8000/files/manifest", expect.objectContaining({ method: "POST" }));

    const rows = Array.from(view.container.querySelectorAll("tr"));
    const manifestRow = rows.find((row) => row.textContent?.includes("package.json"));
    expect(manifestRow).toBeDefined();
    expect(manifestRow?.textContent).toContain("Analyze manifest");
    for (const archiveOnlyAction of [
      "Analyze Redis config",
      "Analyze SQL DB config",
      "Analyze secrets review",
      "Analyze CI/CD config",
      "Analyze Nginx config",
      "Analyze Docker config",
      "Analyze Kubernetes config",
      "Analyze Terraform config"
    ]) {
      expect(manifestRow?.textContent).not.toContain(archiveOnlyAction);
    }
    expect(manifestRow?.textContent).not.toContain("Run all recommended passive checks");
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

  it("creates an Active DNS OSINT job, refreshes jobs, and renders redacted CT OSINT report", async () => {
    const activeDnsOsintJob = {
      id: "job-active-dns-osint-app",
      audit_type: "active_dns_osint",
      file_id: null,
      target_url: "[REDACTED_DOMAIN]",
      target_domain: null,
      status: "completed",
      created_at: "2026-06-15T10:00:00Z",
      updated_at: "2026-06-15T10:01:00Z",
      source_file_deleted_at: null,
      result: {
        audit_type: "active_dns_osint",
        capability: "active_dns_osint",
        mode: "live_dns_osint",
        profile: "ct_subdomain_discovery_bounded",
        status: "osint_best_effort",
        result_status: "osint_best_effort",
        coverage_level: "osint_best_effort",
        domain: "[REDACTED_DOMAIN]",
        sources: {
          certificate_transparency: {
            attempted: true,
            status: "completed",
            names_observed_count: 4,
            names_retained_count: 2,
            names_discarded_count: 2,
            truncated: false
          },
          passive_dns: { attempted: false, status: "not_attempted" }
        },
        observed_names: {
          count: 2,
          max_names: 20,
          sample: ["[REDACTED_DNS_NAME]", "[REDACTED_DNS_NAME]"],
          truncated: false
        },
        summary: {
          manual_validation_required: true,
          result_interpretation: "DNS OSINT review indicator",
          coverage_level: "osint_best_effort",
          observed_names_count: 2,
          ct_source_status: "completed",
          passive_dns_status: "not_attempted"
        },
        execution: {
          external_requests_sent: 1,
          ct_queries_sent: 1,
          passive_dns_queries_sent: 0,
          dns_queries_sent: 0,
          http_requests_sent: 0,
          provider_api_used: false,
          crawling_performed: false,
          observed_name_auto_scan_performed: false
        },
        surface_caveats: ["Manual validation required.", "Observed names are not auto-scanned."]
      },
      error: null
    };
    let jobsCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/jobs")) {
          jobsCalls += 1;
          return Promise.resolve(
            jsonResponse(
              jobsCalls > 1
                ? [
                    {
                      id: activeDnsOsintJob.id,
                      audit_type: activeDnsOsintJob.audit_type,
                      file_id: null,
                      target_url: "[REDACTED_DOMAIN]",
                      target_domain: null,
                      status: "completed",
                      created_at: activeDnsOsintJob.created_at,
                      updated_at: activeDnsOsintJob.updated_at,
                      source_file_deleted_at: null,
                      summary: {
                        capability: "active_dns_osint",
                        coverage_level: "osint_best_effort",
                        observed_names_count: 2,
                        ct_source_status: "completed",
                        passive_dns_status: "not_attempted"
                      }
                    }
                  ]
                : []
            )
          );
        }
        if (url.endsWith("/active/network/dns-osint")) {
          return Promise.resolve(jsonResponse(activeDnsOsintJob, 202));
        }
        if (url.endsWith("/jobs/job-active-dns-osint-app")) {
          return Promise.resolve(jsonResponse(activeDnsOsintJob));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);
    const panel = await screen.findByLabelText("Active / DNS OSINT");
    const scoped = within(panel);

    fireEvent.change(scoped.getByLabelText("Domain"), { target: { value: " Example.Internal " } });
    fireEvent.change(scoped.getByLabelText("Max observed names"), { target: { value: "20" } });
    fireEvent.click(scoped.getByLabelText("I confirm I own or am authorized to query this domain."));
    fireEvent.click(scoped.getByLabelText("I confirm this is my domain or an explicitly authorized domain."));
    fireEvent.click(scoped.getByLabelText("I understand this may send bounded public OSINT queries if backend policy accepts it."));
    fireEvent.click(scoped.getByRole("button", { name: /Create DNS OSINT job/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/network/dns-osint",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi.mocked(globalThis.fetch).mock.calls.find(([input]) => String(input).endsWith("/active/network/dns-osint"))?.[1] as
      | RequestInit
      | undefined;
    expect(JSON.parse(String(request?.body))).toEqual({
      mode: "live_dns_osint",
      profile: "ct_subdomain_discovery_bounded",
      domain: "example.internal",
      include_certificate_transparency: true,
      include_passive_dns: false,
      max_names: 20,
      authorization_confirmed: true,
      owned_or_authorized_domain_confirmed: true,
      public_osint_queries_confirmed: true
    });
    expect(await screen.findByRole("heading", { name: "Active / DNS OSINT report" })).toBeInTheDocument();
    expect(screen.getAllByText("osint_best_effort").length).toBeGreaterThan(0);
    expect(screen.getAllByText("[REDACTED_DNS_NAME]").length).toBeGreaterThan(0);
    expect(screen.getAllByText("not_attempted").length).toBeGreaterThan(0);
    await waitFor(() => expect(jobsCalls).toBeGreaterThan(1));
    expect(view.container.textContent ?? "").not.toContain("example.internal");
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

  it("creates an Active network dry-run plan only after explicit authorization", async () => {
    render(<App />);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalled();
    });
    vi.mocked(globalThis.fetch).mockClear();

    const heading = screen.getByRole("heading", { name: "Active / Network dry-run" });
    const panel = heading.closest("section");
    expect(panel).not.toBeNull();
    const scoped = within(panel as HTMLElement);
    const panelText = panel?.textContent ?? "";
    for (const forbidden of ["Run Nmap", "Scan", "Attack", "Exploit"]) {
      expect(panelText).not.toContain(forbidden);
    }

    const targetInput = scoped.getByPlaceholderText("https://example.test");
    const submit = scoped.getByRole("button", { name: /Create dry-run plan/i });
    expect(submit).toBeDisabled();

    fireEvent.change(targetInput, { target: { value: "https://example.test/" } });
    expect(submit).toBeDisabled();

    fireEvent.click(scoped.getByLabelText("I confirm I own or am authorized to test this target."));
    expect(submit).not.toBeDisabled();
    fireEvent.click(submit);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/network/dry-run",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi
      .mocked(globalThis.fetch)
      .mock.calls.find(([input]) => String(input).endsWith("/active/network/dry-run"))?.[1] as RequestInit | undefined;
    expect(request).toBeDefined();
    expect(JSON.parse(String(request?.body))).toEqual({
      target: "https://example.test/",
      authorization: {
        confirmed: true,
        statement: "I confirm I own or am authorized to test this target.",
        scope: "single-target"
      },
      mode: "dry_run",
      profile: "http_header_probe_preview",
      limits: {
        max_requests: 0,
        timeout_seconds: 0,
        max_redirects: 0,
        response_size_bytes: 0
      }
    });
  });

  it("shows the Active dry-run disabled backend message without env-file guidance", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files") || url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/active/network/dry-run")) {
          return Promise.resolve(jsonResponse({ detail: "Active dry-run checks are disabled in this environment." }, 403));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    const heading = await screen.findByRole("heading", { name: "Active / Network dry-run" });
    const panel = heading.closest("section");
    expect(panel).not.toBeNull();
    const scoped = within(panel as HTMLElement);
    fireEvent.change(scoped.getByPlaceholderText("https://example.test"), { target: { value: "https://example.test/" } });
    fireEvent.click(scoped.getByLabelText("I confirm I own or am authorized to test this target."));
    fireEvent.click(scoped.getByRole("button", { name: /Create dry-run plan/i }));

    expect(await scoped.findByText(/Active dry-run checks are disabled in this environment/i)).toBeInTheDocument();
    expect(scoped.getByText(/Ask an administrator to enable the Active dry-run backend flag/i)).toBeInTheDocument();
    expect(panel?.textContent).not.toContain(".env");
  });

  it("creates an authorized HTTP header probe only after both live confirmations", async () => {
    render(<App />);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalled();
    });
    vi.mocked(globalThis.fetch).mockClear();

    const heading = screen.getByRole("heading", { name: "Authorized HTTP Header Probe" });
    const panel = heading.closest("section");
    expect(panel).not.toBeNull();
    const scoped = within(panel as HTMLElement);
    const panelText = panel?.textContent ?? "";
    expect(panelText).toContain("Live request");
    expect(panelText).toContain("One HTTP HEAD request");
    expect(panelText).toContain("No body read");
    expect(panelText).toContain("Redirects not followed");
    for (const forbidden of ["Scan", "Run Nmap", "Attack", "Exploit", "port scan", "crawl", "fuzz", "brute force"]) {
      expect(panelText).not.toContain(forbidden);
    }

    const targetInput = scoped.getByPlaceholderText("https://example.test/");
    const submit = scoped.getByRole("button", { name: /Create authorized header probe job/i });
    expect(submit).toBeDisabled();

    fireEvent.change(targetInput, { target: { value: "https://example.test/" } });
    expect(submit).toBeDisabled();

    fireEvent.click(scoped.getByLabelText("I confirm I own or am authorized to test this target."));
    expect(submit).toBeDisabled();

    fireEvent.click(scoped.getByLabelText("I understand this will send one HTTP HEAD request to the target."));
    expect(submit).not.toBeDisabled();
    fireEvent.click(submit);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/network/http-header-probe",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi
      .mocked(globalThis.fetch)
      .mock.calls.find(([input]) => String(input).endsWith("/active/network/http-header-probe"))?.[1] as RequestInit | undefined;
    expect(request).toBeDefined();
    const requestBody = JSON.parse(String(request?.body));
    expect(Object.keys(requestBody).sort()).toEqual(["authorization", "limits", "mode", "profile", "target"]);
    expect(Object.keys(requestBody.authorization).sort()).toEqual(["confirmed", "live_traffic_confirmed", "scope", "statement"]);
    expect(Object.keys(requestBody.limits).sort()).toEqual([
      "concurrency",
      "max_dns_answers",
      "max_redirects",
      "max_requests",
      "max_response_header_bytes",
      "max_targets",
      "response_body_bytes",
      "retries",
      "timeout_seconds"
    ]);
    expect(JSON.stringify(requestBody)).not.toContain("file_id");
    expect(JSON.stringify(requestBody)).not.toContain("headers");
    expect(JSON.stringify(requestBody)).not.toContain("cookies");
    expect(requestBody).toEqual({
      target: "https://example.test/",
      authorization: {
        confirmed: true,
        live_traffic_confirmed: true,
        statement: "I confirm I own or am authorized to test this target.",
        scope: "single-target"
      },
      mode: "live_header_probe",
      profile: "http_header_probe",
      limits: {
        max_targets: 1,
        max_requests: 1,
        timeout_seconds: 3,
        max_redirects: 0,
        response_body_bytes: 0,
        max_response_header_bytes: 32768,
        max_dns_answers: 8,
        retries: 0,
        concurrency: 1
      }
    });
  });

  it("shows the Active HTTP header probe disabled backend message without env-file guidance", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files") || url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/active/network/http-header-probe")) {
          return Promise.resolve(jsonResponse({ detail: "Active HTTP header probe is disabled in this environment." }, 403));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    const heading = await screen.findByRole("heading", { name: "Authorized HTTP Header Probe" });
    const panel = heading.closest("section");
    expect(panel).not.toBeNull();
    const scoped = within(panel as HTMLElement);
    fireEvent.change(scoped.getByPlaceholderText("https://example.test/"), {
      target: { value: "http://user:pass@example.com/?token=token_should_never_render" }
    });
    fireEvent.click(scoped.getByLabelText("I confirm I own or am authorized to test this target."));
    fireEvent.click(scoped.getByLabelText("I understand this will send one HTTP HEAD request to the target."));
    fireEvent.click(scoped.getByRole("button", { name: /Create authorized header probe job/i }));

    expect(await scoped.findByText(/Active HTTP header probe is disabled in this environment/i)).toBeInTheDocument();
    expect(scoped.getByText(/This deployment has not enabled live header probes/i)).toBeInTheDocument();
    const rendered = panel?.textContent ?? "";
    expect(rendered).not.toContain(".env");
    expect(rendered).not.toContain("bypass");
    expect(rendered).not.toContain("retry");
    expect(rendered).not.toContain("DNS was attempted");
    expect(rendered).not.toContain("HTTP was attempted");
    expect(rendered).not.toContain("http://user:pass@example.com");
    expect(rendered).not.toContain("token_should_never_render");
    expect(
      vi
        .mocked(globalThis.fetch)
        .mock.calls.filter(([input]) => String(input).endsWith("/jobs"))
    ).toHaveLength(1);
  });

  it("creates and opens an Active HTTP header review no-live job record", async () => {
    const activeJob = {
      id: "job-active-http-basic-header-review-app",
      audit_type: "active_http_basic_header_review",
      file_id: null,
      target_url: "[REDACTED_TARGET]",
      target_domain: null,
      status: "completed",
      created_at: "2026-06-19T10:00:00Z",
      updated_at: "2026-06-19T10:00:00Z",
      source_file_deleted_at: null,
      result: {
        audit_type: "active_http_basic_header_review",
        capability: "active_http_basic_header_review",
        mode: "live_http_basic_header_review",
        profile: "http_headers_single_request",
        status: "not_executed",
        result_status: "not_executed",
        lifecycle_state: "not_executed",
        target: "https://authorized.example/?token=token_should_never_render",
        raw_target: "https://authorized.example/private?token=token_should_never_render",
        target_display: "[REDACTED_TARGET]",
        method: "HEAD",
        headers: [{ name: "Authorization", value: "Bearer token_should_never_render" }],
        cookies: ["session_should_not_render=cookie_should_not_render"],
        redirect_chain: ["redirect-location-should-not-render"],
        response_body: "response_body_should_not_render",
        exception: "raw_exception_should_not_render",
        manual_validation_required: true,
        review_wording: "HTTP header review indicator",
        result_interpretation: "HTTP header review indicator",
        job_status_meaning: "Completed job status means the no-live record was stored; no HTTP request was performed.",
        execution: {
          live_request_performed: false,
          network_requests_sent: 0,
          requests_sent: 0,
          http_requests_sent: 0,
          redirect_followed: false,
          body_read: false,
          job_created: true,
          storage_persisted: true
        },
        summary: {
          status: "not_executed",
          manual_validation_required: true,
          review_wording: "HTTP header review indicator",
          result_interpretation: "HTTP header review indicator",
          job_status_meaning: "Completed job status means the no-live record was stored; no HTTP request was performed.",
          live_request_performed: false,
          redirect_followed: false,
          body_read: false,
          network_requests_sent: 0,
          requests_sent: 0,
          http_requests_sent: 0,
          job_created: true,
          storage_persisted: true
        },
        limits: {
          max_targets: 1,
          method: "HEAD",
          max_redirects: 0,
          response_body_bytes: 0,
          raw_target_persisted: false,
          headers_persisted: false,
          cookies_persisted: false,
          response_body_persisted: false
        },
        surface_caveats: [
          "No live HTTP request was performed",
          "No redirect was followed",
          "No response body was read",
          "Manual validation required",
          "HTTP header review indicator wording only"
        ]
      },
      error: "raw_exception_should_not_render token_should_never_render"
    };
    let jobs = [] as unknown[];
    let jobsCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/active/web/http-basic-header-review")) {
          jobs = [
            {
              ...activeJob,
              result: undefined,
              error: undefined,
              summary: {
                capability: "active_http_basic_header_review",
                result_status: "not_executed",
                target_display: "[REDACTED_TARGET]",
                method: "HEAD",
                requests_sent: 0,
                live_request_performed: false,
                redirect_followed: false,
                body_read: false,
                manual_validation_required: true,
                review_wording: "HTTP header review indicator"
              }
            }
          ];
          return Promise.resolve(jsonResponse(activeJob, 202));
        }
        if (url.endsWith("/jobs")) {
          jobsCalls += 1;
          return Promise.resolve(jsonResponse(jobs));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);
    const heading = await screen.findByRole("heading", { name: "Active / HTTP header review" });
    const panel = heading.closest("section");
    expect(panel).not.toBeNull();
    const scoped = within(panel as HTMLElement);

    fireEvent.change(scoped.getByLabelText("URL target"), { target: { value: "https://authorized.example/" } });
    fireEvent.click(scoped.getByLabelText("I confirm I own or am authorized to test this URL."));
    fireEvent.click(scoped.getByLabelText("I confirm I control this target."));
    fireEvent.click(scoped.getByLabelText("I understand this contract is for a future live HTTP request, while this phase stores a no-live record and performs no HTTP request."));
    fireEvent.click(scoped.getByRole("button", { name: /Create HTTP header review job/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/web/http-basic-header-review",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi
      .mocked(globalThis.fetch)
      .mock.calls.find(([input]) => String(input).endsWith("/active/web/http-basic-header-review"))?.[1] as RequestInit | undefined;
    expect(JSON.parse(String(request?.body))).toEqual({
      mode: "live_http_basic_header_review",
      profile: "http_headers_single_request",
      target: "https://authorized.example/",
      method: "HEAD",
      authorization_confirmed: true,
      target_control_confirmed: true,
      delegated_permission_confirmed: false,
      live_http_request_confirmed: true
    });

    expect(await scoped.findByText(/HTTP header review indicator job created/i)).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Active / HTTP header review report" })).toBeInTheDocument();
    await waitFor(() => expect(jobsCalls).toBeGreaterThan(1));
    const rendered = view.container.textContent ?? "";
    expect(rendered).toContain("HTTP header review");
    expect(rendered).toContain("not_executed");
    expect(rendered).toContain(
      "not_executed, HEAD, HTTP header review indicator, 0 requests sent, live request performed false, redirect followed false, body read false, manual validation required"
    );
    expect(rendered).toContain("HTTP header review indicator");
    expect(rendered).toContain("Manual validation required");
    expect(rendered).toContain("No live HTTP request was performed");
    expect(rendered).toContain("No redirect was followed");
    expect(rendered).toContain("No response body was read");
    expect(rendered).toContain("[REDACTED_TARGET]");
    expect(rendered).toContain('"requests_sent": 0');
    expect(rendered).toContain('"live_request_performed": false');
    for (const value of [
      "authorized.example",
      "token_should_never_render",
      "session_should_not_render",
      "cookie_should_not_render",
      "redirect-location-should-not-render",
      "response_body_should_not_render",
      "raw_exception_should_not_render"
    ]) {
      expect(rendered).not.toContain(value);
    }
    expect(
      vi
        .mocked(globalThis.fetch)
        .mock.calls.some(([input]) => String(input).includes("authorized.example"))
    ).toBe(false);
  });

  it("renders the Active Nmap basic form without calling the API before confirmations", async () => {
    render(<App />);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalled();
    });
    vi.mocked(globalThis.fetch).mockClear();

    const heading = screen.getByRole("heading", { name: "Active / Nmap basic" });
    const panel = heading.closest("section");
    expect(panel).not.toBeNull();
    const scoped = within(panel as HTMLElement);
    const panelText = panel?.textContent ?? "";

    expect(panelText).toContain("Local/private/self-hosted");
    expect(panelText).toContain("Authorized targets only");
    expect(panelText).toContain("bounded authorized lifecycle record");
    expect(panelText).toContain("Manual validation required");
    expect(panelText).toContain("No security finding is asserted");
    expect(panelText).toContain("No raw flags");
    expect(panelText).toContain("no credential validation");
    expect(panelText).not.toContain("full network scan");
    expect(panelText).not.toContain("scan the internet");
    expect(panelText).not.toContain("find assets");
    expect(panelText).not.toContain("target is safe");
    expect(panelText).not.toContain("exploitable");
    expect(panelText).not.toContain("all ports found");
    expect(scoped.getByLabelText("Target")).toBeInTheDocument();
    expect(scoped.getByLabelText("TCP ports")).toBeInTheDocument();
    expect(scoped.getByRole("button", { name: /Create bounded record/i })).toBeDisabled();
    expect(panel?.querySelector("form")).not.toBeNull();
    expect(panel?.querySelector('input[type="file"]')).toBeNull();
    expect(panel?.querySelector("textarea")).toBeNull();
    expect(scoped.queryByLabelText(/raw flags/i)).not.toBeInTheDocument();
    expect(scoped.queryByLabelText(/credentials/i)).not.toBeInTheDocument();
    expect(scoped.queryByLabelText(/cookies/i)).not.toBeInTheDocument();
    expect(scoped.queryByLabelText(/headers/i)).not.toBeInTheDocument();
    expect(scoped.queryByLabelText(/tokens/i)).not.toBeInTheDocument();

    fireEvent.change(scoped.getByLabelText("Target"), { target: { value: "router.local" } });
    fireEvent.change(scoped.getByLabelText("TCP ports"), { target: { value: "22, 443" } });
    fireEvent.click(scoped.getByRole("button", { name: /Create bounded record/i }));
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(
      vi
        .mocked(globalThis.fetch)
        .mock.calls.some(([input]) => String(input).endsWith("/active/network/nmap-basic"))
    ).toBe(false);
  });

  it("creates and opens an Active Nmap basic bounded job record", async () => {
    const activeJob = {
      id: "job-active-nmap-no-live-52",
      audit_type: "active_nmap_basic",
      file_id: null,
      target_url: "[REDACTED_TARGET]",
      target_domain: null,
      status: "completed",
      created_at: "2026-06-12T10:00:00Z",
      updated_at: "2026-06-12T10:00:00Z",
      source_file_deleted_at: null,
      result: {
        audit_type: "active_nmap_basic",
        capability: "active_nmap_basic",
        mode: "live_nmap_basic",
        profile: "tcp_connect_small",
        status: "not_executed",
        lifecycle_state: "completed_no_live",
        no_live_lifecycle_record: true,
        nmap_executed: false,
        network_requests_sent: 0,
        dns_queries_sent: 0,
        evidence_available: false,
        observations_available: false,
        target: "router.local",
        raw_payload: { target: "router.local", token: "token_should_never_render" },
        command: "nmap -sT router.local",
        stdout:
          "stdout with router.local and <nmaprun><host><address addr='192.168.56.10'/></host></nmaprun>",
        stderr: "stderr for secret-lab.internal Authorization: Bearer token_should_never_render",
        raw_xml: "<nmaprun args='nmap -sT router.local'><host><ports /></host></nmaprun>",
        service_details: { banner: "PrivateServer 9.9.9" },
        credentials: { api_key: "raw-api-key-123456" },
        headers: { Authorization: "Bearer token_should_never_render" },
        cookies: { session: "token_should_never_render" },
        tokens: ["token_should_never_render"],
        observations: [{ port: 443, state: "open" }],
        evidence: ["router.local responded"],
        surface_caveats: [
          "No Nmap executed.",
          "No network requests.",
          "No DNS queries.",
          "No evidence collected.",
          "No observations available.",
          "Manual validation required."
        ]
      },
      error: null
    };
    let jobs = [] as unknown[];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend", active_nmap_basic: { enabled: true } }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/active/network/nmap-basic")) {
          jobs = [
            {
              ...activeJob,
              result: undefined,
              error: undefined,
              summary: {
                capability: "active_nmap_basic",
                lifecycle_state: "completed_no_live",
                result_status: "not_executed",
                no_live_lifecycle_record: true,
                network_requests_sent: 0,
                nmap_executed: false,
                observation_count: 0,
                target_display: "[REDACTED_TARGET]"
              }
            }
          ];
          return Promise.resolve(jsonResponse(activeJob, 202));
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse(jobs));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);
    const heading = await screen.findByRole("heading", { name: "Active / Nmap basic" });
    const panel = heading.closest("section");
    expect(panel).not.toBeNull();
    const scoped = within(panel as HTMLElement);

    fireEvent.change(scoped.getByLabelText("Target"), { target: { value: "router.local" } });
    fireEvent.change(scoped.getByLabelText("TCP ports"), { target: { value: "22, 443" } });
    fireEvent.click(scoped.getByLabelText("I confirm I own or am authorized to test this target."));
    fireEvent.click(scoped.getByLabelText("I confirm this is local, private, or self-hosted scope."));
    fireEvent.click(scoped.getByLabelText("I understand this capability is live-traffic scoped and remains bounded by backend policy."));
    fireEvent.click(scoped.getByRole("button", { name: /Create bounded record/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/network/nmap-basic",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi
      .mocked(globalThis.fetch)
      .mock.calls.find(([input]) => String(input).endsWith("/active/network/nmap-basic"))?.[1] as RequestInit | undefined;
    expect(JSON.parse(String(request?.body))).toEqual({
      mode: "live_nmap_basic",
      profile: "tcp_connect_small",
      targets: ["router.local"],
      ports: [22, 443],
      authorization_confirmed: true,
      local_private_scope_confirmed: true,
      live_traffic_confirmed: true
    });

    expect(await scoped.findByText(/No-live lifecycle record created/i)).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Active / Nmap basic report" })).toBeInTheDocument();
    fireEvent.click(screen.getByText("Show redacted Raw JSON"));
    const rendered = view.container.textContent ?? "";
    expect(rendered).toContain("completed_no_live");
    expect(rendered).toContain("not_executed");
    expect(rendered).toContain("No-live lifecycle record");
    expect(rendered).toContain("No Nmap executed");
    expect(rendered).toContain("No network requests");
    expect(rendered).toContain("No DNS queries");
    expect(rendered).toContain("No evidence collected");
    expect(rendered).toContain("No observations available");
    expect(rendered).toContain("Manual validation required");
    expect(rendered).toContain("[REDACTED_TARGET]");
    expect(rendered).toContain("Raw JSON (redacted)");
    expect(rendered).toContain("[REDACTED");
    expect(rendered).not.toContain("router.local");
    expect(rendered).not.toContain("secret-lab.internal");
    expect(rendered).not.toContain("nmap -sT");
    expect(rendered).not.toContain("<nmaprun");
    expect(rendered).not.toContain("stdout with");
    expect(rendered).not.toContain("stderr for");
    expect(rendered).not.toContain("PrivateServer");
    expect(rendered).not.toContain("token_should_never_render");
    expect(rendered).not.toContain("raw-api-key-123456");
    expect(rendered).not.toContain("scan completed");
    expect(rendered).not.toContain("vulnerability found");
    expect(rendered).not.toContain("completed scan");
  });

  it("creates and opens an Active TLS basic review indicator job record", async () => {
    const activeJob = {
      id: "job-active-tls-basic-04",
      audit_type: "active_tls_basic",
      file_id: null,
      target_url: "[REDACTED_TARGET]",
      target_domain: null,
      status: "completed",
      created_at: "2026-06-14T10:00:00Z",
      updated_at: "2026-06-14T10:00:00Z",
      source_file_deleted_at: null,
      result: {
        audit_type: "active_tls_basic",
        capability: "active_tls_basic",
        mode: "live_tls_basic",
        profile: "tls_handshake_summary",
        status: "handshake_succeeded",
        result_status: "handshake_succeeded",
        target: "service.local",
        raw_payload: { target: "service.local", token: "token_should_never_render" },
        port: 443,
        handshake: { status: "succeeded", protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384" },
        certificate: {
          available: true,
          subject: "commonName=service.local",
          issuer: "commonName=Inspectra Test CA",
          san_count: 1,
          san_sample: [{ type: "DNS", value: "service.local" }],
          not_before: "2026-01-01T00:00:00Z",
          not_after: "2026-01-31T00:00:00Z",
          days_until_expiry: 30,
          certificate_pem: "-----BEGIN CERTIFICATE-----token_should_never_render-----END CERTIFICATE-----",
          certificate_der: "raw_der_should_not_render"
        },
        execution: {
          tls_handshake_attempted: true,
          network_requests_sent: 1,
          http_requests_sent: 0,
          target_expansion_performed: false,
          dns_expansion_performed: false,
          crawling_performed: false,
          credential_validation_performed: false
        },
        limits: {
          handshake_timeout_seconds: 3,
          raw_certificate_persisted: false,
          raw_target_persisted: false
        },
        legacy: {
          raw_exception: "raw_exception_should_not_render service.local",
          headers: { Authorization: "Bearer token_should_never_render" },
          cookies: { session: "token_should_never_render" },
          tokens: ["token_should_never_render"],
          credentials: { api_key: "raw-api-key-123456" }
        },
        errors: []
      },
      error: null
    };
    let jobs = [] as unknown[];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/active/network/tls-basic")) {
          jobs = [
            {
              ...activeJob,
              result: undefined,
              error: undefined,
              summary: {
                capability: "active_tls_basic",
                result_status: "handshake_succeeded",
                handshake_status: "succeeded",
                protocol: "TLSv1.3",
                cipher: "TLS_AES_256_GCM_SHA384",
                certificate_available: true,
                san_count: 1,
                days_until_expiry: 30,
                tls_handshake_attempted: true,
                network_requests_sent: 1,
                target_display: "[REDACTED_TARGET]"
              }
            }
          ];
          return Promise.resolve(jsonResponse(activeJob, 202));
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse(jobs));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);
    const heading = await screen.findByRole("heading", { name: "Active / TLS basic" });
    const panel = heading.closest("section");
    expect(panel).not.toBeNull();
    const scoped = within(panel as HTMLElement);

    fireEvent.change(scoped.getByLabelText("Target"), { target: { value: "service.local" } });
    fireEvent.change(scoped.getByLabelText("TLS port"), { target: { value: "443" } });
    fireEvent.click(scoped.getByLabelText("I confirm I own or am authorized to test this target."));
    fireEvent.click(scoped.getByLabelText("I confirm this is local, private, or self-hosted scope."));
    fireEvent.click(scoped.getByLabelText("I understand this capability sends one bounded TLS handshake attempt if backend policy accepts it."));
    fireEvent.click(scoped.getByRole("button", { name: /Create TLS review job/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/network/tls-basic",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi
      .mocked(globalThis.fetch)
      .mock.calls.find(([input]) => String(input).endsWith("/active/network/tls-basic"))?.[1] as RequestInit | undefined;
    expect(JSON.parse(String(request?.body))).toEqual({
      mode: "live_tls_basic",
      profile: "tls_handshake_summary",
      target: "service.local",
      port: 443,
      authorization_confirmed: true,
      local_private_scope_confirmed: true,
      live_traffic_confirmed: true
    });

    expect(await scoped.findByText(/TLS review indicator job created/i)).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Active / TLS basic report" })).toBeInTheDocument();
    fireEvent.click(screen.getByText("Show redacted Raw JSON"));
    const rendered = view.container.textContent ?? "";
    expect(rendered).toContain("handshake_succeeded");
    expect(rendered).toContain("TLS handshake review indicator");
    expect(rendered).toContain("Certificate expiry review indicator");
    expect(rendered).toContain("Manual validation required");
    expect(rendered).toContain("[REDACTED_TARGET]");
    expect(rendered).toContain("TLSv1.3");
    expect(rendered).toContain("TLS_AES_256_GCM_SHA384");
    expect(rendered).toContain("30");
    expect(rendered).toContain("Raw JSON (redacted)");
    expect(rendered).toContain("[REDACTED");
    expect(rendered).not.toContain("service.local");
    expect(rendered).not.toContain("-----BEGIN CERTIFICATE-----");
    expect(rendered).not.toContain("raw_der_should_not_render");
    expect(rendered).not.toContain("raw_exception_should_not_render");
    expect(rendered).not.toContain("token_should_never_render");
    expect(rendered).not.toContain("raw-api-key-123456");
    expect(rendered).not.toMatch(/confirmed\s+vulnerability/i);
    expect(rendered).not.toMatch(/exploitable/i);
    expect(rendered).not.toMatch(/target\s+is\s+safe/i);
    expect(rendered).not.toMatch(/full\s+scan/i);
    expect(rendered).not.toMatch(/all\s+certs\s+found/i);
    expect(rendered).not.toMatch(/public\s+scanner/i);
  });

  it("creates and opens an Active DNS inventory review indicator job record", async () => {
    const activeJob = {
      id: "job-active-dns-inventory-05",
      audit_type: "active_dns_inventory",
      file_id: null,
      target_url: "[REDACTED_DOMAIN]",
      target_domain: null,
      status: "completed",
      created_at: "2026-06-14T10:00:00Z",
      updated_at: "2026-06-14T10:00:00Z",
      source_file_deleted_at: null,
      result: {
        audit_type: "active_dns_inventory",
        capability: "active_dns_inventory",
        mode: "live_dns_inventory",
        profile: "dns_inventory_authorized",
        status: "best_effort_inventory",
        result_status: "best_effort_inventory",
        coverage_level: "best_effort_inventory",
        domain: "secret.example.internal",
        record_types: ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"],
        records: {
          A: { count: 1, sample: [{ name: "secret.example.internal", type: "A", value: "192.0.2.55", ttl: 300 }] },
          MX: {
            count: 1,
            sample: [{ name: "secret.example.internal", type: "MX", value: "mail.secret.example.internal", ttl: 300, priority: 10 }]
          },
          TXT: {
            count: 2,
            sample: [{ name: "secret.example.internal", type: "TXT", value: "v=spf1 include:_spf.example.net -all", ttl: 300 }]
          }
        },
        security_records: {
          spf: { checked: true, present: true, record_value: "v=spf1 include:_spf.example.net -all" },
          dmarc: { checked: true, present: true, record_value: "v=DMARC1; p=reject" },
          caa: { checked: true, present: true, record_count: 1, raw_value: "issue ca.example.net" },
          dkim: { checked: false, status: "not_attempted" }
        },
        subdomains: {
          enabled: true,
          strategy: "fixed_candidate_allowlist",
          candidates_checked: 12,
          query_record_types: ["A", "AAAA", "CNAME"],
          count: 2,
          sample: [
            { name: "www.secret.example.internal", record_types: ["A"], record_count: 1 },
            { name: "admin.secret.example.internal", record_types: ["CNAME"], record_count: 1 }
          ],
          sample_truncated: false
        },
        zone_transfer: { attempted: false, status: "not_attempted" },
        provider_import: { attempted: false, status: "not_attempted" },
        execution: {
          dns_queries_sent: 45,
          subdomain_queries_sent: 36,
          http_requests_sent: 0,
          subprocess_invoked: false,
          nmap_invoked: false,
          zone_transfer_attempted: false,
          provider_api_used: false
        },
        limits: {
          domain_value_persisted: false,
          dns_packets_persisted: false,
          resolver_logs_persisted: false
        },
        raw_dns_packet: "raw_dns_packet token_should_never_render",
        raw_resolver_log: "raw_resolver_log secret.example.internal 192.0.2.55",
        provider_api_token: "provider_api_token token_should_never_render",
        provider_zone_id: "provider-zone-123",
        credentials: { api_key: "raw-api-key-123456" },
        headers: { Authorization: "Bearer token_should_never_render" },
        cookies: "sessionid=secret-session-cookie",
        tokens: ["token_should_never_render"],
        legacy: {
          notes: "confirmed vulnerability exploitable target is safe all records found full DNS inventory public scanner"
        },
        surface_caveats: ["Manual validation required."]
      },
      error: null
    };
    let jobs = [] as unknown[];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/active/network/dns-inventory")) {
          jobs = [
            {
              ...activeJob,
              result: undefined,
              error: undefined,
              summary: {
                capability: "active_dns_inventory",
                result_status: "best_effort_inventory",
                coverage_level: "best_effort_inventory",
                target_display: "[REDACTED_DOMAIN]",
                record_count: 4,
                spf_present: true,
                dmarc_present: true,
                caa_present: true,
                subdomain_observed_count: 2,
                dns_queries_sent: 45,
                subdomain_queries_sent: 36
              }
            }
          ];
          return Promise.resolve(jsonResponse(activeJob, 202));
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse(jobs));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);
    const heading = await screen.findByRole("heading", { name: "Active / DNS inventory" });
    const panel = heading.closest("section");
    expect(panel).not.toBeNull();
    const scoped = within(panel as HTMLElement);

    fireEvent.change(scoped.getByLabelText("Domain"), { target: { value: "secret.example.internal" } });
    fireEvent.click(scoped.getByLabelText("I confirm I own or am authorized to query this domain."));
    fireEvent.click(scoped.getByLabelText("I confirm this domain is local, private, self-hosted, or owned scope."));
    fireEvent.click(scoped.getByLabelText("I understand this capability sends bounded live DNS queries if backend policy accepts it."));
    fireEvent.click(scoped.getByRole("button", { name: /Create DNS inventory job/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/network/dns-inventory",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi
      .mocked(globalThis.fetch)
      .mock.calls.find(([input]) => String(input).endsWith("/active/network/dns-inventory"))?.[1] as RequestInit | undefined;
    expect(JSON.parse(String(request?.body))).toEqual({
      mode: "live_dns_inventory",
      profile: "dns_inventory_authorized",
      domain: "secret.example.internal",
      record_types: ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"],
      include_security_records: true,
      include_subdomain_discovery: true,
      attempt_zone_transfer: false,
      authorization_confirmed: true,
      local_private_or_owned_scope_confirmed: true,
      live_dns_queries_confirmed: true
    });

    expect(await scoped.findByText(/DNS configuration review indicator job created/i)).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Active / DNS inventory report" })).toBeInTheDocument();
    fireEvent.click(screen.getByText("Show redacted Raw JSON"));
    const rendered = view.container.textContent ?? "";
    expect(rendered).toContain("best_effort_inventory");
    expect(rendered).toContain("DNS configuration review indicator");
    expect(rendered).toContain("best-effort DNS inventory");
    expect(rendered).toContain("Manual validation required");
    expect(rendered).toContain("Grouped DNS Records");
    expect(rendered).toContain("Security Record Indicators");
    expect(rendered).toContain("Bounded Subdomain Summary");
    expect(rendered).toContain("[REDACTED_DOMAIN]");
    expect(rendered).toContain("[REDACTED_DNS_VALUE]");
    expect(rendered).toContain("[REDACTED_DNS_NAME]");
    expect(rendered).toContain("not_attempted");
    expect(rendered).toContain("Raw JSON (redacted)");
    expect(rendered).toContain("[REDACTED");
    for (const secret of [
      "secret.example.internal",
      "www.secret.example.internal",
      "admin.secret.example.internal",
      "mail.secret.example.internal",
      "192.0.2.55",
      "_spf.example.net",
      "ca.example.net",
      "raw_dns_packet",
      "raw_resolver_log",
      "provider_api_token",
      "provider-zone-123",
      "token_should_never_render",
      "raw-api-key-123456"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).not.toMatch(/confirmed\s+vulnerability/i);
    expect(rendered).not.toMatch(/exploitable/i);
    expect(rendered).not.toMatch(/target\s+is\s+safe/i);
    expect(rendered).not.toMatch(/all\s+records\s+found/i);
    expect(rendered).not.toMatch(/full\s+DNS\s+inventory/i);
    expect(rendered).not.toMatch(/public\s+scanner/i);
  });

  it("renders Active dry-run jobs with redacted target table and report payload", async () => {
    const activeJob = {
      id: "job-active-legacy-1",
      audit_type: "active_network_dry_run",
      file_id: null,
      target_url: "http://user:pass@example.com/?token=token_should_never_render",
      target_domain: null,
      status: "completed",
      created_at: "2026-05-26T10:21:00Z",
      updated_at: "2026-05-26T10:22:00Z",
      source_file_deleted_at: null,
      summary: {
        target_display: "http://user:pass@example.com/?token=token_should_never_render",
        allowed: false,
        planned_checks_count: 0,
        blocked_reasons_count: 1,
        network_requests_sent: 0
      }
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/jobs/job-active-legacy-1")) {
          return Promise.resolve(
            jsonResponse({
              ...activeJob,
              summary: undefined,
              result: {
                analyzer: "active_network_dry_run",
                mode: "dry_run",
                profile: "http_header_probe_preview",
                target: {
                  raw: "http://user:pass@example.com/?token=token_should_never_render",
                  password: "super-secret-password"
                },
                authorization: {
                  confirmed: true,
                  authorization_header: "Authorization: Bearer token_should_never_render"
                },
                policy: {
                  allowed: false,
                  reason: "url_credentials_rejected"
                },
                limits: {
                  max_requests: 0,
                  timeout_seconds: 0,
                  max_redirects: 0,
                  response_size_bytes: 0
                },
                planned_checks: [{ url: "http://user:pass@example.com/?password=super-secret-password" }],
                blocked_reasons: [{ code: "url_credentials_rejected", message: "Authorization: Bearer token_should_never_render" }],
                audit_log: [{ event: "dry_run_blocked", raw: "-----BEGIN PRIVATE KEY----- fixture -----END PRIVATE KEY-----" }],
                errors: ["PRIVATE KEY token_should_never_render"],
                summary: {
                  allowed: false,
                  planned_checks_count: 0,
                  blocked_reasons_count: 1,
                  network_requests_sent: 0
                }
              },
              error: "Authorization: Bearer token_should_never_render"
            })
          );
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([activeJob]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Active network dry-run")).toBeInTheDocument();
    let rendered = view.container.textContent ?? "";
    for (const secret of [
      "http://user:pass@example.com",
      "user:pass",
      "token_should_never_render",
      "super-secret-password",
      "Authorization: Bearer token_should_never_render",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED]");

    fireEvent.click(screen.getByTitle("View job"));
    expect(await screen.findByRole("heading", { name: "Active network dry-run" })).toBeInTheDocument();
    rendered = view.container.textContent ?? "";
    expect(rendered).toContain("url_credentials_rejected");
    expect(rendered).toContain("network requests");
    for (const secret of [
      "http://user:pass@example.com",
      "user:pass",
      "token_should_never_render",
      "super-secret-password",
      "Authorization: Bearer token_should_never_render",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED]");
  });

  it("renders Active HTTP header probe jobs with redacted target table and report payload", async () => {
    const activeJob = {
      id: "job-active-http-legacy-1",
      audit_type: "active_http_header_probe",
      file_id: null,
      target_url: "http://user:pass@example.com/?token=token_should_never_render",
      target_domain: null,
      status: "completed",
      created_at: "2026-05-26T10:23:00Z",
      updated_at: "2026-05-26T10:24:00Z",
      source_file_deleted_at: null,
      summary: {
        target_display: "http://user:pass@example.com/?token=token_should_never_render",
        allowed: true,
        network_requests_sent: 1,
        body_bytes_read: 0,
        redirects_followed: 0
      }
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/jobs/job-active-http-legacy-1")) {
          return Promise.resolve(
            jsonResponse({
              ...activeJob,
              summary: undefined,
              result: {
                analyzer: "active_http_header_probe",
                mode: "live_header_probe",
                profile: "http_header_probe",
                target: {
                  raw: "http://user:pass@example.com/?token=token_should_never_render",
                  password: "super-secret-password"
                },
                authorization: {
                  confirmed: true,
                  live_traffic_confirmed: true,
                  authorization_header: "Authorization: Bearer token_should_never_render"
                },
                policy: {
                  allowed: true,
                  reason: "policy_allowed"
                },
                dns: {
                  answers_count: 1,
                  blocked_answers_count: 0
                },
                request: {
                  method: "HEAD",
                  network_requests_sent: 1
                },
                response: {
                  body_read: false,
                  body_bytes_read: 0,
                  redirects_followed: 0,
                  headers: [
                    { name: "Set-Cookie", value: "session_should_not_render=cookie_should_not_render" },
                    { name: "Authorization", value: "Authorization: Bearer token_should_never_render" },
                    { name: "X-Api-Key", value: "raw-api-key-123456" },
                    { name: "Location", value: "http://user:pass@example.com/?token=token_should_never_render" },
                    { name: "X-Key", value: "-----BEGIN PRIVATE KEY----- fixture -----END PRIVATE KEY-----" }
                  ]
                },
                observations: [{ code: "legacy_observation", evidence: "raw-api-key-123456" }],
                findings: [{ id: "legacy_finding", evidence: "PRIVATE KEY token_should_never_render" }],
                blocked_reasons: [],
                limits: { max_requests: 1, max_redirects: 0, response_body_bytes: 0 },
                audit_log: [{ event: "head_request_completed", raw: "raw-api-key-123456" }],
                errors: ["PASSWORD=super-secret-password"],
                summary: {
                  allowed: true,
                  network_requests_sent: 1,
                  body_bytes_read: 0,
                  redirects_followed: 0
                }
              },
              error: "Authorization: Bearer token_should_never_render"
            })
          );
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([activeJob]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Authorized HTTP header probe")).toBeInTheDocument();
    let rendered = view.container.textContent ?? "";
    for (const secret of [
      "http://user:pass@example.com",
      "user:pass",
      "token_should_never_render",
      "super-secret-password",
      "Authorization: Bearer token_should_never_render",
      "raw-api-key-123456",
      "session_should_not_render",
      "cookie_should_not_render",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED]");

    fireEvent.click(screen.getByTitle("View job"));
    expect(await screen.findByRole("heading", { name: "Authorized HTTP header probe" })).toBeInTheDocument();
    rendered = view.container.textContent ?? "";
    expect(rendered).toContain("One authorized HTTP HEAD request was sent.");
    expect(rendered).toContain("Response body was not read.");
    expect(rendered).toContain("Redirects were not followed.");
    for (const secret of [
      "http://user:pass@example.com",
      "user:pass",
      "token_should_never_render",
      "super-secret-password",
      "Authorization: Bearer token_should_never_render",
      "raw-api-key-123456",
      "session_should_not_render",
      "cookie_should_not_render",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED]");
  });

  it("renders Active Nmap basic jobs with redacted target table, report payload, and no archive action", async () => {
    const activeJob = {
      id: "job-active-nmap-legacy-1",
      audit_type: "active_nmap_basic",
      file_id: null,
      target_url: "192.168.56.10",
      target_domain: null,
      status: "completed",
      created_at: "2026-05-26T10:25:00Z",
      updated_at: "2026-05-26T10:26:00Z",
      source_file_deleted_at: null,
      summary: {
        target_display: "192.168.56.10",
        capability: "active_nmap_basic",
        result_status: "completed",
        observation_count: 1,
        open_tcp_observations_count: 1
      }
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/jobs/job-active-nmap-legacy-1")) {
          return Promise.resolve(
            jsonResponse({
              ...activeJob,
              summary: undefined,
              result: {
                audit_type: "active_nmap_basic",
                capability: "active_nmap_basic",
                mode: "live_nmap_basic",
                profile: "tcp_connect_small",
                status: "completed",
                target: { raw: "192.168.56.10", hostname: "secret-lab.internal" },
                command: "nmap -sT -Pn -n -oX - -p 22,443 -- 192.168.56.10",
                stdout: "stdout with 192.168.56.10 and <nmaprun><host><address addr='192.168.56.10'/></host></nmaprun>",
                stderr: "stderr for secret-lab.internal Authorization: Bearer token_should_never_render",
                raw_xml: "<nmaprun args='nmap -sT 192.168.56.10'><host><ports /></host></nmaprun>",
                port_observations: [{ port: 443, protocol: "tcp", state: "open", reason: "syn-ack" }],
                limits: { output_truncated: false, stderr_truncated: true, timed_out: false },
                legacy: {
                  service_banner: "OpenSSH_9.9 secret-service-banner",
                  notes: "confirmed vulnerability exploitable target is safe all ports found full network scan",
                  headers: { Cookie: "sessionid=secret-session-cookie", Authorization: "Bearer token_should_never_render" },
                  cookies: "sessionid=secret-session-cookie",
                  tokens: ["token_should_never_render"],
                  credentials: { api_key: "raw-api-key-123456" }
                },
                errors: ["nmap -sT 192.168.56.10 failed with token_should_never_render"]
              },
              error: "nmap -sT 192.168.56.10 PRIVATE KEY token_should_never_render"
            })
          );
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([activeJob]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Active Nmap basic")).toBeInTheDocument();
    let rendered = view.container.textContent ?? "";
    for (const secret of [
      "192.168.56.10",
      "secret-lab.internal",
      "nmap -sT",
      "<nmaprun",
      "stdout with",
      "stderr for",
      "OpenSSH_9.9",
      "secret-service-banner",
      "token_should_never_render",
      "sessionid=secret-session-cookie",
      "raw-api-key-123456",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }

    fireEvent.click(screen.getByTitle("View job"));
    expect(await screen.findByRole("heading", { name: "Active / Nmap basic report" })).toBeInTheDocument();
    rendered = view.container.textContent ?? "";
    expect(rendered).toContain("Observed TCP exposure");
    expect(rendered).toContain("Review indicator");
    expect(rendered).toContain("Manual validation required");
    expect(rendered).toContain("No security finding is asserted");
    expect(rendered).toContain("Authorization is user asserted, not proof of ownership");
    expect(rendered).toContain("Raw JSON (redacted)");
    expect(rendered).toContain("443");
    expect(rendered).toContain("syn-ack");
    expect(rendered).not.toContain("exploitable");
    expect(rendered).not.toContain("target is safe");
    expect(rendered).not.toContain("all ports found");
    expect(rendered).not.toContain("full network scan");
    expect(rendered).not.toContain("Analyze archive");
    expect(rendered).not.toContain("Run all recommended passive checks");
    for (const secret of [
      "192.168.56.10",
      "secret-lab.internal",
      "nmap -sT",
      "<nmaprun",
      "stdout with",
      "stderr for",
      "OpenSSH_9.9",
      "secret-service-banner",
      "token_should_never_render",
      "sessionid=secret-session-cookie",
      "raw-api-key-123456",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED");
    expect(
      vi
        .mocked(globalThis.fetch)
        .mock.calls.some(([input]) => String(input).endsWith("/active/network/nmap-basic"))
    ).toBe(false);
  });

  it("groups archive passive actions by category without adding a run-all action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf"));
    expect(archiveRow).toBeDefined();
    expect(archiveRow?.textContent).toContain("Archive reviews are passive and bounded");
    expect(archiveRow?.textContent).toContain("validate credentials");
    expect(archiveRow?.textContent).toContain("query CVEs");
    expect(archiveRow?.textContent).toContain("Start here");
    expect(archiveRow?.textContent).toContain("Secrets");
    expect(archiveRow?.textContent).toContain("Application");
    expect(archiveRow?.textContent).toContain("Container & service wiring");
    expect(archiveRow?.textContent).toContain("Deployment & IaC");
    expect(archiveRow?.textContent).toContain("Web edge");
    expect(archiveRow?.textContent).toContain("Data layer");
    expect(archiveRow?.textContent).not.toContain("Run all recommended passive checks");
    expect(archiveRow?.textContent).not.toContain("Active network dry-run");
    expect(archiveRow?.textContent).not.toContain("Create dry-run plan");
    expect(archiveRow?.textContent).not.toContain("Authorized HTTP Header Probe");
    expect(archiveRow?.textContent).not.toContain("Create authorized header probe job");
    expect(archiveRow?.textContent).not.toContain("Active / Nmap basic");
    expect(archiveRow?.textContent).not.toContain("Create bounded no-live record");
    expect(pdfRow?.textContent).not.toContain("Start here");
    expect(pdfRow?.textContent).not.toContain("Data layer");

    const forbiddenCopy = [
      "compromised",
      "breached",
      "exploitable",
      "confirmed vulnerability",
      "credentials valid",
      "hacked",
      "live exposure confirmed",
      "database exposed",
      "redis exposed"
    ];
    const archiveText = archiveRow?.textContent?.toLowerCase() ?? "";
    for (const phrase of forbiddenCopy) {
      expect(archiveText).not.toContain(phrase);
    }
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

  it("starts a CI/CD config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze CI/CD config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze CI/CD config");
    expect(pdfRow?.textContent).not.toContain("Analyze CI/CD config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze CI/CD config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/ci-cd-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Kubernetes config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Kubernetes config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Kubernetes config");
    expect(pdfRow?.textContent).not.toContain("Analyze Kubernetes config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Kubernetes config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/k8s-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Terraform config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Terraform config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Terraform config");
    expect(pdfRow?.textContent).not.toContain("Analyze Terraform config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Terraform config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/terraform-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Nginx config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Nginx config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Nginx config");
    expect(pdfRow?.textContent).not.toContain("Analyze Nginx config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Nginx config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/nginx-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Compose config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Compose config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Compose config");
    expect(pdfRow?.textContent).not.toContain("Analyze Compose config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Compose config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/compose-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Database config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze database config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze database config");
    expect(pdfRow?.textContent).not.toContain("Analyze database config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze database config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/database-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Redis config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Redis config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Redis config");
    expect(pdfRow?.textContent).not.toContain("Analyze Redis config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Redis config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/redis-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a SQL DB config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze SQL DB config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze SQL DB config");
    expect(pdfRow?.textContent).not.toContain("Analyze SQL DB config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze SQL DB config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/sql-database-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });
});
