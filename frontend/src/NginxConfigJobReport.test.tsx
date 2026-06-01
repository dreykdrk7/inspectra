import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { NginxConfigJobReport } from "./NginxConfigJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-nginx-1",
  audit_type: "nginx_config_basic",
  file_id: "archive-1",
  target_url: null,
  target_domain: null,
  status: "completed",
  created_at: "2026-05-26T10:00:00Z",
  updated_at: "2026-05-26T10:01:00Z",
  source_file_deleted_at: null,
  error: null
} satisfies Omit<JobRecord, "result">;

afterEach(() => {
  cleanup();
});

describe("NginxConfigJobReport", () => {
  it("renders summary, Nginx sections, includes, findings, limits, errors, and raw JSON", () => {
    render(
      <NginxConfigJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "nginx_config_basic",
            archive_type: "zip",
            summary: {
              files_considered: 4,
              files_reviewed: 2,
              nginx_files_detected: 2,
              server_blocks_detected: 1,
              location_blocks_detected: 2,
              upstream_blocks_detected: 1,
              includes_detected: 2,
              tls_servers_detected: 1,
              findings_count: 2,
              redacted_values_count: 1,
              truncated: true
            },
            limits: { max_files: 100, max_file_bytes: 524288, max_total_bytes: 2097152 },
            files_detected: [
              { path: "deploy/nginx/default.conf", category: "nginx_config", read: true, bytes_read: 2048, context: "production" },
              { path: "deploy/nginx/conf.d/app.conf", category: "nginx_config", read: true, bytes_read: 512, context: "production" }
            ],
            files_reviewed: [
              { path: "deploy/nginx/default.conf", category: "nginx_config", read: true, bytes_read: 2048, context: "production" }
            ],
            servers: [
              {
                path: "deploy/nginx/default.conf",
                context: "production",
                line: 1,
                server_name: "example.com",
                listen: ["80 default_server", "443 ssl"],
                tls: true
              }
            ],
            locations: [
              { path: "deploy/nginx/default.conf", context: "production", line: 20, location: "/api", server_name: "example.com" },
              { path: "deploy/nginx/default.conf", context: "production", line: 28, location: "/.git", server_name: "example.com" }
            ],
            upstreams: [{ path: "deploy/nginx/default.conf", context: "production", line: 40, name: "backend" }],
            includes: [
              { path: "deploy/nginx/default.conf", context: "production", line: 8, target: "/etc/nginx/snippets/tls.conf", absolute: true, glob: false, resolved: false },
              { path: "deploy/nginx/default.conf", context: "production", line: 9, target: "conf.d/*.conf", absolute: false, glob: true, resolved: false }
            ],
            directives: [
              {
                path: "deploy/nginx/default.conf",
                context: "production",
                line: 22,
                directive: "proxy_pass",
                arguments: "http://[REDACTED]@example.com",
                block_type: "location",
                server_name: "example.com",
                location: "/api"
              },
              {
                path: "deploy/nginx/default.conf",
                context: "production",
                line: 23,
                directive: "proxy_set_header",
                arguments: "Host $host",
                block_type: "location",
                server_name: "example.com",
                location: "/api"
              }
            ],
            findings: [
              {
                id: "nginx_proxy_pass_credentials_hint",
                title: "Nginx proxy_pass URL contains credentials",
                level: "medium",
                confidence: "high",
                category: "secrets",
                context: "production",
                block_type: "location",
                server_name: "example.com",
                location: "/api",
                directive: "proxy_pass",
                file_path: "deploy/nginx/default.conf",
                line: "22",
                evidence: "proxy_pass=[REDACTED]",
                recommendation: "Move upstream credentials out of committed proxy URLs."
              },
              {
                id: "nginx_include_not_resolved",
                title: "Nginx include was detected but not resolved",
                level: "low",
                confidence: "high",
                category: "include",
                context: "production",
                directive: "include",
                file_path: "deploy/nginx/default.conf",
                line: "8",
                evidence: "include=/etc/nginx/snippets/tls.conf"
              }
            ],
            redaction_notes: ["Nginx include directives are detected but not resolved by this analyzer."],
            errors: ["controlled parser warning"]
          }
        }}
        file={{ id: "archive-1", kind: "archive", original_filename: "nginx.zip", stored_filename: "nginx.zip", content_type: "application/zip", size_bytes: 100, sha256: "abc", created_at: "2026-05-26T10:00:00Z" }}
      />
    );

    expect(screen.getByRole("heading", { name: "General Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Server Blocks" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Locations" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Upstreams / Proxy Targets" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Includes" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Directives" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText(/Passive archive-only Nginx web-edge config review/)).toBeInTheDocument();
    expect(screen.getByText(/Includes are detected but not resolved/)).toBeInTheDocument();
    expect(screen.getByText("Nginx proxy_pass URL contains credentials")).toBeInTheDocument();
    expect(screen.getAllByText("production").length).toBeGreaterThan(0);
    expect(screen.getAllByText("no (not resolved by v1)").length).toBeGreaterThan(0);
    expect(screen.getByText("Analysis truncated by configured Nginx config limits. Review skipped files and rerun with a smaller archive if needed.")).toBeInTheDocument();
    expect(screen.getByText("controlled parser warning")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("tolerates sparse, malformed, and running style Nginx config payloads", () => {
    render(
      <NginxConfigJobReport
        job={{
          ...baseJob,
          status: "running",
          result: {
            analyzer: "nginx_config_basic",
            summary: {},
            findings: [{ id: "sparse" }]
          }
        }}
      />
    );

    expect(screen.getByText("No Nginx server blocks returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Nginx locations returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Nginx upstream blocks returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Nginx includes returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Nginx config limits returned yet.")).toBeInTheDocument();
    expect(screen.getByText("sparse")).toBeInTheDocument();

    cleanup();

    render(<NginxConfigJobReport job={{ ...baseJob, status: "failed", result: null, error: "controlled failure" }} />);
    expect(screen.getByText("controlled failure")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("redacts legacy Nginx secret-like values in report sections and raw JSON", () => {
    const { container } = render(
      <NginxConfigJobReport
        job={{
          ...baseJob,
          error: "Authorization: Bearer token_should_never_render",
          result: {
            analyzer: "nginx_config_basic",
            summary: { redacted_values_count: 0 },
            servers: [{ server_name: "example.com", password: "super-secret-password" }],
            locations: [{ location: "/api", proxy_pass: "http://user:pass@example.com" }],
            upstreams: [{ name: "backend", url: "http://registry-user:registry-pass@upstream.example.test" }],
            includes: [{ target: "/etc/nginx/secrets.conf", content: "raw-api-key-123456", resolved: false }],
            directives: [
              { directive: "proxy_pass", arguments: "http://user:pass@example.com" },
              { directive: "proxy_set_header", arguments: "Authorization: Bearer token_should_never_render" },
              { directive: "set", arguments: "$api_key raw-api-key-123456" },
              { directive: "set", arguments: "$proxy_password proxy_password_should_not_render" }
            ],
            findings: [
              {
                id: "legacy_nginx_secret",
                title: "Legacy Nginx secret",
                evidence: "proxy_pass http://user:pass@example.com",
                description: "Authorization: Bearer token_should_never_render",
                recommendation: "-----BEGIN PRIVATE KEY----- fixture -----END PRIVATE KEY-----"
              }
            ],
            errors: ["PASSWORD=super-secret-password", "http://user:pass@example.com", "registry-user:registry-pass", "sessionid=secret-session-cookie"]
          }
        }}
      />
    );

    const rendered = container.textContent ?? "";
    for (const secret of [
      "super-secret-password",
      "raw-api-key-123456",
      "token_should_never_render",
      "Authorization: Bearer token_should_never_render",
      "http://user:pass@example.com",
      "registry-user:registry-pass",
      "sessionid=secret-session-cookie",
      "proxy_password_should_not_render",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("REDACTED");
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });
});
