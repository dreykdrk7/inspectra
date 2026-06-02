import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { RedisConfigJobReport } from "./RedisConfigJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-redis-1",
  audit_type: "redis_config_basic",
  file_id: "archive-1",
  target_url: null,
  target_domain: null,
  status: "completed",
  created_at: "2026-06-02T10:00:00Z",
  updated_at: "2026-06-02T10:01:00Z",
  source_file_deleted_at: null,
  error: null
} satisfies Omit<JobRecord, "result">;

afterEach(() => {
  cleanup();
});

describe("RedisConfigJobReport", () => {
  it("renders summary, Redis sections, no-read files, findings, limits, errors, and raw JSON", () => {
    const { container } = render(
      <RedisConfigJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "redis_config_basic",
            archive_type: "zip",
            summary: {
              files_considered: 6,
              files_reviewed: 2,
              redis_files_detected: 1,
              sentinel_files_detected: 1,
              acl_files_detected: 1,
              dump_or_aof_files_detected: 2,
              configs_detected: 2,
              findings_count: 2,
              redacted_values_count: 1,
              truncated: true
            },
            limits: { max_files: 100, max_file_bytes: 524288, max_total_bytes: 2097152 },
            files_detected: [
              { path: "deploy/redis/redis.conf", category: "redis", config_type: "redis", read: true, bytes_read: 2048, context: "production" },
              { path: "deploy/redis/sentinel.conf", category: "sentinel", config_type: "sentinel", read: true, bytes_read: 512, context: "production" },
              { path: ".env.production", category: "sensitive_env", read: false, skip_reason: "sensitive_file_not_read", context: "production" }
            ],
            files_reviewed: [
              { path: "deploy/redis/redis.conf", category: "redis", config_type: "redis", read: true, bytes_read: 2048, context: "production" }
            ],
            configs: [
              { path: "deploy/redis/redis.conf", config_type: "redis", context: "production" },
              { path: "deploy/redis/sentinel.conf", config_type: "sentinel", context: "production" }
            ],
            redis_settings: [
              { config_type: "redis", directive: "bind", setting: "bind", value: "0.0.0.0", file_path: "deploy/redis/redis.conf", line: 2, context: "production" },
              { config_type: "redis", directive: "requirepass", setting: "requirepass", value: "[REDACTED]", file_path: "deploy/redis/redis.conf", line: 3, context: "production" }
            ],
            sentinel_settings: [
              { config_type: "sentinel", directive: "sentinel", setting: "sentinel monitor", value: "mymaster 10.0.0.2 6379 2", file_path: "deploy/redis/sentinel.conf", line: 2, context: "production" },
              { config_type: "sentinel", directive: "sentinel", setting: "sentinel auth-pass", value: "[REDACTED]", file_path: "deploy/redis/sentinel.conf", line: 3, context: "production" }
            ],
            includes: [
              { directive: "include", target: "/etc/redis/secrets.conf", resolved: false, file_path: "deploy/redis/redis.conf", config_type: "redis", line: 8, context: "production" }
            ],
            acl_files: [
              { path: "deploy/redis/users.acl", category: "acl", read: false, skip_reason: "acl_file_not_read", size_bytes: 128, context: "production" }
            ],
            dump_or_aof_files: [
              { path: "deploy/redis/dump.rdb", category: "dump_or_aof", read: false, skip_reason: "dump_or_aof_not_read", size_bytes: 4096, context: "production" },
              { path: "deploy/redis/appendonly.aof", category: "dump_or_aof", read: false, skip_reason: "dump_or_aof_not_read", size_bytes: 4096, context: "production" }
            ],
            findings: [
              {
                id: "redis_requirepass_present_redacted",
                title: "Redis requirepass is present",
                level: "medium",
                confidence: "high",
                category: "secrets",
                context: "production",
                config_type: "redis",
                directive: "requirepass",
                setting: "requirepass",
                file_path: "deploy/redis/redis.conf",
                line: 3,
                evidence: "requirepass [REDACTED]",
                recommendation: "Review this setting in the intended deployment context."
              },
              {
                id: "redis_include_not_resolved",
                title: "Redis config include was detected but not resolved",
                level: "low",
                confidence: "high",
                category: "include",
                context: "production",
                directive: "include",
                file_path: "deploy/redis/redis.conf",
                line: 8,
                evidence: "include /etc/redis/secrets.conf"
              }
            ],
            redaction_notes: ["Redis secret-like settings were redacted before storage."],
            errors: ["controlled parser warning"]
          }
        }}
        file={{ id: "archive-1", kind: "archive", original_filename: "redis.zip", stored_filename: "redis.zip", content_type: "application/zip", size_bytes: 100, sha256: "abc", created_at: "2026-06-02T10:00:00Z" }}
      />
    );

    expect(screen.getByRole("heading", { name: "Redis config" })).toBeInTheDocument();
    expect(screen.getAllByText("redis_config_basic").length).toBeGreaterThan(0);
    expect(screen.getByText("Data layer")).toBeInTheDocument();
    expect(screen.getByText("Passive review")).toBeInTheDocument();
    expect(screen.getAllByText(/Findings are heuristic review indicators and require human validation/).length).toBeGreaterThan(0);
    expect(screen.getByText(/Passive static review only/)).toBeInTheDocument();
    expect(screen.getByText(/Review indicators were reported. Validate them manually before acting./)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Redis Settings" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sentinel Settings" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Includes" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "ACL / Dumps / AOF / Backups" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText(/Sensitive adjacent files are detected but not read by v1/)).toBeInTheDocument();
    expect(screen.getByText("no (not resolved by v1)")).toBeInTheDocument();
    expect(screen.getAllByText("no (not read by v1)").length).toBeGreaterThan(0);
    expect(screen.getByText("Redis requirepass is present")).toBeInTheDocument();
    expect(screen.getByText("sentinel auth-pass")).toBeInTheDocument();
    expect(screen.getByText("deploy/redis/users.acl")).toBeInTheDocument();
    expect(screen.getByText("deploy/redis/dump.rdb")).toBeInTheDocument();
    expect(screen.getByText("deploy/redis/appendonly.aof")).toBeInTheDocument();
    expect(screen.getByText("Limits were reached; results may be partial.")).toBeInTheDocument();
    expect(screen.getByText("controlled parser warning")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Redacted Raw JSON" })).toBeInTheDocument();
    expect(screen.getByText("Show redacted payload")).toBeInTheDocument();
    expect(screen.getAllByText(/Sensitive-looking values are redacted in results, exports, and raw JSON/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Redacted values use \[REDACTED\]/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/This does not sanitize the original uploaded file/).length).toBeGreaterThan(0);

    expectControlledCopyHasNoForbiddenWording(container.textContent ?? "");
  });

  it("tolerates sparse, malformed, and failed Redis config payloads", () => {
    render(
      <RedisConfigJobReport
        job={{
          ...baseJob,
          status: "running",
          result: {
            analyzer: "redis_config_basic",
            summary: {},
            findings: [{ id: "sparse" }]
          }
        }}
      />
    );

    expect(screen.getByText(/Passive analysis is running. No external services are contacted for archive config analyzers./)).toBeInTheDocument();
    expect(screen.getByText(/Some result fields are unavailable; showing available redacted data/)).toBeInTheDocument();
    expect(screen.getAllByText("No entries reported for this section.").length).toBeGreaterThan(5);
    expect(screen.getByText("No controlled errors were reported.")).toBeInTheDocument();
    expect(screen.getByText("No redaction notes were reported.")).toBeInTheDocument();
    expect(screen.getAllByText(/Sensitive-looking values are redacted in results, exports, and raw JSON/).length).toBeGreaterThan(0);
    expect(screen.getByText("sparse")).toBeInTheDocument();

    cleanup();

    render(<RedisConfigJobReport job={{ ...baseJob, status: "failed", result: null, error: "controlled failure" }} />);
    expect(screen.getByText("The job failed in a controlled state. Review errors below; uploaded content was not executed.")).toBeInTheDocument();
    expect(screen.getByText("controlled failure")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Redacted Raw JSON" })).toBeInTheDocument();

    cleanup();

    render(<RedisConfigJobReport job={{ ...baseJob, status: "queued", result: { analyzer: "redis_config_basic", summary: {} }, error: null }} />);
    expect(screen.getByText("Job queued. Results will appear when processing starts.")).toBeInTheDocument();
  });

  it("does not describe completed Redis reports with no findings as safe or secure", () => {
    const { container } = render(
      <RedisConfigJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "redis_config_basic",
            summary: { findings_count: 0 },
            findings: []
          }
        }}
      />
    );

    expect(screen.getByText("No heuristic findings were reported for this analyzer.")).toBeInTheDocument();
    const rendered = container.textContent?.toLowerCase() ?? "";
    expect(rendered).not.toContain("safe");
    expect(rendered).not.toContain("secure");
  });

  it("redacts legacy Redis secret-like values in report sections and raw JSON", () => {
    const { container } = render(
      <RedisConfigJobReport
        job={{
          ...baseJob,
          error: "requirepass super-secret-password",
          result: {
            analyzer: "redis_config_basic",
            summary: { redacted_values_count: 0 },
            configs: [{ path: "deploy/redis/redis.conf", content: "requirepass super-secret-password" }],
            redis_settings: [{ setting: "requirepass", value: "super-secret-password" }],
            sentinel_settings: [{ setting: "sentinel auth-pass", value: "token_should_never_render" }],
            includes: [{ target: "/etc/redis/secrets.conf", content: "raw-api-key-123456", resolved: false }],
            acl_files: [{ path: "users.acl", read: false, content: "acl_password_hash_should_not_render" }],
            dump_or_aof_files: [{ path: "dump.rdb", read: false, content: "dump_value_should_not_render" }],
            findings: [
              {
                id: "legacy_redis_secret",
                title: "Legacy Redis secret",
                evidence: "requirepass super-secret-password redis://:super-secret-password@redis:6379/0",
                description: "Authorization: Bearer token_should_never_render",
                recommendation: "-----BEGIN PRIVATE KEY----- fixture -----END PRIVATE KEY-----"
              }
            ],
            errors: [
              "requirepass super-secret-password",
              "raw-api-key-123456",
              "token_should_never_render",
              "acl_password_hash_should_not_render",
              "dump_value_should_not_render",
              "redis://:super-secret-password@redis:6379/0",
              "-----BEGIN PRIVATE KEY-----",
              "PRIVATE KEY"
            ]
          }
        }}
      />
    );

    const rendered = container.textContent ?? "";
    for (const secret of [
      "super-secret-password",
      "raw-api-key-123456",
      "token_should_never_render",
      "acl_password_hash_should_not_render",
      "dump_value_should_not_render",
      "redis://:super-secret-password@redis:6379/0",
      "-----BEGIN PRIVATE KEY-----",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("REDACTED");
    expect(screen.getByRole("heading", { name: "Redacted Raw JSON" })).toBeInTheDocument();
  });
});

function expectControlledCopyHasNoForbiddenWording(text: string) {
  const normalized = text.toLowerCase();
  for (const phrase of [
    "compromised",
    "breached",
    "exploitable",
    "confirmed vulnerability",
    "credentials valid",
    "hacked",
    "live exposure confirmed",
    "database exposed",
    "redis exposed",
    "safe",
    "secure"
  ]) {
    expect(normalized).not.toContain(phrase);
  }
}
