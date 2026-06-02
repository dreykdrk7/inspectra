import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { DatabaseConfigJobReport } from "./DatabaseConfigJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-database-1",
  audit_type: "database_config_basic",
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

describe("DatabaseConfigJobReport", () => {
  it("renders summary, Database sections, findings, limits, errors, and raw JSON", () => {
    render(
      <DatabaseConfigJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "database_config_basic",
            archive_type: "zip",
            summary: {
              files_considered: 8,
              files_reviewed: 3,
              database_files_detected: 4,
              postgres_files_detected: 2,
              mysql_files_detected: 1,
              mariadb_files_detected: 1,
              pg_hba_files_detected: 1,
              dump_or_backup_files_detected: 3,
              engines_detected: 2,
              findings_count: 2,
              redacted_values_count: 1,
              truncated: true
            },
            limits: { max_files: 100, max_file_bytes: 524288, max_total_bytes: 2097152 },
            files_detected: [
              { path: "db/postgres/postgresql.conf", category: "postgres_config", read: true, bytes_read: 2048, context: "production" },
              { path: ".env.production", category: "database_sensitive_env", read: false, skip_reason: "sensitive_file_not_read", context: "production" },
              { path: ".pgpass", category: "database_client_credentials", read: false, skip_reason: "credential_file_not_read", context: "production" }
            ],
            files_reviewed: [
              { path: "db/postgres/postgresql.conf", category: "postgres_config", read: true, bytes_read: 2048, context: "production" }
            ],
            engines: [{ engine: "postgresql", file_path: "db/postgres/postgresql.conf", context: "production", files_count: 2 }],
            postgres_settings: [
              { engine: "postgresql", setting: "listen_addresses", value: "*", file_path: "db/postgres/postgresql.conf", line: 3, context: "production" }
            ],
            pg_hba_rules: [
              { type: "host", database: "all", user: "all", address: "0.0.0.0/0", auth_method: "trust", file_path: "db/postgres/pg_hba.conf", line: 5, context: "production" }
            ],
            mysql_settings: [
              { engine: "mysql", section: "mysqld", setting: "bind-address", value: "0.0.0.0", file_path: "db/mysql/my.cnf", line: 8, context: "production" }
            ],
            includes: [
              { directive: "include", target: "/etc/postgresql/secret.conf", resolved: false, file_path: "db/postgres/postgresql.conf", engine: "postgresql", line: 10, context: "production" }
            ],
            dump_or_backup_files: [
              { path: "backups/prod.sql", category: "database_dump", read: false, skip_reason: "dump_not_read", size_bytes: 4096, context: "production" },
              { path: ".my.cnf", category: "database_client_credentials", read: false, skip_reason: "credential_file_not_read", context: "production" }
            ],
            findings: [
              {
                id: "postgres_pg_hba_trust_auth",
                title: "pg_hba.conf allows trust authentication",
                level: "medium",
                confidence: "high",
                category: "auth",
                context: "production",
                engine: "postgresql",
                auth_method: "trust",
                address: "0.0.0.0/0",
                file_path: "db/postgres/pg_hba.conf",
                line: 5,
                evidence: "host all all 0.0.0.0/0 trust",
                recommendation: "Review whether trust authentication is appropriate."
              },
              {
                id: "database_dump_or_backup_file_present",
                title: "Database dump or backup file detected",
                level: "info",
                category: "sensitive-files",
                file_path: "backups/prod.sql",
                evidence: "path=backups/prod.sql read=false"
              }
            ],
            redaction_notes: ["Database credential-adjacent files are detected but not read."],
            errors: ["controlled parser warning"]
          }
        }}
        file={{ id: "archive-1", kind: "archive", original_filename: "database.zip", stored_filename: "database.zip", content_type: "application/zip", size_bytes: 100, sha256: "abc", created_at: "2026-05-26T10:00:00Z" }}
      />
    );

    expect(screen.getByRole("heading", { name: "General Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Engines Detected" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "PostgreSQL Settings" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "pg_hba.conf Rules" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "MySQL / MariaDB Settings" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Includes" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Dumps / Backups and Credential Files" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText(/Passive archive-only database config review/)).toBeInTheDocument();
    expect(screen.getAllByText(/not read by v1/).length).toBeGreaterThan(0);
    expect(screen.getByText("no (not resolved by v1)")).toBeInTheDocument();
    expect(screen.getByText("pg_hba.conf allows trust authentication")).toBeInTheDocument();
    expect(screen.getByText("listen_addresses")).toBeInTheDocument();
    expect(screen.getByText("bind-address")).toBeInTheDocument();
    expect(screen.getAllByText(".env.production").length).toBeGreaterThan(0);
    expect(screen.getAllByText(".my.cnf").length).toBeGreaterThan(0);
    expect(screen.getAllByText("backups/prod.sql").length).toBeGreaterThan(0);
    expect(screen.getByText("Analysis truncated by configured Database config limits. Review skipped files and rerun with a smaller archive if needed.")).toBeInTheDocument();
    expect(screen.getByText("controlled parser warning")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("tolerates sparse, malformed, and running style Database config payloads", () => {
    render(
      <DatabaseConfigJobReport
        job={{
          ...baseJob,
          status: "running",
          result: {
            analyzer: "database_config_basic",
            summary: {},
            findings: [{ id: "sparse" }]
          }
        }}
      />
    );

    expect(screen.getByText("No database engines returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No PostgreSQL settings returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No pg_hba.conf rules returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No MySQL or MariaDB settings returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No database include directives returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No database dumps, backups, or credential files returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Database config limits returned yet.")).toBeInTheDocument();
    expect(screen.getByText("sparse")).toBeInTheDocument();

    cleanup();

    render(<DatabaseConfigJobReport job={{ ...baseJob, status: "failed", result: null, error: "controlled failure" }} />);
    expect(screen.getByText("controlled failure")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("redacts legacy Database secret-like values in report sections and raw JSON", () => {
    const { container } = render(
      <DatabaseConfigJobReport
        job={{
          ...baseJob,
          error: "PGPASSWORD=super-secret-password",
          result: {
            analyzer: "database_config_basic",
            summary: { redacted_values_count: 0 },
            engines: [{ engine: "postgresql", content: "raw-db-password-123456" }],
            postgres_settings: [{ setting: "password_encryption", value: "super-secret-password" }],
            pg_hba_rules: [{ content: "postgres://user:pass@example.com/db", auth_method: "trust" }],
            mysql_settings: [{ setting: "MYSQL_PWD", value: "super-secret-password" }],
            includes: [{ target: "/etc/postgresql/secret.conf", content: "replication_password_should_not_render" }],
            dump_or_backup_files: [{ path: "backup.sql", read: false, content: "db_password_plaintext" }],
            findings: [
              {
                id: "legacy_database_secret",
                title: "Legacy Database secret",
                evidence: "postgres://user:pass@example.com/db",
                description: "MYSQL_PWD=super-secret-password",
                recommendation: "raw-db-password-123456 replication_password_should_not_render"
              }
            ],
            errors: ["PGPASSWORD=super-secret-password", "mysql://user:pass@example.com/db", "-----BEGIN PRIVATE KEY-----", "db_password_plaintext"]
          }
        }}
      />
    );

    const rendered = container.textContent ?? "";
    for (const secret of [
      "super-secret-password",
      "raw-db-password-123456",
      "postgres://user:pass@example.com/db",
      "mysql://user:pass@example.com/db",
      "replication_password_should_not_render",
      "PGPASSWORD=super-secret-password",
      "MYSQL_PWD=super-secret-password",
      "db_password_plaintext",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("REDACTED");
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });
});
