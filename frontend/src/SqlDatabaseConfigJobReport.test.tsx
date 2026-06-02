import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { SqlDatabaseConfigJobReport } from "./SqlDatabaseConfigJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-sql-db-1",
  audit_type: "sql_database_config_basic",
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

describe("SqlDatabaseConfigJobReport", () => {
  it("renders summary, SQL DB sections, no-read files, findings, limits, errors, and raw JSON", () => {
    const { container } = render(
      <SqlDatabaseConfigJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "sql_database_config_basic",
            archive_type: "zip",
            summary: {
              files_considered: 9,
              files_reviewed: 3,
              postgres_configs_detected: 1,
              postgres_hba_files_detected: 1,
              mysql_configs_detected: 1,
              mariadb_configs_detected: 1,
              dump_or_backup_files_detected: 1,
              data_files_detected: 1,
              sensitive_files_detected: 2,
              findings_count: 2,
              redacted_values_count: 1,
              truncated: true
            },
            limits: { max_files: 100, max_file_bytes: 524288, max_total_bytes: 2097152 },
            files_detected: [
              { path: "db/postgres/postgresql.conf", category: "postgres", engine: "postgresql", read: true, bytes_read: 2048, context: "production" },
              { path: "db/mysql/my.cnf", category: "mysql", engine: "mysql", read: true, bytes_read: 1024, context: "production" },
              { path: ".pgpass", category: "client_credentials", read: false, skip_reason: "credential_file_not_read", context: "production" }
            ],
            files_reviewed: [
              { path: "db/postgres/postgresql.conf", category: "postgres", engine: "postgresql", read: true, bytes_read: 2048, context: "production" }
            ],
            postgres_configs: [
              { file_path: "db/postgres/postgresql.conf", category: "postgres", engine: "postgresql", context: "production", read: true, bytes_read: 2048, settings_count: 2 }
            ],
            postgres_hba_rules: [
              { type: "host", database: "all", user: "all", address: "0.0.0.0/0", auth_method: "trust", file_path: "db/postgres/pg_hba.conf", line: 5, context: "production" }
            ],
            mysql_configs: [
              { file_path: "db/mysql/my.cnf", category: "mysql", engine: "mysql", context: "production", read: true, bytes_read: 1024, settings_count: 2 }
            ],
            database_settings: [
              { engine: "postgresql", setting: "listen_addresses", value: "*", file_path: "db/postgres/postgresql.conf", line: 3, context: "production" },
              { engine: "postgresql", setting: "password_encryption", value: "scram-sha-256", file_path: "db/postgres/postgresql.conf", line: 4, context: "production" },
              { engine: "mysql", section: "mysqld", setting: "bind-address", value: "0.0.0.0", file_path: "db/mysql/my.cnf", line: 8, context: "production" }
            ],
            includes: [
              { directive: "include", target: "/etc/postgresql/secret.conf", resolved: false, file_path: "db/postgres/postgresql.conf", engine: "postgresql", line: 10, context: "production" }
            ],
            sensitive_files: [
              { path: ".pgpass", category: "client_credentials", read: false, skip_reason: "credential_file_not_read", size_bytes: 128, context: "production" },
              { path: ".my.cnf", category: "client_credentials", read: false, skip_reason: "credential_file_not_read", size_bytes: 128, context: "production" }
            ],
            dump_or_backup_files: [
              { path: "backups/prod.sql", category: "database_dump", read: false, skip_reason: "dump_not_read", size_bytes: 4096, context: "production" }
            ],
            data_files: [
              { path: "db/postgres/pg_wal/0001", category: "database_data", read: false, skip_reason: "data_file_not_read", size_bytes: 4096, context: "production" }
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
                id: "sql_database_dump_or_backup_present_no_read",
                title: "Database dump or backup file detected",
                level: "info",
                category: "sensitive-files",
                file_path: "backups/prod.sql",
                evidence: "path=backups/prod.sql read=false"
              }
            ],
            redaction_notes: ["SQL database credential-adjacent files are detected but not read."],
            errors: ["controlled parser warning"]
          }
        }}
        file={{
          id: "archive-1",
          kind: "archive",
          original_filename: "sql-db.zip",
          stored_filename: "sql-db.zip",
          content_type: "application/zip",
          size_bytes: 100,
          sha256: "abc",
          created_at: "2026-06-02T10:00:00Z"
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "SQL DB config" })).toBeInTheDocument();
    expect(screen.getAllByText("sql_database_config_basic").length).toBeGreaterThan(0);
    expect(screen.getByText("Data layer")).toBeInTheDocument();
    expect(screen.getByText("Passive review")).toBeInTheDocument();
    expect(screen.getAllByText(/Findings are heuristic review indicators and require human validation/).length).toBeGreaterThan(0);
    expect(screen.getByText(/Passive static review only/)).toBeInTheDocument();
    expect(screen.getByText(/Review indicators were reported. Validate them manually before acting./)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Engine / Config Overview" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "PostgreSQL Configs" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "PostgreSQL pg_hba.conf Rules" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "MySQL / MariaDB Configs" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Database Settings" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Includes Detected / Not Resolved" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sensitive Files Detected / Not Read" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Dumps / Backups Detected / Not Read" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Data / WAL / Binlog / InnoDB Files Detected / Not Read" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText("no (not resolved by v1)")).toBeInTheDocument();
    expect(screen.getAllByText("no (not read by v1)").length).toBeGreaterThan(0);
    expect(screen.getByText("pg_hba.conf allows trust authentication")).toBeInTheDocument();
    expect(screen.getByText("password_encryption")).toBeInTheDocument();
    expect(screen.getByText("scram-sha-256")).toBeInTheDocument();
    expect(screen.getAllByText(".pgpass").length).toBeGreaterThan(0);
    expect(screen.getAllByText(".my.cnf").length).toBeGreaterThan(0);
    expect(screen.getAllByText("backups/prod.sql").length).toBeGreaterThan(0);
    expect(screen.getByText("db/postgres/pg_wal/0001")).toBeInTheDocument();
    expect(screen.getByText("controlled parser warning")).toBeInTheDocument();
    expect(screen.getByText("Limits were reached; results may be partial.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Redacted Raw JSON" })).toBeInTheDocument();
    expect(screen.getByText("Show redacted payload")).toBeInTheDocument();
    expect(screen.getAllByText(/Sensitive-looking values are redacted in results, exports, and raw JSON/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Redacted values use \[REDACTED\]/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/This does not sanitize the original uploaded file/).length).toBeGreaterThan(0);

    expectControlledCopyHasNoForbiddenWording(container.textContent ?? "");
  });

  it("tolerates sparse, malformed, and failed SQL database config payloads", () => {
    render(
      <SqlDatabaseConfigJobReport
        job={{
          ...baseJob,
          status: "running",
          result: {
            analyzer: "sql_database_config_basic",
            summary: {},
            findings: [{ id: "sparse" }]
          }
        }}
      />
    );

    expect(screen.getByText(/Passive analysis is running. No external services are contacted for archive config analyzers./)).toBeInTheDocument();
    expect(screen.getByText(/Some result fields are unavailable; showing available redacted data/)).toBeInTheDocument();
    expect(screen.getAllByText("No entries reported for this section.").length).toBeGreaterThan(8);
    expect(screen.getByText("No controlled errors were reported.")).toBeInTheDocument();
    expect(screen.getByText("No redaction notes were reported.")).toBeInTheDocument();
    expect(screen.getAllByText(/Sensitive-looking values are redacted in results, exports, and raw JSON/).length).toBeGreaterThan(0);
    expect(screen.getByText("sparse")).toBeInTheDocument();

    cleanup();

    render(<SqlDatabaseConfigJobReport job={{ ...baseJob, status: "failed", result: null, error: "controlled failure" }} />);
    expect(screen.getByText("The job failed in a controlled state. Review errors below; uploaded content was not executed.")).toBeInTheDocument();
    expect(screen.getByText("controlled failure")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Redacted Raw JSON" })).toBeInTheDocument();

    cleanup();

    render(<SqlDatabaseConfigJobReport job={{ ...baseJob, status: "queued", result: { analyzer: "sql_database_config_basic", summary: {} }, error: null }} />);
    expect(screen.getByText("Job queued. Results will appear when processing starts.")).toBeInTheDocument();
  });

  it("does not describe completed SQL database reports with no findings as safe or secure", () => {
    const { container } = render(
      <SqlDatabaseConfigJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "sql_database_config_basic",
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

  it("redacts legacy SQL database secret-like values in report sections and raw JSON", () => {
    const { container } = render(
      <SqlDatabaseConfigJobReport
        job={{
          ...baseJob,
          error: "PGPASSWORD=super-secret-password",
          result: {
            analyzer: "sql_database_config_basic",
            summary: { redacted_values_count: 0 },
            postgres_configs: [{ file_path: "postgresql.conf", content: "postgres://user:pass@example.com/db" }],
            postgres_hba_rules: [{ user: "all", database: "all", address: "0.0.0.0/0", auth_method: "trust", content: "db_password_plaintext" }],
            mysql_configs: [{ file_path: "my.cnf", content: "raw-db-password-123456" }],
            database_settings: [
              { setting: "primary_conninfo", value: "postgres://user:pass@example.com/db" },
              { setting: "password_encryption", value: "password encryption is weak" }
            ],
            includes: [{ target: "/etc/postgresql/secret.conf", content: "replication_password_should_not_render" }],
            sensitive_files: [{ path: ".pgpass", read: false, content: "pgpass_secret_should_not_render" }],
            dump_or_backup_files: [{ path: "backup.sql", read: false, content: "dump_row_secret_should_not_render" }],
            data_files: [{ path: "pg_wal/0001", read: false, content: "db_password_plaintext" }],
            findings: [
              {
                id: "legacy_sql_database_secret",
                title: "password encryption is weak",
                evidence: "mysql://user:pass@example.com/db",
                description: "MYSQL_PWD=super-secret-password",
                recommendation: "raw-db-password-123456 replication_password_should_not_render"
              }
            ],
            errors: [
              "PGPASSWORD=super-secret-password",
              "mysql://user:pass@example.com/db",
              "-----BEGIN PRIVATE KEY-----",
              "db_password_plaintext",
              "dump_row_secret_should_not_render",
              "pgpass_secret_should_not_render",
              "mycnf_secret_should_not_render"
            ]
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
      "dump_row_secret_should_not_render",
      "pgpass_secret_should_not_render",
      "mycnf_secret_should_not_render",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED]");
    expect(rendered).toContain("password encryption is weak");
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
