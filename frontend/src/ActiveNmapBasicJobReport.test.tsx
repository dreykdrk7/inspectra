import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ActiveNmapBasicJobReport } from "./ActiveNmapBasicJobReport";
import { buildActiveNmapBasicReport, redactActiveNmapBasicValue } from "./activeNmapBasicReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-active-nmap-1",
  audit_type: "active_nmap_basic",
  file_id: null,
  target_url: "192.168.56.10",
  target_domain: null,
  status: "completed",
  created_at: "2026-05-26T10:00:00Z",
  updated_at: "2026-05-26T10:01:00Z",
  source_file_deleted_at: null,
  error: null
} satisfies Omit<JobRecord, "result">;

const fixtureSecrets = [
  "192.168.56.10",
  "secret-lab.internal",
  "nmap -sT",
  "<nmaprun",
  "stdout with",
  "stderr for",
  "OpenSSH_9.9",
  "secret-service-banner",
  "sessionid=secret-session-cookie",
  "token_should_never_render",
  "Authorization: Bearer token_should_never_render",
  "PRIVATE KEY",
  "raw-api-key-123456"
];

afterEach(() => {
  cleanup();
});

describe("ActiveNmapBasicJobReport", () => {
  it("renders completed open TCP observations as observed exposure review indicators", () => {
    render(
      <ActiveNmapBasicJobReport
        job={{
          ...baseJob,
          result: {
            audit_type: "active_nmap_basic",
            capability: "active_nmap_basic",
            mode: "live_nmap_basic",
            profile: "tcp_connect_small",
            status: "completed",
            port_observations: [
              { port: 443, protocol: "tcp", state: "open", reason: "syn-ack" },
              { port: 22, protocol: "tcp", state: "closed", reason: "reset" }
            ],
            observation_count: 2,
            limits: { output_truncated: false, stderr_truncated: false, timed_out: false },
            parser_warnings: []
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "Active / Nmap basic report" })).toBeInTheDocument();
    expect(screen.getAllByText("Observed TCP exposure / Review indicator").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Manual validation required/).length).toBeGreaterThan(0);
    expect(screen.getByText(/No confirmed vulnerability is asserted/)).toBeInTheDocument();
    expect(screen.getByText(/Authorization is user asserted, not proof of ownership/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Port Observations" })).toBeInTheDocument();
    expect(screen.getByText("443")).toBeInTheDocument();
    expect(screen.getByText("syn-ack")).toBeInTheDocument();
    expect(screen.getByText("22")).toBeInTheDocument();
    expect(screen.getByText("reset")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Raw JSON (redacted)" })).toBeInTheDocument();
    expect(screen.getByText("Show redacted Raw JSON")).toBeInTheDocument();
  });

  it("renders closed and filtered states conservatively", () => {
    render(
      <ActiveNmapBasicJobReport
        job={{
          ...baseJob,
          result: {
            capability: "active_nmap_basic",
            status: "completed",
            port_observations: [
              { port: 80, protocol: "tcp", state: "filtered", reason: "no-response" },
              { port: 25, protocol: "tcp", state: "closed|filtered", reason: "admin-prohibited" }
            ],
            limits: { output_truncated: false }
          }
        }}
      />
    );

    expect(screen.getByText("filtered")).toBeInTheDocument();
    expect(screen.getByText("closed|filtered")).toBeInTheDocument();
    expect(screen.getAllByText("Conservative TCP state / Review indicator")).toHaveLength(2);
    expect(screen.queryByText(/high severity/i)).not.toBeInTheDocument();
  });

  it("renders controlled failed, timeout, missing, malformed, truncated, no-ports, and sparse states", () => {
    const states = ["failed", "timed_out", "nmap_missing", "malformed", "truncated", "no_ports"] as const;

    for (const state of states) {
      const { unmount } = render(
        <ActiveNmapBasicJobReport
          job={{
            ...baseJob,
            status: state === "failed" ? "failed" : "completed",
            result: {
              capability: "active_nmap_basic",
              status: state,
              port_observations: [],
              limits: { output_truncated: state === "truncated", timed_out: state === "timed_out" },
              errors: [{ message: "nmap -sT 192.168.56.10 failed with token_should_never_render" }]
            },
            error: state === "failed" ? "PRIVATE KEY token_should_never_render" : null
          }}
        />
      );
      expect(screen.getAllByText(new RegExp(state)).length).toBeGreaterThan(0);
      expect(screen.getByText("No TCP port observations were returned. Manual validation required.")).toBeInTheDocument();
      expect(screen.getByRole("heading", { name: "Raw JSON (redacted)" })).toBeInTheDocument();
      unmount();
    }

    render(<ActiveNmapBasicJobReport job={{ ...baseJob, result: { capability: "active_nmap_basic" } }} />);
    expect(screen.getByText(/Sparse active_nmap_basic payload|Controlled active_nmap_basic state/)).toBeInTheDocument();
  });

  it("redacts raw target, command, XML, stdout, stderr, headers, cookies, tokens, credentials, and legacy claims", () => {
    const { container } = render(
      <ActiveNmapBasicJobReport
        job={{
          ...baseJob,
          target_url: "192.168.56.10",
          error: "nmap -sT 192.168.56.10 PRIVATE KEY token_should_never_render",
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
          }
        }}
      />
    );

    const rendered = container.textContent ?? "";
    for (const secret of fixtureSecrets) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED");
    expect(screen.getByText(/No confirmed vulnerability is asserted/)).toBeInTheDocument();
    expect(rendered).not.toContain("exploitable");
    expect(rendered).not.toContain("target is safe");
    expect(rendered).not.toContain("all ports found");
    expect(rendered).not.toContain("full network scan");
    expect(screen.queryByLabelText(/raw flags/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/run-all/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Analyze archive/i)).not.toBeInTheDocument();
  });

  it("exposes a pure report helper with defensive Raw JSON redaction", () => {
    const report = buildActiveNmapBasicReport({
      ...baseJob,
      result: {
        capability: "active_nmap_basic",
        status: "completed",
        target: "secret-lab.internal",
        raw_command: "nmap -sT -- secret-lab.internal",
        raw_xml: "<nmaprun><host /></nmaprun>",
        port_observations: [{ port: 8080, protocol: "tcp", state: "open", reason: "syn-ack" }]
      }
    });
    const redacted = JSON.stringify(redactActiveNmapBasicValue(report), null, 2);

    expect(report.isActiveNmapBasic).toBe(true);
    expect(report.observations[0]).toMatchObject({ port: 8080, protocol: "tcp", state: "open" });
    expect(report.rawJson).not.toContain("secret-lab.internal");
    expect(report.rawJson).not.toContain("nmap -sT");
    expect(report.rawJson).not.toContain("<nmaprun");
    expect(redacted).not.toContain("secret-lab.internal");
  });
});
