import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ActiveTlsBasicJobReport } from "./ActiveTlsBasicJobReport";
import { buildActiveTlsBasicReport, redactActiveTlsBasicValue } from "./activeTlsBasicReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-active-tls-1",
  audit_type: "active_tls_basic",
  file_id: null,
  target_url: "service.local",
  target_domain: null,
  status: "completed",
  created_at: "2026-06-14T10:00:00Z",
  updated_at: "2026-06-14T10:01:00Z",
  source_file_deleted_at: null,
  error: null
} satisfies Omit<JobRecord, "result">;

const fixtureSecrets = [
  "service.local",
  "192.168.56.10",
  "-----BEGIN CERTIFICATE-----",
  "raw_der_should_not_render",
  "raw_exception_should_not_render",
  "token_should_never_render",
  "Authorization: Bearer token_should_never_render",
  "sessionid=secret-session-cookie",
  "raw-api-key-123456",
  "PRIVATE KEY"
];

afterEach(() => {
  cleanup();
});

describe("ActiveTlsBasicJobReport", () => {
  it("renders handshake and certificate expiry review indicators with bounded fields", () => {
    render(
      <ActiveTlsBasicJobReport
        job={{
          ...baseJob,
          target_url: "[REDACTED_TARGET]",
          result: {
            audit_type: "active_tls_basic",
            capability: "active_tls_basic",
            mode: "live_tls_basic",
            profile: "tls_handshake_summary",
            status: "handshake_succeeded",
            result_status: "handshake_succeeded",
            target: "[REDACTED_TARGET]",
            port: 443,
            handshake: { status: "succeeded", protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384" },
            certificate: {
              available: true,
              subject: "commonName=[REDACTED_TARGET]",
              issuer: "commonName=Inspectra Test CA",
              san_count: 2,
              san_sample: [
                { type: "DNS", value: "[REDACTED_SAN]" },
                { type: "IP Address", value: "[REDACTED_SAN]" }
              ],
              not_before: "2026-01-01T00:00:00Z",
              not_after: "2026-01-31T00:00:00Z",
              days_until_expiry: 30
            },
            execution: { tls_handshake_attempted: true, network_requests_sent: 1, http_requests_sent: 0 },
            limits: { raw_certificate_persisted: false, raw_target_persisted: false, handshake_timeout_seconds: 3 },
            reason_codes: []
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "Active / TLS basic report" })).toBeInTheDocument();
    expect(screen.getAllByText(/TLS handshake review indicator/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Certificate expiry review indicator/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Manual validation required/).length).toBeGreaterThan(0);
    expect(screen.getByText(/No security finding is asserted/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "TLS Handshake Review Indicator" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Certificate Expiry Review Indicator" })).toBeInTheDocument();
    expect(screen.getAllByText("TLSv1.3").length).toBeGreaterThan(0);
    expect(screen.getAllByText("TLS_AES_256_GCM_SHA384").length).toBeGreaterThan(0);
    expect(screen.getByText("commonName=[REDACTED_TARGET]")).toBeInTheDocument();
    expect(screen.getByText("commonName=Inspectra Test CA")).toBeInTheDocument();
    expect(screen.getAllByText("30").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Raw JSON (redacted)" })).toBeInTheDocument();
  });

  it("renders controlled TLS states without target or exception details", () => {
    for (const status of ["timed_out", "handshake_failed", "certificate_unavailable", "tls_error_controlled"] as const) {
      const { container, unmount } = render(
        <ActiveTlsBasicJobReport
          job={{
            ...baseJob,
            status: "failed",
            result: {
              audit_type: "active_tls_basic",
              capability: "active_tls_basic",
              status,
              result_status: status,
              target: "service.local",
              port: 443,
              handshake: { status, protocol: null, cipher: null },
              certificate: {
                available: false,
                subject: null,
                issuer: null,
                san_count: 0,
                san_sample: [],
                not_before: null,
                not_after: null,
                days_until_expiry: null
              },
              reason_codes: ["unexpected_tls_error"],
              errors: [{ code: "unexpected_tls_error", raw_exception: "raw_exception_should_not_render service.local" }]
            },
            error: "raw_exception_should_not_render service.local token_should_never_render"
          }}
        />
      );
      const rendered = container.textContent ?? "";
      expect(rendered).toContain(status);
      expect(rendered).toContain("controlled");
      expect(rendered).toContain("No target details are shown");
      expect(rendered).not.toContain("service.local");
      expect(rendered).not.toContain("raw_exception_should_not_render");
      expect(rendered).not.toContain("token_should_never_render");
      unmount();
    }
  });

  it("redacts raw target, PEM/DER material, raw exceptions, credentials, headers, cookies, and tokens", () => {
    const { container } = render(
      <ActiveTlsBasicJobReport
        job={{
          ...baseJob,
          target_url: "service.local",
          error: "service.local raw_exception_should_not_render PRIVATE KEY token_should_never_render",
          result: {
            audit_type: "active_tls_basic",
            capability: "active_tls_basic",
            mode: "live_tls_basic",
            profile: "tls_handshake_summary",
            status: "handshake_succeeded",
            result_status: "handshake_succeeded",
            target: { raw: "service.local", ip: "192.168.56.10" },
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
            legacy: {
              raw_exception: "raw_exception_should_not_render",
              headers: { Authorization: "Bearer token_should_never_render" },
              cookies: "sessionid=secret-session-cookie",
              tokens: ["token_should_never_render"],
              credentials: { api_key: "raw-api-key-123456" },
              notes: "confirmed vulnerability exploitable target is safe all certs found full scan public scanner"
            },
            errors: ["service.local failed with token_should_never_render"]
          }
        }}
      />
    );

    const rendered = container.textContent ?? "";
    for (const secret of fixtureSecrets) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED");
    expect(screen.getByText(/No security finding is asserted/)).toBeInTheDocument();
    expect(rendered).not.toMatch(/confirmed\s+vulnerability/i);
    expect(rendered).not.toMatch(/exploitable/i);
    expect(rendered).not.toMatch(/target\s+is\s+safe/i);
    expect(rendered).not.toMatch(/all\s+certs\s+found/i);
    expect(rendered).not.toMatch(/full\s+scan/i);
    expect(rendered).not.toMatch(/public\s+scanner/i);
    expect(screen.queryByText(/Analyze archive/i)).not.toBeInTheDocument();
  });

  it("exposes a pure report helper with defensive Raw JSON redaction", () => {
    const report = buildActiveTlsBasicReport({
      ...baseJob,
      result: {
        capability: "active_tls_basic",
        status: "handshake_succeeded",
        target: "service.local",
        certificate: {
          available: true,
          subject: "commonName=service.local",
          issuer: "commonName=Inspectra Test CA",
          san_count: 1,
          san_sample: [{ type: "DNS", value: "service.local" }],
          certificate_pem: "-----BEGIN CERTIFICATE-----token_should_never_render-----END CERTIFICATE-----",
          certificate_der: "raw_der_should_not_render"
        },
        handshake: { status: "succeeded", protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384" }
      }
    });
    const redacted = JSON.stringify(redactActiveTlsBasicValue(report), null, 2);

    expect(report.isActiveTlsBasic).toBe(true);
    expect(report.status).toBe("handshake_succeeded");
    expect(report.certificate.available).toBe(true);
    expect(report.rawJson).not.toContain("service.local");
    expect(report.rawJson).not.toContain("-----BEGIN CERTIFICATE-----");
    expect(report.rawJson).not.toContain("raw_der_should_not_render");
    expect(redacted).not.toContain("service.local");
  });
});
