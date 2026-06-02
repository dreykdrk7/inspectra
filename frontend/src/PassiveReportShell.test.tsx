import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PassiveReportShell } from "./PassiveReportShell";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-shell-1",
  audit_type: "redis_config_basic",
  file_id: "archive-1",
  target_url: null,
  target_domain: null,
  created_at: "2026-06-02T10:00:00Z",
  updated_at: "2026-06-02T10:01:00Z",
  source_file_deleted_at: null,
  result: null,
  error: null
} satisfies Omit<JobRecord, "status">;

describe("PassiveReportShell", () => {
  it("renders queued, running, failed, sparse, finding, no-finding, and truncation copy", () => {
    const { rerender, container } = renderShell({ status: "queued" });
    expect(screen.getByText("Job queued. Results will appear when processing starts.")).toBeInTheDocument();
    expect(screen.getByText("Passive review")).toBeInTheDocument();
    expect(screen.getByText("Data layer")).toBeInTheDocument();
    expect(screen.getAllByText(/Findings are heuristic review indicators and require human validation/).length).toBeGreaterThan(0);

    rerender(shellElement({ status: "running" }));
    expect(screen.getByText("Passive analysis is running. No external services are contacted for archive config analyzers.")).toBeInTheDocument();

    rerender(shellElement({ status: "running", isSparse: true }));
    expect(screen.getByText(/Some result fields are unavailable; showing available redacted data/)).toBeInTheDocument();

    rerender(shellElement({ status: "failed" }));
    expect(screen.getByText("The job failed in a controlled state. Review errors below; uploaded content was not executed.")).toBeInTheDocument();

    rerender(shellElement({ status: "completed", isSparse: true }));
    expect(screen.getByText("Some result fields are unavailable; showing available redacted data.")).toBeInTheDocument();

    rerender(shellElement({ status: "completed", findingsCount: 2 }));
    expect(screen.getByText("Review indicators were reported. Validate them manually before acting.")).toBeInTheDocument();

    rerender(shellElement({ status: "completed", findingsCount: 0, truncated: true }));
    expect(screen.getByText("No heuristic findings were reported for this analyzer.")).toBeInTheDocument();
    expect(screen.getByText("Limits were reached; results may be partial.")).toBeInTheDocument();

    const rendered = container.textContent?.toLowerCase() ?? "";
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
      expect(rendered).not.toContain(phrase);
    }
  });
});

function renderShell(options: { status: JobRecord["status"]; findingsCount?: number; isSparse?: boolean; truncated?: boolean }) {
  return render(shellElement(options));
}

function shellElement(options: { status: JobRecord["status"]; findingsCount?: number; isSparse?: boolean; truncated?: boolean }) {
  return (
    <PassiveReportShell
      job={{ ...baseJob, status: options.status }}
      overview={[{ label: "Findings", value: String(options.findingsCount ?? 0) }]}
      analyzer="redis_config_basic"
      archiveType="zip"
      findingsCount={options.findingsCount}
      isSparse={options.isSparse}
      truncated={options.truncated}
      rawJson={<details><summary>Show redacted payload</summary></details>}
    >
      <section>Report body</section>
    </PassiveReportShell>
  );
}
