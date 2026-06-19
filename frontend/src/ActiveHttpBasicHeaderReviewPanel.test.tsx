import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ActiveHttpBasicHeaderReviewPanel } from "./ActiveHttpBasicHeaderReviewPanel";

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" }
  });
}

describe("ActiveHttpBasicHeaderReviewPanel", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders a separate no-live HTTP header review panel with HEAD fixed", () => {
    render(<ActiveHttpBasicHeaderReviewPanel />);

    const panel = screen.getByLabelText("Active / HTTP header review");
    const method = screen.getByLabelText("Method") as HTMLInputElement;

    expect(screen.getByRole("heading", { name: "Active / HTTP header review" })).toBeInTheDocument();
    expect(screen.getByText("No-live record")).toBeInTheDocument();
    expect(screen.getByLabelText("URL target")).toBeInTheDocument();
    expect(method.value).toBe("HEAD");
    expect(method).toHaveAttribute("readonly");
    expect(panel.textContent).toContain("No HTTP request in this phase");
    expect(panel.textContent).toContain("no-live review record");
    expect(panel.textContent).toContain("no HTTP request is performed yet");
    expect(panel.textContent).toContain("[REDACTED_TARGET]");
    expect(panel.textContent).toContain("not_executed");
    expect(panel.textContent).toContain("requests_sent is 0");
    expect(panel.textContent).toContain("HTTP header review indicator");
    expect(panel.textContent).toContain("Manual validation required");
    expect(screen.getByRole("button", { name: /Create HTTP header review job/i })).toBeDisabled();
    expect(panel.querySelector('input[type="file"]')).toBeNull();
    expect(panel.querySelector("textarea")).toBeNull();
    expect(screen.queryByLabelText(/custom headers/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/request body/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/cookies/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/tokens/i)).not.toBeInTheDocument();
  });

  it("requires authorization, one target permission confirmation, and live request confirmation", () => {
    vi.stubGlobal("fetch", vi.fn());
    render(<ActiveHttpBasicHeaderReviewPanel />);

    const submit = screen.getByRole("button", { name: /Create HTTP header review job/i });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("URL target"), { target: { value: "https://authorized.example/" } });
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this URL."));
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I understand this contract is for a future live HTTP request, while this phase stores a no-live record and performs no HTTP request."));
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I confirm I control this target."));
    expect(submit).not.toBeDisabled();

    cleanup();
    render(<ActiveHttpBasicHeaderReviewPanel />);
    const delegatedSubmit = screen.getByRole("button", { name: /Create HTTP header review job/i });
    fireEvent.change(screen.getByLabelText("URL target"), { target: { value: "https://authorized.example/" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this URL."));
    fireEvent.click(screen.getByLabelText("I confirm I have delegated permission for this target."));
    fireEvent.click(screen.getByLabelText("I understand this contract is for a future live HTTP request, while this phase stores a no-live record and performs no HTTP request."));
    expect(delegatedSubmit).not.toBeDisabled();
  });

  it("submits the exact backend contract and renders the returned no-live JobRecord", async () => {
    const onJobCreated = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).endsWith("/active/web/http-basic-header-review")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-active-http-basic-header-review-05",
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
                  target: "[REDACTED_TARGET]",
                  target_display: "[REDACTED_TARGET]",
                  method: "HEAD",
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
                  limits: { method: "HEAD", max_redirects: 0, response_body_bytes: 0 },
                  surface_caveats: ["No live HTTP request was performed", "No redirect was followed", "No response body was read", "Manual validation required"]
                },
                error: null
              },
              202
            )
          );
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ActiveHttpBasicHeaderReviewPanel onJobCreated={onJobCreated} />);

    fireEvent.change(screen.getByLabelText("URL target"), { target: { value: " https://authorized.example/ " } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this URL."));
    fireEvent.click(screen.getByLabelText("I confirm I control this target."));
    fireEvent.click(screen.getByLabelText("I understand this contract is for a future live HTTP request, while this phase stores a no-live record and performs no HTTP request."));
    fireEvent.click(screen.getByRole("button", { name: /Create HTTP header review job/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/web/http-basic-header-review",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi
      .mocked(globalThis.fetch)
      .mock.calls.find(([input]) => String(input).endsWith("/active/web/http-basic-header-review"))?.[1] as RequestInit | undefined;
    const body = JSON.parse(String(request?.body));
    expect(Object.keys(body).sort()).toEqual([
      "authorization_confirmed",
      "delegated_permission_confirmed",
      "live_http_request_confirmed",
      "method",
      "mode",
      "profile",
      "target",
      "target_control_confirmed"
    ]);
    expect(body).toEqual({
      mode: "live_http_basic_header_review",
      profile: "http_headers_single_request",
      target: "https://authorized.example/",
      method: "HEAD",
      authorization_confirmed: true,
      target_control_confirmed: true,
      delegated_permission_confirmed: false,
      live_http_request_confirmed: true
    });

    expect(await screen.findByText(/HTTP header review indicator job created/i)).toBeInTheDocument();
    expect(screen.getByText("job-active-http-basic-header-review-05")).toBeInTheDocument();
    expect(screen.getAllByText("not_executed").length).toBeGreaterThan(0);
    expect(screen.getAllByText("[REDACTED_TARGET]").length).toBeGreaterThan(0);
    expect(screen.getAllByText("HEAD").length).toBeGreaterThan(0);
    expect(screen.getByText("No live HTTP request was performed. The job record was opened below when the dashboard integration is available.")).toBeInTheDocument();
    expect(onJobCreated).toHaveBeenCalledWith(expect.objectContaining({ id: "job-active-http-basic-header-review-05" }));
    expect(document.body.textContent ?? "").not.toContain("authorized.example");
  });

  it("handles a controlled non-job response without reflecting the target", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).endsWith("/active/web/http-basic-header-review")) {
          return Promise.resolve(
            jsonResponse({
              audit_type: "active_http_basic_header_review",
              status: "blocked_unconfigured",
              target: "[REDACTED_TARGET]"
            })
          );
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );
    render(<ActiveHttpBasicHeaderReviewPanel />);

    fireEvent.change(screen.getByLabelText("URL target"), { target: { value: "https://authorized.example/" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this URL."));
    fireEvent.click(screen.getByLabelText("I confirm I control this target."));
    fireEvent.click(screen.getByLabelText("I understand this contract is for a future live HTTP request, while this phase stores a no-live record and performs no HTTP request."));
    fireEvent.click(screen.getByRole("button", { name: /Create HTTP header review job/i }));

    expect(await screen.findByText("Active / HTTP header review was not accepted as a stored no-live job. Review bounds and confirmations.")).toBeInTheDocument();
    expect(document.body.textContent ?? "").not.toContain("authorized.example");
  });
});
