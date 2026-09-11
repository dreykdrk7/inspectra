import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { IntegrationEventStatusPanel } from "./IntegrationEventStatusPanel";
import { configureAuthContext } from "./api";


function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  configureAuthContext({ csrfRequired: false, csrfToken: null });
  vi.unstubAllGlobals();
});

describe("IntegrationEventStatusPanel", () => {
  it("explains the safe disabled state without exposing a destination", async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({
      contract_version: "2026-09-11.1",
      enabled: false,
      destination_configured: false,
      pending: 0,
      delivering: 0,
      delivered: 0,
      dead: 0,
      delivery_scope: "project_analysis_terminal",
    }));
    vi.stubGlobal("fetch", fetchMock);

    const view = render(<IntegrationEventStatusPanel />);
    expect(await screen.findByText("Disabled by default")).toBeInTheDocument();
    expect(screen.getByText("No outbound event destination is active. Analysis remains entirely local.")).toBeInTheDocument();
    expect(view.container).not.toHaveTextContent("https://");
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("renders bounded queue counts, refresh and a controlled failure", async () => {
    const enabled = {
      contract_version: "2026-09-11.1",
      enabled: true,
      destination_configured: true,
      pending: 2,
      delivering: 1,
      delivered: 9,
      dead: 1,
      delivery_scope: "project_analysis_terminal",
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(enabled))
      .mockResolvedValueOnce(response({ detail: "unavailable" }, 503));
    vi.stubGlobal("fetch", fetchMock);

    render(<IntegrationEventStatusPanel />);
    expect(await screen.findByText("Operator enabled")).toBeInTheDocument();
    expect(screen.getByLabelText("Signed event delivery queue")).toHaveTextContent("Pending3");
    expect(screen.getByLabelText("Signed event delivery queue")).toHaveTextContent("Delivered9");
    fireEvent.click(screen.getByRole("button", { name: "Refresh delivery status" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("temporarily unavailable");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  });

  it("replays only a reviewed aggregate snapshot with CSRF and explicit confirmation", async () => {
    configureAuthContext({ csrfRequired: true, csrfToken: "csrf-fixture" });
    const enabled = {
      contract_version: "2026-09-11.1", enabled: true, destination_configured: true,
      pending: 0, delivering: 0, delivered: 4, dead: 2, delivery_scope: "project_analysis_terminal",
    };
    const preflight = {
      contract_version: "2026-09-11.1",
      observed_at: "2026-09-11T10:00:00Z",
      expires_at: "2026-09-11T10:05:00Z",
      total_dead: 2,
      selected_events: 2,
      truncated: false,
      snapshot_digest: "a".repeat(64),
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/replay-preflight")) return Promise.resolve(response(preflight));
      if (url.endsWith("/replay") && init?.method === "POST") {
        return Promise.resolve(response({ contract_version: "2026-09-11.1", replayed_events: 2, remaining_dead: 0 }));
      }
      return Promise.resolve(response(enabled));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<IntegrationEventStatusPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Review dead deliveries" }));
    expect(await screen.findByText(/2 of 2 dead deliveries/)).toHaveTextContent("Payloads and identifiers remain hidden");
    const replayButton = screen.getByRole("button", { name: "Replay reviewed deliveries" });
    expect(replayButton).toBeDisabled();
    fireEvent.click(screen.getByLabelText("I confirm the receiver is healthy and deduplicates the original event IDs."));
    fireEvent.click(replayButton);

    expect(await screen.findByText("2 delivery events returned to the signed queue.")).toBeInTheDocument();
    const replayCall = fetchMock.mock.calls.find(([input, init]) => String(input).endsWith("/replay") && init?.method === "POST");
    expect(JSON.parse(String(replayCall?.[1]?.body))).toEqual({
      observed_at: preflight.observed_at,
      snapshot_digest: preflight.snapshot_digest,
      confirmation: "replay_dead_integration_events",
    });
    expect(new Headers(replayCall?.[1]?.headers).get("X-CSRF-Token")).toBe("csrf-fixture");
    expect(document.body).not.toHaveTextContent(preflight.snapshot_digest);
  });
});
