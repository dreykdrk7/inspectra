import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TeamInvitationAcceptance } from "./TeamInvitationAcceptance";


function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("TeamInvitationAcceptance", () => {
  it("activates an account, clears sensitive fields and returns the username", async () => {
    const onAccepted = vi.fn();
    const fetchMock = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(response({ accepted: true, username: "reviewer.one" })),
    );
    vi.stubGlobal("fetch", fetchMock);
    render(<TeamInvitationAcceptance onAccepted={onAccepted} />);

    fireEvent.click(screen.getByRole("button", { name: "I have a one-time invitation" }));
    fireEvent.change(screen.getByLabelText("Invitation token"), { target: { value: "a".repeat(40) } });
    fireEvent.change(screen.getByLabelText("Create password"), { target: { value: "reviewer-password" } });
    fireEvent.change(screen.getByLabelText("Confirm password"), { target: { value: "reviewer-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Activate team account" }));

    expect(await screen.findByText("Account activated. Sign in as reviewer.one.")).toBeInTheDocument();
    expect(onAccepted).toHaveBeenCalledWith("reviewer.one");
    expect(screen.getByLabelText("Invitation token")).toHaveValue("");
    expect(screen.getByLabelText("Create password")).toHaveValue("");
    const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body));
    expect(body).toEqual({ token: "a".repeat(40), password: "reviewer-password" });
  });

  it("rejects mismatched passwords without sending a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<TeamInvitationAcceptance onAccepted={() => undefined} />);

    fireEvent.click(screen.getByRole("button", { name: "I have a one-time invitation" }));
    fireEvent.change(screen.getByLabelText("Invitation token"), { target: { value: "a".repeat(40) } });
    fireEvent.change(screen.getByLabelText("Create password"), { target: { value: "reviewer-password" } });
    fireEvent.change(screen.getByLabelText("Confirm password"), { target: { value: "different-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Activate team account" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Passwords do not match.");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
