import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FederatedIdentityPanel } from "./FederatedIdentityPanel";


const members = [
  { user_id: "team-admin", username: "admin", role: "administrator", joined_at: "2026-09-06T10:00:00Z" },
  { user_id: "a".repeat(32), username: "reviewer.one", role: "reader", joined_at: "2026-09-06T11:00:00Z" },
] as const;

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("FederatedIdentityPanel", () => {
  it("provisions an existing non-admin without rendering or retaining the provider subject", async () => {
    let bindings: unknown[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "POST") {
        bindings = [{
          id: "b".repeat(32), user_id: "a".repeat(32), username: "reviewer.one", role: "reader",
          created_at: "2026-09-11T07:00:00Z", revoked_at: null,
        }];
        return Promise.resolve(response(bindings[0], 201));
      }
      return Promise.resolve(response(bindings));
    });
    vi.stubGlobal("fetch", fetchMock);

    const view = render(<FederatedIdentityPanel enabled members={[...members]} />);
    expect(await screen.findByText("No members are linked to SSO.")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Existing member"), { target: { value: "a".repeat(32) } });
    const subject = screen.getByLabelText("Provider subject (`sub`)");
    expect(subject).toHaveAttribute("type", "password");
    fireEvent.change(subject, { target: { value: "sensitive-provider-subject" } });
    fireEvent.click(screen.getByRole("button", { name: "Link exact identity" }));

    expect(await screen.findByRole("button", { name: "Revoke SSO and sessions" })).toBeInTheDocument();
    expect((subject as HTMLInputElement).value).toBe("");
    expect(view.container).not.toHaveTextContent("sensitive-provider-subject");
    const posted = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(JSON.parse(String(posted?.[1]?.body))).toEqual({
      user_id: "a".repeat(32),
      subject: "sensitive-provider-subject",
    });
    await waitFor(async () => expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]));
  });

  it("renders nothing while federation is disabled", () => {
    const { container } = render(<FederatedIdentityPanel enabled={false} members={[...members]} />);
    expect(container).toBeEmptyDOMElement();
  });
});
