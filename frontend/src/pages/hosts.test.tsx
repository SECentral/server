import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { HostListResponse } from "../api/hosts";
import { Hosts } from "./Hosts";

const hostsPayload: HostListResponse = {
  hosts: [
    {
      id: 1,
      hostname: "web-1",
      external_id: "host-abc123def456",
      last_seen_at: "2026-09-25T10:00:00Z",
      agent: { reporting_state: "reporting", agent_version: "0.2.0", last_seen_at: "2026-09-25T10:00:00Z" },
      observation: {
        status: "current",
        last_received_at: "2026-09-25T10:00:00Z",
        last_observed_at: "2026-09-25T10:00:00Z"
      },
      platform: { os_id: "almalinux", os_version: "9.3" },
      selinux: { enforcement: "enforcing", configured_policy_type: "targeted", kernel_policy_version: 33 },
      counts: { active_issues: 2, avcs_24h: 3, total_events: 40 }
    },
    {
      id: 2,
      hostname: "db-1",
      external_id: "host-deadbeef9876",
      agent: { reporting_state: "stale", agent_version: null, last_seen_at: "2026-09-24T10:00:00Z" },
      observation: {
        status: "stale",
        last_received_at: "2026-09-24T10:00:00Z",
        last_observed_at: "2026-09-24T10:00:00Z"
      },
      platform: { os_id: "debian", os_version: "12" },
      selinux: { enforcement: "permissive", configured_policy_type: null, kernel_policy_version: null },
      counts: { active_issues: 0, avcs_24h: 0, total_events: 7 }
    }
  ],
  summary: { agent_state_counts: { reporting: 1, stale: 1, offline: 0 }, total: 2 },
  meta: { page: 1, page_size: 50, total: 2, total_pages: 1 }
};

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: new Headers(),
    json: async () => body
  } as unknown as Response;
}

function renderHosts(payload: HostListResponse = hostsPayload, initialEntry = "/hosts") {
  const fetchMock = vi.fn();
  fetchMock.mockImplementation((url: string) => {
    if (url.startsWith("/api/v1/hosts")) {
      return Promise.resolve(jsonResponse(200, payload));
    }
    return Promise.reject(new Error(`unexpected url ${url}`));
  });
  vi.stubGlobal("fetch", fetchMock);
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } }
  });
  const view = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Routes>
          <Route path="/hosts" element={<Hosts />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return { fetchMock, view, ...view };
}

describe("Hosts", () => {
  it("lists hosts with agent state summary, freshness, and issue links", async () => {
    const { container } = renderHosts();

    await screen.findByRole("link", { name: "web-1" });
    expect(screen.getByRole("link", { name: "web-1" })).toHaveAttribute("href", "/hosts/1");
    expect(screen.getByRole("link", { name: "db-1" })).toHaveAttribute("href", "/hosts/2");
    expect(screen.getByRole("link", { name: "2 active issues" })).toHaveAttribute("href", "/issues?host_id=1&status=open");
    expect(screen.getByText("Monitored hosts")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reporting 1 hosts" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Stale 1 hosts" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Offline 0 hosts" })).toBeInTheDocument();
    expect([...container.querySelectorAll(".hosts-summary-copy .pf-v6-c-label__text")].map((label) => label.textContent)).toEqual([
      "Monitored hosts", "Reporting", "Stale", "Offline"
    ]);
    expect(screen.queryByRole("button", { name: /Copy host ID/ })).not.toBeInTheDocument();
    expect(screen.queryByText("host-abc123def456")).not.toBeInTheDocument();
    expect(screen.getByText("almalinux 9.3")).toBeInTheDocument();
    expect(screen.getByText("v0.2.0")).toBeInTheDocument();
    expect(screen.getByRole("grid", { name: "Hosts" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Operating system" })).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /web-1/ })).toHaveTextContent("3 AVCs / 24h");
    expect(screen.getByRole("row", { name: /web-1/ })).toHaveTextContent("40 total events");
    expect(screen.queryByRole("heading", { name: "Hosts" })).not.toBeInTheDocument();
    expect(screen.queryByText("2 hosts")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Monitored servers" })).toBeInTheDocument();
  });

  it("keeps filter state in the URL and refetches when it changes", async () => {
    const { fetchMock } = renderHosts();
    await screen.findByRole("link", { name: "web-1" });

    const user = userEvent.setup();
    await user.type(screen.getByRole("textbox", { name: "OS" }), "almalinux");
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts?os_id=almalinux", expect.objectContaining({ method: "GET" }))
    );

    await user.click(screen.getByRole("button", { name: /Stale/ }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("status=stale"),
        expect.objectContaining({ method: "GET" })
      )
    );
  });

  it("paginates the host list", async () => {
    const { fetchMock } = renderHosts({ ...hostsPayload, meta: { page: 1, page_size: 50, total: 51, total_pages: 2 } });
    await screen.findByRole("link", { name: "web-1" });
    expect(screen.getByText("Page 1 of 2")).toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts?page=2", expect.objectContaining({ method: "GET" }))
    );
  });
});
