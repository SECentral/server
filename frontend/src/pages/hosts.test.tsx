import { render, screen, waitFor, within } from "@testing-library/react";
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
  meta: { page: 1, page_size: 25, total: 2, total_pages: 1 }
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
      const params = new URL(url, "http://localhost").searchParams;
      const size = Number(params.get("limit") ?? payload.meta.page_size);
      return Promise.resolve(jsonResponse(200, { ...payload, meta: { ...payload.meta, page: Number(params.get("page") ?? 1), page_size: size, total_pages: Math.ceil(payload.meta.total / size) } }));
    }
    return Promise.reject(new Error(`unexpected url ${url}`));
  });
  vi.stubGlobal("fetch", fetchMock);
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } }
  });
  const view = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>
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
    renderHosts();

    await screen.findByRole("link", { name: "web-1" });
    expect(screen.getByRole("link", { name: "web-1" })).toHaveAttribute("href", "/hosts/1");
    expect(screen.getByRole("link", { name: "db-1" })).toHaveAttribute("href", "/hosts/2");
    expect(screen.getByRole("link", { name: "2 active issues" })).toHaveAttribute("href", "/issues?host_id=1&status=open");
    expect(screen.getByRole("link", { name: "Reporting 1" })).toHaveAttribute("href", "/hosts?status=reporting");
    expect(screen.getByRole("link", { name: "Stale 1" })).toHaveAttribute("href", "/hosts?status=stale");
    expect(screen.getByRole("link", { name: "Offline 0" })).toHaveAttribute("href", "/hosts?status=offline");
    expect(screen.getAllByText("Hosts across the fleet")).toHaveLength(3);
    expect(screen.queryByRole("button", { name: /Copy host ID/ })).not.toBeInTheDocument();
    expect(screen.queryByText("host-abc123def456")).not.toBeInTheDocument();
    expect(screen.getByText("AlmaLinux 9.3")).toBeInTheDocument();
    expect(screen.getByText("v0.2.0")).toBeInTheDocument();
    expect(screen.getByRole("grid", { name: "Hosts" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Operating system" })).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /web-1/ })).toHaveTextContent("3 AVCs / 24h");
    expect(screen.getByRole("row", { name: /web-1/ })).toHaveTextContent("40 retained AVC observations");
    const list = screen.getByRole("region", { name: "Hosts" });
    expect(list).toHaveClass("resource-table-card");
    expect(within(list).getByRole("heading", { name: "Hosts" })).toBeInTheDocument();
    expect(within(list).getByText("2 results")).toBeInTheDocument();
    expect(within(list).getByRole("navigation", { name: "Host pagination" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Monitored servers" })).toBeInTheDocument();
  });

  it("uses the shared RHEL display name while preserving the OS version", async () => {
    renderHosts({ ...hostsPayload, hosts: [{ ...hostsPayload.hosts[0], platform: { os_id: "rhel", os_version: "10.1" } }] });
    expect(await screen.findByText("RHEL 10.1")).toBeVisible();
    expect(screen.queryByText("rhel 10.1")).not.toBeInTheDocument();
  });

  it("keeps filter state in the URL and refetches when it changes", async () => {
    const { fetchMock } = renderHosts(hostsPayload, "/hosts?page=2");
    await screen.findByRole("link", { name: "web-1" });

    const user = userEvent.setup();
    const callsBeforeDraft = fetchMock.mock.calls.length;
    await user.type(screen.getByRole("textbox", { name: "Filter value" }), "almalinux");
    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeDraft);
    await user.click(screen.getByRole("button", { name: "Apply filter" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts?os_id=almalinux", expect.objectContaining({ method: "GET" }))
    );

    await user.selectOptions(screen.getByRole("combobox", { name: "Filter attribute" }), "agent_version");
    await user.type(screen.getByRole("textbox", { name: "Filter value" }), "0.2.0");
    await user.click(screen.getByRole("button", { name: "Apply filter" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts?os_id=almalinux&agent_version=0.2.0", expect.anything()));
    const toolbar = screen.getByLabelText("Host filters");
    expect(within(toolbar).getByText("OS: almalinux")).toBeInTheDocument();
    expect(within(toolbar).getByText("Agent version: 0.2.0")).toBeInTheDocument();
    await user.click(within(toolbar).getByRole("button", { name: "Remove OS: almalinux filter" }));
    await user.click(screen.getByRole("button", { name: "Agent state filter" }));
    await user.click(screen.getByRole("option", { name: "Stale" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("status=stale"),
        expect.objectContaining({ method: "GET" })
      )
    );
  });

  it("keeps fleet counts independent from filtered results", async () => {
    const { fetchMock } = renderHosts();
    await screen.findByRole("link", { name: "Reporting 1" });
    fetchMock.mockImplementation((url: string) => Promise.resolve(jsonResponse(200, url.includes("status=offline")
      ? { hosts: [], summary: { total: 0, agent_state_counts: { reporting: 0, stale: 0, offline: 0 } }, meta: { page: 1, page_size: 25, total: 0, total_pages: 0 } }
      : hostsPayload)));
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Agent state filter" }));
    await user.click(screen.getByRole("option", { name: "Offline" }));
    await screen.findByText("No hosts match the filters.");
    expect(screen.getByRole("link", { name: "Reporting 1" })).toBeInTheDocument();
    expect(screen.getByText("0 results")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByRole("link", { name: "web-1" })).toBeInTheDocument();
  });

  it("distinguishes an empty fleet from filtered results", async () => {
    renderHosts({ ...hostsPayload, hosts: [], summary: { total: 0, agent_state_counts: { reporting: 0, stale: 0, offline: 0 } }, meta: { page: 1, page_size: 25, total: 0, total_pages: 0 } });
    expect(await screen.findByText("No monitored hosts yet.")).toBeInTheDocument();
    expect(screen.getByText("Connect an agent to start monitoring a host.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
  });

  it("retains rows during filter refresh and offers retry after a failure", async () => {
    const { fetchMock } = renderHosts();
    await screen.findByRole("link", { name: "web-1" });
    let resolveRequest!: (response: Response) => void;
    fetchMock.mockImplementation(() => new Promise<Response>((resolve) => { resolveRequest = resolve; }));
    const user = userEvent.setup();
    await user.type(screen.getByRole("textbox", { name: "Filter value" }), "rhel");
    await user.click(screen.getByRole("button", { name: "Apply filter" }));
    expect(await screen.findByLabelText("Updating hosts")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "web-1" })).toBeInTheDocument();
    expect(screen.queryByText("2 results")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("showing previous results");
    expect(screen.queryByRole("navigation", { name: "Host pagination" })).not.toBeInTheDocument();
    resolveRequest(jsonResponse(500, { error: "Unavailable" }));
    await screen.findByText("Could not load hosts");
    fetchMock.mockResolvedValue(jsonResponse(200, hostsPayload));
    await user.click(screen.getByRole("button", { name: "Retry hosts" }));
    expect(await screen.findByRole("link", { name: "web-1" })).toBeInTheDocument();
  });

  it("paginates the host list", async () => {
    const { fetchMock } = renderHosts({ ...hostsPayload, meta: { page: 1, page_size: 25, total: 51, total_pages: 3 } });
    await screen.findByRole("link", { name: "web-1" });
    expect(screen.getByRole("spinbutton", { name: "Current page" })).toHaveValue(1);

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Go to next page" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts?page=2", expect.objectContaining({ method: "GET" }))
    );
  });

  it("offers full-page size choices and preserves filters when resizing", async () => {
    const { fetchMock } = renderHosts({ ...hostsPayload, meta: { page: 2, page_size: 25, total: 60, total_pages: 3 } }, "/hosts?status=stale&page=2");
    await screen.findByRole("link", { name: "web-1" });
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "26 - 50 of 60" }));
    await user.click(screen.getByRole("menuitem", { name: "100 per page" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts?status=stale&limit=100", expect.anything()));
    expect(screen.getByRole("spinbutton", { name: "Current page" })).toHaveValue(1);
    expect(screen.queryByText("limit: 100")).not.toBeInTheDocument();
  });

  it("shows configuration snapshot filters separately from agent reporting filters", async () => {
    const { fetchMock } = renderHosts(hostsPayload, "/hosts?configuration_family=booleans&configuration_status=stale");
    expect(await screen.findByText("Boolean coverage: Stale host snapshots")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts?configuration_family=booleans&configuration_status=stale", expect.anything());
    expect(screen.getByRole("button", { name: "Agent state filter" })).toHaveTextContent("All agent states");
  });
});
