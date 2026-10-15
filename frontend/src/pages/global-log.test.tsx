import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { SelinuxLogResponse } from "../api/generated/types.gen";
import { GlobalLog } from "./GlobalLog";

const payload: SelinuxLogResponse = {
  items: [
    { id: 1, category: "administrative", event_time: "2026-10-13T12:00:00.123456Z", host: { id: 10, hostname: "web-1", external_id: "web-identity" },
      administrative: { transition_type: "boolean_change", boundary_established: false,
        boolean_changes: [{ name: "httpd_can_network_connect", old_value: false, new_value: true, state_change_established: false }], enforcement_changes: [], port_changes: [], file_context_changes: [] } },
    { id: 1, category: "avc", event_time: "2026-10-13T12:00:00.123455Z", host: { id: 11, hostname: "offline", external_id: "old-host" }, issue_id: 7,
      avc: { status: "ok", source_type: "httpd_t", target_type: "var_t", target_class: "file", permissions: ["read"], target_paths: ["/srv/data"], command: "httpd", executable: null, permissive: true } },
    { id: 2, category: "avc", event_time: "2026-10-13T11:00:00.000000Z", host: { id: 11, hostname: null, external_id: "old-host" }, issue_id: null,
      avc: { status: "ungroupable", source_type: null, target_type: null, target_class: null, permissions: [], target_paths: [], command: null, executable: null, permissive: null } }
  ], coverage: "Raw AVCs without occurrences are not listed.", meta: { page: 1, total: 30, total_pages: 3, page_size: 10, next_cursor: null }
};

function Location() {
  const location = useLocation();
  return <output aria-label="Current URL">{location.pathname}{location.search}</output>;
}

function renderLog(entry = "/log?range=custom&start=2026-10-13T00%3A00%3A00.123456Z&end=2026-10-14T00%3A00%3A00.654321Z", response: SelinuxLogResponse | Error = payload) {
  const fetch = vi.fn(async (url: string) => {
    const uri = new URL(url, "http://localhost");
    let body: unknown;
    if (uri.pathname === "/api/v1/selinux-log/hosts") {
      const selected = uri.searchParams.getAll("host_ids[]");
      const query = uri.searchParams.get("q") ?? "";
      body = { hosts: [payload.items[0].host, payload.items[1].host].filter((host) => selected.length ? selected.includes(String(host.id)) : host.hostname?.includes(query)) };
    }
    else if (response instanceof Error) return { ok: false, status: 503, headers: new Headers(), json: async () => ({ error: { code: "unavailable", message: response.message } }) } as Response;
    else {
      const page = Number(uri.searchParams.get("page") ?? 1);
      const limit = Number(uri.searchParams.get("limit") ?? 10);
      body = { ...response, items: page === 1 ? response.items : response.items.slice(-1),
        meta: { ...response.meta, page, page_size: limit, total_pages: Math.ceil((response.meta.total ?? 0) / limit) } };
    }
    return { ok: true, status: 200, headers: new Headers(), json: async () => body } as Response;
  });
  vi.stubGlobal("fetch", fetch);
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter initialEntries={[entry]}><Routes><Route path="/log" element={<GlobalLog />} /></Routes><Location /></MemoryRouter>
  </QueryClientProvider>);
  return fetch;
}

describe("Global log", () => {
  it("shows mixed entries with evidence distinctions and correct host, occurrence and issue links", async () => {
    renderLog();
    const table = await screen.findByRole("table", { name: "Global SELinux log" });
    const entries = screen.getByRole("region", { name: "Global log entries" });
    expect(entries).toHaveClass("pf-v6-c-card");
    expect(entries).toContainElement(table);
    expect(within(entries).getByRole("heading", { name: "Entries" })).toBeVisible();
    expect(table).toHaveClass("pf-m-compact", "pf-m-grid-lg");
    expect(screen.getByRole("region", { name: "Global log controls" })).not.toHaveClass("pf-v6-c-page__main-section");
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(within(table).getByText("httpd_can_network_connect").closest("td")).toHaveTextContent("Reported: Off → On · state change not established");
    expect(within(table).getByText("Non-enforced (AVC permissive=1)")).toBeVisible();
    expect(within(table).getByText("Enforcement unknown · Ungrouped occurrence")).toBeVisible();
    expect(within(table).getByRole("link", { name: "View activity" })).toHaveAttribute("href", "/hosts/10?selinux_activity=1#selinux-activity");
    expect(within(table).getAllByRole("link", { name: "View occurrence" })[0]).toHaveAttribute("href", "/hosts/11/occurrences/1");
    expect(within(table).getByRole("link", { name: "Issue #7" })).toHaveAttribute("href", "/issues/7");
    expect(screen.getByText(/2026-10-13T00:00:00.123456Z → 2026-10-14T00:00:00.654321Z/)).toBeVisible();
    expect(screen.queryByText("Timeline coverage")).not.toBeInTheDocument();
    expect(screen.queryByText("web-identity")).not.toBeInTheDocument();
    expect(screen.queryByText("old-host")).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Host filter" }));
    expect(screen.getByRole("checkbox", { name: "web-1" })).toBeInTheDocument();
  });

  it("keeps precise ranges while paging and resets to page one when changing filters", async () => {
    const fetch = renderLog();
    const user = userEvent.setup();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: "Go to next page" }));
    await waitFor(() => expect(screen.getByRole("spinbutton", { name: "Current page" })).toHaveValue(2));
    let url = new URL(screen.getByLabelText("Current URL").textContent!, "http://localhost");
    expect(url.searchParams.get("page")).toBe("2");
    expect(url.searchParams.get("start")).toBe("2026-10-13T00:00:00.123456Z");
    await user.click(screen.getByRole("button", { name: "AVCs" }));
    await screen.findByRole("table");
    url = new URL(screen.getByLabelText("Current URL").textContent!, "http://localhost");
    expect(url.searchParams.has("page")).toBe(false);
    expect(url.searchParams.get("category")).toBe("avc");
    await user.click(screen.getByRole("button", { name: "Host filter" }));
    await user.click(screen.getByRole("checkbox", { name: "offline" }));
    await waitFor(() => expect(fetch.mock.calls.some(([value]) => new URL(value, "http://localhost").searchParams.getAll("host_ids[]").includes("11"))).toBe(true));
    expect(screen.getByRole("button", { name: "AVCs" })).toHaveAttribute("aria-pressed", "true");
  });

  it("opens without any filters or host hashes", async () => {
    const fetch = renderLog("/log");
    await screen.findByRole("table");
    const url = new URL(screen.getByLabelText("Current URL").textContent!, "http://localhost");
    expect(url.search).toBe("");
    expect(screen.queryByLabelText("Active log filters")).not.toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Time range" })).toHaveValue("all");
    expect(fetch.mock.calls.some(([value]) => value === "/api/v1/selinux-log?page=1&limit=10")).toBe(true);
  });

  it("clears every filter and host search without replacing them with a default interval", async () => {
    renderLog("/log?category=avc&host_id=11&range=24&start=2026-10-13T00:00:00Z&end=2026-10-14T00:00:00Z&page=2");
    const user = userEvent.setup();
    await screen.findByRole("table");
    await user.type(screen.getByRole("textbox", { name: "Search hosts" }), "web");
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(screen.getByLabelText("Current URL")).toHaveTextContent(/^\/log$/));
    expect(screen.getByRole("textbox", { name: "Search hosts" })).toHaveValue("");
    expect(screen.getByRole("button", { name: "Host filter" })).toHaveTextContent("All hosts");
    expect(screen.getByRole("combobox", { name: "Time range" })).toHaveValue("all");
    expect(screen.queryByLabelText("Active log filters")).not.toBeInTheDocument();
  });

  it("supports direct page navigation and resets to page one when choosing a page size", async () => {
    const fetch = renderLog("/log?page=2");
    const user = userEvent.setup();
    await screen.findByRole("table");
    const page = screen.getByRole("spinbutton", { name: "Current page" });
    await user.clear(page);
    await user.type(page, "3{Enter}");
    await waitFor(() => expect(fetch.mock.calls.some(([value]) => value.includes("page=3&limit=10"))).toBe(true));
    await waitFor(() => expect(screen.getByRole("button", { name: "21 - 30 of 30" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "21 - 30 of 30" }));
    await user.click(screen.getByRole("menuitem", { name: "25 per page" }));
    await waitFor(() => expect(fetch.mock.calls.some(([value]) => value.includes("page=1&limit=25"))).toBe(true));
    expect(screen.getByRole("spinbutton", { name: "Current page" })).toHaveValue(1);
  });

  it("shows a Type chip for specific activity and omits it for All", async () => {
    renderLog("/log");
    const user = userEvent.setup();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: "AVCs" }));
    expect(screen.getByText("Type: AVCs")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Administrative activity" }));
    expect(screen.getByText("Type: Administrative activity")).toBeVisible();
    expect(screen.queryByText("Type: AVCs")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "All" }));
    expect(screen.queryByText(/^Type:/)).not.toBeInTheDocument();
    expect(new URL(screen.getByLabelText("Current URL").textContent!, "http://localhost").searchParams.has("category")).toBe(false);
  });

  it("adds multiple hosts, preserves selected labels when searching, and removes individual host chips", async () => {
    const fetch = renderLog("/log?page=2");
    const user = userEvent.setup();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: "Host filter" }));
    await user.click(screen.getByRole("checkbox", { name: "web-1" }));
    await user.click(screen.getByRole("checkbox", { name: "offline" }));
    await waitFor(() => expect(fetch.mock.calls.some(([value]) => new URL(value, "http://localhost").searchParams.getAll("host_ids[]").length === 2)).toBe(true));
    expect(screen.getByRole("button", { name: "Host filter" })).toHaveTextContent("2 hosts selected");
    expect(screen.getByText("Host: web-1")).toBeVisible();
    expect(screen.getByText("Host: offline")).toBeVisible();
    expect(new URL(screen.getByLabelText("Current URL").textContent!, "http://localhost").searchParams.has("page")).toBe(false);
    await user.type(screen.getByRole("textbox", { name: "Search hosts" }), "web");
    expect(screen.getByText("Host: offline")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Remove host web-1" }));
    expect(new URL(screen.getByLabelText("Current URL").textContent!, "http://localhost").searchParams.getAll("host_ids[]")).toEqual(["11"]);
    expect(screen.queryByText("Host: web-1")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getByLabelText("Current URL")).toHaveTextContent(/^\/log$/);
  });

  it("restores multiple host selections from a shared URL and uses separated PatternFly toolbar rows", async () => {
    renderLog("/log?host_ids%5B%5D=10&host_ids%5B%5D=11");
    const user = userEvent.setup();
    await screen.findByText("Host: web-1");
    expect(screen.getByText("Host: offline")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Host filter" }));
    expect(screen.getByRole("checkbox", { name: "web-1" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "offline" })).toBeChecked();
    expect(screen.queryByText(/Host search shows up to 50 matches/)).not.toBeInTheDocument();
    const typeRow = screen.getByRole("group", { name: "Activity type" }).closest(".pf-v6-c-toolbar__content");
    expect(typeRow).toHaveClass("pf-v6-u-mb-md");
    expect(typeRow).not.toContainElement(screen.getByRole("textbox", { name: "Search hosts" }));
    const navigation = screen.getByLabelText("Global log table navigation");
    expect(navigation).toHaveClass("table-pagination");
    expect(screen.getByRole("region", { name: "Global log entries" })).toContainElement(navigation);
  });

  it("allows custom precise UTC intervals and widening to all retained time", async () => {
    renderLog();
    const user = userEvent.setup();
    await screen.findByRole("table");
    const start = screen.getByRole("textbox", { name: /Start/ });
    await user.clear(start);
    await user.type(start, "2026-10-12T00:00:00.000001Z");
    await user.click(screen.getByRole("button", { name: "Apply interval" }));
    expect(new URL(screen.getByLabelText("Current URL").textContent!, "http://localhost").searchParams.get("start")).toBe("2026-10-12T00:00:00.000001Z");
    await user.selectOptions(screen.getByRole("combobox", { name: "Time range" }), "all");
    const url = new URL(screen.getByLabelText("Current URL").textContent!, "http://localhost");
    expect(url.searchParams.has("start")).toBe(false);
    expect(url.searchParams.has("end")).toBe(false);
    expect(screen.queryByRole("button", { name: "Apply interval" })).not.toBeInTheDocument();
  });

  it("distinguishes request failure from an empty timeline", async () => {
    renderLog("/log?range=all", new Error("Exactly one organization is required"));
    expect(await screen.findByText("Could not load global log")).toBeVisible();
    expect(screen.getByRole("region", { name: "Global log entries" })).toHaveClass("pf-v6-c-card");
    expect(screen.getByText("Exactly one organization is required")).toBeVisible();
    expect(screen.queryByText("No retained SELinux activity")).not.toBeInTheDocument();
  });

  it("shows a retained-history empty state and disabled pagination", async () => {
    renderLog("/log", { ...payload, items: [], meta: { page: 1, total: 0, total_pages: 0, page_size: 10, next_cursor: null } });
    expect(await screen.findByText("No retained SELinux activity")).toBeVisible();
    expect(screen.getByRole("region", { name: "Global log entries" })).toContainElement(screen.getByText("No retained SELinux activity"));
    expect(screen.getByRole("button", { name: "Go to next page" })).toBeDisabled();
  });
});
