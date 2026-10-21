import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { Profiler } from "react";
import type { IssueListResponse, UngroupableEventsResponse } from "../api/issues";
import { Issues } from "./Issues";

const issuesPayload: IssueListResponse = {
  issues: [
    {
      id: 1,
      status: "open",
      display_status: "open",
      disposition: "unclassified",
      source_type: "httpd_t",
      target_type: "default_t",
      target_class: "file",
      permissions: ["read"],
      fingerprint_version: 1,
      fingerprint_digest: "digest",
      first_seen_at: "2026-09-25T09:00:00Z",
      last_seen_at: "2026-09-25T10:05:00Z",
      occurrences_count: 2,
      hosts_count: 1,
      hosts: [{ id: 10, hostname: "web-1" }],
      observed_paths: ["/srv/app/data"]
    }
  ],
  host_options: [{ id: 10, hostname: "web-1" }],
  meta: { page: 1, page_size: 25, total: 1, total_pages: 1 },
  summary: {
    total_count: 1,
    open_count: 1,
    regressed_count: 0,
    ungroupable_count: 1,
    monitored_hosts: 1,
    enforcing_hosts: 1,
    enforcement_percent: 100
  }
};

const eventsPayload: UngroupableEventsResponse = {
  events: [
    {
      id: 5,
      host: { id: 10, hostname: "web-1" },
      missing: ["scontext"],
      occurred_at: "2026-09-25T09:30:00Z"
    }
  ],
  total_count: 1
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

function mockApi(fetchMock: ReturnType<typeof vi.fn>, issues: IssueListResponse = issuesPayload, events: UngroupableEventsResponse = eventsPayload) {
  fetchMock.mockImplementation((url: string) => {
    if (url.startsWith("/api/v1/issues")) {
      const params = new URL(url, "http://localhost").searchParams;
      const size = Number(params.get("limit") ?? issues.meta.page_size);
      return Promise.resolve(jsonResponse(200, { ...issues, meta: { ...issues.meta, page: Number(params.get("page") ?? 1), page_size: size, total_pages: Math.ceil(issues.meta.total / size) } }));
    }
    if (url.startsWith("/api/v1/ungroupable-events")) {
      return Promise.resolve(jsonResponse(200, events));
    }
    return Promise.reject(new Error(`unexpected url ${url}`));
  });
}

function renderIssues(initialEntry = "/issues") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route path="/issues" element={<Issues />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("Issues", () => {
  it("keeps typing local to the draft input and applies it on submit", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock);
    vi.stubGlobal("fetch", fetchMock);
    const onRender = vi.fn();
    const user = userEvent.setup();
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={["/issues"]}>
      <Profiler id="issues" onRender={onRender}><Issues /></Profiler>
    </MemoryRouter></QueryClientProvider>);
    await screen.findByText("httpd_t");
    await user.click(screen.getByRole("textbox", { name: "Filter value" }));
    onRender.mockClear();
    await user.keyboard("httpd");
    expect(onRender).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Apply filter" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?q=httpd", expect.anything()));
  });

  it("lists issues with summary counts and unclassified events", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock);
    vi.stubGlobal("fetch", fetchMock);

    renderIssues();

    await screen.findByText("httpd_t");
    expect(screen.getByText("default_t")).toBeInTheDocument();
    expect(screen.queryByText(/Monitored servers/i)).not.toBeInTheDocument();
    expect(screen.queryByText("Open issues")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Regressed issues 0" })).toHaveAttribute("href", "/issues?status=regressed");
    expect(screen.getByText("Grouped issues")).toBeInTheDocument();
    expect(screen.getByText("1 result")).toBeInTheDocument();
    expect(screen.getAllByText("Unclassified events").length).toBeGreaterThan(0);
    expect(screen.getByText("scontext")).toBeInTheDocument();
    const grouped = screen.getByRole("region", { name: "Grouped issues" });
    expect(grouped).toHaveClass("pf-v6-c-card");
    expect(within(grouped).getByRole("heading", { name: "Grouped issues" })).toBeVisible();
    expect(within(grouped).getByRole("grid", { name: "Grouped issues" })).toHaveClass("pf-m-compact", "pf-m-grid-lg");
    expect(within(grouped).getByRole("button", { name: "Go to next page" })).toBeDisabled();
    const unclassified = screen.getByRole("region", { name: "Unclassified events" });
    expect(unclassified).toHaveClass("pf-v6-c-card");
    expect(within(unclassified).getByRole("table", { name: "Unclassified events" })).toHaveClass("pf-m-compact", "pf-m-grid-lg");
    expect(unclassified.querySelector(".pf-v6-c-card")).toBeNull();
    expect(screen.getByRole("link", { name: "web-1" })).toHaveAttribute("href", "/hosts?host_id=10");
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues", expect.objectContaining({ method: "GET" }));
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/ungroupable-events", expect.objectContaining({ method: "GET" }));
  });

  it("expands a row to show affected hosts, paths, and detail actions", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock);
    vi.stubGlobal("fetch", fetchMock);

    const user = userEvent.setup();
    renderIssues();
    await screen.findByText("httpd_t");

    expect(screen.queryByRole("link", { name: "Investigate issue" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /httpd_t default_t/ })).toHaveAttribute("href", "/issues/1");
    await user.click(screen.getByRole("button", { name: "Details" }));
    expect(screen.getByRole("grid", { name: "Grouped issues" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Hide details" })).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("link", { name: "Investigate issue" })).toHaveAttribute("href", "/issues/1");
    expect(screen.getByRole("link", { name: "View AVC evidence" })).toHaveAttribute("href", "/issues/1?tab=occurrences");
    expect(screen.getByText("/srv/app/data")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "web-1" })[0]).toHaveAttribute("href", "/hosts?host_id=10");
  });

  it("sends status values rather than display labels to the issues API", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock);
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderIssues();
    await screen.findByText("httpd_t");
    await user.click(screen.getByRole("button", { name: "Status filter" }));
    await user.click(screen.getByText("All statuses"));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?status=all", expect.anything()));
    await user.click(screen.getByRole("button", { name: "Status filter" }));
    await user.click(screen.getByText("Resolved"));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?status=resolved", expect.anything()));
  });

  it("pages through result sets larger than one page", async () => {
    const fetchMock = vi.fn();
    fetchMock.mockImplementation((url: string) => {
      if (url.startsWith("/api/v1/issues")) {
        const page = Number(new URL(url, "http://localhost").searchParams.get("page") ?? 1);
        const issue = { ...issuesPayload.issues[0], id: page, source_type: page === 1 ? "httpd_t" : "sshd_t" };
        return Promise.resolve(jsonResponse(200, { ...issuesPayload, issues: [issue], meta: { page, page_size: 25, total: 26, total_pages: 2 } }));
      }
      if (url.startsWith("/api/v1/ungroupable-events")) {
        return Promise.resolve(jsonResponse(200, eventsPayload));
      }
      return Promise.reject(new Error(`unexpected url ${url}`));
    });
    vi.stubGlobal("fetch", fetchMock);

    const user = userEvent.setup();
    renderIssues();
    await screen.findByText("httpd_t");
    const grouped = screen.getByRole("region", { name: "Grouped issues" });
    const pager = within(grouped).getByRole("navigation", { name: "Grouped issues pagination" });
    expect(pager.closest(".table-pagination")).not.toBeNull();
    expect(within(pager).getByRole("spinbutton", { name: "Current page" })).toHaveValue(1);
    expect(within(pager).getByRole("button", { name: "Go to previous page" })).toBeDisabled();
    await user.click(within(pager).getByRole("button", { name: "Go to next page" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?page=2", expect.objectContaining({ method: "GET" }))
    );
    expect(await screen.findByText("sshd_t")).toBeVisible();
    expect(screen.queryByText("httpd_t")).not.toBeInTheDocument();
    const updatedPager = within(grouped).getByRole("navigation", { name: "Grouped issues pagination" });
    expect(within(updatedPager).getByRole("spinbutton", { name: "Current page" })).toHaveValue(2);
    expect(within(updatedPager).getByRole("button", { name: "Go to next page" })).toBeDisabled();
    await user.click(within(updatedPager).getByRole("button", { name: "Go to first page" }));
    expect(await screen.findByText("httpd_t")).toBeVisible();
  });

  it("offers full-page size choices and resets the page without discarding filters", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, { ...issuesPayload, meta: { page: 2, page_size: 25, total: 60, total_pages: 3 } });
    vi.stubGlobal("fetch", fetchMock);
    renderIssues("/issues?host_id=10&status=all&page=2");
    await screen.findByText("httpd_t");
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "26 - 50 of 60" }));
    await user.click(screen.getByRole("menuitem", { name: "100 per page" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?host_id=10&status=all&limit=100", expect.anything()));
    expect(screen.getByRole("spinbutton", { name: "Current page" })).toHaveValue(1);
  });

  it("preserves filters on page jumps and resets the page when a filter changes", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, { ...issuesPayload, meta: { page: 2, page_size: 50, total: 150, total_pages: 3 } });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderIssues("/issues?host_id=10&status=resolved&page=2");
    await screen.findByText("httpd_t");
    const page = screen.getByRole("spinbutton", { name: "Current page" });
    await user.clear(page);
    await user.type(page, "3{Enter}");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?host_id=10&status=resolved&page=3", expect.anything()));
    await user.type(screen.getByRole("textbox", { name: "Filter value" }), "httpd{Enter}");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?host_id=10&status=resolved&q=httpd", expect.anything()));
  });

  it("composes attribute filters, restores URL chips, and removes one without losing the others", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock);
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderIssues("/issues?host_id=10&status=all&permission=read&page=2");
    await screen.findByText("httpd_t");
    const toolbar = screen.getByLabelText("Issue filters");
    expect(within(toolbar).getByText("Permission: read")).toBeVisible();
    expect(within(toolbar).getByRole("button", { name: "New" })).toBeVisible();
    expect(screen.getAllByRole("textbox")).toHaveLength(1);
    await user.selectOptions(screen.getByRole("combobox", { name: "Filter attribute" }), "source_type");
    await user.type(screen.getByRole("textbox", { name: "Filter value" }), "httpd_t");
    expect(fetchMock).not.toHaveBeenCalledWith(expect.stringContaining("source_type="), expect.anything());
    await user.click(screen.getByRole("button", { name: "Apply filter" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?host_id=10&status=all&permission=read&source_type=httpd_t", expect.anything()));
    await user.selectOptions(screen.getByRole("combobox", { name: "Filter attribute" }), "target_type");
    await user.type(screen.getByRole("textbox", { name: "Filter value" }), "default_t{Enter}");
    await screen.findByText("Target: default_t");
    expect(screen.getByText("Source: httpd_t")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Remove Source filter" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?host_id=10&status=all&permission=read&target_type=default_t", expect.anything()));
    expect(screen.getByText("Target: default_t")).toBeVisible();
    expect(screen.getByText("Permission: read")).toBeVisible();
    await user.click(within(toolbar).getByRole("button", { name: "New" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?host_id=10&status=all&permission=read&target_type=default_t&new=1", expect.anything()));
  });

  it("shows the grouped empty state even when unclassified events are present", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, { ...issuesPayload, issues: [], meta: { page: 1, page_size: 50, total: 0, total_pages: 0 } });
    vi.stubGlobal("fetch", fetchMock);
    renderIssues();
    expect(await screen.findByText("No grouped issues to show.")).toBeVisible();
    expect(screen.getByRole("table", { name: "Unclassified events" })).toBeVisible();
    expect(screen.queryByText("No ingested errors found.")).not.toBeInTheDocument();
  });

  it("offers clearing filters from the table card when no issues match", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, { ...issuesPayload, issues: [], meta: { page: 1, page_size: 50, total: 0, total_pages: 0 } }, { events: [], total_count: 0 });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderIssues("/issues?source_type=unobserved_t");
    expect(await screen.findByText("No issues match the filters.")).toBeVisible();
    await user.click(within(screen.getByRole("region", { name: "Grouped issues" })).getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues", expect.anything()));
    expect(screen.queryByRole("region", { name: "Unclassified events" })).not.toBeInTheDocument();
  });

  it("reports failed unclassified-event requests independently of grouped issues", async () => {
    vi.stubGlobal("fetch", vi.fn((url: string) => Promise.resolve(url.startsWith("/api/v1/ungroupable-events")
      ? jsonResponse(503, { error: { message: "Event list unavailable" } }) : jsonResponse(200, issuesPayload))));
    renderIssues();
    expect(await screen.findByText("Could not load unclassified events")).toBeVisible();
    expect(screen.getByRole("grid", { name: "Grouped issues" })).toBeVisible();
    expect(screen.getByText("Event list unavailable")).toBeVisible();
  });

  it("keeps grouped loading and request failures inside the table card", async () => {
    let resolveIssues!: (response: Response) => void;
    const pending = new Promise<Response>((resolve) => { resolveIssues = resolve; });
    vi.stubGlobal("fetch", vi.fn((url: string) => url.startsWith("/api/v1/issues") ? pending : Promise.resolve(jsonResponse(200, eventsPayload))));
    renderIssues();
    const grouped = screen.getByRole("region", { name: "Grouped issues" });
    expect(within(grouped).getByLabelText("Loading issues")).toBeVisible();
    resolveIssues(jsonResponse(503, { error: { message: "Issue list unavailable" } }));
    expect(await within(grouped).findByText("Could not load issues")).toBeVisible();
    expect(screen.getByRole("table", { name: "Unclassified events" })).toBeVisible();
  });
});
