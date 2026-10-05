import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
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
  meta: { page: 1, page_size: 50, total: 1, total_pages: 1 },
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

function mockApi(fetchMock: ReturnType<typeof vi.fn>) {
  fetchMock.mockImplementation((url: string) => {
    if (url.startsWith("/api/v1/issues")) {
      return Promise.resolve(jsonResponse(200, issuesPayload));
    }
    if (url.startsWith("/api/v1/ungroupable-events")) {
      return Promise.resolve(jsonResponse(200, eventsPayload));
    }
    return Promise.reject(new Error(`unexpected url ${url}`));
  });
}

function renderIssues(initialEntry = "/issues") {
  const queryClient = new QueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Routes>
          <Route path="/issues" element={<Issues />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("Issues", () => {
  it("lists issues with summary counts and unclassified events", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock);
    vi.stubGlobal("fetch", fetchMock);

    renderIssues();

    await screen.findByText("httpd_t");
    expect(screen.getByText("default_t")).toBeInTheDocument();
    expect(screen.getByText(/Monitored servers/i)).toBeInTheDocument();
    expect(screen.getByText("Grouped issues")).toBeInTheDocument();
    expect(screen.getByText("1 result")).toBeInTheDocument();
    expect(screen.getAllByText("Unclassified events").length).toBeGreaterThan(0);
    expect(screen.getByText("scontext")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "web-1" })).toHaveAttribute("href", "/hosts?host_id=10");
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues", expect.objectContaining({ method: "GET" }));
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/ungroupable-events", expect.objectContaining({ method: "GET" }));
  });

  it("keeps filter state in the URL and refetches when it changes", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock);
    vi.stubGlobal("fetch", fetchMock);

    const user = userEvent.setup();
    renderIssues();
    await screen.findByText("httpd_t");

    await user.click(screen.getByRole("button", { name: "New" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?new=1", expect.objectContaining({ method: "GET" }))
    );

    const search = screen.getByPlaceholderText("Search source, target, path, host...");
    await user.type(search, "nginx");
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("q=nginx"),
        expect.objectContaining({ method: "GET" })
      )
    );
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

  it("pages through result sets larger than one page", async () => {
    const fetchMock = vi.fn();
    fetchMock.mockImplementation((url: string) => {
      if (url.startsWith("/api/v1/issues")) {
        return Promise.resolve(jsonResponse(200, { ...issuesPayload, meta: { page: 1, page_size: 50, total: 51, total_pages: 2 } }));
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
    expect(screen.getByText("Page 1 of 2")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues?page=2", expect.objectContaining({ method: "GET" }))
    );
  });
});
