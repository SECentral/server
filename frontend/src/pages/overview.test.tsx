import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { OverviewResponse, OverviewSeriesPoint } from "../api/overview";
import { Overview } from "./Overview";

function series(values: number[]): OverviewSeriesPoint[] {
  return values.map((value, index) => ({ date: `2026-09-${String(index + 1).padStart(2, "0")}`, value }));
}

const staleSince = new Date(Date.now() - 35 * 60 * 1000).toISOString();
const staleUntil = new Date(Date.now() - 25 * 60 * 1000).toISOString();

const payload: OverviewResponse = {
  metrics: {
    active_issues: 2,
    new_issues_24h: 1,
    affected_hosts: 2,
    avcs_24h: 5,
    monitored_hosts: 3,
    agent_states: { reporting: 1, stale: 1, offline: 1 }
  },
  series: {
    new_issues: series([0, 0, 1, 0, 0, 0, 2]),
    avc_occurrences: series([0, 0, 0, 0, 0, 0, 5])
  },
  attention: {
    agent_states: [
      {
        state: "stale",
        host_count: 1,
        heartbeat_range: [staleSince, staleUntil],
        example_hosts: [{ id: 2, hostname: "overview-02" }]
      }
    ],
    permissive: { host_count: 1, example_hosts: [{ id: 1, hostname: "overview-01" }] },
    new_issues: { issue_count: 1, example_issues: [{ id: 10, source_type: "httpd_t", target_type: "default_t" }] },
    multi_host_issues: null
  }
};

const quietPayload: OverviewResponse = {
  ...payload,
  attention: { agent_states: [], permissive: null, new_issues: null, multi_host_issues: null }
};
const noActivityPayload: OverviewResponse = {
  ...quietPayload,
  series: { new_issues: series([0, 0, 0, 0, 0, 0, 0]), avc_occurrences: series([0, 0, 0, 0, 0, 0, 0]) }
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

function renderOverview(fetchBody: unknown = payload, status = 200) {
  const fetchMock = vi.fn();
  fetchMock.mockImplementation(() => Promise.resolve(jsonResponse(status, fetchBody)));
  vi.stubGlobal("fetch", fetchMock);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="/" element={<Overview />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return { fetchMock, ...view };
}

describe("Overview", () => {
  it("shows metrics, series, and attention items with drill-down links", async () => {
    renderOverview();

    expect(await screen.findByRole("heading", { name: "Overview", level: 1 })).toBeInTheDocument();
    await screen.findByRole("link", { name: "Active issues 2" });
    expect(screen.getByText(/Agent reporting and retained SELinux observations/)).toBeInTheDocument();
    for (const heading of ["Issue activity", "Fleet reporting", "Activity trends", "Needs attention"]) {
      expect(screen.getByRole("heading", { name: heading, level: 2 })).toBeInTheDocument();
    }
    for (const linkName of ["Affected hosts 2", "AVCs — 24h 5"]) {
      expect(screen.getByRole("link", { name: linkName })).toBeInTheDocument();
    }
    expect(screen.getByRole("link", { name: "Active issues 2" })).toHaveAttribute("href", "/issues?status=open");
    expect(screen.getByRole("link", { name: "New issues — 24h 1" })).toHaveAttribute("href", "/issues?status=open&new=1");
    expect(screen.getByRole("link", { name: "3 monitored hosts" })).toHaveAttribute("href", "/hosts");
    expect(screen.getByRole("link", { name: "Reporting 1" })).toHaveAttribute("href", "/hosts?status=reporting");
    expect(screen.getByRole("link", { name: "Offline 1" })).toHaveAttribute("href", "/hosts?status=offline");
    expect(screen.getByRole("link", { name: "Stale 1" })).toHaveAttribute("href", "/hosts?status=stale");
    const charts = screen.getAllByRole("img");
    expect(charts).toHaveLength(2);
    expect(charts.map((chart) => chart.getAttribute("aria-label"))).toEqual(["New issues — 7 days", "AVC occurrences — 7 days"]);
    const descriptions = charts.map((chart) => document.getElementById(chart.getAttribute("aria-describedby") ?? "")?.textContent ?? "");
    expect(descriptions[0]).toContain("2026-09-03: 1");
    expect(descriptions[1]).toContain("2026-09-07: 5");
    expect(screen.getByText("3 total")).toBeInTheDocument();
    expect(screen.getByText("5 total")).toBeInTheDocument();
    expect(screen.getAllByText("Last 7 days")).toHaveLength(2);
    expect(screen.getAllByText("Tue 1")).toHaveLength(2);

    expect(screen.getByText("1 agent stale")).toBeInTheDocument();
    expect(screen.getByText("overview-02")).toBeInTheDocument();
    expect(screen.getByText(/Last heartbeat between/)).toBeInTheDocument();
    expect(screen.getByText("1 host currently running SELinux permissive")).toBeInTheDocument();
    expect(screen.getByText("1 new issue in the last 24 hours")).toBeInTheDocument();
    expect(screen.getByText("httpd_t → default_t")).toBeInTheDocument();
    const affectedLinks = screen.getAllByRole("link", { name: "View affected hosts →" });
    expect(affectedLinks.map((link) => link.getAttribute("href")).sort()).toEqual([
      "/hosts?enforcement=permissive",
      "/hosts?status=stale"
    ]);
    expect(screen.getByRole("link", { name: "View new issues →" })).toHaveAttribute("href", "/issues?status=open&new=1");
  });

  it("shows an empty attention message when nothing needs attention", async () => {
    renderOverview(quietPayload);

    expect(await screen.findByText("No listed conditions observed in retained telemetry.")).toBeInTheDocument();
    expect(screen.getByText("Audit capture continuity and workload coverage are unknown.")).toBeVisible();
  });

  it("states clearly when the activity charts have no events in their period", async () => {
    renderOverview(noActivityPayload);

    expect(await screen.findAllByText("No activity recorded in this period.")).toHaveLength(2);
    expect(screen.getAllByText("Last 7 days")).toHaveLength(2);
    expect(screen.getAllByText("0 total")).toHaveLength(2);
  });

  it("surfaces API failures", async () => {
    renderOverview({ error: { code: "unauthorized", message: "Authentication required" } }, 401);

    expect(await screen.findByText("Could not load the overview")).toBeInTheDocument();
    expect(screen.getByText("Authentication required")).toBeInTheDocument();
  });
});
