import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { HostConfigurationResponse } from "../api/configuration";
import type { HostDetailResponse, HostOccurrencesResponse, SelinuxActivityResponse } from "../api/hosts";
import type { OccurrenceDetail } from "../api/issue";
import { HostDetail } from "./HostDetail";
import { HostOccurrenceDetail } from "./HostOccurrenceDetail";

const RAW_PAYLOAD = '<script>alert("x")</script> type=AVC';

const detailPayload: HostDetailResponse = {
  host: {
    id: 10,
    hostname: "web-1",
    external_id: "web-1",
    last_seen_at: "2026-09-25T10:00:00Z",
    agent: { reporting_state: "reporting", agent_version: "0.2.0", last_seen_at: "2026-09-25T10:00:00Z" },
    observation: {
      status: "current",
      last_received_at: "2026-09-25T10:00:00Z",
      last_observed_at: "2026-09-25T10:00:00Z"
    },
    platform: { os_id: "almalinux", os_version: "9.3", architecture: "x86_64" },
    selinux: {
      enforcement: "enforcing",
      configured_policy_type: "targeted",
      kernel_policy_version: 33,
      policy_identity: "sha256:abc"
    },
    snapshot: {
      platform: { os_id: "almalinux", os_version: "9.3", architecture: "x86_64" },
      selinux: {
        enforcement: "enforcing",
        configured_policy_type: "targeted",
        kernel_policy_version: 33,
        policy_identity: "sha256:abc"
      }
    },
    counts: { active_issues: 1, avcs_24h: 2, total_events: 30 }
  }
};

const matchingConfiguration: HostConfigurationResponse = {
  host: { id: 10, hostname: "web-1", external_id: "web-1" },
  observation: { status: "current", last_observed_at: "2026-09-25T10:00:00Z", last_received_at: "2026-09-25T10:00:00Z" },
  selinux: { enforcement: "enforcing", configured_policy_type: "targeted", boolean_status: "observed", policy_identity: "sha256:abc" },
  reference: { kind: "distribution_catalog", catalog_revision: { id: 3, display_name: "AlmaLinux 9", policy_type: "targeted", architecture: "x86_64", loaded_policy_digest: "sha256:abc", applicability: "exact" } },
  comparison: {
    available: true,
    paused: false,
    summary: {
      booleans: { reference_entries: 350, compared: 350, match: 350, differ: 0, host_only: 0, not_observed: 0, unavailable: 0 },
      ports: { compared: 621, match: 621, differ: 0, not_observed: 0 }
    }
  },
  view: "differences",
  differences: { total: 0, booleans: [], ports: [], limitations: { reference_only_booleans: [], unavailable_booleans: [], port_segments: [] } }
};

function occurrence(id: number, issue: { id: number } | null, payload = "type=AVC denied"): OccurrenceDetail {
  return {
    id,
    host: { id: 10, hostname: "web-1" },
    occurred_at: "2026-09-25T10:05:00Z",
    normalized_denial: {
      status: "ok",
      source_type: id === 102 ? "sshd_t" : "httpd_t",
      target_type: "user_home_t",
      target_class: "file",
      permissions: ["read"],
      target_paths: ["/home/user/data"],
      source_context: "system_u:system_r:httpd_t:s0",
      target_context: "system_u:object_r:user_home_t:s0",
      command: "httpd",
      executable: "/usr/sbin/httpd",
      details: { enforcement_mode: "enforcing" }
    },
    raw_event: {
      id: 500 + id,
      audit_timestamp: "2026-09-25T10:05:00Z",
      audit_sequence: 1,
      boot_id: "boot-1",
      category: "avc",
      transition_type: null,
      completion_reason: "eoe",
      evidence_digest: `raw-digest-${id}`,
      audit_records: [
        {
          position: 0,
          record_type: 1400,
          type_name: "avc",
          audit_timestamp: "2026-09-25T10:05:00Z",
          sequence: 1,
          payload
        }
      ]
    },
    guidance:
      issue === null
        ? null
        : {
            summary: "The denial occurred while SELinux was enforcing.",
            observations: [{ observation: "The AVC confirms a denied read on a file object.", basis: "avc_record", certainty: "observed" }],
            checks: [
              { kind: "audit_history", reason: "Look for surrounding audit records near the event timestamp.", expected: "More local context", limitation: "Local audit retention may have expired." },
              { kind: "executable_context", target: "/usr/sbin/httpd", reason: "Compare the executable and source context with current service configuration.", expected: "Current configuration", limitation: "Current state may differ from occurrence time." }
            ],
            missing_evidence: ["complete target path"],
            historical_limitations: ["Current labels may differ from the state at occurrence time."]
          },
    issue
  };
}

function occurrencesPage(page: 1 | 2): HostOccurrencesResponse {
  return {
    occurrences: page === 1 ? [occurrence(101, { id: 7 }, RAW_PAYLOAD), occurrence(102, { id: 8 })] : [occurrence(100, null)],
    meta: { next_cursor: page === 1 ? "cursor-1" : null }
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: new Headers(),
    json: async () => body
  } as unknown as Response;
}

function renderHostDetail(hostId: number, options: {
  notFound?: boolean;
  host?: HostDetailResponse;
  configuration?: HostConfigurationResponse;
  occurrences?: HostOccurrencesResponse;
  activity?: SelinuxActivityResponse;
  initialEntry?: string;
} = {}) {
  const fetchMock = vi.fn();
  fetchMock.mockImplementation((url: string) => {
    if (url.startsWith(`/api/v1/hosts/${hostId}/selinux-activity`)) {
      return Promise.resolve(jsonResponse(200, options.activity ?? { items: [], coverage: "Supported SELinux changes observed in this server's audit stream. Absence of an event does not prove that no change occurred.", meta: { page_size: 20, next_cursor: null, total: 0 } }));
    }
    if (url.startsWith(`/api/v1/hosts/${hostId}/configuration`)) {
      return Promise.resolve(jsonResponse(200, options.configuration ?? matchingConfiguration));
    }
    if (url.startsWith(`/api/v1/hosts/${hostId}/occurrences`)) {
      const params = new URL(url, "http://localhost").searchParams;
      if (params.has("page")) {
        const page = Number(params.get("page"));
        const limit = Number(params.get("limit"));
        const data = options.occurrences ?? occurrencesPage(page === 1 ? 1 : 2);
        return Promise.resolve(jsonResponse(200, { ...data, meta: { ...data.meta, page, page_size: limit, total: 30, total_pages: Math.ceil(30 / limit) } }));
      }
      const cursor = url.includes("before=cursor-1");
      return Promise.resolve(jsonResponse(200, cursor ? occurrencesPage(2) : options.occurrences ?? occurrencesPage(1)));
    }
    if (url === `/api/v1/hosts/${hostId}`) {
      if (options.notFound) {
        return Promise.resolve(jsonResponse(404, { error: { code: "not_found", message: "Host not found" } }));
      }
      return Promise.resolve(jsonResponse(200, options.host ?? detailPayload));
    }
    return Promise.reject(new Error(`unexpected url ${url}`));
  });
  vi.stubGlobal("fetch", fetchMock);
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } }
  });
  const view = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[options.initialEntry ?? `/hosts/${hostId}`]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Routes>
          <Route path="/hosts/:id/occurrences/:occurrenceId" element={<HostOccurrenceDetail />} />
          <Route path="/hosts/:id" element={<HostDetail />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return { fetchMock, ...view };
}

describe("HostDetail", () => {
  it("renders the host core, configuration, and links", async () => {
    const { container } = renderHostDetail(10);

    await screen.findByRole("heading", { name: "web-1" });
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Monitored servers" })).toHaveAttribute("href", "/hosts");
    expect(screen.queryByRole("heading", { name: "Host status" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Host health" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Policy comparison" })).toBeInTheDocument();
    expect(screen.getByText("Baseline: AlmaLinux 9 Catalog")).toBeInTheDocument();
    expect(screen.getAllByText("Reporting")).toHaveLength(2);
    expect(screen.getByText("Current")).toBeInTheDocument();
    expect(screen.getAllByText("Enforcing")).toHaveLength(1);
    for (const badge of container.querySelectorAll(".pf-v6-c-label")) {
      expect(badge.querySelector(".pf-v6-c-label__icon svg[aria-hidden='true']")).not.toBeNull();
    }
    expect(screen.getByText(/AlmaLinux 9\.3 · x86_64 · Last seen/)).toBeInTheDocument();
    expect(screen.getByText("targeted.33")).toBeInTheDocument();
    expect(screen.queryByText("Configured policy")).not.toBeInTheDocument();
    expect(screen.getByText("Matches reference")).toBeInTheDocument();
    expect(screen.getByText("350 / 350 match")).toBeInTheDocument();
    expect(screen.getByText("621 / 621 match")).toBeInTheDocument();
    expect(screen.getByText("0 loaded")).toBeInTheDocument();
    expect(screen.getByText("0 overrides")).toBeInTheDocument();
    expect(screen.getByText("1", { selector: ".host-activity-facts strong" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Total Occurrences" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "AVC / 24h" })).toBeInTheDocument();
    expect(screen.queryByText("web-1", { selector: ".host-overview-subtitle" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy host policy ID" })).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Technical Provenance & Hashes" }));
    expect(screen.getByRole("button", { name: "Copy full host ID" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy host policy ID" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy reference policy ID" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View issues →" })).toHaveAttribute(
      "href",
      "/issues?host_id=10&status=open"
    );
    expect(screen.getByRole("link", { name: "View full comparison" })).toHaveAttribute(
      "href",
      "/hosts/10/configuration"
    );
    expect(screen.getByRole("table", { name: "Recent occurrences" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Issue #7" })).toHaveAttribute("href", "/issues/7");
  });

  it("replaces occurrence pages and navigates back without accumulating rows", async () => {
    const { fetchMock, container } = renderHostDetail(10);

    const user = userEvent.setup();
    await screen.findByRole("link", { name: "Issue #7" });
    expect(screen.queryByText("Ungrouped event")).not.toBeInTheDocument();

    expect(screen.getByRole("heading", { name: "Recent Occurrences (30)" })).toBeInTheDocument();
    const occurrenceView = within(screen.getByRole("region", { name: "Recent occurrences" }));
    await user.click(occurrenceView.getByRole("button", { name: "Go to next page" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/v1/hosts/10/occurrences?limit=10&page=2",
        expect.objectContaining({ method: "GET" })
      )
    );
    expect((await screen.findAllByText("Ungrouped event")).length).toBeGreaterThan(0);
    expect(container.querySelectorAll(".occurrence-denial-types")).toHaveLength(1);
    expect(screen.queryByRole("link", { name: "Issue #7" })).not.toBeInTheDocument();
    await user.click(occurrenceView.getByRole("button", { name: "Go to previous page" }));
    expect(await screen.findByRole("link", { name: "Issue #7" })).toBeInTheDocument();
    expect(container.querySelectorAll(".occurrence-denial-types")).toHaveLength(2);
  });

  it("links compact activity rows to the dedicated occurrence route", async () => {
    const { container } = renderHostDetail(10);
    const user = userEvent.setup();

    const rowLink = await screen.findByRole("link", { name: /httpd_t.*user_home_t/ });
    expect(rowLink).toHaveAttribute("href", "/hosts/10/occurrences/101");
    expect(container.querySelector(".occurrence-host-name")).toBeNull();
    expect(screen.getAllByText("file · read", { selector: "code" })).toHaveLength(2);
    expect(screen.getAllByText("Sep 25, 10:05 UTC")).toHaveLength(2);
    expect(screen.queryByText(RAW_PAYLOAD)).not.toBeInTheDocument();

    await user.click(rowLink);
    expect(await screen.findByRole("heading", { name: "httpd_t → user_home_t" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "web-1" })).toHaveAttribute("href", "/hosts/10");
    await user.click(screen.getByRole("link", { name: "web-1" }));
    expect(await screen.findByRole("heading", { name: "web-1" })).toBeInTheDocument();
  });

  it("resets to page one when selecting 25 or 50 rows and supports direct page navigation", async () => {
    const { fetchMock } = renderHostDetail(10, { initialEntry: "/hosts/10?occurrence_page=2&occurrence_page_size=10" });
    const user = userEvent.setup();
    await screen.findByText("Ungrouped event");
    const occurrenceView = within(screen.getByRole("region", { name: "Recent occurrences" }));
    const currentPage = occurrenceView.getByRole("spinbutton", { name: "Current page" });
    expect(currentPage).toHaveValue(2);
    await user.clear(currentPage);
    await user.type(currentPage, "3{Enter}");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/occurrences?limit=10&page=3", expect.anything()));
    await waitFor(() => expect(screen.getByRole("button", { name: "21 - 30 of 30" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "21 - 30 of 30" }));
    await user.click(screen.getByRole("menuitem", { name: "25 per page" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/occurrences?limit=25&page=1", expect.anything()));
    await screen.findByRole("link", { name: "Issue #7" });
    await user.click(screen.getByRole("button", { name: "1 - 25 of 30" }));
    await user.click(screen.getByRole("menuitem", { name: "50 per page" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/occurrences?limit=50&page=1", expect.anything()));
  });

  it.each(["reporting", "offline", "stale"] as const)("pairs the %s status icon with visible header text", async (reporting_state) => {
    const { container } = renderHostDetail(10, { host: { host: { ...detailPayload.host, agent: { ...detailPayload.host.agent, reporting_state } } } });
    await screen.findByRole("heading", { name: "web-1" });
    const header = within(container.querySelector("header")!);
    expect(header.getByText(reporting_state === "reporting" ? "Reporting" : reporting_state === "offline" ? "Offline" : "Stale")).toBeVisible();
    expect(container.querySelector(`.host-status-${reporting_state} svg[aria-hidden="true"]`)).not.toBeNull();
    expect(header.queryByText("Host policy ID")).not.toBeInTheDocument();
  });

  it.each(["permissive", "disabled"])("shows %s with a red icon badge and readable text", async (enforcement) => {
    renderHostDetail(10, { host: { host: { ...detailPayload.host, snapshot: null, selinux: { ...detailPayload.host.selinux, enforcement } } } });
    const badge = (await screen.findByText(enforcement === "permissive" ? "Permissive" : "Disabled")).closest(".pf-v6-c-label")!;
    expect(badge).toHaveClass("pf-m-red");
    expect(badge.querySelector("svg[aria-hidden='true']")).not.toBeNull();
  });

  it("renders Summary, readable Guidance, and progressive Raw evidence on the occurrence route", async () => {
    renderHostDetail(10, { initialEntry: "/hosts/10/occurrences/101" });

    expect(await screen.findByRole("heading", { name: "httpd_t → user_home_t" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "web-1" })).toHaveAttribute("href", "/hosts/10");
    expect(screen.getByRole("tab", { name: "Summary" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("Source context")).toBeInTheDocument();
    expect(screen.queryByText("enforcement_mode")).not.toBeInTheDocument();
    expect(screen.queryByText(RAW_PAYLOAD)).not.toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Guidance" }));
    expect(screen.getByText("The AVC confirms a denied read on a file object.")).toBeInTheDocument();
    expect(screen.getByText(/Observed evidence · Basis: AVC record/)).toBeInTheDocument();
    expect(screen.getByText("Look for surrounding audit records near the event timestamp.")).toBeInTheDocument();
    expect(screen.getByText("Compare the executable and source context with current service configuration.")).toBeInTheDocument();
    expect(screen.getByText("complete target path")).toBeInTheDocument();
    expect(screen.queryByText("avc_record")).not.toBeInTheDocument();
    expect(screen.queryByText("expected:")).not.toBeInTheDocument();
    expect(screen.queryByText(RAW_PAYLOAD)).not.toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Raw evidence" }));
    expect(screen.getByRole("button", { name: "Normalized details (debug)" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Raw AVC" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Raw audit records" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Other retained payload" })).toBeInTheDocument();
    expect(screen.queryByText(RAW_PAYLOAD)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Raw AVC" }));
    expect((await screen.findAllByText(RAW_PAYLOAD)).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Copy raw AVC record 0 for occurrence 101" })).toBeInTheDocument();
  });

  it("resolves older occurrence routes through the existing cursor API", async () => {
    const { fetchMock } = renderHostDetail(10, { initialEntry: "/hosts/10/occurrences/100" });

    expect(await screen.findByRole("heading", { name: "httpd_t → user_home_t" })).toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/hosts/10/occurrences?limit=50&before=cursor-1",
      expect.objectContaining({ method: "GET" })
    ));
    expect(screen.getByText("Ungrouped event")).toBeInTheDocument();
  });

  it("links an unresolved occurrence to its preceding observed transition without claiming causation", async () => {
    renderHostDetail(10, { initialEntry: "/hosts/10/occurrences/101", activity: {
      items: [{ id: 26710, host_id: 10, boot_id: "boot-1", event_time: "2026-09-25T10:04:00Z", audit_sequence: 10,
        evidence_class: "observed_transition", transition_type: "boolean_change", boundary_established: true,
        boolean_changes: [{ name: "httpd_can_network_connect", old_value: true, new_value: false, state_change_established: true }],
        previous_checkpoint: null, reconciliation: { status: "pending", checkpoint: null, next_transition: null }, window_avc_count: 1 }],
      coverage: "Supported observed transitions", meta: { page_size: 20, next_cursor: null }
    } });
    expect(await screen.findByText("SELinux state changed before this occurrence")).toBeVisible();
    expect(screen.getByRole("link", { name: "View the preceding observed transition" })).toHaveAttribute("href", "/hosts/10?selinux_activity=26710#selinux-activity");
    expect(screen.getByText(/This timing relationship does not establish causation/)).toBeVisible();
    expect(screen.getByText(/checkpoint-dependent policy analysis is unavailable/)).toBeVisible();
  });

  it("shows stale comparison state explicitly", async () => {
    renderHostDetail(10, { configuration: {
      ...matchingConfiguration,
      observation: { ...matchingConfiguration.observation!, status: "stale" },
      comparison: { ...matchingConfiguration.comparison, paused: true }
    } });

    expect((await screen.findAllByText("Comparison paused")).length).toBeGreaterThan(0);
    expect(screen.getByText("Counts reflect last-observed data.")).toBeInTheDocument();
  });

  it("shows differences already computed by the host configuration endpoint", async () => {
    renderHostDetail(10, { configuration: {
      ...matchingConfiguration,
      comparison: {
        ...matchingConfiguration.comparison,
        summary: {
          booleans: { ...matchingConfiguration.comparison.summary.booleans, differ: 1, match: 349 },
          ports: matchingConfiguration.comparison.summary.ports
        }
      },
      differences: { ...matchingConfiguration.differences!, total: 1, booleans: [], ports: [], limitations: matchingConfiguration.differences!.limitations }
    } });

    expect(await screen.findByText("1 drifted")).toBeInTheDocument();
    expect(screen.getByText("1 Differences found")).toBeInTheDocument();
    expect(screen.getByText("(349/350 match)")).toBeInTheDocument();
    expect(screen.getByText("Drifted")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View full comparison" })).toHaveAttribute("href", "/hosts/10/configuration");
  });

  it("shows when no reference catalog is available", async () => {
    renderHostDetail(10, { configuration: {
      ...matchingConfiguration,
      reference: { kind: "none" },
      comparison: { ...matchingConfiguration.comparison, available: false }
    } });

    expect((await screen.findAllByText("No reference available")).length).toBeGreaterThan(0);
    expect(screen.queryByText("350 / 350 match")).not.toBeInTheDocument();
  });

  it("shows empty activity counts without active issues", async () => {
    renderHostDetail(10, { host: { host: { ...detailPayload.host, counts: { active_issues: 0, avcs_24h: 0, total_events: 0 } } } });

    await screen.findByRole("heading", { name: "Host health" });
    expect(screen.getByRole("region", { name: "Activity" })).toHaveTextContent("0");
    expect(screen.getByRole("region", { name: "Activity" })).toHaveTextContent("Active Issues");
  });

  it("keeps a long recent-activity list hostname-free and compact", async () => {
    const occurrences: HostOccurrencesResponse = {
      occurrences: Array.from({ length: 20 }, (_, index) => occurrence(1000 + index, { id: 200 + index })),
      meta: { next_cursor: null }
    };
    const { container } = renderHostDetail(10, { occurrences });

    expect((await screen.findAllByRole("link", { name: /httpd_t.*user_home_t/ })).length).toBeGreaterThan(0);
    expect(container.querySelectorAll(".host-occurrences-table tbody tr")).toHaveLength(20);
    expect(container.querySelector(".occurrence-host-name")).toBeNull();
    expect(screen.queryByText(RAW_PAYLOAD)).not.toBeInTheDocument();
  });

  it("shows a not-found alert for an unknown host", async () => {
    renderHostDetail(999, { notFound: true });

    await screen.findByText("Host not found");
    expect(screen.getByRole("link", { name: "Back to hosts" })).toHaveAttribute("href", "/hosts");
  });
});
