import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { HostConfigurationResponse } from "../api/configuration";
import { HostConfiguration } from "./HostConfiguration";

const identity = "sha256:" + "a".repeat(64);

const base: HostConfigurationResponse = {
  host: { id: 10, hostname: "alma-01", external_id: "alma-01" },
  observation: {
    status: "current",
    last_observed_at: "2026-09-25T10:00:00Z",
    last_received_at: "2026-09-25T10:00:00Z"
  },
  selinux: { enforcement: "enforcing", configured_policy_type: "targeted", boolean_status: "observed", policy_identity: identity },
  reference: {
    kind: "distribution_catalog",
    catalog_revision: {
      id: 3,
      display_name: "AlmaLinux 9",
      policy_type: "targeted",
      architecture: "x86_64",
      loaded_policy_digest: identity,
      content_digest: "sha256:" + "1".repeat(64),
      lifecycle: "active",
      applicability: "major_release"
    }
  },
  selection: {
    mode: "automatic", status: "selected", basis: "major_release_family_agreement", reason: null,
    selected_revision: { id: 3, display_name: "AlmaLinux 9", content_digest: "sha256:" + "1".repeat(64), loaded_policy_digest: identity, lifecycle: "active", distribution: "almalinux", major_version: "9", architecture: "x86_64", policy_type: "targeted" },
    candidates: [], candidate_count: 1, candidates_truncated: false,
    context: { distribution: "almalinux", major_version: "9", architecture: "x86_64", policy_type: "targeted" }, policy_identity_match: false, equivalence_asserted: false,
    families: {
      booleans: { status: "comparable", reference_status: "complete", host_status: "observed", comparison_allowed: true, reason: null },
      ports: { status: "comparable", reference_status: "complete", host_status: "observed", comparison_allowed: true, reason: null },
      effective_permissive_domains: { status: "unknown", reference_status: "unavailable", host_status: "observed", comparison_allowed: false, reason: "effective_policy_requires_exact_reference" }
    }
  },
  reference_options: { revisions: [], truncated: false },
  comparison: {
    available: true,
    paused: false,
    effective_permissive_domains: {
      status: "unknown", reason: "effective_policy_requires_exact_reference", counts: null, matching: null, unexpected_on_host: null, missing_from_host: null,
      host: { status: "observed", policy_identity: identity, semantics_version: 1, evaluator_version: "SETools test", evaluated_at: null, snapshot_id: 1, observation_id: 1, evidence_basis: "trusted_current_checkpoint" },
      reference: { status: "unavailable", policy_identity: identity, semantics_version: null, evaluator_version: null, evaluated_at: null, revision_id: 3, content_digest: "sha256:" + "1".repeat(64) },
      selection: { mode: "automatic", basis: "major_release_family_agreement", policy_identity_match: false, equivalence_asserted: false }
    },
    summary: {
      booleans: { reference_entries: 2, compared: 2, match: 1, differ: 1, host_only: 1, not_observed: 0, unavailable: 0 },
      ports: { compared: 2, match: 1, differ: 1, not_observed: 0 }
    }
  },
  view: "differences",
  differences: {
    total: 3,
    booleans: [
      { name: "httpd_can_network_connect", kind: "differs", reference_default: false, observed_current: true, host_reported_default: false, description: "Allow network" },
      { name: "extra_local_boolean", kind: "host_only", reference_default: null, observed_current: true, host_reported_default: true, description: null }
    ],
    ports: [
      { protocol: "tcp", start: 8443, end: 8443, catalog_types: [], observed_types: ["my_app_port_t"], relation: "observed_not_represented", local_classification: "custom", inventory_status: "observed" }
    ],
    limitations: { reference_only_booleans: [], unavailable_booleans: [], port_segments: [] }
  }
};

const booleansPage: HostConfigurationResponse["booleans"] = {
  rows: [
    { name: "httpd_can_network_connect", current: true, host_default: false, reference_default: false, description: "Allow network", catalog_status: "defined", status: "observed" },
    { name: "extra_local_boolean", current: true, host_default: true, reference_default: null, description: null, catalog_status: "not_defined", status: "observed" },
    { name: "named_file_trusted_context", current: true, host_default: true, reference_default: true, description: "Trust named files", catalog_status: "defined", status: "observed" }
  ],
  total: 57,
  page: 1,
  page_size: 50,
  pages: 2
};

const portsView: HostConfigurationResponse = {
  ...base,
  view: "ports",
  ports: {
    segments: [
      { protocol: "tcp", start: 8443, end: 8443, catalog_types: [], observed_types: ["my_app_port_t"], relation: "observed_not_represented", local_classification: "custom", inventory_status: "observed" },
      { protocol: "tcp", start: 8080, end: 8080, catalog_types: ["http_port_t"], observed_types: ["http_port_t"], relation: "matching_effective_type", local_classification: "not_confirmed_custom", inventory_status: "observed" }
    ],
    total: 2,
    page: 1,
    page_size: 50,
    pages: 1
  },
  differences: undefined
};

const noReference: HostConfigurationResponse = {
  ...base,
  reference: { kind: "none" },
  selection: { ...base.selection, status: "absent", basis: null, reason: "no_matching_candidates", selected_revision: null },
  comparison: { ...base.comparison, available: false, paused: false, summary: { booleans: base.comparison.summary.booleans, ports: base.comparison.summary.ports } },
  differences: undefined
};

const alternateIdentity: NonNullable<HostConfigurationResponse["selection"]["selected_revision"]> = {
  ...base.selection.selected_revision!, id: 4, content_digest: "sha256:" + "2".repeat(64), loaded_policy_digest: "sha256:" + "b".repeat(64)
};
const selectable: HostConfigurationResponse = { ...base, reference_options: { revisions: [base.selection.selected_revision!, alternateIdentity], truncated: false } };
const explicit: HostConfigurationResponse = {
  ...selectable,
  reference: { kind: "distribution_catalog", catalog_revision: { ...base.reference.catalog_revision!, id: 4, content_digest: alternateIdentity.content_digest, applicability: "explicit" } },
  selection: { ...base.selection, mode: "explicit", basis: "explicit_revision", selected_revision: alternateIdentity, equivalence_asserted: false, policy_identity_match: false }
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

function renderHostConfiguration(payload: HostConfigurationResponse, initialEntry = "/hosts/10/configuration", explicitResponse?: HostConfigurationResponse) {
  const fetchMock = vi.fn();
  fetchMock.mockImplementation((url: string) => {
    if (url === "/api/v1/hosts/10") {
      return Promise.resolve(jsonResponse(200, {
        host: {
          id: 10,
          hostname: "alma-01",
          external_id: "alma-01",
          snapshot: { selinux: { kernel_policy_version: 33 } },
          agent: { agent_version: "0.2.0" }
        }
      }));
    }
    if (url.startsWith("/api/v1/hosts/10/configuration")) {
      const search = new URL(url, "http://localhost").searchParams;
      let body = search.has("reference_revision_id") && explicitResponse ? explicitResponse : payload;
      if (search.get("view") === "booleans") {
        body = { ...body, view: "booleans", booleans: booleansPage, differences: undefined };
      } else if (search.get("view") === "ports") {
        body = { ...body, view: "ports", ports: portsView.ports, differences: undefined };
      }
      const query = search.get("q")?.toLowerCase();
      const requestedPage = Number(search.get("page") ?? "1");
      if (body.booleans) {
        const rows = query ? body.booleans.rows.filter((row) => row.name.toLowerCase().includes(query)) : body.booleans.rows;
        const total = query ? rows.length : body.booleans.total;
        body = { ...body, booleans: { ...body.booleans, rows, total, page: requestedPage, pages: Math.ceil(total / body.booleans.page_size) } };
      }
      if (body.ports && query) {
        const segments = body.ports.segments.filter((segment) => `${segment.protocol}/${segment.start}-${segment.end} ${(segment.observed_types ?? []).join(" ")} ${(segment.catalog_types ?? []).join(" ")}`.toLowerCase().includes(query));
        body = { ...body, ports: { ...body.ports, segments, total: segments.length, page: 1, pages: 1 } };
      }
      return Promise.resolve(jsonResponse(200, body));
    }
    return Promise.reject(new Error(`unexpected url ${url}`));
  });
  vi.stubGlobal("fetch", fetchMock);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route path="/hosts/:id/configuration" element={<HostConfiguration />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return { fetchMock, view, ...view };
}

describe("HostConfiguration", () => {
  it("presents automatic exact and major-release fallback bases without inferring them from names", async () => {
    const exact = { ...selectable, selection: { ...base.selection, basis: "exact_policy_identity" as const, policy_identity_match: true, equivalence_asserted: true } };
    const { unmount } = renderHostConfiguration(exact);
    expect(await screen.findByRole("heading", { name: /Exact policy reference/ })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Comparison reference" })).toHaveValue("automatic");
    unmount();
    renderHostConfiguration(selectable);
    expect(await screen.findByRole("heading", { name: /Boolean\/port agreement/ })).toBeInTheDocument();
    expect(screen.getByText(/not exact binary-policy equivalence/)).toBeInTheDocument();
    expect(screen.getByText("Loaded policy identity differs from selected reference.")).toBeInTheDocument();
  });

  it("chooses a temporary explicit URL revision, disambiguates duplicate names and returns to automatic", async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderHostConfiguration(selectable, "/hosts/10/configuration", explicit);
    await screen.findByRole("combobox", { name: "Comparison reference" });
    expect(screen.getByRole("option", { name: /AlmaLinux 9 · revision 3/ })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /AlmaLinux 9 · revision 4/ })).toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Comparison reference" }), "4");
    expect(await screen.findByRole("heading", { name: /Explicit reference/ })).toBeInTheDocument();
    expect(screen.getByText(/does not save a host preference/)).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("reference_revision_id=4"))).toBe(true);
    await user.click(screen.getByRole("tab", { name: "Booleans (2)" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).includes("reference_revision_id=4") && String(url).includes("view=booleans"))).toBe(true));
    await user.click(screen.getByRole("button", { name: "Return to automatic" }));
    expect(await screen.findByRole("heading", { name: /Boolean\/port agreement/ })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Comparison reference" })).toHaveValue("automatic");
    expect(fetchMock.mock.calls.every(([, options]) => options.method === "GET")).toBe(true);
  });

  it("restores only the viewed explicit selection from a shared URL", async () => {
    const { fetchMock } = renderHostConfiguration(selectable, "/hosts/10/configuration?reference_revision_id=4", explicit);
    expect(await screen.findByRole("heading", { name: /Explicit reference/ })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Comparison reference" })).toHaveValue("4");
    expect(fetchMock.mock.calls[0][0]).toContain("reference_revision_id=4");
  });

  it("makes ambiguity and archived target unavailability explicit without selectable archived revisions", async () => {
    const ambiguous = { ...noReference, reference_options: selectable.reference_options, selection: { ...noReference.selection, status: "ambiguous" as const, reason: "incompatible_candidate_families", candidates: selectable.reference_options.revisions, candidate_count: 2 } };
    const { unmount } = renderHostConfiguration(ambiguous);
    expect(await screen.findByRole("heading", { name: /Ambiguous reference/ })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Reference candidates" })).toBeInTheDocument();
    unmount();
    const archived = { ...noReference, selection: { ...noReference.selection, mode: "explicit" as const, status: "unavailable" as const, reason: "archived_reference", candidates: [{ ...alternateIdentity, lifecycle: "archived" as const }] } };
    renderHostConfiguration(archived, "/hosts/10/configuration?reference_revision_id=4");
    expect(await screen.findByText(/No other reference has been substituted/)).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /Requested revision 4 — unavailable/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Return to automatic" })).toBeInTheDocument();
  });

  it("does not present unavailable host families as a zero-difference match", async () => {
    const unknown = {
      ...explicit,
      selection: { ...explicit.selection, families: {
        ...explicit.selection.families,
        booleans: { ...explicit.selection.families.booleans, status: "unknown" as const, host_status: "unknown", comparison_allowed: false, reason: "host_inventory_unknown" },
        ports: { ...explicit.selection.families.ports, status: "unavailable" as const, host_status: "unavailable", comparison_allowed: false, reason: "host_inventory_unavailable" }
      } },
      differences: { ...base.differences!, total: 0, booleans: [], ports: [] }
    };
    renderHostConfiguration(unknown, "/hosts/10/configuration?reference_revision_id=4");
    expect(await screen.findByRole("heading", { name: /Booleans: unknown/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Ports: unavailable/ })).toBeInTheDocument();
    expect(screen.queryByText("Matches reference")).not.toBeInTheDocument();
    expect(screen.getByText("No observed Boolean/port differences — comparison limited")).toBeInTheDocument();
  });

  it("shows facts, reference, summary, and differences", async () => {
    const { container } = renderHostConfiguration(base);

    await screen.findByText("Differences (3)");
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "alma-01" })).toHaveLength(1);
    expect(screen.queryByRole("heading", { name: "alma-01" })).not.toBeInTheDocument();
    expect(screen.queryByText("Configuration", { selector: ".pf-v6-c-breadcrumb__item" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "AlmaLinux 9" })).toBeInTheDocument();
    expect(await screen.findByText((_, element) => Boolean(element?.classList.contains("configuration-reference-line")))).toHaveTextContent("Compared with AlmaLinux 9 · targeted · x86_64");
    expect(screen.getByText("Host policy format 33")).toBeInTheDocument();
    expect(screen.getByText(/^Observed .* ago$/)).toBeInTheDocument();
    expect(container.querySelector(".configuration-observed-at small")).toHaveTextContent("Sep 25, 10:00 UTC");
    expect(screen.getByText("SELinux enforcing")).toBeInTheDocument();
    expect(screen.getByText("Policy targeted")).toBeInTheDocument();
    expect(screen.getByLabelText("Differences found: 3")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Booleans" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Ports" })).toBeInTheDocument();
    expect(screen.getAllByText("1 / 2 match")).toHaveLength(2);
    const booleanSummary = screen.getByRole("heading", { name: "Booleans" }).closest(".configuration-summary-card");
    const portsSummary = screen.getByRole("heading", { name: "Ports" }).closest(".configuration-summary-card");
    expect(booleanSummary).not.toBeNull();
    expect(portsSummary).not.toBeNull();
    expect(within(booleanSummary as HTMLElement).getByText("Differ").closest(".configuration-summary-metric")).toHaveTextContent("1");
    expect(within(booleanSummary as HTMLElement).getByText("Host-only")).toBeInTheDocument();
    expect(within(booleanSummary as HTMLElement).getByText("Not observed")).toBeInTheDocument();
    expect(within(booleanSummary as HTMLElement).getByText("Unavailable")).toBeInTheDocument();
    expect(within(portsSummary as HTMLElement).getByText("Unconfirmed")).toBeInTheDocument();
    expect(within(portsSummary as HTMLElement).getByRole("button", { name: "About Unconfirmed" })).toBeInTheDocument();
    expect(container.querySelector(".configuration-summary-note")).toBeNull();
    expect(screen.getByRole("tab", { name: "Booleans (2)" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Ports (2)" })).toBeInTheDocument();
    expect(screen.getByText("httpd_can_network_connect")).toBeInTheDocument();
    expect(screen.getAllByText("Boolean", { selector: "td" })).toHaveLength(2);
    expect(screen.getByText("Host", { selector: "th" })).toBeInTheDocument();
    expect(screen.getByText("Reference", { selector: "th" })).toBeInTheDocument();
    expect(screen.getAllByText("On", { selector: "td" })).toHaveLength(2);
    expect(screen.getByText("Off", { selector: "td" })).toBeInTheDocument();
    expect(screen.getAllByText("Differs")).toHaveLength(2);
    expect(screen.getByText("Allow network")).toBeInTheDocument();
    expect(screen.getByText("extra_local_boolean")).toBeInTheDocument();
    expect(screen.getAllByText("Host-only")).toHaveLength(2);
    expect(screen.getByText("tcp/8443")).toBeInTheDocument();
    expect(screen.getByText("Custom mapping")).toBeInTheDocument();
    expect(container.querySelector(".configuration-technical-details")).not.toHaveAttribute("open");
    expect(container.querySelector(".configuration-comparison-header")).not.toHaveTextContent(identity);
    await userEvent.setup().click(screen.getByText("Technical details"));
    expect(screen.getByRole("button", { name: "Copy host policy identity" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy reference policy digest" })).toBeInTheDocument();
    expect(screen.getByText("Agent version")).toBeInTheDocument();
  });

  it("switches views through URL state and paginates booleans", async () => {
    const { fetchMock } = renderHostConfiguration(base);
    await screen.findByText("Differences (3)");

    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Booleans (2)" }));
    const pagination = await screen.findByRole("navigation", { name: "booleans pagination" });
    expect(pagination).toBeInTheDocument();
    expect(pagination.closest(".pf-v6-c-pagination")).toHaveClass("pf-m-display-full");
    const paginationStatus = screen.getByText("1–50 of 57");
    expect(paginationStatus).toHaveAttribute("aria-live", "polite");
    expect(paginationStatus.closest(".configuration-view-toolbar")).not.toBeNull();
    expect(paginationStatus.closest(".configuration-view-pagination-status")).toHaveClass("pf-m-align-self-center");
    expect(screen.getByRole("button", { name: "Go to previous page" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Go to next page" })).toBeEnabled();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/configuration?view=booleans", expect.objectContaining({ method: "GET" }));
    expect(screen.getByText("named_file_trusted_context")).toBeInTheDocument();
    expect(screen.getByText("Trust named files")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Host" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Reference" })).toBeInTheDocument();
    expect(screen.getByText("Differs")).toBeInTheDocument();
    expect(screen.getByText("Match")).toBeInTheDocument();
    expect(screen.getAllByRole("row")[1]).toHaveTextContent("httpd_can_network_connect");
    expect(screen.getAllByRole("row")[1]).toHaveTextContent("Differs");

    await user.click(screen.getByRole("button", { name: "Go to next page" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/configuration?view=booleans&page=2", expect.objectContaining({ method: "GET" }))
    );
    expect(await screen.findByText("51–57 of 57")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Go to previous page" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Go to next page" })).toBeDisabled();
  });

  it("searches port segments by number", async () => {
    const { fetchMock } = renderHostConfiguration(base);
    await screen.findByText("Differences (3)");

    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Ports (2)" }));
    expect(await screen.findByRole("navigation", { name: "port segments pagination" })).toBeInTheDocument();
    expect(screen.getByText("1–2 of 2")).toBeInTheDocument();
    expect(screen.getAllByRole("row")[1]).toHaveTextContent("tcp/8443");

    await user.type(screen.getByRole("textbox", { name: "Search ports" }), "8443");
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/configuration?view=ports&q=8443", expect.objectContaining({ method: "GET" }))
    );
    expect(await screen.findByText("1–1 of 1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Go to previous page" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Go to next page" })).toBeDisabled();
    expect(screen.getByRole("columnheader", { name: "Host type" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Reference type" })).toBeInTheDocument();
  });

  it("shows the no-reference state without a comparison", async () => {
    renderHostConfiguration(noReference);

    await screen.findByRole("heading", { name: /No reference available/ });
    expect(
      screen.getByText("No active distribution reference matched this host.")
    ).toBeInTheDocument();
    expect(screen.queryByText("Differences (3)")).not.toBeInTheDocument();
    expect(screen.getByText((_, element) => Boolean(element?.classList.contains("configuration-reference-line")))).toHaveTextContent("Reference No active reference");
  });

  it("uses a compact empty state when there are no differences", async () => {
    renderHostConfiguration({
      ...base,
      differences: { ...base.differences!, total: 0, booleans: [], ports: [] }
    });

    expect(await screen.findByText("No observed Boolean/port differences — comparison limited")).toBeInTheDocument();
    expect(screen.queryByText("Matches reference")).not.toBeInTheDocument();
    expect(screen.getByText("No boolean or port differences were observed.")).toBeInTheDocument();
  });

  it("keeps the stale comparison visible and warns that the data is old", async () => {
    renderHostConfiguration({
      ...base,
      observation: { ...base.observation!, status: "stale" },
      comparison: { ...base.comparison, paused: true }
    });

    expect(await screen.findByText("Comparison based on stale host configuration")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Differences (3)" })).toBeInTheDocument();
    expect(screen.getByText("httpd_can_network_connect")).toBeInTheDocument();
  });

  it("shows a relative observation time with the UTC timestamp as secondary metadata", async () => {
    const observedAt = new Date(Date.now() - 4 * 60_000 - 10_000).toISOString();
    renderHostConfiguration({ ...base, observation: { ...base.observation!, last_observed_at: observedAt } });

    expect(await screen.findByText("Observed 4 minutes ago")).toHaveAttribute("dateTime", observedAt);
  });

  it("lists many boolean and port differences without per-row cards", async () => {
    renderHostConfiguration({
      ...base,
      differences: {
        ...base.differences!,
        total: 60,
        booleans: Array.from({ length: 30 }, (_, index) => ({ name: `boolean_${index}`, kind: "differs" as const, reference_default: false, observed_current: true, host_reported_default: false, description: null })),
        ports: Array.from({ length: 30 }, (_, index) => ({ protocol: "tcp", start: 8000 + index, end: 8000 + index, catalog_types: ["unreserved_port_t"], observed_types: ["http_port_t"], relation: "observed_not_represented", local_classification: "custom", inventory_status: "observed" }))
      }
    });

    expect((await screen.findAllByText("Boolean", { selector: "td" })).length).toBe(30);
    expect(screen.getAllByText("Port mapping", { selector: "td" })).toHaveLength(30);
    expect(screen.getByRole("table", { name: "Configuration differences" })).toBeInTheDocument();
  });
});
