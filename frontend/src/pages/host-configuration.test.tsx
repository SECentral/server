import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";
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
  selinux: { enforcement: "enforcing", configured_policy_type: "targeted", boolean_status: "observed", policy_identity: identity,
    effective_permissive_domains: { status: "observed", domains: ["postgresql_t"], policy_identity: identity, provenance: "exact_loaded_policy_artifact" } },
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
      effective_permissive_domains: { status: "comparable", reference_status: "observed", host_status: "observed", comparison_allowed: true, reason: null }
    }
  },
  reference_options: { revisions: [], truncated: false },
  comparison: {
    available: true,
    paused: false,
    effective_permissive_domains: {
      status: "observed", reason: null, counts: { matching: 1, unexpected_on_host: 0, missing_from_host: 0 }, matching: ["postgresql_t"], unexpected_on_host: [], missing_from_host: [],
      host: { status: "observed", policy_identity: identity, semantics_version: 1, evaluator_version: "SETools test", evaluated_at: null, snapshot_id: 1, observation_id: 1, evidence_basis: "trusted_current_checkpoint" },
      reference: { status: "observed", policy_identity: identity, semantics_version: 1, evaluator_version: "SETools test", evaluated_at: null, revision_id: 3, content_digest: "sha256:" + "1".repeat(64), provenance: "inline_catalog_extraction" },
      selection: { mode: "automatic", basis: "major_release_family_agreement", policy_identity_match: false, equivalence_asserted: false }
    },
    summary: {
      booleans: { reference_entries: 2, compared: 2, match: 1, differ: 1, host_only: 1, not_observed: 0, unavailable: 0 },
      ports: { compared: 2, match: 1, differ: 1, not_observed: 0 }
    }
  },
  view: "differences",
  entries: { rows: [
    { kind: "boolean", name: "httpd_can_network_connect", host_value: "On", reference_value: "Off", result: "differs", description: "Allow network" },
    { kind: "boolean", name: "extra_local_boolean", host_value: "On", reference_value: null, result: "host_only", description: null },
    { kind: "port", name: "tcp/8443", host_value: "my_app_port_t", reference_value: null, result: "host_only", description: "Custom mapping" }
  ], total: 3, page: 1, page_size: 25, pages: 1 },
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
  page_size: 25,
  pages: 3
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
    page_size: 25,
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

const sixDeviations: HostConfigurationResponse = {
  ...base,
  entries: { rows: [
    { kind: "boolean", name: "setting_one", host_value: "On", reference_value: "Off", result: "differs", description: null },
    { kind: "boolean", name: "setting_two", host_value: "Off", reference_value: "On", result: "differs", description: null },
    ...Array.from({ length: 4 }, (_, index) => ({ kind: "boolean" as const, name: `setting_unobserved_${index}`, host_value: null, reference_value: "Off", result: "not_observed" as const, description: null }))
  ], total: 6, page: 1, page_size: 25, pages: 1 },
  comparison: { ...base.comparison, summary: {
    booleans: { ...base.comparison.summary.booleans!, reference_entries: 6, differ: 2, host_only: 0, not_observed: 4 },
    ports: { ...base.comparison.summary.ports!, differ: 0 }
  } }
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

function NavigationState() {
  const location = useLocation();
  const navigate = useNavigate();
  return <><output aria-label="Current URL">{location.search}</output><button onClick={() => navigate(-1)}>Back</button></>;
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
      const deviationRows = body.entries?.rows ?? [];
      body = { ...body, comparison: { ...body.comparison, deviations: body.comparison.available && !body.comparison.paused ? {
        total: deviationRows.length,
        by_result: {
          differs: deviationRows.filter((row) => row.result === "differs").length,
          not_observed: deviationRows.filter((row) => row.result === "not_observed").length,
          host_only: deviationRows.filter((row) => row.result === "host_only").length,
          reference_only: deviationRows.filter((row) => row.result === "reference_only").length
        },
        by_family: { boolean: deviationRows.filter((row) => row.kind === "boolean").length, port: deviationRows.filter((row) => row.kind === "port").length, domain: deviationRows.filter((row) => row.kind === "domain").length }
      } : null } };
      if (search.get("view") === "booleans") {
        body = { ...body, view: "booleans", booleans: booleansPage, differences: undefined };
      } else if (search.get("view") === "ports") {
        body = { ...body, view: "ports", ports: portsView.ports, differences: undefined };
      } else if (search.get("view") === "effective_permissive_domains") {
        const comparable = body.comparison.effective_permissive_domains.status === "observed" && !body.comparison.paused;
        body = { ...body, view: "effective_permissive_domains", entries: {
          rows: body.selinux.effective_permissive_domains?.status === "observed" ? [{ kind: "domain", name: "postgresql_t", host_value: "Permissive", reference_value: comparable ? "Permissive" : null, result: body.comparison.paused ? "stale" : comparable ? "match" : "not_compared", description: null }] : [],
          total: 1, page: 1, page_size: 25, pages: 1
        } };
      }
      const query = search.get("q")?.toLowerCase();
      const requestedPage = Number(search.get("page") ?? "1");
      const pageSize = Number(search.get("limit") ?? 25);
      if (body.entries) {
        let rows = query ? body.entries.rows.filter((row) => `${row.name} ${row.description ?? ""}`.toLowerCase().includes(query)) : body.entries.rows;
        if (search.get("view") === "differences" && search.has("results")) rows = rows.filter((row) => search.get("results")!.split(",").includes(row.result));
        const total = rows.length;
        const page = Math.min(requestedPage, Math.max(1, Math.ceil(total / pageSize)));
        body = { ...body, entries: { rows: rows.slice((page - 1) * pageSize, page * pageSize), total, page, page_size: pageSize, pages: Math.ceil(total / pageSize) } };
      }
      if (body.booleans) {
        const rows = query ? body.booleans.rows.filter((row) => row.name.toLowerCase().includes(query)) : body.booleans.rows;
        const total = query ? rows.length : body.booleans.total;
        body = { ...body, booleans: { ...body.booleans, rows, total, page: requestedPage, page_size: pageSize, pages: Math.ceil(total / pageSize) } };
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
          <Route path="/hosts/:id/configuration" element={<><HostConfiguration /><NavigationState /></>} />
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
    const card = await screen.findByLabelText("Baseline summary");
    expect(within(card).getByRole("combobox", { name: "Comparison baseline" })).toHaveValue("automatic");
    expect(within(card).getByText("Current observation")).toBeVisible();
    expect(screen.queryByText(/Boolean\/port agreement/)).not.toBeInTheDocument();
    unmount();
    renderHostConfiguration(selectable);
    expect(await screen.findByRole("combobox", { name: "Comparison baseline" })).toHaveValue("automatic");
    expect(screen.queryByText(/Active revisions are listed/)).not.toBeInTheDocument();
  });

  it("chooses a temporary explicit URL revision, disambiguates duplicate names and returns to automatic", async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderHostConfiguration(selectable, "/hosts/10/configuration", explicit);
    await screen.findByRole("combobox", { name: "Comparison baseline" });
    expect(screen.getByRole("option", { name: /AlmaLinux 9 · revision 3/ })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /AlmaLinux 9 · revision 4/ })).toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Comparison baseline" }), "4");
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Comparison baseline" })).toHaveValue("4"));
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("reference_revision_id=4"))).toBe(true);
    await user.click(screen.getByRole("tab", { name: "Booleans (2)" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).includes("reference_revision_id=4") && String(url).includes("view=booleans"))).toBe(true));
    await user.click(screen.getByRole("button", { name: "Return to automatic" }));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Comparison baseline" })).toHaveValue("automatic"));
    expect(fetchMock.mock.calls.every(([, options]) => options.method === "GET")).toBe(true);
  });

  it("restores only the viewed explicit selection from a shared URL", async () => {
    const { fetchMock } = renderHostConfiguration(selectable, "/hosts/10/configuration?reference_revision_id=4", explicit);
    expect(await screen.findByRole("combobox", { name: "Comparison baseline" })).toHaveValue("4");
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
    expect(screen.getByText("Comparison limited", { selector: ".pf-v6-c-alert__title" })).toBeInTheDocument();
  });

  it("shows facts, reference, summary, and differences", async () => {
    const { container } = renderHostConfiguration(base);

    await screen.findByText("Deviations (3)");
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "alma-01" })).toHaveLength(1);
    expect(screen.queryByRole("heading", { name: "alma-01" })).not.toBeInTheDocument();
    expect(screen.queryByText("Configuration", { selector: ".pf-v6-c-breadcrumb__item" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "AlmaLinux 9" })).toBeInTheDocument();
    expect(screen.getByLabelText("Baseline summary")).toHaveTextContent("AlmaLinux 9 · targeted · x86_64");
    expect(screen.getByText(/^Observed .* ago/)).toHaveTextContent("Sep 25, 10:00 UTC");
    expect(screen.getByText("enforcing")).toBeInTheDocument();
    expect(screen.getByLabelText("Deviations found: 3")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Booleans" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Ports" })).toBeInTheDocument();
    expect(screen.getAllByText("1 / 2 match")).toHaveLength(2);
    const booleanSummary = screen.getByRole("heading", { name: "Booleans" }).closest(".configuration-summary-card");
    const portsSummary = screen.getByRole("heading", { name: "Ports" }).closest(".configuration-summary-card");
    expect(booleanSummary).not.toBeNull();
    expect(portsSummary).not.toBeNull();
    expect(within(booleanSummary as HTMLElement).getByText("2 deviations")).toBeInTheDocument();
    expect(within(portsSummary as HTMLElement).getByText("1 deviation")).toBeInTheDocument();
    expect(screen.queryByText("Unconfirmed")).not.toBeInTheDocument();
    expect(container.querySelector(".configuration-summary-note")).toBeNull();
    expect(screen.getByRole("tab", { name: "Booleans (2)" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Ports (2)" })).toBeInTheDocument();
    expect(screen.getByText("httpd_can_network_connect")).toBeInTheDocument();
    expect(screen.getAllByText("Boolean", { selector: "td" })).toHaveLength(2);
    expect(screen.getByText("Host", { selector: "th" })).toBeInTheDocument();
    expect(screen.getByText("Reference", { selector: "th" })).toBeInTheDocument();
    expect(screen.getAllByText("On", { selector: "td" })).toHaveLength(2);
    expect(screen.getByText("Off", { selector: "td" })).toBeInTheDocument();
    expect(screen.getAllByText("Value Mismatch")).toHaveLength(1);
    expect(screen.getByText("Allow network")).toBeInTheDocument();
    expect(screen.getByText("extra_local_boolean")).toBeInTheDocument();
    expect(screen.getAllByText("Host Only")).toHaveLength(2);
    expect(screen.getByText("tcp/8443")).toBeInTheDocument();
    expect(screen.getByText("Custom mapping")).toBeInTheDocument();
    expect(container).not.toHaveTextContent("sha256:");
    expect(screen.queryByText("Technical details")).not.toBeInTheDocument();
    expect(screen.queryByText("Comparison evidence")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Comparison scope & limitations" })).not.toBeInTheDocument();
  });

  it("switches views through URL state and paginates booleans", async () => {
    const { fetchMock } = renderHostConfiguration(base);
    await screen.findByText("Deviations (3)");

    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Booleans (2)" }));
    const pagination = await screen.findByRole("navigation", { name: "Booleans pagination" });
    expect(pagination).toBeInTheDocument();
    expect(pagination.closest(".table-pagination")).not.toBeNull();
    expect(screen.getByText("57 results")).toHaveAttribute("aria-live", "polite");
    expect(screen.getByRole("button", { name: "Go to previous page" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Go to next page" })).toBeEnabled();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/configuration?view=booleans", expect.objectContaining({ method: "GET" }));
    expect(screen.getByText("named_file_trusted_context")).toBeInTheDocument();
    expect(screen.getByText("Trust named files")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Host" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Reference" })).toBeInTheDocument();
    expect(screen.getByText("Value Mismatch")).toBeInTheDocument();
    expect(screen.getByText("Match")).toBeInTheDocument();
    expect(screen.getAllByRole("row")[1]).toHaveTextContent("httpd_can_network_connect");
    expect(screen.getAllByRole("row")[1]).toHaveTextContent("Value Mismatch");

    await user.click(screen.getByRole("button", { name: "Go to next page" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/configuration?view=booleans&page=2", expect.objectContaining({ method: "GET" }))
    );
    expect(await screen.findByRole("button", { name: "26 - 50 of 57" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Go to previous page" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Go to next page" })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Go to last page" }));
    expect(await screen.findByRole("button", { name: "51 - 57 of 57" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Go to next page" })).toBeDisabled();
  });

  it("offers full-page sizing and resets the page while preserving the viewed reference", async () => {
    const { fetchMock } = renderHostConfiguration(selectable, "/hosts/10/configuration?view=booleans&page=2&reference_revision_id=4", explicit);
    await screen.findByRole("table", { name: "Boolean rows" });
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "26 - 50 of 57" }));
    await user.click(screen.getByRole("menuitem", { name: "100 per page" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => {
      const params = new URL(url, "http://localhost").searchParams;
      return params.get("limit") === "100" && params.get("reference_revision_id") === "4" && !params.has("page");
    })).toBe(true));
    expect(screen.getByRole("spinbutton", { name: "Current page" })).toHaveValue(1);
  });

  it("searches port segments by number", async () => {
    const { fetchMock } = renderHostConfiguration(base);
    await screen.findByText("Deviations (3)");

    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Ports (2)" }));
    expect(await screen.findByRole("navigation", { name: "Ports pagination" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "1 - 2 of 2" })).toBeInTheDocument();
    expect(screen.getAllByRole("row")[1]).toHaveTextContent("tcp/8443");

    await user.type(screen.getByRole("textbox", { name: "Search ports" }), "8443");
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/configuration?view=ports&q=8443", expect.objectContaining({ method: "GET" }))
    );
    expect(await screen.findByRole("button", { name: "1 - 1 of 1" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Go to previous page" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Go to next page" })).toBeDisabled();
    expect(screen.getByRole("columnheader", { name: "Host type" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Reference type" })).toBeInTheDocument();
  });

  it("shows the no-reference state without a comparison", async () => {
    renderHostConfiguration(noReference);

    await screen.findByRole("heading", { name: /No reference comparison available/ });
    expect(
      screen.getByText("No active distribution reference matched this host.")
    ).toBeInTheDocument();
    expect(screen.queryByText("Deviations (3)")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Baseline summary")).toHaveTextContent("No active reference");
    await userEvent.setup().click(screen.getByRole("tab", { name: "Ports" }));
    const ports = await screen.findByRole("table", { name: "Port segments" });
    expect(within(ports).queryByText("Value Mismatch")).not.toBeInTheDocument();
    expect(within(ports).getAllByText("Not compared")).toHaveLength(2);
  });

  it("groups the domain summary in a card and shows domain inventory only in its URL-backed tab", async () => {
    const user = userEvent.setup();
    const { container, fetchMock, unmount } = renderHostConfiguration(selectable, "/hosts/10/configuration?reference_revision_id=4", explicit);
    const heading = await screen.findByRole("heading", { name: "Effective permissive domains" });
    const summary = heading.closest(".pf-v6-c-card")!;
    expect(summary).not.toBeNull();
    expect(within(summary as HTMLElement).getByText("1 match")).toBeVisible();
    expect(screen.queryByRole("table", { name: "Effective permissive domains" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("link", { name: "View effective permissive domains" }));
    const inventory = await screen.findByRole("table", { name: "Effective permissive domains" });
    expect(inventory.closest(".pf-v6-c-card")).not.toBeNull();
    expect(within(inventory).getByText("postgresql_t")).toBeVisible();
    expect(within(inventory).getByRole("columnheader", { name: "Comparison Result" })).toBeVisible();
    expect(screen.getByRole("navigation", { name: "Effective permissive domains pagination" }).closest(".table-pagination")).not.toBeNull();
    expect(screen.getByRole("tab", { name: "Effective permissive domains (1)" })).toHaveAttribute("aria-controls", "configuration-panel");
    expect(screen.getByRole("tabpanel", { name: "Effective permissive domains (1)" })).toHaveAttribute("id", "configuration-panel");
    expect(screen.getByLabelText("Current URL")).toHaveTextContent("view=effective_permissive_domains");
    expect(screen.getByRole("tab", { name: "Effective permissive domains (1)" })).toHaveAttribute("aria-selected", "true");
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("reference_revision_id=4"))).toBe(true);
    expect(container).not.toHaveTextContent("sha256:");
    expect(container).not.toHaveTextContent("Comparison evidence");
    unmount();
    renderHostConfiguration(selectable, "/hosts/10/configuration?view=effective_permissive_domains&reference_revision_id=4", explicit);
    expect(await screen.findByRole("table", { name: "Effective permissive domains" })).toBeVisible();
    expect(screen.getByRole("combobox", { name: "Comparison baseline" })).toHaveValue("4");
  });

  it("keeps observed domains accessible without a reference and does not claim a match", async () => {
    const payload: HostConfigurationResponse = { ...noReference, comparison: { ...noReference.comparison, effective_permissive_domains: {
      ...base.comparison.effective_permissive_domains, status: "unknown" as const, reason: "reference_absent", counts: null,
      matching: null, unexpected_on_host: null, missing_from_host: null
    } } };
    renderHostConfiguration(payload);
    expect(await screen.findByText("1 observed on host")).toBeVisible();
    await userEvent.setup().click(screen.getByRole("tab", { name: "Effective permissive domains (1)" }));
    expect(await screen.findByText("postgresql_t")).toBeVisible();
    expect(screen.getByText(/No applicable reference was selected/)).toBeVisible();
    expect(screen.queryByText("Matches reference")).not.toBeInTheDocument();
  });

  it("does not display retained domain comparisons as current while paused", async () => {
    renderHostConfiguration({ ...base, comparison: { ...base.comparison, paused: true } }, "/hosts/10/configuration?view=effective_permissive_domains");
    expect(await screen.findByRole("heading", { name: /Comparison paused/ })).toBeVisible();
    expect(screen.getByRole("table", { name: "Effective permissive domains" })).toHaveTextContent("Unverified");
    expect(screen.queryByLabelText("Effective permissive-domain comparison counts")).not.toBeInTheDocument();
    expect(screen.queryByText("Matches reference")).not.toBeInTheDocument();
  });

  it.each([
    ["pending", "Host analysis pending", "host_permissive_analysis_pending"],
    ["error", "Host analysis failed", "host_permissive_analysis_error"],
    ["unavailable", "Host state unavailable", "host_permissive_analysis_unavailable"]
  ] as const)("keeps %s domain analysis distinct from an empty match", async (status, message, reason) => {
    renderHostConfiguration({ ...base,
      selinux: { ...base.selinux, effective_permissive_domains: { ...base.selinux.effective_permissive_domains!, status, domains: null } },
      comparison: { ...base.comparison, effective_permissive_domains: { ...base.comparison.effective_permissive_domains,
        status: "unknown", reason, counts: null, matching: null, unexpected_on_host: null, missing_from_host: null
      } }
    }, "/hosts/10/configuration?view=effective_permissive_domains");
    expect(await screen.findByText(message)).toBeVisible();
    expect(screen.getByRole("tab", { name: "Effective permissive domains" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByLabelText("Effective permissive-domain comparison counts")).not.toBeInTheDocument();
    expect(screen.queryByText("Matches reference")).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("tab", { name: "Deviations (3)" }));
    expect(await screen.findByRole("heading", { name: /Comparison limited/ })).toBeVisible();
  });

  it("uses a compact empty state when there are no differences", async () => {
    renderHostConfiguration({
      ...base,
      comparison: { ...base.comparison, summary: { booleans: { ...base.comparison.summary.booleans!, differ: 0, host_only: 0 }, ports: { ...base.comparison.summary.ports!, differ: 0 } } },
      differences: { ...base.differences!, total: 0, booleans: [], ports: [] },
      entries: { rows: [], total: 0, page: 1, page_size: 25, pages: 0 }
    });

    expect(await screen.findByText("No deviations.")).toBeInTheDocument();
    expect(screen.getByText("Matches reference")).toBeInTheDocument();
  });

  it("retains the baseline while replacing stale match and difference summaries with an explicit paused state", async () => {
    renderHostConfiguration({
      ...base,
      observation: { ...base.observation!, status: "stale" },
      comparison: { ...base.comparison, paused: true }
    });

    expect(await screen.findByRole("heading", { name: /Comparison paused/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Deviations" })).toBeInTheDocument();
    expect(screen.getByText(/Current matches and deviations are unverified/)).toBeVisible();
    expect(screen.queryByLabelText("Deviations found: 3")).not.toBeInTheDocument();
    expect(screen.queryAllByText(/\d+ \/ \d+ match/)).toHaveLength(0);
    expect(screen.queryByRole("table", { name: "Baseline deviations" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "AlmaLinux 9" })).toBeVisible();
  });

  it("shows a relative observation time with the UTC timestamp as secondary metadata", async () => {
    const observedAt = new Date(Date.now() - 4 * 60_000 - 10_000).toISOString();
    renderHostConfiguration({ ...base, observation: { ...base.observation!, last_observed_at: observedAt } });

    expect(await screen.findByText(/^Observed 4 minutes ago/)).toHaveAttribute("dateTime", observedAt);
  });

  it("paginates differences, searches from page one, and preserves the baseline through back navigation", async () => {
    const rows: NonNullable<HostConfigurationResponse["entries"]>["rows"] = Array.from({ length: 60 }, (_, index) => ({ kind: "boolean", name: `boolean_${index}`, host_value: "On", reference_value: "Off", result: "differs", description: null }));
    const { fetchMock } = renderHostConfiguration({
      ...base,
      entries: { rows, total: 60, page: 1, page_size: 25, pages: 3 },
      differences: {
        ...base.differences!,
        total: 60,
        booleans: Array.from({ length: 30 }, (_, index) => ({ name: `boolean_${index}`, kind: "differs" as const, reference_default: false, observed_current: true, host_reported_default: false, description: null })),
        ports: Array.from({ length: 30 }, (_, index) => ({ protocol: "tcp", start: 8000 + index, end: 8000 + index, catalog_types: ["unreserved_port_t"], observed_types: ["http_port_t"], relation: "observed_not_represented", local_classification: "custom", inventory_status: "observed" }))
      }
    }, "/hosts/10/configuration?reference_revision_id=4&page=2");
    const table = await screen.findByRole("table", { name: "Baseline deviations" });
    expect(within(table).getAllByText("Boolean")).toHaveLength(25);
    expect(within(table).getByText("boolean_25")).toBeVisible();
    const pagination = screen.getByRole("navigation", { name: "Deviations pagination" });
    expect(pagination.closest(".table-pagination")).not.toBeNull();
    const user = userEvent.setup();
    await user.type(screen.getByRole("textbox", { name: "Search deviations" }), "boolean_59");
    await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => {
      const params = new URL(url, "http://localhost").searchParams;
      return params.get("q") === "boolean_59" && !params.has("page") && params.get("reference_revision_id") === "4";
    })).toBe(true));
    expect(await screen.findByRole("button", { name: "1 - 1 of 1" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByLabelText("Current URL")).toHaveTextContent("q=boolean_5");
  });

  it("shows not-observed booleans directly in Differences, separately from confirmed drift", async () => {
    const names = ["gluster_anon_write", "gluster_export_all_ro", "gluster_export_all_rw", "gluster_use_execmem"];
    renderHostConfiguration({ ...base,
      comparison: { ...base.comparison, summary: {
        booleans: { ...base.comparison.summary.booleans!, reference_entries: 4, differ: 0, host_only: 0, match: 0, not_observed: 4 },
        ports: { ...base.comparison.summary.ports!, differ: 0 }
      } },
      entries: { rows: names.map((name, index) => ({ kind: "boolean", name, host_value: null, reference_value: index ? "Off" : "On", result: "not_observed", description: null })), total: 4, page: 1, page_size: 25, pages: 1 },
      differences: { ...base.differences!, total: 0, booleans: [], ports: [], limitations: { ...base.differences!.limitations, reference_only_booleans: names } }
    });
    const table = await screen.findByRole("table", { name: "Baseline deviations" });
    expect(screen.queryByRole("button", { name: "Comparison scope & limitations" })).not.toBeInTheDocument();
    for (const name of names) {
      const row = within(table).getByText(name).closest("tr")!;
      expect(row).toBeVisible();
      expect(within(row).getByText("Not observed")).toBeVisible();
      expect(within(row).getByText("Unobserved")).toBeVisible();
      expect(within(row).queryByText("Unknown")).not.toBeInTheDocument();
    }
    expect(within(table).getByText("On")).toBeVisible();
    expect(within(table).getAllByText("Off")).toHaveLength(3);
    expect(screen.getByRole("tab", { name: "Deviations (4)" })).toBeVisible();
    expect(screen.getByLabelText("Deviations found: 4")).toHaveTextContent("4 deviations");
    expect(screen.getByText("4 of 4 deviations")).toBeVisible();
    expect(screen.queryByText("Matches reference")).not.toBeInTheDocument();
    expect(screen.queryByText("Comparison limited")).not.toBeInTheDocument();
    expect(within(screen.getByLabelText("Baseline summary")).getByText("4 deviations")).toBeVisible();
    const user = userEvent.setup();
    expect(screen.queryByText(/Reference-only booleans:/)).not.toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: "Search deviations" }), "gluster_use_execmem");
    await waitFor(() => expect(screen.getByText("1 of 4 deviations")).toBeVisible());
    expect(screen.getByRole("table", { name: "Baseline deviations" })).toHaveTextContent("gluster_use_execmem");
    expect(screen.getByLabelText("Deviations found: 4")).toHaveTextContent("4 deviations");
  });

  it("keeps genuine comparison failures visible and discloses only additional useful details", async () => {
    renderHostConfiguration({ ...base,
      comparison: { ...base.comparison, summary: { ...base.comparison.summary, booleans: { ...base.comparison.summary.booleans!, not_observed: 1, unavailable: 1 } } },
      differences: { ...base.differences!, limitations: { ...base.differences!.limitations, reference_only_booleans: ["gluster_anon_write"], unavailable_booleans: ["other_unavailable"] } }
    });
    expect(await screen.findByRole("heading", { name: /Comparison limited/ })).toBeVisible();
    const disclosure = screen.getByRole("button", { name: "Comparison scope & limitations" });
    expect(disclosure).toHaveAttribute("aria-expanded", "false");
    await userEvent.setup().click(disclosure);
    expect(screen.getByText("Unavailable booleans: other_unavailable")).toBeVisible();
    expect(screen.queryByText(/Reference-only booleans:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/A comparison does not establish/)).not.toBeInTheDocument();
  });

  it("keeps six baseline deviations synchronized while category filters show two of six and restore through Back", async () => {
    const { fetchMock } = renderHostConfiguration(sixDeviations, "/hosts/10/configuration?view=differences&reference_revision_id=4&q=setting&page=2&limit=10");
    expect(await screen.findByRole("tab", { name: "Deviations (6)" })).toBeVisible();
    expect(screen.getByLabelText("Deviations found: 6")).toHaveTextContent("6 deviations");
    const card = screen.getByRole("link", { name: "View booleans" });
    expect(within(card).getByText("6 deviations")).toBeVisible();
    expect(screen.getByText("6 of 6 deviations")).toBeVisible();
    const table = screen.getByRole("table", { name: "Baseline deviations" });
    expect(within(table).getAllByText("Value Mismatch")).toHaveLength(2);
    expect(within(table).getAllByText("Unobserved")).toHaveLength(4);
    const unobserved = screen.getByRole("checkbox", { name: "Unobserved Items (4)" });
    expect(unobserved).toBeChecked();
    const user = userEvent.setup();
    await user.click(unobserved);
    await waitFor(() => expect(screen.getByText("2 of 6 deviations")).toBeVisible());
    expect(screen.getByRole("tab", { name: "Deviations (6)" })).toBeVisible();
    expect(screen.getByLabelText("Deviations found: 6")).toHaveTextContent("6 deviations");
    expect(within(table).queryByText("Unobserved")).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => {
      const params = new URL(url, "http://localhost").searchParams;
      return params.get("results") === "differs,host_only,reference_only" && params.get("q") === "setting" && params.get("reference_revision_id") === "4" && params.get("limit") === "10" && !params.has("page");
    })).toBe(true);
    await user.click(screen.getByRole("button", { name: "Back" }));
    await waitFor(() => expect(screen.getByText("6 of 6 deviations")).toBeVisible());
    expect(screen.getByRole("checkbox", { name: "Unobserved Items (4)" })).toBeChecked();
  });

  it("restores an empty category selection without presenting the baseline as a match", async () => {
    renderHostConfiguration(sixDeviations, "/hosts/10/configuration?view=differences&results=");
    expect(await screen.findByText("No matching deviations.")).toBeVisible();
    expect(screen.getByText("0 of 6 deviations")).toBeVisible();
    expect(screen.queryByText("Matches reference")).not.toBeInTheDocument();
    for (const checkbox of screen.getAllByRole("checkbox")) expect(checkbox).not.toBeChecked();
    const user = userEvent.setup();
    await user.click(screen.getByRole("checkbox", { name: "Value Mismatches (2)" }));
    await waitFor(() => expect(screen.getByText("2 of 6 deviations")).toBeVisible());
    expect(screen.getByRole("checkbox", { name: "Unobserved Items (4)" })).not.toBeChecked();
    await user.click(screen.getByRole("checkbox", { name: "Host Only (0)" }));
    await user.click(screen.getByRole("checkbox", { name: "Reference Only (0)" }));
    expect(screen.getByRole("checkbox", { name: "Unobserved Items (4)" })).not.toBeChecked();
    await user.click(screen.getByRole("checkbox", { name: "Value Mismatches (2)" }));
    await waitFor(() => expect(screen.getByText("No matching deviations.")).toBeVisible());
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(screen.getByText("6 of 6 deviations")).toBeVisible());
    for (const checkbox of screen.getAllByRole("checkbox")) expect(checkbox).toBeChecked();
  });
});
