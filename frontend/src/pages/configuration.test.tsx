import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { ConfigurationFleetResponse } from "../api/configuration";
import { Configuration } from "./Configuration";

const identity = "sha256:" + "3".repeat(64);
const otherIdentity = "sha256:" + "b".repeat(64);

const booleansCatalog = {
  available: true,
  policy_identity: identity,
  version: "sha256:" + "d".repeat(64),
  provenance: "Imported distribution catalog",
  reference_source: "distribution_catalog",
  content_digest: "sha256:" + "d".repeat(64),
  loaded_policy_digest: identity,
  distribution_catalog_revision_id: 1,
  completeness: "complete",
  entries: null,
  mappings: null
};

const booleansPayload: ConfigurationFleetResponse = {
  family: "booleans",
  families: ["overview", "booleans", "ports", "file_contexts", "modules"],
  hosts: { total: 2 },
  booleans: {
    coverage: { observed: 1, unavailable: 1, stale: 0, unknown: 0 },
    pagination: { total: 1, page: 1, page_size: 25, total_pages: 1 },
    inventory: [
      { name: "virt_use_nfs", description: null, counts: { enabled: 1, disabled: 0, unknown: 0, unavailable: 1, stale: 0, drift: 1 } }
    ],
    policy_cohorts: [identity, otherIdentity],
    cohort_details: [
      { policy_identity: identity, host_count: 1, latest_observation_at: "2026-01-02T03:04:05Z", platforms: [{ os_id: "almalinux", os_version: "9.4", policy_type: "targeted", architecture: "x86_64", host_count: 1 }] },
      { policy_identity: otherIdentity, host_count: 1, latest_observation_at: "2026-01-02T04:04:05Z", platforms: [{ os_id: "rhel", os_version: "9.5", policy_type: "targeted", architecture: "x86_64", host_count: 1 }] }
    ],
    selected_policy_identity: identity,
    catalog: booleansCatalog,
    catalog_overlay: {
      cohort: identity,
      catalog: booleansCatalog,
      observed: {
        fresh_host_count: 1,
        stale_host_count: 0,
        outside_cohort_host_count: 1,
        no_current_configuration_host_count: 0,
        rows: [
          {
            name: "virt_use_nfs",
            catalog: null,
            catalog_status: "not_defined",
            counts: { on: 1, off: 0, unknown: 0, unavailable: 0, stale: 0, runtime_default_divergence: 1, reference_match: 0, reference_difference: 0 }
          }
        ],
        unmatched_observed_names: ["virt_use_nfs"]
      }
    }
  }
};

const portsPayload: ConfigurationFleetResponse = {
  family: "ports",
  families: ["overview", "booleans", "ports", "file_contexts", "modules"],
  hosts: { total: 1 },
  ports: {
    coverage: { observed: 1, partial: 0, unavailable: 0, unknown: 0, stale: 0, no_heartbeat: 0 },
    pagination: { total: 1, page: 1, page_size: 25, total_pages: 1 },
    policy_cohorts: [otherIdentity],
    cohort_details: [{ policy_identity: otherIdentity, host_count: 1, latest_observation_at: "2026-01-02T04:04:05Z", platforms: [{ os_id: "rhel", os_version: "9.5", policy_type: "targeted", architecture: "x86_64", host_count: 1 }] }],
    selected_policy_identity: otherIdentity,
    catalog: { available: false, policy_identity: otherIdentity, version: null, provenance: null, reference_source: null, content_digest: null, loaded_policy_digest: otherIdentity, distribution_catalog_revision_id: null, completeness: {}, entries: null, mappings: [] },
    catalog_overlay: {
      cohort: otherIdentity,
      catalog: { available: false, policy_identity: otherIdentity, version: null, provenance: null, reference_source: null, content_digest: null, loaded_policy_digest: otherIdentity, distribution_catalog_revision_id: null, completeness: {}, entries: null, mappings: [] },
      observed: {
        fresh_complete_host_count: 1,
        partial_host_count: 0,
        unavailable_host_count: 0,
        unknown_host_count: 0,
        stale_host_count: 0,
        outside_cohort_host_count: 0,
        no_current_configuration_host_count: 0,
        segments: [],
        observed_mappings: [
          { protocol: "tcp", type: "http_port_t", start: 8080, end: 8080, provenance: "not_confirmed_custom", inventory_status: "observed", host_count: 1 }
        ],
        stale_observed_mappings: []
      }
    }
  }
};

const modulesPayload: ConfigurationFleetResponse = {
  family: "modules",
  families: ["overview", "booleans", "ports", "file_contexts", "modules"],
  hosts: { total: 1 },
  rows: [
    { pattern: null, file_type: null, context: null, name: "local_web", priority: 400, version: null, source_package: null, type: null, protocol: null, ports: null, provenance: ["unknown"], host_ids: [1] }
  ],
  observed_host_count: 1
};

const fileContextsPayload: ConfigurationFleetResponse = {
  family: "file_contexts",
  families: ["overview", "booleans", "ports", "file_contexts", "modules"],
  hosts: { total: 1 },
  rows: [
    { pattern: "/srv/www(/.*)?", file_type: "all files", context: "httpd_sys_content_t", name: null, priority: null, version: null, source_package: null, type: null, protocol: null, ports: null, provenance: ["distribution"], host_ids: [1] },
    { pattern: "/srv/local(/.*)?", file_type: "all files", context: "httpd_sys_rw_content_t", name: null, priority: null, version: null, source_package: null, type: null, protocol: null, ports: null, provenance: ["custom"], host_ids: [1] }
  ],
  observed_host_count: 1,
  pagination: { total: 2, page: 1, page_size: 25, total_pages: 1 }
};

const overviewPayload: ConfigurationFleetResponse = {
  family: "overview",
  families: ["overview", "booleans", "ports", "file_contexts", "modules"],
  hosts: { total: 2 }
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

function renderConfiguration(initialEntry = "/configuration?family=booleans", override?: ConfigurationFleetResponse) {
  const fetchMock = vi.fn();
  fetchMock.mockImplementation((url: string) => {
    const search = new URL(url, "http://localhost").searchParams;
    const family = search.get("family") ?? "overview";
    const identityParam = search.get("policy_identity");
    let payload: ConfigurationFleetResponse;
    if (family === "booleans") {
      payload = booleansPayload;
      if (identityParam && booleansPayload.booleans) {
        payload = {
          ...booleansPayload,
          booleans: { ...booleansPayload.booleans, selected_policy_identity: identityParam }
        };
      }
    } else if (family === "ports") {
      payload = portsPayload;
    } else if (family === "modules") {
      payload = modulesPayload;
    } else if (family === "file_contexts") {
      payload = fileContextsPayload;
    } else {
      payload = overviewPayload;
    }
    return Promise.resolve(jsonResponse(200, override ?? payload));
  });
  vi.stubGlobal("fetch", fetchMock);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route path="/configuration" element={<Configuration />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return { fetchMock, view, ...view };
}

describe("Configuration", () => {
  it("shows one paginated Boolean inventory with its reference comparison", async () => {
    renderConfiguration();

    await screen.findByRole("table", { name: "Boolean inventory rows" });
    expect((await screen.findAllByText("virt_use_nfs")).length).toBe(1);
    expect(screen.getByText(/2 monitored hosts fleet-wide/)).toBeInTheDocument();
    expect(screen.queryByText("sha256:" + "d".repeat(64))).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View baseline details" })).toHaveAttribute("href", "/catalogs/1");
    expect(screen.getByText("1 On")).toBeInTheDocument();
    expect(screen.getByText(/not_defined/)).toBeInTheDocument();
    expect(screen.getByText("AlmaLinux 9 · targeted · x86_64")).toBeInTheDocument();
    expect(screen.getByText(/Latest observation:/)).toBeInTheDocument();
    expect(screen.getByText("Baseline: Available")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Stale host snapshots 0" })).toHaveAttribute("href", "/hosts?configuration_family=booleans&configuration_status=stale");
    expect(screen.queryByText(/0 Off/)).not.toBeInTheDocument();
    expect(screen.queryByText("No catalog baseline")).not.toBeInTheDocument();
    expect(screen.queryByRole("table", { name: "Catalog booleans" })).not.toBeInTheDocument();
  });

  it("moves between families through URL-backed tabs", async () => {
    const { fetchMock } = renderConfiguration("/configuration");

    await screen.findByText(/2 monitored hosts fleet-wide/);
    expect(screen.queryByText("Select a family")).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Booleans" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByRole("tab", { name: "Overview" })).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/configuration?family=booleans&limit=25", expect.anything());

    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Ports" }));
    await screen.findByRole("table", { name: "Port inventory rows" });
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("family=ports"), expect.objectContaining({ method: "GET" }));
    expect(screen.getByText("http_port_t")).toBeInTheDocument();
    expect(screen.getByText("1 host")).toBeInTheDocument();
    expect(screen.getByText("Policy default")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "TCP" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("family=ports&limit=25&protocol=tcp"), expect.anything()));
  });

  it.each(["/configuration", "/configuration?family=overview", "/configuration?family=invalid"])("loads useful inventory for %s", async (entry) => {
    renderConfiguration(entry);
    expect(await screen.findByRole("table", { name: "Boolean inventory rows" })).toBeVisible();
    expect(screen.queryByText("Select a family")).not.toBeInTheDocument();
  });

  it.each(["absent", "ambiguous", "unavailable"] as const)("preserves inventory with %s reference selection and only offers a header import action for a missing catalog", async (status) => {
    const family = { status: "unknown", reference_status: "unavailable", host_status: "observed", comparison_allowed: false, reason: "reference_not_selected" } as const;
    const selection = { mode: "automatic" as const, status, reason: status === "absent" ? "no_matching_candidates" : "host_policy_identity_unavailable", basis: null, selected_revision: null,
      candidates: [], candidate_count: 0, candidates_truncated: false, context: { distribution: "", major_version: "", architecture: "", policy_type: "" }, policy_identity_match: null,
      equivalence_asserted: false, families: { booleans: family, ports: family, effective_permissive_domains: family } };
    const noCatalog: ConfigurationFleetResponse = { ...booleansPayload, booleans: { ...booleansPayload.booleans!, selection, catalog: { ...booleansCatalog, available: false }, catalog_overlay: null } };
    renderConfiguration("/configuration", noCatalog);
    expect(await screen.findByRole("table", { name: "Boolean inventory rows" })).toBeVisible();
    if (status === "absent") expect(screen.getByRole("button", { name: "Import catalog" })).toBeInTheDocument();
    else expect(screen.queryByRole("button", { name: "Import catalog" })).not.toBeInTheDocument();
    if (status === "absent") expect(screen.getByText("Baseline: None")).toBeInTheDocument();
    expect(screen.queryByText("No catalog baseline")).not.toBeInTheDocument();
    expect(screen.queryByText("unknown version")).not.toBeInTheDocument();
    expect(screen.queryByRole("table", { name: "Catalog booleans" })).not.toBeInTheDocument();
  });

  it("shows rows families with observed host counts", async () => {
    renderConfiguration("/configuration?family=modules");

    await screen.findByText("local_web");
    expect(screen.getByText("1 host with fresh observations")).toBeInTheDocument();
    expect(screen.getByText("400")).toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(screen.getByText("1 host")).toBeInTheDocument();
  });

  it("labels file-context provenance as distribution policy or local customization", async () => {
    renderConfiguration("/configuration?family=file_contexts");
    await screen.findByRole("table", { name: "file_contexts rows" });
    expect(screen.getByText("Distribution")).toBeInTheDocument();
    expect(screen.getByText("Local customization")).toBeInTheDocument();
    expect(screen.getByText("Source is based on the effective and local custom file-context listings.")).toBeInTheDocument();
  });

  it("highlights mixed Boolean states with nonzero pills and a split marker", async () => {
    const split: ConfigurationFleetResponse = {
      ...booleansPayload,
      booleans: {
        ...booleansPayload.booleans!,
        inventory: [],
        catalog_overlay: {
          ...booleansPayload.booleans!.catalog_overlay!,
          observed: {
            ...booleansPayload.booleans!.catalog_overlay!.observed,
            rows: [{ ...booleansPayload.booleans!.catalog_overlay!.observed.rows[0], counts: { ...booleansPayload.booleans!.catalog_overlay!.observed.rows[0].counts, on: 2, off: 1 } }]
          }
        }
      }
    };
    renderConfiguration("/configuration", split);
    await screen.findByRole("table", { name: "Boolean inventory rows" });
    expect(screen.getByText("2 On")).toBeInTheDocument();
    expect(screen.getByText("1 Off")).toBeInTheDocument();
    expect(screen.getByText("Split")).toBeInTheDocument();
    expect(screen.queryByText(/0 Unknown/)).not.toBeInTheDocument();
  });

  it("keeps fleet port mappings visible without a policy cohort or catalog", async () => {
    const noCohort: ConfigurationFleetResponse = {
      ...portsPayload,
      ports: {
        ...portsPayload.ports!,
        policy_cohorts: [], cohort_details: [], selected_policy_identity: null, catalog: null, catalog_overlay: null,
        selection: { ...portsPayload.ports!.selection!, status: "absent", reason: "no_matching_candidates" },
        pagination: { total: 1, page: 1, page_size: 25, total_pages: 1 },
        rows: [{ pattern: null, file_type: null, context: null, name: null, priority: null, version: null, source_package: null, type: "http_port_t", protocol: "tcp", ports: [{ start: 8080, end: 8080, provenance: "custom" }], provenance: ["custom"], host_ids: [1] }]
      }
    };
    renderConfiguration("/configuration?family=ports", noCohort);
    expect(await screen.findByRole("table", { name: "Port inventory rows" })).toBeVisible();
    expect(screen.getByText("http_port_t")).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "Reference" })).not.toBeInTheDocument();
    expect(screen.getByText("Baseline: None")).toBeInTheDocument();
    expect(screen.queryByText(/Import a catalog/)).not.toBeInTheDocument();
  });

  it("shows comparison provenance and an aggregate host count instead of hostnames", async () => {
    const catalog = { ...portsPayload.ports!.catalog!, available: true };
    const comparison: ConfigurationFleetResponse = {
      ...portsPayload,
      ports: {
        ...portsPayload.ports!,
        catalog,
        catalog_overlay: {
          ...portsPayload.ports!.catalog_overlay!,
          catalog,
          observed: {
            ...portsPayload.ports!.catalog_overlay!.observed,
            segments: [{ protocol: "tcp", start: 8080, end: 8080, catalog_types: ["http_port_t"], observed_types: ["http_port_t"], relation: "matching_effective_type", local_classification: "not_confirmed_custom", host_count: 200 }]
          }
        }
      }
    };
    renderConfiguration("/configuration?family=ports", comparison);
    expect(await screen.findByRole("table", { name: "Port inventory rows" })).toBeVisible();
    expect(screen.getByText("200 hosts")).toBeInTheDocument();
    expect(screen.getByText("Policy default")).toBeInTheDocument();
  });

  it("selects a policy cohort from the URL", async () => {
    const { fetchMock } = renderConfiguration();

    await screen.findByRole("table", { name: "Boolean inventory rows" });
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Policy cohort: Auto/ }));
    await user.click(screen.getByRole("option", { name: "RHEL 9 · targeted · x86_64 — 1 host" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining(`policy_identity=${encodeURIComponent(otherIdentity)}`),
        expect.objectContaining({ method: "GET" })
      )
    );
  });

  it("searches a family through URL-backed API state and resets pagination", async () => {
    const { fetchMock } = renderConfiguration("/configuration?family=modules&page=3&q=old");
    const search = await screen.findByRole("textbox", { name: "Search modules" });
    const user = userEvent.setup();
    await user.clear(search);
    await user.type(await screen.findByRole("textbox", { name: "Search modules" }), "web");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("family=modules&limit=25&q=web"), expect.anything()));
    const committedQueries = fetchMock.mock.calls.map(([url]) => new URL(String(url), "http://localhost").searchParams.get("q")).filter((query) => query && query !== "old");
    expect(committedQueries).toEqual(["web"]);
  });

  it("shows searchable human-readable choices for larger cohort lists", async () => {
    const manyCohorts: ConfigurationFleetResponse = {
      ...booleansPayload,
      booleans: { ...booleansPayload.booleans!, cohort_details: Array.from({ length: 6 }, (_, index) => ({
        policy_identity: `sha256:${String(index).repeat(64)}`,
        host_count: index + 1,
        latest_observation_at: null,
        platforms: [{ os_id: index === 5 ? "fedora" : "almalinux", os_version: index === 5 ? "40" : "9.4", policy_type: "targeted", architecture: "x86_64", host_count: index + 1 }]
      })) }
    };
    renderConfiguration("/configuration", manyCohorts);
    const input = await screen.findByRole("textbox", { name: "Search policy cohorts" });
    const user = userEvent.setup();
    await user.type(input, "Fedora");
    expect(screen.getByRole("option", { name: "Fedora 40 · targeted · x86_64 — 6 hosts" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /AlmaLinux/ })).not.toBeInTheDocument();
    expect(screen.queryByText(/sha256:/)).not.toBeInTheDocument();
  });
});
