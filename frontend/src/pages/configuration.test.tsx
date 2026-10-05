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
    inventory: [
      { name: "virt_use_nfs", description: null, counts: { enabled: 1, disabled: 0, unknown: 0, unavailable: 1, stale: 0, drift: 1 } }
    ],
    policy_cohorts: [identity, otherIdentity],
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
    policy_cohorts: [otherIdentity],
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
          { protocol: "tcp", type: "http_port_t", start: 8080, end: 8080, provenance: "custom", inventory_status: "observed", host_id: 1, hostname: "config-01" }
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

function renderConfiguration(initialEntry = "/configuration?family=booleans") {
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
    } else {
      payload = overviewPayload;
    }
    return Promise.resolve(jsonResponse(200, payload));
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
  it("shows the fleet boolean coverage, catalog overlay, and inventory", async () => {
    renderConfiguration();

    await screen.findByText("1 fresh · 0 stale · 1 outside cohort · 0 without current configuration");
    expect((await screen.findAllByText("virt_use_nfs")).length).toBe(2);
    expect(screen.getByText("2 monitored hosts")).toBeInTheDocument();
    expect(screen.getByText("sha256:" + "d".repeat(64))).toBeInTheDocument();
    expect(screen.getByText((content) => content.includes("Imported distribution catalog"))).toBeInTheDocument();
    expect(screen.getByText("1 fresh · 0 stale · 1 outside cohort · 0 without current configuration")).toBeInTheDocument();
    expect(screen.getByText("not_defined")).toBeInTheDocument();
    expect(screen.getByText("on 1 / 2")).toBeInTheDocument();
    expect(screen.getByText("unavailable 1 / 2")).toBeInTheDocument();
    expect(screen.getByText("drift 1")).toBeInTheDocument();
    expect(screen.getByText("Observed names not in the catalog: virt_use_nfs")).toBeInTheDocument();
  });

  it("moves between families through URL-backed tabs", async () => {
    const { fetchMock } = renderConfiguration("/configuration");

    await screen.findByText("2 monitored hosts");
    expect(screen.getByText("Select a family")).toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Ports" }));
    await screen.findByText("Observed mappings without catalog comparison");
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("family=ports"), expect.objectContaining({ method: "GET" }));
    expect(screen.getByText("http_port_t")).toBeInTheDocument();
    expect(screen.getByText("config-01")).toBeInTheDocument();
  });

  it("shows rows families with observed host counts", async () => {
    renderConfiguration("/configuration?family=modules");

    await screen.findByText("local_web");
    expect(screen.getByText("1 hosts with fresh observations")).toBeInTheDocument();
    expect(screen.getByText("400")).toBeInTheDocument();
    expect(screen.getByText("unknown")).toBeInTheDocument();
    expect(screen.getByText("1 host")).toBeInTheDocument();
  });

  it("selects a policy cohort from the URL", async () => {
    const { fetchMock } = renderConfiguration();

    await screen.findByText("1 fresh · 0 stale · 1 outside cohort · 0 without current configuration");
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Policy cohort" }));
    await user.click(screen.getByRole("option", { name: otherIdentity.slice(0, 19) + "…" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining(`policy_identity=${encodeURIComponent(otherIdentity)}`),
        expect.objectContaining({ method: "GET" })
      )
    );
  });
});
