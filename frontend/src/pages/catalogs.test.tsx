import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { CatalogListResponse } from "../api/catalogs";
import { Catalogs } from "./Catalogs";

const loadedPolicyDigest = "sha256:" + "a".repeat(64);
const contentDigest = "sha256:" + "1".repeat(64);

const listPayload: CatalogListResponse = {
  catalogs: [
    {
      id: 7,
      display_name: "AlmaLinux 9",
      lifecycle: "active",
      distribution: "almalinux",
      major_version: "9",
      architecture: "x86_64",
      policy_type: "targeted",
      kernel_policy_version: 33,
      schema_version: 1,
      collector_semantics_version: 3,
      content_digest: contentDigest,
      loaded_policy_digest: loadedPolicyDigest,
      booleans_complete: true,
      ports_complete: true,
      booleans_count: 12,
      port_mappings_count: 4,
      created_at: "2026-09-20T12:00:00Z"
    }
  ]
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

function renderCatalogs(fetchBody: unknown = listPayload) {
  const fetchMock = vi.fn();
  fetchMock.mockImplementation(() => Promise.resolve(jsonResponse(200, fetchBody)));
  vi.stubGlobal("fetch", fetchMock);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/catalogs"]}>
        <Routes>
          <Route path="/catalogs" element={<Catalogs />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return { fetchMock, ...view };
}

describe("Catalogs", () => {
  it("lists catalog identity with structured metadata and configuration links", async () => {
    renderCatalogs();

    const name = await screen.findByText("AlmaLinux 9");
    expect(screen.getByRole("grid", { name: "Imported SELinux distribution catalogs" })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "Policy identity" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Import catalog" }).closest("header")).toHaveClass("app-page-header");
    expect(name.closest("a")).toHaveAttribute("href", "/catalogs/7");
    expect(screen.getByText("targeted · x86_64 · policy 33")).toBeInTheDocument();
    expect(screen.getByText("12 booleans · complete")).toBeInTheDocument();
    expect(screen.getByText("4 port mappings · complete")).toBeInTheDocument();
    expect(screen.getByText("Sep 20, 2026")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Copy .* digest/ })).not.toBeInTheDocument();
    expect(screen.queryByText(/sha256:/)).not.toBeInTheDocument();
    expect(screen.getByText("12 booleans · complete").closest(".pf-v6-c-label")).toBeNull();
    expect(screen.getByRole("region", { name: "Distribution catalogs" })).toHaveClass("pf-v6-c-card");

    expect(screen.getByRole("link", { name: "Compare in configuration" })).toHaveAttribute(
      "href",
      `/configuration?family=booleans&policy_identity=${encodeURIComponent(loadedPolicyDigest)}`
    );
  });

  it("shows an empty state when no catalogs are imported", async () => {
    renderCatalogs({ catalogs: [] });

    expect(await screen.findByText("No imported distribution catalogs")).toBeInTheDocument();
  });

  it("keeps archived references inspectable, with no new comparison action", async () => {
    renderCatalogs({ catalogs: [{ ...listPayload.catalogs[0], lifecycle: "archived" }] });
    expect(await screen.findByText("Archived", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View archived reference" })).toHaveAttribute("href", "/catalogs/7");
    expect(screen.queryByRole("link", { name: "Compare in configuration" })).not.toBeInTheDocument();
    expect(screen.queryByText(/sha256:/)).not.toBeInTheDocument();
    expect(screen.getByText(/excluded from new automatic selection/)).toBeInTheDocument();
  });

  it("keeps incomplete inventory prominent without coloring ordinary inventory counts", async () => {
    renderCatalogs({ catalogs: [{ ...listPayload.catalogs[0], booleans_complete: false }] });
    expect(await screen.findByText("incomplete")).toBeVisible();
    expect(screen.getByText("incomplete").closest(".pf-v6-c-label")).not.toBeNull();
    expect(screen.getByText("4 port mappings · complete").closest(".pf-v6-c-label")).toBeNull();
  });
});
