import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { CatalogDetailResponse } from "../api/catalogs";
import { CatalogDetail } from "./CatalogDetail";

const loadedPolicyDigest = "sha256:" + "a".repeat(64);

const detailPayload: CatalogDetailResponse = {
  catalog: {
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
    content_digest: "sha256:" + "1".repeat(64),
    loaded_policy_digest: loadedPolicyDigest,
    booleans_complete: true,
    ports_complete: false,
    booleans_count: 1,
    port_mappings_count: 1,
    created_at: "2026-09-20T12:00:00Z",
    policy_packages: [{ name: "selinux-policy-targeted", version: "38.1.75", release: "2.el9_8" }],
    imports: [
      { id: 3, source_path: "artifacts/almalinux-9.json", acquisition_metadata: { source: "distribution-release" }, imported_at: "2026-09-20T12:00:05Z" }
    ],
    booleans: [{ name: "httpd_can_network_connect", default_value: false, description: "Allow httpd network connections" }],
    port_mappings: [{ protocol: "tcp", start: 80, end: 90, type: "http_port_t" }]
  }
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

function renderCatalogDetail(fetchBody: unknown = detailPayload, status = 200, initialEntry: string | { pathname: string; state: { catalogImportOutcome: string } } = "/catalogs/7") {
  const fetchMock = vi.fn();
  fetchMock.mockImplementation(() => Promise.resolve(jsonResponse(status, fetchBody)));
  vi.stubGlobal("fetch", fetchMock);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route path="/catalogs/:id" element={<CatalogDetail />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return { fetchMock, ...view };
}

describe("CatalogDetail", () => {
  it("shows identity, provenance, and structured families", async () => {
    renderCatalogDetail();

    expect(await screen.findByText("AlmaLinux 9 SELinux policy")).toBeInTheDocument();
    expect(screen.getByText("targeted / x86_64 · kernel policy 33")).toBeInTheDocument();
    expect(screen.getByText("selinux-policy-targeted-38.1.75-2.el9_8")).toBeInTheDocument();
    expect(screen.getByText(loadedPolicyDigest, { selector: "code" })).toBeInTheDocument();
    expect(screen.getByText("Booleans: complete · Ports: incomplete")).toBeInTheDocument();
    expect(screen.getByText("2026-09-20 12:00:00 UTC")).toBeInTheDocument();
    expect(screen.getByText(/artifacts\/almalinux-9.json/)).toBeInTheDocument();
    expect(screen.getByText(/"source":"distribution-release"/)).toBeInTheDocument();

    expect(screen.getByText("httpd_can_network_connect")).toBeInTheDocument();
    expect(screen.getByText("Off")).toBeInTheDocument();
    expect(screen.getByText("Allow httpd network connections")).toBeInTheDocument();
    expect(screen.getByText("80-90")).toBeInTheDocument();
    expect(screen.getByText("http_port_t")).toBeInTheDocument();

    expect(screen.getByRole("link", { name: "Compare booleans in configuration" })).toHaveAttribute(
      "href",
      `/configuration?family=booleans&policy_identity=${encodeURIComponent(loadedPolicyDigest)}`
    );
    expect(screen.getByRole("link", { name: "Compare ports in configuration" })).toHaveAttribute(
      "href",
      `/configuration?family=ports&policy_identity=${encodeURIComponent(loadedPolicyDigest)}`
    );
  });

  it("surfaces API failures", async () => {
    renderCatalogDetail({ error: { code: "not_found", message: "Resource not found" } }, 404);

    expect(await screen.findByText("Could not load the catalog")).toBeInTheDocument();
    expect(screen.getByText("Resource not found")).toBeInTheDocument();
  });

  it("renames, archives and unarchives while preserving identity/provenance", async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderCatalogDetail();
    await screen.findByText("AlmaLinux 9 SELinux policy");
    let current = structuredClone(detailPayload);
    fetchMock.mockImplementation(async (path: string, options: RequestInit) => {
      if (path.endsWith("/name")) {
        current = { catalog: { ...current.catalog, display_name: JSON.parse(options.body as string).display_name } };
      } else if (path.endsWith("/archive")) {
        current = { catalog: { ...current.catalog, lifecycle: "archived" } };
      } else if (path.endsWith("/unarchive")) {
        current = { catalog: { ...current.catalog, lifecycle: "active" } };
      }
      return jsonResponse(200, current);
    });
    await user.clear(screen.getByRole("textbox", { name: "Display name" }));
    await user.type(screen.getByRole("textbox", { name: "Display name" }), "Oracle reference");
    await user.click(screen.getByRole("button", { name: "Save name" }));
    expect(await screen.findByText("Oracle reference SELinux policy")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/catalogs/7/name", expect.objectContaining({ method: "PATCH", body: JSON.stringify({ display_name: "Oracle reference" }) }));
    await user.click(screen.getByRole("button", { name: "Archive" }));
    expect(await screen.findByText("Archived reference")).toBeInTheDocument();
    expect(screen.getByText("Archived", { exact: true })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Compare booleans in configuration" })).not.toBeInTheDocument();
    expect(screen.getByText(detailPayload.catalog.content_digest, { selector: "code" })).toBeInTheDocument();
    expect(screen.getByText(/"source":"distribution-release"/)).toBeInTheDocument();
    expect(screen.getByText(/Import and a valid digest do not establish review/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Unarchive" }));
    await waitFor(() => expect(screen.queryByText("Archived reference")).not.toBeInTheDocument());
    expect(screen.getByText("Active", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Compare booleans in configuration" })).toBeInTheDocument();
  });

  it("shows failed management validation without changing name or lifecycle", async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderCatalogDetail();
    await screen.findByText("AlmaLinux 9 SELinux policy");
    const input = screen.getByRole("textbox", { name: "Display name" });
    expect(input).toHaveAttribute("maxlength", "120");
    await user.clear(input);
    expect(screen.getByRole("button", { name: "Save name" })).toBeDisabled();
    await user.type(input, "Proposed name");
    fetchMock.mockResolvedValue(jsonResponse(422, { error: { code: "invalid_catalog_management", message: "Invalid display name" } }));
    await user.click(screen.getByRole("button", { name: "Save name" }));
    expect(await screen.findByText("Could not update catalog")).toBeInTheDocument();
    expect(screen.getByText("Invalid display name")).toBeInTheDocument();
    expect(screen.getByText("AlmaLinux 9 SELinux policy")).toBeInTheDocument();
    expect(screen.getByText("Active", { exact: true })).toBeInTheDocument();
  });

  it("explains reuse after import and displays neutral upload provenance on an archived revision", async () => {
    const data = { catalog: { ...detailPayload.catalog, lifecycle: "archived", imports: [{ ...detailPayload.catalog.imports[0], source_path: null, source_kind: "operator_upload", imported_by: "operator" }] } };
    renderCatalogDetail(data, 200, { pathname: "/catalogs/7", state: { catalogImportOutcome: "reuse_existing_revision" } });
    expect(await screen.findByText("Existing revision reused; import evidence appended")).toBeInTheDocument();
    expect(screen.getByText(/This revision remains archived. Import did not change/)).toBeInTheDocument();
    expect(screen.getByText(/Operator upload · Imported by operator/)).toBeInTheDocument();
  });
});
