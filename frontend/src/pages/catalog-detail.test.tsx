import { render, screen, waitFor, within } from "@testing-library/react";
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
    collector_semantics_version: 4,
    content_digest: "sha256:" + "1".repeat(64),
    loaded_policy_digest: loadedPolicyDigest,
    effective_permissive_domains: { status: "observed", domains: ["example_t"], provenance: "inline_catalog_extraction", policy_identity: loadedPolicyDigest, catalog_revision_id: 7, content_digest: "sha256:" + "1".repeat(64), semantics_version: 1, evaluator_version: "SETools 4.5.1" },
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
  it("leads with reference facts and inventories, and reveals copyable verification details only on request", async () => {
    const user = userEvent.setup();
    const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    renderCatalogDetail();

    expect(await screen.findByText("AlmaLinux 9 SELinux policy")).toBeInTheDocument();
    expect(screen.getByText("targeted / x86_64 · kernel policy format 33")).toBeVisible();
    expect(screen.getByText("selinux-policy-targeted-38.1.75-2.el9_8")).toBeInTheDocument();
    expect(screen.queryByText(loadedPolicyDigest)).not.toBeInTheDocument();
    expect(screen.getByText("Booleans: complete · Ports: incomplete")).toBeInTheDocument();
    expect(screen.getByText("2026-09-20 12:00:00 UTC")).toBeInTheDocument();
    expect(screen.queryByText(/artifacts\/almalinux-9.json/)).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Display name" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rename catalog" })).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByRole("button", { name: "Archive catalog" }).closest("header")).not.toBeNull();
    expect(screen.getByText("Active").closest(".pf-v6-c-label")).not.toHaveClass("pf-m-green");
    expect(screen.getByRole("table", { name: "Catalog boolean defaults" })).toHaveClass("pf-m-compact", "pf-m-grid-lg");

    expect(screen.getByText("httpd_can_network_connect")).toBeInTheDocument();
    expect(screen.getByText("Off")).toBeInTheDocument();
    expect(screen.getByText("Allow httpd network connections")).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: "Catalog port mappings" })).not.toBeInTheDocument();

    expect(screen.getByRole("link", { name: "Compare booleans in configuration" })).toHaveAttribute(
      "href",
      `/configuration?family=booleans&policy_identity=${encodeURIComponent(loadedPolicyDigest)}`
    );
    await user.click(screen.getByRole("tab", { name: "Ports (1)" }));
    expect(screen.getByText("80-90")).toBeVisible();
    expect(screen.getByText("http_port_t")).toBeVisible();
    expect(screen.getByRole("link", { name: "Compare ports in configuration" })).toHaveAttribute(
      "href",
      `/configuration?family=ports&policy_identity=${encodeURIComponent(loadedPolicyDigest)}`
    );
    await user.click(screen.getByRole("button", { name: "Technical details & policy digests" }));
    expect(screen.getByText(/artifacts\/almalinux-9.json/)).toBeVisible();
    expect(screen.getByText(/"source":"distribution-release"/)).toBeVisible();
    expect(screen.getByText(loadedPolicyDigest)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Copy loaded-policy digest" }));
    expect(write).toHaveBeenCalledWith(loadedPolicyDigest);
    await user.click(screen.getByRole("button", { name: "Technical details & policy digests" }));
    expect(screen.queryByText(loadedPolicyDigest)).not.toBeInTheDocument();
  });

  it("surfaces API failures", async () => {
    renderCatalogDetail({ error: { code: "not_found", message: "Resource not found" } }, 404);

    expect(await screen.findByText("Could not load the catalog")).toBeInTheDocument();
    expect(screen.getByText("Resource not found")).toBeInTheDocument();
  });

  it("shows inline reference membership before any host comparison with collapsed membership and honest provenance", async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderCatalogDetail();
    expect(await screen.findByText("1 in reference")).toBeVisible();
    await user.click(screen.getByRole("tab", { name: "Effective permissive domains (1)" }));
    expect(screen.getByText(/Inline catalog extraction, collector-reported/)).toBeVisible();
    expect(screen.getByText(/semantics 1 · SETools 4.5.1/)).toBeVisible();
    const toggle = screen.getByRole("button", { name: "Reference membership (1)" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);
    expect(within(screen.getByRole("table", { name: "Catalog permissive domains" })).getByText("example_t")).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("distinguishes a complete empty reference from unavailable facts", async () => {
    const user = userEvent.setup();
    const payload = structuredClone(detailPayload);
    payload.catalog.effective_permissive_domains.domains = [];
    renderCatalogDetail(payload);
    expect(await screen.findByText("0 in reference")).toBeVisible();
    await user.click(screen.getByRole("tab", { name: "Effective permissive domains (0)" }));
    await user.click(screen.getByRole("button", { name: "Reference membership (0)" }));
    expect(screen.getByText("The reference policy has no effective permissive domains.")).toBeVisible();
  });

  it("does not present unavailable inline facts as an empty reference", async () => {
    const user = userEvent.setup();
    const payload = structuredClone(detailPayload);
    payload.catalog.effective_permissive_domains = { ...payload.catalog.effective_permissive_domains, status: "unavailable", domains: null, semantics_version: null, evaluator_version: null };
    renderCatalogDetail(payload);
    await screen.findByText("AlmaLinux 9 SELinux policy");
    await user.click(screen.getByRole("tab", { name: "Effective permissive domains (unavailable)" }));
    expect(screen.getByText(/Inline reference membership is unavailable/)).toBeVisible();
    expect(screen.queryByText("The reference policy has no effective permissive domains.")).not.toBeInTheDocument();
  });

  it("renames, archives and unarchives while preserving identity/provenance", async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderCatalogDetail();
    await screen.findByText("AlmaLinux 9 SELinux policy");
    await user.click(screen.getByRole("button", { name: "Rename catalog" }));
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
    await user.click(screen.getByRole("button", { name: "Archive catalog" }));
    expect(await screen.findByText("Archived reference")).toBeInTheDocument();
    expect(screen.getByText("Archived", { exact: true })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Compare booleans in configuration" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Technical details & policy digests" }));
    expect(screen.getByText(detailPayload.catalog.content_digest)).toBeVisible();
    expect(screen.getByText(/"source":"distribution-release"/)).toBeInTheDocument();
    expect(screen.getByText(/Import and a valid digest do not establish review/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Unarchive catalog" }));
    await waitFor(() => expect(screen.queryByText("Archived reference")).not.toBeInTheDocument());
    expect(screen.getByText("Active", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Compare booleans in configuration" })).toBeInTheDocument();
  });

  it("shows failed management validation without changing name or lifecycle", async () => {
    const user = userEvent.setup();
    const { fetchMock } = renderCatalogDetail();
    await screen.findByText("AlmaLinux 9 SELinux policy");
    await user.click(screen.getByRole("button", { name: "Rename catalog" }));
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
    await userEvent.setup().click(screen.getByRole("button", { name: "Technical details & policy digests" }));
    expect(screen.getByText(/Operator upload · Imported by operator/)).toBeInTheDocument();
  });

  it("pairs each import's source, importer, timestamp and metadata in its own description-list group", async () => {
    renderCatalogDetail({ catalog: { ...detailPayload.catalog, imports: [...detailPayload.catalog.imports,
      { id: 4, source_path: null, source_kind: "operator_upload", imported_by: "operator", imported_at: "2026-09-21T12:00:00Z", acquisition_metadata: { note: "second import" } }
    ] } });
    await screen.findByText("AlmaLinux 9 SELinux policy");
    await userEvent.setup().click(screen.getByRole("button", { name: "Technical details & policy digests" }));
    const history = screen.getByRole("region", { name: "Import history" });
    const first = within(history).getByText("Import #3").closest(".pf-v6-c-description-list__group")!;
    const second = within(history).getByText("Import #4").closest(".pf-v6-c-description-list__group")!;
    expect(first).toHaveTextContent("artifacts/almalinux-9.json");
    expect(first).toHaveTextContent("2026-09-20 12:00:05 UTC");
    expect(first).not.toHaveTextContent("operator");
    expect(second).toHaveTextContent("Operator upload · Imported by operator");
    expect(second).toHaveTextContent("2026-09-21 12:00:00 UTC");
    expect(second).toHaveTextContent('"note":"second import"');
  });

  it("bounds inventory rows, restores independent URL pages, and clamps out-of-range pages", async () => {
    const catalog = { ...detailPayload.catalog,
      booleans: Array.from({ length: 55 }, (_, index) => ({ name: `boolean_${index}`, default_value: false, description: "" })),
      port_mappings: Array.from({ length: 58 }, (_, index) => ({ protocol: "tcp", start: index, end: index, type: `port_${index}_t` }))
    };
    renderCatalogDetail({ catalog }, 200, "/catalogs/7?boolean_page=99&port_page=2");
    const booleans = await screen.findByRole("region", { name: "Boolean reference" });
    expect(within(booleans).getByRole("table").querySelectorAll("tbody tr")).toHaveLength(5);
    expect(within(booleans).getByRole("spinbutton", { name: "Current page" })).toHaveValue(3);
    const user = userEvent.setup();
    await user.click(within(booleans).getByRole("button", { name: "Go to first page" }));
    expect(within(booleans).getByRole("table").querySelectorAll("tbody tr")).toHaveLength(25);
    expect(within(booleans).queryByText("boolean_50")).not.toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Ports (58)" }));
    const ports = screen.getByRole("region", { name: "Port reference" });
    expect(within(ports).getByRole("table").querySelectorAll("tbody tr")).toHaveLength(25);
    expect(within(ports).getByRole("spinbutton", { name: "Current page" })).toHaveValue(2);
    await user.click(screen.getByRole("tab", { name: "Booleans (55)" }));
    const booleanView = screen.getByRole("region", { name: "Boolean reference" });
    await user.click(within(booleanView).getByRole("button", { name: "Go to last page" }));
    expect(within(booleanView).getByText("boolean_50")).toBeVisible();
    await user.type(screen.getByRole("textbox", { name: "Search catalog booleans" }), "boolean_50");
    expect(within(booleanView).getByRole("spinbutton", { name: "Current page" })).toHaveValue(1);
    expect(within(booleanView).getByRole("table").querySelectorAll("tbody tr")).toHaveLength(1);
    expect(screen.queryByRole("tab", { name: /Permissive|File contexts/ })).not.toBeInTheDocument();
  });

  it("offers full-page sizes and resets only the resized family's page", async () => {
    const catalog = { ...detailPayload.catalog, booleans: Array.from({ length: 55 }, (_, index) => ({ name: `boolean_${index}`, default_value: false, description: "" })) };
    renderCatalogDetail({ catalog }, 200, "/catalogs/7?boolean_page=2&port_q=http");
    await screen.findByRole("table", { name: "Catalog boolean defaults" });
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "26 - 50 of 55" }));
    await user.click(screen.getByRole("menuitem", { name: "100 per page" }));
    expect(screen.getByRole("table", { name: "Catalog boolean defaults" }).querySelectorAll("tbody tr")).toHaveLength(55);
    expect(screen.getByRole("spinbutton", { name: "Current page" })).toHaveValue(1);
    await user.click(screen.getByRole("tab", { name: "Ports (1)" }));
    expect(screen.getByRole("textbox", { name: "Search catalog ports" })).toHaveValue("http");
  });
});
