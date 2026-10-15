import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { CatalogImportPreviewResponse } from "../api/catalogs";
import { CatalogImport } from "./CatalogImport";

const payload: CatalogImportPreviewResponse = { preview: {
  validation_status: "valid", supported: true, schema_version: 1, collector_semantics_version: 4,
  content_digest: "sha256:" + "1".repeat(64), loaded_policy_digest: "sha256:" + "a".repeat(64),
  platform: { distribution: "rhel", major_version: "9", architecture: "x86_64" }, policy_type: "targeted",
  policy_packages: [{ name: "selinux-policy-targeted", epoch: "0", version: "38", release: "1", architecture: "x86_64" }],
  acquisition: { collected_at: "2026-09-20T16:00:00Z", collector_version: "collector-v1" },
  families: { booleans: { status: "complete", count: 350 }, ports: { status: "complete", count: 621, protocols: ["tcp", "udp", "sctp", "dccp"] }, effective_permissive_domains: { status: "complete", count: 7 } },
  display_name: "RHEL 9", outcome: "create_new_revision", reason: "A new immutable revision will be created", existing_revision: null,
  preview_token: "signed-receipt", expires_at: "2099-01-01T00:00:00Z"
} };

function jsonResponse(status: number, body: unknown): Response {
  return { ok: status < 400, status, headers: new Headers(), json: async () => body } as Response;
}

function Destination() {
  const location = useLocation();
  return <p>Catalog detail: {location.state?.catalogImportOutcome}</p>;
}

function setup(value = payload) {
  const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, value));
  vi.stubGlobal("fetch", fetchMock);
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
    <MemoryRouter initialEntries={["/catalogs/import"]}><Routes>
      <Route path="/catalogs/import" element={<CatalogImport />} />
      <Route path="/catalogs/7" element={<Destination />} />
      <Route path="/catalogs" element={<p>Catalog inventory</p>} />
    </Routes></MemoryRouter>
  </QueryClientProvider>);
  return { user: userEvent.setup(), fetchMock, file: new File(['{"artifact":"bytes"}'], "catalog.json", { type: "application/json" }) };
}

describe("Catalog product import", () => {
  it("only validates on request, then explicitly confirms the same File and navigates to the result", async () => {
    const { user, fetchMock, file } = setup();
    await user.upload(screen.getByLabelText("JSON artifact", { exact: false }), file);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Import new catalog revision" })).not.toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: "Initial display name (optional)" }), "Named reference");
    await user.click(screen.getByRole("button", { name: "Validate / Preview" }));
    expect(await screen.findByText("Import preview — RHEL 9")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/catalogs/import-preview?display_name=Named%20reference", expect.objectContaining({ body: file, method: "POST", headers: expect.objectContaining({ "Content-Type": "application/octet-stream" }) }));
    expect(screen.getByText(payload.preview.content_digest)).toBeInTheDocument();
    expect(screen.getByText(/Booleans: complete \(350\)/)).toBeInTheDocument();
    expect(screen.getByText(/not a trusted-publisher claim/)).toBeInTheDocument();
    fetchMock.mockResolvedValue(jsonResponse(201, { outcome: "create_new_revision", catalog: { id: 7 } }));
    await user.click(screen.getByRole("button", { name: "Import new catalog revision" }));
    expect(await screen.findByText("Catalog detail: create_new_revision")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenLastCalledWith("/api/v1/catalogs/import-confirm", expect.objectContaining({ body: file, headers: expect.objectContaining({ "X-Catalog-Preview": "signed-receipt" }) }));
  });

  it("shows archived reuse with evidence-only confirmation and no unarchive action", async () => {
    const { user, file } = setup({ preview: { ...payload.preview, outcome: "reuse_existing_revision", display_name: "Retained name", existing_revision: { id: 7, content_digest: payload.preview.content_digest, display_name: "Retained name", lifecycle: "archived" } } });
    await user.upload(screen.getByLabelText("JSON artifact", { exact: false }), file);
    await user.click(screen.getByRole("button", { name: "Validate / Preview" }));
    expect(await screen.findByText(/Retained name · archived/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Record another import of existing revision" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Unarchive" })).not.toBeInTheDocument();
  });

  it("never confirms a conflicting preview", async () => {
    const { user, file } = setup({ preview: { ...payload.preview, outcome: "conflict", preview_token: null, expires_at: null } });
    await user.upload(screen.getByLabelText("JSON artifact", { exact: false }), file);
    await user.click(screen.getByRole("button", { name: "Validate / Preview" }));
    expect(await screen.findByText("Import conflict")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Import new catalog revision" })).not.toBeInTheDocument();
  });

  it("invalidates preview after upload/name replacement and cancels without confirming", async () => {
    const { user, fetchMock, file } = setup();
    await user.upload(screen.getByLabelText("JSON artifact", { exact: false }), file);
    await user.click(screen.getByRole("button", { name: "Validate / Preview" }));
    await screen.findByText("Import preview — RHEL 9");
    await user.type(screen.getByRole("textbox", { name: "Initial display name (optional)" }), "Other name");
    expect(screen.queryByText("Import preview — RHEL 9")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Validate / Preview" }));
    await screen.findByText("Import preview — RHEL 9");
    await user.upload(screen.getByLabelText("JSON artifact", { exact: false }), new File(["other bytes"], "other.json"));
    expect(screen.queryByText("Import preview — RHEL 9")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(await screen.findByText("Catalog inventory")).toBeInTheDocument();
    expect(fetchMock.mock.calls.every(([path]) => !String(path).endsWith("import-confirm"))).toBe(true);
  });

  it("reports expired previews and requires validation again", async () => {
    const { user, fetchMock, file } = setup();
    await user.upload(screen.getByLabelText("JSON artifact", { exact: false }), file);
    await user.click(screen.getByRole("button", { name: "Validate / Preview" }));
    await screen.findByText("Import preview — RHEL 9");
    fetchMock.mockResolvedValue(jsonResponse(422, { error: { code: "invalid_preview", message: "Preview expired; validate again" } }));
    await user.click(screen.getByRole("button", { name: "Import new catalog revision" }));
    expect(await screen.findByText("Preview expired; validate again")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText("Import preview — RHEL 9")).not.toBeInTheDocument());
  });

  it("shows validation errors without a preview or confirm action", async () => {
    const { user, fetchMock, file } = setup();
    fetchMock.mockResolvedValue(jsonResponse(422, { error: { code: "digest_mismatch", message: "Content digest mismatch" } }));
    await user.upload(screen.getByLabelText("JSON artifact", { exact: false }), file);
    await user.click(screen.getByRole("button", { name: "Validate / Preview" }));
    expect(await screen.findByText("Content digest mismatch")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Import new catalog revision" })).not.toBeInTheDocument();
  });

  it("disables repeated confirmation while pending and permits safe retry after a response failure", async () => {
    const { user, fetchMock, file } = setup();
    await user.upload(screen.getByLabelText("JSON artifact", { exact: false }), file);
    await user.click(screen.getByRole("button", { name: "Validate / Preview" }));
    await screen.findByText("Import preview — RHEL 9");
    let finish: (response: Response) => void = () => {};
    fetchMock.mockImplementationOnce(() => new Promise<Response>((resolve) => { finish = resolve; }));
    const confirmButton = screen.getByRole("button", { name: "Import new catalog revision" });
    await user.click(confirmButton);
    expect(confirmButton).toBeDisabled();
    await user.click(confirmButton);
    expect(fetchMock.mock.calls.filter(([path]) => String(path).endsWith("import-confirm"))).toHaveLength(1);
    finish(jsonResponse(500, { error: { code: "unknown", message: "Response unavailable" } }));
    await screen.findByText("Response unavailable");
    fetchMock.mockResolvedValue(jsonResponse(200, { outcome: "reuse_existing_revision", catalog: { id: 7 } }));
    await user.click(screen.getByRole("button", { name: "Import new catalog revision" }));
    expect(await screen.findByText("Catalog detail: reuse_existing_revision")).toBeInTheDocument();
  });
});
