import { apiFetch } from "./client";
import type * as Types from "./generated/types.gen";

export type Catalog = Types.Catalog;
export type CatalogDetail = Types.CatalogDetail;
export type CatalogListResponse = Types.CatalogListResponse;
export type CatalogDetailResponse = Types.CatalogDetailResponse;
export type CatalogImportPreviewResponse = Types.CatalogImportPreviewResponse;
export type CatalogImportConfirmation = Types.CatalogImportConfirmation;

export function fetchCatalogs(): Promise<CatalogListResponse> {
  return apiFetch<CatalogListResponse>("/api/v1/catalogs");
}

export function fetchCatalog(id: number | string): Promise<CatalogDetailResponse> {
  return apiFetch<CatalogDetailResponse>(`/api/v1/catalogs/${id}`);
}

export function renameCatalog(id: number, displayName: string): Promise<CatalogDetailResponse> {
  return apiFetch<CatalogDetailResponse>(`/api/v1/catalogs/${id}/name`, { method: "PATCH", body: { display_name: displayName } });
}

export function setCatalogArchived(id: number, archived: boolean): Promise<CatalogDetailResponse> {
  return apiFetch<CatalogDetailResponse>(`/api/v1/catalogs/${id}/${archived ? "archive" : "unarchive"}`, { method: "POST" });
}

export function previewCatalogImport(file: File, displayName?: string): Promise<CatalogImportPreviewResponse> {
  const query = displayName === undefined ? "" : `?display_name=${encodeURIComponent(displayName)}`;
  return apiFetch<CatalogImportPreviewResponse>(`/api/v1/catalogs/import-preview${query}`, { method: "POST", rawBody: file });
}

export function confirmCatalogImport(file: File, token: string): Promise<CatalogImportConfirmation> {
  return apiFetch<CatalogImportConfirmation>("/api/v1/catalogs/import-confirm", { method: "POST", rawBody: file, headers: { "X-Catalog-Preview": token } });
}
