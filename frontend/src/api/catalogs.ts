import { apiFetch } from "./client";
import type * as Types from "./generated/types.gen";

export type Catalog = Types.Catalog;
export type CatalogDetail = Types.CatalogDetail;
export type CatalogListResponse = Types.CatalogListResponse;
export type CatalogDetailResponse = Types.CatalogDetailResponse;

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
