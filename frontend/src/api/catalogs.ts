import { apiFetch } from "./client";
import type { components } from "./types.gen";

export type Catalog = components["schemas"]["Catalog"];
export type CatalogDetail = components["schemas"]["CatalogDetail"];
export type CatalogListResponse = components["schemas"]["CatalogListResponse"];
export type CatalogDetailResponse = components["schemas"]["CatalogDetailResponse"];

export function fetchCatalogs(): Promise<CatalogListResponse> {
  return apiFetch<CatalogListResponse>("/api/v1/catalogs");
}

export function fetchCatalog(id: number | string): Promise<CatalogDetailResponse> {
  return apiFetch<CatalogDetailResponse>(`/api/v1/catalogs/${id}`);
}
