import { apiFetch } from "./client";
import type { components } from "./types.gen";

export type OverviewResponse = components["schemas"]["OverviewResponse"];
export type OverviewSeriesPoint = components["schemas"]["OverviewSeriesPoint"];
export type OverviewAttentionHost = components["schemas"]["OverviewAttentionHost"];

export function fetchOverview(): Promise<OverviewResponse> {
  return apiFetch<OverviewResponse>("/api/v1/overview");
}
