import { apiFetch } from "./client";
import type * as Types from "./generated/types.gen";

export type OverviewResponse = Types.OverviewResponse;
export type OverviewSeriesPoint = Types.OverviewSeriesPoint;
export type OverviewAttentionHost = Types.OverviewAttentionHost;

export function fetchOverview(): Promise<OverviewResponse> {
  return apiFetch<OverviewResponse>("/api/v1/overview");
}
