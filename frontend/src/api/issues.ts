import { apiFetch } from "./client";
import type { components } from "./types.gen";

export type IssueHost = components["schemas"]["IssueHost"];
export type IssueListItem = components["schemas"]["IssueListItem"];
export type IssueListSummary = components["schemas"]["IssueListSummary"];
export type IssueListResponse = components["schemas"]["IssueListResponse"];
export type UngroupableEvent = components["schemas"]["UngroupableEvent"];
export type UngroupableEventsResponse = components["schemas"]["UngroupableEventsResponse"];

export function fetchIssues(params: URLSearchParams): Promise<IssueListResponse> {
  const query = params.toString();
  return apiFetch<IssueListResponse>(`/api/v1/issues${query ? `?${query}` : ""}`);
}

export function fetchUngroupableEvents(hostId?: string): Promise<UngroupableEventsResponse> {
  const query = hostId ? `?host_id=${encodeURIComponent(hostId)}` : "";
  return apiFetch<UngroupableEventsResponse>(`/api/v1/ungroupable-events${query}`);
}
