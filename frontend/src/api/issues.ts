import { apiFetch } from "./client";
import type * as Types from "./generated/types.gen";

export type IssueHost = Types.IssueHost;
export type IssueListItem = Types.IssueListItem;
export type IssueListSummary = Types.IssueListSummary;
export type IssueListResponse = Types.IssueListResponse;
export type UngroupableEvent = Types.UngroupableEvent;
export type UngroupableEventsResponse = Types.UngroupableEventsResponse;

export function fetchIssues(params: URLSearchParams): Promise<IssueListResponse> {
  const query = params.toString();
  return apiFetch<IssueListResponse>(`/api/v1/issues${query ? `?${query}` : ""}`);
}

export function fetchUngroupableEvents(hostId?: string): Promise<UngroupableEventsResponse> {
  const query = hostId ? `?host_id=${encodeURIComponent(hostId)}` : "";
  return apiFetch<UngroupableEventsResponse>(`/api/v1/ungroupable-events${query}`);
}
