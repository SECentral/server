import { apiFetch } from "./client";
import type { components } from "./types.gen";

export type Issue = components["schemas"]["Issue"];
export type Diagnosis = components["schemas"]["Diagnosis"];
export type IssueDetailResponse = components["schemas"]["IssueDetailResponse"];
export type OccurrenceDetail = components["schemas"]["OccurrenceDetail"];
export type IssueOccurrencesResponse = components["schemas"]["IssueOccurrencesResponse"];
export type IssueAnalysisResponse = components["schemas"]["IssueAnalysisResponse"];
export type OccurrencePage = components["schemas"]["OccurrenceSummaryPage"];

export function fetchIssueOccurrencePage(id: number, page: number): Promise<OccurrencePage> {
  return apiFetch<OccurrencePage>(`/api/v1/issues/${id}/occurrences?view=summary&page=${page}`);
}

export function fetchIssueOccurrence(id: number, occurrenceId: number): Promise<OccurrenceDetail> {
  return apiFetch<OccurrenceDetail>(`/api/v1/issues/${id}/occurrences/${occurrenceId}`);
}

export function fetchIssue(id: number): Promise<IssueDetailResponse> {
  return apiFetch<IssueDetailResponse>(`/api/v1/issues/${id}`);
}

export function fetchIssueOccurrences(
  id: number,
  params: { limit?: number; before?: string } = {}
): Promise<IssueOccurrencesResponse> {
  const query = new URLSearchParams();
  if (params.limit !== undefined) {
    query.set("limit", String(params.limit));
  }
  if (params.before) {
    query.set("before", params.before);
  }
  const suffix = query.toString();
  return apiFetch<IssueOccurrencesResponse>(`/api/v1/issues/${id}/occurrences${suffix ? `?${suffix}` : ""}`);
}

export function fetchIssueAnalysis(id: number): Promise<IssueAnalysisResponse> {
  return apiFetch<IssueAnalysisResponse>(`/api/v1/issues/${id}/analysis`);
}

export function updateIssueStatus(id: number, status: "open" | "resolved" | "ignored"): Promise<Issue> {
  return apiFetch<Issue>(`/api/v1/issues/${id}/status`, { method: "PATCH", body: { status } });
}

export function updateIssueDisposition(id: number, disposition: string, note?: string): Promise<Issue> {
  return apiFetch<Issue>(`/api/v1/issues/${id}/disposition`, {
    method: "PATCH",
    body: note ? { disposition, note } : { disposition }
  });
}
