import { apiFetch } from "./client";
import type * as Types from "./generated/types.gen";

export type Issue = Types.Issue;
export type Diagnosis = Types.Diagnosis;
export type IssueDetailResponse = Types.IssueDetailResponse;
export type OccurrenceDetail = Types.OccurrenceDetail;
export type IssueOccurrencesResponse = Types.IssueOccurrencesResponse;
export type IssueAnalysisResponse = Types.IssueAnalysisResponse;
export type OccurrencePage = Types.OccurrenceSummaryPage;

export function fetchIssueOccurrencePage(id: number, page: number, limit = 10, signatureId?: string | null): Promise<OccurrencePage> {
  return apiFetch<OccurrencePage>(`/api/v1/issues/${id}/occurrences?view=summary&page=${page}&limit=${limit}${signatureId ? `&signature_id=${encodeURIComponent(signatureId)}` : ""}`);
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

export function updateIssueStatus(id: number, status: "open" | "resolved" | "ignored", signatureIds: number[]): Promise<Issue> {
  return apiFetch<Issue>(`/api/v1/issues/${id}/status`, { method: "PATCH", body: { status, signature_ids: signatureIds } });
}

export function updateIssueDisposition(id: number, disposition: string, signatureIds: number[], note?: string): Promise<Issue> {
  return apiFetch<Issue>(`/api/v1/issues/${id}/disposition`, {
    method: "PATCH",
    body: { disposition, signature_ids: signatureIds, ...(note ? { note } : {}) }
  });
}
