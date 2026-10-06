import { apiFetch } from "./client";
import type * as Types from "./generated/types.gen";

export type ResolutionWorkflow = Types.ResolutionWorkflow;
export type ChangePlan = Types.ChangePlan;
export type PolicyDraft = Types.PolicyDraft;
export type PolicyDraftExport = Types.PolicyDraftExport;

export const fetchResolutions = (id: number) => apiFetch<ResolutionWorkflow>(`/api/v1/issues/${id}/resolutions`);
export const selectIntent = (id: number, candidate_id: string, evidence_version: string) =>
  apiFetch<ResolutionWorkflow>(`/api/v1/issues/${id}/resolution-intent`, { method: "PATCH", body: { candidate_id, evidence_version } });
export const clearIntent = (id: number) => apiFetch<ResolutionWorkflow>(`/api/v1/issues/${id}/resolution-intent`, { method: "DELETE" });
export const fetchDrafts = (issue_id: number) => apiFetch<{ drafts: PolicyDraft[] }>(`/api/v1/policy-drafts?issue_id=${issue_id}`);
export const createDraft = (issue_id: number, name: string) => apiFetch<PolicyDraft>("/api/v1/policy-drafts", { method: "POST", body: { issue_id, name } });
export const stagePermission = (id: number, issue_id: number, occurrence_id: number) =>
  apiFetch<PolicyDraft>(`/api/v1/policy-drafts/${id}/entries`, { method: "POST", body: { issue_id, occurrence_id } });
export const removeEntry = (id: number, entry_id: number) => apiFetch<PolicyDraft>(`/api/v1/policy-drafts/${id}/entries/${entry_id}`, { method: "DELETE" });
export const exportDraft = (id: number, format: "json" | "te", module_name?: string, literal_confirmed?: boolean, evidence_version?: string) =>
  apiFetch<PolicyDraftExport>(`/api/v1/policy-drafts/${id}/export`, { method: "POST", body: { format, module_name, literal_confirmed, evidence_version } });
