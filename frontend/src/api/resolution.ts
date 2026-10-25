import { apiFetch } from "./client";
import type * as Types from "./generated/types.gen";

export type ResolutionWorkflow = Types.ResolutionWorkflow;
export type ChangePlan = Types.ChangePlan;
export type HomeContentReview = { path: string; confirmed: boolean };

export const fetchResolutions = (id: number) => apiFetch<ResolutionWorkflow>(`/api/v1/issues/${id}/resolutions`);
export const selectIntent = (id: number, candidate_id: string, evidence_version: string, home_content_review?: HomeContentReview) =>
  apiFetch<ResolutionWorkflow>(`/api/v1/issues/${id}/resolution-intent`, { method: "PATCH", body: { candidate_id, evidence_version, ...(home_content_review ? { home_content_review } : {}) } });
export const clearIntent = (id: number) => apiFetch<ResolutionWorkflow>(`/api/v1/issues/${id}/resolution-intent`, { method: "DELETE" });
