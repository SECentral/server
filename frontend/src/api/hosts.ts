import { apiFetch } from "./client";
import type * as Types from "./generated/types.gen";

export type HostListItem = Types.HostListItem;
export type HostDetail = Types.HostDetail;
export type HostListResponse = Types.HostListResponse;
export type HostDetailResponse = Types.HostDetailResponse;
export type HostOccurrencesResponse = Types.HostOccurrencesResponse;
export type SelinuxActivityItem = Types.SelinuxActivityItem;
export type SelinuxCheckpoint = Types.SelinuxCheckpoint;
export type SelinuxActivityResponse = Types.SelinuxActivityResponse;
export type SelinuxActivityDetailResponse = Types.SelinuxActivityDetailResponse;

export function fetchHosts(params: URLSearchParams): Promise<HostListResponse> {
  const suffix = params.toString();
  return apiFetch<HostListResponse>(`/api/v1/hosts${suffix ? `?${suffix}` : ""}`);
}

export function fetchHost(id: number): Promise<HostDetailResponse> {
  return apiFetch<HostDetailResponse>(`/api/v1/hosts/${id}`);
}

export function fetchHostOccurrences(
  id: number,
  params: { limit?: number; before?: string; page?: number } = {}
): Promise<HostOccurrencesResponse> {
  const query = new URLSearchParams();
  if (params.limit !== undefined) {
    query.set("limit", String(params.limit));
  }
  if (params.before) {
    query.set("before", params.before);
  }
  if (params.page !== undefined) query.set("page", String(params.page));
  const suffix = query.toString();
  return apiFetch<HostOccurrencesResponse>(`/api/v1/hosts/${id}/occurrences${suffix ? `?${suffix}` : ""}`);
}

export function fetchHostSelinuxActivity(id: number, params: { before?: string; eventId?: number; occurrenceId?: number; page?: number } = {}): Promise<SelinuxActivityResponse> {
  const query = new URLSearchParams();
  if (params.before) query.set("before", params.before);
  if (params.eventId) query.set("event_id", String(params.eventId));
  if (params.occurrenceId) query.set("occurrence_id", String(params.occurrenceId));
  if (params.page !== undefined) query.set("page", String(params.page));
  const suffix = query.toString();
  return apiFetch<SelinuxActivityResponse>(`/api/v1/hosts/${id}/selinux-activity${suffix ? `?${suffix}` : ""}`);
}

export function fetchHostSelinuxActivityEvidence(id: number, eventId: number): Promise<SelinuxActivityDetailResponse> {
  return apiFetch<SelinuxActivityDetailResponse>(`/api/v1/hosts/${id}/selinux-activity/${eventId}`);
}
