import { apiFetch } from "./client";
import type { components } from "./types.gen";

export type HostListItem = components["schemas"]["HostListItem"];
export type HostDetail = components["schemas"]["HostDetail"];
export type HostListResponse = components["schemas"]["HostListResponse"];
export type HostDetailResponse = components["schemas"]["HostDetailResponse"];
export type HostOccurrencesResponse = components["schemas"]["HostOccurrencesResponse"];
export type SelinuxActivityItem = components["schemas"]["SelinuxActivityItem"];
export type SelinuxCheckpoint = components["schemas"]["SelinuxCheckpoint"];
export type SelinuxActivityResponse = components["schemas"]["SelinuxActivityResponse"];
export type SelinuxActivityDetailResponse = components["schemas"]["SelinuxActivityDetailResponse"];

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
