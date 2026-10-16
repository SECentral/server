import { apiFetch } from "./client";
import type * as Types from "./generated/types.gen";

export type ConfigurationFamily = Types.ConfigurationFamily;
export type ConfigurationFleetResponse = Types.ConfigurationFleetResponse;
export type ConfigurationPolicyCohort = Types.ConfigurationPolicyCohort;
export type HostConfigurationResponse = Types.HostConfigurationResponse;

export function fetchConfiguration(family: ConfigurationFamily, params: { policyIdentity?: string; page?: number; limit?: number; q?: string; protocol?: "tcp" | "udp" } = {}): Promise<ConfigurationFleetResponse> {
  const query = new URLSearchParams();
  query.set("family", family);
  if (params.policyIdentity) query.set("policy_identity", params.policyIdentity);
  if (params.page && params.page > 1) query.set("page", String(params.page));
  if (params.limit) query.set("limit", String(params.limit));
  if (params.q) query.set("q", params.q);
  if (params.protocol) query.set("protocol", params.protocol);
  return apiFetch<ConfigurationFleetResponse>(`/api/v1/configuration?${query.toString()}`);
}

export function fetchHostConfiguration(
  id: number,
  params: { view?: string; q?: string; page?: number; referenceRevisionId?: string; limit?: number; results?: string } = {}
): Promise<HostConfigurationResponse> {
  const query = new URLSearchParams();
  if (params.referenceRevisionId !== undefined) query.set("reference_revision_id", params.referenceRevisionId);
  if (params.view) {
    query.set("view", params.view);
  }
  if (params.q) {
    query.set("q", params.q);
  }
  if (params.page !== undefined && params.page > 1) {
    query.set("page", String(params.page));
  }
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  if (params.results !== undefined) query.set("results", params.results);
  const suffix = query.toString();
  return apiFetch<HostConfigurationResponse>(`/api/v1/hosts/${id}/configuration${suffix ? `?${suffix}` : ""}`);
}
