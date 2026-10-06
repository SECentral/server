import { apiFetch } from "./client";
import type * as Types from "./generated/types.gen";

export type ConfigurationFamily = Types.ConfigurationFamily;
export type ConfigurationFleetResponse = Types.ConfigurationFleetResponse;
export type HostConfigurationResponse = Types.HostConfigurationResponse;

export function fetchConfiguration(family: ConfigurationFamily, policyIdentity?: string): Promise<ConfigurationFleetResponse> {
  const query = new URLSearchParams();
  query.set("family", family);
  if (policyIdentity) {
    query.set("policy_identity", policyIdentity);
  }
  return apiFetch<ConfigurationFleetResponse>(`/api/v1/configuration?${query.toString()}`);
}

export function fetchHostConfiguration(
  id: number,
  params: { view?: string; q?: string; page?: number } = {}
): Promise<HostConfigurationResponse> {
  const query = new URLSearchParams();
  if (params.view) {
    query.set("view", params.view);
  }
  if (params.q) {
    query.set("q", params.q);
  }
  if (params.page !== undefined && params.page > 1) {
    query.set("page", String(params.page));
  }
  const suffix = query.toString();
  return apiFetch<HostConfigurationResponse>(`/api/v1/hosts/${id}/configuration${suffix ? `?${suffix}` : ""}`);
}
