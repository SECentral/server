import { apiFetch } from "./client";
import type { SelinuxLogHost, SelinuxLogResponse } from "./generated/types.gen";

export function fetchSelinuxLog(params: URLSearchParams): Promise<SelinuxLogResponse> {
  return apiFetch(`/api/v1/selinux-log?${params}`);
}

export function searchLogHosts(query: string, hostIds: string[] = []): Promise<{ hosts: SelinuxLogHost[] }> {
  const params = new URLSearchParams({ q: query });
  for (const id of hostIds) params.append("host_ids[]", id);
  return apiFetch(`/api/v1/selinux-log/hosts?${params}`);
}
