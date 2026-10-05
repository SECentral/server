import { apiFetch } from "./client";
import type { components } from "./types.gen";

export type System = components["schemas"]["System"];

export function getSystem(): Promise<System> {
  return apiFetch<System>("/api/v1/system");
}
