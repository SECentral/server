import { apiFetch } from "./client";
import type * as Types from "./generated/types.gen";

export type System = Types.System;

export function getSystem(): Promise<System> {
  return apiFetch<System>("/api/v1/system");
}
