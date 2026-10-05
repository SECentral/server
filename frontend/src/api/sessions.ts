import { apiFetch } from "./client";
import type { components } from "./types.gen";

export type Session = components["schemas"]["Session"];

export function getSession(): Promise<Session> {
  return apiFetch<Session>("/api/v1/sessions");
}

export function createSession(username: string, password: string): Promise<Session> {
  return apiFetch<Session>("/api/v1/sessions", { method: "POST", body: { username, password } });
}

export function deleteSession(): Promise<void> {
  return apiFetch<void>("/api/v1/sessions", { method: "DELETE" });
}
