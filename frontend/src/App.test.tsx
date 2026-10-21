import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { App } from "./App";

it("keeps navigation available while lazy pages load and supports route changes", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["session"], { operator: { username: "admin" } });
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    const body = url.startsWith("/api/v1/issues")
      ? { issues: [], host_options: [], meta: { page: 1, page_size: 25, total: 0, total_pages: 0 }, summary: { regressed_count: 0 } }
      : url.startsWith("/api/v1/hosts")
        ? { hosts: [], meta: { page: 1, page_size: 25, total: 0, total_pages: 0 }, summary: { total: 0, agent_state_counts: { reporting: 0, stale: 0, offline: 0 } } }
        : { events: [], total_count: 0 };
    return { ok: true, status: 200, headers: new Headers(), json: async () => body } as Response;
  }));
  const user = userEvent.setup();
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/issues"]}><App /></MemoryRouter></QueryClientProvider>);

  expect(screen.getByRole("button", { name: "Toggle navigation" })).toBeVisible();
  expect(screen.getByLabelText("Loading page")).toBeInTheDocument();
  expect(await screen.findByRole("heading", { name: "SELinux issues", level: 1 })).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Toggle navigation" }));
  await user.click(screen.getByRole("link", { name: "Monitored servers" }));
  expect(await screen.findByRole("heading", { name: "Monitored servers", level: 1 })).toBeVisible();
  expect(screen.queryByRole("heading", { name: "SELinux issues", level: 1 })).not.toBeInTheDocument();
});
