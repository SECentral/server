import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { ResolutionWorkflow as Workflow, ChangePlan } from "../api/resolution";
import type { IssueDetailResponse } from "../api/issue";
import { ResolutionWorkflow } from "./ResolutionWorkflow";

const candidate: Workflow["candidates"][number] = {
  id: "port-candidate", kind: "set_port_mapping", finding_kind: "port_policy_alternative", title: "Classify TCP/12345 as http_port_t",
  explanation: "Exact policy supplies name_bind for http_port_t; service intent remains unknown.", host_id: 1, hostname: "web-1",
  scope_kind: "host_port", scope_description: "TCP/12345 on web-1; not per process or remote IP.",
  scope_warning: "Inspect effective/local ranges and ownership; stop if they differ.", expected_effect: "Persistent classification affects other workloads; not a firewall rule.",
  intent_prompt: "I verified the service intent, ranges and other-workload ownership for TCP/12345 on web-1.",
  status: "proposed", mechanically_supported: true, intent_confirmation_required: true, evidence_version: "port-v1", limitations: [],
  evidence_basis: { occurrence_id: 11, protocol: "tcp", port: 12345, operation: "name_bind", target_port_type: "http_port_t", action: "add",
    prior_mappings: [{ type: "unreserved_port_t", start: 1024, end: 32767, provenance: "not_confirmed_custom" }] }
};
const service = { id: "http", label: "HTTP service", description: "Reference HTTP service classification; confirm the intended role.",
  source: "Fixture reference policy", source_url: "https://example.test/reference/http", macro_url: "https://example.test/reference/macro", source_entry: "network_port(http, ...) declares http_port_t" };
const investigation: NonNullable<Workflow["port_investigations"]>[number] = {
  host_id: 1, hostname: "web-1", occurrence_id: 11, protocol: "tcp", port: 12345, operation: "name_bind", observed_type: "unreserved_port_t",
  state: "ready", reason: "Compare correcting Listen, an existing endpoint, a relevant Boolean or a mapping. Generated options are not exhaustive.",
  inventory_status: "observed", local_status: "observed", latest_observed_at: "2026-10-17T10:00:00Z", type_count: 1,
  current_mappings: [{ type: "unreserved_port_t", start: 1024, end: 32767, provenance: "not_confirmed_custom" }],
  types: [{ type: "http_port_t", permission: "name_bind", state: "supported", explanation: "Supplies bind permission, not a service-intent recommendation.",
    service, existing_endpoints: [{ type: "http_port_t", start: 80, end: 80, provenance: "not_confirmed_custom" }] }]
};
function workflow(): Workflow {
  return { candidates: [candidate], rejected_candidates: [], port_investigations: [investigation], observed_access: null,
    intent: null, freshness: null, history: [], change_plan: null };
}
function plan(): ChangePlan {
  return { ...candidate, id: candidate.id, persistence: "Persistent local mapping; no firewall change.",
    preview_steps: [{ title: "Inspect local overrides", command: "semanage port -l -C", persistence: "inspection", explanation: "Verify no conflicting use." }],
    apply_steps: [{ title: "Add reviewed port mapping", command: "sudo semanage port -a -p tcp -t http_port_t 12345", persistence: "port_mapping", explanation: candidate.expected_effect }],
    verification_steps: [{ title: "Verify effective mapping and workload", command: "semanage port -l", persistence: "inspection", explanation: "Retry the real listener and request; check fresh AVCs and delivery health." }],
    rollback_steps: [{ title: "Remove only the new local singleton", command: "sudo semanage port -d -p tcp 12345", persistence: "port_mapping", explanation: "Only if this reviewed change was applied and no later changes intervened." }],
    rollback_description: "Restore the previous base-range behavior; never delete a pre-existing local mapping." };
}
function mount(state: Workflow) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const detail = { operator_guidance: { source: { host_id: 1, occurrence_id: 11, path: null }, possible_fix: investigation.reason } } as IssueDetailResponse;
  return render(<QueryClientProvider client={client}><MemoryRouter><ResolutionWorkflow issueId={7} stage="intent" initialData={state} initialDataUpdatedAt={Date.now()} detail={detail} /></MemoryRouter></QueryClientProvider>);
}

describe("Port troubleshooting", () => {
  it("compares policy and endpoint evidence, requires intent and labels persistent mapping mutations before Copy", async () => {
    let state = workflow();
    vi.stubGlobal("fetch", vi.fn(async (_url: string, options?: RequestInit) => {
      if (options?.method === "PATCH") {
        expect(JSON.parse(String(options.body))).toEqual({ candidate_id: candidate.id, evidence_version: "port-v1" });
        state = { ...state, intent: { candidate_id: candidate.id, candidate_kind: candidate.kind, selected_intent: candidate.intent_prompt,
          operator: "test", selected_at: "2026-10-17T11:00:00Z", evidence_version: "port-v1", status: "selected" }, freshness: "current", change_plan: plan() };
      }
      return new Response(JSON.stringify(state), { status: 200 });
    }));
    const user = userEvent.setup();
    mount(state);
    expect(screen.getByRole("article", { name: "Port investigation" })).toHaveTextContent("Local bind");
    expect(screen.getByText(/Intersecting observed ranges:/)).toHaveTextContent("unreserved_port_t 1024–32767");
    expect(screen.queryByRole("button", { name: /Copy sudo semanage/ })).not.toBeInTheDocument();
    expect(document.querySelectorAll(".resolution-candidate-card")).toHaveLength(0);
    expect(screen.getByLabelText("What service should listen on this port?")).toHaveValue("");
    await user.selectOptions(screen.getByLabelText("What service should listen on this port?"), "http");
    await user.selectOptions(screen.getByLabelText("Policy-supported port type"), "http_port_t");
    expect(screen.getByRole("link", { name: "Fixture reference policy" })).toHaveAttribute("href", service.source_url);
    expect(screen.getByText(/Your stated service intent/)).toHaveTextContent("not observed host evidence");
    expect(screen.getByText(/Observed endpoint\/range examples:/)).toHaveTextContent("TCP/80");
    await user.click(screen.getByRole("button", { name: "Choose intent" }));
    expect(screen.getByText(candidate.intent_prompt)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Confirm intent" }));
    const reviewed = await screen.findByRole("region", { name: "Selected change plan" });
    const copy = within(reviewed).getByRole("button", { name: "Copy sudo semanage port -a -p tcp -t http_port_t 12345" });
    const badge = within(reviewed).getAllByText("Changes SELinux port mapping")[0];
    expect(badge.compareDocumentPosition(copy) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(reviewed).queryByText("Changes host-wide Boolean")).not.toBeInTheDocument();
    expect(within(reviewed).getByRole("region", { name: "Verify port change" })).toHaveTextContent("real listener and request");
    expect(reviewed).toHaveTextContent("never delete a pre-existing local mapping");
  });

  it("keeps missing/partial evidence and mapping conflicts explicit without offering commands", () => {
    const state = { ...workflow(), candidates: [], port_investigations: [{ ...investigation, state: "blocked" as const, inventory_status: "partial",
      reason: "A service-specific range overlaps TCP/12345. Confirm its owner and inspect semanage port -l -C; no replacement is generated." }] };
    mount(state);
    expect(screen.getByRole("article", { name: "Port investigation" })).toHaveTextContent("service-specific range overlaps");
    expect(screen.getByText(/Stored effective inventory:/)).toHaveTextContent("partial");
    expect(screen.queryByRole("button", { name: "Choose intent" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("sudo semanage port");
  });

  it("keeps other ports on the same host secondary and retains outbound-connect semantics", async () => {
    const other = { ...candidate, id: "another-port", title: "Classify TCP/23456 as http_port_t", evidence_basis: { ...candidate.evidence_basis, port: 23456, occurrence_id: 22, operation: "name_connect" } };
    mount({ ...workflow(), candidates: [other, candidate], port_investigations: [investigation, { ...investigation, occurrence_id: 22, port: 23456, operation: "name_connect" }] });
    expect(screen.queryByText(other.title)).not.toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByText("Other port evidence examples · 1"));
    const secondary = screen.getByText(/TCP\/23456 · Outbound connect/).closest("article")!;
    await user.selectOptions(within(secondary).getByLabelText("What is the intended destination service?"), "http");
    await user.selectOptions(within(secondary).getByLabelText("Policy-supported port type"), "http_port_t");
    expect(screen.getByText(other.title)).toBeVisible();
    expect(screen.getByLabelText("What service should listen on this port?")).toHaveValue("");
    expect(screen.queryByText(/Historical checkpoint/)).not.toBeInTheDocument();
  });

  it("searches every discovered type beyond twelve without inventing descriptions or requiring known service intent", async () => {
    const types = Array.from({ length: 20 }, (_, index) => ({ type: `z_service_${index}_port_t`, permission: "name_bind", state: "supported" as const,
      explanation: "Exact policy supports this permission; suitability is unknown.", existing_endpoints: [] }));
    const candidates = types.map((option) => ({ ...candidate, id: option.type, title: `Classify TCP/12345 as ${option.type}`,
      evidence_basis: { ...candidate.evidence_basis, target_port_type: option.type } }));
    mount({ ...workflow(), candidates, port_investigations: [{ ...investigation, type_count: types.length, types }] });
    const user = userEvent.setup();
    expect(within(screen.getByLabelText("Policy-supported port type")).getAllByRole("option")).toHaveLength(21);
    await user.type(screen.getByRole("textbox", { name: "Search policy-supported port types" }), "z_service_19");
    await user.selectOptions(screen.getByLabelText("Policy-supported port type"), "z_service_19_port_t");
    expect(screen.getByRole("region", { name: "Selected port type" })).toHaveTextContent("No reference service description is available");
    expect(screen.getByRole("button", { name: "Choose intent" })).toBeEnabled();
    expect(screen.getByLabelText("What service should listen on this port?")).toHaveValue("");
    expect(document.querySelectorAll(".resolution-candidate-card")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Show all policy types" }));
    expect(within(screen.getByLabelText("Policy-supported port type")).getAllByRole("option")).toHaveLength(21);
  });

  it("distinguishes documented HTTP from HTTP cache without inferring either from the process or port", async () => {
    const cache = { ...investigation.types[0], type: "http_cache_port_t", service: { ...service, id: "http_cache", label: "HTTP cache service" } };
    mount({ ...workflow(), port_investigations: [{ ...investigation, types: [cache, investigation.types[0]], type_count: 2 }] });
    const user = userEvent.setup();
    expect(screen.queryByRole("region", { name: "Selected port type" })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("What service should listen on this port?"), "http");
    const choices = within(screen.getByLabelText("Policy-supported port type"));
    expect(choices.getByRole("option", { name: /HTTP service — http_port_t/ })).toBeInTheDocument();
    expect(choices.queryByRole("option", { name: /http_cache_port_t/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Choose intent" })).not.toBeInTheDocument();
  });

  it.each(["stale", "already permitted"])("keeps %s evidence inspectable without exposing a new change", async (kind) => {
    const state: Workflow = kind === "stale" ? { ...workflow(), candidates: [{ ...candidate, status: "evidence_changed", unavailable_reason: "Host state is stale; refresh before review." }] }
      : { ...workflow(), candidates: [], port_investigations: [{ ...investigation, state: "no_change", reason: "Current policy already permits this operation; check runtime state and retry.", types: [{ ...investigation.types[0], state: "no_op" }] }] };
    mount(state);
    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText("Policy-supported port type"), "http_port_t");
    expect(screen.queryByRole("button", { name: "Choose intent" })).not.toBeInTheDocument();
    expect(screen.getByRole("article", { name: "Port investigation" })).toHaveTextContent(kind === "stale" ? "Host state is stale" : "already permits");
    expect(document.body.textContent).not.toContain("sudo semanage port");
  });

  it("asks about listener intent for UDP bind without supplying an HTTP default", () => {
    mount({ ...workflow(), port_investigations: [{ ...investigation, protocol: "udp" }], candidates: [] });
    expect(screen.getByRole("article", { name: "Port investigation" })).toHaveTextContent("UDP/12345 · Local bind");
    expect(screen.getByLabelText("What service should listen on this port?")).toHaveValue("");
    expect(screen.getByLabelText("Policy-supported port type")).toHaveValue("");
  });
});
