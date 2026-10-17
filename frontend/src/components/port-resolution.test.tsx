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
  evidence_basis: { occurrence_id: 11, protocol: "tcp", port: 12345, target_port_type: "http_port_t", action: "add",
    prior_mappings: [{ type: "unreserved_port_t", start: 1024, end: 32767, provenance: "not_confirmed_custom" }] }
};
const investigation: NonNullable<Workflow["port_investigations"]>[number] = {
  host_id: 1, hostname: "web-1", occurrence_id: 11, protocol: "tcp", port: 12345, operation: "name_bind", observed_type: "unreserved_port_t",
  state: "ready", reason: "Compare correcting Listen, an existing endpoint, a relevant Boolean or a mapping. Generated options are not exhaustive.",
  inventory_status: "observed", local_status: "observed", latest_observed_at: "2026-10-17T10:00:00Z", type_count: 1,
  types: [{ type: "http_port_t", permission: "name_bind", state: "supported", explanation: "Supplies bind permission, not a service-intent recommendation.",
    existing_endpoints: [{ type: "http_port_t", start: 80, end: 80, provenance: "not_confirmed_custom" }] }]
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
    expect(screen.getByText(/Recorded prior state:/)).toHaveTextContent("unreserved_port_t 1024–32767");
    expect(screen.queryByRole("button", { name: /Copy sudo semanage/ })).not.toBeInTheDocument();
    await user.click(screen.getByText("Compare policy-supported port types · 1 of 1"));
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
    const other = { ...candidate, id: "another-port", title: "Classify TCP/23456 as http_port_t", evidence_basis: { ...candidate.evidence_basis, port: 23456, occurrence_id: 22 } };
    mount({ ...workflow(), candidates: [other, candidate], port_investigations: [investigation, { ...investigation, occurrence_id: 22, port: 23456, operation: "name_connect" }] });
    expect(screen.getByText(other.title)).not.toBeVisible();
    const user = userEvent.setup();
    await user.click(screen.getByText("Other host/resource examples · 1"));
    expect(screen.getByText(other.title)).toBeVisible();
    await user.click(screen.getByText("Other port evidence examples · 1"));
    expect(screen.getByText(/TCP\/23456 · Outbound connect/)).toBeVisible();
    expect(screen.queryByText(/Historical checkpoint/)).not.toBeInTheDocument();
  });
});
