import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
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
  host_id: 1, hostname: "web-1", occurrence_id: 11, occurrence_count: 1, protocol: "tcp", port: 12345, operation: "name_bind", observed_type: "unreserved_port_t",
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
    verification_steps: [{ title: "Verify effective mapping and workload", command: "semanage port -l", persistence: "inspection", explanation: "Retry the real listener and request; check fresh AVCs and delivery health. Silence alone is not success." }],
    rollback_steps: [{ title: "Remove only the new local singleton", command: "sudo semanage port -d -p tcp 12345", persistence: "port_mapping", explanation: "Only if this reviewed change was applied and no later changes intervened." }],
    rollback_description: "Restore the previous base-range behavior; never delete a pre-existing local mapping." };
}
function mount(state: Workflow, inspectionDetail?: IssueDetailResponse, entry = "/issues/7") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const detail = { operator_guidance: { source: { host_id: 1, occurrence_id: 11, hostname: "web-1", occurred_at: "2026-10-17T10:00:00Z", observed_type: "unreserved_port_t", path: null }, checks: [], manual_check: "Confirm workload intent", possible_fix: investigation.reason, verification: "Retry the actual workload", verification_limit: "Silence alone is not success", restriction: "Keep unwanted access denied" } } as unknown as IssueDetailResponse;
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}><HistoryControls /><ResolutionWorkflow issueId={7} stage="intent" initialData={state} initialDataUpdatedAt={Date.now()} detail={inspectionDetail ?? detail} /></MemoryRouter></QueryClientProvider>);
}

function HistoryControls() {
  const navigate = useNavigate();
  const location = useLocation();
  return <><button onClick={() => navigate(-1)}>Back</button><button onClick={() => navigate(1)}>Forward</button><output aria-label="Location">{location.search}</output></>;
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
    expect(screen.getByRole("article", { name: "Port investigation" })).toHaveTextContent("Recorded classification: unreserved_port_t 1024–32767");
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
    const copy = within(reviewed).getByRole("button", { name: "Copy command: sudo semanage port -a -p tcp -t http_port_t 12345" });
    const badge = within(reviewed).getAllByText("Changes SELinux port mapping")[0];
    expect(badge.compareDocumentPosition(copy) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(reviewed).queryByText("Changes host-wide Boolean")).not.toBeInTheDocument();
    expect(within(reviewed).getByRole("region", { name: "Verify port change" })).toHaveTextContent("Test the intended operation through the confined workload.");
    expect(reviewed).toHaveTextContent("never delete a pre-existing local mapping");
  });

  it("keeps missing/partial evidence and mapping conflicts explicit without offering commands", () => {
    const state = { ...workflow(), candidates: [], port_investigations: [{ ...investigation, state: "blocked" as const, inventory_status: "partial",
      reason: "A service-specific range overlaps TCP/12345. Confirm its owner and inspect semanage port -l -C; no replacement is generated." }] };
    mount(state);
    expect(screen.getByRole("article", { name: "Port investigation" })).toHaveTextContent("service-specific range overlaps");
    expect(screen.getByRole("article", { name: "Port investigation" })).toHaveTextContent("Inventory coverage: effective partial");
    expect(screen.queryByRole("button", { name: "Choose intent" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("sudo semanage port");
  });

  it("keeps other ports on the same host secondary and retains outbound-connect semantics", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ host: { id: 1, hostname: "web-1" }, guidance: null }), { status: 200 })));
    const other = { ...candidate, id: "another-port", title: "Classify TCP/23456 as http_port_t", evidence_basis: { ...candidate.evidence_basis, port: 23456, occurrence_id: 22, operation: "name_connect" } };
    mount({ ...workflow(), candidates: [other, candidate], port_investigations: [investigation, { ...investigation, occurrence_id: 22, port: 23456, operation: "name_connect" }] });
    expect(screen.queryByText(other.title)).not.toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: /TCP\/23456/ }));
    const secondary = screen.getByRole("article", { name: "Port investigation" });
    await user.selectOptions(within(secondary).getByLabelText("What remote service does this workload connect to?"), "http");
    await user.selectOptions(within(secondary).getByLabelText("Policy-supported port type"), "http_port_t");
    expect(screen.getByText(other.title)).toBeVisible();
    expect(screen.queryByLabelText("What service should listen on this port?")).not.toBeInTheDocument();
    expect(screen.queryByText(/Historical checkpoint/)).not.toBeInTheDocument();
  });

  it("browses resource B without mutating resource A's durable review and restores URL history", async () => {
    const state = workflow();
    state.port_investigations!.push({ ...investigation, port: 23456, occurrence_id: 22, occurrence_count: 5 });
    state.candidates.push({ ...candidate, id: "port-b", evidence_basis: { ...candidate.evidence_basis, port: 23456, occurrence_id: 22 } });
    state.intent = { candidate_id: candidate.id, candidate_kind: candidate.kind, selected_intent: candidate.intent_prompt,
      operator: "test", selected_at: "2026-10-17T11:00:00Z", evidence_version: "port-v1", status: "selected" };
    state.freshness = "current";
    state.change_plan = plan();
    const fetchMock = vi.fn(async (url: string, options?: RequestInit) => {
      expect(url).toMatch(/\/api\/v1\/issues\/7/);
      expect(options?.method ?? "GET").toBe("GET");
      return new Response(JSON.stringify(url.endsWith("/occurrences/22") ? { id: 22, host: { id: 1, hostname: "web-1" }, guidance: { checks: [{ command: "ss -ltnp 'sport = :23456'", reason: "Inspect listeners", expected: "Confirm owner" }] } } : state), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    mount(state);
    expect(screen.getByRole("region", { name: "Selected change plan" })).toBeVisible();
    expect(document.querySelectorAll(".resolution-candidate-card")).toHaveLength(1);
    expect(screen.queryByText(/Intent is unknown/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: /TCP\/23456/ }));
    expect(screen.getByText(/Viewing TCP\/23456; the reviewed plan is on TCP\/12345/)).toBeVisible();
    expect(screen.getByRole("tab", { name: /TCP\/12345.*1 denial.*Review current/ })).toBeVisible();
    expect(screen.getByRole("tab", { name: /TCP\/23456.*5 denials/ })).toBeVisible();
    expect(await screen.findByRole("button", { name: "Copy command: ss -ltnp 'sport = :23456'" })).toBeVisible();
    expect(screen.getByRole("region", { name: "Inspect active resource" })).toHaveTextContent("Inspect listeners");
    expect(screen.queryByRole("region", { name: "Selected change plan" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Copy sudo/ })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Location")).toHaveTextContent("resource=1%3Atcp%3A23456%3Aname_bind");
    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByRole("region", { name: "Selected change plan" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Forward" }));
    expect(screen.queryByRole("region", { name: "Selected change plan" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Switch to reviewed plan" }));
    expect(screen.getByRole("region", { name: "Selected change plan" })).toBeVisible();
    expect(fetchMock.mock.calls.every((call) => !call[1] || !["PATCH", "DELETE"].includes(String((call[1] as RequestInit)?.method)))).toBe(true);
  });

  it("keeps inspection without intent, consolidates matching pre-change checks, and retains post-change verification", async () => {
    const state = workflow();
    const detail = { operator_guidance: { source: { host_id: 1, occurrence_id: 11, protocol: "tcp", port: 12345, operation: "name_bind", path: null },
      checks: [{ title: "Inspect local overrides", command: "semanage port -l -C", interpretation: "Stop for a changed range." }],
      manual_check: "Confirm ownership", possible_fix: "Compare approaches", verification: "Retry the actual application request", verification_limit: "Silence alone is not success", restriction: "Keep unwanted access denied" } } as IssueDetailResponse;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ id: 11, host: { id: 1, hostname: "web-1" }, guidance: { checks: [{ reason: "Inspect local overrides", command: "semanage port -l -C", expected: "Stop for a changed range." }] } }), { status: 200 })));
    const view = mount(state, detail);
    expect(await screen.findByRole("button", { name: "Copy command: semanage port -l -C" })).toBeVisible();
    view.unmount();
    state.intent = { candidate_id: candidate.id, candidate_kind: candidate.kind, selected_intent: candidate.intent_prompt,
      operator: "test", selected_at: "2026-10-17T11:00:00Z", evidence_version: "port-v1", status: "selected" };
    state.freshness = "current";
    state.change_plan = plan();
    state.change_plan.verification_steps![0].command = "semanage port -l -C";
    detail.operator_guidance!.checks.push({ title: "Listener ownership", command: "ss -ltnp", interpretation: "Inspect the intended owner." });
    const reviewedView = mount(state, detail);
    expect(screen.getByRole("region", { name: "Check" })).toHaveTextContent("Listener ownership");
    expect(screen.getAllByRole("button", { name: "Copy command: semanage port -l -C" })).toHaveLength(2);
    expect(screen.getByRole("region", { name: "Selected change plan" })).toHaveTextContent("Retry the actual application request");
    expect(screen.getByRole("button", { name: "Copy command: ss -ltnp" })).toBeVisible();
    reviewedView.unmount();
    state.change_plan.preview_steps[0].command = "semanage port -l";
    mount(state, detail);
    expect(screen.getAllByRole("button", { name: "Copy command: semanage port -l -C" })).toHaveLength(2);
  });

  it("shares baseline and optional policy checks across hosts while retaining each occurrence's enforcement and syscall result", async () => {
    const state = { ...workflow(), candidates: [], port_investigations: [investigation, { ...investigation, host_id: 2, hostname: "web-2", occurrence_id: 22 }] };
    const checks = [
      { kind: "socket_listeners", command: "ss -ltnp 'sport = :12345'", reason: "Inspect listeners", expected: "Confirm owner" },
      { kind: "port_classification", command: "semanage port -l", reason: "Inspect classification", expected: "Compare ranges" },
      { kind: "port_local_classification", command: "semanage port -l -C", reason: "Inspect overrides", expected: "Check local changes" },
      { kind: "port_policy_alternatives", command: "sesearch -A -s httpd_t -c tcp_socket -p name_bind -C", reason: "Inspect policy", expected: "Current policy is not historical evidence" }
    ];
    const fetchMock = vi.fn(async (url: string) => {
      const permissive = url.endsWith("/22");
      return new Response(JSON.stringify({ id: permissive ? 22 : 11, host: { id: permissive ? 2 : 1, hostname: permissive ? "web-2" : "web-1" },
        normalized_denial: { target_class: "tcp_socket", details: { permissive, syscall_evidence: [{ success: permissive ? "yes" : "no", exit: permissive ? "0" : "-13" }] } },
        guidance: { checks } }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    mount(state);
    const user = userEvent.setup();
    expect(await screen.findByText(/Enforcing \(permissive=0\)/)).toHaveTextContent("Failed");
    for (const check of checks.slice(0, 3)) expect(screen.getByRole("button", { name: `Copy command: ${check.command}` })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Policy inspection" }));
    expect(screen.getByRole("button", { name: `Copy command: ${checks[3].command}` })).toBeVisible();
    await user.click(screen.getByRole("tab", { name: /web-2/ }));
    expect(await screen.findByText(/Non-enforced \(permissive=1\)/)).toHaveTextContent("Succeeded");
    expect(screen.queryByText(/Enforcing \(permissive=0\)/)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "web-2 · #22" })).toHaveAttribute("href", "/hosts/2/occurrences/22");
    for (const check of checks.slice(0, 3)) expect(screen.getByRole("button", { name: `Copy command: ${check.command}` })).toBeVisible();
    expect(screen.getByRole("button", { name: "Policy inspection" })).toHaveAttribute("aria-expanded", "false");
    await user.click(screen.getByRole("button", { name: "Policy inspection" }));
    expect(screen.getByRole("button", { name: `Copy command: ${checks[3].command}` })).toBeVisible();
    expect(screen.queryByRole("region", { name: "Selected change plan" })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual(["/api/v1/issues/7/occurrences/11", "/api/v1/issues/7/occurrences/22"]);
  });

  it("does not infer syscall success from a permissive AVC", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ id: 11, host: { id: 1, hostname: "web-1" },
      normalized_denial: { details: { permissive: true } }, guidance: { checks: [] } }), { status: 200 })));
    mount(workflow());
    expect(await screen.findByText(/Non-enforced \(permissive=1\)/)).toHaveTextContent("Recorded syscall result: Not established");
  });

  it("opens rollback from a phase deep link and retains prior-state warnings before its mutation Copy", async () => {
    const state = workflow();
    state.intent = { candidate_id: candidate.id, candidate_kind: candidate.kind, selected_intent: candidate.intent_prompt,
      operator: "test", selected_at: "2026-10-17T11:00:00Z", evidence_version: "port-v1", status: "selected" };
    state.freshness = "current";
    state.change_plan = plan();
    mount(state, undefined, "/issues/7?resource=1%3Atcp%3A12345%3Aname_bind&phase=rollback");
    expect(screen.getByRole("button", { name: "Rollback procedure" })).toHaveAttribute("aria-expanded", "true");
    const rollback = document.getElementById("plan-rollback")!;
    const copy = within(rollback).getByRole("button", { name: "Copy command: sudo semanage port -d -p tcp 12345" });
    expect(within(rollback).getByText(/no later changes intervened/).compareDocumentPosition(copy) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(rollback).getByText("Changes SELinux port mapping").compareDocumentPosition(copy) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await userEvent.setup().click(screen.getByRole("button", { name: "Rollback procedure" }));
    expect(screen.getByRole("button", { name: "Rollback procedure" })).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByLabelText("Location")).not.toHaveTextContent("phase=rollback");
    expect(screen.getByLabelText("Location")).toHaveTextContent("resource=1%3Atcp%3A12345%3Aname_bind");
  });

  it("restores a URL-selected identical port on another host without exposing the reviewed host's plan", () => {
    const state = workflow();
    state.port_investigations!.push({ ...investigation, host_id: 2, hostname: "web-2", occurrence_id: 22 });
    state.intent = { candidate_id: candidate.id, candidate_kind: candidate.kind, selected_intent: candidate.intent_prompt,
      operator: "test", selected_at: "2026-10-17T11:00:00Z", evidence_version: "port-v1", status: "selected" };
    state.freshness = "current";
    state.change_plan = plan();
    mount(state, undefined, "/issues/7?resource=2%3Atcp%3A12345%3Aname_bind");
    expect(screen.getByRole("tab", { name: /web-2/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("article", { name: "Port investigation" })).toHaveTextContent("web-2");
    expect(screen.queryByRole("region", { name: "Selected change plan" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Switch to reviewed plan" })).toBeVisible();
  });

  it("falls back from an invalid resource URL and searches a bounded selector for more than five investigations", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ host: { id: 1, hostname: "web-1" }, guidance: null }), { status: 200 })));
    const state = { ...workflow(), candidates: [], port_investigations: Array.from({ length: 8 }, (_, index) => ({ ...investigation, port: 12345 + index, occurrence_id: 11 + index })) };
    mount(state, undefined, "/issues/7?resource=removed-resource");
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
    const select = screen.getByRole("combobox", { name: "Active investigation resource" });
    expect(select).toHaveValue("1:tcp:12345:name_bind");
    const user = userEvent.setup();
    await user.type(screen.getByRole("textbox", { name: "Search investigation resources" }), "12352");
    expect(within(select).getAllByRole("option")).toHaveLength(2);
    await user.selectOptions(select, "1:tcp:12352:name_bind");
    expect(screen.getByRole("article", { name: "Port investigation" })).toHaveTextContent("TCP/12352");
    expect(screen.getByLabelText("Location")).toHaveTextContent("resource=1%3Atcp%3A12352%3Aname_bind");
  });

  it("reports a failed active-resource inspection without presenting it as a successful empty check", async () => {
    const state = { ...workflow(), port_investigations: [investigation, { ...investigation, port: 23456, occurrence_id: 22 }] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: { message: "Inspection evidence unavailable" } }), { status: 503 })));
    mount(state, undefined, "/issues/7?resource=1%3Atcp%3A23456%3Aname_bind");
    expect(await screen.findByRole("heading", { name: /Could not load resource inspection/ })).toBeVisible();
    expect(within(screen.getByRole("region", { name: "Inspect active resource" })).queryByRole("button", { name: /Copy/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Selected change plan" })).not.toBeInTheDocument();
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
