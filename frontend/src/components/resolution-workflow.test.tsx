import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";
import type { PolicyDraft, ResolutionWorkflow as Workflow } from "../api/resolution";
import { CopyCommand, ResolutionWorkflow } from "./ResolutionWorkflow";
import { ReadOnlyCommands } from "./OperatorGuidance";
import { fileResourceLabel, resolutionResources } from "./resolutionResources";
import { TechnicalEvidenceDisclosure } from "./WorkbenchEvidence";
import { MemoryRouter } from "react-router-dom";
import type { IssueDetailResponse } from "../api/issue";

const candidate: Workflow["candidates"][number] = {
  id: "boolean-path", kind: "enable_boolean", title: "Enable capability controlled by httpd_can_network_connect",
  explanation: "The exact retained policy rule supplies name_connect when this condition is On.", finding_kind: "conditional_allow_inactive",
  host_id: 1, hostname: "web-1", evidence_basis: { policy_fact_id: 4432, boolean: "httpd_can_network_connect", current_boolean: { current: false } }, evidence_version: "v1",
  intent_prompt: "I intend this workload to have this capability", scope_kind: "host_boolean", scope_description: "Host-wide; not only TCP/12345",
  scope_warning: "Other rules may activate", expected_effect: "Activates the matched True branch", mechanically_supported: true,
  intent_confirmation_required: true, limitations: ["Persistent rollback state unknown"], status: "proposed"
};
function initial(): Workflow {
  return { candidates: [candidate], rejected_candidates: [{ kind: "port_mapping", reason: "Alternative type not proven" }],
    observed_access: { occurrence_id: 1, host_id: 1, hostname: "web-1", actor: "httpd", source_type: "httpd_t", resource: "TCP/12345",
      target_type: "unreserved_port_t", object_class: "tcp_socket", permissions: ["name_connect"], operation_label: "connect", outcome: "DENIED", observed_at: "2026-10-01T10:42:20Z" },
    intent: null, freshness: null, change_plan: null, history: [] };
}
function selected(): Workflow {
  return { ...initial(), intent: { candidate_id: candidate.id, candidate_kind: candidate.kind, selected_intent: candidate.intent_prompt,
    operator: "admin", selected_at: "2026-10-01T11:00:00Z", evidence_version: "v1", status: "selected" }, freshness: "current",
    change_plan: { id: candidate.id, title: candidate.title, explanation: candidate.explanation, scope_kind: candidate.scope_kind,
      scope_description: candidate.scope_description, scope_warning: candidate.scope_warning, expected_effect: candidate.expected_effect,
      limitations: candidate.limitations, evidence_basis: candidate.evidence_basis, evidence_version: "v1", persistence: "Temporary and optional persistent alternatives",
      preview_steps: [{ title: "Inspect", command: "getsebool httpd_can_network_connect", explanation: "Confirm Off", persistence: "inspection" }],
      apply_steps: [{ title: "Apply temporarily", command: "sudo setsebool httpd_can_network_connect on", explanation: "Runtime only", persistence: "temporary" },
        { title: "Apply persistently (optional)", command: "sudo setsebool -P httpd_can_network_connect on", explanation: "Persistent", persistence: "persistent" }],
      rollback_steps: [{ title: "Undo temporary", command: "sudo setsebool httpd_can_network_connect off", explanation: "Runtime only", persistence: "temporary" }],
      rollback_description: "Persistent rollback state unknown" } };
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter><ResolutionWorkflow issueId={1939} stage="actions" /><ResolutionWorkflow issueId={1939} stage="draft" /><ResolutionWorkflow issueId={1939} stage="observed" /><ResolutionWorkflow issueId={1939} stage="intent" /></MemoryRouter></QueryClientProvider>);
}

describe("Evidence-driven resolution UI", () => {
  it("shows exact supporting permission sets and scoped examples before reviewing one shared remedy", async () => {
    const state = initial();
    state.candidates = [{ ...candidate, id: "shared-read", permissions: ["open", "read"], supporting_observations: [
      { issue_signature_id: 11, permissions: ["read"], occurrence_id: 101, occurrence_count: 2, enforcement_modes: ["enforcing"] },
      { issue_signature_id: 12, permissions: ["open", "read"], occurrence_id: 102, occurrence_count: 1, enforcement_modes: ["permissive"] }
    ] }];
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(state), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    mount();
    const support = await screen.findByRole("region", { name: "Remedy support" });
    expect(support).toHaveTextContent("Supporting permission sets: read · open, read");
    expect(support).toHaveTextContent("Shared mechanics do not establish that every permission becomes allowed or that the workload succeeds");
    expect(screen.getAllByRole("button", { name: "Review Boolean change" })).toHaveLength(1);
    expect(screen.queryByRole("button", { name: /Copy command:.*setsebool/ })).not.toBeInTheDocument();
    await user.click(within(support).getByRole("button", { name: "Supporting observations" }));
    expect(within(support).getByRole("link", { name: "Example #101" })).toHaveAttribute("href", "/hosts/1/occurrences/101");
    expect(within(support).getByRole("link", { name: "Example #102" })).toHaveAttribute("href", "/hosts/1/occurrences/102");
    expect(support).toHaveTextContent("enforcing · 2 supporting occurrences");
    expect(support).toHaveTextContent("permissive · 1 supporting occurrence");
    await user.click(screen.getByRole("button", { name: "Review Boolean change" }));
    await user.click(screen.getByRole("button", { name: "Confirm intent" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues/1939/resolution-intent", expect.objectContaining({ method: "PATCH", body: JSON.stringify({ candidate_id: "shared-read", evidence_version: "v1" }) })));
  });

  it("requires identified file and home-content confirmation before submitting a Boolean review", async () => {
    const state = initial();
    state.candidates = [{ ...candidate, id: "home-content", requires_home_content_review: true, home_content_path: null, presentation: "technical_alternative",
      evidence_basis: { occurrence_id: 1, boolean: "httpd_read_user_content" }, intent_prompt: "I checked labels and confirm intentional home content." }];
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(state), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: /Alternative policy approaches/ }));
    await user.click(screen.getByRole("button", { name: "Review Boolean change" }));
    const confirm = screen.getByRole("button", { name: "Confirm intent" });
    expect(confirm).toBeDisabled();
    expect(screen.getByText(/account\/NSS database/)).toBeVisible();
    expect(screen.queryByText("sudo setsebool httpd_read_user_content on")).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Identified home-content file path"), "/srv/custom-home/alice/report.html");
    expect(confirm).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /I completed these checks/ }));
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues/1939/resolution-intent", expect.objectContaining({ method: "PATCH",
      body: JSON.stringify({ candidate_id: "home-content", evidence_version: "v1", home_content_review: { path: "/srv/custom-home/alice/report.html", confirmed: true } }) })));
  });

  it("synchronizes file resource focus, preserves full identities and reports failed evidence without substituting the latest event", async () => {
    const state = initial();
    const paths = ["/srv/a/20261006/first", "/srv/a/20261006/later-modify", "/srv/b/20261006/first"];
    state.history = [{ action: "selected", operator: "operator-a", created_at: "2026-10-01T10:00:00Z", details: {} }];
    state.candidates = paths.map((path, index) => ({ ...candidate, id: `file-${index}`, kind: "restore_configured_label", scope_kind: "single_object", evidence_basis: { path, occurrence_id: index + 11 }, status: "evidence_changed", unavailable_reason: "Host configuration snapshot missing." }));
    const detail = { issue: { source_type: "httpd_t", target_type: "var_t", target_class: "file", permissions: ["read"], occurrences_count: 3, disposition_history: [] }, host_explanations: [], intelligence: {}, diagnosis: null } as unknown as IssueDetailResponse;
    let fail = false;
    const fetchMock = vi.fn<(url: string, options?: RequestInit) => Promise<Response>>(async (url: string) => {
      const id = Number(url.split("/").at(-1));
      return new Response(JSON.stringify(url.includes("/occurrences/") ? fail ? { error: { message: "Unavailable" } } : { id, host: { id: 1, hostname: "web-1" }, occurred_at: "2026-10-01T10:42:20Z", normalized_denial: { command: `process-${id}`, source_type: "httpd_t", target_type: "var_t", target_class: "file", permissions: ["read"], target_paths: [paths[id - 11]], details: {} }, guidance: { checks: [] } } : { host: {} }), { status: fail && url.includes("/occurrences/") ? 404 : 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><ResolutionWorkflow issueId={7} stage="observed" initialData={state} detail={detail} /><ResolutionWorkflow issueId={7} stage="context" initialData={state} detail={detail} /><ResolutionWorkflow issueId={7} stage="intent" initialData={state} detail={detail} /></MemoryRouter></QueryClientProvider>);
    const user = userEvent.setup();
    expect(await screen.findByRole("complementary", { name: "Investigation context" })).toHaveTextContent(paths[0]);
    const history = within(screen.getByRole("complementary", { name: "Investigation context" })).getByRole("button", { name: "Intent history" });
    expect(history).toHaveAttribute("aria-expanded", "false");
    await user.click(history);
    expect(screen.getByRole("region", { name: "Operator history" })).toHaveTextContent("operator-a");
    expect(document.querySelector(".workbench-activity-history")).toBeNull();
    expect(screen.getByRole("tab", { name: `${paths[0]} · web-1` })).toHaveTextContent("a/20261006/first");
    const next = screen.getByRole("tab", { name: `${paths[1]} · web-1` });
    expect(next).toHaveTextContent("later-modify");
    expect(within(next).getByTitle(`${paths[1]} · web-1`)).toBeInTheDocument();
    await user.click(next);
    await waitFor(() => expect(screen.getByRole("region", { name: "Observed access" })).toHaveTextContent(paths[1]));
    expect(screen.getByRole("complementary", { name: "Investigation context" })).toHaveTextContent("process-12");
    expect(screen.getByRole("region", { name: "Resolution options" })).toHaveTextContent("Host configuration snapshot missing.");
    expect(screen.queryByRole("region", { name: "Verify" })).not.toBeInTheDocument();
    fail = true;
    await user.click(screen.getByRole("tab", { name: `${paths[2]} · web-1` }));
    await waitFor(() => expect(screen.getAllByText("Active resource evidence unavailable")).toHaveLength(2));
    expect(screen.getByRole("region", { name: "Observed access" })).not.toHaveTextContent("TCP/12345");
    expect(fetchMock.mock.calls.every((call) => !call[1]?.method || call[1].method === "GET")).toBe(true);
  });

  it("keeps next steps and review controls aligned with changing server eligibility and observation trust", () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const baseTime = Date.now();
    const content = (state: Workflow, version: number) => <QueryClientProvider client={client}><MemoryRouter><ResolutionWorkflow issueId={7} stage="intent" initialData={state} initialDataUpdatedAt={baseTime + version} /></MemoryRouter></QueryClientProvider>;
    const view = render(content(initial(), 0));
    expect(screen.getByLabelText("Suggested next step")).toHaveTextContent("runtime and persistent Boolean state");
    expect(screen.getByRole("button", { name: "Review Boolean change" })).toBeEnabled();
    const unavailable = { ...candidate, status: "evidence_changed" as const, evidence_basis: { current_boolean: { status: "observed", current: true } }, unavailable_reason: "Host configuration snapshot missing or stale." };
    view.rerender(content({ ...initial(), candidates: [unavailable] }, 1));
    expect(screen.getByLabelText("Suggested next step")).toHaveTextContent("Refresh the missing or stale evidence");
    expect(screen.getByText("Needs verification · plan unavailable")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Review Boolean change" })).not.toBeInTheDocument();
    view.rerender(content({ ...initial(), candidates: [{ ...unavailable, status: "no_longer_supported" }] }, 2));
    expect(screen.getByLabelText("Suggested next step")).toHaveTextContent("Recheck current runtime state and retry");
    view.rerender(content({ ...initial(), candidates: [{ ...unavailable, status: "no_longer_supported", evidence_basis: { current_boolean: { status: "unavailable", current: true } } }] }, 3));
    expect(screen.queryByText("Last observed Boolean: On")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Suggested next step")).toHaveTextContent("policy-evidence blocker");
    view.rerender(content({ ...initial(), candidates: [] }, 4));
    expect(screen.queryByLabelText("Suggested next step")).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Verify" })).not.toBeInTheDocument();
  });

  it("uses whole path segments for unique suffixes and distinguishes identical paths on different hosts", () => {
    const state = initial();
    state.candidates = ["/srv/a/later-modify", "/srv/b/later-modify", "/srv/b/later-add"].map((path, index) => ({ ...candidate, id: `file-${index}`, evidence_basis: { path } }));
    let resources = resolutionResources(state);
    expect(resources.map((resource) => fileResourceLabel(resource, resources))).toEqual(["a/later-modify", "b/later-modify", "later-add"]);
    state.candidates.push({ ...state.candidates[0], id: "other-host", host_id: 2 });
    resources = resolutionResources(state);
    const labels = resources.map((resource) => fileResourceLabel(resource, resources));
    expect(new Set(labels).size).toBe(4);
    expect(labels[0]).toContain("#1");
    expect(labels[3]).toContain("#2");
  });

  it("keeps command purpose and safety interpretation together above exact code and announces copy failure", async () => {
    const command = "stat -- '/srv/a file'";
    render(<><ReadOnlyCommands checks={[{ title: "Inspect object identity", command, interpretation: "Stop if missing or replaced." }]} /><CopyCommand command="getsebool httpd_read_user_content" /></>);
    const header = screen.getByText("Inspect object identity").closest("p")!;
    expect(header).toHaveTextContent("Inspect object identity · Stop if missing or replaced.");
    const code = screen.getByText(command).closest(".command-block")!;
    expect(header.compareDocumentPosition(code) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(code.nextElementSibling).toBeNull();
    const user = userEvent.setup();
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("Denied"));
    await user.click(screen.getByRole("button", { name: `Copy command: ${command}` }));
    await waitFor(() => expect(within(code as HTMLElement).getByRole("status")).toHaveTextContent("Copy unavailable; select the command text"));
    expect(screen.queryByRole("button", { name: "Confirm intent" })).not.toBeInTheDocument();
  });

  it("prioritizes identifying a missing file path while keeping eligible host-wide Boolean review separate", () => {
    const state = { ...initial(), candidates: [{ ...candidate, evidence_basis: { ...candidate.evidence_basis, occurrence_id: 1 } }] };
    const detail = { issue: { target_class: "file" }, operator_guidance: { source: { host_id: 1, occurrence_id: 1, path: null }, checks: [], manual_check: "Inspect intended access" } } as unknown as IssueDetailResponse;
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><ResolutionWorkflow issueId={7} stage="intent" initialData={state} detail={detail} /></MemoryRouter></QueryClientProvider>);
    expect(screen.getByLabelText("Suggested next step")).toHaveTextContent("Identify the complete target path");
    expect(screen.getByRole("button", { name: "Review Boolean change" })).toBeEnabled();
    expect(screen.getByText(/Can enable broader access/)).toBeVisible();
    expect(screen.queryByRole("button", { name: /Copy command:.*restorecon/ })).not.toBeInTheDocument();
  });

  it("keeps hashes, policy conditions and nested provenance out of the default view but available on demand", async () => {
    const basis = { policy_identity: "sha256:policy-identity", execution_fingerprint: "sha256:execution-identity",
      evidence_digest: "sha256:evidence-identity", condition_ast: { operator: "and", operands: ["httpd_unified", "httpd_enable_cgi"] },
      provenance: [{ checkpoint_id: 4432, policy_identity: "sha256:checkpoint-policy" }], missing_path: null };
    const user = userEvent.setup();
    render(<TechnicalEvidenceDisclosure basis={basis} title="Technical evidence" />);
    expect(screen.getByRole("button", { name: "Technical evidence" })).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText(/sha256:/)).not.toBeInTheDocument();
    expect(screen.queryByText("httpd_unified")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Technical evidence" }));
    const raw = screen.getByRole("button", { name: "Copy Technical evidence" }).closest(".pf-v6-c-code-block")!;
    expect(raw).toHaveTextContent("sha256:evidence-identity");
    expect(raw).toHaveTextContent("sha256:execution-identity");
    expect(raw).toHaveTextContent("httpd_unified");
    expect(raw).toHaveTextContent("4432");
    expect(screen.queryByText("missing path")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Technical evidence" }));
    expect(screen.queryByText(/sha256:/)).not.toBeInTheDocument();
  });

  it("uses a selector with full path identities for more than three file resources", () => {
    const state = initial();
    state.candidates = ["first", "second", "third", "fourth"].map((name, index) => ({ ...candidate, id: name, kind: "restore_configured_label", scope_kind: "single_object", evidence_basis: { path: `/srv/long-directory/${name}`, occurrence_id: index + 11 } }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(state), { status: 200 })));
    render(<QueryClientProvider client={client}><MemoryRouter><ResolutionWorkflow issueId={7} stage="intent" initialData={state} /></MemoryRouter></QueryClientProvider>);
    const selector = screen.getByRole("combobox", { name: "Active investigation resource" });
    expect(within(selector).getAllByRole("option")).toHaveLength(4);
    expect(within(selector).getByRole("option", { name: "/srv/long-directory/third · web-1" })).toBeInTheDocument();
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
  });

  it("gates commands by durable intent, restores after remount, and clears through the API", async () => {
    let state = initial();
    const requests: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_path: string, options?: RequestInit) => {
      const method = options?.method ?? "GET";
      requests.push(method);
      if (method === "PATCH") { expect(JSON.parse(String(options?.body))).toEqual({ candidate_id: "boolean-path", evidence_version: "v1" }); state = selected(); }
      if (method === "DELETE") state = initial();
      return new Response(JSON.stringify(state), { status: 200, headers: { "Content-Type": "application/json" } });
    }));
    const user = userEvent.setup();
    const view = mount();
    await screen.findByRole("button", { name: "Review Boolean change" });
    expect(screen.getByRole("region", { name: "Observed access" })).toHaveTextContent("TCP/12345");
    expect(screen.getByText("Host-wide boolean · web-1")).toBeVisible();
    expect(screen.getByText(/Can enable broader access/)).toBeVisible();
    expect(screen.getByText(/Selection does not apply or verify a change/)).toBeVisible();
    expect(screen.queryByText("sudo setsebool httpd_can_network_connect on")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review Boolean change" }));
    expect(screen.getByText(candidate.intent_prompt)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Confirm intent" }));
    await screen.findByRole("region", { name: "Selected change plan" });
    expect(screen.getByRole("button", { name: "Copy command: sudo setsebool -P httpd_can_network_connect on" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rollback procedure" })).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("button", { name: "Copy command: sudo setsebool httpd_can_network_connect off" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Rollback procedure" }));
    screen.getAllByText("Runtime only").forEach((label) => expect(label).toBeVisible());
    expect(screen.getByText("Persistent · optional")).toBeVisible();
    screen.getAllByText("Changes host-wide Boolean").forEach((label) => expect(label).toBeVisible());
    const effect = screen.getAllByText("Changes host-wide Boolean")[0];
    const copy = screen.getByRole("button", { name: "Copy command: sudo setsebool httpd_can_network_connect on" });
    expect(effect.compareDocumentPosition(copy) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText(candidate.scope_description)).toBeVisible();
    expect(screen.getByText(candidate.scope_warning)).toBeVisible();
    expect(screen.getByRole("region", { name: "Selected change plan" })).toHaveTextContent("Persistent rollback state unknown");
    view.unmount();
    mount();
    await screen.findByRole("region", { name: "Selected change plan" });
    await user.click(screen.getByRole("button", { name: "Clear selected intent" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Selected change plan" })).not.toBeInTheDocument());
    expect(requests).toContain("DELETE");
  });

  it("withholds old commands and renders server freshness without deriving remediation", async () => {
    const state: Workflow = { ...selected(), freshness: "evidence_changed", change_plan: null };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(state), { status: 200 })));
    mount();
    await screen.findByText("Evidence changed");
    expect(screen.queryByRole("region", { name: "Selected change plan" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review updated option" })).toBeEnabled();
    expect(document.body.textContent).not.toContain("sudo setsebool");
  });

  it("shows a current-state rejection and does not allow unsupported intent selection", async () => {
    const state = { ...initial(), candidates: [{ ...candidate, evidence_basis: { ...candidate.evidence_basis, current_boolean: {current: true} }, status: "no_longer_supported" }] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(state), { status: 200 })));
    mount();
    await screen.findByText("Last observed Boolean: On");
    expect(screen.queryByRole("button", { name: "Review Boolean change" })).not.toBeInTheDocument();
    expect(screen.getByText("Last observed Boolean: On")).toBeVisible();
    await userEvent.setup().click(screen.getByRole("button", { name: "Evidence & limitations" }));
    expect(screen.getByText("Why is this shown?")).toBeVisible();
  });

  it("restores staged draft permissions across navigation and requires separate literal-rule intent", async () => {
    let draft: PolicyDraft = { id: 1, name: "Web review", organization_id: 1, operator: "admin", status: "draft",
      updated_at: "2026-10-01T11:00:00Z", entries: [], limitations: ["No exact-policy validation"], evidence_version: "d1" };
    vi.stubGlobal("fetch", vi.fn(async (path: string, options?: RequestInit) => {
      if (path.includes("/entries") && options?.method === "POST") {
        draft = { ...draft, evidence_version: "d2", entries: [{ id: 1, source_type: "httpd_t", target_type: "unreserved_port_t",
          object_class: "tcp_socket", permission: "name_connect", provenance: [{ issue_id: 1939 }],
          known_alternatives: [{ kind: "enable_boolean", title: candidate.title, status: "proposed" }] }] };
        return new Response(JSON.stringify(draft), { status: 200 });
      }
      return new Response(JSON.stringify(path.includes("policy-drafts") ? { drafts: [draft] } : initial()), { status: 200 });
    }));
    const user = userEvent.setup();
    const view = mount();
    await screen.findByRole("button", { name: "Review Boolean change" });
    await user.click(screen.getByRole("button", { name: "Open policy draft workspace" }));
    await user.click(await screen.findByRole("button", { name: "Add observed permission to Custom Policy Draft" }));
    await screen.findByText("Known alternatives at staging");
    expect(screen.getByText("httpd_t → unreserved_port_t:tcp_socket name_connect")).toBeVisible();
    view.unmount();
    mount();
    await screen.findByRole("button", { name: "Review Boolean change" });
    await user.click(screen.getByRole("button", { name: "Open policy draft workspace" }));
    await screen.findByText("httpd_t → unreserved_port_t:tcp_socket name_connect");
    await user.click(screen.getByText("Review proposed literal policy export"));
    expect(screen.getByRole("button", { name: "Export proposed .te" })).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: "I reviewed the alternatives and intend the literal type-wide permissions in this draft." }));
    expect(screen.getByRole("button", { name: "Export proposed .te" })).toBeEnabled();
    expect(screen.queryByRole("region", { name: "Selected change plan" })).not.toBeInTheDocument();
  });

  it("makes the selected option dominant and collapses informational alternatives", async () => {
    const other = { ...candidate, id: "other", evidence_basis: { boolean: "nis_enabled", current_boolean: { current: true } }, status: "no_longer_supported" as const };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ ...selected(), candidates: [candidate, other] }), { status: 200 })));
    const user = userEvent.setup();
    mount();
    await screen.findByText("Selected · current");
    expect(document.querySelectorAll(".resolution-selected")).toHaveLength(1);
    expect(screen.getByText("Last observed Boolean: On")).not.toBeVisible();
    await user.click(screen.getByRole("button", { name: /Alternative approaches · 1 · Host-wide Boolean/ }));
    expect(screen.getByText("Last observed Boolean: On")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Review Boolean change" })).not.toBeInTheDocument();
  });

  it("groups label choices by mechanism while preserving their resource-scoped confirmation", async () => {
    const file = (id: string, path: string) => ({ ...candidate, id, kind: "restore_configured_label" as const, scope_kind: "single_object" as const,
      evidence_basis: { path, observed_context: "u:object_r:user_home_t:s0", expected_context: "u:object_r:httpd_sys_content_t:s0" } });
    const state = { ...initial(), candidates: [file("a", "/var/www/a"), file("b", "/var/www/b")] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(state), { status: 200 })));
    const user = userEvent.setup();
    mount();
    await screen.findByRole("region", { name: "Restore configured SELinux labeling" });
    expect(screen.getAllByRole("tab")).toHaveLength(2);
    expect(document.querySelectorAll(".candidate-paths .resolution-candidate-card")).toHaveLength(1);
    await user.click(screen.getByRole("tab", { name: /\/var\/www\/b/ }));
    await user.click(screen.getByRole("button", { name: "Review label restoration" }));
    const confirmation = document.querySelector(".intent-confirmation")!;
    expect(confirmation.closest("article")).toHaveTextContent("/var/www/b");
    expect(screen.queryByText("sudo restorecon")).not.toBeInTheDocument();
  });

  it("puts inspection before file mutation and does not present unknown object state as verified", async () => {
    const state = selected();
    state.change_plan = { ...state.change_plan!, scope_kind: "single_object", rollback_steps: [], rollback_description: "Automatic rollback cannot be generated safely.",
      preview_steps: [ { title: "Inspect object", command: "stat -- /var/www/a", explanation: "Stop if missing", persistence: "inspection" },
        { title: "Preview labeling change", command: "sudo restorecon -n -v -- /var/www/a", explanation: "No change", persistence: "inspection" } ],
      apply_steps: [{ title: "Apply", command: "sudo restorecon -v -- /var/www/a", explanation: "Single object", persistence: "configured_label" }] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(state), { status: 200 })));
    const user = userEvent.setup();
    mount();
    await screen.findByRole("region", { name: "Selected change plan" });
    expect(screen.getByText("stat -- /var/www/a")).toBeVisible();
    expect(screen.getByText("sudo restorecon -v -- /var/www/a")).not.toBeVisible();
    await user.click(screen.getByText("Apply — only after successful inspection"));
    expect(screen.getByText(/Stop if the object is missing, replaced/)).toBeVisible();
    expect(screen.getByText("sudo restorecon -v -- /var/www/a")).toBeVisible();
    expect(document.body.textContent).not.toContain("chcon");
  });

  it("copies the exact server command without recording application", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(selected()), { status: 200 })));
    const user = userEvent.setup();
    const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    mount();
    await screen.findByRole("region", { name: "Selected change plan" });
    await user.click(screen.getByRole("button", { name: "Copy command: sudo setsebool httpd_can_network_connect on" }));
    expect(write).toHaveBeenCalledWith("sudo setsebool httpd_can_network_connect on");
    await waitFor(() => expect(screen.getByRole("tooltip")).toHaveTextContent("Copied"));
    expect(screen.getByText("Review current against retained evidence")).toBeVisible();
  });

  it("replaces a cached current plan immediately when the issue core supplies newer stale evidence", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const now = Date.now();
    client.setQueryData(["issue-resolutions", 1939], selected(), { updatedAt: now });
    const node = (data: Workflow, updatedAt: number) => <QueryClientProvider client={client}><MemoryRouter><ResolutionWorkflow issueId={1939} stage="intent" initialData={data} initialDataUpdatedAt={updatedAt} /></MemoryRouter></QueryClientProvider>;
    const view = render(node(selected(), now));
    expect(screen.getByRole("region", { name: "Selected change plan" })).toBeVisible();
    view.rerender(node({ ...selected(), freshness: "evidence_changed", change_plan: null }, now + 1000));
    expect(screen.getByRole("alert")).toHaveTextContent("Evidence changed");
    expect(screen.queryByRole("region", { name: "Selected change plan" })).not.toBeInTheDocument();
    expect(document.querySelectorAll(".command-block")).toHaveLength(0);
  });

  it("renders the server freshness reason instead of comparing policy or occurrence metadata", async () => {
    const state: Workflow = { ...selected(), freshness: "evidence_changed", change_plan: null,
      freshness_reasons: ["Plan-generation semantics changed since this plan was reviewed."],
      history: [{ action: "selected", operator: "admin", created_at: "2026-10-01T11:00:00Z",
        details: { candidate_id: candidate.id, evidence_version: "v1", evidence_basis: { issue_evidence_digest: "older-inventory" } } }] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(state), { status: 200 })));
    mount();
    expect(await screen.findByText(state.freshness_reasons![0])).toBeVisible();
    expect(screen.queryByText("Occurrence evidence inventory changed")).not.toBeInTheDocument();
    expect(document.querySelectorAll(".command-block")).toHaveLength(0);
  });

  it("keeps an already-On workload capability primary and an incidental matching path expandable and review-gated", async () => {
    const state: Workflow = { ...initial(), candidates: [
      { ...candidate, presentation: "primary", status: "no_longer_supported", latest_observed_at: "2026-10-17T12:00:00Z",
        unavailable_reason: "Latest retained state is On; check runtime and retry the intended workload.",
        evidence_basis: { ...candidate.evidence_basis, checkpoint_observed_at: "2026-10-01T10:00:00Z", current_boolean: { current: true } } },
      { ...candidate, id: "incidental", presentation: "technical_alternative", presentation_reason: "Matches through a source attribute.",
        evidence_basis: { boolean: "nis_enabled", current_boolean: { current: false } } }
    ] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(state), { status: 200 })));
    const user = userEvent.setup();
    mount();
    await screen.findByText(/Latest retained state is On/);
    expect(screen.getByText(/2026-10-17T12:00:00Z/)).not.toBeVisible();
    await user.click(screen.getAllByRole("button", { name: "Evidence & limitations" })[0]);
    expect(screen.getByText(/2026-10-17T12:00:00Z/)).toBeVisible();
    expect(screen.getByText(/2026-10-01T10:00:00Z/)).toBeVisible();
    expect(screen.getByText("Enable nis_enabled")).not.toBeVisible();
    expect(screen.queryByRole("button", { name: "Review Boolean change" })).not.toBeInTheDocument();
    const disclosure = screen.getByRole("button", { name: "Alternative policy approaches · 1 · Host-wide scope" });
    await user.click(disclosure);
    expect(screen.getByText("Enable nis_enabled")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Review Boolean change" }));
    expect(screen.getByRole("button", { name: "Confirm intent" })).toBeVisible();
    expect(document.body.textContent).not.toContain("setsebool");
  });

  it("places the investigation host/path first and explains stale scope separately from other examples", () => {
    const file = (id: string, host: number, path: string) => ({ ...candidate, id, kind: "restore_configured_label" as const,
      host_id: host, hostname: `host-${host}`, scope_kind: "single_object" as const, evidence_basis: { occurrence_id: host, path } });
    const primary = { ...file("selected-example", 2, "/srv/launch"), status: "evidence_changed" as const,
      unavailable_reason: "The host configuration observation is stale; refresh before review." };
    const state = { ...initial(), candidates: [file("other", 1, "/var/www/content"), primary, file("same-host-other-path", 2, "/srv/another")] };
    const detail = { operator_guidance: { source: { host_id: 2, occurrence_id: 2, path: "/srv/launch" }, checks: [], possible_fix: "Restoration does not establish execution permission." } } as unknown as IssueDetailResponse;
    const client = new QueryClient();
    render(<QueryClientProvider client={client}><MemoryRouter><ResolutionWorkflow issueId={7} stage="intent" initialData={state} initialDataUpdatedAt={Date.now()} detail={detail} /></MemoryRouter></QueryClientProvider>);
    expect(screen.getByRole("heading", { name: "/srv/launch" })).toBeVisible();
    expect(screen.getByText(primary.unavailable_reason)).toBeVisible();
    expect(screen.queryByText("/var/www/content", { selector: "h3" })).not.toBeInTheDocument();
    expect(screen.queryByText("/srv/another", { selector: "h3" })).not.toBeInTheDocument();
    expect(screen.getAllByRole("tab")).toHaveLength(3);
    const card = screen.getByRole("heading", { name: "/srv/launch" }).closest("article")!;
    expect(within(card).getByRole("link", { name: "Occurrence #2" })).toHaveAttribute("href", "/hosts/2/occurrences/2");
    expect(within(card).queryByRole("button", { name: "Review label restoration" })).not.toBeInTheDocument();
  });

  it("does not render an unavailable Boolean observation as a known On state", async () => {
    const state = { ...initial(), candidates: [{ ...candidate, status: "evidence_changed" as const,
      unavailable_reason: "The latest Boolean value is not observed; obtain runtime state before reviewing a change.",
      evidence_basis: { ...candidate.evidence_basis, current_boolean: { status: "unavailable", current: true } } }] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(state), { status: 200 })));
    mount();
    expect(await screen.findByText("Not verified (unavailable)")).toBeVisible();
    expect(screen.queryByText("Last observed Boolean: On")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Review Boolean change" })).not.toBeInTheDocument();
  });
});
