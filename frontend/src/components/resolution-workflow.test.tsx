import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";
import type { PolicyDraft, ResolutionWorkflow as Workflow } from "../api/resolution";
import { ResolutionWorkflow } from "./ResolutionWorkflow";
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
  return render(<QueryClientProvider client={client}><MemoryRouter><ResolutionWorkflow issueId={1939} stage="observed" /><ResolutionWorkflow issueId={1939} stage="intent" /></MemoryRouter></QueryClientProvider>);
}

describe("Evidence-driven resolution UI", () => {
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
    expect(screen.getByText("sha256:evidence-identity")).toBeVisible();
    expect(screen.getByText("sha256:execution-identity")).toBeVisible();
    expect(screen.getByText("httpd_unified")).toBeVisible();
    expect(screen.getByText("4432")).toBeVisible();
    expect(screen.queryByText("missing path")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Technical evidence" }));
    expect(screen.queryByText(/sha256:/)).not.toBeInTheDocument();
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
    await screen.findByRole("button", { name: "Choose intent" });
    expect(screen.getByRole("region", { name: "Observed access" })).toHaveTextContent("TCP/12345");
    expect(screen.getByText("Host-wide boolean")).toBeVisible();
    expect(screen.getByText(/Can enable broader access/)).toBeVisible();
    expect(screen.getByText(/Review this option to see copyable inspection and change commands/)).toBeVisible();
    expect(screen.queryByText("sudo setsebool httpd_can_network_connect on")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Choose intent" }));
    expect(screen.getByText(candidate.intent_prompt)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Confirm intent" }));
    await screen.findByRole("region", { name: "Selected change plan" });
    expect(screen.getByRole("button", { name: "Copy sudo setsebool -P httpd_can_network_connect on" })).toBeInTheDocument();
    screen.getAllByText("Runtime only").forEach((label) => expect(label).toBeVisible());
    expect(screen.getByText("Persistent · optional")).toBeVisible();
    screen.getAllByText("Changes host-wide Boolean").forEach((label) => expect(label).toBeVisible());
    const effect = screen.getAllByText("Changes host-wide Boolean")[0];
    const copy = screen.getByRole("button", { name: "Copy sudo setsebool httpd_can_network_connect on" });
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
    await screen.findByText("Latest observation recorded this capability On.");
    expect(screen.queryByRole("button", { name: "Choose intent" })).not.toBeInTheDocument();
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
    await screen.findByRole("button", { name: "Choose intent" });
    await user.click(screen.getByText("Intent history & policy draft"));
    await user.click(screen.getByRole("button", { name: "Open policy draft workspace" }));
    await user.click(await screen.findByRole("button", { name: "Add observed permission to Custom Policy Draft" }));
    await screen.findByText("Known alternatives at staging");
    expect(screen.getByText("httpd_t → unreserved_port_t:tcp_socket name_connect")).toBeVisible();
    view.unmount();
    mount();
    await screen.findByRole("button", { name: "Choose intent" });
    await user.click(screen.getByText("Intent history & policy draft"));
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
    expect(screen.getByText("Latest observation recorded this capability On.")).not.toBeVisible();
    await user.click(screen.getByText("Other options · 1"));
    expect(screen.getByText("Latest observation recorded this capability On.")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Choose intent" })).not.toBeInTheDocument();
  });

  it("groups label choices by mechanism while preserving their resource-scoped confirmation", async () => {
    const file = (id: string, path: string) => ({ ...candidate, id, kind: "restore_configured_label" as const, scope_kind: "single_object" as const,
      evidence_basis: { path, observed_context: "u:object_r:user_home_t:s0", expected_context: "u:object_r:httpd_sys_content_t:s0" } });
    const state = { ...initial(), candidates: [file("a", "/var/www/a"), file("b", "/var/www/b")] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(state), { status: 200 })));
    const user = userEvent.setup();
    mount();
    await screen.findByRole("region", { name: "Restore configured SELinux labeling" });
    expect(screen.getByText("2 host/path candidates")).toBeVisible();
    expect(document.querySelectorAll(".candidate-paths .resolution-candidate-card")).toHaveLength(2);
    await user.click(screen.getAllByRole("button", { name: "Choose this path" })[1]);
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
    expect(screen.getByText(/Current object has not been verified/)).toBeVisible();
    expect(screen.getByText("sudo restorecon -v -- /var/www/a")).toBeVisible();
    expect(document.body.textContent).not.toContain("chcon");
  });

  it("copies the exact server command without recording application", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(selected()), { status: 200 })));
    const user = userEvent.setup();
    const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
    mount();
    await screen.findByRole("region", { name: "Selected change plan" });
    await user.click(screen.getByRole("button", { name: "Copy sudo setsebool httpd_can_network_connect on" }));
    expect(write).toHaveBeenCalledWith("sudo setsebool httpd_can_network_connect on");
    expect(await screen.findByText("Copied")).toBeVisible();
    expect(screen.getByText("Reviewed · current")).toBeVisible();
  });

  it("replaces a cached current plan immediately when the issue core supplies newer stale evidence", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const now = Date.now();
    client.setQueryData(["issue-resolutions", 1939], selected(), { updatedAt: now });
    const node = (data: Workflow, updatedAt: number) => <QueryClientProvider client={client}><ResolutionWorkflow issueId={1939} stage="intent" initialData={data} initialDataUpdatedAt={updatedAt} /></QueryClientProvider>;
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
    expect(screen.getByText("2026-10-17T12:00:00Z")).toBeVisible();
    expect(screen.getByText(/2026-10-01T10:00:00Z/)).toBeVisible();
    expect(screen.getByText("Enable nis_enabled")).not.toBeVisible();
    expect(screen.getByRole("button", { name: "Choose intent" })).not.toBeVisible();
    const disclosure = screen.getByText("Technical policy alternatives · 1");
    await user.click(disclosure);
    expect(screen.getByText("Enable nis_enabled")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Choose intent" }));
    expect(screen.getByRole("button", { name: "Confirm intent" })).toBeVisible();
    expect(document.body.textContent).not.toContain("setsebool");
  });

  it("places the investigation host/path first and explains stale scope separately from other examples", () => {
    const file = (id: string, host: number, path: string) => ({ ...candidate, id, kind: "restore_configured_label" as const,
      host_id: host, hostname: `host-${host}`, scope_kind: "single_object" as const, evidence_basis: { occurrence_id: host, path } });
    const primary = { ...file("selected-example", 2, "/srv/launch"), status: "evidence_changed" as const,
      unavailable_reason: "The host configuration observation is stale; refresh before review." };
    const state = { ...initial(), candidates: [file("other", 1, "/var/www/content"), primary, file("same-host-other-path", 2, "/srv/another")] };
    const detail = { operator_guidance: { source: { host_id: 2, occurrence_id: 2, path: "/srv/launch" }, possible_fix: "Restoration does not establish execution permission." } } as IssueDetailResponse;
    const client = new QueryClient();
    render(<QueryClientProvider client={client}><MemoryRouter><ResolutionWorkflow issueId={7} stage="intent" initialData={state} initialDataUpdatedAt={Date.now()} detail={detail} /></MemoryRouter></QueryClientProvider>);
    expect(screen.getByText("/srv/launch")).toBeVisible();
    expect(screen.getByText(primary.unavailable_reason)).toBeVisible();
    expect(screen.getByText("/var/www/content")).not.toBeVisible();
    expect(screen.getByText("/srv/another")).not.toBeVisible();
    expect(screen.getByText("Other host/resource examples · 2")).toBeVisible();
    const card = screen.getByText("/srv/launch").closest("article")!;
    expect(within(card).getByRole("link", { name: "Occurrence #2" })).toHaveAttribute("href", "/hosts/2/occurrences/2");
    expect(within(card).queryByRole("button", { name: "Choose this path" })).not.toBeInTheDocument();
  });

  it("does not render an unavailable Boolean observation as a known On state", async () => {
    const state = { ...initial(), candidates: [{ ...candidate, status: "evidence_changed" as const,
      unavailable_reason: "The latest Boolean value is not observed; obtain runtime state before reviewing a change.",
      evidence_basis: { ...candidate.evidence_basis, current_boolean: { status: "unavailable", current: true } } }] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(state), { status: 200 })));
    mount();
    expect(await screen.findByText("Not verified (unavailable)")).toBeVisible();
    expect(screen.queryByText("Latest observation recorded this capability On.")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Choose intent" })).not.toBeInTheDocument();
  });
});
