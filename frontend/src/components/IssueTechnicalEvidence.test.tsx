import { render, screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { IssueDetailResponse, OccurrenceDetail } from "../api/issue";
import { IssueTechnicalEvidence } from "./IssueTechnicalEvidence";

const identity = `sha256:${"a".repeat(64)}`;
const rule = "allow nsswitch_domain unreserved_port_t:tcp_socket name_bind; [ nis_enabled ]:True";
const detail = {
  issue: { id: 7, source_type: "httpd_t", fingerprint_version: 3, fingerprint_digest: "fingerprint", first_seen_at: "2026-10-01T10:00:00Z", last_seen_at: "2026-10-02T10:00:00Z" },
  diagnosis: { kind: "conditional_allow_inactive", title: "Historical finding", occurrence_id: 11, source_domain: "httpd_t", target_type: "unreserved_port_t", target_class: "tcp_socket", operation: "name_bind", bind_port: "12345", checkpoint_observed_at: "2026-10-01T09:00:00Z", policy_identity: identity,
    evaluations: [{ result: "matched", permissions: ["name_bind"], evaluator_version: "4.5.1", policy_identity: identity, matching_rules: [rule] }], conditional_rules: [{ rule, expression: "nis_enabled", state: "inactive" }] },
  host_explanations: [],
  resolutions: { candidates: [], rejected_candidates: [], intent: null, freshness: null, change_plan: null, observed_access: null, history: [] }
} as unknown as IssueDetailResponse;

function occurrence(id = 11): OccurrenceDetail {
  return { id, host: { id: id === 11 ? 1 : 2, hostname: id === 11 ? "web-1" : "web-2" }, occurred_at: "2026-10-01T10:00:00Z",
    normalized_denial: { status: "ok", source_type: "httpd_t", target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_bind"], target_paths: [], command: "httpd", details: { network_evidence: { bind_port_fields: [String(id === 11 ? 12345 : 23451)] } } },
    raw_event: { id: id + 100, audit_timestamp: "2026-10-01T10:00:00Z", audit_sequence: id, boot_id: `historical-boot-${id}`, category: "avc", transition_type: null, completion_reason: "eoe", evidence_digest: "event-digest", checkpoint_policy_identity: identity,
      checkpoint: { snapshot_id: id + 40, observed_at: "2026-10-01T09:00:00Z", kernel_release: "historical-kernel" },
      collection: { agent_installation_id: 6, schema_version: 2, agent_received_at: "2026-10-01T10:00:01Z", server_received_at: "2026-10-01T10:00:02Z" },
      audit_records: [{ position: 0, record_type: 1400, type_name: "AVC", audit_timestamp: "2026-10-01T10:00:00Z", sequence: id, payload: `type=AVC historical occurrence ${id}` }] }, guidance: null };
}

function Navigation() {
  const location = useLocation(); const navigate = useNavigate();
  return <><output aria-label="Evidence URL">{location.search}</output><button onClick={() => navigate(-1)}>Back</button></>;
}
function mount(entry = "/issues/7", payload = detail) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}><Navigation /><IssueTechnicalEvidence detail={payload} updatedAt={Date.now()} /></MemoryRouter></QueryClientProvider>);
}

describe("Issue technical evidence", () => {
  it("keeps policy evidence scoped, highlights source JSON, and hides low-value metadata", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(occurrence()), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    mount();
    const policy = screen.getByRole("tabpanel", { name: "Policy evaluation" });
    expect(policy).not.toHaveTextContent("4.5.1");
    expect(policy).toHaveTextContent(rule);
    expect(policy.querySelector(".issue-evidence-source")).toBeNull();
    expect(within(policy).getByRole("heading", { name: "Conditional policy evaluation · occurrence #11" })).toHaveClass("pf-v6-c-title");
    expect(within(policy).queryByText("No matching allow found")).not.toBeInTheDocument();
    expect(within(policy).queryByText("Evaluator version")).not.toBeInTheDocument();
    expect(within(policy).queryByText("Evaluated policy")).not.toBeInTheDocument();
    expect(within(policy).queryByText("Checkpoint policy")).not.toBeInTheDocument();
    expect(within(policy).queryByRole("button", { name: "Copy exact policy identity" })).not.toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
    await user.click(within(policy).getByRole("button", { name: "Evaluation source data" }));
    const jsonProperty = policy.querySelector(".json-token-property");
    expect(jsonProperty).not.toBeNull();
    expect(jsonProperty?.closest(".issue-evaluation-source-json")).not.toBeNull();
    expect(policy).toHaveTextContent(identity);
    expect(policy).toHaveTextContent("4.5.1");
    expect(jsonProperty?.closest(".issue-evaluation-source-json")).toHaveClass("issue-evaluation-source-json");
    await user.click(screen.getByRole("tab", { name: "Provenance" }));
    expect(screen.getByRole("tab", { name: "Provenance" })).toHaveAttribute("aria-selected", "true");
    const provenance = screen.getByRole("tabpanel", { name: "Provenance" });
    expect(provenance.querySelectorAll(".issue-evidence-source strong")).toHaveLength(1);
    expect(within(provenance).queryByRole("heading", { name: "Evaluation checkpoint" })).not.toBeInTheDocument();
    expect(provenance).not.toHaveTextContent("sha256:");
    expect(within(provenance).getAllByRole("link", { name: "Open occurrence" })).toHaveLength(1);
    expect(within(provenance).queryByText("historical-boot-11")).not.toBeInTheDocument();
    expect(within(provenance).queryByRole("heading", { name: "Issue grouping identity" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Evidence URL")).toHaveTextContent("evidence_tab=provenance");
    expect(fetchMock.mock.calls).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByRole("tab", { name: "Policy evaluation" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByText("historical-kernel")).not.toBeInTheDocument();
  });

  it("shows one readable occurrence summary and links to its full record", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(url).toBe("/api/v1/issues/7/occurrences/22");
      return new Response(JSON.stringify(occurrence(22)), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    mount("/issues/7?resource=other-resource&evidence=audit-evidence&evidence_tab=audit&evidence_occurrence=22");
    const record = await screen.findByRole("region", { name: "Selected occurrence evidence" });
    expect(screen.getByText(/web-2 · Occurrence #22/)).toBeVisible();
    expect(record).toHaveTextContent("TCP/23451");
    expect(screen.getAllByRole("heading", { name: "Audit record" })).toHaveLength(1);
    expect(within(record).getByRole("heading", { name: "Audit record" })).toHaveAttribute("class", expect.stringContaining("pf-v6-c-title"));
    expect(within(record).getByRole("region", { name: "Observed access" })).toHaveTextContent("httpd_t → name_bind → unreserved_port_t:tcp_socket");
    const eventAndProcess = within(record).getByRole("region", { name: "Event and process" });
    expect(eventAndProcess.querySelector("time")).toHaveAttribute("datetime", "2026-10-01T10:00:00Z");
    expect(eventAndProcess).toHaveTextContent("Oct 1, 10:00:00 UTC");
    expect(eventAndProcess.querySelector(".detail-facts")).toBeInTheDocument();
    const targetDetails = within(record).getByRole("region", { name: "Target details" });
    const syscallEvidence = within(record).getByRole("region", { name: "Syscall evidence" });
    expect(targetDetails).toHaveTextContent("TCP/23451");
    expect(syscallEvidence).toHaveTextContent("Not recorded");
    expect(eventAndProcess.closest(".pf-v6-l-grid__item")).not.toBe(targetDetails.closest(".pf-v6-l-grid__item"));
    expect(targetDetails.closest(".pf-v6-l-grid__item")).toBe(syscallEvidence.closest(".pf-v6-l-grid__item"));
    const occurrenceLink = screen.getAllByRole("link", { name: "Open occurrence" });
    expect(occurrenceLink).toHaveLength(1);
    expect(occurrenceLink[0]).toHaveAttribute("href", "/hosts/2/occurrences/22");
    expect(screen.queryByRole("link", { name: "Browse occurrences" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Raw audit records" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Other retained payload" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Normalized source data" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Socket, syscall & path fields" })).not.toBeInTheDocument();
    expect(screen.queryByText("type=AVC historical occurrence 22")).not.toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Provenance" }));
    expect(screen.queryByText("historical-kernel")).not.toBeInTheDocument();
    expect(screen.queryByText("historical-boot-22")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Evidence URL")).toHaveTextContent("evidence_occurrence=22");
    expect(screen.getByLabelText("Evidence URL")).toHaveTextContent("resource=other-resource");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([[0, false], [2, true]] as const)("shows omitted finding groups only when present (%s)", async (additionalGroups, isOmitted) => {
    const host = {
      host_id: 1,
      hostname: "web-1",
      occurrence_count: 2,
      unexplained_occurrence_count: 1,
      additional_diagnosis_group_count: additionalGroups,
      diagnosis_groups: [{
        status: "diagnosed",
        count: 1,
        diagnosis: detail.diagnosis,
        sample_occurrence_ids: [11],
        policy_identity_count: 2,
        policy_provenance: [{ policy_identity: identity, checkpoint_observed_at: "2026-10-01T09:00:00Z", occurrence_id: 11 }],
        additional_policy_identity_count: 0
      }]
    };
    const payload = { ...detail, host_explanations: [host] } as unknown as IssueDetailResponse;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(occurrence()), { status: 200 })));
    mount("/issues/7?evidence_tab=provenance&evidence=artifact-provenance", payload);

    const title = await screen.findByRole("heading", { name: "web-1 · finding groups" });
    const card = title.closest(".pf-v6-c-card") as HTMLElement;
    expect(within(card).getByText(/2 occurrences · 1 unconfirmed/)).toBeVisible();
    expect(within(card).queryByText(/up to five|three example events/i)).not.toBeInTheDocument();
    expect(within(card).getByText("Policy evaluation varied across these occurrences.")).toBeVisible();
    const examples = within(card).getByRole("list", { name: "Example occurrences" });
    expect(within(examples).getByRole("link", { name: "Occurrence #11" })).toHaveAttribute("href", expect.stringContaining("evidence_occurrence=11"));
    expect(within(card).queryByText("Example occurrence")).not.toBeInTheDocument();
    expect(within(card).queryByText("Checkpoint")).not.toBeInTheDocument();
    expect(card).not.toHaveTextContent("sha256:");
    if (isOmitted) expect(within(card).getByText(/2 additional finding groups not shown/)).toBeVisible();
    else expect(within(card).queryByText(/additional finding groups not shown/)).not.toBeInTheDocument();
  });

  it.each(["invalid", "0", "-1", "1.5"])("rejects invalid occurrence %s without substituting the primary example", (id) => {
    const fetchMock = vi.fn(); vi.stubGlobal("fetch", fetchMock);
    mount(`/issues/7?evidence=audit-evidence&evidence_tab=audit&evidence_occurrence=${id}`);
    expect(screen.getByRole("heading", { name: /Invalid evidence occurrence/ })).toBeVisible();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.queryByRole("region", { name: "Selected occurrence evidence" })).not.toBeInTheDocument();
  });

  it("reports unavailable record evidence without fallback to another host or occurrence", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ error: { message: "Record unavailable" } }), { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);
    mount("/issues/7?evidence=audit-evidence&evidence_tab=audit&evidence_occurrence=999");
    expect(await screen.findByRole("heading", { name: /Could not load occurrence evidence/ })).toBeVisible();
    expect(screen.queryByRole("region", { name: "Selected occurrence evidence" })).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("keeps occurrence checkpoint metadata on the occurrence page rather than Provenance", async () => {
    const legacy = occurrence(); delete legacy.raw_event.checkpoint; delete legacy.raw_event.collection;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(legacy), { status: 200 })));
    mount("/issues/7?evidence=artifact-provenance&evidence_tab=provenance");
    await waitFor(() => expect(screen.getByRole("tabpanel", { name: "Provenance" })).toHaveTextContent("Occurrence #11"));
    expect(screen.queryByText("historical-kernel")).not.toBeInTheDocument();
    expect(screen.queryByText("Snapshot ID")).not.toBeInTheDocument();
  });

  it("preserves option evidence and its source occurrence across tabs without selecting durable intent", async () => {
    const payload = { ...detail, resolutions: { ...detail.resolutions!, candidates: [
      { id: "a", title: "Port option A", hostname: "web-1", evidence_basis: { host_id: 1, occurrence_id: 11 } },
      { id: "b", title: "Port option B", hostname: "web-2", evidence_basis: { host_id: 2, occurrence_id: 22 } }
    ] } } as unknown as IssueDetailResponse;
    const fetchMock = vi.fn(async (url: string, options?: RequestInit) => {
      expect(url).toBe("/api/v1/issues/7/occurrences/22");
      expect(options?.method ?? "GET").toBe("GET");
      return new Response(JSON.stringify(occurrence(22)), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    mount("/issues/7", payload);
    await user.selectOptions(screen.getByRole("combobox", { name: "Option evidence" }), "b");
    expect(screen.getByLabelText("Evidence URL")).toHaveTextContent("evidence_option=b");
    await user.click(screen.getByRole("tab", { name: "Provenance" }));
    expect(await screen.findByText(/web-2 · Occurrence #22/)).toBeVisible();
    expect(screen.queryByText("historical-boot-22")).not.toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Policy evaluation" }));
    expect(screen.getByRole("combobox", { name: "Option evidence" })).toHaveValue("b");
    expect(payload.resolutions!.intent).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
