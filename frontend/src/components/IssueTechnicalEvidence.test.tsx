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
  it("shows curated policy facts without loading audit data, then follows an artifact into provenance with browser history", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(occurrence()), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    mount();
    expect(screen.getByRole("tabpanel", { name: "Policy evaluation" })).toHaveTextContent("4.5.1");
    expect(screen.getByText(rule)).toBeVisible();
    expect(fetchMock).not.toHaveBeenCalled();
    await user.click(screen.getAllByRole("link", { name: /Policy artifact/ })[0]);
    expect(screen.getByRole("tab", { name: "Provenance" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("historical-kernel")).toBeVisible();
    expect(screen.getByText("historical-boot-11")).toBeVisible();
    expect(screen.getByLabelText("Evidence URL")).toHaveTextContent("evidence_tab=provenance");
    expect(fetchMock.mock.calls).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByRole("tab", { name: "Policy evaluation" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByText("historical-kernel")).not.toBeInTheDocument();
  });

  it("restores the explicitly selected occurrence on another host and copies exact raw audit data only on request", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(url).toBe("/api/v1/issues/7/occurrences/22");
      return new Response(JSON.stringify(occurrence(22)), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    mount("/issues/7?resource=other-resource&evidence=audit-evidence&evidence_tab=audit&evidence_occurrence=22");
    const record = await screen.findByRole("region", { name: "Selected occurrence evidence" });
    expect(record).toHaveTextContent("web-2");
    expect(record).toHaveTextContent("TCP/23451");
    expect(screen.queryByText("type=AVC historical occurrence 22")).not.toBeInTheDocument();
    await user.click(within(record).getByRole("button", { name: "Raw AVC" }));
    await user.click(within(record).getByRole("button", { name: "Copy raw AVC record 0 for occurrence 22" }));
    expect(await navigator.clipboard.readText()).toBe("type=AVC historical occurrence 22");
    await user.click(screen.getByRole("tab", { name: "Provenance" }));
    expect(await screen.findByText("historical-boot-22")).toBeVisible();
    expect(screen.getByLabelText("Evidence URL")).toHaveTextContent("evidence_occurrence=22");
    expect(screen.getByLabelText("Evidence URL")).toHaveTextContent("resource=other-resource");
    expect(fetchMock).toHaveBeenCalledTimes(1);
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

  it("keeps missing historical metadata explicit for older occurrence responses", async () => {
    const legacy = occurrence(); delete legacy.raw_event.checkpoint; delete legacy.raw_event.collection;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(legacy), { status: 200 })));
    mount("/issues/7?evidence=artifact-provenance&evidence_tab=provenance");
    await waitFor(() => expect(screen.getByRole("tabpanel", { name: "Provenance" })).toHaveTextContent("historical-boot-11"));
    expect(screen.queryByText("historical-kernel")).not.toBeInTheDocument();
    expect(screen.getByText("Snapshot ID").closest(".pf-v6-c-description-list__group")).toHaveTextContent("Not recorded");
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
    expect(await screen.findByText("historical-boot-22")).toBeVisible();
    await user.click(screen.getByRole("tab", { name: "Policy evaluation" }));
    expect(screen.getByRole("combobox", { name: "Option evidence" })).toHaveValue("b");
    expect(payload.resolutions!.intent).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
