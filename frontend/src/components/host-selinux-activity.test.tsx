import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { MemoryRouter, useSearchParams } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { fetchHostSelinuxActivity, type SelinuxActivityItem, type SelinuxActivityResponse, type SelinuxCheckpoint } from "../api/hosts";
import { HostSelinuxActivity } from "./HostSelinuxActivity";

const COVERAGE = "Supported SELinux changes observed in this server's audit stream. Absence of an event does not prove that no change occurred.";
const RAW = '<script>alert("audit")</script> bool=httpd_can_network_connect val=0 old_val=1';

function checkpoint(value: boolean): SelinuxCheckpoint {
  return { id: value ? 1172 : 1177, host_id: 10, boot_id: "boot-1", event_time: "2026-10-01T14:58:21.043Z",
    evidence_class: "observed_checkpoint", policy_identity: `sha256:${(value ? "a" : "b").repeat(64)}`, enforcement: "enforcing",
    booleans: [{ name: "httpd_can_network_connect", value }] };
}

function item(overrides: Partial<SelinuxActivityItem> = {}): SelinuxActivityItem {
  return { id: 26710, host_id: 10, boot_id: "boot-1", event_time: "2026-10-01T14:58:17.569Z",
    evidence_class: "observed_transition", transition_type: "boolean_change", boundary_established: true,
    audit_sequence: 51127, boolean_changes: [{ name: "httpd_can_network_connect", old_value: true, new_value: false, state_change_established: true }],
    actor: { login_uid: 0, execution_uid: 0, pid: 1402, context: "system_u:system_r:sysadm_t:s0", session: 535, executable: "/usr/sbin/setsebool", command: "setsebool", proctitle: "setsebool httpd_can_network_connect off" },
    previous_checkpoint: { ...checkpoint(true), event_time: "2026-10-01T14:57:56.428Z" },
    reconciliation: { status: "pending", checkpoint: null, next_transition: null }, window_avc_count: 0, ...overrides };
}

function response(items: SelinuxActivityItem[], cursor: string | null = null): SelinuxActivityResponse {
  return { items, coverage: COVERAGE, meta: { page_size: 20, next_cursor: cursor, total: items.length } };
}

function TestPage() {
  const [params] = useSearchParams();
  const before = params.get("activity_before") ?? undefined;
  const selected = Number(params.get("selinux_activity")) || undefined;
  const page = Number(params.get("activity_page") ?? 1);
  const activity = useQuery({ queryKey: ["host-selinux-activity", 10, before, selected, page],
    queryFn: () => fetchHostSelinuxActivity(10, { before, eventId: selected, page: before || selected ? undefined : page }) });
  return <HostSelinuxActivity activity={activity} />;
}

function renderActivity(first: SelinuxActivityResponse, older = response([]), entry = "/hosts/10") {
  const fetchMock = vi.fn((url: string) => {
    const selected = first.items[0] ?? item();
    let body: unknown = /\/selinux-activity\/\d+$/.test(url) ? { item: { ...selected,
      actor: selected.actor,
      evidence: { completion_reason: "eoe", digest: "test-digest", records: [{ position: 0, record_type: 1405,
        type_name: "MAC_CONFIG_CHANGE", audit_timestamp: selected.event_time, sequence: selected.audit_sequence, payload: RAW }] },
      window_occurrences: selected.window_avc_count ? [{ id: 26691, issue_id: 1939, event_time: "2026-10-01T14:58:17.616Z" }] : []
    } } : url.includes("before=") ? older : first;
    const params = new URL(url, "http://localhost").searchParams;
    if (params.has("page")) {
      const page = Number(params.get("page"));
      const items = [...first.items, ...older.items];
      body = { ...first, items: items.slice((page - 1) * 10, page * 10), meta: { page, page_size: 10, total: items.length, total_pages: Math.ceil(items.length / 10), next_cursor: null } };
    }
    return Promise.resolve({ ok: true, status: 200, headers: new Headers(), json: async () => body } as Response);
  });
  vi.stubGlobal("fetch", fetchMock);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}>
    <TestPage />
  </MemoryRouter></QueryClientProvider>);
  return { ...view, fetchMock };
}

async function openAudit() {
  await userEvent.setup().click(await screen.findByRole("button", { name: "View Audit" }));
}

describe("Monitored-server SELinux activity", () => {
  it("labels a later incomplete observation without claiming state reconciliation", async () => {
    renderActivity(response([item({ reconciliation: { status: "pending", checkpoint: { ...checkpoint(false), booleans: [{ name: "httpd_can_network_connect", value: null }] }, next_transition: null } })]));
    await openAudit();
    expect(screen.getByText("Later incomplete checkpoint")).toBeVisible();
    expect(screen.queryByText("SELinux state confirmed")).not.toBeInTheDocument();
    expect(screen.getByText(/State awaiting reconciliation/)).toBeVisible();
  });
  it.each(["add", "modify", "delete"] as const)("renders a validated %s port write without inventing old/delete type", async (operation) => {
    renderActivity(response([item({ transition_type: "port_change", boolean_changes: [],
      port_changes: [{ operation, protocol: "tcp", start: 23451, end: 23451, target_context: operation === "delete" ? null : "system_u:object_r:http_port_t:s0",
        selinux_type: operation === "delete" ? null : "http_port_t", success: true, boundary_established: true }] })]));
    expect(await screen.findByText(new RegExp(`TCP/23451 · ${operation}`))).toBeVisible();
    await openAudit();
    expect(screen.getByText(/USER_MAC_CONFIG_CHANGE/)).toBeVisible();
    await userEvent.setup().click(screen.getByRole("button", { name: "Technical Provenance & Hashes" }));
    expect(screen.getByText(/no port delta is reconstructed/)).toBeVisible();
    expect(screen.queryByText(/unreserved_port_t/)).not.toBeInTheDocument();
  });
  it.each([["enforcing", "permissive", "Enforcing → Permissive"], ["permissive", "enforcing", "Permissive → Enforcing"]] as const)("renders a scoped %s -> %s transition", async (old_mode, new_mode, label) => {
    renderActivity(response([item({ transition_type: "enforcement_change", boolean_changes: [],
      enforcement_changes: [{ old_mode, new_mode, state_change_established: true }] })]));
    expect(await screen.findByText(label)).toBeVisible();
    await openAudit();
    expect(screen.getByText("Enforcement changed")).toBeVisible();
    expect(screen.getByText("Runtime host enforcement mode")).toBeVisible();
    expect(screen.getByText(/MAC_STATUS/)).toBeVisible();
    await userEvent.setup().click(screen.getByRole("button", { name: "Technical Provenance & Hashes" }));
    expect(screen.getByText(/Exact policy identity and boolean evidence remain valid/)).toBeVisible();
    expect(screen.queryByRole("switch")).not.toBeInTheDocument();
  });

  it("retains unvalidated MAC_STATUS history without inventing a mode delta", async () => {
    renderActivity(response([item({ transition_type: "enforcement_change", boolean_changes: [], enforcement_changes: [],
      boundary_established: false, evidence_class: "administrative_history" })]));
    expect(await screen.findByText("Enforcement status reported · state change not established")).toBeVisible();
    await openAudit();
    expect(screen.getByText(/this event did not invalidate the checkpoint/)).toBeVisible();
    expect(screen.queryByText("Enforcement changed")).not.toBeInTheDocument();
  });
  it.each([[true, false, "On → Off"], [false, true, "Off → On"]] as const)("renders %s -> %s as a boundary awaiting reconciliation", async (old_value, new_value, label) => {
    renderActivity(response([item({ boolean_changes: [{ name: "httpd_can_network_connect", old_value, new_value, state_change_established: true }] })]));
    await openAudit();
    expect((await screen.findAllByText(label, { exact: false })).length).toBeGreaterThan(0);
    expect(screen.getByText("Boolean changed")).toBeVisible();
    expect(screen.getByText(/State awaiting reconciliation/)).toBeVisible();
    expect(screen.getAllByText("httpd_can_network_connect").length).toBeGreaterThan(0);
    expect(screen.queryByRole("switch")).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /enable|disable|remediate|apply/i })).not.toBeInTheDocument();
  });

  it("shows a policy load without inventing a resulting SHA from the load record", async () => {
    renderActivity(response([item({ transition_type: "policy_load", boolean_changes: [] })]));
    await openAudit();
    expect(screen.getAllByText("SELinux policy loaded").length).toBeGreaterThan(0);
    await userEvent.setup().click(screen.getByRole("button", { name: "Technical Provenance & Hashes" }));
    expect(screen.getByText(/The load record does not identify the new policy SHA/)).toBeVisible();
    expect(screen.queryByText("SELinux state confirmed")).not.toBeInTheDocument();
  });

  it("shows the separately observed refreshed checkpoint and discloses its exact provenance", async () => {
    const { fetchMock } = renderActivity(response([item({ reconciliation: { status: "reconciled", checkpoint: checkpoint(false), next_transition: null } })]));
    await openAudit();
    expect(await screen.findByText("SELinux state confirmed")).toBeVisible();
    expect(screen.queryByText(`sha256:${"b".repeat(64)}`)).not.toBeInTheDocument();
    expect(screen.getByText(/: Off ·/)).toBeVisible();
    expect(screen.getByText("Observed at host checkpoint")).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    await userEvent.setup().click(screen.getByRole("button", { name: "Technical Provenance & Hashes" }));
    expect(screen.getByText(`sha256:${"b".repeat(64)}`)).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("preserves retained checkpoint completion precision in the visible timestamp", async () => {
    renderActivity(response([item({ reconciliation: { status: "reconciled", checkpoint: { ...checkpoint(false), event_time: "2026-10-01T14:58:21.043831Z" }, next_transition: null } })]));
    await openAudit();
    expect(await screen.findByText("2026-10-01 14:58:21.043831 UTC")).toBeVisible();
  });

  it("keeps a checkpoint boolean unknown rather than copying the change record's new value", async () => {
    renderActivity(response([item({ reconciliation: { status: "reconciled", checkpoint: { ...checkpoint(false),
      booleans: [{ name: "httpd_can_network_connect", value: null }] }, next_transition: null } })]));
    await openAudit();
    expect(await screen.findByText(/: Unknown ·/)).toBeVisible();
    expect(screen.getAllByText(/On → Off/).length).toBeGreaterThan(0);
  });

  it("links interval denials on disclosure without claiming causation", async () => {
    const { fetchMock } = renderActivity(response([item({ window_avc_count: 2, reconciliation: { status: "reconciled", checkpoint: checkpoint(false), next_transition: null } })]));
    expect(screen.queryByRole("link", { name: "Occurrence #26691" })).not.toBeInTheDocument();
    await openAudit();
    expect(await screen.findByText("2 AVCs in the unresolved interval.")).toBeVisible();
    expect(await screen.findByRole("link", { name: "Occurrence #26691" })).toHaveAttribute("href", "/hosts/10/occurrences/26691");
    expect(screen.getByRole("link", { name: "Issue #1939" })).toHaveAttribute("href", "/issues/1939");
    expect(screen.getByText(/This relationship does not establish causation/)).toBeVisible();
    expect(screen.getByText(/Showing the 1 most recent retained interval occurrences of 2/)).toBeVisible();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/selinux-activity/26710", expect.anything());
  });

  it("groups multiple boolean records under one activity identity", async () => {
    renderActivity(response([item({ boolean_changes: [item().boolean_changes[0],
      { name: "httpd_can_network_relay", old_value: false, new_value: true, state_change_established: true }] })]));
    await openAudit();
    expect(await screen.findByText("SELinux booleans changed")).toBeVisible();
    expect(screen.getAllByText("httpd_can_network_relay").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Off → On/).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("row", { name: "SELinux activity 26710" })).toHaveLength(1);
  });

  it("keeps non-boundary history distinct from a successful change", async () => {
    renderActivity(response([item({ boundary_established: false, evidence_class: "administrative_history",
      boolean_changes: [{ ...item().boolean_changes[0], state_change_established: false }],
      reconciliation: { status: "not_applicable", checkpoint: null, next_transition: null } })]));
    await openAudit();
    expect(await screen.findByText("Boolean change reported")).toBeVisible();
    expect(screen.getAllByText(/Reported: On → Off · state change not established/).length).toBeGreaterThan(0);
    expect(screen.getByText(/this event did not invalidate the checkpoint/)).toBeVisible();
    expect(screen.queryByText("Boolean changed")).not.toBeInTheDocument();
    expect(screen.queryByText(/State awaiting reconciliation/)).not.toBeInTheDocument();
  });

  it("shows coverage even on an empty activity view, without synthetic change rows", async () => {
    renderActivity(response([]));
    expect(await screen.findByText("No administrative SELinux policy modifications retained for this server.")).toBeVisible();
    expect(screen.queryByText(COVERAGE)).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "SELinux Administrative Activity (0)" })).toBeVisible();
    screen.getByRole("button", { name: "About SELinux administrative activity" }).focus();
    expect(await screen.findByRole("tooltip")).toHaveTextContent(COVERAGE);
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
  });

  it("does not render an unsuccessful policy-load report as a successful load", async () => {
    renderActivity(response([item({ transition_type: "policy_load", boolean_changes: [], boundary_established: false,
      evidence_class: "administrative_history", reconciliation: { status: "not_applicable", checkpoint: null, next_transition: null } })]));
    await openAudit();
    expect(screen.getAllByText("Policy load reported").length).toBeGreaterThan(0);
    expect(screen.getByText(/State change not established/)).toBeVisible();
    expect(screen.queryByText("SELinux policy loaded")).not.toBeInTheDocument();
  });

  it("loads raw records only after View Audit and renders them as escaped data", async () => {
    const { container, fetchMock } = renderActivity(response([item()]));
    const row = await screen.findByRole("row", { name: "SELinux activity 26710" });
    expect(screen.getByRole("table", { name: "SELinux administrative activity" })).toBeVisible();
    expect(within(row).getByText("Oct 1, 14:58 UTC")).toBeVisible();
    expect(screen.queryByText(/State awaiting reconciliation/)).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(within(row).getByText(/UID 0/)).toBeVisible();
    expect(screen.queryByText("Not loaded")).not.toBeInTheDocument();
    expect(screen.queryByText(RAW)).not.toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(within(row).getByRole("button", { name: "View Audit" }));
    expect(await screen.findByText("/usr/sbin/setsebool")).toBeVisible();
    expect(screen.getByText("UID 0 (root) / PID 1402")).toBeVisible();
    expect(screen.getByText("Temporary (runtime)")).toBeVisible();
    expect(screen.queryByText("Checkpoint provenance")).not.toBeInTheDocument();
    expect(screen.queryByText(/Completion: eoe/)).not.toBeInTheDocument();
    expect(screen.queryByText("test-digest")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Technical Provenance & Hashes" }));
    expect(screen.getByText("test-digest")).toBeVisible();
    expect(screen.getByText("Earlier historical checkpoint")).toBeVisible();
    expect(screen.getByText(/Command fields provide context, not the authority/)).toBeVisible();
    expect(await screen.findByText(RAW)).toBeVisible();
    expect(within(row).getByText(/UID 0/)).toBeVisible();
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByRole("button", { name: "Copy SELinux activity 26710 audit records" })).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    await user.click(within(row).getByRole("button", { name: "Hide Audit" }));
    expect(screen.queryByText(RAW)).not.toBeInTheDocument();
  });

  it("replaces a bounded activity page instead of accumulating unbounded rows", async () => {
    const first = response(Array.from({ length: 20 }, (_, index) => item({ id: 100 + index })), "older-cursor");
    const { fetchMock } = renderActivity(first, response([item({ id: 80 })]));
    await screen.findByRole("row", { name: "SELinux activity 100" });
    expect(screen.getAllByRole("button", { name: "View Audit" })).toHaveLength(10);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Go to last page" }));
    expect(await screen.findByRole("row", { name: "SELinux activity 80" })).toBeVisible();
    expect(screen.getAllByRole("button", { name: "View Audit" })).toHaveLength(1);
    expect(screen.queryByRole("row", { name: "SELinux activity 100" })).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/selinux-activity?page=3", expect.anything());
    await user.click(screen.getByRole("button", { name: "Go to first page" }));
    expect(await screen.findByRole("row", { name: "SELinux activity 100" })).toBeVisible();
  });

  it("selects older activity through a stable cross-navigation address", async () => {
    const { fetchMock } = renderActivity(response([item({ id: 80 })]), response([]), "/hosts/10?selinux_activity=80");
    expect(await screen.findByText("/usr/sbin/setsebool")).toBeVisible();
    expect(screen.getByRole("button", { name: "Show recent SELinux activity" })).toBeVisible();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/hosts/10/selinux-activity?event_id=80", expect.anything());
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  });

  it("shows requested persistent scope without presenting the command as proof of a saved change", async () => {
    renderActivity(response([item({ actor: { ...item().actor!, proctitle: "setsebool -P httpd_can_network_connect off" } })]));
    await openAudit();
    expect(screen.getByText("Persistent (command request)")).toBeVisible();
    expect(screen.getByText("System Context")).toBeVisible();
  });

  it("shows genuinely unknown actors without fetching every event's raw evidence", async () => {
    const { fetchMock } = renderActivity(response([item({ actor: { login_uid: null, session: null, executable: null, command: null, proctitle: null } })]));
    expect(await screen.findByText("Unknown user")).toBeVisible();
    expect(screen.queryByText("Not loaded")).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("changes disclosure chevrons with state and copies the complete audit text with failure feedback", async () => {
    const { container } = renderActivity(response([item()]));
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText");
    const toggle = await screen.findByRole("button", { name: "View Audit" });
    const rightPath = toggle.querySelector("path")!.getAttribute("d");
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);
    expect(screen.getByRole("button", { name: "Hide Audit" })).toHaveAttribute("aria-expanded", "true");
    expect(toggle.querySelector("path")!.getAttribute("d")).not.toBe(rightPath);
    expect(screen.getByRole("region", { name: "Execution Context" })).toBeVisible();
    expect(screen.getByRole("region", { name: "SELinux Policy Effect" })).toBeVisible();
    const copy = await screen.findByRole("button", { name: "Copy SELinux activity 26710 audit records" });
    expect(container.querySelectorAll(".pf-v6-c-code-block")).toHaveLength(1);
    writeText.mockRejectedValueOnce(new Error("Clipboard unavailable"));
    await user.click(copy);
    expect(await within(copy).findByText("Copy failed")).toBeVisible();
    writeText.mockResolvedValueOnce(undefined);
    await user.click(copy);
    expect(writeText).toHaveBeenLastCalledWith(RAW);
    expect(await within(copy).findByText("Copied")).toBeVisible();
    const provenance = screen.getByRole("button", { name: "Technical Provenance & Hashes" });
    const provenancePath = provenance.querySelector("path")!.getAttribute("d");
    expect(provenance).toHaveAttribute("aria-expanded", "false");
    await user.click(provenance);
    expect(provenance).toHaveAttribute("aria-expanded", "true");
    expect(provenance.querySelector("path")!.getAttribute("d")).not.toBe(provenancePath);
    expect(screen.queryByText("Checkpoint provenance")).not.toBeInTheDocument();
    writeText.mockRestore();
  });

  it("does not present an intermediate state as reconciled when another transition preceded the checkpoint", async () => {
    renderActivity(response([item({ reconciliation: { status: "superseded", checkpoint: checkpoint(true),
       next_transition: { id: 80, event_time: "2026-10-01T14:58:17.588Z", audit_sequence: 51128 } } })]));
    await openAudit();
    expect(await screen.findByText(/Another transition was observed before reconciliation/)).toBeVisible();
    expect(screen.getByText("Later SELinux state observed")).toBeVisible();
    expect(screen.getAllByText(/: On ·/).length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "View later transition" })).toHaveAttribute("href", "/hosts/10?selinux_activity=80#selinux-activity");
  });
});
