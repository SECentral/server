import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { OccurrenceDetail } from "../api/issue";
import { OccurrenceInvestigation } from "./OccurrenceInvestigation";
import { EvidenceBlock, OccurrenceRawEvidence } from "./OccurrenceEvidence";

describe("exact-policy occurrence state", () => {
  it("keeps a permissive domain and AVC distinct from an Enforcing host", () => {
    const occurrence: OccurrenceDetail = {
      id: 1, host: { id: 1, hostname: "host" }, occurred_at: "2026-10-07T13:47:21Z", issue: null, guidance: null,
      normalized_denial: { status: "ok", source_type: "postgresql_t", target_type: "bin_t", target_class: "file", permissions: ["entrypoint"], target_paths: [], source_context: "system_u:system_r:postgresql_t:s0", target_context: "system_u:object_r:bin_t:s0", command: "id", executable: "/usr/bin/id", details: { permissive: true, enforcement_mode: "permissive" } },
      raw_event: { id: 1, audit_timestamp: "2026-10-07T13:47:21Z", audit_sequence: 1, boot_id: "boot", category: "avc", transition_type: null, completion_reason: "eoe", evidence_digest: "digest", audit_records: [], file_context_observations: [], checkpoint_enforcement_mode: "enforcing", checkpoint_policy_identity: "sha256:p", permissive_policy_state: { status: "observed", policy_identity: "sha256:p", provenance: "exact_loaded_policy_artifact", source_type: "postgresql_t", source_domain_permissive: true, avc_policy_consistency: "consistent" } }
    };
    render(<MemoryRouter><OccurrenceInvestigation occurrence={occurrence} /></MemoryRouter>);
    expect(screen.getByText(/Non-enforced \(AVC permissive=1\) · Associated checkpoint mode: enforcing/)).toBeInTheDocument();
    expect(screen.getByText(/postgresql_t is permissive in the exact policy/)).toBeInTheDocument();
    expect(screen.queryByText("sha256:p")).not.toBeInTheDocument();
  });
});

function socketOccurrence(): OccurrenceDetail {
  return {
    id: 2, host: { id: 1, hostname: "host" }, occurred_at: "2026-10-07T13:47:21Z", issue: null,
    normalized_denial: {
      status: "ok", source_type: "httpd_t", target_type: "unreserved_port_t", target_class: "tcp_socket", permissions: ["name_bind"],
      target_paths: [], source_context: "system_u:system_r:httpd_t:s0", target_context: "system_u:object_r:unreserved_port_t:s0", command: "httpd", executable: "/usr/sbin/httpd",
      details: { enforcement_mode: "enforcing", network_evidence: { bind_port_fields: ["12345"], proto_fields: ["tcp"] } }
    },
    raw_event: {
      id: 2, audit_timestamp: "2026-10-07T13:47:21Z", audit_sequence: 2, boot_id: "boot", category: "avc", transition_type: null,
      completion_reason: "eoe", evidence_digest: "digest", file_context_observations: [],
      checkpoint_enforcement_mode: "enforcing", checkpoint_port_inventory_status: "observed", checkpoint_file_context_mappings_status: "observed",
      permissive_policy_state: { status: "observed", policy_identity: "sha256:policy-digest", provenance: "exact_loaded_policy_artifact", source_type: "httpd_t", source_domain_permissive: false, avc_policy_consistency: "consistent" },
      audit_records: [
        { position: 1, record_type: 1300, type_name: "SYSCALL", audit_timestamp: "2026-10-07T13:47:21Z", sequence: 2, payload: "type=SYSCALL exe=\"/usr/sbin/httpd\"" },
        { position: 0, record_type: 1400, type_name: "AVC", audit_timestamp: "2026-10-07T13:47:21Z", sequence: 2, payload: "type=AVC denied { name_bind } src=12345" }
      ]
    },
    guidance: {
      summary: "Investigation checks based on retained evidence; no diagnosis is implied.",
      observations: [
        { observation: "The audit record contains bind port field 12345.", basis: "avc_record", certainty: "observed", summary_fact: true },
        { observation: "Executable: /usr/sbin/httpd", basis: "syscall_record", certainty: "observed" },
        { observation: "A derived comparison", basis: "fleet_comparison", certainty: "derived" }
      ],
      checks: [{ kind: "executable_context", target: "/usr/sbin/httpd", reason: "Compare the observed executable with current service configuration.", expected: "Current context may differ.", limitation: "current_state_only" }],
      missing_evidence: [], historical_limitations: ["Current host labels and policy may differ from occurrence time."]
    }
  };
}

function renderOccurrence(occurrence = socketOccurrence(), initialEntry = "/hosts/1/occurrences/2") {
  render(<MemoryRouter initialEntries={[initialEntry]}><OccurrenceInvestigation occurrence={occurrence} /></MemoryRouter>);
  return userEvent.setup();
}

describe("occurrence investigation presentation", () => {
  it("groups identity and policy, exposes normalized ports, and omits irrelevant path and checkpoint facts", () => {
    renderOccurrence();
    expect(screen.getByRole("heading", { name: "Process (Subject)" })).toHaveClass("pf-v6-c-title", "pf-m-md");
    expect(screen.queryByRole("heading", { name: "Access identity" })).not.toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Process (Subject)" })).getByText("httpd")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Target (Object)" })).getByText("name_bind")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Network Detail" })).getByText("12345")).toBeInTheDocument();
    expect(screen.getByText("Enforcing (AVC permissive=0)")).toBeInTheDocument();
    expect(screen.getByText(/httpd_t is not permissive/)).toBeInTheDocument();
    expect(screen.queryByText(/Associated checkpoint mode/)).not.toBeInTheDocument();
    expect(screen.queryByText("Observed path")).not.toBeInTheDocument();
    expect(screen.queryByText("Checkpoint port inventory")).not.toBeInTheDocument();
    expect(screen.queryByText(/sha256:/)).not.toBeInTheDocument();
  });

  it.each(["capability", "capability2", "cap_userns", "cap2_userns", "udp_socket"])("suppresses path rows for %s", (targetClass) => {
    const occurrence = socketOccurrence();
    occurrence.normalized_denial.target_class = targetClass;
    renderOccurrence(occurrence);
    expect(screen.queryByText("Observed path")).not.toBeInTheDocument();
  });

  it("retains filesystem path fallbacks and unknown policy states without an empty network section", () => {
    const occurrence = socketOccurrence();
    occurrence.normalized_denial.target_class = "file";
    occurrence.normalized_denial.details = {};
    occurrence.raw_event.permissive_policy_state = undefined;
    occurrence.raw_event.checkpoint_enforcement_mode = undefined;
    renderOccurrence(occurrence);
    expect(screen.getByText("Complete path not recorded")).toBeInTheDocument();
    expect(screen.getByText(/Unknown — AVC enforcement not recorded/)).toBeInTheDocument();
    expect(screen.getByText(/Unknown — trusted exact-policy membership/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Network Detail" })).not.toBeInTheDocument();
  });

  it("offers only forensic tabs even when the API includes guidance", async () => {
    const user = renderOccurrence();
    expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["Summary", "Raw evidence", "Normalized details"]);
    await user.click(screen.getByRole("tab", { name: "Raw evidence" }));
    expect(screen.queryByText(/no diagnosis is implied/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Copy investigation check/ })).not.toBeInTheDocument();
  });

  it("links grouped occurrences to the parent issue investigation rather than its occurrence list", () => {
    const occurrence = socketOccurrence();
    occurrence.issue = { id: 1942 };
    renderOccurrence(occurrence);
    expect(screen.getByText("Belongs to Issue #1942.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /View Issue #1942 Investigation & Change Review/ })).toHaveAttribute("href", "/issues/1942");
  });

  it("keeps ungrouped occurrences inspectable without an investigation link", () => {
    renderOccurrence();
    expect(screen.getByText("Ungrouped event")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Investigation & Resolution Plan/ })).not.toBeInTheDocument();
  });

  it("separates normalized JSON from raw records and retains exact copying", async () => {
    const user = renderOccurrence();
    await user.click(screen.getByRole("tab", { name: "Raw evidence" }));
    expect(screen.queryByRole("region", { name: "Normalized JSON payload" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Audit Event Records" }).closest(".pf-v6-c-card")).not.toBeNull();
    expect(screen.getByRole("heading", { name: "Retained Event Metadata" }).closest(".pf-v6-c-card")).not.toBeNull();
    expect(screen.queryByRole("button", { name: "Normalized details (debug)" })).not.toBeInTheDocument();
    expect(screen.getAllByText("type=AVC denied { name_bind } src=12345")).toHaveLength(1);
    const copyButtons = screen.getAllByRole("button", { name: /^Copy audit record/ });
    expect(copyButtons.map((button) => button.getAttribute("aria-label"))).toEqual([
      "Copy audit record 0 for occurrence 2", "Copy audit record 1 for occurrence 2"
    ]);
    await user.click(copyButtons[0]);
    expect(await navigator.clipboard.readText()).toBe("type=AVC denied { name_bind } src=12345");
    expect(screen.getByText("Checkpoint port inventory").closest(".pf-v6-c-description-list")).not.toBeNull();
    expect(screen.getByText("Checkpoint expected-label mappings")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Copy exact policy identity for occurrence 2" }));
    expect(await navigator.clipboard.readText()).toBe("sha256:policy-digest");
    await user.click(screen.getByRole("tab", { name: "Normalized details" }));
    expect(screen.queryByRole("heading", { name: "Audit Event Records" })).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Normalized JSON payload" })).toHaveAttribute("tabindex", "0");
    expect(screen.getByRole("region", { name: "Normalized JSON payload" }).querySelector(".json-token-property")).not.toBeNull();
    await user.click(screen.getByRole("button", { name: "Copy normalized details for occurrence 2" }));
    expect(JSON.parse(await navigator.clipboard.readText())).toEqual(socketOccurrence().normalized_denial.details);
  });

  it.each([
    ["?tab=normalized", "Normalized details"],
    ["?tab=evidence", "Raw evidence"],
    ["?tab=invalid", "Summary"],
    ["", "Summary"]
  ])("restores the active tab from %s", (query, title) => {
    renderOccurrence(socketOccurrence(), `/hosts/1/occurrences/2${query}`);
    expect(screen.getByRole("tab", { name: title })).toHaveAttribute("aria-selected", "true");
    if (title === "Normalized details") expect(screen.getByRole("region", { name: "Normalized JSON payload" })).toBeInTheDocument();
  });

  it("persists tab changes while preserving other query parameters and browser history", async () => {
    function Navigation() {
      const location = useLocation();
      const navigate = useNavigate();
      return <><output aria-label="Current URL">{location.pathname}{location.search}</output><button onClick={() => navigate(-1)}>Back</button><button onClick={() => navigate(1)}>Forward</button></>;
    }
    render(<MemoryRouter initialEntries={["/hosts/1/occurrences/2?source=log"]}><Navigation /><OccurrenceInvestigation occurrence={socketOccurrence()} /></MemoryRouter>);
    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Normalized details" }));
    expect(screen.getByLabelText("Current URL")).toHaveTextContent("?source=log&tab=normalized");
    await user.click(screen.getByRole("tab", { name: "Raw evidence" }));
    expect(screen.getByLabelText("Current URL")).toHaveTextContent("?source=log&tab=evidence");
    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByRole("tab", { name: "Normalized details" })).toHaveAttribute("aria-selected", "true");
    await user.click(screen.getByRole("button", { name: "Forward" }));
    expect(screen.getByRole("tab", { name: "Raw evidence" })).toHaveAttribute("aria-selected", "true");
    await user.click(screen.getByRole("tab", { name: "Summary" }));
    expect(screen.getByLabelText("Current URL")).toHaveTextContent("/hosts/1/occurrences/2?source=log");
    expect(screen.getByLabelText("Current URL")).not.toHaveTextContent("tab=");
  });

  it("downloads the exact normalized payload as JSON with an occurrence-specific filename", async () => {
    const createObjectURL = vi.fn<(blob: Blob) => string>(() => "blob:normalized-json");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", class extends URL {
      static createObjectURL = createObjectURL;
      static revokeObjectURL = revokeObjectURL;
    });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    try {
      const user = renderOccurrence(socketOccurrence(), "/hosts/1/occurrences/2?tab=normalized");
      await user.click(screen.getByRole("button", { name: "Download JSON" }));
      const blob = createObjectURL.mock.calls[0][0] as Blob;
      expect(blob.type).toBe("application/json;charset=utf-8");
      const text = await new Promise<string>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.readAsText(blob);
      });
      expect(text).toBe(JSON.stringify(socketOccurrence().normalized_denial.details, null, 2));
      expect((click.mock.instances[0] as HTMLAnchorElement).download).toBe("occurrence-2-normalized-details.json");
      expect(revokeObjectURL).toHaveBeenCalledWith("blob:normalized-json");
    } finally {
      click.mockRestore();
      vi.unstubAllGlobals();
    }
  });

  it("handles missing audit records without hiding retained metadata", async () => {
    const occurrence = socketOccurrence();
    occurrence.raw_event.audit_records = [];
    const user = renderOccurrence(occurrence);
    await user.click(screen.getByRole("tab", { name: "Raw evidence" }));
    expect(screen.getByText("No raw audit records are present.")).toBeInTheDocument();
    expect(screen.getByText("Audit sequence")).toBeInTheDocument();
  });

  it("preserves collapsed raw sections in embedded technical evidence", () => {
    render(<OccurrenceRawEvidence occurrence={socketOccurrence()} collapsed />);
    expect(screen.getByRole("button", { name: "Raw AVC" })).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByRole("button", { name: "Normalized details (debug)" })).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText("type=AVC denied { name_bind } src=12345")).not.toBeInTheDocument();
  });

  it("highlights JSON tokens as escaped text and copies the unchanged source", async () => {
    const value = JSON.stringify({ payload: '</code><img src=x onerror="alert(1)">', value: 123, enabled: true, absent: null }, null, 2);
    const user = userEvent.setup();
    const { container } = render(<EvidenceBlock value={value} label="test JSON" isJson hasCopyButton />);
    expect(container.querySelector(".pf-v6-c-code-block__pre")).toHaveTextContent(/payload/);
    expect(container.querySelector(".pf-v6-c-code-block__pre")?.textContent).toBe(value);
    for (const type of ["property", "string", "number", "boolean", "null", "punctuation"]) {
      expect(container.querySelector(`.json-token-${type}`)).not.toBeNull();
    }
    expect(container.querySelector("img, script")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Copy test JSON" }));
    expect(await navigator.clipboard.readText()).toBe(value);
  });

  it("falls back to escaped plain text for invalid JSON", () => {
    const value = '{"payload": "<script>alert(1)</script>"';
    const { container } = render(<EvidenceBlock value={value} label="invalid JSON" isJson />);
    expect(container.querySelector(".pf-v6-c-code-block__pre")?.textContent).toBe(value);
    expect(container.querySelector('[class^="json-token-"], script')).toBeNull();
  });
});
