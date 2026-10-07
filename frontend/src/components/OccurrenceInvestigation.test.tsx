import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import type { OccurrenceDetail } from "../api/issue";
import { OccurrenceInvestigation } from "./OccurrenceInvestigation";

describe("exact-policy occurrence state", () => {
  it("keeps a permissive domain and AVC distinct from an Enforcing host", () => {
    const occurrence: OccurrenceDetail = {
      id: 1, host: { id: 1, hostname: "host" }, occurred_at: "2026-10-07T13:47:21Z", issue: null, guidance: null,
      normalized_denial: { status: "ok", source_type: "postgresql_t", target_type: "bin_t", target_class: "file", permissions: ["entrypoint"], target_paths: [], source_context: "system_u:system_r:postgresql_t:s0", target_context: "system_u:object_r:bin_t:s0", command: "id", executable: "/usr/bin/id", details: { permissive: true, enforcement_mode: "permissive" } },
      raw_event: { id: 1, audit_timestamp: "2026-10-07T13:47:21Z", audit_sequence: 1, boot_id: "boot", category: "avc", transition_type: null, completion_reason: "eoe", evidence_digest: "digest", audit_records: [], file_context_observations: [], checkpoint_enforcement_mode: "enforcing", checkpoint_policy_identity: "sha256:p", permissive_policy_state: { status: "observed", policy_identity: "sha256:p", provenance: "exact_loaded_policy_artifact", source_type: "postgresql_t", source_domain_permissive: true, avc_policy_consistency: "consistent" } }
    };
    render(<MemoryRouter><OccurrenceInvestigation occurrence={occurrence} /></MemoryRouter>);
    expect(screen.getByText("Non-enforced (AVC permissive=1)")).toBeTruthy();
    expect(screen.getByText("enforcing")).toBeTruthy();
    expect(screen.getByText(/postgresql_t is permissive in exact policy/)).toBeTruthy();
  });
});
