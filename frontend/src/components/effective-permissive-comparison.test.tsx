import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { EffectivePermissiveComparison as Comparison } from "../api/generated/types.gen";
import { EffectivePermissiveComparison } from "./EffectivePermissiveComparison";

const base: Comparison = {
  status: "observed", reason: null, matching: ["bootupd_t"], unexpected_on_host: ["postgresql_t"], missing_from_host: ["rhcd_t"],
  counts: { matching: 1, unexpected_on_host: 1, missing_from_host: 1 },
  host: { status: "observed", policy_identity: "sha256:host", semantics_version: 1, evaluator_version: "SETools host", evaluated_at: null, snapshot_id: 10, observation_id: 20, evidence_basis: "trusted_current_checkpoint" },
  reference: { status: "observed", policy_identity: "sha256:reference", semantics_version: 1, evaluator_version: "SETools compatible", evaluated_at: null, revision_id: 3, content_digest: "sha256:catalog", provenance: "inline_catalog_extraction" },
  selection: { mode: "explicit", basis: "explicit_revision", policy_identity_match: false, equivalence_asserted: false }
};

describe("Effective permissive comparison", () => {
  it("shows neutral differences, explicit non-equivalence and secondary matching/evidence", () => {
    render(<EffectivePermissiveComparison comparison={base} />);
    expect(screen.getByText(/1 match · 1 unexpected on host · 1 missing from host/)).toBeInTheDocument();
    expect(within(screen.getByRole("list", { name: "Unexpected domains" })).getByText("postgresql_t")).toBeInTheDocument();
    expect(within(screen.getByRole("list", { name: "Missing domains" })).getByText("rhcd_t")).toBeInTheDocument();
    expect(screen.getByText(/explicitly selected reference/)).toBeInTheDocument();
    expect(screen.getByText("Exact policy identities differ.")).toBeInTheDocument();
    expect(screen.getByText("Matching domains (1)").closest("details")).not.toHaveAttribute("open");
    expect(screen.getByText("Comparison evidence").closest("details")).not.toHaveAttribute("open");
    expect(screen.getByText(/do not identify who changed the policy or why/)).toBeInTheDocument();
    expect(screen.getByText(/Inline catalog extraction, collector-reported/)).toBeInTheDocument();
  });

  it("treats two observed empty sets as a match", () => {
    render(<EffectivePermissiveComparison comparison={{ ...base, matching: [], unexpected_on_host: [], missing_from_host: [], counts: { matching: 0, unexpected_on_host: 0, missing_from_host: 0 } }} />);
    expect(screen.getByText(/both observed sets are empty/)).toBeInTheDocument();
    expect(screen.queryByText(/Unknown/)).not.toBeInTheDocument();
  });

  it("replaces previous membership with a human Unknown reason when analysis becomes pending or candidate facts disagree", () => {
    const { rerender } = render(<EffectivePermissiveComparison comparison={base} />);
    rerender(<EffectivePermissiveComparison comparison={{ ...base, status: "unknown", reason: "host_permissive_analysis_pending", counts: null, matching: null, unexpected_on_host: null, missing_from_host: null }} />);
    expect(screen.getByRole("status")).toHaveTextContent("Host policy analysis is pending");
    expect(screen.queryByText("postgresql_t")).not.toBeInTheDocument();
    rerender(<EffectivePermissiveComparison comparison={{ ...base, status: "unknown", reason: "effective_permissive_reference_ambiguous", counts: null, matching: null, unexpected_on_host: null, missing_from_host: null }} />);
    expect(screen.getByRole("status")).toHaveTextContent("Eligible catalogs agree on Boolean/port facts but differ in effective permissive-domain membership");
    expect(screen.getByRole("status")).not.toHaveTextContent("effective_permissive_reference_ambiguous");
  });

  it("bounds visible domain rows and supports accessible pagination", async () => {
    const user = userEvent.setup();
    const domains = Array.from({ length: 25 }, (_, index) => `type_${index}_t`);
    render(<EffectivePermissiveComparison comparison={{ ...base, unexpected_on_host: domains, counts: { matching: 1, unexpected_on_host: 25, missing_from_host: 1 } }} />);
    expect(within(screen.getByRole("list", { name: "Unexpected domains" })).getAllByRole("listitem")).toHaveLength(20);
    await user.click(screen.getByRole("button", { name: "Next unexpected domains" }));
    expect(within(screen.getByRole("list", { name: "Unexpected domains" })).getAllByRole("listitem")).toHaveLength(5);
  });
});
