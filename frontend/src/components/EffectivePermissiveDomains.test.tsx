import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EffectivePermissiveDomains } from "./EffectivePermissiveDomains";

describe("effective policy domains", () => {
  it("distinguishes authoritative empty from unknown and stored configuration", () => {
    const { rerender } = render(<EffectivePermissiveDomains state={{ status: "observed", policy_identity: "sha256:p", domains: [], provenance: "exact_loaded_policy_artifact" }} />);
    expect(screen.getByText("No permissive domains in the observed loaded policy.")).toBeTruthy();
    rerender(<EffectivePermissiveDomains state={{ status: "unavailable", policy_identity: null, domains: null, provenance: "exact_loaded_policy_artifact" }} />);
    expect(screen.queryByText("No permissive domains in the observed loaded policy.")).toBeNull();
    expect(screen.getByText(/Unknown/)).toBeTruthy();
    expect(screen.getByText(/not global host mode or stored semanage configuration/)).toBeTruthy();
  });

  it("bounds domain rows and exposes exact-policy provenance", () => {
    const domains = Array.from({ length: 25 }, (_, i) => `domain_${i}_t`);
    render(<EffectivePermissiveDomains state={{ status: "observed", policy_identity: "sha256:p", domains, provenance: "exact_loaded_policy_artifact" }} />);
    expect(screen.getAllByRole("listitem").length).toBe(20);
    fireEvent.click(screen.getByRole("button", { name: "Next domains" }));
    expect(screen.getAllByRole("listitem").length).toBe(5);
    expect(screen.getByText("sha256:p")).toBeTruthy();
  });
});
