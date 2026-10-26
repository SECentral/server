import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ObservationCounts } from "./ObservationCounts";

describe("ObservationCounts", () => {
  it("labels decision counts separately from deduplicated syscall outcomes", () => {
    render(<ObservationCounts observations={{ occurrences: 5, audit_events: 3,
      modes: { enforcing: 3, permissive: 1, unknown: 1 },
      syscall_outcomes: { failed: 1, succeeded: 1, unknown: 1 },
      decision_outcomes: [{ enforcement_mode: "enforcing", syscall_outcome: "failed", occurrences: 3 }] }} />);
    expect(screen.getByText("5 AVC observations · 3 audit events")).toBeVisible();
    expect(screen.getByText(/Associated syscalls by event: 1 failed · 1 succeeded · 1 unknown/)).toBeVisible();
    expect(screen.getByText(/3 enforced \/ syscall failed/)).toBeVisible();
  });

  it("keeps an unavailable breakdown distinct from observed zero", () => {
    render(<ObservationCounts />);
    expect(screen.getByText("Observation breakdown unavailable.")).toBeVisible();
    expect(screen.queryByText(/0 failed/)).not.toBeInTheDocument();
  });
});
