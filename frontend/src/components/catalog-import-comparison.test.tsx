import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import type { CatalogImportComparison as Report } from "../api/generated/types.gen";
import { CatalogImportComparison } from "./CatalogImportComparison";

const identity = { id: 1, content_digest: "sha256:" + "a".repeat(64), loaded_policy_digest: "sha256:" + "1".repeat(64), distribution: "almalinux", major_version: "9", architecture: "x86_64", policy_type: "targeted" };
const empty = { count: 0, samples: [], truncated: false };
const report: Report = {
  status: "compared", reason: null, basis: "unique_existing_same_context_revision", direction: "existing_to_imported",
  from_revision: identity, to_revision: { ...identity, id: 2, content_digest: "sha256:" + "b".repeat(64) },
  candidate_count: 1, candidates: [identity], candidates_truncated: false,
  changes: { policy: { loaded_policy_digest_changed: true, packages_changed: false },
    booleans: { added: empty, removed: empty, default_changed: { count: 12, samples: ["httpd_can_network_connect"], truncated: true }, description_changed: empty },
    ports: { added: empty, removed: empty, changed: empty } }
};

describe("Recorded import comparison", () => {
  it("shows immutable basis identities and bounded structural changes without an upgrade claim", () => {
    render(<MemoryRouter><CatalogImportComparison report={report} /></MemoryRouter>);
    expect(screen.getByRole("link", { name: "1" })).toHaveAttribute("href", "/catalogs/1");
    expect(screen.getByText(identity.content_digest)).toBeInTheDocument();
    expect(screen.getByText(report.to_revision.content_digest)).toBeInTheDocument();
    expect(screen.getByText(/not an upgrade, downgrade, security impact/)).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Recorded catalog changes" });
    expect(within(table).getByText("default changed")).toBeInTheDocument();
    expect(within(table).getByText("12")).toBeInTheDocument();
    expect(within(table).getByText(/additional changes omitted/)).toBeInTheDocument();
  });

  it("explains ambiguous basis without choosing a predecessor", () => {
    render(<MemoryRouter><CatalogImportComparison report={{ ...report, status: "ambiguous", from_revision: null, changes: null, candidate_count: 2 }} /></MemoryRouter>);
    expect(screen.getByText("2 existing compatible revisions; no predecessor was chosen.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});
