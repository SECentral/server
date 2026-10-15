import { useState } from "react";
import type { EffectivePermissiveComparison as Comparison } from "../api/generated/types.gen";

const REASONS: Record<string, string> = {
  host_policy_identity_unavailable: "Trusted exact host policy identity is unavailable.",
  stale_host_observation: "The host observation is stale; current comparison is paused.",
  host_policy_artifact_unavailable: "The host's exact policy artifact is unavailable.",
  host_permissive_analysis_pending: "Host policy analysis is pending.",
  host_permissive_analysis_unavailable: "Host policy analysis is unavailable.",
  host_permissive_analysis_error: "Host policy analysis failed.",
  reference_absent: "No applicable reference was selected.",
  reference_ambiguous: "Reference selection is ambiguous.",
  reference_unavailable: "Reference selection is unavailable.",
  reference_archived: "The requested reference is archived and unavailable for new selection.",
  incompatible_policy_context: "The explicit reference's policy type or architecture is incompatible with this host.",
  reference_inline_facts_unavailable: "At least one eligible catalog lacks usable inline permissive-domain facts.",
  reference_extraction_semantics_incompatible: "The catalog's extraction semantics are incompatible with host analysis.",
  effective_permissive_reference_ambiguous: "Eligible catalogs agree on Boolean/port facts but differ in effective permissive-domain membership."
};

function DomainList({ domains, label }: { domains: string[]; label: string }) {
  const [page, setPage] = useState(0);
  return <>
    <ul aria-label={label}>{domains.slice(page * 20, (page + 1) * 20).map((domain) => <li key={domain}><code>{domain}</code></li>)}</ul>
    {domains.length > 20 ? <div>
      <button type="button" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>Previous {label.toLowerCase()}</button>{" "}
      <span>Page {page + 1} of {Math.ceil(domains.length / 20)}</span>{" "}
      <button type="button" disabled={(page + 1) * 20 >= domains.length} onClick={() => setPage((value) => value + 1)}>Next {label.toLowerCase()}</button>
    </div> : null}
  </>;
}

export function EffectivePermissiveComparison({ comparison }: { comparison: Comparison }) {
  return <section aria-label="Effective permissive-domain reference comparison" className="pf-v6-u-my-md">
    <h3>Effective permissive domains — reference comparison</h3>
    <p>Host membership is extracted from exact compiled policy; reference membership is reported inline by the catalog collector. Differences show host versus selected reference state; they do not identify who changed the policy or why.</p>
    {comparison.selection.mode === "explicit" ? <p>Comparing host policy against an explicitly selected reference; selection does not assert binary equivalence.</p> : null}
    {comparison.selection.policy_identity_match === false ? <p>Exact policy identities differ.</p> : null}
    {comparison.status === "observed" && comparison.counts ? <>
      <p aria-label="Effective permissive-domain comparison counts">{comparison.counts.matching} match · {comparison.counts.unexpected_on_host} unexpected on host · {comparison.counts.missing_from_host} missing from host</p>
      {comparison.counts.unexpected_on_host === 0 && comparison.counts.missing_from_host === 0 ? <p>Matches reference{comparison.counts.matching === 0 ? " — both observed sets are empty" : ""}.</p> : null}
      {comparison.unexpected_on_host?.length ? <div><h4>Unexpected on host</h4><DomainList domains={comparison.unexpected_on_host} label="Unexpected domains" /></div> : null}
      {comparison.missing_from_host?.length ? <div><h4>Missing from host</h4><DomainList domains={comparison.missing_from_host} label="Missing domains" /></div> : null}
      {comparison.matching?.length ? <details><summary>Matching domains ({comparison.counts.matching})</summary><DomainList domains={comparison.matching} label="Matching domains" /></details> : null}
    </> : <p role="status">Unknown — {comparison.reason ? REASONS[comparison.reason] ?? "Exact-policy comparison is unavailable." : "Exact-policy comparison is unavailable."}</p>}
    <details><summary>Comparison evidence</summary><dl>
      <dt>Host checkpoint</dt><dd>Snapshot {comparison.host.snapshot_id ?? "unavailable"} · observation {comparison.host.observation_id ?? "unavailable"}</dd>
      <dt>Host policy SHA</dt><dd><code>{comparison.host.policy_identity ?? "unavailable"}</code></dd>
      <dt>Host extraction</dt><dd>{comparison.host.status} · semantics {comparison.host.semantics_version ?? "unavailable"} · {comparison.host.evaluator_version ?? "tool version unavailable"}</dd>
      <dt>Reference revision</dt><dd>{comparison.reference?.revision_id ?? "unavailable"} · <code>{comparison.reference?.content_digest ?? "unavailable"}</code></dd>
      <dt>Reference policy SHA</dt><dd><code>{comparison.reference?.policy_identity ?? "unavailable"}</code></dd>
      <dt>Reference extraction</dt><dd>{comparison.reference?.status ?? "unavailable"} · semantics {comparison.reference?.semantics_version ?? "unavailable"} · {comparison.reference?.evaluator_version ?? "tool version unavailable"}</dd>
      <dt>Reference source</dt><dd>{comparison.reference?.provenance === "inline_catalog_extraction" ? "Inline catalog extraction, collector-reported; not server-verified binary extraction." : "Unavailable"}</dd>
      <dt>Selection</dt><dd>{comparison.selection.mode === "explicit" ? "Explicit comparison target, non-equivalent" : comparison.selection.basis === "exact_policy_identity" ? "Automatic exact policy identity" : comparison.status === "observed" ? "Automatic major-release family agreement; eligible effective permissive facts agree" : "Automatic major-release family agreement; effective permissive applicability is unverified"}</dd>
    </dl></details>
  </section>;
}
