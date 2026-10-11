import { Alert, Button, FormGroup, FormSelect, FormSelectOption } from "@patternfly/react-core";
import { Link } from "react-router-dom";
import type { HostConfigurationResponse } from "../api/configuration";

const STATUS_TITLES = { absent: "No active reference", ambiguous: "Ambiguous reference", unavailable: "Reference unavailable", selected: "Reference selected" };
const REASONS: Record<string, string> = {
  host_policy_identity_unavailable: "Trusted host policy identity is unavailable. Reference selection cannot recover an older identity or upgrade host observations.",
  platform_context_missing: "The host lacks the platform context needed for automatic distribution reference selection.",
  no_matching_candidates: "No active distribution reference matched this host.",
  archived_only: "Only archived references matched. They remain inspectable but are unavailable for new selection.",
  archived_reference: "The requested revision is archived. No other reference has been substituted.",
  incomplete_reference_families: "Matching references lack complete Boolean/port facts.",
  incompatible_candidate_families: "Active major-release candidates have different Boolean/port content. Automatic selection cannot choose safely.",
  incompatible_policy_context: "The selected revision's policy type or architecture is incompatible with the known host context.",
  reference_family_incomplete: "The selected reference family is incomplete.",
  reference_not_selected: "No reference was selected.",
  partial_host_inventory: "Only observed entries can be compared; missing entries remain unknown.",
  stale_host_observation: "Current comparison is paused; the retained observation is stale.",
  host_inventory_unknown: "Host observations for this family are unknown.",
  host_inventory_unavailable: "Host collection for this family is unavailable."
};

export function CatalogReferenceSelection({ data, requestedRevision, onSelect }: {
  data: HostConfigurationResponse;
  requestedRevision: string | null;
  onSelect: (revision: string | null) => void;
}) {
  const selection = data.selection;
  const selected = selection.selected_revision;
  const options = [...data.reference_options.revisions];
  if (selected && !options.some((entry) => entry.id === selected.id)) options.unshift(selected);
  const missingOption = requestedRevision !== null && !options.some((entry) => String(entry.id) === requestedRevision);
  const label = selection.mode === "explicit" ? "Explicit reference" : selection.basis === "exact_policy_identity" ? "Exact policy reference" : "Distribution reference — Boolean/port agreement";

  return (
    <section aria-label="Catalog reference selection" className="pf-v6-u-my-md">
      <FormGroup label="Comparison reference" fieldId="comparison-reference">
        <FormSelect id="comparison-reference" value={requestedRevision ?? "automatic"} onChange={(_event, value) => onSelect(value === "automatic" ? null : value)}>
          <FormSelectOption value="automatic" label="Automatic" />
          {missingOption && <FormSelectOption value={requestedRevision} label={`Requested revision ${requestedRevision} — unavailable`} isDisabled />}
          {options.map((entry) => <FormSelectOption key={entry.id} value={String(entry.id)} label={`${entry.display_name} · revision ${entry.id} · ${entry.content_digest.slice(0, 23)}`} />)}
        </FormSelect>
      </FormGroup>
      <p>Active revisions are listed with relevant platform context first. Relevance and display names do not establish policy equivalence.</p>
      {requestedRevision !== null && <Button variant="link" onClick={() => onSelect(null)}>Return to automatic</Button>}
      {data.reference_options.truncated && <p>The first 50 active references are listed. <Link to="/catalogs">Browse catalogs</Link> for other immutable revisions.</p>}
      {selection.status === "selected" && selected ? (
        <Alert isInline variant="info" title={label}>
          <p><Link to={`/catalogs/${selected.id}`}>{selected.display_name}</Link> · revision {selected.id} · <code>{selected.content_digest}</code> · {selected.lifecycle}</p>
          {selection.mode === "explicit" ? <p>This request uses a selected comparison target. Selection does not establish that this catalog matches the host's loaded policy and does not save a host preference.</p>
            : selection.basis === "adr0010_major_release_family_agreement" ? <p>Complete Boolean/port families agree across eligible major-release candidates under ADR 0010. This is not exact binary-policy equivalence and does not apply to other policy facts.</p>
              : <p>Automatic selection used the trusted host's exact loaded-policy digest. Family availability and host evidence limits still apply.</p>}
          {selection.policy_identity_match === false && <p>Loaded policy identity differs from selected reference.</p>}
        </Alert>
      ) : (
        <Alert isInline variant={selection.status === "ambiguous" ? "warning" : "info"} title={STATUS_TITLES[selection.status]}>
          <p>{selection.reason ? REASONS[selection.reason] ?? selection.reason.replaceAll("_", " ") : "Reference selection is unavailable."}</p>
          {selection.candidates.length > 0 && <ul aria-label="Reference candidates">{selection.candidates.map((entry) => <li key={entry.id}>
            <Link to={`/catalogs/${entry.id}`}>{entry.display_name} · revision {entry.id}</Link> · <code>{entry.content_digest}</code> · {entry.lifecycle} · {entry.distribution} {entry.major_version} / {entry.architecture} / {entry.policy_type}
          </li>)}</ul>}
          {selection.candidates_truncated && <p>Showing {selection.candidates.length} of {selection.candidate_count} candidates.</p>}
        </Alert>
      )}
      {selected && Object.entries(selection.families).map(([name, family]) => family.status !== "comparable" && <Alert key={name} isInline variant="warning" title={`${name === "booleans" ? "Booleans" : "Ports"}: ${family.status}`} className="pf-v6-u-mt-sm">
        {family.reason ? REASONS[family.reason] ?? family.reason.replaceAll("_", " ") : "Comparison is limited."} Reference: {family.reference_status}; host: {family.host_status}.
      </Alert>)}
    </section>
  );
}
