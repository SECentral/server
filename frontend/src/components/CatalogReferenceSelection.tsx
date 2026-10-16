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

  return (
    <section aria-label="Catalog reference selection" className="configuration-baseline-selector">
      <FormGroup label="Comparison baseline" fieldId="comparison-reference">
        <FormSelect id="comparison-reference" value={requestedRevision ?? "automatic"} onChange={(_event, value) => onSelect(value === "automatic" ? null : value)}>
          <FormSelectOption value="automatic" label={selection.mode === "automatic" && selected ? `Automatic (${selected.display_name})` : "Automatic"} />
          {missingOption && <FormSelectOption value={requestedRevision} label={`Requested revision ${requestedRevision} — unavailable`} isDisabled />}
          {options.map((entry) => <FormSelectOption key={entry.id} value={String(entry.id)} label={`${entry.display_name} · revision ${entry.id}`} />)}
        </FormSelect>
      </FormGroup>
      {requestedRevision !== null && <Button variant="link" onClick={() => onSelect(null)}>Return to automatic</Button>}
      {data.reference_options.truncated && <p>The first 50 active references are listed. <Link to="/catalogs">Browse catalogs</Link> for other immutable revisions.</p>}
      {selection.status !== "selected" && (
        <Alert isInline variant={selection.status === "ambiguous" ? "warning" : "info"} title={STATUS_TITLES[selection.status]}>
          <p>{selection.reason ? REASONS[selection.reason] ?? selection.reason.replaceAll("_", " ") : "Reference selection is unavailable."}</p>
          {selection.candidates.length > 0 && <ul aria-label="Reference candidates">{selection.candidates.map((entry) => <li key={entry.id}>
            <Link to={`/catalogs/${entry.id}`}>{entry.display_name} · revision {entry.id}</Link> · {entry.lifecycle} · {entry.distribution} {entry.major_version} / {entry.architecture} / {entry.policy_type}
          </li>)}</ul>}
          {selection.candidates_truncated && <p>Showing {selection.candidates.length} of {selection.candidate_count} candidates.</p>}
        </Alert>
      )}
      {selected && Object.entries(selection.families).filter(([name]) => name !== "effective_permissive_domains").map(([name, family]) => family.status !== "comparable" && <Alert key={name} isInline variant="warning" title={`${name === "booleans" ? "Booleans" : "Ports"}: ${family.status}`} className="pf-v6-u-mt-sm">
        {family.reason ? REASONS[family.reason] ?? family.reason.replaceAll("_", " ") : "Comparison is limited."} Reference: {family.reference_status}; host: {family.host_status}.
      </Alert>)}
    </section>
  );
}
