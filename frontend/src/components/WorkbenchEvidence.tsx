import { Button, Label, Tooltip } from "@patternfly/react-core";
import { useState } from "react";
import CogsIcon from "@patternfly/react-icons/dist/esm/icons/cogs-icon";
import ServerIcon from "@patternfly/react-icons/dist/esm/icons/server-icon";
import FileIcon from "@patternfly/react-icons/dist/esm/icons/file-icon";
import FolderIcon from "@patternfly/react-icons/dist/esm/icons/folder-icon";
import PlugIcon from "@patternfly/react-icons/dist/esm/icons/plug-icon";
import ClockIcon from "@patternfly/react-icons/dist/esm/icons/clock-icon";
import TimesCircleIcon from "@patternfly/react-icons/dist/esm/icons/times-circle-icon";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { fetchHost } from "../api/hosts";
import type { IssueDetailResponse } from "../api/issue";
import type { ResolutionWorkflow } from "../api/resolution";
import { osDisplayName } from "../platform";
import { activeResourceFinding, resolutionResources } from "./resolutionResources";
import { EvidenceBlock } from "./OccurrenceEvidence";
import { Disclosure as ExpandableSection } from "./Disclosure";
import { Disclosure } from "./Disclosure";

export function valueText(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

export function evidenceRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

export function PolicyArtifactReference({ identity }: { identity: string }) {
  return /^sha256:[a-f0-9]{64}$/.test(identity) ? <EvidenceLink target={`artifact-${identity}`}>Policy artifact {identity.slice(7, 15)}…</EvidenceLink> : <code>{identity}</code>;
}

export function PolicyArtifacts({ evidence }: { evidence: unknown }) {
  const identities = new Set<string>();
  function collect(value: unknown, key = "") {
    if (typeof value === "string" && key.includes("policy_identity") && /^sha256:[a-f0-9]{64}$/.test(value)) identities.add(value);
    else if (Array.isArray(value)) value.forEach((item) => collect(item, key));
    else if (value && typeof value === "object") Object.entries(value).forEach(([name, item]) => collect(item, name));
  }
  collect(evidence);
  return identities.size > 0 ? <section aria-label="Retained policy artifacts"><h3>Retained policy artifacts</h3><p>Identities are listed once; checkpoint, current-observation and review-time references above keep their distinct roles.</p>
    {[...identities].map((identity) => <div key={identity} id={`artifact-${identity}`} tabIndex={-1}><EvidenceBlock value={identity} label="Policy identity" hasCopyButton /></div>)}
  </section> : null;
}

export function EvidenceLink({ target, children, occurrenceId }: { target: string; children: React.ReactNode; occurrenceId?: number }) {
  const [params] = useSearchParams();
  const next = new URLSearchParams(params);
  next.delete("phase");
  next.set("evidence", target);
  next.set("evidence_tab", evidenceTabFor(target));
  if (target.startsWith("option-")) next.set("evidence_option", target.slice("option-".length));
  if (target === "reviewed-plan-evidence") next.delete("evidence_option");
  if (occurrenceId != null) next.set("evidence_occurrence", String(occurrenceId));
  return <Link to={`?${next}#${target}`}>{children}</Link>;
}

export function evidenceTabFor(target: string | null): "policy" | "audit" | "provenance" {
  if (target === "audit-evidence") return "audit";
  if (target === "artifact-provenance" || target?.startsWith("artifact-") || target?.startsWith("host-evidence-")) return "provenance";
  return "policy";
}

export function TechnicalEvidenceDisclosure({ basis, title = "Evidence & provenance" }: { basis: Record<string, unknown>; title?: string }) {
  const [expanded, setExpanded] = useState(false);
  return <ExpandableSection className="workbench-technical" toggleText={title} isExpanded={expanded} onToggle={(_event, open) => setExpanded(open)}>
    {expanded && <EvidenceBlock value={JSON.stringify(basis, null, 2)} label={title} hasCopyButton isJson />}
  </ExpandableSection>;
}

export function ResourceIcon({ objectClass }: { objectClass: string }) {
  return objectClass.endsWith("socket") ? <PlugIcon aria-hidden="true" /> : objectClass === "dir" ? <FolderIcon aria-hidden="true" /> : <FileIcon aria-hidden="true" />;
}

export function ObservedAccessFlow({ access }: { access: NonNullable<ResolutionWorkflow["observed_access"]> }) {
  return <section className="workbench-observed" aria-label="Observed access"><h2>What happened</h2>
    <div className="access-flow">
      <div className="access-node access-subject"><span className="entity-label"><CogsIcon aria-hidden="true" /> Subject</span><strong>{access.actor}</strong><code>{access.source_type}</code></div>
      <div className="access-edge"><span className="access-action">{access.operation_label}</span><span className="access-line" aria-hidden="true" /><span className="access-denied"><TimesCircleIcon aria-hidden="true" /> POLICY DENIAL</span></div>
      <div className="access-node access-target"><span className="entity-label"><ResourceIcon objectClass={access.object_class} /> Target</span><strong title={access.resource}>{access.resource}</strong><code>{access.target_type}</code></div>
    </div>
  </section>;
}

export function ContextSidebar({ detail, workflow, focusedAccess, onShowTechnicalEvidence }: { detail: IssueDetailResponse; workflow: ResolutionWorkflow; focusedAccess?: ResolutionWorkflow["observed_access"]; onShowTechnicalEvidence?: () => void }) {
  const [params] = useSearchParams();
  const reviewed = resolutionResources(workflow).find((resource) => resource.candidates.some((candidate) => candidate.id === workflow.intent?.candidate_id));
  const planLink = (phase: string) => {
    const next = new URLSearchParams(params);
    if (reviewed) next.set("resource", reviewed.key);
    next.set("phase", phase);
    return `?${next}#plan-${phase}`;
  };
  const access = focusedAccess ?? workflow.observed_access;
  const finding = activeResourceFinding(detail, workflow, params.get("resource"));
  const diagnosis = finding.diagnosis;
  const source = detail.operator_guidance?.source;
  const diagnosisHost = diagnosis && detail.host_explanations.find((host) => host.diagnosis_groups.some((group) => group.sample_occurrence_ids.includes(diagnosis.occurrence_id)));
  const hostId = access?.host_id ?? source?.host_id ?? diagnosisHost?.host_id ?? diagnosis?.host_id;
  const findingOccurrenceId = diagnosis?.occurrence_id;
  const findingHostId = diagnosis?.host_id ?? diagnosisHost?.host_id;
  const resource = access?.resource ?? source?.path ?? diagnosis?.path;
  const host = useQuery({ queryKey: ["host", hostId], queryFn: () => fetchHost(hostId!), enabled: !!hostId, staleTime: 60_000 });
  const platform = host.data?.host?.platform;
  const unexplained = detail.finding_coverage?.unexplained ?? detail.host_explanations.reduce((total, host) => total + host.unexplained_occurrence_count, 0);
  return <div className="workbench-context-column"><aside className="workbench-context" aria-label="Investigation context"><h2>Context</h2>
    <section><h3><ServerIcon aria-hidden="true" /> Host</h3>{hostId ? <Link to={`/hosts/${hostId}`}>{valueText(access?.hostname) ?? valueText(source?.hostname) ?? diagnosisHost?.hostname ?? `Host ${hostId}`}</Link> : <span>Host not established</span>}
      {access && <small><span>{findingOccurrenceId === access.occurrence_id ? "Observed access & finding example" : "Active resource example"}</span> · <Link to={`/hosts/${access.host_id}/occurrences/${access.occurrence_id}`}>#{access.occurrence_id}</Link></small>}
      {workflow.observed_access && workflow.observed_access.occurrence_id !== access?.occurrence_id && <small><span>Latest access</span> · <Link to={`/hosts/${workflow.observed_access.host_id}/occurrences/${workflow.observed_access.occurrence_id}`}>#{workflow.observed_access.occurrence_id}</Link></small>}
      {findingOccurrenceId && findingOccurrenceId !== access?.occurrence_id && <small>{access ? "Finding example · differs from diagram" : "Finding example"} · {findingHostId ? <Link to={`/hosts/${findingHostId}/occurrences/${findingOccurrenceId}`}>#{findingOccurrenceId}</Link> : `#${findingOccurrenceId}`}</small>}
      {platform?.os_id && <small>{osDisplayName(platform.os_id)} {platform.os_version} · latest retained inventory</small>}</section>
    {workflow.intent && <section><h3>Selected plan</h3><Label color={workflow.freshness === "current" ? "blue" : "orange"}>{workflow.freshness === "current" ? "Selected · current" : "Selected · review required"}</Label>
      {reviewed && <small>Reviewed resource: {reviewed.label}</small>}
      {workflow.freshness === "current" && workflow.change_plan && <><Link to={planLink("inspection")}>Next safe step: {workflow.change_plan.preview_steps[0]?.title}</Link><Link to={planLink("rollback")}>View rollback</Link></>}</section>}
    <section><h3><CogsIcon aria-hidden="true" /> Process</h3><strong>{valueText(access?.actor) ?? valueText(diagnosis?.process_command) ?? valueText(detail.intelligence.resource_summary?.process_command) ?? "Process not recorded"}</strong><small>Domain <code>{access?.source_type ?? detail.issue.source_type}</code></small></section>
    <section><h3><ResourceIcon objectClass={detail.issue.target_class} /> {detail.issue.target_class.endsWith("socket") ? "Observed target" : "Observed resource"}</h3><span className="context-resource">{resource ?? "Identity not established"}</span>
      <small>{access?.object_class ?? detail.issue.target_class} · AVC label <code>{access?.target_type ?? source?.observed_type ?? detail.issue.target_type}</code></small></section>
    <section><h3>Permission</h3><code>{(access?.permissions ?? detail.issue.permissions).join(", ")}</code></section>
    {diagnosis?.kind === "file_context_mismatch" && (!access || diagnosis.occurrence_id === access.occurrence_id) && <section><h3>Expected for this path</h3><code>{diagnosis.expected_type ?? "Not available"}</code><small><ClockIcon aria-hidden="true" /> Checked after the denial</small></section>}
     {diagnosis?.kind === "conditional_allow_inactive" && (!access || diagnosis.occurrence_id === access.occurrence_id) && <section><h3>Policy state at checkpoint</h3><span>{diagnosis.conditional_rules?.length ?? 0} conditional path{(diagnosis.conditional_rules?.length ?? 0) === 1 ? "" : "s"} recorded</span><small>Historical checkpoint evidence</small></section>}
      <section aria-label="Finding coverage"><h3>Finding coverage</h3><Tooltip content="Occurrences with evidence-supported findings, not verified root causes or confirmed remediation. Counts cover the whole issue, not just the selected resource."><strong tabIndex={0}>Supported findings: {detail.issue.occurrences_count - unexplained} of {detail.issue.occurrences_count} occurrences</strong></Tooltip>
       <small>{unexplained} occurrence{unexplained === 1 ? " lacks" : "s lack"} a complete explanation</small>
         {diagnosis && <small>Displayed finding: {finding.count ?? "Not counted"} · <EvidenceLink target="policy-evaluation-evidence" occurrenceId={diagnosis.occurrence_id}>Policy evidence</EvidenceLink></small>}</section>
     <Button component="a" variant="link" href="#issue-technical-evidence" onClick={onShowTechnicalEvidence}>View technical evidence</Button>
   {(workflow.history.length > 0 || detail.issue.disposition_history.length > 0) && <section aria-label="Operator history"><h3>Operator history</h3>
      {workflow.history.length > 0 && <Disclosure toggleText="Intent history"><ul>{workflow.history.map((change, i) => <li key={i}>{change.created_at} · {change.operator} · {change.action}{change.issue_signature_id ? ` · Historical signature #${change.issue_signature_id}; review required in this workspace` : ""}</li>)}</ul></Disclosure>}
      {detail.issue.disposition_history.length > 0 && <Disclosure toggleText="Disposition history"><ul>{detail.issue.disposition_history.map((change, index) => <li key={`${change.changed_at}-${index}`}><time dateTime={change.changed_at}>{change.changed_at}</time> · {change.previous_disposition} → {change.disposition}{change.issue_signature_id ? ` · Signature #${change.issue_signature_id}` : ""}{change.note ? ` · ${change.note}` : ""}</li>)}</ul></Disclosure>}
   </section>}
   </aside>
   </div>;
}
