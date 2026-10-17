import { Button, ExpandableSection, Label } from "@patternfly/react-core";
import { useState } from "react";
import CogsIcon from "@patternfly/react-icons/dist/esm/icons/cogs-icon";
import ServerIcon from "@patternfly/react-icons/dist/esm/icons/server-icon";
import FileIcon from "@patternfly/react-icons/dist/esm/icons/file-icon";
import FolderIcon from "@patternfly/react-icons/dist/esm/icons/folder-icon";
import PlugIcon from "@patternfly/react-icons/dist/esm/icons/plug-icon";
import ClockIcon from "@patternfly/react-icons/dist/esm/icons/clock-icon";
import TimesCircleIcon from "@patternfly/react-icons/dist/esm/icons/times-circle-icon";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { fetchHost } from "../api/hosts";
import type { IssueDetailResponse } from "../api/issue";
import type { ResolutionWorkflow } from "../api/resolution";
import { osDisplayName } from "../platform";

export function valueText(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

export function evidenceRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function EvidenceFields({ values }: { values: Record<string, unknown> }) {
  return <dl className="workbench-evidence-fields">{Object.entries(values).filter(([, value]) => value != null).map(([key, value]) => <div key={key}>
    <dt>{key.replaceAll("_", " ")}</dt><dd>{Array.isArray(value) ? <ul>{value.map((item, i) => <li key={i}>{typeof item === "object" ? <EvidenceFields values={evidenceRecord(item)} /> : <code>{String(item)}</code>}</li>)}</ul>
      : typeof value === "object" ? <EvidenceFields values={evidenceRecord(value)} /> : <code>{String(value)}</code>}</dd>
  </div>)}</dl>;
}

export function TechnicalEvidenceDisclosure({ basis, title = "Evidence & provenance" }: { basis: Record<string, unknown>; title?: string }) {
  const [expanded, setExpanded] = useState(false);
  return <ExpandableSection className="workbench-technical" toggleText={title} isExpanded={expanded} onToggle={(_event, open) => setExpanded(open)}>
    {expanded && <EvidenceFields values={basis} />}
  </ExpandableSection>;
}

export function ResourceIcon({ objectClass }: { objectClass: string }) {
  return objectClass.endsWith("socket") ? <PlugIcon aria-hidden="true" /> : objectClass === "dir" ? <FolderIcon aria-hidden="true" /> : <FileIcon aria-hidden="true" />;
}

export function ObservedAccessFlow({ access }: { access: NonNullable<ResolutionWorkflow["observed_access"]> }) {
  return <section className="workbench-observed" aria-label="Observed access"><h2>What happened</h2>
    <div className="access-flow">
      <div className="access-node access-subject"><span className="entity-label"><CogsIcon aria-hidden="true" /> Subject</span><strong>{access.actor}</strong><code>{access.source_type}</code></div>
      <div className="access-edge"><span className="access-action">{access.operation_label}</span><span className="access-line" aria-hidden="true" /><span className="access-denied"><TimesCircleIcon aria-hidden="true" /> DENIED</span></div>
      <div className="access-node access-target"><span className="entity-label"><ResourceIcon objectClass={access.object_class} /> Target</span><strong title={access.resource}>{access.resource}</strong><code>{access.target_type}</code></div>
    </div>
    <p className="workbench-caption">Latest occurrence: <Link to={`/hosts/${access.host_id}/occurrences/${access.occurrence_id}`}>{access.hostname} · #{access.occurrence_id}</Link> · observed access, not an intended allowed flow</p>
  </section>;
}

export function ContextSidebar({ detail, workflow, onShowTechnicalEvidence }: { detail: IssueDetailResponse; workflow: ResolutionWorkflow; onShowTechnicalEvidence?: () => void }) {
  const access = workflow.observed_access;
  const diagnosis = detail.diagnosis;
  const source = detail.operator_guidance?.source;
  const hostId = source?.host_id ?? access?.host_id;
  const sameAccess = !source || source.occurrence_id === access?.occurrence_id;
  const resource = source ? source.path ?? (diagnosis?.destination_port ? `TCP/${diagnosis.destination_port}` : diagnosis?.bind_port ? `TCP/${diagnosis.bind_port}` : detail.issue.target_class === "file" ? "Complete path not recorded" : sameAccess ? access?.resource : "Identity not established") : access?.resource ?? diagnosis?.path;
  const host = useQuery({ queryKey: ["host", hostId], queryFn: () => fetchHost(hostId!), enabled: !!hostId, staleTime: 60_000 });
  const platform = host.data?.host?.platform;
  const coverage = diagnosis ? diagnosis.kind === "file_context_mismatch" ? detail.findings?.[0]?.occurrence_count : detail.finding_coverage?.[diagnosis.kind] ?? detail.findings?.[0]?.occurrence_count : undefined;
  return <aside className="workbench-context" aria-label="Investigation context"><h2>Context</h2>
    <section><h3><ServerIcon aria-hidden="true" /> Host</h3>{hostId ? <Link to={`/hosts/${hostId}`}>{(source ? valueText(source.hostname) : valueText(access?.hostname)) ?? `Host ${hostId}`}</Link> : <span>Host not established</span>}
      {source && <small>Investigation example · <Link to={`/hosts/${source.host_id}/occurrences/${source.occurrence_id}`}>#{source.occurrence_id}</Link></small>}
      {platform?.os_id && <small>{osDisplayName(platform.os_id)} {platform.os_version} · latest retained inventory</small>}</section>
    {workflow.intent && <section><h3>Selected plan</h3><Label color={workflow.freshness === "current" ? "blue" : "orange"}>{workflow.freshness === "current" ? "Selected · current" : "Selected · review required"}</Label>
      {workflow.freshness === "current" && workflow.change_plan && <><a href="#plan-inspection">Next safe step: {workflow.change_plan.preview_steps[0]?.title}</a><a href="#plan-rollback">View rollback</a></>}</section>}
    <section><h3><CogsIcon aria-hidden="true" /> Process</h3><strong>{valueText(diagnosis?.process_command) ?? valueText(detail.intelligence.resource_summary?.process_command) ?? (sameAccess ? valueText(access?.actor) : null) ?? "Process not recorded"}</strong><small>Domain <code>{detail.issue.source_type}</code></small></section>
    <section><h3><ResourceIcon objectClass={detail.issue.target_class} /> {detail.issue.target_class.endsWith("socket") ? "Observed target" : "Observed resource"}</h3><span className="context-resource">{resource ?? "Identity not established"}</span>
      <small>{detail.issue.target_class} · AVC label <code>{source?.observed_type ?? detail.issue.target_type}</code></small></section>
    <section><h3>Permission</h3><code>{detail.issue.permissions.join(", ")}</code></section>
    {diagnosis?.kind === "file_context_mismatch" && <section><h3>Expected for this path</h3><code>{diagnosis.expected_type ?? "Not available"}</code><small><ClockIcon aria-hidden="true" /> Checked after the denial</small></section>}
    {diagnosis?.kind === "conditional_allow_inactive" && <section><h3>Policy state at checkpoint</h3><span>{diagnosis.conditional_rules?.length ?? 0} relevant conditional paths</span><small>Current option states shown separately</small></section>}
    <section aria-label="Evidence scope"><h3>Finding coverage</h3><strong>{coverage ?? "Unknown"} of {detail.issue.occurrences_count} denials</strong>
      {detail.findings?.[0] && <small>{diagnosis?.kind === "file_context_mismatch" ? `${detail.findings[0].observation_count} inspection(s) · all labeling findings: ${detail.finding_coverage?.file_context_mismatch ?? coverage}` : `Shown resource: ${detail.findings[0].occurrence_count} denial(s)`}</small>}</section>
    <Button component="a" variant="link" href="#issue-technical-evidence" onClick={onShowTechnicalEvidence}>View technical evidence</Button>
  </aside>;
}
