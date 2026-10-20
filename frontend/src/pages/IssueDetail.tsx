import { Alert, Breadcrumb, BreadcrumbItem, Button, Card, CardBody, Label, Pagination, Spinner, TextInput, Title, Tooltip } from "@patternfly/react-core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import {
  fetchIssue,
  fetchIssueAnalysis,
  fetchIssueOccurrencePage,
  updateIssueDisposition,
  updateIssueStatus,
  type Diagnosis,
  type IssueDetailResponse,
  type OccurrenceDetail
} from "../api/issue";
import { EvidenceLink } from "../components/WorkbenchEvidence";
import { Disclosure as ExpandableSection } from "../components/Disclosure";
import { IssueTechnicalEvidence } from "../components/IssueTechnicalEvidence";
import { Table, Thead, Tbody, Tr, Th, Td } from "@patternfly/react-table";
import { ResolutionWorkflow } from "../components/ResolutionWorkflow";
import { StandardRestoration } from "../components/OperatorGuidance";
import { EMBEDDED_PAGE_SIZES, pageSize } from "../pagination";

const STATUS_OPTIONS = ["open", "resolved", "ignored"] as const;
const DISPOSITIONS = ["unclassified", "under_investigation", "expected_harmless", "application_configuration", "labeling_configuration", "policy_required", "possible_policy_package_defect", "suspicious_behavior"];
type Row = Record<string, unknown>;

function row(value: unknown): Row {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
}

function rows(value: unknown): Row[] {
  return Array.isArray(value) ? value.map(row) : [];
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function displayState(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatUtc(iso: string): string {
  return `${new Intl.DateTimeFormat("en", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: "UTC" }).format(new Date(iso))} UTC`;
}

function timeAgo(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  const units: [number, Intl.RelativeTimeFormatUnit][] = [[31_536_000, "year"], [2_592_000, "month"], [604_800, "week"], [86_400, "day"], [3_600, "hour"], [60, "minute"], [1, "second"]];
  const [size, unit] = units.find(([size]) => seconds >= size) ?? units.at(-1)!;
  return new Intl.RelativeTimeFormat("en", { numeric: "auto" }).format(-Math.round(seconds / size), unit);
}

function permissionLabel(permission: string): string {
  return ({
    name_connect: "network connection",
    name_bind: "local port bind",
    execute: "file execution",
    entrypoint: "execution entrypoint",
    read: "file read",
    write: "file write",
    getattr: "file metadata access"
  } as Record<string, string>)[permission] ?? permission.replaceAll("_", " ");
}

function networkValue(occurrences: OccurrenceDetail[], key: "dport_fields" | "dest_fields" | "bind_port_fields"): string | null {
  const port = (value: unknown): string | null => (typeof value === "string" || typeof value === "number") && /^\d+$/.test(String(value)) && Number(value) <= 65535 ? String(value) : null;
  for (const occurrence of occurrences) {
    const network = row(occurrence.normalized_denial.details.network_evidence);
    const raw = network[key];
    if (Array.isArray(raw)) {
      const found = raw.map((item) => port(typeof item === "object" ? row(item).value : item)).find(Boolean);
      if (found) return found;
    }
  }
  return null;
}

function resourceFor(issue: { target_class: string; target_type: string }, diagnosis: Diagnosis | null, occurrences: OccurrenceDetail[], paths: string[], names: string[], destinationPort?: string | null): string {
  if (diagnosis?.destination_port) return `TCP port ${diagnosis.destination_port} (destination)`;
  if (diagnosis?.bind_port) return `TCP port ${diagnosis.bind_port} (local bind)`;
  if (issue.target_class === "tcp_socket") {
    const port = destinationPort ?? networkValue(occurrences, diagnosis?.operation === "name_bind" ? "bind_port_fields" : "dport_fields") ?? networkValue(occurrences, "dest_fields");
    return port ? `TCP port ${port}${diagnosis?.operation === "name_bind" ? " (local bind)" : " (destination)"}` : "TCP socket; port not recorded";
  }
  const path = diagnosis?.path ?? paths[0];
  if (path) return path;
  if (names.length > 0) return `${names[0]} (complete path not recorded)`;
  return `${issue.target_class} labeled ${issue.target_type}`;
}

function practicalHeadline(issue: { source_type: string; target_type: string; target_class: string; permissions: string[] }, diagnosis: Diagnosis | null, occurrences: OccurrenceDetail[], paths: string[], names: string[], processCommand?: string | null, destinationPort?: string | null): string {
  const permission = diagnosis?.operation ?? diagnosis?.permissions?.[0] ?? issue.permissions[0] ?? "access";
  const diagnosisEvidence = row(diagnosis);
  const process = text(diagnosisEvidence.process_command) ?? occurrences.find((occurrence) => occurrence.normalized_denial.command)?.normalized_denial.command;
  const actor = process ?? processCommand ?? `The ${issue.source_type} domain`;
  const resource = resourceFor(issue, diagnosis, occurrences, paths, names, destinationPort);
  const blocked = diagnosisEvidence.syscall_failed === true && diagnosisEvidence.enforcement_mode === "enforcing";
  if (permission === "name_connect") return `${actor} was ${blocked ? "blocked from" : "denied permission for"} connecting to ${resource}.`;
  if (permission === "name_bind") return `${actor} was ${blocked ? "blocked from" : "denied permission for"} binding locally on ${resource}.`;
  if (permission === "execute") return blocked ? `${actor} could not execute ${resource}.` : `${actor} was denied permission to execute ${resource}.`;
  if (permission === "entrypoint") return blocked ? `${actor} could not start ${resource}.` : `${actor} was denied permission to start ${resource}.`;
  if (permission === "read") return `${actor} was denied reading ${resource}.`;
  if (permission === "write") return `${actor} was denied writing ${resource}.`;
  if (permission === "getattr") return blocked ? `${actor} was blocked from checking file metadata for ${resource}.` : `${actor} was denied file metadata access to ${resource}.`;
  return `${actor} was denied ${permissionLabel(permission)} on ${resource}.`;
}

function primaryFindingLead(diagnosis: Diagnosis): string | null {
  if (diagnosis.kind === "file_context_mismatch") return null;
  if (diagnosis.kind === "conditional_allow_inactive" && diagnosis.operation === "name_connect") {
    const count = rows(diagnosis.conditional_rules).length;
    return count > 1 ? `SELinux has ${count} conditional policy paths for this connection; their conditions were inactive at the associated host checkpoint.` : "SELinux has a conditional policy path for this connection, but its condition was inactive at the associated host checkpoint.";
  }
  if (diagnosis.kind === "conditional_allow_inactive") return diagnosis.operation === "read" ? "A matching SELinux read rule exists, but its condition was inactive at the associated host checkpoint." : "A matching SELinux allow path exists, but its condition was inactive at the associated host checkpoint.";
  if (diagnosis.kind === "no_matching_allow") {
    if (diagnosis.permissions?.includes("entrypoint")) return "The evaluated policy has no allow rule for this launch on the observed file label.";
    if (diagnosis.permissions?.includes("getattr")) return `The evaluated policy has no allow rule for checking metadata on this file labeled ${diagnosis.target_type ?? "the observed type"}.`;
    return `The evaluated policy has no allow rule for the denied ${permissionLabel(diagnosis.permissions?.[0] ?? "access")}.`;
  }
  return text(row(diagnosis).lead) ?? text(row(diagnosis).finding);
}

function issueHeadline(detail: IssueDetailResponse): string {
  const { issue, intelligence } = detail;
  if ((issue.signatures?.length ?? 0) > 1) return `${issue.source_type} access to ${issue.target_class} objects labeled ${issue.target_type}`;
  const summary = intelligence.resource_summary;
  if (["tcp_socket", "udp_socket"].includes(issue.target_class) && issue.permissions.includes("name_bind") && (summary?.bind_port_count ?? 0) > 0) {
    const protocol = issue.target_class === "udp_socket" ? "UDP" : "TCP";
    const ports = summary!.bind_ports?.map((item) => item.port).join(", ") ?? "";
    const more = Math.max(0, summary!.bind_port_count! - (summary!.bind_ports?.length ?? 0));
    return `${summary?.process_command ?? `The ${issue.source_type} domain`} was denied local ${protocol} binding on ${summary!.bind_port_count === 1 ? "port" : "ports"} ${ports}${more ? ` and ${more} more` : ""}${summary?.without_bind_port_occurrences ? "; some denial ports were not recorded" : ""}.`;
  }
  if (issue.target_class === "tcp_socket" && issue.permissions.includes("name_connect") && (summary?.destination_port_count ?? 0) > 1) return `${summary?.process_command ?? `The ${issue.source_type} domain`} was denied outbound TCP connections.`;
  if (issue.target_class === "file" && issue.permissions.length === 1 && issue.permissions[0] === "read" && (summary?.name_count ?? 0) > 1) return `${summary?.process_command ?? `The ${issue.source_type} domain`} was denied reading files labeled ${issue.target_type}.`;
  if ((summary?.path_count ?? 0) > 1 || (summary?.name_count ?? 0) > 1) return `${summary?.process_command ?? `The ${issue.source_type} domain`} was denied ${issue.permissions.map(permissionLabel).join(", ")} on ${issue.target_class} objects labeled ${issue.target_type}.`;
  return practicalHeadline(issue, detail.diagnosis, [], intelligence.paths, intelligence.names, summary?.process_command, summary?.destination_ports?.length === 1 ? summary.destination_ports[0].port : null);
}

function primaryLimitation(diagnosis: Diagnosis): string | null {
  if (diagnosis.kind === "file_context_mismatch") return "The expected label was checked shortly after the denial; it may not reflect the label configuration at that time.";
  if (diagnosis.kind === "conditional_allow_inactive" && diagnosis.operation === "execute") return "This denial does not establish that a domain transition was attempted or intended.";
  if (diagnosis.kind === "conditional_allow_inactive") return null;
  if (diagnosis.kind === "no_matching_allow" && diagnosis.permissions?.includes("entrypoint")) return "Audit evidence does not establish whether this launch is part of expected workload behavior.";
  if (diagnosis.kind === "no_matching_allow" && diagnosis.source_domain === "mysqld_t") return "SECentral cannot infer the intended database path or label from this denial.";
  if (diagnosis.kind === "no_matching_allow") return "No matching allow does not establish that this workload should receive the access.";
  return diagnosis.limitation;
}

function ContextComparison({ diagnosis }: { diagnosis: Diagnosis }) {
  return (
    <div className="issue-context-comparison" aria-label="Observed and expected file context comparison">
      <article>
        <h3>Label SELinux used <small>At the denial</small></h3>
        <code className="issue-context-type">{diagnosis.observed_type ?? "Not available"}</code>
      </article>
      <p className="issue-context-difference"><span aria-hidden="true">≠</span><small>Different types</small></p>
      <article>
        <h3>Expected for this path <small>Checked after the denial</small></h3>
        <code className="issue-context-type">{diagnosis.expected_type ?? "Not available"}</code>
      </article>
    </div>
  );
}

function BooleanCheckpointSummary({ diagnosis }: { diagnosis: Diagnosis }) {
  const conditions = rows(diagnosis.condition_boolean_states);
  const booleans = conditions.flatMap((condition) => rows(condition.booleans));
  const unique = [...new Map(booleans.map((boolean) => [text(boolean.name) ?? "Boolean", boolean])).values()];
  if (!unique.length) return <p className="issue-condition-summary">A conditional allow path was found; its boolean state is unavailable.</p>;
  return <section className="issue-condition-summary" aria-label="Possible policy paths"><ul>{unique.slice(0, 3).map((boolean) => <li key={text(boolean.name)}><code>{text(boolean.name) ?? "Boolean"}</code><Label color={boolean.current === false ? "orange" : "grey"} isCompact>{typeof boolean.current === "boolean" ? boolean.current ? "On" : "Off" : "Unavailable"}</Label></li>)}</ul><small>At the associated historical checkpoint{diagnosis.checkpoint_observed_at && ` · ${diagnosis.checkpoint_observed_at}`} · {conditions.length > 1 ? "independent alternatives" : "conditional path"}; not latest runtime state or proposed fixes</small></section>;
}

function DiagnosisEvidence({ diagnosis }: { diagnosis: Diagnosis }) {
  return <>
    {diagnosis.kind === "file_context_mismatch" && <ContextComparison diagnosis={diagnosis} />}
    {diagnosis.kind === "conditional_allow_inactive" && <ExpandableSection toggleText="Conditional policy paths"><BooleanCheckpointSummary diagnosis={diagnosis} /><EvidenceLink target="policy-evaluation-evidence">Inspect policy evaluation</EvidenceLink></ExpandableSection>}
  </>;
}

function LabelMismatchGuidance({ guidance }: { guidance: NonNullable<IssueDetailResponse["triage_guidance"]> }) {
  return <article className="issue-label-guidance">
    <Title headingLevel="h3" size="xl">{guidance.title}</Title>
    <p>Labeling may explain this access; the cause is not confirmed. Check the current object and configured context below.</p>
    <ExpandableSection toggleText="Why this investigation lead"><p>{guidance.summary}</p><p>{guidance.path_count} distinct qualifying paths; the investigation example is representative, not whole-issue coverage.</p></ExpandableSection>
  </article>;
}

function diagnosisVariantDetail(diagnosis: Diagnosis | null | undefined): string | null {
  if (!diagnosis) return "Cause not confirmed";
  let detail: string | null;
  if (diagnosis.kind === "file_context_mismatch") detail = [diagnosis.path, diagnosis.observed_type && `${diagnosis.observed_type} → ${diagnosis.expected_type ?? "expected type unavailable"}`].filter(Boolean).join(" · ");
  else if (diagnosis.kind === "conditional_allow_inactive") {
    const conditions = rows(diagnosis.condition_boolean_states).flatMap((condition) => rows(condition.booleans).map((boolean) => `${text(boolean.name) ?? "Boolean"} ${typeof boolean.current === "boolean" ? (boolean.current ? "On" : "Off") : "state unavailable"}`));
    detail = [diagnosis.operation && permissionLabel(diagnosis.operation), diagnosis.destination_port && `TCP destination ${diagnosis.destination_port}`, diagnosis.bind_port && `TCP bind ${diagnosis.bind_port}`, ...conditions].filter(Boolean).join(" · ");
  }
  else if (diagnosis.kind === "no_matching_allow") detail = `No matching allow for ${(diagnosis.permissions ?? []).join(", ")} on ${diagnosis.target_type ?? "target"}:${diagnosis.target_class ?? "class"}${diagnosis.path ? ` · example: ${diagnosis.path}` : ""}`;
  else detail = diagnosis.kind.replaceAll("_", " ");
  return detail;
}

function FindingCard({ detail }: { detail: IssueDetailResponse }) {
  const { issue, intelligence, diagnosis, triage_guidance, findings, policy_analysis } = detail;
  const lead = diagnosis ? primaryFindingLead(diagnosis) : null;
  const conditionalTitle = diagnosis?.kind === "conditional_allow_inactive" ? `${diagnosis.source_domain ?? issue.source_type} was denied ${diagnosis.operation === "name_bind" ? "binding" : diagnosis.operation === "name_connect" ? "connecting to" : diagnosis.operation === "read" ? "reading" : "executing"} ${diagnosis.path ?? (diagnosis.bind_port || diagnosis.destination_port ? `${issue.target_class === "udp_socket" ? "UDP" : "TCP"}/${diagnosis.bind_port ?? diagnosis.destination_port}` : `objects labeled ${diagnosis.target_type ?? issue.target_type}`)}.` : null;
  return <section aria-labelledby="finding-title" className="issue-section issue-primary-finding"><h2 id="finding-title">Diagnosis</h2>
    {policy_analysis.status !== "evaluated" && <p role="status">Policy analysis: {displayState(policy_analysis.status)}. Retained facts and local checks remain available; this is not a completed policy assessment.</p>}
     {!diagnosis && triage_guidance ? <LabelMismatchGuidance guidance={triage_guidance} /> : diagnosis ? <article>
      <Title headingLevel="h3" size="xl">{conditionalTitle ?? diagnosis.title}</Title>
      {lead && <p className="issue-finding-lead">{lead}</p>}
      {diagnosis.kind === "conditional_allow_inactive" && <p>Recorded target type: <code>{diagnosis.target_type ?? issue.target_type}</code></p>}
      <DiagnosisEvidence diagnosis={diagnosis} />
       {primaryLimitation(diagnosis) && <p className="issue-limitation"><strong>Limitation:</strong> {primaryLimitation(diagnosis)}</p>}
     </article> : <MissingExplanation issue={issue} paths={intelligence.paths} names={intelligence.names} hasFindings={(findings?.length ?? 0) > 0} policyAnalysis={policy_analysis} />}
  </section>;
}

function fleetSummary(state: string, affectedHosts: number): string {
  if (affectedHosts === 1) return ({
    consistent: "Same supported findings across recorded denials",
    disagreement: "Finding evidence varies between occurrences",
    partially_explained: "Some denials lack a supported finding",
    insufficient_evidence: "Some causes remain unconfirmed; use the investigation checks"
  } as Record<string, string>)[state] ?? "Occurrence findings unavailable";
  return ({
    consistent: "Same explanation across affected hosts",
    disagreement: "Explanations differ across affected hosts",
    partially_explained: "Some hosts are not fully explained",
    insufficient_evidence: "Some host causes remain unconfirmed; inspect their evidence"
  } as Record<string, string>)[state] ?? "Host explanations unavailable";
}

function MissingExplanation({
  issue,
  paths,
  names,
  hasFindings,
  policyAnalysis
}: {
  issue: { target_class: string; target_type: string };
  paths: string[];
  names: string[];
  hasFindings: boolean;
  policyAnalysis: IssueDetailResponse["policy_analysis"];
}) {
  const status = policyAnalysis.status;
  const limitations = policyAnalysis.limitations;
  const fileTarget = ["file", "dir", "fifo_file", "chr_file", "blk_file", "lnk_file", "sock_file"].includes(issue.target_class);
  const nextChecks = [
    ...(fileTarget && paths.length === 0 ? ["Identify the complete absolute path from the host or workload configuration before path-specific checks."] : []),
    ...(fileTarget && paths.length > 0 ? ["Review the path's configured expected context and why no event-linked inspection result is available."] : []),
    ...(status === "pending" ? ["Review the exact policy result after evaluation finishes."] : []),
    ...(["unavailable", "error"].includes(status) ? ["Confirm the occurrence's loaded policy identity and availability of its policy evidence."] : []),
    ...(!fileTarget && !["pending", "unavailable", "error"].includes(status) ? ["Review the retained AVC and the policy evidence for the associated occurrence."] : [])
  ];
  return (
    <div className="issue-unexplained" role="status">
      <p><strong>{hasFindings ? "Individual occurrences have findings; check their scope." : "Cause not confirmed; start with the checks below."}</strong></p>
      <p>SELinux recorded target label <code>{issue.target_type}</code> for this denied access.</p>
      {fileTarget && paths.length === 0 && <p><strong>No absolute path was retained.</strong> SECentral cannot compare the recorded label with expected path labeling without a complete path.</p>}
      <ExpandableSection toggleText="Retained evidence & analysis availability">
       {fileTarget && paths.length > 0 && <p>Observed paths: {paths.slice(0, 3).map((path) => <span key={path}><code>{path}</code> </span>)}</p>}
      {fileTarget && names.length > 0 && <p>Resource examples: {names.slice(0, 3).join(", ")}. Inspect occurrences for individual evidence.</p>}
      {fileTarget && paths.length > 0 && <p>No event-linked expected-context observation is available. Check current labeling on the host.</p>}
      {status === "pending" && <p>Policy evaluation is pending for the correlated occurrence.</p>}
      {status === "unavailable" && <p>Policy knowledge is unavailable for the correlated occurrence.</p>}
      {status === "error" && <p>Policy evaluation encountered an error; treat policy knowledge as unavailable until it can be checked.</p>}
      {limitations.map((limitation) => <p key={limitation}>{limitation.replaceAll("_", " ")}</p>)}
      {!status && limitations.length === 0 && <p>Review the occurrence evidence and policy availability for the affected host.</p>}
      <div className="issue-next-check"><h3>Check next</h3><ul>{nextChecks.map((check) => <li key={check}>{check}</li>)}</ul></div>
      </ExpandableSection>
    </div>
  );
}

function FleetSection({
  hostExplanations,
  fleet,
  relatedAnalysis,
  loadingRelated,
  relatedError,
  onRelatedToggle
}: {
  hostExplanations: IssueDetailResponse["host_explanations"];
  fleet: IssueDetailResponse["fleet_explanation"];
  relatedAnalysis: Awaited<ReturnType<typeof fetchIssueAnalysis>> | undefined;
  loadingRelated: boolean;
  relatedError: boolean;
  onRelatedToggle: (open: boolean) => void;
}) {
  const hypotheses = relatedAnalysis?.hypotheses.filter((hypothesis) => ["policy_version_correlation", "local_file_context_difference", "custom_policy_difference"].includes(hypothesis.kind)) ?? [];
  return (
    <section className="issue-fleet-section" aria-labelledby="issue-fleet-title">
      <header><div><h2 id="issue-fleet-title">Fleet Scope & Occurrences</h2><p>{fleet.affected_host_count} affected host{fleet.affected_host_count === 1 ? "" : "s"} · {fleetSummary(fleet.state, fleet.affected_host_count)}</p></div></header>
      <Table role="table" variant="compact" gridBreakPoint="grid-lg" aria-label="Finding distribution">
        <Thead><Tr><Th>Host</Th><Th><Tooltip content="Supported findings are evidence-backed explanations for occurrences, not verified root causes or successful remediation."><span tabIndex={0}>Finding coverage</span></Tooltip></Th><Th>Finding groups</Th><Th>Evidence</Th></Tr></Thead><Tbody>
        {hostExplanations.map((host) => {
          const groups = host.diagnosis_groups ?? [];
          const unexplained = host.unexplained_occurrence_count;
          const occurrenceSummary = host.status === "disagreement"
            ? `Mixed findings across ${host.occurrence_count} occurrences`
            : host.status === "insufficient_evidence"
              ? `${unexplained} of ${host.occurrence_count} occurrences lack a complete explanation`
              : `Same explanation across ${host.occurrence_count} occurrences`;
          return <Tr key={host.host_id}>
            <Td dataLabel="Host"><Link to={`/hosts/${host.host_id}`}>{host.hostname ?? `Host ${host.host_id}`}</Link></Td>
            <Td dataLabel="Finding coverage"><p>{host.occurrence_count - unexplained} with supported findings · {unexplained} without a complete explanation</p><small>{occurrenceSummary}</small></Td>
            <Td dataLabel="Finding groups"><ul>{groups.map((group, index) => <li key={index}>{diagnosisVariantDetail(group.diagnosis) ?? "Cause not confirmed"} · {group.count} occurrence{group.count === 1 ? "" : "s"}</li>)}</ul>
              {host.additional_diagnosis_group_count > 0 && <small>{host.additional_diagnosis_group_count} more groups; inspect occurrence records</small>}
            </Td>
            <Td dataLabel="Evidence"><EvidenceLink target={`host-evidence-${host.host_id}`} occurrenceId={host.diagnosis_groups[0]?.sample_occurrence_ids[0]}>View group evidence</EvidenceLink></Td>
          </Tr>;
        })}
      </Tbody></Table>
      {fleet.affected_host_count > 1 && <ExpandableSection className="issue-fleet-leads" toggleText="Fleet correlations" onToggle={(_event, open) => onRelatedToggle(open)}>
        {loadingRelated && <p>Checking supporting fleet evidence…</p>}
        {relatedError && <p>Fleet correlations could not be loaded.</p>}
        {!loadingRelated && !relatedError && hypotheses.length === 0 && <p>No fleet correlation is supported by the available evidence.</p>}
        {hypotheses.map((hypothesis) => (
        <article key={hypothesis.kind}>
          <h3>{hypothesis.label}</h3>
          {hypothesis.why && <p>{hypothesis.why}</p>}
          {hypothesis.supporting_evidence.map((item, index) => typeof item.fact === "string" && <p key={index}>{item.fact}</p>)}
          {hypothesis.does_not_prove && <p><strong>Does not prove:</strong> {hypothesis.does_not_prove}</p>}
          {hypothesis.confirmation && <p><strong>Check next:</strong> {hypothesis.confirmation}</p>}
          {hypothesis.temporal_scope && <small>Evidence scope: {displayState(hypothesis.temporal_scope)}</small>}
        </article>
      ))}
      </ExpandableSection>}
    </section>
  );
}

export function IssueDetail() {
  const { id } = useParams();
  const issueId = Number(id);
  const validId = Number.isInteger(issueId) && issueId > 0;
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const detailQuery = useQuery({ queryKey: ["issue", issueId], queryFn: () => fetchIssue(issueId), enabled: validId });
  const showOccurrences = searchParams.get("tab") === "occurrences";
  const setShowOccurrences = (open: boolean) => setSearchParams((previous) => {
    const next = new URLSearchParams(previous); if (open) next.set("tab", "occurrences"); else next.delete("tab"); return next;
  });
  const [showRelatedFleet, setShowRelatedFleet] = useState(false);
  const [technicalEvidenceIssueId, setTechnicalEvidenceIssueId] = useState<number | null>(null);
  const evidenceTarget = searchParams.get("evidence");
  const showTechnicalEvidence = technicalEvidenceIssueId === issueId || !!evidenceTarget || !!searchParams.get("evidence_tab");
  useEffect(() => {
    if (!evidenceTarget) return;
    const target = document.getElementById(evidenceTarget) ?? document.getElementById("issue-technical-evidence");
    target?.focus();
    target?.scrollIntoView?.({ block: "start" });
  }, [evidenceTarget, detailQuery.dataUpdatedAt]);
  const requestedPage = Number(searchParams.get("occurrence_page") ?? 1);
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
  const perPage = pageSize(searchParams.get("occurrence_limit"), EMBEDDED_PAGE_SIZES, 10);
  const signatureFilter = searchParams.get("signature_id");
  const occurrencesQuery = useQuery({ queryKey: ["issue-occurrence-page", issueId, page, perPage, signatureFilter], queryFn: () => fetchIssueOccurrencePage(issueId, page, perPage, signatureFilter), enabled: validId && showOccurrences });
  const showSignatureOccurrences = (signatureId: number | null) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", "occurrences"); next.set("occurrence_page", "1");
    if (signatureId === null) next.delete("signature_id"); else next.set("signature_id", String(signatureId));
    setSearchParams(next);
  };
  const setOccurrencePage = (nextPage: number, size = perPage) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", "occurrences");
    next.set("occurrence_page", String(nextPage));
    next.set("occurrence_limit", String(size));
    setSearchParams(next);
  };
  const inspectOccurrence = (occurrenceId: number) => {
    setSearchParams((previous) => { const next = new URLSearchParams(previous); next.delete("phase"); next.set("evidence", "audit-evidence"); next.set("evidence_tab", "audit"); next.set("evidence_occurrence", String(occurrenceId)); return next; });
  };
  const analysisQuery = useQuery({ queryKey: ["issue-analysis", issueId], queryFn: () => fetchIssueAnalysis(issueId), enabled: validId && showRelatedFleet });
  const [pendingDisposition, setPendingDisposition] = useState<string | null>(null);
  const [dispositionNote, setDispositionNote] = useState("");
  const [savingStatus, setSavingStatus] = useState(false);
  const [savingDisposition, setSavingDisposition] = useState(false);
  const [workflowError, setWorkflowError] = useState<string | null>(null);
  const [showKeepRestriction, setShowKeepRestriction] = useState(false);
  const [acknowledgementSaved, setAcknowledgementSaved] = useState(false);

  const changeStatus = async (status: typeof STATUS_OPTIONS[number], signatureIds = detailQuery.data?.issue.signatures?.map((signature) => signature.id) ?? []) => {
    setSavingStatus(true);
    setWorkflowError(null);
    try {
      await updateIssueStatus(issueId, status, signatureIds);
      await queryClient.invalidateQueries({ queryKey: ["issue", issueId] });
    } catch (error) {
      setWorkflowError(error instanceof Error ? error.message : "Could not update status");
    } finally {
      setSavingStatus(false);
    }
  };

  const applyDisposition = async (keepRestriction = false) => {
    const issue = detailQuery.data?.issue;
    if (!issue) return;
    setSavingDisposition(true);
    setWorkflowError(null);
    try {
      const signatures = issue.signatures ?? [];
      if (keepRestriction) {
        await Promise.all(signatures.map((signature) => updateIssueDisposition(issueId, signature.disposition, [signature.id], dispositionNote.trim() || undefined)));
      } else {
        await updateIssueDisposition(issueId, pendingDisposition ?? issue.disposition, signatures.map((signature) => signature.id), dispositionNote.trim() || undefined);
      }
      await queryClient.invalidateQueries({ queryKey: ["issue", issueId] });
      setPendingDisposition(null);
      setDispositionNote("");
      if (keepRestriction) setAcknowledgementSaved(true);
    } catch (error) {
      setWorkflowError(error instanceof Error ? error.message : "Could not update disposition");
    } finally {
      setSavingDisposition(false);
    }
  };

  const changeSignatureDisposition = async (signatureId: number, value: string) => {
    setSavingDisposition(true);
    setWorkflowError(null);
    try {
      await updateIssueDisposition(issueId, value, [signatureId]);
      await queryClient.invalidateQueries({ queryKey: ["issue", issueId] });
    } catch (error) {
      setWorkflowError(error instanceof Error ? error.message : "Could not update signature disposition");
    } finally {
      setSavingDisposition(false);
    }
  };

  if (!validId) return <Alert variant="danger" isInline title="Invalid issue id"><Link to="/issues">Back to issues</Link></Alert>;
  if (detailQuery.isError) {
    const error = detailQuery.error;
    return error instanceof ApiError && error.status === 404
      ? <Alert variant="danger" isInline title="Issue not found">This issue does not exist. <Link to="/issues">Back to issues</Link></Alert>
      : <Alert variant="danger" isInline title="Could not load issue">{error instanceof Error ? error.message : "Unknown error"}</Alert>;
  }
  if (detailQuery.isPending) return <div aria-label="Loading issue" className="issue-loading"><Spinner size="xl" /></div>;

  const { issue, intelligence, diagnosis, triage, host_explanations, fleet_explanation, policy_analysis, findings, additional_finding_count } = detailQuery.data;
  const disposition = pendingDisposition ?? issue.disposition;

  return (
    <div className="issue-investigation">
      <Breadcrumb aria-label="Breadcrumb" className="pf-v6-u-mb-sm"><BreadcrumbItem><Link to="/issues">SELinux issues</Link></BreadcrumbItem><BreadcrumbItem isActive>Issue #{issue.id}</BreadcrumbItem></Breadcrumb>
      <header className="issue-investigation-header">
        <div>
           <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">{issueHeadline(detailQuery.data)}</Title>
          <p className="issue-operation-label">{issue.occurrences_count.toLocaleString()} denial{issue.occurrences_count === 1 ? "" : "s"} · {issue.affected_hosts} server{issue.affected_hosts === 1 ? "" : "s"}{(intelligence.resource_summary?.name_count ?? 0) > 1 && ` · ${intelligence.resource_summary!.name_count.toLocaleString()} filenames`} · First {timeAgo(issue.first_seen_at)} · Last {timeAgo(issue.last_seen_at)}</p>
          {(intelligence.resource_summary?.destination_ports?.length ?? 0) > 0 && <p className="issue-operation-label">Recorded destination ports: {intelligence.resource_summary!.destination_ports!.map((item) => `TCP/${item.port} (${item.occurrence_count} denial${item.occurrence_count === 1 ? "" : "s"})`).join(" · ")}{intelligence.resource_summary!.destination_port_count! > 3 && ` · ${intelligence.resource_summary!.destination_port_count! - 3} more ports`}</p>}
        </div>
        <div className="issue-workflow">
          <Label color={issue.display_status === "resolved" ? "green" : issue.display_status === "ignored" ? "grey" : issue.display_status === "regressed" ? "orange" : "blue"}>{displayState(issue.display_status)}</Label>
          <ExpandableSection toggleText={`Actions · ${displayState(issue.disposition)}`}>
            <div className="issue-workflow-panel">
              {workflowError && <Alert variant="danger" isInline title="Workflow update failed">{workflowError}</Alert>}
              <p>Applies to all signatures currently shown. Future signatures require a new review.</p>
              <label>Lifecycle status<select aria-label="Issue status" value={issue.status} disabled={savingStatus} onChange={(event) => void changeStatus(event.target.value as typeof STATUS_OPTIONS[number])}>{STATUS_OPTIONS.map((status) => <option key={status} value={status}>{displayState(status)}</option>)}</select></label>
              <label>Operator disposition<select aria-label="Operator disposition" value={disposition} onChange={(event) => setPendingDisposition(event.target.value)}>{issue.disposition === "mixed" && <option value="mixed" disabled>Mixed — review signatures</option>}{DISPOSITIONS.map((item) => <option key={item} value={item}>{displayState(item)}</option>)}</select></label>
              <TextInput value={dispositionNote} onChange={(_event, value) => setDispositionNote(value)} aria-label="Disposition note" placeholder="Note (optional)" />
              <Button variant="primary" isDisabled={savingDisposition || disposition === "mixed" || (disposition === issue.disposition && !dispositionNote.trim())} onClick={() => void applyDisposition()}>{savingDisposition ? "Applying…" : "Save disposition"}</Button>
            </div>
          </ExpandableSection>
          <Button variant="secondary" onClick={() => setShowKeepRestriction(!showKeepRestriction)} isExpanded={showKeepRestriction} aria-controls="restriction-note">Keep restriction</Button>
          <ResolutionWorkflow issueId={issueId} stage="actions" initialData={detailQuery.data.resolutions} initialDataUpdatedAt={detailQuery.dataUpdatedAt} />
          {showKeepRestriction && <section id="restriction-note" aria-label="Keep restriction" className="issue-workflow-panel">
            <p>Record why this access should remain denied. This saves a note without declaring it harmless, changing policy or marking the issue resolved.</p>
            {workflowError && <Alert variant="danger" isInline title="Could not save acknowledgement">{workflowError}</Alert>}
            <TextInput aria-label="Restriction note" value={dispositionNote} onChange={(_event, value) => { setDispositionNote(value); setAcknowledgementSaved(false); }} />
            <Button variant="secondary" isDisabled={savingDisposition || !dispositionNote.trim()} onClick={() => void applyDisposition(true)}>Save acknowledgement</Button>
            {acknowledgementSaved && <p role="status">Acknowledgement saved. Restriction and lifecycle status unchanged.</p>}
          </section>}
        </div>
      </header>

      {(issue.signatures?.length ?? 0) > 0 && <Card isCompact><CardBody>
        <Title headingLevel="h2" size="lg">Permission signatures</Title>
        <p>This relationship groups related evidence, not a confirmed shared cause. Review operations independently; permissions below are exact observed sets unless marked historical.</p>
        {workflowError && <Alert variant="danger" isInline title="Signature update failed">{workflowError}</Alert>}
        <Table role="table" variant="compact" gridBreakPoint="grid-lg" aria-label="Permission signatures"><Thead><Tr><Th>Permissions</Th><Th>Occurrences</Th><Th>Hosts</Th><Th>Status</Th><Th>Disposition</Th></Tr></Thead><Tbody>
          {issue.signatures.map((signature) => <Tr key={signature.id}>
            <Td dataLabel="Permissions"><code>{signature.permissions.join(", ")}</code>{signature.legacy && <Label isCompact>Historical fingerprint</Label>}</Td>
            <Td dataLabel="Occurrences"><Button variant="link" onClick={() => showSignatureOccurrences(signature.id)} aria-label={`View ${signature.permissions.join(", ")} signature ${signature.id} occurrences`}>{signature.occurrences_count}</Button></Td><Td dataLabel="Hosts">{signature.affected_hosts}</Td>
            <Td dataLabel="Status"><select aria-label={`Status for ${signature.permissions.join(", ")} signature ${signature.id}`} value={signature.status} disabled={savingStatus} onChange={(event) => void changeStatus(event.target.value as typeof STATUS_OPTIONS[number], [signature.id])}>{STATUS_OPTIONS.map((status) => <option key={status} value={status}>{displayState(status)}</option>)}</select></Td>
            <Td dataLabel="Disposition"><select aria-label={`Disposition for ${signature.permissions.join(", ")} signature ${signature.id}`} value={signature.disposition} disabled={savingDisposition} onChange={(event) => void changeSignatureDisposition(signature.id, event.target.value)}>{DISPOSITIONS.map((value) => <option key={value} value={value}>{displayState(value)}</option>)}</select></Td>
          </Tr>)}
        </Tbody></Table>
      </CardBody></Card>}

      <ResolutionWorkflow issueId={issueId} stage="draft" initialData={detailQuery.data.resolutions} initialDataUpdatedAt={detailQuery.dataUpdatedAt} />

      <div className="issue-workbench">
      <div className="issue-workspace">
      <ResolutionWorkflow issueId={issueId} stage="observed" initialData={detailQuery.data.resolutions} initialDataUpdatedAt={detailQuery.dataUpdatedAt} detail={detailQuery.data} />

      <Card isCompact><CardBody>
        <FindingCard detail={detailQuery.data} />
      </CardBody></Card>

      <ResolutionWorkflow issueId={issueId} stage="intent" initialData={detailQuery.data.resolutions} initialDataUpdatedAt={detailQuery.dataUpdatedAt} detail={detailQuery.data}>
        {!diagnosis && detailQuery.data.triage_guidance ? <StandardRestoration detail={detailQuery.data} /> : undefined}
      </ResolutionWorkflow>
      </div>
      <ResolutionWorkflow issueId={issueId} stage="context" initialData={detailQuery.data.resolutions} initialDataUpdatedAt={detailQuery.dataUpdatedAt} detail={detailQuery.data} onShowTechnicalEvidence={() => setTechnicalEvidenceIssueId(issueId)} />
      </div>

      {((findings?.length ?? 0) > 1 || (issue.target_class === "file" && (intelligence.resource_summary?.without_absolute_path_occurrences ?? 0) > 0) || (additional_finding_count ?? 0) > 0 || policy_analysis.limitations.length > 0) && <ExpandableSection className="workbench-additional" toggleText="Findings & evidence gaps"><section aria-label="Findings & evidence gaps" className="issue-section">
        {findings?.slice(1).map((finding, index) => <ExpandableSection key={index} toggleText={`${finding.diagnosis.title} · ${finding.occurrence_count.toLocaleString()} denials`}><p>{primaryFindingLead(finding.diagnosis) ?? text(row(finding.diagnosis).finding)}</p><DiagnosisEvidence diagnosis={finding.diagnosis} /><p><strong>Check next:</strong> {finding.diagnosis.next_step}</p><p>{primaryLimitation(finding.diagnosis)}</p><EvidenceLink target="policy-evaluation-evidence">Technical evidence for this finding</EvidenceLink></ExpandableSection>)}
        {issue.target_class === "file" && (intelligence.resource_summary?.without_absolute_path_occurrences ?? 0) > 0 && <div><h3>Path-based label check unavailable</h3><p>{intelligence.resource_summary!.without_absolute_path_occurrences.toLocaleString()} of {issue.occurrences_count.toLocaleString()} denials contain filenames but no complete filesystem path. SECentral cannot determine whether <code>{issue.target_type}</code> is the expected label for those files.</p></div>}
        {(additional_finding_count ?? 0) > 0 && <p>{additional_finding_count} finding variant(s) not shown. Inspect host and occurrence evidence for their coverage.</p>}
         {diagnosis && policy_analysis.limitations.length > 0 && <div><p>Some occurrence policy assessments have limitations. These describe occurrence assessments, not the eligibility of a separate reviewed plan.</p><ul>{policy_analysis.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul><p>Unconfirmed occurrence examples: {host_explanations.flatMap((host) => host.diagnosis_groups.filter((group) => !group.diagnosis).flatMap((group) => group.sample_occurrence_ids.map((id) => <Link key={`${host.host_id}-${id}`} to={`/hosts/${host.host_id}/occurrences/${id}`}>{host.hostname} · #{id} </Link>)))}</p></div>}
      </section></ExpandableSection>}

      <Card isCompact className="issue-fleet-occurrences"><CardBody>
      <FleetSection
        hostExplanations={host_explanations}
        fleet={fleet_explanation}
        relatedAnalysis={analysisQuery.data}
        loadingRelated={analysisQuery.isPending && showRelatedFleet}
        relatedError={analysisQuery.isError}
        onRelatedToggle={setShowRelatedFleet}
      />

      {triage.signals.length > 0 && <ExpandableSection className="issue-activity-context" toggleText="Occurrence pattern"><ul>{triage.signals.map((signal) => <li key={signal.code}><strong>{signal.label}:</strong> {signal.explanation}</li>)}</ul></ExpandableSection>}

      <section id="issue-occurrences" tabIndex={-1} aria-labelledby="occurrences-title" className="issue-section issue-occurrences-section">
        {signatureFilter && <p>Showing signature #{signatureFilter}. <Button variant="link" onClick={() => showSignatureOccurrences(null)}>Show all signatures</Button></p>}
        <header><div><h3 id="occurrences-title">Retained occurrences</h3><p>{issue.occurrences_count} retained denial{issue.occurrences_count === 1 ? "" : "s"}{occurrencesQuery.data && ` · ${(occurrencesQuery.data.meta.page - 1) * occurrencesQuery.data.meta.page_size + (occurrencesQuery.data.meta.total ? 1 : 0)}–${Math.min(occurrencesQuery.data.meta.page * occurrencesQuery.data.meta.page_size, occurrencesQuery.data.meta.total)} of ${occurrencesQuery.data.meta.total}`}</p></div></header>
        {!showOccurrences ? <Button variant="secondary" onClick={() => setShowOccurrences(true)}>Show recent occurrences</Button>
          : occurrencesQuery.isPending ? <div aria-label="Loading occurrences"><Spinner /></div>
          : occurrencesQuery.isError ? <Alert variant="warning" isInline title="Could not load occurrences">{occurrencesQuery.error instanceof Error ? occurrencesQuery.error.message : "Unknown error"}</Alert>
            : occurrencesQuery.data.occurrences.length ? <>
              <Table role="table" variant="compact" gridBreakPoint="grid-lg" aria-label="Occurrence summary"><Thead><Tr><Th>Time (UTC)</Th><Th>Host</Th><Th>Resource</Th><Th>Permissions</Th><Th>SELinux mode</Th><Th>Syscall outcome</Th>{!issue.target_class.endsWith("_socket") && <Th>Path evidence</Th>}<Th>Inspect</Th></Tr></Thead><Tbody>{occurrencesQuery.data.occurrences.map((item) => <Tr key={item.id}><Td dataLabel="Time (UTC)">{formatUtc(item.occurred_at)}</Td><Td dataLabel="Host"><Link to={`/hosts/${item.host.id}`}>{item.host.hostname}</Link></Td><Td dataLabel="Resource"><code>{item.resource ?? "Not recorded"}</code></Td><Td dataLabel="Permissions">{item.permissions.join(", ")}</Td><Td dataLabel="SELinux mode">{displayState(item.enforcement_mode ?? "unknown")}</Td><Td dataLabel="Syscall outcome">{displayState(item.syscall_outcome ?? "unknown")}</Td>{!issue.target_class.endsWith("_socket") && <Td dataLabel="Path evidence">{item.absolute_path ? "Absolute path" : item.resource ? "Basename only" : "Not recorded"}</Td>}<Td dataLabel="Inspect"><Button variant="link" onClick={() => inspectOccurrence(item.id)} aria-label={`Inspect occurrence ${item.id}`}>View evidence</Button></Td></Tr>)}</Tbody></Table>
              <div className="table-pagination"><Pagination itemCount={occurrencesQuery.data.meta.total} page={occurrencesQuery.data.meta.page} perPage={occurrencesQuery.data.meta.page_size}
                perPageOptions={EMBEDDED_PAGE_SIZES.map((value) => ({ title: String(value), value }))} titles={{ paginationAriaLabel: "Issue occurrence pagination" }}
                isDisabled={occurrencesQuery.isFetching} onSetPage={(_event, value) => setOccurrencePage(value)} onPerPageSelect={(_event, size) => setOccurrencePage(1, size)} /></div>
              <Button className="pf-v6-u-mt-md" variant="link" onClick={() => setShowOccurrences(false)}>Hide occurrences</Button></>
              : <p>No occurrences are retained for this issue.</p>}
      </section>
      </CardBody></Card>

      <ExpandableSection id="issue-technical-evidence" tabIndex={-1} className="issue-advanced-details" toggleText="Technical details & audit provenance" isExpanded={showTechnicalEvidence} onToggle={(_event, expanded) => {
        setTechnicalEvidenceIssueId(expanded ? issueId : null);
        if (!expanded && (evidenceTarget || searchParams.has("evidence_tab"))) { const next = new URLSearchParams(searchParams); next.delete("evidence"); next.delete("evidence_tab"); setSearchParams(next); }
      }}>
        {showTechnicalEvidence && <IssueTechnicalEvidence detail={detailQuery.data} updatedAt={detailQuery.dataUpdatedAt} />}
      </ExpandableSection>
    </div>
  );
}
