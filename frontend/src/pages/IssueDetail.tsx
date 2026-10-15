import { Alert, Breadcrumb, BreadcrumbItem, Button, ExpandableSection, Label, Pagination, Spinner, TextInput, Title } from "@patternfly/react-core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import {
  fetchIssue,
  fetchIssueAnalysis,
  fetchIssueOccurrencePage,
  fetchIssueOccurrence,
  updateIssueDisposition,
  updateIssueStatus,
  type Diagnosis,
  type IssueDetailResponse,
  type OccurrenceDetail
} from "../api/issue";
import { OccurrenceRawEvidence } from "../components/OccurrenceEvidence";
import { ResolutionWorkflow } from "../components/ResolutionWorkflow";
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

function namesFromOccurrences(occurrences: OccurrenceDetail[]): string[] {
  return [...new Set(occurrences.flatMap((occurrence) => {
    const names = row(occurrence.normalized_denial.details.target_evidence).object_names;
    return Array.isArray(names) ? names.filter((name): name is string => typeof name === "string") : [];
  }))];
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
  const blocked = diagnosisEvidence.syscall_failed === true || diagnosis?.title.toLowerCase().includes("blocked") === true;
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

function primaryLimitation(diagnosis: Diagnosis): string {
  if (diagnosis.kind === "file_context_mismatch") return "The expected label was checked shortly after the denial; it may not reflect the label configuration at that time.";
  if (diagnosis.kind === "conditional_allow_inactive" && diagnosis.operation === "execute") return "This denial does not establish that a domain transition was attempted or intended.";
  if (diagnosis.kind === "conditional_allow_inactive") return "Checkpoint boolean state does not tell us whether this workload should have this capability.";
  if (diagnosis.kind === "no_matching_allow" && diagnosis.permissions?.includes("entrypoint")) return "Audit evidence does not establish whether this launch is part of expected workload behavior.";
  if (diagnosis.kind === "no_matching_allow" && diagnosis.source_domain === "mysqld_t") return "SECentral cannot infer the intended database path or label from this denial.";
  if (diagnosis.kind === "no_matching_allow") return "No matching allow does not establish that this workload should receive the access.";
  return diagnosis.limitation;
}

function EvidenceFacts({ diagnosis }: { diagnosis: Diagnosis }) {
  const facts = rows((diagnosis as Row).evidence).filter((item) => text(item.fact));
  if (!facts.length) return null;
  return (
    <section aria-label="Evidence supporting this finding" className="issue-evidence-facts">
      <h3>Why this finding</h3>
      <ul>{facts.map((fact, index) => <li key={index}>{String(fact.fact)} <small>{fact.certainty === "derived" ? "Derived from correlated evidence" : "Observed evidence"}</small></li>)}</ul>
    </section>
  );
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

function PolicyConditions({ diagnosis }: { diagnosis: Diagnosis }) {
  const conditionRows = rows(diagnosis.condition_boolean_states);
  const rules = rows(diagnosis.conditional_rules);
  if (!conditionRows.length && !rules.length) return <p>Conditional-rule or boolean-state detail is not available for this finding.</p>;
  const conditions = conditionRows.length ? conditionRows : rules;
  return (
    <div className="issue-policy-conditions">
      {conditions.map((condition, index) => {
        const expression = text(condition.expression);
        const rule = text(condition.rule);
        const booleans = rows(condition.booleans);
        return (
          <article key={`${rule ?? expression ?? "condition"}-${index}`}>
            <div className="issue-policy-condition-header">
              <strong>{expression ?? rule ?? "Conditional allow rule"}</strong>
              <Label color={condition.state === "inactive" ? "orange" : condition.state === "active" ? "green" : "grey"} isCompact>{text(condition.state) ? displayState(String(condition.state)) : "State unavailable"}</Label>
            </div>
            {booleans.length > 0 ? (
              <ul>{booleans.map((boolean, booleanIndex) => {
                const name = text(boolean.name) ?? "Boolean";
                const current = typeof boolean.current === "boolean" ? (boolean.current ? "On" : "Off") : text(boolean.status) ? displayState(String(boolean.status)) : "Unavailable";
                return <li key={`${name}-${booleanIndex}`}><code>{name}</code>: {current}{text(boolean.description) && <> — {String(boolean.description)}</>}</li>;
              })}</ul>
            ) : <p>Boolean state for this condition was not available.</p>}
            {rule && (["read", "name_connect"].includes(diagnosis.operation ?? "") ? <pre>{rule}</pre> : <details><summary>Exact SELinux allow rule</summary><pre>{rule}</pre></details>)}
          </article>
        );
      })}
      {!conditionRows.length && rules.filter((rule) => text(rule.rule)).map((rule, index) => <details key={`rule-${index}`}><summary>Exact SELinux allow rule</summary><pre>{String(rule.rule)}</pre></details>)}
    </div>
  );
}

function PolicyEvaluations({ diagnosis }: { diagnosis: Diagnosis }) {
  const evaluations = rows((diagnosis as Row).evaluations);
  if (!evaluations.length) return null;
  return <details className="issue-technical-details"><summary>Policy evaluation evidence</summary>{evaluations.map((evaluation, index) => (
    <article key={index}>
      <p>{Array.isArray(evaluation.permissions) ? evaluation.permissions.join(", ") : "Denied permission"}: <strong>{text(evaluation.result) ?? "state unavailable"}</strong></p>
      {text(evaluation.policy_identity) && <p>Policy identity <code>{String(evaluation.policy_identity)}</code></p>}
      {text(evaluation.evaluator_version) && <p>Evaluator version <code>{String(evaluation.evaluator_version)}</code></p>}
      {Array.isArray(evaluation.matching_rules) && evaluation.matching_rules.length > 0
        ? <ul>{evaluation.matching_rules.map((rule, ruleIndex) => <li key={ruleIndex}><code>{typeof rule === "string" ? rule : JSON.stringify(rule)}</code></li>)}</ul>
        : <p>No matching allow rule was returned for this permission.</p>}
      {Array.isArray(evaluation.limitations) && evaluation.limitations.map((limitation, limitationIndex) => <p key={limitationIndex}>{String(limitation)}</p>)}
    </article>
  ))}</details>;
}

function PolicyProvenance({ diagnosis }: { diagnosis: Diagnosis }) {
  const values = row(diagnosis);
  const identity = text(values.policy_identity);
  const checkpoint = text(values.checkpoint_observed_at);
  if (!identity && !checkpoint) return null;
  return <details className="issue-policy-provenance">
    <summary>Policy provenance</summary>
    <dl className="issue-technical-facts">
      {identity && <div><dt>Policy identity at checkpoint</dt><dd><code>{identity}</code></dd></div>}
      {checkpoint && <div><dt>Associated host checkpoint</dt><dd><time dateTime={checkpoint}>{checkpoint}</time></dd></div>}
    </dl>
    {checkpoint && <p>This is checkpoint evidence, not a measurement made at AVC time.</p>}
  </details>;
}

function BooleanCheckpointSummary({ diagnosis }: { diagnosis: Diagnosis }) {
  const conditions = rows(diagnosis.condition_boolean_states);
  const booleans = conditions.flatMap((condition) => rows(condition.booleans));
  const unique = [...new Map(booleans.map((boolean) => [text(boolean.name) ?? "Boolean", boolean])).values()];
  if (!unique.length) return <p className="issue-condition-summary">A conditional allow path was found; its boolean state is unavailable.</p>;
  return <section className="issue-condition-summary" aria-label="Possible policy paths"><ul>{unique.slice(0, 3).map((boolean) => <li key={text(boolean.name)}><code>{text(boolean.name) ?? "Boolean"}</code><Label color={boolean.current === false ? "orange" : "grey"} isCompact>{typeof boolean.current === "boolean" ? boolean.current ? "On" : "Off" : "Unavailable"}</Label></li>)}</ul><small>At the associated checkpoint · {conditions.length > 1 ? "independent alternatives" : "conditional path"}</small></section>;
}

function DiagnosisEvidence({ diagnosis }: { diagnosis: Diagnosis }) {
  return <>
    {diagnosis.kind === "file_context_mismatch" && <ContextComparison diagnosis={diagnosis} />}
    {diagnosis.kind === "conditional_allow_inactive" && <BooleanCheckpointSummary diagnosis={diagnosis} />}
  </>;
}

function DiagnosisTechnicalEvidence({ diagnosis }: { diagnosis: Diagnosis }) {
  const kind = diagnosis.kind;
  return (
      <section className="issue-selinux-explanation" aria-label="SELinux explanation">
        {kind === "file_context_mismatch" && <section className="issue-context-evidence"><h3>Full labeling evidence</h3>
          {diagnosis.path && <p className="issue-context-path">Path <code>{diagnosis.path}</code>{diagnosis.file_type && <> · {diagnosis.file_type}</>}</p>}
          <p>AVC context <code className="issue-full-context">{diagnosis.observed_context ?? "Not recorded"}</code></p>
          <p>Expected context <code className="issue-full-context">{diagnosis.expected_context ?? "Not available"}</code></p>
          {diagnosis.expected_context_observed_at && <p>Exact inspection time <time dateTime={diagnosis.expected_context_observed_at}>{diagnosis.expected_context_observed_at}</time></p>}
        </section>}
        {kind === "conditional_allow_inactive" && <>
          {diagnosis.operation === "name_connect" && <p>These are independent rules, not a requirement to enable every listed setting. Values come from the associated checkpoint.</p>}
          {diagnosis.operation === "read" && <p>Under the recorded checkpoint state, this conditional rule did not provide the denied read permission. That does not establish the expected filesystem label or the only reason for the workload failure.</p>}
          {diagnosis.operation === "name_connect" && <p><code>name_connect</code> controls connecting a socket to a labeled network port. Under the recorded checkpoint state, the matching conditional rules did not provide this permission. That does not establish workload intent or the only reason for the failure. Destination address and service identity are not established by this finding.</p>}
          <p className="issue-denial-tuple">
            <code>{diagnosis.source_domain ?? "Source type not recorded"}</code> → <code>{diagnosis.operation ?? diagnosis.permissions?.[0] ?? "Permission not recorded"}</code> → <code>{diagnosis.target_type ?? "Target type not recorded"}:{diagnosis.target_class ?? "Object class not recorded"}</code>
            {diagnosis.destination_port && <> · TCP destination <code>{diagnosis.destination_port}</code></>}
            {diagnosis.bind_port && <> · TCP bind <code>{diagnosis.bind_port}</code></>}
          </p>
          <section aria-label="Conditional rule evidence"><h3>Conditional policy path</h3><PolicyConditions diagnosis={diagnosis} /></section>
        </>}
        {kind === "no_matching_allow" && <p className="issue-denial-tuple"><code>{diagnosis.source_domain ?? "Source type"}</code> → <code>{diagnosis.permissions?.join(", ") ?? "Denied permission"}</code> → <code>{diagnosis.target_type ?? "Target type"}:{diagnosis.target_class ?? "Object class"}</code></p>}
        <EvidenceFacts diagnosis={diagnosis} />
        <PolicyEvaluations diagnosis={diagnosis} />
        {(kind === "conditional_allow_inactive" || kind === "no_matching_allow") && <PolicyProvenance diagnosis={diagnosis} />}
      </section>
  );
}

function diagnosisVariantDetail(diagnosis: Diagnosis | null | undefined): string | null {
  if (!diagnosis) return "No evidence-backed explanation";
  let detail: string | null;
  if (diagnosis.kind === "file_context_mismatch") detail = [diagnosis.path, diagnosis.observed_type && `${diagnosis.observed_type} → ${diagnosis.expected_type ?? "expected type unavailable"}`].filter(Boolean).join(" · ");
  else if (diagnosis.kind === "conditional_allow_inactive") {
    const conditions = rows(diagnosis.condition_boolean_states).flatMap((condition) => rows(condition.booleans).map((boolean) => `${text(boolean.name) ?? "Boolean"} ${typeof boolean.current === "boolean" ? (boolean.current ? "On" : "Off") : "state unavailable"}`));
    detail = [diagnosis.operation && permissionLabel(diagnosis.operation), diagnosis.destination_port && `TCP destination ${diagnosis.destination_port}`, diagnosis.bind_port && `TCP bind ${diagnosis.bind_port}`, ...conditions].filter(Boolean).join(" · ");
  }
  else if (diagnosis.kind === "no_matching_allow") detail = `No matching allow for ${(diagnosis.permissions ?? []).join(", ")} on ${diagnosis.target_type ?? "target"}:${diagnosis.target_class ?? "class"}`;
  else detail = diagnosis.kind.replaceAll("_", " ");
  return detail;
}

function FindingCard({ detail, onShowOccurrences }: { detail: IssueDetailResponse; onShowOccurrences: () => void }) {
  const { issue, intelligence, diagnosis, findings, finding_coverage, host_explanations, policy_analysis } = detail;
  const findingHost = diagnosis && host_explanations.find((host) => host.diagnosis_groups.some((group) => group.sample_occurrence_ids.includes(diagnosis.occurrence_id)))?.hostname;
  const values = row(diagnosis);
  const hostId = typeof values.host_id === "number" ? values.host_id : null;
  const lead = diagnosis ? primaryFindingLead(diagnosis) : null;
  return <section aria-labelledby="finding-title" className="issue-section issue-primary-finding"><h2 id="finding-title">What SECentral found</h2>
    {diagnosis ? <article>
      <Title headingLevel="h3" size="xl">{diagnosis.kind === "conditional_allow_inactive" ? diagnosis.operation === "name_connect" ? rows(diagnosis.conditional_rules).length > 1 ? "Matching conditional policy paths were inactive" : "A matching conditional policy path was inactive" : diagnosis.operation === "read" ? "A matching SELinux rule exists, but its condition was inactive" : "A relevant SELinux allow rule was inactive" : diagnosis.title}</Title>
      {lead && diagnosis.kind !== "conditional_allow_inactive" && <p className="issue-finding-lead">{lead}</p>}
      <DiagnosisEvidence diagnosis={diagnosis} />
      <p className="issue-limitation"><strong>What remains unknown:</strong> {primaryLimitation(diagnosis)}</p>
      <details className="finding-followup"><summary>Check next · limitations & coverage</summary>
        <div className="issue-next-check"><h3>Check next</h3><p>{diagnosis.next_step}</p></div>
        {findings?.[0] && <small aria-label="Finding coverage">{diagnosis.operation === "name_connect" && finding_coverage && `Conditional-policy findings cover ${(finding_coverage[diagnosis.kind] ?? 0).toLocaleString()} of ${issue.occurrences_count.toLocaleString()} denials. `}{diagnosis.kind === "file_context_mismatch" ? "This path is evidenced in" : diagnosis.operation === "name_connect" ? "Shown destination finding covers" : "Supported for"} {findings[0].occurrence_count.toLocaleString()} of {issue.occurrences_count.toLocaleString()} denials.{diagnosis.kind === "file_context_mismatch" && ` Based on ${findings[0].observation_count} distinct inspection observation(s).`}{(findings[0].reused_observation_occurrences ?? 0) > 0 && ` ${findings[0].reused_observation_occurrences} denials reuse another event's inspection within the same checkpoint.`} </small>}
        <small>Based on a retained denial{findingHost ? ` on ${findingHost}` : ""}. {hostId ? <Link to={`/hosts/${hostId}/occurrences/${diagnosis.occurrence_id}`}>View source event</Link> : <a href="#issue-occurrences" onClick={onShowOccurrences}>View source event</a>}</small>
      </details>
    </article> : <MissingExplanation issue={issue} paths={intelligence.paths} names={intelligence.names} resourceSummary={intelligence.resource_summary} hasFindings={(findings?.length ?? 0) > 0} policyAnalysis={policy_analysis} />}
  </section>;
}

function fleetSummary(state: string, affectedHosts: number): string {
  if (affectedHosts === 1) return ({
    consistent: "Same supported findings across recorded denials",
    disagreement: "Finding evidence varies between occurrences",
    partially_explained: "Some denials lack a supported finding",
    insufficient_evidence: "Not every denial has a supported finding"
  } as Record<string, string>)[state] ?? "Occurrence findings unavailable";
  return ({
    consistent: "Same explanation across affected hosts",
    disagreement: "Explanations differ across affected hosts",
    partially_explained: "Some hosts are not fully explained",
    insufficient_evidence: "No complete explanation across affected hosts"
  } as Record<string, string>)[state] ?? "Host explanations unavailable";
}

function MissingExplanation({
  issue,
  paths,
  names,
  resourceSummary,
  hasFindings,
  policyAnalysis
}: {
  issue: { target_class: string; target_type: string };
  paths: string[];
  names: string[];
  resourceSummary: IssueDetailResponse["intelligence"]["resource_summary"];
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
      <p><strong>{hasFindings ? "Individual occurrences have findings, but no single issue-wide explanation is available." : "No evidence-backed explanation is available yet."}</strong></p>
      <p>This is an unknown state, not evidence that the access is safe, allowed, or intended.</p>
      <p>SELinux recorded the target label type <code>{issue.target_type}</code> for this denied access.</p>
      {fileTarget && paths.length === 0 && <p><strong>No absolute path was retained.</strong> SECentral cannot compare the recorded label with expected path labeling without a complete path.</p>}
      {fileTarget && resourceSummary && <p>Complete path unavailable for {resourceSummary.without_absolute_path_occurrences.toLocaleString()} denials; {resourceSummary.absolute_path_occurrences.toLocaleString()} contain an absolute path. {resourceSummary.name_count.toLocaleString()} distinct basenames were recorded.</p>}
      {fileTarget && names.length > 0 && <p>Resource examples: {names.slice(0, 3).join(", ")}. Inspect occurrences for individual evidence.</p>}
      {fileTarget && paths.length > 0 && <p>An absolute path was retained, but no event-linked expected-context observation is available for a file-context comparison.</p>}
      {status === "pending" && <p>Policy evaluation is pending for the correlated occurrence.</p>}
      {status === "unavailable" && <p>Policy knowledge is unavailable for the correlated occurrence.</p>}
      {status === "error" && <p>Policy evaluation encountered an error; treat policy knowledge as unavailable until it can be checked.</p>}
      {limitations.map((limitation) => <p key={limitation}>{limitation.replaceAll("_", " ")}</p>)}
      {!status && limitations.length === 0 && <p>Review the occurrence evidence and policy availability for the affected host.</p>}
      <div className="issue-next-check"><h3>Check next</h3><ul>{nextChecks.map((check) => <li key={check}>{check}</li>)}</ul></div>
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
      <header><div><h2 id="issue-fleet-title">Where this occurs</h2><p>{fleet.affected_host_count} affected host{fleet.affected_host_count === 1 ? "" : "s"} · {fleetSummary(fleet.state, fleet.affected_host_count)}</p></div></header>
      <ul className="issue-host-explanations">
        {hostExplanations.map((host) => {
          const groups = host.diagnosis_groups ?? [];
          const titles = groups.map((group) => group.diagnosis?.title ?? "No explanation");
          const unexplained = host.unexplained_occurrence_count;
          let summary = host.diagnosis?.title ?? "No complete explanation for every occurrence";
          if (host.status === "disagreement") {
            const patterns = groups.length + host.additional_diagnosis_group_count;
            summary = `${titles.length ? [...new Set(titles)].join("; ") : "Different occurrence evidence"}${patterns > 1 ? ` · ${patterns} explanations` : ""}${unexplained ? `; ${unexplained} without a complete explanation` : ""}`;
          } else if (host.status === "insufficient_evidence") {
            summary = `${titles.join("; ") || "Explanation unavailable"}${unexplained ? ` · ${unexplained} occurrence${unexplained === 1 ? "" : "s"} without a finding` : ""}`;
          }
          const occurrenceSummary = host.status === "disagreement"
            ? `Mixed findings across ${host.occurrence_count} occurrences`
            : host.status === "insufficient_evidence"
              ? `${unexplained} of ${host.occurrence_count} occurrences lack a complete explanation`
              : `Same explanation across ${host.occurrence_count} occurrences`;
          return <li key={host.host_id}>
            <Link to={`/hosts/${host.host_id}`}>{host.hostname ?? `Host ${host.host_id}`}</Link>
            <span>{summary}</span>
            <small>{occurrenceSummary}</small>
            {host.status !== "agreement" && host.diagnosis && diagnosisVariantDetail(host.diagnosis) && <small>{diagnosisVariantDetail(host.diagnosis)}</small>}
            {(host.status === "disagreement" || groups.some((group) => (group.policy_provenance ?? []).length > 0)) && groups.length > 0 && <ul className="issue-diagnosis-groups">{groups.map((group, index) => <li key={`${group.diagnosis?.kind ?? "unknown"}-${index}`}>
              <strong>{group.diagnosis?.title ?? "No explanation"}</strong> · {group.count} occurrence{group.count === 1 ? "" : "s"}
              {host.status === "disagreement" && diagnosisVariantDetail(group.diagnosis) && <small>{diagnosisVariantDetail(group.diagnosis)}</small>}
              {((group.policy_provenance ?? []).length > 0 || group.sample_occurrence_ids.length > 0) && <details className="issue-group-provenance">
                <summary>Technical provenance</summary>
                {group.sample_occurrence_ids.length > 0 && <p>Example occurrence{group.sample_occurrence_ids.length === 1 ? "" : "s"}: {group.sample_occurrence_ids.map((occurrenceId) => `#${occurrenceId}`).join(", ")}</p>}
                {diagnosisVariantDetail(group.diagnosis) && <small>{diagnosisVariantDetail(group.diagnosis)}</small>}
                {(group.policy_provenance ?? []).map((provenance) => <dl key={provenance.policy_identity} className="issue-technical-facts">
                  <div><dt>Loaded policy identity</dt><dd><code>{provenance.policy_identity}</code></dd></div>
                  {provenance.checkpoint_observed_at && <div><dt>Checkpoint</dt><dd><time dateTime={provenance.checkpoint_observed_at}>{formatUtc(provenance.checkpoint_observed_at)}</time></dd></div>}
                  <div><dt>Example occurrence</dt><dd>#{provenance.occurrence_id}</dd></div>
                </dl>)}
                {group.additional_policy_identity_count > 0 && <small>{group.additional_policy_identity_count} more policy identities.</small>}
              </details>}
            </li>)}</ul>}
          </li>;
        })}
      </ul>
      {fleet.affected_host_count > 1 && <details className="issue-fleet-leads" onToggle={(event) => onRelatedToggle(event.currentTarget.open)}>
        <summary>Check for additional fleet correlations</summary>
        {loadingRelated && <p>Checking supporting fleet evidence…</p>}
        {relatedError && <p>Additional fleet evidence could not be loaded.</p>}
        {!loadingRelated && !relatedError && hypotheses.length === 0 && <p>No additional fleet correlation is supported by the available evidence.</p>}
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
      </details>}
    </section>
  );
}

function IssueOccurrence({ occurrence }: { occurrence: OccurrenceDetail }) {
  const denial = occurrence.normalized_denial;
  const names = namesFromOccurrences([occurrence]);
  const port = denial.target_class === "tcp_socket" && denial.permissions?.includes("name_connect") ? networkValue([occurrence], "dport_fields") ?? networkValue([occurrence], "dest_fields") : null;
  const resource = port ? `TCP/${port}` : denial.target_paths[0] ?? names[0] ?? `${denial.target_class ?? "object"} labeled ${denial.target_type ?? "unknown"}`;
  const operation = denial.permissions?.map(permissionLabel).join(", ") || "SELinux access";
  const details = row(denial.details);
  const syscall = rows(details.syscall_evidence)[0];
  const enforcement = text(details.enforcement_mode) ?? (details.permissive === false ? "enforcing" : details.permissive === true ? "permissive" : "not recorded");
  return (
    <details className="issue-occurrence">
      <summary>
        <span className="issue-occurrence-primary"><strong>{occurrence.host.hostname ?? `Host ${occurrence.host.id}`}</strong><span>Occurrence #{occurrence.id} · {operation} · {resource} · {denial.target_type ?? "unknown target type"}</span></span>
        <time dateTime={occurrence.occurred_at} title={formatUtc(occurrence.occurred_at)}>{timeAgo(occurrence.occurred_at)}</time>
      </summary>
      <div className="issue-occurrence-content">
        <section><h3>What happened</h3><p>{denial.command ? <><code>{denial.command}</code> ({denial.source_type ?? "unknown domain"})</> : <code>{denial.source_type ?? "unknown domain"}</code>} was denied {operation} on <code>{resource}</code>. Target <code>{denial.target_type ?? "unknown"}:{denial.target_class ?? "unknown class"}</code>; {enforcement} mode.</p></section>
        <details><summary>SELinux evidence · {denial.permissions?.join(", ") || "permission unavailable"}</summary>
          {denial.permissions?.includes("entrypoint") && <p>SELinux did not permit a file with this label to act as the executable entry point for this execution path. This does not establish an intended domain transition.</p>}
          <dl className="issue-technical-facts">
            <div><dt>AVC time / host</dt><dd><time dateTime={occurrence.occurred_at}>{formatUtc(occurrence.occurred_at)}</time> · {occurrence.host.hostname ?? occurrence.host.id}</dd></div>
            <div><dt>Source context</dt><dd><code>{denial.source_context ?? "Not recorded"}</code></dd></div>
            <div><dt>Target context at denial</dt><dd><code>{denial.target_context ?? "Not recorded"}</code></dd></div>
            <div><dt>Executable</dt><dd><code>{denial.executable ?? "Not recorded"}</code></dd></div>
            <div><dt>Syscall result</dt><dd>{syscall ? <code>{String(syscall.syscall ?? "syscall")} · success={String(syscall.success)} · exit={String(syscall.exit ?? "unknown")}</code> : "Not recorded"}</dd></div>
            <div><dt>Audit sequence</dt><dd>{occurrence.raw_event.audit_sequence} · boot <code>{occurrence.raw_event.boot_id}</code></dd></div>
          </dl>
          {rows(details.policy_evaluations).length > 0 && <details><summary>Policy evaluation and rules</summary>{rows(details.policy_evaluations).map((evaluation, index) => (
            <article key={index}>
              <p>{Array.isArray(evaluation.permissions) ? evaluation.permissions.join(", ") : "Policy evaluation"}: <strong>{text(evaluation.result) ?? "result unavailable"}</strong></p>
              {text(evaluation.policy_identity) && <p>Policy identity <code>{String(evaluation.policy_identity)}</code></p>}
              {Array.isArray(evaluation.matching_rules) && evaluation.matching_rules.length > 0
                ? <ul>{evaluation.matching_rules.map((rule, ruleIndex) => <li key={ruleIndex}><code>{typeof rule === "string" ? rule : JSON.stringify(rule)}</code></li>)}</ul>
                : <p>No matching allow rule was returned for this permission.</p>}
            </article>
          ))}</details>}
        </details>
        {occurrence.raw_event.file_context_observations && occurrence.raw_event.file_context_observations.length > 0 && <details><summary>Expected-context evidence</summary>{rows(occurrence.raw_event.file_context_observations).map((item, index) => <article key={index}><p><code>{String(item.path)}</code>: {String(item.status)}{text(item.expected_context) && <> · <code>{String(item.expected_context)}</code></>}</p><p>Inspected after the denial at {String(item.observed_at)} using {String(item.resolver ?? "matchpathcon")}. {text(item.reason)}</p></article>)}</details>}
        {occurrence.guidance && <details><summary>Occurrence checks and limitations</summary>
          {occurrence.guidance.observations.length > 0 && <ul>{occurrence.guidance.observations.map((item, index) => <li key={index}>{text(row(item).observation) ?? "Evidence observed."}</li>)}</ul>}
          {occurrence.guidance.checks.map((item, index) => <article key={index}><p>{text(row(item).reason) ?? "Review related evidence."}</p>{text(row(item).expected) && <p>{String(row(item).expected).replaceAll("_", " ")}</p>}{text(row(item).command) && <details><summary>Inspection command</summary><code>{String(row(item).command)}</code></details>}</article>)}
          {occurrence.guidance.missing_evidence.length > 0 && <p><strong>Unavailable:</strong> {occurrence.guidance.missing_evidence.join("; ")}</p>}
          {occurrence.guidance.historical_limitations.map((limitation) => <p key={limitation}><strong>Time limitation:</strong> {limitation}</p>)}
        </details>}
        <details><summary>Technical details and raw audit records</summary><OccurrenceRawEvidence occurrence={occurrence} collapsed /></details>
        <Link to={`/hosts/${occurrence.host.id}/occurrences/${occurrence.id}`}>Open occurrence record</Link>
      </div>
    </details>
  );
}

export function IssueDetail() {
  const { id } = useParams();
  const issueId = Number(id);
  const validId = Number.isInteger(issueId) && issueId > 0;
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const detailQuery = useQuery({ queryKey: ["issue", issueId], queryFn: () => fetchIssue(issueId), enabled: validId });
  const [showOccurrences, setShowOccurrences] = useState(() => searchParams.get("tab") === "occurrences");
  const [showRelatedFleet, setShowRelatedFleet] = useState(false);
  const [technicalEvidenceIssueId, setTechnicalEvidenceIssueId] = useState<number | null>(null);
  const showTechnicalEvidence = technicalEvidenceIssueId === issueId;
  const requestedPage = Number(searchParams.get("occurrence_page") ?? 1);
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
  const perPage = pageSize(searchParams.get("occurrence_limit"), EMBEDDED_PAGE_SIZES, 10);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const occurrencesQuery = useQuery({ queryKey: ["issue-occurrence-page", issueId, page, perPage], queryFn: () => fetchIssueOccurrencePage(issueId, page, perPage), enabled: validId && showOccurrences });
  const setOccurrencePage = (nextPage: number, size = perPage) => {
    setSelectedId(null);
    const next = new URLSearchParams(searchParams);
    next.set("tab", "occurrences");
    next.set("occurrence_page", String(nextPage));
    next.set("occurrence_limit", String(size));
    setSearchParams(next);
  };
  const selectedQuery = useQuery({ queryKey: ["issue-occurrence", issueId, selectedId], queryFn: () => fetchIssueOccurrence(issueId, selectedId!), enabled: validId && selectedId !== null });
  const analysisQuery = useQuery({ queryKey: ["issue-analysis", issueId], queryFn: () => fetchIssueAnalysis(issueId), enabled: validId && showRelatedFleet });
  const [pendingDisposition, setPendingDisposition] = useState<string | null>(null);
  const [dispositionNote, setDispositionNote] = useState("");
  const [savingStatus, setSavingStatus] = useState(false);
  const [savingDisposition, setSavingDisposition] = useState(false);
  const [workflowError, setWorkflowError] = useState<string | null>(null);

  const changeStatus = async (status: typeof STATUS_OPTIONS[number]) => {
    setSavingStatus(true);
    setWorkflowError(null);
    try {
      await updateIssueStatus(issueId, status);
      await queryClient.invalidateQueries({ queryKey: ["issue", issueId] });
    } catch (error) {
      setWorkflowError(error instanceof Error ? error.message : "Could not update status");
    } finally {
      setSavingStatus(false);
    }
  };

  const applyDisposition = async () => {
    const issue = detailQuery.data?.issue;
    if (!issue) return;
    setSavingDisposition(true);
    setWorkflowError(null);
    try {
      await updateIssueDisposition(issueId, pendingDisposition ?? issue.disposition, dispositionNote.trim() || undefined);
      await queryClient.invalidateQueries({ queryKey: ["issue", issueId] });
      setPendingDisposition(null);
      setDispositionNote("");
    } catch (error) {
      setWorkflowError(error instanceof Error ? error.message : "Could not update disposition");
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
  const occurrences = selectedQuery.data ? [selectedQuery.data] : [];
  const paths = intelligence.paths;
  const names = intelligence.names;
  const disposition = pendingDisposition ?? issue.disposition;

  return (
    <main className="issue-investigation">
      <Breadcrumb aria-label="Breadcrumb" className="pf-v6-u-mb-sm"><BreadcrumbItem><Link to="/issues">SELinux issues</Link></BreadcrumbItem><BreadcrumbItem isActive>Issue #{issue.id}</BreadcrumbItem></Breadcrumb>
      <header className="issue-investigation-header">
        <div>
          <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">{issue.target_class === "tcp_socket" && issue.permissions.includes("name_connect") && (intelligence.resource_summary?.destination_port_count ?? 0) > 1 ? `${intelligence.resource_summary?.process_command ?? `The ${issue.source_type} domain`} was denied outbound TCP connections.` : issue.target_class === "file" && issue.permissions.length === 1 && issue.permissions[0] === "read" && (intelligence.resource_summary?.name_count ?? 0) > 1 ? `${intelligence.resource_summary?.process_command ?? `The ${issue.source_type} domain`} was denied reading files labeled ${issue.target_type}.` : practicalHeadline(issue, diagnosis, [], paths, names, intelligence.resource_summary?.process_command, intelligence.resource_summary?.destination_ports?.length === 1 ? intelligence.resource_summary.destination_ports[0].port : null)}</Title>
          <p className="issue-operation-label">{issue.occurrences_count.toLocaleString()} denial{issue.occurrences_count === 1 ? "" : "s"} · {issue.affected_hosts} server{issue.affected_hosts === 1 ? "" : "s"}{(intelligence.resource_summary?.name_count ?? 0) > 1 && ` · ${intelligence.resource_summary!.name_count.toLocaleString()} filenames`} · First {timeAgo(issue.first_seen_at)} · Last {timeAgo(issue.last_seen_at)}</p>
          {(intelligence.resource_summary?.destination_ports?.length ?? 0) > 0 && <p className="issue-operation-label">Recorded destination ports: {intelligence.resource_summary!.destination_ports!.map((item) => `TCP/${item.port} (${item.occurrence_count} denial${item.occurrence_count === 1 ? "" : "s"})`).join(" · ")}{intelligence.resource_summary!.destination_port_count! > 3 && ` · ${intelligence.resource_summary!.destination_port_count! - 3} more ports`}</p>}
        </div>
        <div className="issue-workflow">
          <Label color={issue.display_status === "resolved" ? "green" : issue.display_status === "ignored" ? "grey" : issue.display_status === "regressed" ? "orange" : "blue"}>{displayState(issue.display_status)}</Label>
          <details>
            <summary>Actions · {displayState(issue.disposition)}</summary>
            <div className="issue-workflow-panel">
              {workflowError && <Alert variant="danger" isInline title="Workflow update failed">{workflowError}</Alert>}
              <label>Lifecycle status<select aria-label="Issue status" value={issue.status} disabled={savingStatus} onChange={(event) => void changeStatus(event.target.value as typeof STATUS_OPTIONS[number])}>{STATUS_OPTIONS.map((status) => <option key={status} value={status}>{displayState(status)}</option>)}</select></label>
              <label>Operator disposition<select aria-label="Operator disposition" value={disposition} onChange={(event) => setPendingDisposition(event.target.value)}>{DISPOSITIONS.map((item) => <option key={item} value={item}>{displayState(item)}</option>)}</select></label>
              <TextInput value={dispositionNote} onChange={(_event, value) => setDispositionNote(value)} aria-label="Disposition note" placeholder="Note (optional)" />
              <Button variant="primary" isDisabled={savingDisposition || (disposition === issue.disposition && !dispositionNote.trim())} onClick={() => void applyDisposition()}>{savingDisposition ? "Applying…" : "Save disposition"}</Button>
            </div>
          </details>
        </div>
      </header>

      <div className="issue-workbench">
      <div className="issue-workspace">
      <ResolutionWorkflow issueId={issueId} stage="observed" initialData={detailQuery.data.resolutions} initialDataUpdatedAt={detailQuery.dataUpdatedAt} />

      <FindingCard detail={detailQuery.data} onShowOccurrences={() => setShowOccurrences(true)} />

      <ResolutionWorkflow issueId={issueId} stage="intent" initialData={detailQuery.data.resolutions} initialDataUpdatedAt={detailQuery.dataUpdatedAt} />
      </div>
      <ResolutionWorkflow issueId={issueId} stage="context" initialData={detailQuery.data.resolutions} initialDataUpdatedAt={detailQuery.dataUpdatedAt} detail={detailQuery.data} onShowTechnicalEvidence={() => setTechnicalEvidenceIssueId(issueId)} />
      </div>

      {((findings?.length ?? 0) > 1 || (issue.target_class === "file" && (intelligence.resource_summary?.without_absolute_path_occurrences ?? 0) > 0) || (additional_finding_count ?? 0) > 0 || policy_analysis.limitations.length > 0) && <details className="workbench-additional"><summary>Additional investigation</summary><section aria-label="Additional investigation" className="issue-section">
        <h2>Additional investigation</h2>
        {findings?.slice(1).map((finding, index) => <details key={index}><summary>{finding.diagnosis.title} · {finding.occurrence_count.toLocaleString()} denials</summary><p>{primaryFindingLead(finding.diagnosis) ?? text(row(finding.diagnosis).finding)}</p><DiagnosisEvidence diagnosis={finding.diagnosis} /><p><strong>Check next:</strong> {finding.diagnosis.next_step}</p><p>{primaryLimitation(finding.diagnosis)}</p><details><summary>Technical evidence for this finding</summary><DiagnosisTechnicalEvidence diagnosis={finding.diagnosis} /></details></details>)}
        {issue.target_class === "file" && (intelligence.resource_summary?.without_absolute_path_occurrences ?? 0) > 0 && <div><h3>Path-based label check unavailable</h3><p>{intelligence.resource_summary!.without_absolute_path_occurrences.toLocaleString()} of {issue.occurrences_count.toLocaleString()} denials contain filenames but no complete filesystem path. SECentral cannot determine whether <code>{issue.target_type}</code> is the expected label for those files.</p></div>}
        {(additional_finding_count ?? 0) > 0 && <p>{additional_finding_count} additional finding variant(s). Inspect host and occurrence evidence for their coverage.</p>}
        {diagnosis && policy_analysis.limitations.map((limitation) => <p key={limitation}>{limitation}</p>)}
      </section></details>}

      <FleetSection
        hostExplanations={host_explanations}
        fleet={fleet_explanation}
        relatedAnalysis={analysisQuery.data}
        loadingRelated={analysisQuery.isPending && showRelatedFleet}
        relatedError={analysisQuery.isError}
        onRelatedToggle={setShowRelatedFleet}
      />

      {triage.signals.length > 0 && <details className="issue-activity-context"><summary>Occurrence pattern</summary><ul>{triage.signals.map((signal) => <li key={signal.code}><strong>{signal.label}:</strong> {signal.explanation}</li>)}</ul></details>}

      <section id="issue-occurrences" aria-labelledby="occurrences-title" className="issue-section issue-occurrences-section">
        <header><div><h2 id="occurrences-title">Occurrences</h2><p>{issue.occurrences_count} retained denial{issue.occurrences_count === 1 ? "" : "s"}{occurrencesQuery.data && ` · ${(occurrencesQuery.data.meta.page - 1) * occurrencesQuery.data.meta.page_size + (occurrencesQuery.data.meta.total ? 1 : 0)}–${Math.min(occurrencesQuery.data.meta.page * occurrencesQuery.data.meta.page_size, occurrencesQuery.data.meta.total)} of ${occurrencesQuery.data.meta.total}`}</p></div></header>
        {!showOccurrences ? <Button variant="secondary" onClick={() => setShowOccurrences(true)}>Show recent occurrences</Button>
          : occurrencesQuery.isPending ? <div aria-label="Loading occurrences"><Spinner /></div>
          : occurrencesQuery.isError ? <Alert variant="warning" isInline title="Could not load occurrences">{occurrencesQuery.error instanceof Error ? occurrencesQuery.error.message : "Unknown error"}</Alert>
            : occurrencesQuery.data.occurrences.length ? <>
              <table className="pf-v6-c-table" aria-label="Occurrence summary"><thead><tr><th scope="col">Time (UTC)</th>{issue.affected_hosts > 1 && <th scope="col">Host</th>}<th scope="col">Resource</th>{issue.target_class !== "tcp_socket" && <th scope="col">Path evidence</th>}<th scope="col">Inspect</th></tr></thead><tbody>{occurrencesQuery.data.occurrences.map((item) => <tr key={item.id}><td>{formatUtc(item.occurred_at)}</td>{issue.affected_hosts > 1 && <td>{item.host.hostname}</td>}<td><code>{item.resource ?? "Not recorded"}</code></td>{issue.target_class !== "tcp_socket" && <td>{item.absolute_path ? "Absolute path" : "Basename only"}</td>}<td><Button variant="link" onClick={() => setSelectedId(item.id)} aria-label={`Inspect occurrence ${item.id}`}>View evidence</Button></td></tr>)}</tbody></table>
              <div className="table-pagination"><Pagination itemCount={occurrencesQuery.data.meta.total} page={occurrencesQuery.data.meta.page} perPage={occurrencesQuery.data.meta.page_size}
                perPageOptions={EMBEDDED_PAGE_SIZES.map((value) => ({ title: String(value), value }))} titles={{ paginationAriaLabel: "Issue occurrence pagination" }}
                isDisabled={occurrencesQuery.isFetching} onSetPage={(_event, value) => setOccurrencePage(value)} onPerPageSelect={(_event, size) => setOccurrencePage(1, size)} /></div>
              {selectedId !== null && <section aria-label="Selected occurrence evidence">{selectedQuery.isPending ? <Spinner aria-label="Loading occurrence evidence" /> : selectedQuery.isError ? <Alert variant="warning" isInline title="Could not load occurrence evidence" /> : occurrences.map((occurrence) => <IssueOccurrence key={occurrence.id} occurrence={occurrence} />)}</section>}
              <Button className="pf-v6-u-mt-md" variant="link" onClick={() => setShowOccurrences(false)}>Hide occurrences</Button></>
              : <p>No occurrences are retained for this issue.</p>}
      </section>

      <ExpandableSection id="issue-technical-evidence" className="issue-advanced-details" toggleText="Technical evidence & issue history" isExpanded={showTechnicalEvidence} onToggle={(_event, expanded) => setTechnicalEvidenceIssueId(expanded ? issueId : null)}>
        {showTechnicalEvidence && <>
        {diagnosis && <DiagnosisTechnicalEvidence diagnosis={diagnosis} />}
        <details><summary>SELinux types, class, and permission</summary><dl className="issue-technical-facts"><div><dt>Source type</dt><dd><code>{issue.source_type}</code></dd></div><div><dt>Target type</dt><dd><code>{issue.target_type}</code></dd></div><div><dt>Object class</dt><dd><code>{issue.target_class}</code></dd></div><div><dt>Denied permission set</dt><dd>{issue.permissions.map((permission) => <code key={permission}>{permission}</code>)}</dd></div></dl></details>
        <dl className="issue-technical-facts"><div><dt>Fingerprint version</dt><dd>{issue.fingerprint_version}</dd></div><div><dt>Fingerprint</dt><dd><code>{issue.fingerprint_digest}</code></dd></div><div><dt>First seen</dt><dd><time dateTime={issue.first_seen_at}>{formatUtc(issue.first_seen_at)}</time></dd></div><div><dt>Last seen</dt><dd><time dateTime={issue.last_seen_at}>{formatUtc(issue.last_seen_at)}</time></dd></div></dl>
        {issue.disposition_history.length > 0 && <ul>{issue.disposition_history.map((change) => <li key={change.changed_at}><time dateTime={change.changed_at}>{formatUtc(change.changed_at)}</time> {change.previous_disposition} → {change.disposition}{change.note ? ` — ${change.note}` : ""}</li>)}</ul>}
        </>}
      </ExpandableSection>
    </main>
  );
}
