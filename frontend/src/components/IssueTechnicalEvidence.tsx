import { Alert, Card, CardBody, CardTitle, FormSelect, FormSelectOption, Spinner, Stack, StackItem, Tab, Tabs, TabTitleText } from "@patternfly/react-core";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { fetchIssueOccurrence, type Diagnosis, type IssueDetailResponse } from "../api/issue";
import { fetchResolutions } from "../api/resolution";
import { Disclosure } from "./Disclosure";
import { EvidenceBlock, EvidenceFacts as Facts, OccurrenceRawEvidence } from "./OccurrenceEvidence";
import { evidenceRecord as row, evidenceTabFor, PolicyArtifactReference, PolicyArtifacts, valueText as text } from "./WorkbenchEvidence";

type Row = Record<string, unknown>;
const rows = (value: unknown): Row[] => Array.isArray(value) ? value.map(row) : [];
const tabs = { policy: "Policy evaluation", audit: "Audit record", provenance: "Provenance" } as const;
const targets = { policy: "policy-evaluation-evidence", audit: "audit-evidence", provenance: "artifact-provenance" } as const;

function RawData({ value, label }: { value: unknown; label: string }) {
  const [expanded, setExpanded] = useState(false);
  return <Disclosure toggleText={label} isExpanded={expanded} onToggle={(_event, open) => setExpanded(open)}>{expanded && <EvidenceBlock value={JSON.stringify(value, null, 2)} label={label} hasCopyButton isJson downloadFilename="secentral-evidence.json" />}</Disclosure>;
}

function Rules({ rules }: { rules: unknown }) {
  if (!Array.isArray(rules) || !rules.length) return null;
  return <div className="evidence-rules">{[...new Set(rules.map((rule) => typeof rule === "string" ? rule : JSON.stringify(rule)))].map((rule) => <EvidenceBlock key={rule} value={rule} label="SELinux allow rule" hasCopyButton />)}</div>;
}

function Evaluation({ diagnosis }: { diagnosis: Diagnosis }) {
  const values = row(diagnosis);
  const evaluations = rows(values.evaluations);
  const conditions = rows(diagnosis.condition_boolean_states);
  const rules = rows(diagnosis.conditional_rules);
  return <Card isCompact className="issue-selinux-explanation" aria-label="SELinux explanation">
    <CardTitle><h3>{diagnosis.kind === "file_context_mismatch" ? "Label comparison" : diagnosis.kind === "conditional_allow_inactive" ? "Conditional policy evaluation" : "Policy evaluation"} · occurrence #{diagnosis.occurrence_id}</h3></CardTitle><CardBody>
      <Facts isHorizontal fields={[
        ["Source domain", <code>{diagnosis.source_domain ?? "Not recorded"}</code>],
        ["Denied operation", <code>{diagnosis.operation ?? diagnosis.permissions?.join(", ") ?? "Not recorded"}</code>],
        ["Recorded target", <code>{diagnosis.target_type ?? diagnosis.observed_type ?? "Not recorded"}:{diagnosis.target_class ?? "Not recorded"}</code>],
        ["Resource", diagnosis.path ?? (diagnosis.bind_port ? `TCP/${diagnosis.bind_port} · local bind` : diagnosis.destination_port ? `TCP/${diagnosis.destination_port} · destination` : "Complete resource not recorded")],
        ["Associated checkpoint", diagnosis.checkpoint_observed_at ?? "Not recorded"],
        ["Checkpoint policy", text(values.policy_identity) ? <PolicyArtifactReference identity={String(values.policy_identity)} /> : "Not recorded"],
        ["Observed context", diagnosis.observed_context && <code>{diagnosis.observed_context}</code>],
        ["Expected context", diagnosis.expected_context && <code>{diagnosis.expected_context}</code>],
        ["Expected-context inspection", diagnosis.expected_context_observed_at]
      ]} />
      {evaluations.map((evaluation, index) => <section key={index} className="policy-evaluation-result"><h4>{Array.isArray(evaluation.permissions) ? evaluation.permissions.join(", ") : "Policy result"}</h4>
        <Facts isHorizontal fields={[["Rule lookup result", text(evaluation.result) ?? "Unavailable"], ["Evaluator version", text(evaluation.evaluator_version) ?? "Not recorded"], ["Evaluated policy", text(evaluation.policy_identity) ? <PolicyArtifactReference identity={String(evaluation.policy_identity)} /> : "Not recorded"]]} />
        <Rules rules={evaluation.matching_rules} />
        {Array.isArray(evaluation.limitations) && evaluation.limitations.length > 0 && <ul>{evaluation.limitations.map((value, i) => <li key={i}>{String(value)}</li>)}</ul>}
      </section>)}
      {(conditions.length ? conditions : rules).map((condition, index) => <section key={index}><h4>{text(condition.expression) ?? "Conditional path"}</h4>
        <Facts isHorizontal fields={[["Condition at checkpoint", text(condition.state) ?? "Unavailable"], ...rows(condition.booleans).map((boolean): [string, React.ReactNode] => [text(boolean.name) ?? "Boolean", typeof boolean.current === "boolean" ? boolean.current ? "On" : "Off" : "Unavailable"])]} />
      </section>)}
      {!evaluations.some((evaluation) => Array.isArray(evaluation.matching_rules) && evaluation.matching_rules.length) && <Rules rules={rules.map((rule) => rule.rule).filter(Boolean)} />}
      <RawData value={diagnosis} label="Evaluation source data" />
    </CardBody>
  </Card>;
}

function ResolutionBasis({ title, basis, id }: { title: string; basis: Row; id: string }) {
  const current = row(basis.current_boolean);
  return <Card isCompact id={id} tabIndex={-1}><CardTitle><h3>{title}</h3></CardTitle><CardBody>
    <Facts isHorizontal fields={[
      ["Host ID", basis.host_id as number | undefined], ["Source occurrence", basis.occurrence_id as number | undefined],
      ["Operation", text(basis.operation)], ["Protocol / port", basis.protocol && basis.port != null ? `${String(basis.protocol).toUpperCase()}/${basis.port}` : null],
      ["Recorded type", text(basis.observed_type)], ["Selected classification", text(basis.target_port_type)], ["Path", text(basis.path)],
      ["Boolean", text(basis.boolean)], ["Observed Boolean state", typeof current.current === "boolean" ? current.current ? "On" : "Off" : text(current.status)],
      ["Policy fact", basis.policy_fact_id as number | undefined], ["Evaluator version", text(basis.evaluator_version)],
      ["Current policy", text(basis.current_policy_identity) ? <PolicyArtifactReference identity={String(basis.current_policy_identity)} /> : null],
      ["Historical policy", text(basis.historical_policy_identity) ? <PolicyArtifactReference identity={String(basis.historical_policy_identity)} /> : null],
      ["Latest observation", text(basis.latest_observed_at)], ["Historical checkpoint", text(basis.checkpoint_observed_at)]
    ]} />
    <Rules rules={basis.matching_rules} />
    <RawData value={basis} label="Resolution source data" />
  </CardBody></Card>;
}

export function IssueTechnicalEvidence({ detail, updatedAt }: { detail: IssueDetailResponse; updatedAt: number }) {
  const [params, setParams] = useSearchParams();
  const target = params.get("evidence");
  const requestedTab = params.get("evidence_tab");
  const tab = requestedTab === "policy" || requestedTab === "audit" || requestedTab === "provenance" ? requestedTab : evidenceTabFor(target);
  const workflowQuery = useQuery({ queryKey: ["issue-resolutions", detail.issue.id], queryFn: () => fetchResolutions(detail.issue.id), initialData: detail.resolutions, initialDataUpdatedAt: updatedAt, staleTime: 30_000 });
  const workflow = workflowQuery.isError ? undefined : detail.resolutions && updatedAt > workflowQuery.dataUpdatedAt ? detail.resolutions : workflowQuery.data;
  const requestedOccurrence = Number(params.get("evidence_occurrence"));
  const invalidOccurrence = params.has("evidence_occurrence") && (!Number.isSafeInteger(requestedOccurrence) || requestedOccurrence <= 0);
  const occurrenceId = invalidOccurrence ? undefined : requestedOccurrence > 0 ? requestedOccurrence : detail.diagnosis?.occurrence_id ?? workflow?.observed_access?.occurrence_id;
  const occurrenceQuery = useQuery({ queryKey: ["issue-occurrence", detail.issue.id, occurrenceId], queryFn: () => fetchIssueOccurrence(detail.issue.id, occurrenceId!), enabled: tab !== "policy" && !!occurrenceId });
  const occurrence = occurrenceQuery.data;
  const candidate = workflow?.candidates.find((item) => item.id === params.get("evidence_option") || `option-${item.id}` === target) ?? workflow?.candidates.find((item) => item.id === workflow.intent?.candidate_id) ?? workflow?.candidates[0];
  const selectTab = (key: keyof typeof tabs) => setParams((previous) => {
    const next = new URLSearchParams(previous); next.delete("phase"); next.set("evidence_tab", key); next.set("evidence", targets[key]); return next;
  });
  useEffect(() => {
    const element = document.getElementById(target ?? targets[tab]) ?? document.getElementById(targets[tab]);
    element?.focus(); element?.scrollIntoView?.({ block: "start" });
  }, [target, tab, occurrenceQuery.dataUpdatedAt, workflowQuery.dataUpdatedAt]);
  const recordState = invalidOccurrence ? <Alert variant="warning" isInline title="Invalid evidence occurrence">Select a retained occurrence from the table.</Alert> : !occurrenceId ? <p>Select a retained occurrence to inspect its audit record and checkpoint.</p> : occurrenceQuery.isError ? <Alert variant="warning" isInline title="Could not load occurrence evidence">No record has been substituted. <Link to={`/issues/${detail.issue.id}?tab=occurrences`}>Browse occurrences</Link></Alert>
    : occurrenceQuery.isPending ? <Spinner aria-label="Loading occurrence evidence" size="md" /> : null;
  const issueDiagnoses = detail.findings?.length ? detail.findings.map((finding) => finding.diagnosis) : detail.diagnosis ? [detail.diagnosis] : [];
  const diagnoses = invalidOccurrence ? [] : params.has("evidence_occurrence")
    ? [...new Map([...issueDiagnoses, ...detail.host_explanations.flatMap((host) => host.diagnosis_groups.flatMap((group) => group.diagnosis ? [group.diagnosis] : []))]
      .filter((diagnosis) => diagnosis.occurrence_id === occurrenceId)
      .map((diagnosis) => [`${diagnosis.host_id}:${diagnosis.occurrence_id}:${diagnosis.kind}`, diagnosis])).values()]
    : issueDiagnoses;
  const denial = occurrence?.normalized_denial;
  const syscall = rows(denial?.details.syscall_evidence)[0];
  const network = row(denial?.details.network_evidence);
  const protocol = denial?.target_class === "tcp_socket" ? "TCP" : denial?.target_class === "udp_socket" ? "UDP" : null;
  const portFields = denial?.permissions?.length === 1 && denial.permissions[0] === "name_bind" ? network.bind_port_fields : denial?.permissions?.length === 1 && denial.permissions[0] === "name_connect" ? [...(Array.isArray(network.dport_fields) ? network.dport_fields : []), ...(Array.isArray(network.dest_fields) ? network.dest_fields : [])] : [];
  const ports = [...new Set((Array.isArray(portFields) ? portFields : []).filter((value) => (typeof value === "string" || typeof value === "number") && /^\d+$/.test(String(value)) && Number(value) <= 65535).map(String))];

  return <div className="issue-evidence-workspace">
    <Tabs activeKey={tab} aria-label="Technical evidence" onSelect={(_event, key) => selectTab(key as keyof typeof tabs)}>
      {Object.entries(tabs).map(([key, label]) => <Tab key={key} eventKey={key} title={<TabTitleText>{label}</TabTitleText>} tabContentId={targets[key as keyof typeof tabs]} />)}
    </Tabs>
    <section id={targets[tab]} role="tabpanel" tabIndex={-1} aria-label={tabs[tab]}>
      {tab === "policy" && <Stack hasGutter>
        {invalidOccurrence ? <StackItem>{recordState}</StackItem> : !diagnoses.length && <StackItem><p>{params.has("evidence_occurrence") ? `No retained policy finding is available for occurrence #${occurrenceId}. No other occurrence's finding has been substituted.` : "No authoritative policy finding is available for this issue."}</p></StackItem>}
        {diagnoses.map((diagnosis, index) => <StackItem key={index}><Evaluation diagnosis={diagnosis} /></StackItem>)}
        {workflowQuery.isError && <StackItem><Alert variant="warning" isInline title="Resolution evidence could not be refreshed" /></StackItem>}
        {workflow?.change_plan && <StackItem><ResolutionBasis id="reviewed-plan-evidence" title={`Reviewed plan · ${workflow.change_plan.title}`} basis={workflow.change_plan.evidence_basis} /></StackItem>}
        {candidate && <StackItem><FormSelect aria-label="Option evidence" value={candidate.id} onChange={(_event, id) => setParams((previous) => {
          const next = new URLSearchParams(previous); next.set("evidence", `option-${id}`); next.set("evidence_option", id); next.set("evidence_tab", "policy");
          const sourceId = workflow?.candidates.find((item) => item.id === id)?.evidence_basis.occurrence_id;
          if (typeof sourceId === "number") next.set("evidence_occurrence", String(sourceId));
          return next;
        })}>{workflow!.candidates.map((item) => <FormSelectOption key={item.id} value={item.id} label={`${item.title} · ${item.hostname}`} />)}</FormSelect>
          <ResolutionBasis id={`option-${candidate.id}`} title={`Current option · ${candidate.title} · ${candidate.hostname}`} basis={candidate.evidence_basis} />
        </StackItem>}
      </Stack>}
      {tab === "audit" && <><h2>Audit & occurrence record</h2>{recordState}
        {occurrence && denial && <section aria-label="Selected occurrence evidence">
          <Card isCompact><CardTitle><h3>Occurrence #{occurrence.id} · {occurrence.host.hostname}</h3></CardTitle><CardBody>
            <p><code>{denial.source_type ?? "Source not recorded"}</code> → <code>{denial.permissions?.join(", ") ?? "Permission not recorded"}</code> → <code>{denial.target_type ?? "Target not recorded"}:{denial.target_class ?? "Class not recorded"}</code></p>
            <Facts isHorizontal fields={[["Occurred at", occurrence.occurred_at], ["Recorded endpoint", protocol && ports.length ? ports.map((port) => `${protocol}/${port}`).join(", ") : "Not recorded"], ["Process", denial.command ?? "Not recorded"], ["Executable", denial.executable ?? "Not recorded"],
              ["Recorded PIDs", Array.isArray(row(denial.details.process_evidence).pids) ? (row(denial.details.process_evidence).pids as unknown[]).join(", ") || "Not recorded" : typeof syscall?.pid === "number" || typeof syscall?.pid === "string" ? String(syscall.pid) : "Not recorded"],
              ["AVC enforcement", text(denial.details.enforcement_mode) ?? (denial.details.permissive === true ? "Permissive" : denial.details.permissive === false ? "Enforcing" : "Not recorded")],
              ["Paths", denial.target_paths.length ? denial.target_paths.join(", ") : "Complete path not recorded"], ["Source context", denial.source_context ?? "Not recorded"], ["Target context", denial.target_context ?? "Not recorded"],
              ["First recorded syscall result", syscall ? `${syscall.syscall ?? "Unknown syscall"} · success=${syscall.success ?? "unknown"} · exit=${syscall.exit ?? "unknown"}` : "Not recorded"]]} />
            <Disclosure toggleText="Socket, syscall & path fields"><EvidenceBlock value={JSON.stringify({ network: denial.details.network_evidence, syscalls: denial.details.syscall_evidence, target: denial.details.target_evidence }, null, 2)} label="Socket, syscall and path evidence" hasCopyButton isJson /></Disclosure>
            <Link to={`/hosts/${occurrence.host.id}/occurrences/${occurrence.id}`}>Open occurrence record</Link>
          </CardBody></Card>
          <OccurrenceRawEvidence occurrence={occurrence} collapsed includeNormalized={false} />
          <RawData value={{ occurrence_id: occurrence.id, host: occurrence.host, normalized_denial: denial, guidance: occurrence.guidance }} label="Normalized source data" />
        </section>}
        <Link to={`?${new URLSearchParams({ ...Object.fromEntries(params), tab: "occurrences" })}#issue-occurrences`}>Browse occurrences</Link>
      </>}
      {tab === "provenance" && <Stack hasGutter>
        <StackItem><Card isCompact><CardTitle><h2>Host snapshot & checkpoint</h2></CardTitle><CardBody>{recordState}
          {occurrence && <><p>Occurrence #{occurrence.id} · {occurrence.host.hostname}. Associated checkpoint, not the host's latest inventory.</p>
            <Facts isHorizontal fields={[["Host ID", occurrence.host.id], ["Snapshot ID", occurrence.raw_event.checkpoint?.snapshot_id ?? "Not recorded"], ["Checkpoint observed at", occurrence.raw_event.checkpoint?.observed_at ?? "Not recorded"],
              ["Kernel release", occurrence.raw_event.checkpoint?.kernel_release ?? "Not recorded"], ["Boot ID", occurrence.raw_event.boot_id], ["Audit sequence", occurrence.raw_event.audit_sequence],
              ["Recorded checkpoint invalidations", occurrence.raw_event.checkpoint_invalidated_fields ? occurrence.raw_event.checkpoint_invalidated_fields.join(", ") || "None recorded" : "Not recorded"],
              ["Checkpoint port inventory", occurrence.raw_event.checkpoint_port_inventory_status ?? "Not recorded"], ["Checkpoint file-context mappings", occurrence.raw_event.checkpoint_file_context_mappings_status ?? "Not recorded"],
              ["Agent installation ID", occurrence.raw_event.collection?.agent_installation_id ?? "Not recorded"], ["Collection schema", occurrence.raw_event.collection?.schema_version ?? "Not recorded"],
              ["Agent received at", occurrence.raw_event.collection?.agent_received_at ?? "Not recorded"], ["Server received at", occurrence.raw_event.collection?.server_received_at ?? "Not recorded"],
              ["Checkpoint policy", occurrence.raw_event.checkpoint_policy_identity ? <PolicyArtifactReference identity={occurrence.raw_event.checkpoint_policy_identity} /> : "Not recorded"]]} />
            <RawData value={occurrence.raw_event} label="Retained event provenance" />
          </>}
        </CardBody></Card></StackItem>
        <StackItem><PolicyArtifacts evidence={{ detail, workflow, occurrence }} /></StackItem>
        {detail.host_explanations.map((host) => <StackItem key={host.host_id}><Card isCompact id={`host-evidence-${host.host_id}`} tabIndex={-1}><CardTitle><h3>{host.hostname} · finding groups</h3></CardTitle><CardBody>
          <p>{host.occurrence_count} occurrences · {host.unexplained_occurrence_count} unconfirmed. Up to five groups and three example events per group; {host.additional_diagnosis_group_count} groups omitted.</p>
          {host.diagnosis_groups.map((group, index) => <section key={index}><h4>{group.diagnosis?.kind.replaceAll("_", " ") ?? "Cause unconfirmed"} · {group.count} occurrences</h4>
            <p>Source events: {group.sample_occurrence_ids.map((id) => <Link key={id} to={`?${new URLSearchParams({ ...Object.fromEntries(params), evidence: "audit-evidence", evidence_tab: "audit", evidence_occurrence: String(id) })}#audit-evidence`}>#{id} </Link>)}</p>
            {group.policy_provenance.map((provenance, i) => <Facts key={i} isHorizontal fields={[["Policy", <PolicyArtifactReference identity={provenance.policy_identity} />], ["Checkpoint", provenance.checkpoint_observed_at ?? "Not recorded"], ["Example occurrence", provenance.occurrence_id]]} />)}
            {group.additional_policy_identity_count > 0 && <p>{group.additional_policy_identity_count} policy identities omitted; inspect source events.</p>}
          </section>)}
        </CardBody></Card></StackItem>)}
        <StackItem><Card isCompact><CardTitle><h3>Issue identity</h3></CardTitle><CardBody><Facts isHorizontal fields={[["Fingerprint version", detail.issue.fingerprint_version], ["Fingerprint", <code>{detail.issue.fingerprint_digest}</code>], ["First seen", detail.issue.first_seen_at], ["Last seen", detail.issue.last_seen_at]]} /></CardBody></Card></StackItem>
      </Stack>}
    </section>
  </div>;
}
