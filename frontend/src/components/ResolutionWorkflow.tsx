import { Alert, Button, Card, CardBody, CodeBlock, CodeBlockAction, CodeBlockCode, FormGroup, FormSelect, FormSelectOption, Label, SearchInput, Spinner, Stack, StackItem, Tab, Tabs, TabTitleText, TextInput, Tooltip } from "@patternfly/react-core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import ShieldAltIcon from "@patternfly/react-icons/dist/esm/icons/shield-alt-icon";
import CheckCircleIcon from "@patternfly/react-icons/dist/esm/icons/check-circle-icon";
import ExclamationTriangleIcon from "@patternfly/react-icons/dist/esm/icons/exclamation-triangle-icon";
import CopyIcon from "@patternfly/react-icons/dist/esm/icons/copy-icon";
import { fetchIssueOccurrence, type IssueDetailResponse } from "../api/issue";
import { ContextSidebar, EvidenceLink, ObservedAccessFlow, TechnicalEvidenceDisclosure, evidenceRecord, valueText } from "./WorkbenchEvidence";
import { clearIntent, createDraft, exportDraft, fetchDrafts, fetchResolutions, removeEntry, selectIntent, stagePermission,
  type ChangePlan as PlanData, type HomeContentReview, type PolicyDraftExport, type ResolutionWorkflow as Workflow } from "../api/resolution";
import { activeResolutionResource, candidateFilePath, fileResourceLabel, resolutionResources } from "./resolutionResources";
import { InspectionCommands, OperatorChecks, OperatorVerification, ReadOnlyCommands } from "./OperatorGuidance";
import { Disclosure as ExpandableSection } from "./Disclosure";

function download(filename: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function CopyCommand({ command }: { command: string }) {
  const [feedback, setFeedback] = useState({ command: "", message: "" });
  const message = feedback.command === command ? feedback.message : "";
  const setMessage = (text: string) => setFeedback({ command, message: text });
  return <div className="command-block"><CodeBlock actions={<CodeBlockAction><Tooltip content={message || "Copy command"}><Button variant="plain" icon={message === "Copied" ? <CheckCircleIcon /> : <CopyIcon />} aria-label={`Copy command: ${command}`} onClick={() => {
    if (!navigator.clipboard) { setMessage("Copy unavailable; select the command text"); return; }
    void navigator.clipboard.writeText(command).then(() => setMessage("Copied"), () => setMessage("Copy unavailable; select the command text"));
  }} /></Tooltip></CodeBlockAction>}><CodeBlockCode tabIndex={0} aria-label="Exact command">{command}</CodeBlockCode></CodeBlock><small className="pf-v6-screen-reader" role="status">{message}</small></div>;
}

function optionTitle(basis: Record<string, unknown>, title: string) {
  return valueText(basis.boolean) ? `Enable ${basis.boolean}` : valueText(basis.path) ? "Restore configured SELinux labeling" : title;
}

function ChangePlanStep({ step, explanation }: { step: PlanData["preview_steps"][number]; explanation?: string }) {
  return <article className="change-plan-step"><header><h4>{step.title}</h4>
    {step.persistence !== "port_mapping" && <Label color={step.persistence === "persistent" ? "orange" : "blue"} isCompact>{step.persistence === "persistent" ? "Persistent · optional" : step.persistence === "temporary" ? "Runtime only" : step.title.toLowerCase().includes("preview") ? "Non-mutating preview" : step.persistence === "inspection" ? "Inspect" : "Single object"}</Label>}</header>
    {step.persistence !== "inspection" && <Label color="orange">{step.persistence === "port_mapping" ? "Changes SELinux port mapping" : step.persistence === "configured_label" ? "Changes file labels" : "Changes host-wide Boolean"}</Label>}
    <p className="step-detail">{explanation ?? step.explanation}</p><CopyCommand command={step.command} /></article>;
}

function ChangePlan({ plan, detail }: { plan: PlanData; detail?: IssueDetailResponse }) {
  const [params, setParams] = useSearchParams();
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const showRollback = rollbackOpen || params.get("phase") === "rollback";
  const file = plan.scope_kind === "single_object";
  const port = plan.scope_kind === "host_port";
  return <section className="selected-change-plan" aria-label="Selected change plan"><header className="workbench-section-header"><h3>Reviewed runbook</h3></header>
    <div className="plan-scope"><ShieldAltIcon aria-hidden="true" /><strong>{port ? "Host protocol/port classification" : file ? "Single evidenced object · no recursion" : "Host-wide SELinux boolean"}</strong><a href="#plan-rollback" onClick={() => setRollbackOpen(true)}>Rollback</a></div>
    <p>{plan.scope_description}</p>
    {evidenceRecord(plan.evidence_basis.home_content_review).confirmed === true && <p>Operator-confirmed home-content path: <code>{String(evidenceRecord(plan.evidence_basis.home_content_review).path)}</code></p>}
    <ExpandableSection className="plan-mechanism" toggleText="Why this affects the denial"><p>{plan.explanation}</p></ExpandableSection>
    <section id="plan-inspection" tabIndex={-1}><h3>1. Inspect host baseline <Label isCompact color="blue">Read-only</Label></h3>
      {port && <PriorPortMappings basis={plan.evidence_basis} />}
      <ReadOnlyCommands checks={plan.preview_steps.map((step) => ({ title: step.title, command: step.command, interpretation: step.explanation }))} />
      {detail && <OperatorChecks detail={detail} runbookCommands={plan.preview_steps.map((step) => step.command)} supplemental />}
    </section>
    <section><h3>2. Apply after inspection</h3>
    {!file && !port && <><p>{plan.persistence}</p><p>{plan.scope_warning}</p><p>{plan.expected_effect}</p></>}
      {file ? <ExpandableSection className="file-apply-disclosure" toggleText="Apply — only after successful inspection"><p>Stop if the object is missing, replaced, unintended, or its configured label is unsuitable.</p><p>{plan.scope_warning}</p><p>{plan.expected_effect}</p><p>{plan.persistence}</p>{plan.apply_steps.map((step) => <ChangePlanStep key={step.command} step={step} />)}</ExpandableSection>
        : plan.apply_steps.map((step) => <ChangePlanStep key={step.command} step={step} explanation={port ? "Persistently maps this protocol/port; may affect other workloads on this host." : undefined} />)}</section>
    <section aria-label={port ? "Verify port change" : "Verify workload"}><h3>{port ? "3. Verify classification & workload" : "3. Verify workload"}</h3>
      {!!plan.verification_steps?.length && <ReadOnlyCommands checks={plan.verification_steps.map((step) => ({ title: step.title, command: step.command, interpretation: port ? `Confirm ${String(plan.evidence_basis.target_port_type ?? "the reviewed type")} for this protocol/port.` : step.explanation }))} />}
      {detail ? <OperatorVerification detail={detail} inline includeLimit={!port || !plan.verification_steps?.length} /> : <p>Test the intended operation through the confined workload. Confirm the expected response, enforcement/domain state, fresh AVCs and event-delivery health.</p>}
    </section>
    <ExpandableSection className="plan-rollback" id="plan-rollback" tabIndex={-1} toggleText="Rollback procedure" isExpanded={showRollback} onToggle={(_event, expanded) => {
      setRollbackOpen(expanded);
      if (!expanded && params.get("phase") === "rollback") setParams((previous) => { const next = new URLSearchParams(previous); next.delete("phase"); return next; });
    }}><p>{plan.rollback_description}</p>{plan.rollback_steps.map((step) => <ChangePlanStep key={step.command} step={step} />)}</ExpandableSection>
    {plan.limitations.length > 0 && <div className="plan-uncertainty"><h3>Remaining uncertainty</h3><ul>{plan.limitations.map((text) => <li key={text}>{text}</li>)}</ul></div>}
    <EvidenceLink target="reviewed-plan-evidence" occurrenceId={typeof plan.evidence_basis.occurrence_id === "number" ? plan.evidence_basis.occurrence_id : undefined}>Evidence & provenance for this reviewed plan</EvidenceLink>
    <Button variant="secondary" onClick={() => download("secentral-change-plan.json", JSON.stringify(plan, null, 2))}>Export reviewed plan</Button>
  </section>;
}

type Candidate = Workflow["candidates"][number];
type SelectCandidate = (candidate: Candidate, review?: HomeContentReview) => void;

function CandidateSupport({ candidate }: { candidate: Candidate }) {
  const support = candidate.supporting_observations;
  if (!support?.length) return candidate.permissions && <p>Supporting signature: <code>{candidate.permissions.join(", ")}</code></p>;
  return <section aria-label="Remedy support">
    <p>Supporting permission sets: {support.map((item, index) => <span key={item.occurrence_id}>{index > 0 && " · "}<code>{item.permissions.join(", ")}</code></span>)}</p>
    <ExpandableSection toggleText="Supporting observations"><ul>{support.map((item) => <li key={item.occurrence_id}>
      <Link to={`/hosts/${candidate.host_id}/occurrences/${item.occurrence_id}`}>Example #{item.occurrence_id}</Link> · <code>{item.permissions.join(", ")}</code> · {item.enforcement_modes.join(", ")} · {item.occurrence_count} supporting occurrence{item.occurrence_count === 1 ? "" : "s"}
    </li>)}</ul><p>Current support is separate from the reviewed plan's evidence snapshot and from tracking decisions for each permission set.</p></ExpandableSection>
  </section>;
}

function candidatePresentation(candidate: Candidate) {
  const boolean = evidenceRecord(candidate.evidence_basis.current_boolean);
  const observedOn = (!boolean.status || boolean.status === "observed") && boolean.current === true;
  if (candidate.status === "proposed") return { state: "review", label: "Available for review" } as const;
  if (candidate.status === "evidence_changed") return { state: "verify", label: "Needs verification · plan unavailable" } as const;
  if (candidate.scope_kind === "host_boolean" && observedOn) return { state: "observed_on", label: "Last observed Boolean: On" } as const;
  return { state: "unsupported", label: "Plan unavailable" } as const;
}

function candidateNextStep(candidate: Candidate): string | null {
  const { state } = candidatePresentation(candidate);
  if (state === "observed_on") return "Recheck current runtime state and retry the intended workload before considering a policy change.";
  if (state === "verify") return candidate.kind === "restore_configured_label"
    ? "Refresh the host configuration evidence and verify the current file label before reviewing restoration."
    : "Refresh the missing or stale evidence identified below and inspect runtime state before reviewing a change.";
  if (state === "unsupported") return "Inspect the policy-evidence blocker below; no applicable change plan is supported by the retained evidence.";
  if (candidate.kind === "restore_configured_label") return "Inspect current object identity and host-configured labeling before reviewing targeted restoration.";
  if (candidate.requires_home_content_review) return "Identify the file, inspect its labels and configured home location, and confirm intentional home-content access before reviewing a Boolean change.";
  if (candidate.kind === "enable_boolean") return "Inspect runtime and persistent Boolean state, then review the host-wide impact before saving a plan.";
  return null;
}

function FocusedResource({ issueId, workflow, detail, stage, onShowTechnicalEvidence }: { issueId: number; workflow: Workflow; detail?: IssueDetailResponse; stage: "observed" | "context"; onShowTechnicalEvidence?: () => void }) {
  const [params] = useSearchParams();
  const active = activeResolutionResource(workflow, params.get("resource"), detail?.operator_guidance?.source);
  const candidate = active?.candidates[0];
  const source = detail?.operator_guidance?.source;
  const path = active?.path ?? (!active ? source?.path : null);
  const occurrenceId = active?.port?.occurrence_id ?? active?.source?.occurrence_id ?? candidate?.evidence_basis.occurrence_id ?? source?.occurrence_id;
  const hostId = active?.port?.host_id ?? active?.source?.host_id ?? candidate?.host_id ?? source?.host_id;
  const needsOccurrence = typeof occurrenceId === "number" && (occurrenceId !== workflow.observed_access?.occurrence_id || hostId !== workflow.observed_access?.host_id || !!path && path !== workflow.observed_access?.resource);
  const query = useQuery({ queryKey: ["issue-occurrence", issueId, occurrenceId], queryFn: () => fetchIssueOccurrence(issueId, occurrenceId as number), enabled: needsOccurrence });
  if (needsOccurrence && (query.isPending || query.isError || !query.data?.normalized_denial || query.data.id !== occurrenceId || query.data.host?.id !== hostId)) return <section aria-label={stage === "observed" ? "Observed access" : "Investigation context"}>{query.isPending ? <Spinner size="md" aria-label="Loading active resource" /> : <Alert isInline variant="warning" title="Active resource evidence unavailable"><Button variant="link" onClick={() => void query.refetch()}>Retry evidence</Button></Alert>}</section>;
  const occurrence = needsOccurrence ? query.data : undefined;
  const denial = occurrence?.normalized_denial;
  const access = occurrence && denial ? {
    occurrence_id: occurrence.id, host_id: occurrence.host.id, hostname: occurrence.host.hostname,
    actor: denial.command ?? denial.executable ?? "Process not recorded", source_type: denial.source_type ?? "Not recorded",
    resource: active?.port ? `${active.port.protocol.toUpperCase()}/${active.port.port ?? "port not recorded"}` : path ?? (denial.target_paths.length === 1 ? denial.target_paths[0] : "Resource identity not established"),
    target_type: denial.target_type ?? "Not recorded", object_class: denial.target_class ?? "unknown", permissions: denial.permissions ?? [],
    operation_label: (denial.permissions ?? []).join(", ") || "access", outcome: "DENIED" as const, observed_at: occurrence.occurred_at
  } : workflow.observed_access;
  return stage === "observed" ? access && <ObservedAccessFlow access={access} /> : detail && <ContextSidebar detail={detail} workflow={workflow} focusedAccess={access} onShowTechnicalEvidence={onShowTechnicalEvidence} />;
}

function priorPortState(basis: Record<string, unknown>) {
  return Array.isArray(basis.prior_mappings) && basis.prior_mappings.length
    ? basis.prior_mappings.map((item) => { const range = evidenceRecord(item); const source = range.provenance === "custom" ? "Local customization" : range.provenance === "not_confirmed_custom" ? "Policy default" : "Not recorded"; return `${range.type} ${range.start}–${range.end} (${source})`; }).join("; ")
    : "No intersecting record in the complete observed inventory; inspect before applying.";
}

function PriorPortMappings({ basis }: { basis: Record<string, unknown> }) {
  const observedRecords = Array.isArray(basis.prior_mappings) ? basis.prior_mappings.map((item) => { const range = evidenceRecord(item); return { type: range.type, start: range.start, end: range.end }; }) : [];
  const exactRecords = Array.isArray(basis.prior_policy_records) ? basis.prior_policy_records.map((item) => { const range = evidenceRecord(item); return { type: range.type, start: range.start, end: range.end }; }) : [];
  return <><p>Recorded prior state: {priorPortState(basis)}</p>{Array.isArray(basis.prior_policy_records) && JSON.stringify(observedRecords) !== JSON.stringify(exactRecords) && <p>Exact policy record boundaries: {basis.prior_policy_records.map((item) => {
    const record = evidenceRecord(item); return `${record.type} ${record.start}–${record.end}`;
  }).join("; ") || "No intersecting record"}. These distinguish add from modify when inventory ranges were coalesced.</p>}</>;
}

type PortInvestigationData = NonNullable<Workflow["port_investigations"]>[number];

function ResourceInspection({ issueId, occurrenceId, hostId, policyChecks = [] }: { issueId: number; occurrenceId: number; hostId?: number; policyChecks?: NonNullable<IssueDetailResponse["operator_guidance"]>["checks"] }) {
  const query = useQuery({ queryKey: ["issue-occurrence", issueId, occurrenceId], queryFn: () => fetchIssueOccurrence(issueId, occurrenceId) });
  if (query.isSuccess && (!query.data || typeof query.data !== "object" || query.data.id !== occurrenceId || !query.data.host || hostId != null && query.data.host.id !== hostId || !query.data.guidance)) return <section aria-label="Inspect active resource"><h3>Inspect host baseline</h3><p>Scoped checks are unavailable for this occurrence. Review its source record before continuing.</p></section>;
  const checks = query.data?.guidance?.checks ?? [];
  const commands = (policy: boolean) => checks.flatMap((check) => typeof check.command === "string" && (check.kind === "port_policy_alternatives") === policy ? [{ title: typeof check.reason === "string" ? check.reason : "Inspect current host state", command: check.command, interpretation: typeof check.expected === "string" ? check.expected : "" }] : []);
  const details = query.data?.normalized_denial?.details;
  const syscalls = Array.isArray(details?.syscall_evidence) ? details.syscall_evidence.map(evidenceRecord) : [];
  const syscallOutcome = syscalls.some((item) => ["no", "false", "0"].includes(String(item.success))) ? "Failed"
    : syscalls.length > 0 && syscalls.every((item) => ["yes", "true", "1"].includes(String(item.success))) ? "Succeeded" : "Not established";
  return <section aria-label="Inspect active resource"><h3>Inspect host baseline</h3>
    {query.isPending ? <Spinner aria-label="Loading resource inspection" size="md" /> : query.isError ? <Alert variant="warning" isInline title="Could not load resource inspection"><Button variant="link" onClick={() => void query.refetch()}>Retry inspection</Button></Alert>
      : <><p>Inspect on <Link to={`/hosts/${query.data.host.id}/occurrences/${occurrenceId}`}>{query.data.host.hostname} · #{occurrenceId}</Link></p>
        {details && <p><strong>Recorded AVC enforcement:</strong> {details.permissive === true ? "Non-enforced (permissive=1)" : details.permissive === false ? "Enforcing (permissive=0)" : "Not recorded"}. <strong>Recorded syscall result:</strong> {syscallOutcome}.</p>}
        {query.data.guidance ? <>
          <InspectionCommands primary={commands(false)} secondary={[...commands(true), ...policyChecks]} />
          {query.data.guidance.checks.filter((check) => !check.command && typeof check.reason === "string").map((check, index) => <p key={index}>{String(check.reason)}</p>)}</>
          : <p>No scoped inspection guidance is available. Review the occurrence record and identify the intended workload.</p>}
      </>}
  </section>;
}

function PortTypeSelection({ investigation, candidates, workflow, busy, onSelect }: { investigation: PortInvestigationData; candidates: Candidate[]; workflow: Workflow; busy: boolean; onSelect: (c: Candidate) => void }) {
  const fieldId = useId();
  const [service, setService] = useState("");
  const [search, setSearch] = useState("");
  const [type, setType] = useState<string | null>(null);
  const reviewed = candidates.find((item) => item.id === workflow.intent?.candidate_id);
  const selectedType = type ?? valueText(reviewed?.evidence_basis.target_port_type) ?? "";
  const selected = investigation.types.find((option) => option.type === selectedType);
  const candidate = candidates.find((item) => item.evidence_basis.target_port_type === selectedType);
  const services = [...new Map(investigation.types.flatMap((option) => option.service ? [[option.service.id, option.service] as const] : [])).values()];
  const query = search.trim().toLowerCase();
  const choices = investigation.types.filter((option) => (!service || option.service?.id === service) &&
    [option.type, option.service?.label, option.service?.description, option.state].filter(Boolean).join(" ").toLowerCase().includes(query));
  const clearFilters = () => { setService(""); setSearch(""); setType(""); };
  return <section className="pf-v6-u-mt-md" aria-label="Choose a port type">
    <Stack hasGutter>
      <StackItem><FormGroup fieldId={`${fieldId}-service`} label={investigation.operation === "name_bind" ? "What service should listen on this port?" : "What remote service does this workload connect to?"}>
        <FormSelect id={`${fieldId}-service`} value={service} onChange={(_event, value) => { setService(value); setSearch(""); setType(""); }}>
          <FormSelectOption value="" label="All services" />
          {services.map((item) => <FormSelectOption key={item.id} value={item.id} label={item.label} />)}
        </FormSelect>
      </FormGroup></StackItem>
      <StackItem><SearchInput aria-label="Search policy-supported port types" placeholder="Search types or reference service descriptions" value={search} onChange={(_event, value) => { setSearch(value); setType(""); }} onClear={() => { setSearch(""); setType(""); }} /></StackItem>
      <StackItem><FormGroup fieldId={`${fieldId}-type`} label="Policy-supported port type">
        <FormSelect id={`${fieldId}-type`} value={selectedType} onChange={(_event, value) => setType(value)}>
          <FormSelectOption value="" label="Choose a type to inspect" />
          {choices.map((option) => <FormSelectOption key={option.type} value={option.type} label={`${option.service ? `${option.service.label} — ` : ""}${option.type} · ${option.state.replaceAll("_", " ")}${option.service ? "" : " · description unavailable"}`} />)}
        </FormSelect>
      </FormGroup><small>{choices.length} of {investigation.type_count} policy types</small>
      {(service || search) && <Button variant="link" onClick={clearFilters}>Show all policy types</Button>}
      {!choices.length && <p role="status">No policy types match these filters. Clear the filters to inspect all discovered possibilities.</p>}</StackItem>
    </Stack>
    {selected && <section className="pf-v6-u-mt-md" aria-label="Selected port type">
      <h4>{selected.type} · {selected.permission} · {selected.state.replaceAll("_", " ")}</h4>
      {selected.service ? <><p>{selected.service.description}</p><p>Reference: <a href={selected.service.source_url}>{selected.service.source}</a> · <code>{selected.service.source_entry}</code> · <a href={selected.service.macro_url}>Type declaration macro</a></p></>
        : <p>No reference service description is available for this type.</p>}
      <p>{selected.explanation}</p>
      {selected.state === "conditional" && selected.conditional_rules?.length ? <section aria-label="Conditional port policy paths">
        <h5>Possible multi-step path · not a change recommendation</h5>
        <p>A mapping to this type alone will not enable the permission while these policy conditions are inactive or unknown. If the confirmed service intent warrants one of these capabilities, review it separately; after any approved Boolean change, refresh host evidence and review the mapping again. A Boolean has host-wide effects; a port mapping affects every workload using this host/protocol/port.</p>
        <ul>{selected.conditional_rules.map((condition) => <li key={condition.rule}><code>{condition.expression}</code> · {condition.branch} branch · {condition.state} at latest retained state <details><summary>Matching rule</summary><code>{condition.rule}</code></details></li>)}</ul>
      </section> : null}
      {selected.existing_endpoints.length > 0 && <p>Observed endpoint/range examples: {selected.existing_endpoints.map((range) => `${investigation.protocol.toUpperCase()}/${range.start}${range.end !== range.start ? `–${range.end}` : ""}`).join(", ")}. Confirm ownership and application configuration before using an existing endpoint.</p>}
      {candidate ? candidate.id === workflow.intent?.candidate_id ? <p>This is the reviewed selection shown below; browsing does not replace its review.</p> : <ResolutionCandidateCard key={candidate.id} candidate={candidate} selected={false} freshness={workflow.freshness} busy={busy} onSelect={onSelect} />
        : <p>The retained prerequisites do not support a reviewed mapping change for this type. Continue investigating the evidence and alternatives above.</p>}
    </section>}
  </section>;
}

function PortInvestigation({ investigation, workflow, busy, onSelect, children }: { investigation: PortInvestigationData; workflow: Workflow; busy: boolean; onSelect: (c: Candidate) => void; children?: ReactNode }) {
  const [reviewOpen, setReviewOpen] = useState(false);
  const bind = investigation.operation === "name_bind";
  const candidates = workflow.candidates.filter((item) => item.kind === "set_port_mapping" && item.host_id === investigation.host_id &&
    item.evidence_basis.protocol === investigation.protocol && item.evidence_basis.port === investigation.port && item.evidence_basis.operation === investigation.operation);
  const reviewedPort = workflow.freshness === "current" && candidates.some((item) => item.id === workflow.intent?.candidate_id);
  return <article className="pf-v6-u-mt-md" aria-label="Port investigation">
    <h3>{investigation.protocol.toUpperCase()}/{investigation.port ?? "port not recorded"} · {bind ? "Local bind" : "Outbound connect"} · {investigation.hostname ?? `Host ${investigation.host_id}`}</h3>
    <p><Link to={`/hosts/${investigation.host_id}/occurrences/${investigation.occurrence_id}`}>Occurrence #{investigation.occurrence_id}</Link> · AVC label <code>{investigation.observed_type}</code>{investigation.occurred_at && <> · recorded <time dateTime={investigation.occurred_at}>{new Date(investigation.occurred_at).toUTCString()}</time></>}</p>
    {!reviewedPort && !["ready", "unavailable"].includes(investigation.state) && <p>{investigation.reason}</p>}
    {investigation.inventory_status === "observed" && investigation.local_status === "observed" && investigation.current_mappings && <p><strong>Latest retained classification:</strong> {priorPortState({ prior_mappings: investigation.current_mappings })}{investigation.latest_observed_at && <> · observed <time dateTime={investigation.latest_observed_at}>{new Date(investigation.latest_observed_at).toUTCString()}</time></>}</p>}
    {(investigation.classification_differs === true || investigation.policy_differs === true) && <Alert isInline isPlain variant="info" title="Historical and latest evidence differ">
      {investigation.classification_differs === true && <p>The AVC target type differs from the latest retained port classification.</p>}
      {investigation.policy_differs === true && <p>The trusted historical and latest retained policy identities differ.</p>}
      {investigation.policy_differs == null && <p>A trusted historical-to-latest policy comparison is unavailable.</p>}
      <p>Check current effective/local mappings and retry the intended workload before reviewing a mapping change.</p>
    </Alert>}
    {(investigation.inventory_status !== "observed" || investigation.local_status !== "observed") && investigation.inventory_status && <p>Inventory coverage: effective {investigation.inventory_status} · local overrides {investigation.local_status ?? "unknown"}</p>}
    {children}
    {investigation.types.length > 0 && <ExpandableSection toggleText={reviewedPort ? "Explore another classification" : "Review port classification"} isExpanded={reviewOpen} onToggle={(_event, open) => setReviewOpen(open)}>
      {reviewOpen && <PortTypeSelection investigation={investigation} candidates={candidates} workflow={workflow} busy={busy} onSelect={onSelect} />}
    </ExpandableSection>}
  </article>;
}

function ResolutionCandidateCard({ candidate, selected, freshness, busy, onSelect }: { candidate: Candidate; selected: boolean; freshness: Workflow["freshness"]; busy: boolean; onSelect: SelectCandidate }) {
  const [confirming, setConfirming] = useState(false);
  const [homePath, setHomePath] = useState(candidate.home_content_path ?? "");
  const [homeConfirmed, setHomeConfirmed] = useState(false);
  const basis = candidate.evidence_basis;
  const boolean = evidenceRecord(basis.current_boolean);
  const state = boolean.status && boolean.status !== "observed" ? `Not verified (${String(boolean.status)})` : typeof boolean.current === "boolean" ? boolean.current ? "On" : "Off" : "Not verified";
  const presentation = candidatePresentation(candidate);
  const unavailable = presentation.state !== "review";
  const path = valueText(basis.path);
  const port = candidate.scope_kind === "host_port";
  const current = selected && freshness === "current";
  const historicalLimit = (text: string) => text === "Checkpoint state is not an AVC-time or apply-time measurement.";
  const visibleLimitations = candidate.limitations.filter((text) => !historicalLimit(text));
  if (current) return <article className="resolution-candidate-card resolution-selected" aria-label={optionTitle(basis, candidate.title)}>
    <header><h3>Reviewed selection: {optionTitle(basis, candidate.title)}</h3><Label color="blue" isCompact>Selected · current</Label></header>
    <CandidateSupport candidate={candidate} />
    <EvidenceLink target={`option-${candidate.id}`} occurrenceId={typeof basis.occurrence_id === "number" ? basis.occurrence_id : undefined}>Evidence supporting this option</EvidenceLink>
  </article>;
  return <article className={`resolution-candidate-card ${selected ? "resolution-selected" : ""} ${unavailable ? "candidate-muted" : ""}`} aria-label={optionTitle(basis, candidate.title)}>
    <header><ShieldAltIcon aria-hidden="true" /><h3>{path ?? (unavailable && valueText(basis.boolean) ? String(basis.boolean) : optionTitle(basis, candidate.title))}</h3>{selected && <Label color={current ? "blue" : "orange"} icon={<CheckCircleIcon />}>{current ? "Selected · current" : "Selected · review required"}</Label>}{unavailable && <Label color={presentation.state === "verify" ? "orange" : "grey"}>{presentation.label}</Label>}</header>
    <CandidateSupport candidate={candidate} />
    {unavailable && <Alert variant="info" isInline isPlain title={presentation.state === "verify" ? "Verify prerequisites before review" : "No proposed change plan"}>{candidate.unavailable_reason}</Alert>}
    {path ? <p className="candidate-label-change">AVC label <code>{valueText(basis.observed_context)?.split(":")[2] ?? "Not recorded"}</code><span aria-label="to">→</span> Configured label <code>{valueText(basis.expected_context)?.split(":")[2] ?? "Not recorded"}</code></p>
      : (port || !unavailable) && <p className="candidate-relevance">{port ? candidate.explanation : "Matching independent policy path"}</p>}
    <dl className="candidate-facts">{!path && !port && <div><dt>Recorded state</dt><dd>Off at checkpoint · last observed Boolean state: <Label color={state === "Off" ? "orange" : "grey"} isCompact>{state}</Label>. Recheck runtime state.</dd></div>}<div><dt>Scope</dt><dd>{port ? "Host protocol/port classification" : candidate.scope_kind === "host_boolean" ? "Host-wide boolean" : "Targeted path relabel"} · {candidate.hostname ?? "Host not recorded"}</dd></div>{typeof basis.occurrence_id === "number" && <div><dt>Evidence example</dt><dd><Link to={`/hosts/${candidate.host_id}/occurrences/${basis.occurrence_id}`}>Occurrence #{basis.occurrence_id}</Link></dd></div>}</dl>
    {candidate.scope_kind === "host_boolean" && <p className="candidate-breadth">Can enable broader access through other policy rules; not limited to this occurrence or destination.</p>}
    {!unavailable && (confirming ? <div className="intent-confirmation"><p>{candidate.intent_prompt}</p>
      {candidate.requires_home_content_review && <>
        <p>Identify the actual file on {candidate.hostname ?? "this host"} and inspect its current label and configured context first. Verify home-directory configuration through the account/NSS database (for example, getent passwd for a known account) and SELinux home mappings; /home or file ownership alone does not establish intent.</p>
        <label>Identified absolute file path<TextInput aria-label="Identified home-content file path" value={homePath} onChange={(_event, value) => { setHomePath(value); setHomeConfirmed(false); }} /></label>
        <label><input type="checkbox" checked={homeConfirmed} onChange={(event) => setHomeConfirmed(event.target.checked)} /> I completed these checks and intend Apache to serve this home content.</label>
      </>}
      <Button variant="primary" isDisabled={busy || (candidate.requires_home_content_review && (!homeConfirmed || !homePath.startsWith("/")))} onClick={() => onSelect(candidate, candidate.requires_home_content_review ? { path: homePath, confirmed: homeConfirmed } : undefined)}>Save reviewed plan</Button><Button variant="link" onClick={() => { setConfirming(false); setHomeConfirmed(false); }}>Cancel</Button></div>
           : <Button variant="primary" isDisabled={busy} onClick={() => setConfirming(true)}>{selected ? "Review updated change" : "Review this change"}</Button>)}
    <p>{candidate.scope_warning}</p>
    {visibleLimitations.length > 0 && <ul>{visibleLimitations.map((text) => <li key={text}>{text}</li>)}</ul>}
    <ExpandableSection toggleText="Evidence & limitations">
      {!path && !port && <p>Checkpoint: {valueText(basis.checkpoint_observed_at) ?? "Time not recorded"}. Latest observation: {candidate.latest_observed_at ?? "Time not recorded"}; not a fresh host inspection.</p>}
      {candidate.presentation_reason && <p>{candidate.presentation_reason}</p>}
      {candidate.limitations.filter(historicalLimit).map((text) => <p key={text}>{text}</p>)}
      <EvidenceLink target={`option-${candidate.id}`} occurrenceId={typeof basis.occurrence_id === "number" ? basis.occurrence_id : undefined}>{unavailable ? "Why is this shown?" : "Evidence supporting this option"}</EvidenceLink>
    </ExpandableSection>
  </article>;
}

function CandidateGroup({ candidates, workflow, busy, onSelect }: { candidates: Candidate[]; workflow: Workflow; busy: boolean; onSelect: SelectCandidate }) {
  const labels = candidates.filter((c) => c.kind === "restore_configured_label");
  const others = candidates.filter((c) => c.kind !== "restore_configured_label" && c.kind !== "set_port_mapping");
  const card = (candidate: Candidate) => <ResolutionCandidateCard key={`${candidate.id}:${candidate.evidence_version}`} candidate={candidate} selected={workflow.intent?.candidate_id === candidate.id} freshness={workflow.freshness} busy={busy} onSelect={onSelect} />;
  if (labels.length === 1 && !others.length) return card(labels[0]);
  return <>{labels.length > 0 && <section className="candidate-group" aria-label="Restore configured SELinux labeling"><h3>Restore configured SELinux labeling</h3><div className="candidate-grid candidate-paths">{labels.map(card)}</div></section>}
    {others.length > 0 && <div className="candidate-grid">{others.map(card)}</div>}</>;
}

function EvidenceChangeSummary({ workflow }: { workflow: Workflow }) {
  const reasons = workflow.freshness_reasons ?? [];
  return reasons.length ? <ul aria-label="What changed">{reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : null;
}

function DraftWorkspace({ issueId, occurrenceId }: { issueId: number; occurrenceId: number }) {
  const client = useQueryClient();
  const drafts = useQuery({ queryKey: ["policy-drafts", issueId], queryFn: () => fetchDrafts(issueId) });
  const [draftId, setDraftId] = useState<number | null>(null);
  const [name, setName] = useState("Custom policy draft");
  const [moduleName, setModuleName] = useState("secentral_local");
  const [literalConfirmed, setLiteralConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exported, setExported] = useState<PolicyDraftExport | null>(null);
  const selected = drafts.data?.drafts.find((d) => d.id === draftId) ?? drafts.data?.drafts[0];
  const run = async (action: () => Promise<unknown>) => {
    setBusy(true); setError(null); setExported(null); setLiteralConfirmed(false);
    try { await action(); await client.invalidateQueries({ queryKey: ["policy-drafts", issueId] }); }
    catch (e) { setError(e instanceof Error ? e.message : "Draft update failed"); }
    finally { setBusy(false); }
  };
  return <section aria-label="Custom policy draft workspace">
    <h3>Custom policy draft</h3><p>Stage evidence for policy review. Existing labeling or conditional mechanisms may avoid a new custom rule.</p>
    {error && <Alert variant="danger" isInline title="Draft action failed">{error}</Alert>}
    {drafts.isPending ? <Spinner size="md" /> : drafts.isError ? <Alert variant="warning" isInline title="Could not load drafts" /> : <>
      <label>Draft <select aria-label="Policy draft" value={selected?.id ?? ""} onChange={(e) => { setDraftId(Number(e.target.value)); setLiteralConfirmed(false); setExported(null); }}>{drafts.data.drafts.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</select></label>
      <TextInput aria-label="New draft name" value={name} onChange={(_e, value) => setName(value)} />
      <Button variant="secondary" isDisabled={busy || !name.trim()} onClick={() => void run(async () => { const d = await createDraft(issueId, name); setDraftId(d.id); })}>Create draft</Button>
      {selected && <>
        <Button variant="secondary" isDisabled={busy} onClick={() => void run(() => stagePermission(selected.id, issueId, occurrenceId))}>Add observed permission to Custom Policy Draft</Button>
        <p>{selected.name} · {selected.status} · {selected.entries.length} staged permission(s)</p>
        {selected.entries.map((entry) => <article key={entry.id}><p><code>{entry.source_type} → {entry.target_type}:{entry.object_class} {entry.permission}</code> · {entry.provenance.length} evidence reference(s)</p>
          {entry.known_alternatives.length > 0 && <div><strong>Known alternatives at staging</strong><ul>{entry.known_alternatives.map((alternative, index) => <li key={index}>{alternative.title} · {alternative.status.replaceAll("_", " ")}</li>)}</ul></div>}
          <TechnicalEvidenceDisclosure basis={{ evidence_references: entry.provenance }} title="Known alternatives and source evidence" />
          <Button variant="link" isDisabled={busy} onClick={() => void run(() => removeEntry(selected.id, entry.id))}>Remove staged permission</Button></article>)}
        <ul>{selected.limitations.map((text) => <li key={text}>{text}</li>)}</ul>
        <Button variant="secondary" isDisabled={busy || !selected.entries.length} onClick={() => void run(async () => { const result = await exportDraft(selected.id, "json"); setExported(result); download(result.filename, result.content); })}>Export semantic draft</Button>
        <ExpandableSection toggleText="Review proposed literal policy export"><p>A literal allow rule affects all objects of its target type, not just the recorded path or port. These rules have not been compiled or evaluated against the retained policy.</p>
          <TextInput aria-label="Policy module name" value={moduleName} onChange={(_e, value) => { setModuleName(value); setLiteralConfirmed(false); }} />
          <label><input type="checkbox" checked={literalConfirmed} onChange={(e) => setLiteralConfirmed(e.target.checked)} /> I reviewed the alternatives and intend the literal type-wide permissions in this draft.</label>
          <Button variant="secondary" isDisabled={busy || !literalConfirmed || !selected.entries.length} onClick={() => void run(async () => { const result = await exportDraft(selected.id, "te", moduleName, literalConfirmed, selected.evidence_version); setExported(result); download(result.filename, result.content); })}>Export proposed .te</Button>
        </ExpandableSection>
        {exported && <div><Label color="orange">{exported.validation_status}</Label><p>Exported {exported.filename}</p>{exported.validation_status === "unvalidated" && <pre>{exported.content}</pre>}{exported.build_steps.map((command) => <CopyCommand key={command} command={command} />)}<p>Compilation instructions do not establish exact-policy effectiveness. No installation command is generated.</p></div>}
      </>}
    </>}
  </section>;
}

export function ResolutionWorkflow({ issueId, stage, initialData, initialDataUpdatedAt, detail, onShowTechnicalEvidence, children }: { issueId: number; stage: "observed" | "intent" | "context" | "actions" | "draft"; initialData?: Workflow; initialDataUpdatedAt?: number; detail?: IssueDetailResponse; onShowTechnicalEvidence?: () => void; children?: ReactNode }) {
  const resourceFieldId = useId();
  const client = useQueryClient();
  const query = useQuery({ queryKey: ["issue-resolutions", issueId], queryFn: () => fetchResolutions(issueId), initialData, initialDataUpdatedAt, staleTime: 30_000 });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [params, setParams] = useSearchParams();
  const phase = params.get("phase");
  const requestedResource = params.get("resource");
  useEffect(() => {
    if (stage === "intent" && !phase && requestedResource) {
      document.querySelector<HTMLElement>('[aria-label="Investigation resources"] [role="tab"][aria-selected="true"]')?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
    }
  }, [stage, phase, requestedResource]);
  useEffect(() => {
    if (stage !== "intent" || !phase || !["inspection", "rollback"].includes(phase)) return;
    document.getElementById(`plan-${phase}`)?.focus();
    document.getElementById(`plan-${phase}`)?.scrollIntoView?.({ block: "start" });
  }, [stage, phase, requestedResource, query.dataUpdatedAt]);
  const showDrafts = params.get("workspace") === "draft";
  const toggleDrafts = () => setParams((previous) => {
    const next = new URLSearchParams(previous);
    if (showDrafts) next.delete("workspace"); else next.set("workspace", "draft");
    return next;
  });
  const run = async (action: () => Promise<unknown>) => {
    setBusy(true); setError(null);
    try { await action(); }
    catch (e) { setError(e instanceof Error ? e.message : "Change review failed"); }
    finally { await client.invalidateQueries({ queryKey: ["issue-resolutions", issueId] }); setBusy(false); }
  };
  if (query.isPending || query.isError) return stage === "intent" ? <Card isCompact className="resolution-options"><CardBody><section aria-label="Resolution options"><h2>Resolution workspace</h2>
    {query.isError ? <Alert variant="warning" isInline title="Could not load resolution options">{query.error.message}</Alert> : <Spinner size="md" aria-label="Loading resolution options" />}
    {!requestedResource && detail && <OperatorChecks detail={detail} />}
  </section></CardBody></Card> : stage === "observed" && query.isPending ? <Spinner size="md" aria-label="Loading observed access" /> : null;
  // A newly fetched issue core may be newer than the shared workflow cache.
  const workflow = initialData && (initialDataUpdatedAt ?? 0) > query.dataUpdatedAt ? initialData : query.data;
  if (stage === "observed" || stage === "context") return <FocusedResource issueId={issueId} workflow={workflow} detail={detail} stage={stage} onShowTechnicalEvidence={onShowTechnicalEvidence} />;
  if (stage === "actions") return <>
    {workflow.observed_access && <Button variant="secondary" onClick={toggleDrafts} isExpanded={showDrafts} aria-controls="issue-policy-draft">{showDrafts ? "Close policy draft workspace" : "Open policy draft workspace"}</Button>}
  </>;
  if (stage === "draft") return showDrafts && workflow.observed_access ? <section id="issue-policy-draft" className="issue-section">
    <p>Draft evidence: <Link to={`/hosts/${workflow.observed_access.host_id}/occurrences/${workflow.observed_access.occurrence_id}`}>{workflow.observed_access.hostname} · #{workflow.observed_access.occurrence_id}</Link>. Resource browsing does not change this staging source.</p>
    <DraftWorkspace key={`${issueId}-${workflow.observed_access.occurrence_id}`} issueId={issueId} occurrenceId={workflow.observed_access.occurrence_id} />
  </section> : null;
  const selected = workflow.candidates.find((c) => c.id === workflow.intent?.candidate_id);
  const source = detail?.operator_guidance?.source;
  const resources = resolutionResources(workflow, source);
  const reviewedResource = resources.find((resource) => resource.candidates.some((c) => c.id === workflow.intent?.candidate_id));
  const active = activeResolutionResource(workflow, requestedResource, source);
  const selectedHere = !!selected && !!active?.candidates.includes(selected);
  const alternatives = (active?.candidates ?? workflow.candidates).filter((c) => c.id !== selected?.id && c.kind !== "set_port_mapping");
  const primaryOptions = alternatives.filter((c) => c.presentation !== "technical_alternative");
  const technicalOptions = alternatives.filter((c) => c.presentation === "technical_alternative");
  const plan = selectedHere && workflow.freshness === "current" ? workflow.change_plan : null;
  const sameCheckScope = !!source && !!selected && selected.host_id === source.host_id &&
    (selected.kind === "set_port_mapping" ? selected.evidence_basis.port === source.port && selected.evidence_basis.protocol === source.protocol && selected.evidence_basis.operation === source.operation
      : selected.kind === "restore_configured_label" ? candidateFilePath(selected) === source.path : selected.evidence_basis.occurrence_id === source.occurrence_id);
  const inspectionElsewhere = !!active && !!source && (active.port ? active.port.host_id === source.host_id &&
    (active.port.occurrence_id === source.occurrence_id || (active.port.port === source.port && active.port.protocol === source.protocol && active.port.operation === source.operation))
    : active.source?.occurrence_id === source.occurrence_id || active.candidates.some((candidate) => candidate.host_id === source.host_id && (source.path ? candidateFilePath(candidate) === source.path : candidate.evidence_basis.occurrence_id === source.occurrence_id)));
  const nextCandidate = selectedHere ? selected : primaryOptions.find((candidate) => candidatePresentation(candidate).state === "observed_on") ?? primaryOptions.find((candidate) => candidatePresentation(candidate).state === "verify") ?? primaryOptions[0];
  const missingPath = detail && ["file", "dir"].includes(detail.issue?.target_class) && (active ? !active.port && !active.path : source && !source.path);
  const nextStep = plan ? "Inspect the reviewed host/resource baseline before making any change."
    : selectedHere && workflow.freshness && workflow.freshness !== "current" ? "Review the changed evidence and prerequisites below before saving an updated plan."
    : missingPath ? "Identify the complete target path before considering a file-label modification."
    : nextCandidate && candidatePresentation(nextCandidate).state !== "review" ? candidateNextStep(nextCandidate)
    : active?.port && ["ready", "no_change"].includes(active.port.state) && (active.port.classification_differs === true || active.port.policy_differs === true) ? "Recheck effective/local mappings and retry the intended confined workload; the historical denial and latest retained state differ."
    : active?.port?.operation === "name_bind" ? "Confirm the intended listener and existing port classification before selecting an SELinux port type."
    : active?.port?.operation === "name_connect" ? "Confirm the intended remote service, inspect runtime Boolean state and check port policy classification."
    : nextCandidate ? candidateNextStep(nextCandidate)
    : (!active || inspectionElsewhere) && source?.path ? "Inspect the current file label and host-configured labeling before considering restoration." : null;
  const resourceOccurrenceId = active?.port?.occurrence_id ?? active?.source?.occurrence_id ?? active?.candidates[0]?.evidence_basis.occurrence_id;
  const inspection = !plan && (active?.port ? <ResourceInspection key={active.key} issueId={issueId} occurrenceId={active.port.occurrence_id} hostId={active.port.host_id}
      policyChecks={source?.occurrence_id === active.port.occurrence_id && source.host_id === active.port.host_id ? detail?.operator_guidance?.checks.filter((check) => check.command.startsWith("getsebool ")) : undefined} />
    : (inspectionElsewhere || !active) && detail?.operator_guidance ? <OperatorChecks detail={detail} />
    : active && typeof resourceOccurrenceId === "number" && Number.isSafeInteger(resourceOccurrenceId) && resourceOccurrenceId > 0 ? <ResourceInspection key={active.key} issueId={issueId} occurrenceId={resourceOccurrenceId} /> : null);
  const compactPorts = resources.length > 0 && resources.every((resource) => resource.port && resource.port.host_id === resources[0].port?.host_id && resource.port.operation === resources[0].port?.operation);
  const resourceName = (resource: typeof resources[number]) => {
    if (compactPorts && resource.port) return `${resource.port.protocol.toUpperCase()}/${resource.port.port ?? "port not recorded"}`;
    return fileResourceLabel(resource, resources);
  };
  const useTabs = resources.length <= 5 && !(resources.length > 3 && resources.some((resource) => resource.path));
  const resourceLabel = (resource: typeof resources[number]) => `${resourceName(resource)}${resource.port?.occurrence_count != null ? ` (${resource.port.occurrence_count} denial${resource.port.occurrence_count === 1 ? "" : "s"})` : ""}${resource === reviewedResource ? workflow.freshness === "current" ? " · Review current" : " · Review required" : ""}`;
  const navigateResource = (key: string) => setParams((previous) => {
    const next = new URLSearchParams(previous);
    next.set("resource", key);
    next.delete("phase");
    return next;
  });
  const choose: SelectCandidate = (candidate, review) => void run(() => selectIntent(issueId, candidate.id, candidate.evidence_version, review));
  return <Card isCompact className="resolution-options"><CardBody>
    <section aria-label="Resolution options"><header className="workbench-section-header"><h2>Resolution workspace</h2>{workflow.intent && <Button variant="link" isDisabled={busy} onClick={() => void run(() => clearIntent(issueId))}>Clear reviewed plan</Button>}</header>
      {error && <Alert variant="danger" isInline title="Change review failed">{error}</Alert>}
      {workflow.freshness && workflow.freshness !== "current" && <div className="stale-plan" role="alert"><h3><ExclamationTriangleIcon aria-hidden="true" /> {workflow.freshness === "no_longer_supported" ? "Plan no longer supported" : "Evidence changed"}</h3><p>This plan was reviewed against older SELinux state. Commands are hidden until the updated evidence is reviewed.</p><EvidenceChangeSummary workflow={workflow} /><strong>Review this option again before using its commands.</strong></div>}
      {workflow.intent && !selectedHere && <p role="status" className="resource-review-notice">
        {reviewedResource ? <>Viewing {active ? resourceName(active) : "another resource"}; the reviewed plan is on {resourceName(reviewedResource)}. <Button variant="link" onClick={() => navigateResource(reviewedResource.key)}>Switch to reviewed plan</Button></>
          : <>The reviewed resource is no longer supported by retained evidence; no reviewed commands are shown.</>}
      </p>}
      {resources.length > 1 && (useTabs ? <Tabs activeKey={active.key} onSelect={(_event, key) => navigateResource(String(key))} aria-label="Investigation resources" isBox>
        {resources.map((resource) => <Tab key={resource.key} eventKey={resource.key} aria-label={`${resource.label}${resourceLabel(resource).slice(resourceName(resource).length)}`} title={<TabTitleText><span title={resource.label}>{resourceLabel(resource)}</span></TabTitleText>} tabContentId="issue-resource-panel" />)}
      </Tabs> : <FormGroup label="Host / resource" fieldId={resourceFieldId}>
        <FormSelect id={resourceFieldId} aria-label="Active investigation resource" value={active.key} onChange={(_event, key) => navigateResource(key)}>
          {resources.map((resource) => <FormSelectOption key={resource.key} value={resource.key} label={resource.label + resourceLabel(resource).slice(resourceName(resource).length)} />)}
        </FormSelect>
      </FormGroup>)}
      <section id="issue-resource-panel" role={resources.length > 1 && useTabs ? "tabpanel" : undefined} tabIndex={0} aria-label={`Active resource: ${active?.label ?? "Investigation example"}`}>
      {active && !active.port && <p><strong>Inspecting:</strong> {active.label}</p>}
      {nextStep && <p className="suggested-next-step" aria-label="Suggested next step"><strong>Suggested next step</strong> · {nextStep}</p>}
      {detail?.operator_guidance && (!active || inspectionElsewhere) && source?.path && <p>{detail.operator_guidance.possible_fix}</p>}
      {active?.port ? <PortInvestigation key={`${issueId}-${active.key}`} investigation={active.port} workflow={workflow} busy={busy} onSelect={choose}>{inspection}</PortInvestigation> : inspection}
      {(!active || inspectionElsewhere) && children}
      {!active?.port && !workflow.candidates.length && !children && <p>No reviewed change plan yet. Use the checks above and review the workload configuration with its operator; a manual next step can be appropriate.</p>}
      {selectedHere && (selected.kind === "set_port_mapping" ? <ResolutionCandidateCard candidate={selected} selected freshness={workflow.freshness} busy={busy} onSelect={choose} /> : <CandidateGroup candidates={[selected]} workflow={workflow} busy={busy} onSelect={choose} />)}
      {plan && <ChangePlan plan={plan} detail={sameCheckScope ? detail : undefined} />}
      {selectedHere ? alternatives.length > 0 && <ExpandableSection className="other-options" toggleText={`Alternative approaches · ${alternatives.length}${alternatives.some((candidate) => candidate.scope_kind === "host_boolean") ? " · Host-wide Boolean; broader access" : ""}`}><CandidateGroup candidates={alternatives} workflow={workflow} busy={busy} onSelect={choose} /></ExpandableSection>
         : <><CandidateGroup candidates={primaryOptions} workflow={workflow} busy={busy} onSelect={choose} />{technicalOptions.length > 0 && <ExpandableSection className="other-options" toggleText={`Alternative policy approaches · ${technicalOptions.length} · Host-wide scope`}><p>Matching policy paths do not establish workload intent. Identify the resource, inspect its configuration and review the capability's broader effects.</p><CandidateGroup candidates={technicalOptions} workflow={workflow} busy={busy} onSelect={choose} /></ExpandableSection>}</>}
      {!plan && detail?.triage_guidance && (!active || inspectionElsewhere) && <ExpandableSection toggleText="Post-restoration verification checklist"><OperatorVerification detail={detail} inline /></ExpandableSection>}
      </section>
    </section>
  </CardBody></Card>;
}
