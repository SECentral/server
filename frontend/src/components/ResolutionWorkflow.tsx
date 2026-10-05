import { Alert, Button, Label, Spinner, TextInput } from "@patternfly/react-core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import ShieldAltIcon from "@patternfly/react-icons/dist/esm/icons/shield-alt-icon";
import CheckCircleIcon from "@patternfly/react-icons/dist/esm/icons/check-circle-icon";
import ExclamationTriangleIcon from "@patternfly/react-icons/dist/esm/icons/exclamation-triangle-icon";
import CopyIcon from "@patternfly/react-icons/dist/esm/icons/copy-icon";
import type { IssueDetailResponse } from "../api/issue";
import { ContextSidebar, ObservedAccessFlow, TechnicalEvidenceDisclosure, evidenceRecord, valueText } from "./WorkbenchEvidence";
import { clearIntent, createDraft, exportDraft, fetchDrafts, fetchResolutions, removeEntry, selectIntent, stagePermission,
  type ChangePlan as PlanData, type PolicyDraftExport, type ResolutionWorkflow as Workflow } from "../api/resolution";

function download(filename: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function CopyCommand({ command }: { command: string }) {
  const [message, setMessage] = useState("");
  return <div className="command-block"><pre tabIndex={0} aria-label="Exact command"><code>{command}</code></pre><Button variant="secondary" icon={<CopyIcon />} aria-label={`Copy ${command}`} onClick={() => {
    if (!navigator.clipboard) { setMessage("Copy unavailable; select the command text"); return; }
    void navigator.clipboard.writeText(command).then(() => setMessage("Copied"), () => setMessage("Copy unavailable; select the command text"));
  }}>Copy</Button><small role="status">{message}</small></div>;
}

function optionTitle(basis: Record<string, unknown>, title: string) {
  return valueText(basis.boolean) ? `Enable ${basis.boolean}` : valueText(basis.path) ? "Restore configured SELinux labeling" : title;
}

function ChangePlanStep({ step, number }: { step: PlanData["preview_steps"][number]; number?: number }) {
  return <article className="change-plan-step"><header>{number != null && <span className="step-number">{number}</span>}<h3>{step.title}</h3>
    <Label color={step.persistence === "persistent" ? "orange" : "blue"} isCompact>{step.persistence === "persistent" ? "Persistent · optional" : step.persistence === "temporary" ? "Runtime only" : step.title.toLowerCase().includes("preview") ? "Non-mutating preview" : step.persistence === "inspection" ? "Inspect" : "Single object"}</Label></header>
    <CopyCommand command={step.command} /><details className="step-detail"><summary>Step details</summary><p>{step.explanation}</p></details></article>;
}

function ChangePlan({ plan }: { plan: PlanData }) {
  const file = plan.scope_kind === "single_object";
  return <section className="selected-change-plan" aria-label="Selected change plan"><header className="workbench-section-header"><h2>Selected change plan</h2><Label color="blue">Reviewed · current</Label></header>
    <h3 className="plan-title">{optionTitle(plan.evidence_basis, plan.title)}</h3>
    <div className="plan-scope"><ShieldAltIcon aria-hidden="true" /><strong>{file ? "Single evidenced object · no recursion" : "Host-wide SELinux boolean"}</strong><a href="#plan-rollback">Rollback ↓</a></div>
    <p className="plan-warning"><ExclamationTriangleIcon aria-hidden="true" /> {file ? "Current object has not been verified. Inspect it and its configured label before proceeding." : "May affect other policy rules beyond this occurrence."}</p>
    <details className="plan-mechanism"><summary>Why this affects the denial · scope & expected effect</summary><p>{plan.explanation}</p><p>{plan.expected_effect}</p><p>{plan.scope_description}</p><p>{plan.scope_warning}</p><p>{plan.persistence}</p></details>
    <div className="plan-steps" id="plan-inspection">{plan.preview_steps.map((step, i) => <ChangePlanStep key={step.command} step={step} number={i + 1} />)}
      {file ? <details className="file-apply-disclosure"><summary>Apply — only after successful inspection</summary><p>Stop if the object is missing, replaced, or not the intended resource.</p>{plan.apply_steps.map((step, i) => <ChangePlanStep key={step.command} step={step} number={plan.preview_steps.length + i + 1} />)}</details>
        : plan.apply_steps.map((step, i) => <ChangePlanStep key={step.command} step={step} number={plan.preview_steps.length + i + 1} />)}</div>
    <section className="plan-rollback" id="plan-rollback"><h3>Rollback</h3>{plan.rollback_steps.map((step) => <ChangePlanStep key={step.command} step={step} />)}<p>{plan.rollback_description}</p></section>
    <details className="plan-uncertainty"><summary>Remaining uncertainty</summary><ul>{plan.limitations.map((text) => <li key={text}>{text}</li>)}</ul></details>
    <TechnicalEvidenceDisclosure basis={plan.evidence_basis} />
    <Button variant="secondary" onClick={() => download("secentral-change-plan.json", JSON.stringify(plan, null, 2))}>Export reviewed plan</Button>
    <small className="workbench-caption">Selection, copy and export do not apply a change.</small>
  </section>;
}

type Candidate = Workflow["candidates"][number];

function ResolutionCandidateCard({ candidate, selected, freshness, busy, onSelect }: { candidate: Candidate; selected: boolean; freshness: Workflow["freshness"]; busy: boolean; onSelect: (c: Candidate) => void }) {
  const [confirming, setConfirming] = useState(false);
  const basis = candidate.evidence_basis;
  const boolean = evidenceRecord(basis.current_boolean);
  const state = typeof boolean.current === "boolean" ? boolean.current ? "On" : "Off" : "Not verified";
  const unavailable = candidate.status !== "proposed";
  const path = valueText(basis.path);
  const current = selected && freshness === "current";
  return <article className={`resolution-candidate-card ${selected ? "resolution-selected" : ""} ${unavailable ? "candidate-muted" : ""}`} aria-label={optionTitle(basis, candidate.title)}>
    <header><ShieldAltIcon aria-hidden="true" /><h3>{path ?? (unavailable && valueText(basis.boolean) ? String(basis.boolean) : optionTitle(basis, candidate.title))}</h3>{selected && <Label color={current ? "blue" : "orange"} icon={<CheckCircleIcon />}>{current ? "Selected · current" : "Selected · review required"}</Label>}</header>
    {path ? <p className="candidate-label-change"><code>{valueText(basis.observed_context)?.split(":")[2] ?? "Observed label"}</code><span aria-label="to">→</span><code>{valueText(basis.expected_context)?.split(":")[2] ?? "Expected label"}</code></p>
      : <p className="candidate-relevance">{unavailable && state === "On" ? "This capability is already enabled." : "Matching independent policy path"}</p>}
    <dl className="candidate-facts">{!path && <div><dt>Current state</dt><dd><Label color={state === "Off" ? "orange" : "grey"} isCompact>{state}</Label></dd></div>}<div><dt>Scope</dt><dd>{candidate.scope_kind === "host_boolean" ? "Host-wide" : "Single object"}</dd></div></dl>
    <p className="candidate-breadth">{candidate.scope_kind === "host_boolean" ? "Broader than this occurrence / destination" : "Inspect before applying · no recursion"}</p>
    {unavailable ? <p className="candidate-unavailable">{state === "On" ? "Enabling it is not a current resolution option." : "Current retained evidence does not support an actionable plan."}</p>
      : current ? <span className="selected-association"><CheckCircleIcon aria-hidden="true" /> Selected plan below</span>
        : confirming ? <div className="intent-confirmation"><p>{candidate.intent_prompt}</p><Button variant="primary" isDisabled={busy} onClick={() => onSelect(candidate)}>Confirm intent</Button><Button variant="link" onClick={() => setConfirming(false)}>Cancel</Button></div>
          : <Button variant="primary" isDisabled={busy} onClick={() => setConfirming(true)}>{selected ? "Review updated option" : path ? "Choose this path" : "Choose intent"}</Button>}
    <TechnicalEvidenceDisclosure basis={{ explanation: candidate.explanation, scope: candidate.scope_description, breadth: candidate.scope_warning, ...basis, limitations: candidate.limitations }} title={unavailable ? "Why is this shown?" : "Evidence supporting this option"} />
  </article>;
}

function CandidateGroup({ candidates, workflow, busy, onSelect }: { candidates: Candidate[]; workflow: Workflow; busy: boolean; onSelect: (c: Candidate) => void }) {
  const labels = candidates.filter((c) => c.kind === "restore_configured_label");
  const others = candidates.filter((c) => c.kind !== "restore_configured_label");
  const card = (candidate: Candidate) => <ResolutionCandidateCard key={candidate.id} candidate={candidate} selected={workflow.intent?.candidate_id === candidate.id} freshness={workflow.freshness} busy={busy} onSelect={onSelect} />;
  if (labels.length === 1 && workflow.intent?.candidate_id === labels[0].id && !others.length) return card(labels[0]);
  return <>{labels.length > 0 && <section className="candidate-group" aria-label="Restore configured SELinux labeling"><h3>Restore configured SELinux labeling <span aria-hidden="true">· </span><small>{labels.length} path{labels.length === 1 ? "" : "s"} with retained candidates</small></h3><div className="candidate-grid candidate-paths">{labels.map(card)}</div></section>}
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
        <details><summary>Review proposed literal policy export</summary><p>A literal allow rule affects all objects of its target type, not just the recorded path or port. These rules have not been compiled or evaluated against the retained policy.</p>
          <TextInput aria-label="Policy module name" value={moduleName} onChange={(_e, value) => { setModuleName(value); setLiteralConfirmed(false); }} />
          <label><input type="checkbox" checked={literalConfirmed} onChange={(e) => setLiteralConfirmed(e.target.checked)} /> I reviewed the alternatives and intend the literal type-wide permissions in this draft.</label>
          <Button variant="secondary" isDisabled={busy || !literalConfirmed || !selected.entries.length} onClick={() => void run(async () => { const result = await exportDraft(selected.id, "te", moduleName, literalConfirmed, selected.evidence_version); setExported(result); download(result.filename, result.content); })}>Export proposed .te</Button>
        </details>
        {exported && <div><Label color="orange">{exported.validation_status}</Label><p>Exported {exported.filename}</p>{exported.validation_status === "unvalidated" && <pre>{exported.content}</pre>}{exported.build_steps.map((command) => <CopyCommand key={command} command={command} />)}<p>Compilation instructions do not establish exact-policy effectiveness. No installation command is generated.</p></div>}
      </>}
    </>}
  </section>;
}

export function ResolutionWorkflow({ issueId, stage, initialData, initialDataUpdatedAt, detail }: { issueId: number; stage: "observed" | "intent" | "context"; initialData?: Workflow; initialDataUpdatedAt?: number; detail?: IssueDetailResponse }) {
  const client = useQueryClient();
  const query = useQuery({ queryKey: ["issue-resolutions", issueId], queryFn: () => fetchResolutions(issueId), initialData, initialDataUpdatedAt, staleTime: 30_000 });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showDrafts, setShowDrafts] = useState(false);
  const run = async (action: () => Promise<unknown>) => {
    setBusy(true); setError(null);
    try { await action(); }
    catch (e) { setError(e instanceof Error ? e.message : "Intent update failed"); }
    finally { await client.invalidateQueries({ queryKey: ["issue-resolutions", issueId] }); setBusy(false); }
  };
  if (query.isPending) return stage === "observed" ? <Spinner size="md" aria-label="Loading observed access" /> : null;
  if (query.isError) return stage === "intent" ? <Alert variant="warning" isInline title="Could not load resolution options">{query.error.message}</Alert> : null;
  // A newly fetched issue core may be newer than the shared workflow cache.
  const workflow = initialData && (initialDataUpdatedAt ?? 0) > query.dataUpdatedAt ? initialData : query.data;
  if (stage === "observed") {
    const access = workflow.observed_access;
    return access ? <ObservedAccessFlow access={access} /> : null;
  }
  if (stage === "context") return detail ? <ContextSidebar detail={detail} workflow={workflow} /> : null;
  const selected = workflow.candidates.find((c) => c.id === workflow.intent?.candidate_id);
  const alternatives = workflow.candidates.filter((c) => c.id !== selected?.id);
  const choose = (c: Candidate) => void run(() => selectIntent(issueId, c.id, c.evidence_version));
  return <>
    <section className="resolution-options" aria-label="Resolution options"><header className="workbench-section-header"><h2>Resolution options</h2>{workflow.intent && <Button variant="link" isDisabled={busy} onClick={() => void run(() => clearIntent(issueId))}>Clear selected intent</Button>}</header>
      {error && <Alert variant="danger" isInline title="Intent update failed">{error}</Alert>}
      {workflow.freshness && workflow.freshness !== "current" && <div className="stale-plan" role="alert"><h3><ExclamationTriangleIcon aria-hidden="true" /> {workflow.freshness === "no_longer_supported" ? "Plan no longer supported" : "Evidence changed"}</h3><p>This plan was reviewed against older SELinux state. Commands are hidden until the updated evidence is reviewed.</p><EvidenceChangeSummary workflow={workflow} /><strong>Review this option again before using its commands.</strong></div>}
      {!workflow.candidates.length && <p>No mechanically supported resolution candidate is available from retained evidence.</p>}
      {selected ? <><CandidateGroup candidates={[selected]} workflow={workflow} busy={busy} onSelect={choose} />{alternatives.length > 0 && <details className="other-options"><summary>Other options · {alternatives.length}</summary><CandidateGroup candidates={alternatives} workflow={workflow} busy={busy} onSelect={choose} /></details>}</>
        : <><CandidateGroup candidates={workflow.candidates} workflow={workflow} busy={busy} onSelect={choose} /><p className="workbench-caption">You can choose neither and continue investigating.</p></>}
    </section>
    {workflow.change_plan && workflow.freshness === "current" && <ChangePlan plan={workflow.change_plan} />}
    <details className="other-approaches"><summary>Other approaches & intent history</summary><details><summary>Options not offered</summary><ul>{workflow.rejected_candidates.map((c, i) => <li key={i}><strong>{c.kind.replaceAll("_", " ")}:</strong> {c.reason}</li>)}</ul></details>
      <details><summary>Intent history</summary><ul>{workflow.history.map((change, i) => <li key={i}>{change.created_at} · {change.operator} · {change.action}</li>)}</ul></details>
      {workflow.observed_access && <><p>Need a custom SELinux policy instead?</p><Button variant="secondary" onClick={() => setShowDrafts(!showDrafts)}>{showDrafts ? "Close policy draft workspace" : "Open policy draft workspace"}</Button>{showDrafts && <DraftWorkspace issueId={issueId} occurrenceId={workflow.observed_access.occurrence_id} />}</>}
    </details>
  </>;
}
