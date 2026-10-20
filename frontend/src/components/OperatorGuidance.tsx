import { Alert, Label, Title } from "@patternfly/react-core";
import { Link } from "react-router-dom";
import type { IssueDetailResponse } from "../api/issue";
import { CopyCommand } from "./ResolutionWorkflow";
import { Disclosure } from "./Disclosure";

export function ReadOnlyCommands({ checks }: { checks: NonNullable<IssueDetailResponse["operator_guidance"]>["checks"] }) {
  if (!checks.length) return null;
  return <div className="inspection-commands">{checks.map((check) => <div key={check.command} className="inspection-command">
    <p className="inspection-command-header"><strong>{check.command.startsWith("getsebool ") ? check.title.replace(/^Current Boolean:/, "Inspect runtime Boolean:") : check.title}</strong>{check.interpretation && <> · <span>{check.interpretation}</span></>}</p>
    <CopyCommand command={check.command} />
  </div>)}</div>;
}

export function OperatorChecks({ detail, runbookCommands = [], supplemental = false }: { detail: IssueDetailResponse; runbookCommands?: string[]; supplemental?: boolean }) {
  const guidance = detail.operator_guidance;
  if (!guidance) return null;
  const { source } = guidance;
  const latest = detail.resolutions?.observed_access;
  const different = latest && (latest.occurrence_id !== source.occurrence_id || (source.path && latest.resource !== source.path));
  const expected = detail.diagnosis?.occurrence_id === source.occurrence_id ? detail.diagnosis : null;
  const primaryCount = source.path || source.operation === "name_bind" ? 3 : 1;
  const primary = guidance.checks.slice(0, primaryCount).filter((check) => !runbookCommands.includes(check.command));
  const secondary = guidance.checks.slice(primaryCount).filter((check) => !runbookCommands.includes(check.command));
  if (supplemental && !primary.length && !secondary.length) return null;
  return <section className="workspace-inspection" aria-label="Check">
    {(!supplemental || primary.length > 0) && <h3>{supplemental ? "Resource inspection" : "Inspect host baseline"}</h3>}
    {!supplemental && <>
    <p>Investigation example: <Link to={`/hosts/${source.host_id}/occurrences/${source.occurrence_id}`}>{source.hostname ?? `Host ${source.host_id}`} · occurrence #{source.occurrence_id}</Link>{source.path && <> · <code>{source.path}</code></>}</p>
    {different && <p>Checks are scoped to the linked investigation example. Do not apply one host's results to another.</p>}
    {!detail.diagnosis && detail.triage_guidance && <p>The convention lead uses the lexicographically first qualifying retained path, not necessarily the latest occurrence.</p>}
    {source.path && <p>Historical AVC label: <code>{source.observed_type ?? "Not recorded"}</code>. Current object label: inspect on host; local results have not been observed by SECentral. Host-configured context: {expected?.expected_context ? <><code>{expected.expected_context}</code> · checked after denial at {expected.expected_context_observed_at ?? "retained inspection time"}; recheck current configuration.</> : "Look up on host; not established by a convention."}</p>}
    {!source.path && ["file", "dir"].includes(detail.issue?.target_class) ? <Alert variant="info" isInline isPlain title="Complete target path not recorded">Identify the files this workload is accessing before considering a labeling or Boolean change.</Alert> : <p>{guidance.manual_check}</p>}
    </>}
    {primary.length > 0 && <ReadOnlyCommands checks={primary} />}
    {secondary.length > 0 && <Disclosure className="pf-v6-u-mt-sm" toggleText="Policy inspection">
      <ReadOnlyCommands checks={secondary} />
    </Disclosure>}
    {!supplemental && <small>A failed check is not a successful comparison; resolve missing tooling or failures with the host operator.</small>}
  </section>;
}

export function StandardRestoration({ detail }: { detail: IssueDetailResponse }) {
  const guidance = !detail.diagnosis ? detail.triage_guidance : null;
  if (!guidance) return null;
  const source = detail.operator_guidance?.source;
  return <section aria-label="Optional restoration after verification">
    <h3>Restore only after checking <Label color="orange">Changes file labels</Label></h3>
    <p>Only if the current object differs from suitable host-configured labeling. Uses configured mappings, including local customizations; does not guarantee access.</p>
    <p>Targeted scope: <code>{guidance.path}</code> on {source?.path === guidance.path
      ? <Link to={`/hosts/${source.host_id}/occurrences/${source.occurrence_id}`}>{source.hostname ?? `Host ${source.host_id}`} · occurrence #{source.occurrence_id}</Link>
      : "the affected host verified from its occurrence evidence"} only; stop for a missing or replaced object.</p>
    {guidance.commands.filter((item) => item.action === "restore_targeted").map((item) => <CopyCommand key={item.action} command={item.command} />)}
    {guidance.recursive_directory && <Disclosure className="pf-v6-u-mt-md" toggleText="Broader alternative: recursive restoration">
      <Label color="orange">Changes file labels</Label>
      <p>Entire directory <code>{guidance.recursive_directory}</code>, including unrelated files. {guidance.recursive_path_count} of {guidance.path_count} qualifying retained paths lie beneath it; not occurrence or host coverage. Verify scope separately on each affected host.</p>
      {guidance.commands.filter((item) => item.action === "restore_recursive").map((item) => <CopyCommand key={item.action} command={item.command} />)}
    </Disclosure>}
  </section>;
}

export function OperatorVerification({ detail, inline = false, includeLimit = true }: { detail: IssueDetailResponse; inline?: boolean; includeLimit?: boolean }) {
  const guidance = detail.operator_guidance;
  if (!guidance) return null;
  return <section className="issue-section" aria-label="Verify">
    {!inline && <Title headingLevel="h3" size="lg">Verify the investigation example</Title>}
    {!inline && <p className="workbench-caption">Scope: {guidance.source.hostname ?? `Host ${guidance.source.host_id}`} · occurrence #{guidance.source.occurrence_id}. Other resources require their own workload verification.</p>}
    <p>{guidance.verification}</p>
    {includeLimit && <p className="pf-v6-u-mt-sm">Check enforcement/domain permissiveness and event-delivery health alongside the workload result.</p>}
    <Disclosure className="pf-v6-u-mt-sm" toggleText="If you keep the restriction"><p>{guidance.restriction}</p></Disclosure>
  </section>;
}
