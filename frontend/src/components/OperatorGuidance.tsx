import { Label, Title } from "@patternfly/react-core";
import { Link } from "react-router-dom";
import type { IssueDetailResponse } from "../api/issue";
import { CopyCommand } from "./ResolutionWorkflow";

function ReadOnlyCheck({ check }: { check: NonNullable<IssueDetailResponse["operator_guidance"]>["checks"][number] }) {
  return <article className="pf-v6-u-mt-md">
    <h3>{check.title} <Label color="blue" isCompact>{check.title.includes("preview") ? "Read-only preview" : "Read-only check"}</Label></h3>
    <CopyCommand command={check.command} />
    <details><summary>How to interpret the result</summary><p>{check.interpretation}</p><p>If tooling is missing or the check fails, confirm the host setup with its operator; a failed check is not a successful comparison.</p></details>
  </article>;
}

export function OperatorChecks({ detail }: { detail: IssueDetailResponse }) {
  const guidance = detail.operator_guidance;
  if (!guidance) return null;
  const { source } = guidance;
  const latest = detail.resolutions?.observed_access;
  const different = latest && (latest.occurrence_id !== source.occurrence_id || (source.path && latest.resource !== source.path));
  const expected = detail.diagnosis?.occurrence_id === source.occurrence_id ? detail.diagnosis : null;
  const primaryCount = source.path ? 3 : 1;
  return <section className="issue-section" aria-label="Check">
    <Title headingLevel="h2" size="xl">Check</Title>
    <p>Investigation example: <Link to={`/hosts/${source.host_id}/occurrences/${source.occurrence_id}`}>{source.hostname ?? `Host ${source.host_id}`} · occurrence #{source.occurrence_id}</Link>{source.path && <> · <code>{source.path}</code></>}</p>
    {different && <p>{latest.occurrence_id !== source.occurrence_id
      ? "The diagram shows the latest occurrence; these checks use a different retained investigation example. Do not apply one host's results to another."
       : "These checks use one retained path from the latest occurrence; its diagram does not identify a single resource. Use the linked evidence to confirm the object."}</p>}
    {!detail.diagnosis && detail.triage_guidance && <p>The convention lead uses the lexicographically first qualifying retained path, not necessarily the latest occurrence.</p>}
    <dl className="issue-technical-facts">
      <div><dt>Recorded at denial</dt><dd><code>{source.observed_type ?? "Not recorded"}</code> · <time dateTime={source.occurred_at}>{source.occurred_at}</time></dd></div>
      {source.path && <><div><dt>Current object label</dt><dd>Inspect on host; local results have not been observed by SECentral.</dd></div>
        <div><dt>Host-configured context</dt><dd>{expected?.expected_context ? <><code>{expected.expected_context}</code> · checked after denial at {expected.expected_context_observed_at ?? "retained inspection time"}; recheck current configuration.</> : "Look up on host; not established by a convention."}</dd></div></>}
    </dl>
    <p>{guidance.manual_check}</p>
    {guidance.checks.slice(0, primaryCount).map((check) => <ReadOnlyCheck key={check.command} check={check} />)}
    {guidance.checks.length > primaryCount && <details className="pf-v6-u-mt-md"><summary>More read-only checks</summary>
      {guidance.checks.slice(primaryCount).map((check) => <ReadOnlyCheck key={check.command} check={check} />)}
    </details>}
  </section>;
}

export function StandardRestoration({ detail }: { detail: IssueDetailResponse }) {
  const guidance = !detail.diagnosis ? detail.triage_guidance : null;
  if (!guidance) return null;
  const source = detail.operator_guidance?.source;
  return <section aria-label="Optional restoration after verification">
    <h3>Restore only after checking <Label color="orange">Changes file labels</Label></h3>
    <p>Only if the current object differs from suitable host-configured labeling. Uses configured mappings, including local customizations; does not guarantee access. SECentral does not execute commands.</p>
    <p>Targeted scope: <code>{guidance.path}</code> on {source?.path === guidance.path
      ? <Link to={`/hosts/${source.host_id}/occurrences/${source.occurrence_id}`}>{source.hostname ?? `Host ${source.host_id}`} · occurrence #{source.occurrence_id}</Link>
      : "the affected host verified from its occurrence evidence"} only; stop for a missing or replaced object.</p>
    {guidance.commands.filter((item) => item.action === "restore_targeted").map((item) => <CopyCommand key={item.action} command={item.command} />)}
    {guidance.recursive_directory && <details className="pf-v6-u-mt-md"><summary>Broader alternative: recursive restoration</summary>
      <Label color="orange">Changes file labels</Label>
      <p>Entire directory <code>{guidance.recursive_directory}</code>, including unrelated files. {guidance.recursive_path_count} of {guidance.path_count} qualifying retained paths lie beneath it; not occurrence or host coverage. Verify scope separately on each affected host.</p>
      {guidance.commands.filter((item) => item.action === "restore_recursive").map((item) => <CopyCommand key={item.action} command={item.command} />)}
    </details>}
  </section>;
}

export function OperatorVerification({ detail }: { detail: IssueDetailResponse }) {
  const guidance = detail.operator_guidance;
  if (!guidance) return null;
  return <section className="issue-section" aria-label="Verify">
    <Title headingLevel="h2" size="xl">Verify</Title>
    <p>{guidance.verification}</p>
    <p className="pf-v6-u-mt-sm">{guidance.verification_limit}</p>
    <details className="pf-v6-u-mt-sm"><summary>If you keep the restriction</summary><p>{guidance.restriction}</p></details>
  </section>;
}
