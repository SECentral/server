import {
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Tab,
  TabTitleText,
  Tabs
} from "@patternfly/react-core";
import { useState } from "react";
import { Link } from "react-router-dom";
import type { OccurrenceDetail } from "../api/issue";
import { OccurrenceRawEvidence } from "./OccurrenceEvidence";

function Facts({ fields }: { fields: [string, React.ReactNode][] }) {
  return (
    <DescriptionList isHorizontal isCompact columnModifier={{ default: "1Col", xl: "2Col" }}>
      {fields
        .filter(([, value]) => value !== null && value !== undefined && value !== "")
        .map(([label, value]) => (
          <DescriptionListGroup key={label}>
            <DescriptionListTerm>{label}</DescriptionListTerm>
            <DescriptionListDescription>{value}</DescriptionListDescription>
          </DescriptionListGroup>
        ))}
    </DescriptionList>
  );
}

const BASIS_LABELS: Record<string, string> = {
  avc_record: "AVC record",
  issue_occurrences: "Issue occurrences",
  fleet_comparison: "Fleet comparison",
  current_configuration_fleet: "Current configuration",
  occurrence_file_context_evidence: "Occurrence file-context evidence"
};

function Guidance({ occurrence }: { occurrence: OccurrenceDetail }) {
  const guidance = occurrence.guidance;
  if (!guidance) return <p className="pf-v6-u-color-200">No occurrence-specific guidance was generated.</p>;

  return (
    <div className="occurrence-investigation-guidance">
      {guidance.summary && <p className="pf-v6-u-color-200">{guidance.summary}</p>}
      {guidance.observations.length > 0 && (
        <section>
          <h3>Observed evidence</h3>
          <ul>
            {guidance.observations.map((item, index) => {
              const observation = typeof item["observation"] === "string" ? item["observation"] : "Retained audit evidence was observed.";
              const certainty = item["certainty"] === "derived" ? "Derived evidence" : "Observed evidence";
              const rawBasis = item["basis"];
              const basis = typeof rawBasis === "string" ? BASIS_LABELS[rawBasis] ?? rawBasis.replaceAll("_", " ") : null;
              return <li key={index}><p>{observation}</p><small>{certainty}{basis ? ` · Basis: ${basis}` : ""}</small></li>;
            })}
          </ul>
        </section>
      )}
      {guidance.checks.length > 0 && (
        <section>
          <h3>Investigation checks</h3>
          <ul>
            {guidance.checks.map((check, index) => {
              const reason = typeof check["reason"] === "string" ? check["reason"] : "Review related SELinux and audit evidence.";
              const target = typeof check["target"] === "string" ? check["target"] : null;
              return <li key={index}>{reason}{target ? <> <code>{target}</code></> : null}</li>;
            })}
          </ul>
        </section>
      )}
      <section>
        <h3>Missing evidence</h3>
        {guidance.missing_evidence.length > 0
          ? <ul>{guidance.missing_evidence.map((item) => <li key={item}>{item}</li>)}</ul>
          : <p>No missing evidence identified.</p>}
      </section>
      <section>
        <h3>Limitations</h3>
        {guidance.historical_limitations.length > 0
          ? <ul>{guidance.historical_limitations.map((item) => <li key={item}>{item}</li>)}</ul>
          : <p>No additional limitations reported.</p>}
      </section>
    </div>
  );
}

export function OccurrenceInvestigation({ occurrence }: { occurrence: OccurrenceDetail }) {
  const [tab, setTab] = useState<"summary" | "guidance" | "evidence">("summary");
  const denial = occurrence.normalized_denial;
  return (
    <div className="occurrence-investigation">
      <Tabs activeKey={tab} onSelect={(_event, key) => setTab(String(key) as typeof tab)} aria-label="Occurrence details">
        <Tab eventKey="summary" title={<TabTitleText>Summary</TabTitleText>} />
        <Tab eventKey="guidance" title={<TabTitleText>Guidance</TabTitleText>} />
        <Tab eventKey="evidence" title={<TabTitleText>Raw evidence</TabTitleText>} />
      </Tabs>
      <section className="occurrence-investigation-panel" role="tabpanel" aria-label={`${tab} details`}>
        {tab === "summary" && (
          <Facts fields={[
            ["Source type", denial.source_type && <code>{denial.source_type}</code>],
            ["Target type", denial.target_type && <code>{denial.target_type}</code>],
            ["Class", denial.target_class && <code>{denial.target_class}</code>],
            ["Permission", denial.permissions?.map((permission) => <code key={permission}>{permission}</code>)],
            ["Process", denial.command && <code>{denial.command}</code>],
            ["Executable", denial.executable && <code>{denial.executable}</code>],
            ["Source context", denial.source_context && <code>{denial.source_context}</code>],
             ["Target context", denial.target_context && <code>{denial.target_context}</code>],
             ["AVC-local enforcement", denial.details.enforcement_mode === "permissive" ? "Non-enforced (AVC permissive=1)" : denial.details.enforcement_mode === "enforcing" ? "Enforced (AVC permissive=0)" : "Unknown"],
               ["Trusted host enforcement for this occurrence", occurrence.raw_event.checkpoint_enforcement_mode],
               ["Source domain policy state", occurrence.raw_event.permissive_policy_state?.status === "observed" && occurrence.raw_event.permissive_policy_state.source_domain_permissive !== null
                 ? <span>{denial.source_type} is {occurrence.raw_event.permissive_policy_state.source_domain_permissive ? "permissive" : "not permissive"} in exact policy <code>{occurrence.raw_event.permissive_policy_state.policy_identity}</code>.</span>
                 : "Unknown — trusted exact-policy membership is unavailable"],
              ["Checkpoint port inventory", occurrence.raw_event.checkpoint_port_inventory_status],
              ["Checkpoint expected-label mappings", occurrence.raw_event.checkpoint_file_context_mappings_status],
            ["Observed path", denial.target_paths.length ? denial.target_paths.map((path) => <code key={path}>{path}</code>) : "None recorded"],
            ["Issue", occurrence.issue ? <Link to={`/issues/${occurrence.issue.id}?tab=occurrences`}>Issue #{occurrence.issue.id}</Link> : "Ungrouped event"]
          ]} />
        )}
        {tab === "guidance" && <Guidance occurrence={occurrence} />}
        {tab === "evidence" && <OccurrenceRawEvidence occurrence={occurrence} collapsed />}
      </section>
    </div>
  );
}
