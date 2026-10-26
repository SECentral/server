import {
  Alert,
  Card,
  CardBody,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Grid,
  GridItem,
  Stack,
  StackItem,
  Tab,
  TabTitleText,
  Tabs,
  Title
} from "@patternfly/react-core";
import { Link, useSearchParams } from "react-router-dom";
import type { OccurrenceDetail } from "../api/issue";
import { OccurrenceNormalizedDetails, OccurrenceRawEvidence } from "./OccurrenceEvidence";

function Facts({ fields }: { fields: [string, React.ReactNode][] }) {
  return (
    <DescriptionList orientation={{ sm: "horizontal" }} isCompact isFluid>
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

function Summary({ occurrence }: { occurrence: OccurrenceDetail }) {
  const denial = occurrence.normalized_denial;
  const policy = occurrence.raw_event.permissive_policy_state;
  const mode = occurrence.enforcement_mode ?? denial.details.enforcement_mode;
  const hostMode = occurrence.raw_event.checkpoint_enforcement_mode;
  const network = denial.details.network_evidence;
  const networkFields = network && typeof network === "object" && !Array.isArray(network) ? network as Record<string, unknown> : {};
  const ports = (key: string) => Array.isArray(networkFields[key])
    ? networkFields[key].filter((value): value is string | number => typeof value === "string" || typeof value === "number").join(", ")
    : null;
  const networkFacts: [string, React.ReactNode][] = [
    ["Bind port", ports("bind_port_fields")],
    ["Destination port (dport)", ports("dport_fields")],
    ["Destination field (dest)", ports("dest_fields")],
    ["Local port", ports("lport_fields")],
    ["Protocol field", ports("proto_fields")]
  ];
  const pathApplicable = !denial.target_class?.endsWith("_socket") && !["socket", "capability", "capability2", "cap_userns", "cap2_userns"].includes(denial.target_class ?? "");

  return <Stack hasGutter>
    <StackItem><Card isCompact aria-label="Access identity">
      <CardBody><Grid hasGutter>
        <GridItem md={6}><section aria-label="Process (Subject)">
          <Title headingLevel="h2" size="md" className="pf-v6-u-mb-md">Process (Subject)</Title>
          <Facts fields={[
            ["Process", denial.command ? <code>{denial.command}</code> : "Not recorded"],
            ["Executable", denial.executable ? <code>{denial.executable}</code> : "Not recorded"],
            ["Source type", denial.source_type && <code>{denial.source_type}</code>],
            ["Source context", denial.source_context && <code>{denial.source_context}</code>]
          ]} />
        </section></GridItem>
        <GridItem md={6}><section aria-label="Target (Object)">
          <Title headingLevel="h2" size="md" className="pf-v6-u-mb-md">Target (Object)</Title>
          <Facts fields={[
            ["Class", denial.target_class && <code>{denial.target_class}</code>],
            ["Permission", denial.permissions?.join(", ")],
            ["Target type", denial.target_type && <code>{denial.target_type}</code>],
            ["Target context", denial.target_context && <code>{denial.target_context}</code>],
            ["Observed path", pathApplicable ? denial.target_paths.length ? denial.target_paths.map((path) => <div key={path}><code>{path}</code></div>) : "Complete path not recorded" : null]
          ]} />
        </section></GridItem>
        {networkFacts.some(([, value]) => value) && <GridItem><section aria-label="Network Detail">
          <Title headingLevel="h2" size="md" className="pf-v6-u-mb-md">Network Detail</Title><Facts fields={networkFacts} />
        </section></GridItem>}
      </Grid></CardBody>
    </Card></StackItem>
    <StackItem><Card isCompact>
      <CardTitle><h2>Enforcement &amp; policy context</h2></CardTitle>
      <CardBody><Facts fields={[
        ["Enforcement", <span>
          {mode === "enforcing" ? "Enforcing (AVC permissive=0)" : mode === "permissive" ? "Non-enforced (AVC permissive=1)" : "Unknown — AVC enforcement not recorded"}
          {hostMode !== mode && <> · Associated checkpoint mode: {hostMode ?? "unavailable"}</>}
        </span>],
        ["Associated syscall outcome", occurrence.syscall_outcome ?? "unknown"],
        ["Event assembly", occurrence.raw_event.completion_reason === "eoe" ? "End-of-event record retained; continuous audit capture is not established" : `${occurrence.raw_event.completion_reason} — record completeness not established`],
        ["Source domain policy state", policy?.status === "observed" && typeof policy.source_domain_permissive === "boolean"
          ? `${denial.source_type ?? "Source domain"} is ${policy.source_domain_permissive ? "permissive" : "not permissive"} in the exact policy retained for this occurrence.`
          : "Unknown — trusted exact-policy membership is unavailable"],
        ["Issue", occurrence.issue ? <>Belongs to Issue #{occurrence.issue.id}. <Link to={`/issues/${occurrence.issue.id}`}>View Issue #{occurrence.issue.id} Investigation &amp; Change Review →</Link></> : "Ungrouped event"]
      ]} /><p>AVC enforcement, checkpoint mode and syscall outcome are separate observations. Application impact and the cause of a failed syscall are not established.</p></CardBody>
    </Card></StackItem>
  </Stack>;
}

export function OccurrenceInvestigation({ occurrence }: { occurrence: OccurrenceDetail }) {
  const [params, setParams] = useSearchParams();
  const requestedTab = params.get("tab");
  const tab = requestedTab === "evidence" || requestedTab === "normalized" ? requestedTab : "summary";
  return (
    <div className="occurrence-investigation">
      {occurrence.superseded_at && <Alert variant="warning" isInline title="Historical interpretation superseded">
        Reprocessing replaced this interpretation. It is retained for evidence and review history, but excluded from current counts and change guidance.
      </Alert>}
      <Tabs activeKey={tab} onSelect={(_event, key) => setParams((previous) => {
        const next = new URLSearchParams(previous);
        if (key === "summary") next.delete("tab");
        else next.set("tab", String(key));
        return next;
      })} aria-label="Occurrence details">
        <Tab eventKey="summary" title={<TabTitleText>Summary</TabTitleText>} />
        <Tab eventKey="evidence" title={<TabTitleText>Raw evidence</TabTitleText>} />
        <Tab eventKey="normalized" title={<TabTitleText>Normalized details</TabTitleText>} />
      </Tabs>
      <section className="occurrence-investigation-panel" role="tabpanel" aria-label={`${tab} details`}>
        {tab === "summary" && <Summary occurrence={occurrence} />}
        {tab === "evidence" && <OccurrenceRawEvidence occurrence={occurrence} includeNormalized={false} />}
        {tab === "normalized" && <OccurrenceNormalizedDetails occurrence={occurrence} />}
      </section>
    </div>
  );
}
