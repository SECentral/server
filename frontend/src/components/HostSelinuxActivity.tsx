import { Alert, Button, Card, CardBody, DescriptionList, DescriptionListDescription, DescriptionListGroup, DescriptionListTerm, ExpandableSection, Grid, GridItem, Pagination, Spinner, Title, Tooltip } from "@patternfly/react-core";
import { ChevronDownIcon, ChevronRightIcon, InfoCircleIcon } from "@patternfly/react-icons";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  fetchHostSelinuxActivityEvidence,
  type SelinuxActivityItem,
  type SelinuxActivityResponse,
  type SelinuxCheckpoint
} from "../api/hosts";
import { EvidenceBlock, formatUtc } from "./OccurrenceEvidence";

function time(iso: string): string {
  return iso.replace("T", " ").replace(/Z$/, " UTC");
}

function state(value: boolean | null): string {
  return value === true ? "On" : value === false ? "Off" : "Unknown";
}

function mode(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function Checkpoint({ checkpoint, title }: { checkpoint: SelinuxCheckpoint; title: string }) {
  return (
    <div className="selinux-activity-checkpoint">
      <strong>{title}</strong>{" "}<time dateTime={checkpoint.event_time}>{time(checkpoint.event_time)}</time>
      <p>{checkpoint.booleans.map((boolean) => <span key={boolean.name}><code>{boolean.name}</code>: {state(boolean.value)} · </span>)}
        {checkpoint.enforcement ? ` · ${checkpoint.enforcement}` : ""}</p>
    </div>
  );
}

function AuditFacts({ fields }: { fields: [string, React.ReactNode][] }) {
  return <DescriptionList orientation={{ sm: "horizontal" }} isCompact isFluid>
    {fields.map(([label, value]) => <DescriptionListGroup key={label}><DescriptionListTerm>{label}</DescriptionListTerm><DescriptionListDescription>{value}</DescriptionListDescription></DescriptionListGroup>)}
  </DescriptionList>;
}

function ActivityItem({ item, selected }: { item: SelinuxActivityItem; selected: boolean }) {
  const [expanded, setExpanded] = useState(selected);
  const [historyExpanded, setHistoryExpanded] = useState(false);
  const details = useQuery({
    queryKey: ["host-selinux-activity-evidence", item.host_id, item.id],
    queryFn: () => fetchHostSelinuxActivityEvidence(item.host_id, item.id),
    enabled: expanded
  });
  const activity = details.data?.item ?? item;
  const { reconciliation } = activity;
  const checkpoint = reconciliation.checkpoint;
  const actor = details.data?.item.actor ?? item.actor;
  const enforcement = activity.transition_type === "enforcement_change";
  const ports = activity.transition_type === "port_change";
  const portChanges = activity.port_changes ?? [];
  const portSummary = portChanges.map((change) => `${change.protocol.toUpperCase()}/${change.start}${change.end === change.start ? "" : `-${change.end}`} · ${change.operation}${change.selinux_type ? ` → ${change.selinux_type}` : ""}${change.boundary_established ? "" : " · boundary not established"}`).join("; ") || "Port configuration reported · boundary not established";
  const enforcementChanges = activity.enforcement_changes ?? [];
  const persistentRequested = actor?.proctitle?.split(/\s+/).some((argument) => argument === "-P" || argument === "--persistent");
  const title = ports ? (activity.boundary_established ? "Port mapping write reported" : "Port configuration reported") : !activity.boundary_established ? (enforcement ? "Enforcement status reported" : activity.transition_type === "policy_load" ? "Policy load reported" : "Boolean change reported")
    : activity.transition_type === "policy_load" ? "SELinux policy loaded"
    : enforcement ? "Enforcement changed"
    : activity.boolean_changes.length > 1 ? "SELinux booleans changed" : "Boolean changed";

  return (
    <Tbody>
      <Tr id={`selinux-activity-${item.id}`} aria-label={`SELinux activity ${item.id}`}>
        <Td dataLabel="Timestamp"><time dateTime={activity.event_time} title={activity.event_time}>{formatUtc(activity.event_time)}</time></Td>
        <Td dataLabel="Type">{ports ? "Port mapping" : enforcement ? "Enforcement" : activity.transition_type === "policy_load" ? "Policy load" : "Boolean"}</Td>
        <Td dataLabel="Summary" className="selinux-activity-summary">{ports ? portSummary : enforcement ? enforcementChanges.length ? enforcementChanges.map((change, index) => <span key={index}>
          {index ? "; " : ""}{change.state_change_established ? "" : "Reported: "}{mode(change.old_mode)} → {mode(change.new_mode)}{change.state_change_established ? "" : " · state change not established"}
        </span>) : "Enforcement status reported · state change not established" : activity.transition_type === "policy_load" ? title : activity.boolean_changes.map((change, index) => <span key={`${change.name}-${index}`}>
          {index > 0 ? "; " : ""}<code>{change.name}</code>: {change.state_change_established ? "" : "Reported: "}{state(change.old_value)} → {state(change.new_value)}{change.state_change_established ? "" : " · state change not established"}
        </span>)}</Td>
        <Td dataLabel="User / Origin">{actor?.login_uid != null ? <code>UID {actor.login_uid}</code> : "Unknown user"}{actor?.command ? <> · <code>{actor.command}</code></> : null}</Td>
        <Td dataLabel="Action"><Button variant="link" isInline icon={expanded ? <ChevronDownIcon aria-hidden="true" /> : <ChevronRightIcon aria-hidden="true" />} aria-expanded={expanded} aria-controls={`selinux-audit-${item.id}`} onClick={() => setExpanded((value) => !value)}>{expanded ? "Hide Audit" : "View Audit"}</Button></Td>
      </Tr>
      {expanded ? <Tr><Td colSpan={5}><div id={`selinux-audit-${item.id}`} className="selinux-activity-item" role="region" aria-label={`SELinux activity ${item.id} audit`}>
        <Grid hasGutter>
          <GridItem span={12} lg={6}><section aria-label="Execution Context">
            <Title headingLevel="h3" size="md">Execution Context</Title>
            <AuditFacts fields={[
              ["Timestamp", <time dateTime={activity.event_time}>{time(activity.event_time)}</time>],
              ["Execution User / PID", <code>UID {actor?.execution_uid ?? "Unknown"}{actor?.execution_uid === 0 ? " (root)" : ""} / PID {actor?.pid ?? "Unknown"}</code>],
              ["Command Executed", <code>{actor?.executable ?? actor?.command ?? "Unknown"}</code>],
               ["Scope", <Tooltip content="A validated runtime record establishes an observed change. Command flags record requested scope, not proof of saved configuration."><span tabIndex={0}>{enforcement ? "Temporary (runtime)" : persistentRequested ? "Persistent (command request)" : activity.transition_type === "boolean_change" ? "Temporary (runtime)" : "Unknown"}</span></Tooltip>],
               ["Audit Identity", <code>{ports ? "USER_MAC_CONFIG_CHANGE" : enforcement ? "MAC_STATUS" : activity.transition_type === "policy_load" ? "MAC_POLICY_LOAD" : "MAC_CONFIG_CHANGE"} · {activity.audit_sequence}</code>]
            ]} />
          </section></GridItem>
          <GridItem span={12} lg={6}><section aria-label="SELinux Policy Effect">
            <Title headingLevel="h3" size="md">SELinux Policy Effect</Title>
            <AuditFacts fields={[
               ["Affected Target", ports ? portSummary : enforcement ? "Runtime host enforcement mode" : activity.boolean_changes.length ? activity.boolean_changes.map((change) => <code key={change.name}>{change.name} </code>) : "Kernel policy"],
              ["System Context", <code>{actor?.context ?? "Unknown"}</code>],
              ["Reconciliation", !activity.boundary_established ? "State change not established; this event did not invalidate the checkpoint."
                : reconciliation.status === "pending" ? "State awaiting reconciliation."
                : reconciliation.status === "superseded" ? <>Another transition was observed before reconciliation. {reconciliation.next_transition ? <Link to={`/hosts/${item.host_id}?selinux_activity=${reconciliation.next_transition.id}#selinux-activity`}>View later transition</Link> : null}</>
                : "Observed at host checkpoint"],
              ["Observed Result", title],
              ["Host Checkpoint", checkpoint ? <Checkpoint checkpoint={checkpoint} title={reconciliation.status === "pending" ? "Later incomplete checkpoint" : reconciliation.status === "superseded" ? "Later SELinux state observed" : "SELinux state confirmed"} /> : "No later checkpoint retained for this boot"]
            ]} />
          </section></GridItem>
        </Grid>
          {details.isPending ? <Spinner size="md" aria-label="Loading transition evidence" />
            : details.isError ? <Alert variant="warning" isInline title="Could not load transition evidence" />
            : details.data ? <>
               {activity.window_avc_count > 0 ? <section aria-label="Unresolved interval AVCs">
                 <strong>{activity.window_avc_count} {activity.window_avc_count === 1 ? "AVC" : "AVCs"} in the unresolved interval.</strong>
                <p>These AVCs occurred after this observed transition, before a refreshed checkpoint could apply, or before a further transition. This relationship does not establish causation.</p>
                <ul>{details.data.item.window_occurrences.map((occurrence) => <li key={occurrence.id}>
                  <Link to={`/hosts/${item.host_id}/occurrences/${occurrence.id}`}>Occurrence #{occurrence.id}</Link>{" "}
                  <time dateTime={occurrence.event_time}>{time(occurrence.event_time)}</time>
                  {occurrence.issue_id ? <> · <Link to={`/issues/${occurrence.issue_id}`}>Issue #{occurrence.issue_id}</Link></> : null}
                </li>)}</ul>
                {details.data.item.window_occurrences.length < activity.window_avc_count ? <p>Showing the {details.data.item.window_occurrences.length} most recent retained interval occurrences of {activity.window_avc_count}.</p> : null}
              </section> : null}
              <section aria-label="Original audit records">
                   <EvidenceBlock hasCopyButton value={details.data.item.evidence.records.map((record) => record.payload).join("\n")} label={`SELinux activity ${item.id} audit records`} />
              </section>
             </> : null}
        <ExpandableSection className="host-disclosure host-technical-details" toggleText="Technical Provenance & Hashes" toggleIcon={historyExpanded ? <ChevronDownIcon aria-hidden="true" /> : <ChevronRightIcon aria-hidden="true" />} isExpanded={historyExpanded} onToggle={(_event, value) => setHistoryExpanded(value)}>
          {historyExpanded ? <>
            {activity.previous_checkpoint ? <Checkpoint checkpoint={activity.previous_checkpoint} title="Earlier historical checkpoint" /> : <p>No earlier checkpoint retained for this boot.</p>}
             {activity.transition_type === "policy_load" && activity.boundary_established ? <p>Previous exact policy state invalidated. The load record does not identify the new policy SHA.</p> : null}
              {enforcement && activity.boundary_established ? <p>The earlier checkpoint's host enforcement state became untrusted until refresh. Exact policy identity and boolean evidence remain valid. AVC-local permissive evidence is separate.</p> : null}
              {ports && activity.boundary_established ? <p>Port inventory and exact policy identity are unknown until refresh. This successful write may be an equal-value modify; no port delta is reconstructed. AVC-local target context remains evidence. Separate policy-load boundaries can invalidate additional checkpoint evidence.</p> : null}
            <p>The audit transition is separate from checkpoint observations. Command fields provide context, not the authority for a state change.</p>
            <AuditFacts fields={[
              ["Boot", <code>{activity.boot_id}</code>],
              ["Audit session", <code>{actor?.session ?? "Unknown"}</code>],
              ["Process title", <code>{actor?.proctitle ?? "Unknown"}</code>],
              ["Earlier checkpoint ID", <code>{activity.previous_checkpoint?.id ?? "Unknown"}</code>],
              ["Earlier policy ID", <code>{activity.previous_checkpoint?.policy_identity ?? "Unknown"}</code>],
              ["Host checkpoint ID", <code>{checkpoint?.id ?? "Unknown"}</code>],
              ["Host checkpoint policy ID", <code>{checkpoint?.policy_identity ?? "Unknown"}</code>],
              ["Evidence digest", <code>{details.data?.item.evidence.digest ?? "Unavailable"}</code>]
            ]} />
          </> : null}
        </ExpandableSection>
      </div></Td></Tr> : null}
    </Tbody>
  );
}

export function HostSelinuxActivity({ activity }: { activity: UseQueryResult<SelinuxActivityResponse, Error> }) {
  const [params, setParams] = useSearchParams();
  const before = params.get("activity_before") ?? undefined;
  const selected = Number(params.get("selinux_activity")) || undefined;
  const requestedPage = Number(params.get("activity_page") ?? 1);
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
  function navigate(page = 1) {
    setParams((previous) => {
      const next = new URLSearchParams(previous);
      next.delete("selinux_activity");
      next.delete("activity_before");
      next.set("activity_page", String(page));
      return next;
    });
  }
  return (
    <section id="selinux-activity" className="host-activity-section" aria-label="SELinux activity">
      <Card className="host-surface-card host-table-card"><CardBody>
      <div className="host-activity-heading selinux-activity-heading">
        <Title headingLevel="h2" size="lg">SELinux Administrative Activity ({activity.data?.meta.total?.toLocaleString("en-US") ?? "…"})</Title>
        <Tooltip content={<><p>Supported policy loads, runtime boolean/enforcement changes, and validated SELinux port writes observed in this host's audit stream.</p><p>{activity.data?.coverage ?? "Absence of an event does not prove that no change occurred."}</p></>}>
          <Button variant="plain" aria-label="About SELinux administrative activity"><InfoCircleIcon aria-hidden="true" /></Button>
        </Tooltip>
      </div>
      {selected ? <p>Selected activity · <Button variant="link" isInline onClick={() => navigate()}>Show recent SELinux activity</Button></p> : null}
      {activity.isPending ? <Spinner aria-label="Loading SELinux activity" />
        : activity.isError ? <Alert variant="warning" isInline title="Could not load SELinux activity">{activity.error.message}</Alert>
        : <>
          {activity.data.items.length === 0 ? <p className="pf-v6-u-color-200">No administrative SELinux policy modifications retained for this server.</p>
            : <Table role="table" aria-label="SELinux administrative activity" variant="compact" gridBreakPoint="grid-lg">
              <Thead><Tr><Th>Timestamp</Th><Th>Type</Th><Th>Summary</Th><Th>User / Origin</Th><Th>Action</Th></Tr></Thead>
              {activity.data.items.map((item) => <ActivityItem key={item.id} item={item} selected={item.id === selected} />)}
            </Table>}
          <div className="selinux-activity-pagination">
            {before && !selected ? <Button variant="link" onClick={() => navigate()}>Recent activity</Button> : null}
            {!selected && !before ? <Pagination itemCount={activity.data.meta.total ?? activity.data.items.length} page={activity.data.meta.page ?? page} perPage={10} perPageOptions={[{ title: "10", value: 10 }]} isDisabled={activity.isFetching} onSetPage={(_event, value) => navigate(value)} titles={{ paginationAriaLabel: "SELinux activity pagination" }} /> : null}
          </div>
        </>}
      </CardBody></Card>
    </section>
  );
}
