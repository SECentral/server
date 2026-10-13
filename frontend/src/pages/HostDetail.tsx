import {
  Alert,
  Breadcrumb,
  BreadcrumbItem,
  Button,
  Card,
  CardBody,
  CardFooter,
  CardTitle,
  ClipboardCopy,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  ExpandableSection,
  Grid,
  GridItem,
  Icon,
  Pagination,
  Spinner,
  Title,
  Tooltip
} from "@patternfly/react-core";
import { CheckCircleIcon, ChevronDownIcon, ChevronRightIcon, ExclamationTriangleIcon, InfoCircleIcon, TimesCircleIcon } from "@patternfly/react-icons";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { formatUtc } from "../components/OccurrenceEvidence";
import { HostSelinuxActivity } from "../components/HostSelinuxActivity";
import { EffectivePermissiveDomains } from "../components/EffectivePermissiveDomains";
import { StatusLabel } from "../components/StatusLabel";
import { fetchHostConfiguration, type HostConfigurationResponse } from "../api/configuration";
import { fetchHost, fetchHostOccurrences, fetchHostSelinuxActivity } from "../api/hosts";

const AGENT_COLORS: Record<string, "green" | "orange" | "red" | "grey"> = {
  reporting: "green",
  stale: "orange",
  offline: "red"
};

const OBSERVATION_COLORS: Record<string, "green" | "orange" | "grey"> = {
  current: "green",
  stale: "orange",
  none: "grey"
};

const ENFORCEMENT_COLORS: Record<string, "green" | "orange" | "red" | "grey"> = {
  enforcing: "green",
  permissive: "red",
  disabled: "red"
};

function displayState(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function DescriptionFacts({ fields }: { fields: [string, React.ReactNode][] }) {
  return (
    <DescriptionList orientation={{ sm: "horizontal" }} isCompact isFluid>
      {fields.filter(([, value]) => value !== null && value !== undefined && value !== "").map(([label, value]) => (
        <DescriptionListGroup key={label}>
          <DescriptionListTerm>{label}</DescriptionListTerm>
          <DescriptionListDescription>{value}</DescriptionListDescription>
        </DescriptionListGroup>
      ))}
    </DescriptionList>
  );
}

function comparisonStatus(data: HostConfigurationResponse): { label: string; color: "green" | "orange" | "grey" } {
  if (data.comparison.paused || data.observation?.status === "stale") return { label: "Comparison paused", color: "orange" };
  if (data.selection.status === "ambiguous") return { label: "Ambiguous reference", color: "orange" };
  if (data.selection.status === "unavailable") return { label: "Reference unavailable", color: "orange" };
  if (data.reference.kind === "none") return { label: "No reference available", color: "grey" };
  if (!data.comparison.available) return { label: "Comparison unavailable", color: "orange" };
  const { booleans, ports } = data.comparison.summary;
  const differences = data.differences?.total ?? (booleans?.differ ?? 0) + (booleans?.host_only ?? 0) + (ports?.differ ?? 0);
  if (differences > 0) return { label: `${differences} Differences found`, color: "orange" };
  if ((booleans?.compared ?? 0) + (ports?.compared ?? 0) === 0) return { label: "No comparable settings", color: "grey" };
  if (Object.values(data.selection.families).some((family) => family.status !== "comparable") || (booleans?.not_observed ?? 0) + (booleans?.unavailable ?? 0) + (ports?.not_observed ?? 0) > 0) return { label: "Partially compared", color: "orange" };
  return { label: "Matches reference", color: "green" };
}

export function HostDetail() {
  const { id } = useParams();
  const [queryParams, setQueryParams] = useSearchParams();
  const hostId = Number(id);
  const validId = Number.isInteger(hostId) && hostId > 0;
  const requestedPage = Number(queryParams.get("occurrence_page") ?? 1);
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
  const requestedSize = Number(queryParams.get("occurrence_page_size") ?? 10);
  const perPage = [10, 25, 50].includes(requestedSize) ? requestedSize : 10;
  const [provenanceExpanded, setProvenanceExpanded] = useState(false);
  function setOccurrencePage(nextPage: number, size = perPage) {
    setQueryParams((previous) => {
      const next = new URLSearchParams(previous);
      next.set("occurrence_page", String(nextPage));
      next.set("occurrence_page_size", String(size));
      return next;
    });
  }

  const detailQuery = useQuery({
    queryKey: ["host", hostId],
    queryFn: () => fetchHost(hostId),
    refetchInterval: (query) => query.state.data?.host.selinux.effective_permissive_domains?.status === "pending" ? 2000 : 60000,
    enabled: validId
  });
  const configurationQuery = useQuery({
    queryKey: ["host-configuration", hostId, "differences", "", 1, null],
    queryFn: () => fetchHostConfiguration(hostId, { view: "differences" }),
    enabled: validId
  });
  const occurrencesQuery = useQuery({
    queryKey: ["host-occurrences", hostId, page, perPage],
    queryFn: () => fetchHostOccurrences(hostId, { limit: perPage, page }),
    enabled: validId
  });
  const activityBefore = queryParams.get("activity_before") ?? undefined;
  const selectedActivity = Number(queryParams.get("selinux_activity")) || undefined;
  const requestedActivityPage = Number(queryParams.get("activity_page") ?? 1);
  const activityPage = Number.isSafeInteger(requestedActivityPage) && requestedActivityPage > 0 ? requestedActivityPage : 1;
  const activityQuery = useQuery({
    queryKey: ["host-selinux-activity", hostId, activityBefore, selectedActivity, activityPage],
    queryFn: () => fetchHostSelinuxActivity(hostId, { before: activityBefore, eventId: selectedActivity, page: activityBefore || selectedActivity ? undefined : activityPage }),
    enabled: validId
  });

  const occurrences = occurrencesQuery.data?.occurrences ?? [];

  if (!validId) {
    return <Alert variant="danger" isInline title="Invalid host id"><Link to="/hosts">Back to hosts</Link></Alert>;
  }
  if (detailQuery.isError) {
    const error = detailQuery.error;
    if (error instanceof ApiError && error.status === 404) {
      return <Alert variant="danger" isInline title="Host not found">This host does not exist. <Link to="/hosts">Back to hosts</Link></Alert>;
    }
    return <Alert variant="danger" isInline title="Could not load host">{error instanceof Error ? error.message : "Unknown error"}</Alert>;
  }
  if (detailQuery.isPending) {
    return <div aria-label="Loading host" style={{ padding: "var(--pf-v6-global--spacer--xl)" }}><Spinner size="xl" /></div>;
  }

  const { host } = detailQuery.data;
  const readiness = host.enforcing_readiness;
  const showReadiness = host.observation.status === "current" && host.selinux.enforcement === "permissive";
  const configuration = configurationQuery.data;
  const reference = configuration?.reference;
  const revision = reference?.catalog_revision;
  const paused = Boolean(configuration && (configuration.comparison.paused || configuration.observation?.status === "stale"));
  const noReference = reference?.kind === "none";
  const comparison = configuration ? comparisonStatus(configuration) : null;
  const selinux = host.snapshot?.selinux ?? host.selinux;
  const hostPolicyIdentity = host.snapshot?.selinux.policy_identity ?? selinux.policy_identity;
  const platform = host.snapshot?.platform ?? host.platform;
  const comparisonSummary = configuration?.comparison.summary;
  const booleanDifferences = comparisonSummary?.booleans?.differ ?? 0;
  const hostOnlyBooleans = comparisonSummary?.booleans?.host_only ?? 0;
  const portDifferences = comparisonSummary?.ports?.differ ?? 0;
  const drifted = host.observation.status === "current" && !paused && configuration?.comparison.available && (configuration.differences?.total ?? booleanDifferences + hostOnlyBooleans + portDifferences) > 0;
  const platformLabel = platform.os_id === "almalinux" ? "AlmaLinux" : platform.os_id
    ? platform.os_id.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase())
    : "Unknown platform";
  const platformSubtitle = [
    `${platformLabel}${platform.os_version ? ` ${platform.os_version}` : ""}`,
    platform.architecture,
    host.last_seen_at ? `Last seen ${timeAgo(host.last_seen_at)}` : "Never seen"
  ].filter(Boolean).join(" · ");

  return (
    <div className="host-detail-page">
      <Breadcrumb aria-label="Breadcrumb" className="pf-v6-u-mb-sm">
        <BreadcrumbItem><Link to="/hosts">Monitored servers</Link></BreadcrumbItem>
        <BreadcrumbItem isActive>{host.hostname ?? `Host ${host.id}`}</BreadcrumbItem>
      </Breadcrumb>
      <header className="host-overview-header">
        <div className="host-title-line">
          <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">{host.hostname ?? `Host ${host.id}`}</Title>
          <span className={`host-status host-status-${host.agent.reporting_state}`}>
            <Icon status={host.agent.reporting_state === "reporting" ? "success" : host.agent.reporting_state === "stale" ? "warning" : "danger"}>
              {host.agent.reporting_state === "reporting" ? <CheckCircleIcon aria-hidden="true" /> : host.agent.reporting_state === "stale" ? <ExclamationTriangleIcon aria-hidden="true" /> : <TimesCircleIcon aria-hidden="true" />}
            </Icon> {displayState(host.agent.reporting_state)}
          </span>
        </div>
        <p className="host-overview-subtitle">{platformSubtitle}</p>
      </header>

      <div className="host-overview-grid">
        <div className="host-overview-column">
          <Card className="host-overview-card host-surface-card">
            <CardTitle component="h2">Host health</CardTitle>
            <CardBody>
              <DescriptionFacts fields={[
                ["Agent status", <StatusLabel color={AGENT_COLORS[host.agent.reporting_state] ?? "grey"}>{displayState(host.agent.reporting_state)}</StatusLabel>],
                ["SELinux mode", selinux.enforcement ? <StatusLabel color={ENFORCEMENT_COLORS[selinux.enforcement] ?? "grey"}>{displayState(selinux.enforcement)}</StatusLabel> : "Unknown"],
                ["Configuration freshness", <StatusLabel color={drifted ? "orange" : OBSERVATION_COLORS[host.observation.status] ?? "grey"}>{drifted ? "Drifted" : displayState(host.observation.status)}</StatusLabel>],
                ["Kernel policy version", <code>{selinux.kernel_policy_version != null ? [selinux.configured_policy_type, selinux.kernel_policy_version].filter((value) => value != null).join(".") : "Unknown"}</code>],
                ["Last heartbeat", host.agent.last_seen_at ? <time dateTime={host.agent.last_seen_at} title={host.agent.last_seen_at}>{timeAgo(host.agent.last_seen_at)}</time> : "Never reported"]
              ]} />
            </CardBody>
          </Card>
          {showReadiness && (
            <Card component="section" aria-labelledby="enforcing-readiness-title" className="host-overview-card host-surface-card host-readiness-card">
              <CardTitle id="enforcing-readiness-title" component="h2">Enforcing readiness</CardTitle>
              <CardBody>
                <p className="pf-v6-u-color-200 pf-v6-u-font-size-sm"><em>Based on a {readiness.target_days}-day observation target</em></p>
                <div>
                  <strong>{readiness.status === "observed" ? readiness.band : "Unknown"}</strong>{" "}
                  <Tooltip content={<div className="host-readiness-tooltip-paragraphs">{readiness.explanation.split("\n\n").map((paragraph) => <p key={paragraph}>{paragraph}</p>)}</div>} isContentLeftAligned position="right" maxWidth="min(24rem, calc(100vw - 11rem))">
                    <Button variant="plain" aria-label="About enforcing readiness"><InfoCircleIcon aria-hidden="true" /></Button>
                  </Tooltip>
                </div>
              </CardBody>
            </Card>
          )}
        </div>

        <Card className="host-overview-card host-surface-card">
          <CardTitle component="h2">Policy comparison</CardTitle>
          <CardBody>
            <p className="host-policy-baseline">Baseline: {configurationQuery.isPending ? "Loading…" : revision?.display_name ? `${revision.display_name} Catalog` : "No catalog reference"}</p>
            {configurationQuery.isError ? (
              <Alert variant="warning" isInline title="Reference comparison unavailable">Could not load the host configuration comparison.</Alert>
            ) : configurationQuery.isPending ? (
              <p className="pf-v6-u-color-200">Loading reference comparison…</p>
            ) : configuration ? (
              <>
                {paused && <Alert variant="warning" isInline title="Comparison paused">Counts reflect last-observed data.</Alert>}
                {noReference && <Alert variant="info" isInline title="No reference available">There is no catalog/reference to compare with this host.</Alert>}
                {!paused && !noReference && !configuration.comparison.available && <Alert variant="warning" isInline title="Comparison unavailable">The current host state cannot be compared with this reference.</Alert>}
                {comparison && <StatusLabel color={comparison.color}>{comparison.label}</StatusLabel>}
              </>
            ) : null}
            <dl className="host-policy-metrics">
              <div><dt>Booleans</dt><dd>{configuration?.comparison.available && comparisonSummary?.booleans ? <>{booleanDifferences + hostOnlyBooleans > 0 ? <><StatusLabel color="orange">{booleanDifferences + hostOnlyBooleans} drifted</StatusLabel>{" "}</> : null}<span>{booleanDifferences + hostOnlyBooleans > 0 ? `(${comparisonSummary.booleans.match}/${comparisonSummary.booleans.reference_entries} match)` : `${comparisonSummary.booleans.match} / ${comparisonSummary.booleans.reference_entries} match`}</span></> : "Unavailable"}</dd></div>
              <div><dt>Ports</dt><dd>{configuration?.comparison.available && comparisonSummary?.ports ? <>{portDifferences > 0 ? <><StatusLabel color="orange">{portDifferences} drifted</StatusLabel>{" "}</> : null}<span>{portDifferences > 0 ? `(${comparisonSummary.ports.match}/${comparisonSummary.ports.compared + comparisonSummary.ports.not_observed} match)` : `${comparisonSummary.ports.match} / ${comparisonSummary.ports.compared + comparisonSummary.ports.not_observed} match`}</span></> : "Unavailable"}</dd></div>
            </dl>
          </CardBody>
          <CardFooter className="host-comparison-footer"><Button component="a" href={`/hosts/${host.id}/configuration`} variant="link" isInline>View full comparison <span aria-hidden="true">→</span></Button></CardFooter>
        </Card>
      </div>

      <Card className="host-surface-card"><CardBody><EffectivePermissiveDomains key={selinux.effective_permissive_domains?.policy_identity} state={selinux.effective_permissive_domains} /></CardBody></Card>

      <section className="host-activity-section" aria-labelledby="host-activity-title">
        <div className="host-activity-heading">
          <Title id="host-activity-title" headingLevel="h2" size="lg">Activity</Title>
          <Button component="a" href={`/issues?host_id=${host.id}&status=open`} variant="link" isInline>View issues →</Button>
        </div>
        <Grid hasGutter className="host-activity-facts" aria-label="Activity metrics">
          <GridItem span={12} lg={4}><Card className="host-surface-card host-metric-card"><CardTitle component="h3">Active Issues</CardTitle><CardBody><strong>{host.counts.active_issues.toLocaleString("en-US")}</strong></CardBody></Card></GridItem>
          <GridItem span={12} lg={4}><Card className="host-surface-card host-metric-card"><CardTitle component="h3">Total Occurrences</CardTitle><CardBody><strong>{host.counts.total_events.toLocaleString("en-US")}</strong></CardBody></Card></GridItem>
          <GridItem span={12} lg={4}><Card className="host-surface-card host-metric-card"><CardTitle component="h3">AVC / 24h</CardTitle><CardBody><strong>{host.counts.avcs_24h.toLocaleString("en-US")}</strong></CardBody></Card></GridItem>
        </Grid>
      </section>

      <HostSelinuxActivity activity={activityQuery} />

      <section aria-label="Recent occurrences">
        <Card className="host-surface-card host-table-card"><CardBody>
        <Title headingLevel="h2" size="lg">Recent Occurrences ({(occurrencesQuery.data?.meta.total ?? host.counts.total_events).toLocaleString("en-US")})</Title>
        <p className="pf-v6-u-color-200">Latest AVC denial events observed on this server.</p>
        {occurrencesQuery.isPending ? (
          <div aria-label="Loading occurrences" style={{ padding: "var(--pf-v6-global--spacer--lg)" }}><Spinner /></div>
        ) : occurrencesQuery.isError ? (
          <Alert variant="danger" title="Could not load occurrences">{occurrencesQuery.error instanceof Error ? occurrencesQuery.error.message : "Unknown error"}</Alert>
        ) : (
          <>
            {occurrences.length > 0 && (
              <Table role="table" aria-label="Recent occurrences" variant="compact" gridBreakPoint="grid-lg" className="host-occurrences-table">
                <Thead><Tr><Th width={40}>Observed access tuple</Th><Th width={25}>Resource &amp; permission</Th><Th width={15}>Issue link</Th><Th width={20}>Timestamp</Th></Tr></Thead>
                <Tbody>{occurrences.map((occurrence) => {
                  const denial = occurrence.normalized_denial;
                  return <Tr key={occurrence.id}>
                    <Td dataLabel="Observed access tuple"><Link className="occurrence-denial-types" to={`/hosts/${host.id}/occurrences/${occurrence.id}`}><code>{denial.source_type ?? "unknown source"} ── {denial.permissions?.join(", ") || "unknown permission"} ──X──&gt; {denial.target_type ?? "unknown target"}</code></Link>{denial.status !== "ok" && <StatusLabel color="orange" isCompact>Ungroupable</StatusLabel>}</Td>
                    <Td dataLabel="Resource & permission"><code>{denial.target_class ?? "unknown class"} · {denial.permissions?.join(", ") || "unknown permission"}</code></Td>
                    <Td dataLabel="Issue link">{occurrence.issue ? <Link to={`/issues/${occurrence.issue.id}`}>Issue #{occurrence.issue.id}</Link> : <span className="pf-v6-u-color-200">Ungrouped event</span>}</Td>
                    <Td dataLabel="Timestamp"><time dateTime={occurrence.occurred_at} title={occurrence.occurred_at}>{formatUtc(occurrence.occurred_at)}</time></Td>
                  </Tr>;
                })}</Tbody>
              </Table>
            )}
            {occurrences.length === 0 && <p className="pf-v6-u-color-200">No occurrences recorded for this host.</p>}
            <Pagination itemCount={occurrencesQuery.data?.meta.total ?? host.counts.total_events} page={occurrencesQuery.data?.meta.page ?? page} perPage={perPage} titles={{ paginationAriaLabel: "Recent occurrences pagination" }}
              perPageOptions={[10, 25, 50].map((value) => ({ title: String(value), value }))}
              onSetPage={(_event, nextPage) => setOccurrencePage(nextPage)} onPerPageSelect={(_event, size) => setOccurrencePage(1, size)}
              isDisabled={occurrencesQuery.isFetching} aria-label="Recent occurrences pagination" />
          </>
        )}
        </CardBody></Card>
      </section>
      <ExpandableSection className="host-technical-details host-disclosure" toggleText="Technical Provenance & Hashes" toggleIcon={provenanceExpanded ? <ChevronDownIcon aria-hidden="true" /> : <ChevronRightIcon aria-hidden="true" />} isExpanded={provenanceExpanded} onToggle={(_event, expanded) => setProvenanceExpanded(expanded)}>
        {provenanceExpanded ? <DescriptionFacts fields={[
          ["Host ID", <ClipboardCopy variant="inline-compact" isReadOnly isCode copyAriaLabel="Copy full host ID" textAriaLabel="Full host ID" hoverTip="Copy host ID" clickTip="Host ID copied">{host.external_id}</ClipboardCopy>],
          ["Host policy ID", hostPolicyIdentity && <ClipboardCopy variant="inline-compact" isReadOnly isCode copyAriaLabel="Copy host policy ID" textAriaLabel="Host policy ID" hoverTip="Copy host policy ID" clickTip="Host policy ID copied">{hostPolicyIdentity}</ClipboardCopy>],
          ["Reference policy ID", revision?.loaded_policy_digest && <ClipboardCopy variant="inline-compact" isReadOnly isCode copyAriaLabel="Copy reference policy ID" textAriaLabel="Reference policy ID" hoverTip="Copy reference policy ID" clickTip="Reference policy ID copied">{revision.loaded_policy_digest}</ClipboardCopy>]
        ]} /> : null}
      </ExpandableSection>
    </div>
  );
}

function timeAgo(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 90) return "less than a minute ago";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}
