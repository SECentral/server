import {
  Alert,
  Breadcrumb,
  BreadcrumbItem,
  Button,
  Card,
  CardBody,
  CardFooter,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Grid,
  GridItem,
  Icon,
  Pagination,
  Spinner,
  Title,
  Tooltip
} from "@patternfly/react-core";
import { CheckCircleIcon, ExclamationTriangleIcon, InfoCircleIcon, TimesCircleIcon } from "@patternfly/react-icons";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { formatUtc } from "../components/OccurrenceEvidence";
import { HostSelinuxActivity } from "../components/HostSelinuxActivity";
import { MetricCard } from "../components/MetricCard";
import { osDisplayName } from "../platform";
import { StatusLabel } from "../components/StatusLabel";
import { fetchHostConfiguration, type HostConfigurationResponse } from "../api/configuration";
import { fetchHost, fetchHostOccurrences, fetchHostSelinuxActivity } from "../api/hosts";
import { EMBEDDED_PAGE_SIZES, pageSize } from "../pagination";

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

function comparisonDifferenceCount(data: HostConfigurationResponse): number {
  const { booleans, ports } = data.comparison.summary;
  const domains = data.comparison.effective_permissive_domains;
  return (data.differences?.total ?? (booleans?.differ ?? 0) + (booleans?.host_only ?? 0) + (ports?.differ ?? 0))
    + (domains?.status === "observed" ? (domains.counts?.unexpected_on_host ?? 0) + (domains.counts?.missing_from_host ?? 0) : 0);
}

function comparisonStatus(data: HostConfigurationResponse): { label: string; color: "green" | "orange" | "grey" } {
  if (data.comparison.paused || data.observation?.status === "stale") return { label: "Comparison paused", color: "orange" };
  if (data.selection.status === "ambiguous") return { label: "Ambiguous reference", color: "orange" };
  if (data.selection.status === "unavailable") return { label: "Reference unavailable", color: "orange" };
  if (data.reference.kind === "none") return { label: "No reference available", color: "grey" };
  if (!data.comparison.available) return { label: "Comparison unavailable", color: "orange" };
  const { booleans, ports } = data.comparison.summary;
  const differences = comparisonDifferenceCount(data);
  if (differences > 0) return { label: `${differences} Differences found`, color: "orange" };
  const domainsCompared = data.comparison.effective_permissive_domains?.status === "observed" && data.comparison.effective_permissive_domains.counts != null;
  if ((booleans?.compared ?? 0) + (ports?.compared ?? 0) === 0 && !domainsCompared) return { label: "No comparable settings", color: "grey" };
  if (!domainsCompared || Object.values(data.selection.families).some((family) => family.status !== "comparable") || (booleans?.not_observed ?? 0) + (booleans?.unavailable ?? 0) + (ports?.not_observed ?? 0) > 0) return { label: "Partially compared", color: "orange" };
  return { label: "Matches reference", color: "green" };
}

export function HostDetail() {
  const { id } = useParams();
  const [queryParams, setQueryParams] = useSearchParams();
  const hostId = Number(id);
  const validId = Number.isInteger(hostId) && hostId > 0;
  const requestedPage = Number(queryParams.get("occurrence_page") ?? 1);
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
  const perPage = pageSize(queryParams.get("occurrence_page_size"), EMBEDDED_PAGE_SIZES, 10);
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
  const activitySize = pageSize(queryParams.get("activity_page_size"), EMBEDDED_PAGE_SIZES, 10);
  const activityQuery = useQuery({
    queryKey: ["host-selinux-activity", hostId, activityBefore, selectedActivity, activityPage, activitySize],
    queryFn: () => fetchHostSelinuxActivity(hostId, { before: activityBefore, eventId: selectedActivity, page: activityBefore || selectedActivity ? undefined : activityPage, limit: activityBefore || selectedActivity ? undefined : activitySize }),
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
  const missingCatalog = !configurationQuery.isError && !paused && noReference
    && configuration?.selection.status === "absent" && configuration.selection.reason === "no_matching_candidates";
  const comparison = configuration ? comparisonStatus(configuration) : null;
  const selinux = host.snapshot?.selinux ?? host.selinux;
  const platform = host.snapshot?.platform ?? host.platform;
  const comparisonSummary = configuration?.comparison.summary;
  const booleanDifferences = comparisonSummary?.booleans?.differ ?? 0;
  const hostOnlyBooleans = comparisonSummary?.booleans?.host_only ?? 0;
  const portDifferences = comparisonSummary?.ports?.differ ?? 0;
  const drifted = host.observation.status === "current" && !paused && configuration?.comparison.available && comparisonDifferenceCount(configuration) > 0;
  const domainComparison = configuration?.comparison.effective_permissive_domains;
  const domainCounts = !configurationQuery.isError && !paused && !noReference && domainComparison?.status === "observed" ? domainComparison.counts : null;
  const domainDifferences = (domainCounts?.unexpected_on_host ?? 0) + (domainCounts?.missing_from_host ?? 0);
  const domainState = host.selinux.effective_permissive_domains;
  const domainCount = domainState?.status === "observed" ? domainState.domains?.length : undefined;
  const platformLabel = osDisplayName(platform.os_id);
  const catalogDistribution = configuration?.selection.context.distribution || platform.os_id;
  const catalogFamily = [osDisplayName(catalogDistribution), configuration?.selection.context.major_version || platform.os_version?.split(".")[0]].filter(Boolean).join(" ");
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
            {revision && <p className="host-policy-baseline">Baseline: {revision.display_name} Catalog</p>}
            {configurationQuery.isError ? (
              <Alert variant="warning" isInline title="Reference comparison unavailable">Could not load the host configuration comparison.</Alert>
            ) : configurationQuery.isPending ? (
              <p className="pf-v6-u-color-200">Loading reference comparison…</p>
            ) : configuration ? (
              <>
                {paused && <Alert variant="warning" isInline title="Comparison paused">The retained host observation is stale; current matches and differences are unverified.</Alert>}
                {noReference && <p>{missingCatalog ? "No catalog reference is available for this host's OS family." : "No reference is selected. Review the host evidence and catalog selection in the full comparison."}</p>}
                {!paused && !noReference && !configuration.comparison.available && <Alert variant="warning" isInline title="Comparison unavailable">The current host state cannot be compared with this reference.</Alert>}
                {!paused && !missingCatalog && comparison && <StatusLabel color={comparison.color}>{comparison.label}</StatusLabel>}
              </>
            ) : null}
            {configuration && !configurationQuery.isError && !noReference && <dl className="host-policy-metrics">
               <div><dt>Booleans</dt><dd>{paused ? "Paused — current state unverified" : configuration?.comparison.available && comparisonSummary?.booleans ? <>{booleanDifferences + hostOnlyBooleans > 0 ? <><StatusLabel color="orange">{booleanDifferences + hostOnlyBooleans} drifted</StatusLabel>{" "}</> : null}<span>{booleanDifferences + hostOnlyBooleans > 0 ? `(${comparisonSummary.booleans.match}/${comparisonSummary.booleans.reference_entries} match)` : `${comparisonSummary.booleans.match} / ${comparisonSummary.booleans.reference_entries} match`}</span></> : "Unavailable"}</dd></div>
               <div><dt>Ports</dt><dd>{paused ? "Paused — current state unverified" : configuration?.comparison.available && comparisonSummary?.ports ? <>{portDifferences > 0 ? <><StatusLabel color="orange">{portDifferences} drifted</StatusLabel>{" "}</> : null}<span>{portDifferences > 0 ? `(${comparisonSummary.ports.match}/${comparisonSummary.ports.compared + comparisonSummary.ports.not_observed} match)` : `${comparisonSummary.ports.match} / ${comparisonSummary.ports.compared + comparisonSummary.ports.not_observed} match`}</span></> : "Unavailable"}</dd></div>
               <div><dt>Effective permissive domains</dt><dd>{paused ? "Paused — current state unverified" : configurationQuery.isPending ? "Loading…" : domainCounts ? <>
                {domainDifferences > 0 && <><StatusLabel color="orange">{domainDifferences} differ</StatusLabel>{" "}</>}
                <span>{domainCounts.matching} match{domainDifferences > 0 ? ` · ${domainCounts.unexpected_on_host} host-only · ${domainCounts.missing_from_host} reference-only` : domainCounts.matching === 0 ? " · both sets empty" : ""}</span>
              </> : <>{domainCount != null ? `${domainCount} observed` : "Unknown"} · {paused ? "Comparison paused" : "Comparison unavailable"}</>}</dd></div>
            </dl>}
          </CardBody>
          {!configurationQuery.isPending && <CardFooter className="host-comparison-footer">{missingCatalog
            ? <Button component="a" href="/catalogs/import" variant="link" isInline>Import a catalog for {catalogDistribution ? catalogFamily : "this OS family"}</Button>
            : <Button component="a" href={`/hosts/${host.id}/configuration`} variant="link" isInline>View full comparison <span aria-hidden="true">→</span></Button>}
          </CardFooter>}
        </Card>
      </div>

      <section className="host-activity-section" aria-labelledby="host-activity-title">
        <div className="host-activity-heading">
          <Title id="host-activity-title" headingLevel="h2" size="lg">Activity</Title>
        </div>
        <Grid hasGutter className="host-activity-facts" aria-label="Activity metrics">
          <GridItem span={12} lg={4}><MetricCard className="host-surface-card" label="Active issues" value={host.counts.active_issues} href={`/issues?host_id=${host.id}&status=open`} /></GridItem>
          <GridItem span={12} lg={4}><MetricCard className="host-surface-card" label="Total occurrences" value={host.counts.total_events} href="#recent-occurrences" /></GridItem>
          <GridItem span={12} lg={4}><MetricCard className="host-surface-card" label="AVCs — 24h" value={host.counts.avcs_24h} /></GridItem>
        </Grid>
      </section>

      <HostSelinuxActivity activity={activityQuery} />

      <section id="recent-occurrences" tabIndex={-1} aria-label="Recent occurrences">
        <Card className="host-surface-card host-table-card"><CardBody>
        <div className="host-activity-heading"><Title headingLevel="h2" size="lg">Recent Occurrences ({(occurrencesQuery.data?.meta.total ?? host.counts.total_events).toLocaleString("en-US")})</Title></div>
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
            <div className="host-table-pagination"><Pagination widgetId="host-occurrences-pagination" itemCount={occurrencesQuery.data?.meta.total ?? host.counts.total_events} page={occurrencesQuery.data?.meta.page ?? page} perPage={perPage} titles={{ paginationAriaLabel: "Recent occurrences pagination" }}
              perPageOptions={EMBEDDED_PAGE_SIZES.map((value) => ({ title: String(value), value }))}
              onSetPage={(_event, nextPage) => setOccurrencePage(nextPage)} onPerPageSelect={(_event, size) => setOccurrencePage(1, size)}
              isDisabled={occurrencesQuery.isFetching} aria-label="Recent occurrences pagination" /></div>
          </>
        )}
        </CardBody></Card>
      </section>
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
