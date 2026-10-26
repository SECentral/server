import {
  Alert,
  AlertGroup,
  Card,
  CardBody,
  Flex,
  FlexItem,
  Grid,
  GridItem,
  Label,
  PageSection,
  Spinner,
  Title
} from "@patternfly/react-core";
import { useQuery } from "@tanstack/react-query";
import { fetchOverview, type OverviewAttentionHost, type OverviewResponse } from "../api/overview";
import { SeriesChart } from "../components/SeriesChart";
import { MetricCard } from "../components/MetricCard";
import { ObservationCounts } from "../components/ObservationCounts";

const AGENT_STATES = [
  { key: "reporting", label: "Reporting", status: "success" },
  { key: "stale", label: "Stale", status: "warning" },
  { key: "offline", label: "Offline", status: "danger" }
] as const;

const ATTENTION_STATE: Record<string, { label: string; variant: "info" | "warning" | "danger" }> = {
  stale: { label: "stale", variant: "warning" },
  offline: { label: "offline", variant: "danger" },
};

function timeAgo(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 90) return "less than a minute";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? "" : "s"}`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? "" : "s"}`;
}

function hostNames(hosts: OverviewAttentionHost[], total: number): string {
  const names = hosts.map((host) => host.hostname ?? "Unknown hostname").join(", ");
  return total > hosts.length ? `${names}, …` : names;
}

function AttentionAlert({
  heading,
  detail,
  examples,
  href,
  linkLabel,
  variant
}: {
  heading: string;
  detail: string;
  examples?: string;
  href: string;
  linkLabel: string;
  variant: "info" | "warning" | "danger";
}) {
  return (
    <Alert variant={variant} title={heading} isInline className="overview-attention-alert">
      <div className="overview-attention-content">
        <span>{detail}</span>
        {examples && <span className="pf-v6-u-color-200">{examples}</span>}
        <a href={href} className="pf-v6-c-button pf-m-link">{linkLabel}</a>
      </div>
    </Alert>
  );
}

export function Overview() {
  const overviewQuery = useQuery({
    queryKey: ["overview"],
    queryFn: fetchOverview
  });

  const data: OverviewResponse | undefined = overviewQuery.data;

  return (
    <main className="overview-page">
      <header className="overview-header">
        <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">Overview</Title>
        <p className="pf-v6-u-color-200">Agent reporting and retained SELinux observations. Audit capture continuity is unknown, including for reporting agents.</p>
      </header>

      {overviewQuery.isPending ? (
        <div aria-label="Loading overview" className="pf-v6-u-p-xl">
          <Spinner />
        </div>
      ) : overviewQuery.isError ? (
        <Alert variant="danger" title="Could not load the overview">
          {overviewQuery.error instanceof Error ? overviewQuery.error.message : "Unknown error"}
        </Alert>
      ) : (
        data && (
          <>
            <PageSection isPlain padding={{ default: "noPadding" }} aria-labelledby="issue-health-heading" className="overview-section">
              <Title headingLevel="h2" size="xl" id="issue-health-heading">Issue activity</Title>
              <Grid hasGutter>
                <GridItem sm={12} md={6} xl={3}><MetricCard label="Active issues" value={data.metrics.active_issues} detail="Open and regressed" href="/issues?status=open" /></GridItem>
                <GridItem sm={12} md={6} xl={3}><MetricCard label="New issues — 24h" value={data.metrics.new_issues_24h} detail="First observed in the last 24h" href="/issues?status=open&new=1" /></GridItem>
                <GridItem sm={12} md={6} xl={3}><MetricCard label="Affected hosts" value={data.metrics.affected_hosts} detail="With active issues" href="/issues?status=open" /></GridItem>
                <GridItem sm={12} md={6} xl={3}><MetricCard label="AVCs — 24h" value={data.metrics.avcs_24h} detail="In the last 24 hours" href="/issues" /></GridItem>
              </Grid>
              <ObservationCounts observations={data.metrics.observations_24h} />
              <p>Last 24 hours by recorded event time. Outcomes refer to associated syscalls, not application requests or established SELinux causation.</p>
            </PageSection>

            <PageSection isPlain padding={{ default: "noPadding" }} aria-labelledby="fleet-health-heading" className="overview-section">
              <Flex
                className="overview-fleet-heading"
                alignItems={{ default: "alignItemsCenter" }}
                justifyContent={{ default: "justifyContentSpaceBetween" }}
              >
                <FlexItem><Title headingLevel="h2" size="xl" id="fleet-health-heading">Fleet reporting</Title></FlexItem>
                <FlexItem><a href="/hosts" className="overview-host-total">{data.metrics.monitored_hosts} monitored hosts</a></FlexItem>
              </Flex>
              <Grid hasGutter aria-label="Agent reporting status">
                {AGENT_STATES.map(({ key, label, status }) => (
                  <GridItem key={key} sm={12} md={4} xl={4}>
                    <Card isClickable isCompact className="overview-status-card" component="a" href={`/hosts?status=${key}`} aria-label={`${label} ${data.metrics.agent_states[key]}`}>
                      <CardBody>
                        <Label status={status} isCompact>{label}</Label>
                        <Title headingLevel="h3" size="2xl">{data.metrics.agent_states[key]}</Title>
                      </CardBody>
                    </Card>
                  </GridItem>
                ))}
              </Grid>
            </PageSection>

            <PageSection isPlain padding={{ default: "noPadding" }} aria-labelledby="activity-trends-heading" className="overview-section">
              <Title headingLevel="h2" size="xl" id="activity-trends-heading">Activity trends</Title>
              <Grid hasGutter>
                <GridItem sm={12} xl={6}><SeriesChart title="New issues — 7 days" points={data.series.new_issues} /></GridItem>
                <GridItem sm={12} xl={6}><SeriesChart title="AVC occurrences — 7 days" points={data.series.avc_occurrences} /></GridItem>
              </Grid>
            </PageSection>

            <PageSection isPlain padding={{ default: "noPadding" }} aria-labelledby="attention-heading" className="overview-section">
              <div className="overview-section-heading overview-attention-heading">
                <Title headingLevel="h2" size="xl" id="attention-heading">Needs attention</Title>
                <span className="pf-v6-u-color-200">Current, evidence-backed conditions only.</span>
              </div>
              {data.attention.agent_states.length === 0 && !data.attention.permissive && !data.attention.new_issues && !data.attention.multi_host_issues ? (
                <Alert variant="info" title="No listed conditions observed in retained telemetry." isInline isPlain className="overview-attention-alert">Audit capture continuity and workload coverage are unknown.</Alert>
              ) : (
                <AlertGroup aria-label="Fleet conditions requiring attention" className="overview-alert-group">
                  {data.attention.agent_states.map((group) => (
                    <AttentionAlert
                      key={group.state}
                      heading={`${group.host_count} agent${group.host_count === 1 ? "" : "s"} ${ATTENTION_STATE[group.state]?.label ?? group.state}`}
                      detail={
                        group.heartbeat_range?.length
                          ? `Last heartbeat between ${timeAgo(group.heartbeat_range[0])} and ${timeAgo(group.heartbeat_range[1])} ago`
                          : "No heartbeat received"
                      }
                      examples={hostNames(group.example_hosts, group.host_count)}
                      href={`/hosts?status=${group.state}`}
                      linkLabel="View affected hosts →"
                      variant={ATTENTION_STATE[group.state]?.variant ?? "info"}
                    />
                  ))}
                  {data.attention.permissive && (
                    <AttentionAlert
                      heading={`${data.attention.permissive.host_count} host${data.attention.permissive.host_count === 1 ? "" : "s"} currently running SELinux permissive`}
                      detail="Fresh heartbeat-confirmed enforcement state is permissive."
                      examples={hostNames(data.attention.permissive.example_hosts, data.attention.permissive.host_count)}
                      href="/hosts?enforcement=permissive"
                      linkLabel="View affected hosts →"
                      variant="warning"
                    />
                  )}
                  {data.attention.new_issues && (
                    <AttentionAlert
                      heading={`${data.attention.new_issues.issue_count} new issue${data.attention.new_issues.issue_count === 1 ? "" : "s"} in the last 24 hours`}
                      detail="Open issues first observed during the current window."
                      examples={data.attention.new_issues.example_issues.map((issue) => `${issue.source_type} → ${issue.target_type}`).join(", ")}
                      href="/issues?status=open&new=1"
                      linkLabel="View new issues →"
                      variant="info"
                    />
                  )}
                  {data.attention.multi_host_issues && (
                    <AttentionAlert
                      heading={`${data.attention.multi_host_issues.issue_count} active issues affect multiple hosts`}
                      detail="Based on distinct hosts with retained occurrences."
                      examples={data.attention.multi_host_issues.example_issues.map((issue) => `${issue.source_type} → ${issue.target_type}`).join(", ")}
                      href="/issues?status=open&multiple_hosts=1"
                      linkLabel="View issues →"
                      variant="warning"
                    />
                  )}
                </AlertGroup>
              )}
            </PageSection>
          </>
        )
      )}
    </main>
  );
}
