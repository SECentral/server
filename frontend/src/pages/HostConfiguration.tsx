import {
  Alert,
  Breadcrumb,
  BreadcrumbItem,
  Button,
  Card,
  CardBody,
  ClipboardCopy,
  Label,
  Pagination,
  SearchInput,
  Spinner,
  Tab,
  TabTitleText,
  Tabs,
  Title,
  Tooltip,
  Toolbar,
  ToolbarContent,
  ToolbarItem
} from "@patternfly/react-core";
import { InfoCircleIcon } from "@patternfly/react-icons";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { fetchHostConfiguration } from "../api/configuration";
import type { HostConfigurationResponse } from "../api/configuration";
import { fetchHost, type HostDetailResponse } from "../api/hosts";
import { EffectivePermissiveDomains } from "../components/EffectivePermissiveDomains";
import { EffectivePermissiveComparison } from "../components/EffectivePermissiveComparison";
import { CatalogReferenceSelection } from "../components/CatalogReferenceSelection";
import { PAGE_SIZES, pageSize } from "../pagination";

function comparisonLimited(data: HostConfigurationResponse): boolean {
  return Object.values(data.selection.families).some((family) => family.status !== "comparable") ||
    (data.comparison.summary.booleans?.not_observed ?? 0) + (data.comparison.summary.booleans?.unavailable ?? 0) + (data.comparison.summary.ports?.not_observed ?? 0) > 0;
}

const VIEWS = [
  { value: "differences", label: "Differences" },
  { value: "booleans", label: "Booleans" },
  { value: "ports", label: "Ports" }
] as const;

type View = (typeof VIEWS)[number]["value"];

const BOOLEAN_STATUS_COLORS: Record<string, "green" | "orange" | "red" | "grey"> = {
  observed: "green",
  unknown: "orange",
  unavailable: "red",
  not_observed: "grey",
  stale: "orange"
};

const RELATION_COLORS: Record<string, "green" | "orange" | "red" | "grey"> = {
  matching_effective_type: "green",
  comparison_unknown: "orange"
};

function boolText(value: boolean | null | undefined): string {
  if (value === true) return "On";
  if (value === false) return "Off";
  return "unknown";
}

function formatUtc(iso: string): string {
  return `${new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZone: "UTC"
  }).format(new Date(iso))} UTC`;
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

function plural(count: number, singular: string): string {
  return `${count} ${singular}${count === 1 ? "" : "s"}`;
}

function displayState(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function booleanResult(row: NonNullable<HostConfigurationResponse["booleans"]>["rows"][number]): { label: string; color: "green" | "orange" | "red" | "grey" } {
  if (row.status !== "observed") return { label: displayState(row.status), color: BOOLEAN_STATUS_COLORS[row.status] ?? "grey" };
  if (row.catalog_status === "not_defined") return { label: "Host-only", color: "grey" };
  if (row.catalog_status === "unavailable") return { label: "Unavailable", color: "red" };
  if (row.catalog_status === "not_represented") return { label: "Not represented", color: "grey" };
  if (row.current === null) return { label: "Unknown", color: "orange" };
  if (row.reference_default === null) return { label: "Not compared", color: "grey" };
  return row.current === row.reference_default ? { label: "Match", color: "green" } : { label: "Differs", color: "orange" };
}

function ComparisonHeader({ data, host }: { data: HostConfigurationResponse; host?: HostDetailResponse["host"] }) {
  const reference = data.reference.catalog_revision;
  const referenceName = data.reference.kind === "distribution_catalog"
    ? reference?.display_name ?? "Distribution catalog"
    : data.selection.status === "ambiguous" ? "Ambiguous reference" : data.selection.status === "unavailable" ? "Reference unavailable" : "No active reference";
  const kernelPolicyVersion = host?.snapshot?.selinux.kernel_policy_version ?? host?.selinux.kernel_policy_version;
  const referenceDetails = reference ? [reference.policy_type, reference.architecture]
    .filter(Boolean).join(" · ") : "";
  const stale = data.observation?.status === "stale" || data.comparison.paused;
  const differenceCount = (data.differences?.total
    ?? (data.comparison.summary.booleans?.differ ?? 0) + (data.comparison.summary.booleans?.host_only ?? 0) + (data.comparison.summary.ports?.differ ?? 0))
    + (data.comparison.effective_permissive_domains.counts?.unexpected_on_host ?? 0) + (data.comparison.effective_permissive_domains.counts?.missing_from_host ?? 0);
  const limited = comparisonLimited(data);

  return (
    <div className="configuration-comparison-header">
      <div>
        <p className="configuration-reference-line">
          {data.comparison.available ? "Compared with" : "Reference"} <strong>{referenceName}</strong>{referenceDetails && ` · ${referenceDetails}`}
        </p>
        <div className="configuration-header-metadata">
          {data.observation ? (
            <span className="configuration-observed-at">
              <time dateTime={data.observation.last_observed_at} title={formatUtc(data.observation.last_observed_at)}>
                Observed {timeAgo(data.observation.last_observed_at)}
              </time>
              <small>{formatUtc(data.observation.last_observed_at)}</small>
            </span>
          ) : <span>No current observation</span>}
          <span>SELinux {data.selinux.enforcement ?? "unknown"}</span>
           <span>Policy {data.selinux.configured_policy_type ?? "unknown"}</span>
           {kernelPolicyVersion != null && <span>Host policy format {kernelPolicyVersion}</span>}
        </div>
      </div>
      <div className="configuration-header-status" aria-label="Comparison status">
        <Label color={stale ? "orange" : data.observation ? "green" : "grey"}>
          {stale ? "Stale observation" : data.observation ? "Current observation" : "No observation"}
        </Label>
        {data.comparison.available && !stale && (
          <Label color={differenceCount > 0 || limited ? "orange" : "green"} aria-label={differenceCount > 0 ? `Differences found: ${differenceCount}` : limited ? "Comparison limited" : "Matches reference"}>
            {differenceCount > 0 ? plural(differenceCount, "difference") : limited ? "Comparison limited" : "Matches reference"}
          </Label>
        )}
      </div>
    </div>
  );
}

function TechnicalDetails({ data, host }: { data: HostConfigurationResponse; host?: HostDetailResponse["host"] }) {
  const reference = data.reference.catalog_revision;
  return (
    <details className="configuration-technical-details">
      <summary>Technical details</summary>
      <dl>
        <div><dt>Host ID</dt><dd>{data.host.external_id}</dd></div>
        {data.observation && <div><dt>Observed at</dt><dd>{formatUtc(data.observation.last_observed_at)}</dd></div>}
        {data.selinux.policy_identity && <div><dt>Host policy identity</dt><dd><ClipboardCopy variant="inline-compact" isReadOnly isCode copyAriaLabel="Copy host policy identity" textAriaLabel="Host policy identity">{data.selinux.policy_identity}</ClipboardCopy></dd></div>}
        {reference?.loaded_policy_digest && <div><dt>Reference policy digest</dt><dd><ClipboardCopy variant="inline-compact" isReadOnly isCode copyAriaLabel="Copy reference policy digest" textAriaLabel="Reference policy digest">{reference.loaded_policy_digest}</ClipboardCopy></dd></div>}
        {reference?.content_digest && <div><dt>Catalog content digest</dt><dd><code>{reference.content_digest}</code></dd></div>}
        <div><dt>Selection basis</dt><dd>{data.selection.basis ?? data.selection.reason ?? data.selection.status}</dd></div>
        {host?.agent.agent_version && <div><dt>Agent version</dt><dd>{host.agent.agent_version}</dd></div>}
      </dl>
    </details>
  );
}

function SummaryMetric({ count, label, color, help }: { count: number; label: string; color: "warning" | "danger"; help?: string }) {
  return (
    <div className="configuration-summary-metric">
      <strong className={count > 0 ? `pf-v6-u-text-color-status-${color}` : undefined}>{count}</strong>
      <span>
        {label}
        {help && <Tooltip content={help}><button type="button" className="configuration-summary-help" aria-label={`About ${label}`}><InfoCircleIcon /></button></Tooltip>}
      </span>
    </div>
  );
}

function ComparisonSummary({ data }: { data: HostConfigurationResponse }) {
  const booleans = data.comparison.summary.booleans;
  const ports = data.comparison.summary.ports;
  if (!booleans && !ports) return null;
  if (data.comparison.paused || data.observation?.status === "stale") {
    return <p role="status" className="pf-v6-u-mb-md">Comparison paused — current matches and differences are unverified.</p>;
  }
  return (
    <div className="configuration-summary-grid" aria-label="Comparison summary">
      {booleans && data.selection.families.booleans.comparison_allowed && (
        <Card isCompact className="configuration-summary-card">
          <CardBody>
            <Title headingLevel="h3" size="md">Booleans</Title>
            <div className="configuration-summary-outcome">
              <strong>{booleans.match} / {booleans.reference_entries} match</strong>
              <Label color={booleans.differ > 0 ? "orange" : "green"}>{plural(booleans.differ, "difference")}</Label>
            </div>
            <div className="configuration-summary-metrics" aria-label="Boolean comparison counts">
              <SummaryMetric count={booleans.differ} label="Differ" color="warning" />
              <SummaryMetric count={booleans.host_only} label="Host-only" color="warning" />
              <SummaryMetric count={booleans.not_observed} label="Not observed" color="warning" />
              <SummaryMetric count={booleans.unavailable} label="Unavailable" color="danger" />
            </div>
          </CardBody>
        </Card>
      )}
      {ports && data.selection.families.ports.comparison_allowed && (
        <Card isCompact className="configuration-summary-card">
          <CardBody>
            <Title headingLevel="h3" size="md">Ports</Title>
            <div className="configuration-summary-outcome">
              <strong>{ports.match} / {ports.compared + ports.not_observed} match</strong>
              <Label color={ports.differ > 0 ? "orange" : "green"}>{plural(ports.differ, "difference")}</Label>
            </div>
            <div className="configuration-summary-metrics configuration-summary-metrics-ports" aria-label="Port comparison counts">
              <SummaryMetric count={ports.differ} label="Differ" color="warning" />
              <SummaryMetric
                count={ports.not_observed}
                label="Unconfirmed"
                color="warning"
                help="Reference port mappings not seen in a partial host inventory are neither matches nor differences."
              />
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
}

function Differences({ data }: { data: HostConfigurationResponse }) {
  const differences = data.differences;
  if (!differences) return null;
  const limitations = differences.limitations;
  return (
    <section aria-label="Differences">
      {differences.total === 0 ? (
          <p className="configuration-no-differences"><Label color={comparisonLimited(data) ? "orange" : "green"}>{comparisonLimited(data) ? "No observed Boolean/port differences — comparison limited" : "No Boolean/port differences"}</Label> No boolean or port differences were observed.</p>
      ) : (
        <div className="pf-v6-c-table__responsive-wrapper">
          <table className="pf-v6-c-table pf-m-compact pf-m-grid-md configuration-differences-table" aria-label="Configuration differences">
            <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
              <th className="pf-v6-c-table__th" scope="col">Type</th>
              <th className="pf-v6-c-table__th" scope="col">Identity</th>
              <th className="pf-v6-c-table__th" scope="col">Host</th>
              <th className="pf-v6-c-table__th" scope="col">Reference</th>
              <th className="pf-v6-c-table__th" scope="col">Result / explanation</th>
            </tr></thead>
            <tbody className="pf-v6-c-table__tbody">
              {differences.booleans.map((finding) => (
                <tr className="pf-v6-c-table__tr" key={`boolean-${finding.name}`}>
                  <td className="pf-v6-c-table__td" data-label="Type">Boolean</td>
                  <td className="pf-v6-c-table__td" data-label="Identity"><code>{finding.name}</code></td>
                  <td className="pf-v6-c-table__td" data-label="Host">{boolText(finding.observed_current)}</td>
                  <td className="pf-v6-c-table__td" data-label="Reference">{finding.reference_default === null || finding.reference_default === undefined ? "—" : boolText(finding.reference_default)}</td>
                  <td className="pf-v6-c-table__td" data-label="Result / explanation">
                    <Label color={finding.kind === "differs" ? "orange" : "grey"} isCompact>{finding.kind === "differs" ? "Differs" : "Host-only"}</Label>
                    <small className="configuration-difference-explanation">{finding.description ?? (finding.kind === "host_only" ? "Not present in reference" : "Host value differs from reference")}</small>
                  </td>
                </tr>
              ))}
              {differences.ports.map((segment, index) => (
                <tr className="pf-v6-c-table__tr" key={`port-${segment.protocol}-${segment.start}-${index}`}>
                  <td className="pf-v6-c-table__td" data-label="Type">Port mapping</td>
                  <td className="pf-v6-c-table__td" data-label="Identity"><code>{segment.protocol}/{segment.start === segment.end ? segment.start : `${segment.start}-${segment.end}`}</code></td>
                  <td className="pf-v6-c-table__td" data-label="Host">{(segment.observed_types ?? []).filter(Boolean).join(", ") || "—"}</td>
                  <td className="pf-v6-c-table__td" data-label="Reference">{(segment.catalog_types ?? []).filter(Boolean).join(", ") || "—"}</td>
                  <td className="pf-v6-c-table__td" data-label="Result / explanation">
                    <Label color={RELATION_COLORS[segment.relation] ?? "orange"} isCompact>
                      {segment.relation === "matching_effective_type" ? "Match" : segment.relation === "comparison_unknown" ? "Unknown" : "Differs"}
                    </Label>
                    <small className="configuration-difference-explanation">{segment.local_classification === "custom" ? "Custom mapping" : displayState(segment.local_classification ?? segment.relation)}</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {(limitations.reference_only_booleans.length > 0 || limitations.unavailable_booleans.length > 0 || limitations.port_segments.length > 0) && (
        <>
          <Title headingLevel="h4" size="md" className="pf-v6-u-mt-md">
            Comparison limitations
          </Title>
          {limitations.reference_only_booleans.length > 0 && (
            <p className="pf-v6-u-mt-sm">
              Reference-only booleans: {limitations.reference_only_booleans.join(", ")}
            </p>
          )}
          {limitations.unavailable_booleans.length > 0 && (
            <p className="pf-v6-u-mt-sm">
              Unavailable booleans: {limitations.unavailable_booleans.join(", ")}
            </p>
          )}
          {limitations.port_segments.length > 0 && (
            <p className="pf-v6-u-mt-sm">
              {limitations.port_segments.length} port segment{limitations.port_segments.length === 1 ? "" : "s"} could not be compared.
            </p>
          )}
        </>
      )}
    </section>
  );
}

function ConfigurationViewToolbar({
  query,
  placeholder,
  searchLabel,
  total,
  page,
  pageSize,
  paginationLabel,
  onSearch,
  onPage,
  onPageSize
}: {
  query: string;
  placeholder: string;
  searchLabel: string;
  total: number;
  page: number;
  pageSize: number;
  paginationLabel: string;
  onSearch: (value: string) => void;
  onPage: (page: number) => void;
  onPageSize: (size: number) => void;
}) {
  return (
    <Toolbar className="configuration-view-toolbar">
      <ToolbarContent>
        <ToolbarItem className="configuration-view-search">
          <SearchInput
            value={query}
            onChange={(_event, value) => onSearch(value)}
            onClear={() => onSearch("")}
            aria-label={searchLabel}
            placeholder={placeholder}
          />
        </ToolbarItem>
        <ToolbarItem className="configuration-view-pagination-status" alignSelf="center">
          <span aria-live="polite" aria-atomic="true">
            {total === 0 ? 0 : (page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
          </span>
        </ToolbarItem>
        <ToolbarItem align={{ default: "alignEnd" }}>
          <Pagination
            variant="top"
            className="pf-m-display-full"
            itemCount={total}
            page={page}
            perPage={pageSize}
            perPageOptions={PAGE_SIZES.map((value) => ({ title: String(value), value }))}
            onPerPageSelect={(_event, size) => onPageSize(size)}
            onSetPage={(_event, nextPage) => onPage(nextPage)}
            titles={{ paginationAriaLabel: `${paginationLabel} pagination` }}
            widgetId={`${paginationLabel.replaceAll(" ", "-")}-pagination`}
          />
        </ToolbarItem>
      </ToolbarContent>
    </Toolbar>
  );
}

function BooleansView({ data, query, onSearch, onPage, onPageSize }: {
  data: HostConfigurationResponse;
  query: string;
  onSearch: (value: string) => void;
  onPage: (page: number) => void;
  onPageSize: (size: number) => void;
}) {
  const booleans = data.booleans;
  if (!booleans) return null;

  return (
    <section aria-label="Boolean comparison">
      <ConfigurationViewToolbar
        query={query}
        onSearch={onSearch}
        onPage={onPage}
        onPageSize={onPageSize}
        searchLabel="Search booleans"
        placeholder="Search by name or description"
        total={booleans.total}
        page={booleans.page}
        pageSize={booleans.page_size}
        paginationLabel="booleans"
      />
      <div className="pf-v6-c-table__responsive-wrapper">
        <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label="Boolean rows">
          <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
            <th className="pf-v6-c-table__th" scope="col">Boolean</th><th className="pf-v6-c-table__th" scope="col">Host</th>
            <th className="pf-v6-c-table__th" scope="col">Reference</th><th className="pf-v6-c-table__th" scope="col">Result</th>
          </tr></thead>
          <tbody className="pf-v6-c-table__tbody">
            {booleans.rows.map((row) => {
              const result = booleanResult(row);
              return (
                <tr className="pf-v6-c-table__tr" key={row.name}>
                  <td className="pf-v6-c-table__td" data-label="Boolean">{row.name}<div className="pf-v6-u-color-200">{row.description ?? ""}</div></td>
                  <td className="pf-v6-c-table__td" data-label="Host">{boolText(row.current)}</td>
                  <td className="pf-v6-c-table__td" data-label="Reference">{row.reference_default === null || row.reference_default === undefined ? "—" : boolText(row.reference_default)}</td>
                  <td className="pf-v6-c-table__td" data-label="Result"><Label color={result.color} isCompact>{result.label}</Label></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function PortsView({ data, query, onSearch, onPage, onPageSize }: {
  data: HostConfigurationResponse;
  query: string;
  onSearch: (value: string) => void;
  onPage: (page: number) => void;
  onPageSize: (size: number) => void;
}) {
  const ports = data.ports;
  if (!ports) return null;

  return (
    <section aria-label="Port comparison">
      <ConfigurationViewToolbar
        query={query}
        onSearch={onSearch}
        onPage={onPage}
        onPageSize={onPageSize}
        searchLabel="Search ports"
        placeholder="Search by port number, protocol, or type"
        total={ports.total}
        page={ports.page}
        pageSize={ports.page_size}
        paginationLabel="port segments"
      />
      <div className="pf-v6-c-table__responsive-wrapper">
        <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label="Port segments">
          <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
            <th className="pf-v6-c-table__th" scope="col">Port/protocol</th><th className="pf-v6-c-table__th" scope="col">Host type</th>
            <th className="pf-v6-c-table__th" scope="col">Reference type</th><th className="pf-v6-c-table__th" scope="col">Result</th>
          </tr></thead>
          <tbody className="pf-v6-c-table__tbody">
            {ports.segments.map((segment, index) => (
              <tr className="pf-v6-c-table__tr" key={`${segment.protocol}-${segment.start}-${index}`}>
                <td className="pf-v6-c-table__td" data-label="Port/protocol">
                  {segment.protocol}/{segment.start === segment.end ? segment.start : `${segment.start}-${segment.end}`}
                </td>
                <td className="pf-v6-c-table__td" data-label="Host type">{(segment.observed_types ?? []).filter(Boolean).join(", ") || "—"}</td>
                <td className="pf-v6-c-table__td" data-label="Reference type">{(segment.catalog_types ?? []).filter(Boolean).join(", ") || "—"}</td>
                <td className="pf-v6-c-table__td" data-label="Result">
                  <Label color={RELATION_COLORS[segment.relation] ?? "orange"} isCompact>
                    {segment.relation === "matching_effective_type" ? "Match" : segment.relation === "comparison_unknown" ? "Unknown" : "Differs"}
                  </Label>
                  <small className="configuration-difference-explanation">{segment.local_classification === "custom" ? "Custom mapping" : displayState(segment.local_classification ?? segment.relation)}</small>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function HostConfiguration() {
  const { id } = useParams<{ id: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedView = searchParams.get("view") ?? "differences";
  const view: View = VIEWS.some((entry) => entry.value === requestedView) ? (requestedView as View) : "differences";
  const q = searchParams.get("q") ?? "";
  const page = Number(searchParams.get("page") ?? "1");
  const perPage = pageSize(searchParams.get("limit"));
  const referenceRevisionId = searchParams.get("reference_revision_id");

  const configQuery = useQuery({
    queryKey: ["host-configuration", Number(id), view, q, page, referenceRevisionId, perPage],
    queryFn: () => fetchHostConfiguration(Number(id), { view, q: q || undefined, page, referenceRevisionId: referenceRevisionId ?? undefined, limit: searchParams.has("limit") ? perPage : undefined }),
    refetchInterval: (query) => query.state.data?.selinux.effective_permissive_domains?.status === "pending" ? 2000 : false,
    placeholderData: (previousData, previousQuery) => previousQuery?.queryKey[1] === Number(id) && previousQuery.queryKey[5] === referenceRevisionId ? previousData : undefined
  });
  const hostQuery = useQuery({
    queryKey: ["host", Number(id)],
    queryFn: () => fetchHost(Number(id)),
    enabled: Number.isInteger(Number(id)) && Number(id) > 0
  });

  const setView = (nextView: View) => {
    const next = new URLSearchParams(searchParams);
    if (nextView === "differences") {
      next.delete("view");
    } else {
      next.set("view", nextView);
    }
    next.delete("q");
    next.delete("page");
    setSearchParams(next);
  };

  const commitViewSearch = (value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value) {
      next.set("q", value);
    } else {
      next.delete("q");
    }
    next.delete("page");
    setSearchParams(next);
  };

  const setPage = (nextPage: number) => {
    const next = new URLSearchParams(searchParams);
    if (nextPage > 1) next.set("page", String(nextPage));
    else next.delete("page");
    setSearchParams(next);
  };

  const setPageSize = (size: number) => {
    const next = new URLSearchParams(searchParams);
    next.set("limit", String(size));
    next.delete("page");
    setSearchParams(next);
  };

  const setReference = (revision: string | null) => {
    const next = new URLSearchParams(searchParams);
    if (revision === null) next.delete("reference_revision_id");
    else next.set("reference_revision_id", revision);
    next.delete("page");
    next.delete("q");
    setSearchParams(next);
  };

  const data = configQuery.data;
  const comparisonAvailable = data?.comparison.available ?? false;
  const comparisonPaused = data?.comparison.paused || data?.observation?.status === "stale";

  return (
    <>
      <Breadcrumb aria-label="Breadcrumb" className="pf-v6-u-mb-sm">
        <BreadcrumbItem><Link to="/hosts">Monitored servers</Link></BreadcrumbItem>
        <BreadcrumbItem isActive><Link to={`/hosts/${id}`}>{data?.host.hostname ?? `Host ${id}`}</Link></BreadcrumbItem>
      </Breadcrumb>
      <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">
        SELinux configuration
      </Title>

      {configQuery.isPending ? (
        <div aria-label="Loading host configuration" style={{ padding: "var(--pf-v6-global--spacer--xl)" }}>
          <Spinner size="xl" />
        </div>
      ) : configQuery.isError ? (
         <Alert variant="danger" title="Could not load host configuration">
           {configQuery.error instanceof Error ? configQuery.error.message : "Unknown error"}
           {referenceRevisionId !== null && <Button variant="link" onClick={() => setReference(null)}>Return to automatic</Button>}
        </Alert>
      ) : (
        <>
          {data && <ComparisonHeader data={data} host={hostQuery.data?.host} />}
          {data && <TechnicalDetails data={data} host={hostQuery.data?.host} />}
          {data && <CatalogReferenceSelection data={data} requestedRevision={referenceRevisionId} onSelect={setReference} />}
          <EffectivePermissiveDomains key={data?.selinux.effective_permissive_domains?.policy_identity} state={data?.selinux.effective_permissive_domains} />
          {data && (configQuery.isFetching ? <section aria-label="Effective permissive-domain reference comparison"><h3>Effective permissive domains — reference comparison</h3><p role="status">Refreshing the current exact-policy comparison…</p></section>
            : <EffectivePermissiveComparison key={`${data.comparison.effective_permissive_domains.host.policy_identity}-${data.comparison.effective_permissive_domains.reference?.policy_identity}-${data.comparison.effective_permissive_domains.host.semantics_version}-${data.comparison.effective_permissive_domains.reference?.semantics_version}-${referenceRevisionId}`} comparison={data.comparison.effective_permissive_domains} />)}
          {comparisonAvailable ? (
            <>
              {(data?.comparison.paused || data?.observation?.status === "stale") && (
                <Alert variant="warning" isInline title="Stale configuration" className="pf-v6-u-mb-md configuration-stale-alert">
                  Comparison based on stale host configuration
                </Alert>
              )}
              {data && <ComparisonSummary data={data} />}
              <Tabs
                activeKey={view}
                onSelect={(_event, key) => setView(String(key) as View)}
                aria-label="Configuration views"
                className="pf-v6-u-mb-lg"
              >
                {VIEWS.map((entry) => {
                  const booleans = data?.comparison.summary.booleans;
                  const ports = data?.comparison.summary.ports;
                  const count = entry.value === "differences"
                    ? data?.differences?.total ?? (booleans && ports ? booleans.differ + booleans.host_only + ports.differ : 0)
                    : entry.value === "booleans" ? booleans?.reference_entries ?? 0 : (ports?.compared ?? 0) + (ports?.not_observed ?? 0);
                   return <Tab key={entry.value} eventKey={entry.value} title={<TabTitleText>{entry.label}{comparisonPaused ? "" : ` (${count})`}</TabTitleText>} />;
                })}
              </Tabs>
              {configQuery.isPending ? (
                <div aria-label="Loading configuration view" style={{ padding: "var(--pf-v6-global--spacer--xl)" }}>
                  <Spinner />
                </div>
              ) : (
                data && (
                  <>
                    {view === "differences" && (comparisonPaused ? <p>Current differences cannot be determined from a stale observation. Inspect the Booleans or Ports view for retained inventory state.</p> : <Differences data={data} />)}
                    {view === "booleans" && <BooleansView data={data} query={q} onSearch={commitViewSearch} onPage={setPage} onPageSize={setPageSize} />}
                    {view === "ports" && <PortsView data={data} query={q} onSearch={commitViewSearch} onPage={setPage} onPageSize={setPageSize} />}
                  </>
                )
              )}
            </>
          ) : data ? (
            <Alert variant="info" isInline title={data.selection.status === "selected" ? "Comparison unavailable" : "No reference available"}>
              Host observations and selected reference facts cannot currently support this comparison. Observed facts remain available in host details.
            </Alert>
          ) : null}
        </>
      )}
    </>
  );
}
