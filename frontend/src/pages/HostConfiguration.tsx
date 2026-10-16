import {
  Alert, Breadcrumb, BreadcrumbItem, Button, Card, CardBody, Checkbox, DescriptionList,
  DescriptionListDescription, DescriptionListGroup, DescriptionListTerm,
  ExpandableSection, Label, Pagination, SearchInput, Spinner, Stack, StackItem,
  Tab, TabTitleText, Tabs, Title, Toolbar, ToolbarContent, ToolbarGroup, ToolbarItem
} from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { fetchHostConfiguration, type HostConfigurationResponse } from "../api/configuration";
import { CatalogReferenceSelection } from "../components/CatalogReferenceSelection";
import { PAGE_SIZES, pageSize } from "../pagination";

const VIEWS = [
  { value: "differences", label: "Deviations", table: "Baseline deviations", search: "Search deviations" },
  { value: "booleans", label: "Booleans", table: "Boolean rows", search: "Search booleans" },
  { value: "ports", label: "Ports", table: "Port segments", search: "Search ports" },
  { value: "effective_permissive_domains", label: "Effective permissive domains", table: "Effective permissive domains", search: "Search domains" }
] as const;
type View = (typeof VIEWS)[number]["value"];
type Result = { label: string; color: "green" | "orange" | "grey" | "blue" };
const DEVIATION_CATEGORIES = [
  { value: "differs", label: "Value Mismatches" },
  { value: "not_observed", label: "Unobserved Items" },
  { value: "host_only", label: "Host Only" },
  { value: "reference_only", label: "Reference Only" }
] as const;
const DOMAIN_REASONS: Record<string, string> = {
  stale_host_observation: "The host observation is stale; current membership is unverified.",
  host_policy_identity_unavailable: "The host's current policy could not be identified.",
  host_policy_artifact_unavailable: "The host policy is not available for analysis.",
  host_permissive_analysis_pending: "Host policy analysis is pending.",
  host_permissive_analysis_unavailable: "Host policy analysis is unavailable.",
  host_permissive_analysis_error: "Host policy analysis failed.",
  reference_absent: "No applicable reference was selected. Showing observed host membership when available.",
  reference_ambiguous: "Select a baseline to resolve the ambiguous reference.",
  reference_archived: "The selected baseline is archived.",
  reference_unavailable: "The selected baseline is unavailable.",
  incompatible_policy_context: "The baseline's policy type or architecture is incompatible with this host.",
  reference_inline_facts_unavailable: "Eligible catalogs do not all provide usable domain membership.",
  reference_extraction_semantics_incompatible: "The baseline does not support a compatible domain comparison.",
  effective_permissive_reference_ambiguous: "Eligible catalogs disagree on permissive domains. Select a baseline to compare."
};

function comparisonWarning(data: HostConfigurationResponse): boolean {
  return data.comparison.effective_permissive_domains.status !== "observed" ||
    Object.values(data.selection.families).some((family) => family.status !== "comparable") ||
    (data.comparison.summary.booleans?.unavailable ?? 0) + (data.comparison.summary.ports?.not_observed ?? 0) > 0;
}

function deviationCount(data: HostConfigurationResponse): number {
  if (data.comparison.deviations) return data.comparison.deviations.total;
  const { booleans, ports } = data.comparison.summary;
  const domains = data.comparison.effective_permissive_domains;
  return (booleans?.differ ?? 0) + (booleans?.host_only ?? 0) + (booleans?.not_observed ?? 0) + (ports?.differ ?? 0) +
    (domains.status === "observed" ? (domains.counts?.unexpected_on_host ?? 0) + (domains.counts?.missing_from_host ?? 0) : 0);
}

function formatUtc(iso: string): string {
  return `${new Intl.DateTimeFormat("en", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: "UTC" }).format(new Date(iso))} UTC`;
}

function timeAgo(iso: string): string {
  const minutes = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60_000));
  if (minutes < 1) return "less than a minute ago";
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function boolText(value: boolean | null | undefined): string {
  return value === true ? "On" : value === false ? "Off" : "Unknown";
}

function resultLabel(result: string): Result {
  if (result === "match" || result === "matching_effective_type") return { label: "Match", color: "green" };
  if (result === "differs") return { label: "Value Mismatch", color: "orange" };
  if (result === "host_only") return { label: "Host Only", color: "blue" };
  if (result === "reference_only") return { label: "Reference Only", color: "orange" };
  if (result === "stale") return { label: "Unverified", color: "orange" };
  if (result === "unavailable") return { label: "Unavailable", color: "grey" };
  if (result === "not_observed") return { label: "Unobserved", color: "grey" };
  if (result === "not_compared") return { label: "Not compared", color: "grey" };
  return { label: "Unknown", color: "grey" };
}

function ComparisonHeader({ data, requestedRevision, onSelect }: {
  data: HostConfigurationResponse; requestedRevision: string | null; onSelect: (revision: string | null) => void;
}) {
  const reference = data.reference.catalog_revision;
  const paused = data.comparison.paused || data.observation?.status === "stale";
  const count = deviationCount(data);
  const limited = comparisonWarning(data);
  const notObserved = data.comparison.deviations?.by_result.not_observed ?? data.comparison.summary.booleans?.not_observed ?? 0;
  const comparisonStatus = count ? `${count} deviation${count === 1 ? "" : "s"}` : limited ? "Comparison limited" : "Matches reference";
  return <Card isCompact aria-label="Baseline summary"><CardBody>
    <div className="configuration-comparison-header">
      <div>
        <DescriptionList orientation={{ sm: "horizontal" }} isCompact className="configuration-baseline-facts">
          <DescriptionListGroup><DescriptionListTerm>Baseline</DescriptionListTerm><DescriptionListDescription>
            {reference ? <><Link to={`/catalogs/${reference.id}`}>{reference.display_name}</Link> · {[reference.policy_type, reference.architecture].filter(Boolean).join(" · ")}</> : "No active reference"}
          </DescriptionListDescription></DescriptionListGroup>
          <DescriptionListGroup><DescriptionListTerm>Last observed</DescriptionListTerm><DescriptionListDescription>
            {data.observation ? <time dateTime={data.observation.last_observed_at} title={formatUtc(data.observation.last_observed_at)}>Observed {timeAgo(data.observation.last_observed_at)} · {formatUtc(data.observation.last_observed_at)}</time> : "No current observation"}
          </DescriptionListDescription></DescriptionListGroup>
          <DescriptionListGroup><DescriptionListTerm>SELinux mode</DescriptionListTerm><DescriptionListDescription>{data.selinux.enforcement ?? "Unknown"}</DescriptionListDescription></DescriptionListGroup>
        </DescriptionList>
        <div className="configuration-header-status" aria-label="Comparison status">
          <Label color={paused ? "orange" : data.observation ? "green" : "grey"}>{paused ? "Stale observation" : data.observation ? "Current observation" : "No observation"}</Label>
          {data.comparison.available && !paused && <Label color={count > notObserved || limited ? "orange" : notObserved ? "grey" : "green"} aria-label={count ? `Deviations found: ${count}` : comparisonStatus}>
            {comparisonStatus}
          </Label>}
        </div>
      </div>
      <CatalogReferenceSelection data={data} requestedRevision={requestedRevision} onSelect={onSelect} />
    </div>
  </CardBody></Card>;
}

function ComparisonSummary({ data, viewUrl, onView }: { data: HostConfigurationResponse; viewUrl: (view: View) => string; onView: (view: View) => void }) {
  if (data.comparison.paused || data.observation?.status === "stale") return <Alert isInline variant="warning" title="Comparison paused">Current matches and deviations are unverified. Retained inventory remains available.</Alert>;
  const { booleans, ports } = data.comparison.summary;
  const domains = data.comparison.effective_permissive_domains;
  const state = data.selinux.effective_permissive_domains;
  const cards: { view: View; label: string; value: string; deviations?: number; scope?: string }[] = [];
  if (data.comparison.available && booleans && data.selection.families.booleans.comparison_allowed) cards.push({ view: "booleans", label: "Booleans", value: `${booleans.match} / ${booleans.reference_entries} match`, deviations: data.comparison.deviations?.by_family.boolean ?? booleans.differ + booleans.host_only + booleans.not_observed,
    scope: booleans.unavailable > 0 ? "Some reference settings could not be checked" : booleans.not_observed > 0 ? `${booleans.not_observed} not observed` : undefined });
  if (data.comparison.available && ports && data.selection.families.ports.comparison_allowed) cards.push({ view: "ports", label: "Ports", value: `${ports.match} / ${ports.compared + ports.not_observed} match`, deviations: data.comparison.deviations?.by_family.port ?? ports.differ,
    scope: ports.not_observed > 0 ? "Some reference mappings could not be checked" : undefined });
  cards.push({ view: "effective_permissive_domains", label: "Effective permissive domains",
    value: domains.status === "observed" && domains.counts && data.reference.kind !== "none" ? `${domains.counts.matching} match` : state?.status === "observed" ? `${state.domains?.length ?? 0} observed on host` : state?.status === "pending" ? "Host analysis pending" : state?.status === "error" ? "Host analysis failed" : "Host state unavailable",
    deviations: domains.status === "observed" && domains.counts && data.reference.kind !== "none" ? data.comparison.deviations?.by_family.domain ?? domains.counts.unexpected_on_host + domains.counts.missing_from_host : undefined });
  return <div className="configuration-summary-grid" aria-label="Host comparison summary">{cards.map((card) =>
    <Card key={card.view} isCompact isClickable component="a" href={viewUrl(card.view)} aria-label={`View ${card.label.toLowerCase()}`} className="metric-card configuration-summary-card" onClick={(event) => {
      if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) { event.preventDefault(); onView(card.view); }
    }}><CardBody>
      <Title headingLevel="h3" size="md">{card.label}</Title>
      <div className="configuration-summary-outcome"><strong>{card.value}</strong>
        {card.deviations != null ? <Label color={card.deviations ? "orange" : card.scope ? "grey" : "green"}>{card.deviations} deviation{card.deviations === 1 ? "" : "s"}</Label> : <span>Comparison unavailable</span>}
      </div>
      {card.scope && <p>{card.scope}</p>}
    </CardBody></Card>
  )}</div>;
}

function ComparisonScope({ data }: { data: HostConfigurationResponse }) {
  const [expanded, setExpanded] = useState(false);
  const limits = data.differences?.limitations;
  if (!limits || (limits.unavailable_booleans.length === 0 && limits.port_segments.length === 0)) return null;
  return <StackItem><ExpandableSection toggleText="Comparison scope & limitations" isExpanded={expanded} onToggle={(_event, expanded) => setExpanded(expanded)}>
    {limits.unavailable_booleans.length > 0 && <p>Unavailable booleans: {limits.unavailable_booleans.join(", ")}</p>}
    {limits.port_segments.length > 0 && <p>{limits.port_segments.length} reference port segments could not be checked.</p>}
  </ExpandableSection></StackItem>;
}

export function HostConfiguration() {
  const { id } = useParams<{ id: string }>();
  const [params, setParams] = useSearchParams();
  const view = VIEWS.find((entry) => entry.value === (params.get("view") ?? "differences")) ?? VIEWS[0];
  const q = params.get("q") ?? "";
  const page = Math.max(1, Number(params.get("page")) || 1);
  const perPage = pageSize(params.get("limit"));
  const reference = params.get("reference_revision_id");
  const results = view.value === "differences" ? params.get("results") : null;
  const selectedResults = results === null ? DEVIATION_CATEGORIES.map((category) => category.value) : results.split(",").filter((value) => DEVIATION_CATEGORIES.some((category) => category.value === value));
  const query = useQuery({
    queryKey: ["host-configuration", Number(id), view.value, q, page, reference, perPage, results],
    queryFn: () => fetchHostConfiguration(Number(id), { view: view.value, q: q || undefined, page, referenceRevisionId: reference ?? undefined, limit: params.has("limit") ? perPage : undefined, results: results ?? undefined }),
    refetchInterval: (query) => query.state.data?.selinux.effective_permissive_domains?.status === "pending" ? 2000 : false,
    placeholderData: (previous, previousQuery) => previousQuery?.queryKey[1] === Number(id) && previousQuery.queryKey[5] === reference && previousQuery.queryKey[2] === view.value ? previous : undefined
  });
  function update(values: Record<string, string | null>) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(values)) { if (value === null) next.delete(key); else next.set(key, value); }
    setParams(next);
  }
  function viewParams(nextView: View) {
    const next = new URLSearchParams(params);
    if (nextView === "differences") next.delete("view"); else next.set("view", nextView);
    next.delete("q"); next.delete("page"); next.delete("results");
    return next;
  }
  const setView = (nextView: View) => setParams(viewParams(nextView));
  const setReference = (revision: string | null) => update({ reference_revision_id: revision, page: null, q: null });
  const data = query.data;
  const paused = data?.comparison.paused || data?.observation?.status === "stale";
  const tablePage = view.value === "booleans" ? data?.booleans : view.value === "ports" ? data?.ports : data?.entries;
  const domainState = data?.selinux.effective_permissive_domains;
  const domainComparison = data?.comparison.effective_permissive_domains;
  const counts = data ? {
    differences: deviationCount(data), booleans: data.comparison.summary.booleans?.reference_entries,
    ports: data.comparison.summary.ports ? data.comparison.summary.ports.compared + data.comparison.summary.ports.not_observed : undefined,
    effective_permissive_domains: domainState?.status === "observed" ? new Set([...(domainState.domains ?? []), ...(domainComparison?.missing_from_host ?? [])]).size : undefined
  } : null;
  const cannotCompare = view.value === "differences" && (!data?.comparison.available || paused);
  const domainUnknown = view.value === "effective_permissive_domains" && (paused || domainComparison?.status !== "observed");
  return <Stack hasGutter>
    <StackItem>
      <Breadcrumb aria-label="Breadcrumb"><BreadcrumbItem><Link to="/hosts">Monitored servers</Link></BreadcrumbItem><BreadcrumbItem><Link to={`/hosts/${id}`}>{data?.host.hostname ?? `Host ${id}`}</Link></BreadcrumbItem><BreadcrumbItem isActive>SELinux configuration</BreadcrumbItem></Breadcrumb>
      <Title headingLevel="h1" size="2xl">SELinux configuration</Title>
    </StackItem>
    {query.isPending ? <StackItem><Spinner aria-label="Loading host configuration" /></StackItem> : query.isError ? <StackItem><Alert variant="danger" title="Could not load host configuration">
      {query.error instanceof Error ? query.error.message : "Unknown error"}
      <Button variant="link" onClick={() => query.refetch()}>Retry</Button>
      {reference !== null && <Button variant="link" onClick={() => setReference(null)}>Return to automatic</Button>}
    </Alert></StackItem> : data && <>
      <StackItem><ComparisonHeader data={data} requestedRevision={reference} onSelect={setReference} /></StackItem>
      <StackItem><ComparisonSummary data={data} viewUrl={(view) => `?${viewParams(view)}`} onView={setView} /></StackItem>
      <StackItem><Tabs activeKey={view.value} onSelect={(_event, key) => setView(key as View)} aria-label="Configuration views">
        {VIEWS.map((entry) => <Tab key={entry.value} id={`configuration-${entry.value}`} tabContentId="configuration-panel" eventKey={entry.value} title={<TabTitleText>{entry.label}{!paused && counts?.[entry.value] != null && (data.comparison.available || entry.value === "effective_permissive_domains") ? ` (${counts[entry.value]})` : ""}</TabTitleText>} />)}
      </Tabs></StackItem>
      <StackItem><Card role="tabpanel" id="configuration-panel" aria-labelledby={`pf-tab-${view.value}-configuration-${view.value}`}><CardBody><Stack hasGutter>
        <StackItem><Title headingLevel="h2" size="lg">{view.label}</Title></StackItem>
        {cannotCompare ? <StackItem><Alert isInline variant={paused ? "warning" : "info"} title={paused ? "Current deviations are unverified" : "No reference comparison available"}>Inspect the inventory tabs for observed host settings.</Alert></StackItem> : <>
          {domainUnknown && <StackItem><Alert isInline variant={paused ? "warning" : "info"} title={paused ? "Current domain membership is unverified" : "Domain comparison unavailable"}>
            {paused ? DOMAIN_REASONS.stale_host_observation : domainComparison?.reason ? DOMAIN_REASONS[domainComparison.reason] ?? "The selected baseline cannot currently be compared." : "The selected baseline cannot currently be compared."}
          </Alert></StackItem>}
          {comparisonWarning(data) && view.value === "differences" && <StackItem><Alert isInline variant="warning" title="Comparison limited">Some settings could not be checked. Unavailable settings are excluded from deviation counts.</Alert></StackItem>}
          <StackItem><Toolbar hasNoPadding className="configuration-view-toolbar"><ToolbarContent>
            <ToolbarItem className="configuration-view-search"><SearchInput aria-label={view.search} placeholder={view.search} value={q} onChange={(_event, value) => update({ q: value || null, page: null })} onClear={() => update({ q: null, page: null })} /></ToolbarItem>
            <ToolbarItem align={{ default: "alignEnd" }}><span aria-live="polite">{view.value === "differences" ? `${tablePage?.total ?? 0} of ${deviationCount(data)} deviations` : `${tablePage?.total ?? 0} results`}</span></ToolbarItem>
            {view.value === "differences" && <ToolbarGroup variant="filter-group" aria-label="Deviation categories">{DEVIATION_CATEGORIES.map((category) => <ToolbarItem key={category.value}><Checkbox id={`deviation-${category.value}`} label={`${category.label}${data.comparison.deviations ? ` (${data.comparison.deviations.by_result[category.value]})` : ""}`} isChecked={selectedResults.includes(category.value)} onChange={(_event, checked) => {
              const selected = new Set(selectedResults);
              if (checked) selected.add(category.value); else selected.delete(category.value);
              update({ results: selected.size === DEVIATION_CATEGORIES.length ? null : DEVIATION_CATEGORIES.filter((entry) => selected.has(entry.value)).map((entry) => entry.value).join(","), page: null });
            }} /></ToolbarItem>)}</ToolbarGroup>}
          </ToolbarContent></Toolbar></StackItem>
          <StackItem><Table role="table" aria-label={view.table} variant="compact" gridBreakPoint="grid-lg">
            <Thead><Tr>{view.value === "differences" && <Th>Type</Th>}<Th>{view.value === "effective_permissive_domains" ? "Domain Name" : view.value === "booleans" ? "Boolean" : view.value === "ports" ? "Port/protocol" : "Identity"}</Th><Th>{view.value === "effective_permissive_domains" ? "Host Status" : view.value === "ports" ? "Host type" : "Host"}</Th><Th>{view.value === "effective_permissive_domains" ? "Reference Status" : view.value === "ports" ? "Reference type" : "Reference"}</Th><Th>{view.value === "effective_permissive_domains" ? "Comparison Result" : "Result"}</Th></Tr></Thead>
            <Tbody>
              {view.value === "booleans" && data.booleans?.rows.map((row) => {
                const result = row.status !== "observed" ? resultLabel(row.status) : row.current == null ? resultLabel("unknown") : row.catalog_status === "not_defined" ? resultLabel("host_only") : row.reference_default == null ? resultLabel("not_compared") : resultLabel(row.current === row.reference_default ? "match" : "differs");
                return <Tr key={row.name}><Td dataLabel="Boolean">{row.name}{row.description && <div>{row.description}</div>}</Td><Td dataLabel="Host">{boolText(row.current)}</Td><Td dataLabel="Reference">{row.reference_default == null ? "Not compared" : boolText(row.reference_default)}</Td><Td dataLabel="Result"><Label color={result.color}>{result.label}</Label></Td></Tr>;
              })}
              {view.value === "ports" && data.ports?.segments.map((row) => {
                const result = paused ? resultLabel("stale") : !data.selection.families.ports.comparison_allowed || data.reference.kind === "none" ? resultLabel("not_compared") : resultLabel(row.relation === "comparison_unknown" ? "unknown" : row.relation === "matching_effective_type" ? "match" : row.relation === "catalog_defined_not_observed" ? "not_observed" : row.relation.startsWith("observed_not_represented") ? "host_only" : "differs");
                return <Tr key={`${row.protocol}-${row.start}-${row.end}`}><Td dataLabel="Port/protocol">{row.protocol}/{row.start === row.end ? row.start : `${row.start}-${row.end}`}</Td><Td dataLabel="Host type">{row.observed_types?.join(", ") || "Unknown"}</Td><Td dataLabel="Reference type">{row.catalog_types?.join(", ") || "Not represented"}</Td><Td dataLabel="Result"><Label color={result.color}>{result.label}</Label>{row.local_classification === "custom" && <div>Custom mapping</div>}</Td></Tr>;
              })}
              {(view.value === "differences" || view.value === "effective_permissive_domains") && data.entries?.rows.map((row) => {
                const result = resultLabel(row.result);
                return <Tr key={`${row.kind}-${row.name}`}>
                  {view.value === "differences" && <Td dataLabel="Type">{row.kind === "boolean" ? "Boolean" : row.kind === "port" ? "Port mapping" : "Permissive domain"}</Td>}
                  <Td dataLabel={view.value === "differences" ? "Identity" : "Domain Name"}>{row.name}</Td><Td dataLabel="Host Status">{row.result === "not_observed" ? "Not observed" : row.host_value ?? "Unknown"}</Td><Td dataLabel="Reference Status">{row.reference_value ?? "Not compared"}</Td><Td dataLabel="Comparison Result"><Label color={result.color}>{result.label}</Label>{row.description && <div>{row.description}</div>}</Td>
                </Tr>;
              })}
            </Tbody>
          </Table></StackItem>
          {tablePage?.total === 0 && <StackItem><p>{view.value === "differences" ? q || results !== null ? "No matching deviations." : "No deviations." : q ? "No matching settings." : view.value === "effective_permissive_domains" && domainState?.status !== "observed" ? "Domain membership has not been determined." : "No entries recorded."}</p>{(q || results !== null) && <Button variant="link" onClick={() => update({ q: null, results: null, page: null })}>Clear filters</Button>}</StackItem>}
          {tablePage && <StackItem><div className="table-pagination"><Pagination itemCount={tablePage.total} page={tablePage.page} perPage={tablePage.page_size} perPageOptions={PAGE_SIZES.map((value) => ({ title: String(value), value }))} titles={{ paginationAriaLabel: `${view.label} pagination` }} widgetId={`${view.value}-pagination`} onSetPage={(_event, page) => update({ page: page > 1 ? String(page) : null })} onPerPageSelect={(_event, size) => update({ limit: String(size), page: null })} isDisabled={query.isFetching} /></div></StackItem>}
        </>}
        <ComparisonScope data={data} />
      </Stack></CardBody></Card></StackItem>
    </>}
  </Stack>;
}
