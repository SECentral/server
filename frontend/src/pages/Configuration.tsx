import {
  Alert,
  Button,
  Card,
  CardBody,
  Flex,
  FlexItem,
  Grid,
  GridItem,
  Label,
  Pagination,
  SearchInput,
  Select,
  SelectOption,
  Spinner,
  Tab,
  TabTitleText,
  Tabs,
  Title,
  ToggleGroup,
  ToggleGroupItem,
  Toolbar,
  ToolbarContent,
  ToolbarItem
} from "@patternfly/react-core";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { fetchConfiguration } from "../api/configuration";
import { MetricCard } from "../components/MetricCard";
import type { ConfigurationFleetResponse, ConfigurationFamily, ConfigurationPolicyCohort } from "../api/configuration";
import { PAGE_SIZES, pageSize } from "../pagination";
import { osDisplayName } from "../platform";

const FAMILIES: { value: ConfigurationFamily; label: string }[] = [
  { value: "booleans", label: "Booleans" },
  { value: "ports", label: "Ports" },
  { value: "file_contexts", label: "File contexts" },
  { value: "modules", label: "Modules" }
];

const BOOLEAN_COVERAGE: [string, string][] = [
  ["observed", "Observed hosts"],
  ["unavailable", "Boolean data unavailable"],
  ["stale", "Stale host snapshots"],
  ["unknown", "Unknown Boolean state"]
];

const PORT_COVERAGE: [string, string][] = [
  ["observed", "Complete port inventory"],
  ["partial", "Partial port inventory"],
  ["unavailable", "Unavailable port inventory"],
  ["unknown", "Unknown port inventory"],
  ["stale", "Stale host snapshots"],
  ["no_heartbeat", "No configuration snapshot"]
];

function CoverageCards({ family, items, counts, scoped }: { family: "booleans" | "ports"; items: [string, string][]; counts: Record<string, number>; scoped: boolean }) {
  return (
    <section aria-label="Host coverage" className="pf-v6-u-mb-md">
    <Title headingLevel="h2" size="lg">{scoped ? "Selected cohort coverage" : "Fleet coverage"}</Title>
    <Grid hasGutter aria-label="Configuration coverage">
      {items.map(([key, label]) => (
        <GridItem key={key} sm={6} md={4} xl={2}>
          <MetricCard label={label} value={counts[key] ?? 0} href={scoped ? undefined : `/hosts?configuration_family=${family}&configuration_status=${key}`} />
        </GridItem>
      ))}
    </Grid>
    </section>
  );
}

type Page = { total: number; page: number; page_size: number };
type ListProps = { search: string; onSearch: (query: string) => void; pagination: Page; onPage: (page: number) => void; onPageSize: (size: number) => void };
type ConfigurationCatalog = NonNullable<NonNullable<ConfigurationFleetResponse["booleans"]>["catalog"]>;
type ConfigurationSelection = NonNullable<NonNullable<ConfigurationFleetResponse["booleans"]>["selection"]>;

function referenceLabel(catalog: ConfigurationCatalog | null | undefined, selection: ConfigurationSelection | null | undefined): string {
  if (catalog?.available) return `Distribution reference: ${selection?.selected_revision?.display_name ?? "Available"}`;
  if (selection?.status === "absent" && selection.reason === "no_matching_candidates") return "Distribution reference: None";
  if (selection?.status === "ambiguous") return "Distribution reference: Selection ambiguous";
  return "Distribution reference: Unavailable";
}

function BooleanStateSummary({ counts }: { counts: Record<string, number> }) {
  const states = [
    { key: "on", label: "On", color: "green" as const },
    { key: "off", label: "Off", color: "grey" as const },
    { key: "unknown", label: "Unknown", color: "orange" as const },
    { key: "unavailable", label: "Unavailable", color: "red" as const },
    { key: "stale", label: "Stale", color: "orange" as const }
  ].filter(({ key }) => (counts[key] ?? 0) > 0);
  if (states.length === 0) return <>State unavailable</>;
  return <>{states.map(({ key, label, color }) => <Label key={key} color={color} isCompact className="pf-v6-u-mr-xs">{counts[key]} {label}</Label>)}{(counts.on ?? 0) > 0 && (counts.off ?? 0) > 0 && <Label color="orange" isCompact>Split</Label>}{(counts.runtime_default_divergence ?? counts.drift ?? 0) > 0 && <Label color="orange" isCompact className="pf-v6-u-ml-xs">{counts.runtime_default_divergence ?? counts.drift} default drift</Label>}</>;
}

function InventoryToolbar({ label, search, total, onSearch, protocol, onProtocolChange }: { label: string; search: string; total: number; onSearch: (query: string) => void; protocol?: string; onProtocolChange?: (protocol: string) => void }) {
  const [draftState, setDraftState] = useState({ search, value: search });
  const draft = draftState.search === search ? draftState.value : search;
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (timer.current) clearTimeout(timer.current);
  }, [search]);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);
  const updateDraft = (value: string) => {
    setDraftState({ search, value });
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => onSearch(value), 300);
  };
  const clearSearch = () => {
    if (timer.current) clearTimeout(timer.current);
    setDraftState({ search, value: "" });
    onSearch("");
  };
  return <Toolbar aria-label={`${label} filters`} hasNoPadding className="pf-v6-u-mb-md"><ToolbarContent>
    <ToolbarItem><SearchInput aria-label={`Search ${label.toLowerCase()}`} placeholder={`Search ${label.toLowerCase()}`} value={draft} onChange={(_event, value) => updateDraft(value)} onClear={clearSearch} /></ToolbarItem>
    {protocol && onProtocolChange && <ToolbarItem><ToggleGroup aria-label="Port protocol">
      {[ ["all", "All"], ["tcp", "TCP"], ["udp", "UDP"] ].map(([value, text]) => <ToggleGroupItem key={value} text={text} buttonId={`port-protocol-${value}`} isSelected={protocol === value} onChange={() => onProtocolChange(value)} />)}
    </ToggleGroup></ToolbarItem>}
    <ToolbarItem align={{ default: "alignEnd" }}><span aria-live="polite">{total} results</span></ToolbarItem>
  </ToolbarContent></Toolbar>;
}

function portSourceLabel(value: string | null | undefined): string {
  return ({ custom: "Local customization", not_confirmed_custom: "Policy default", unknown: "Source unknown" }[value ?? ""] ?? "Not recorded");
}

function portRelationLabel(value: string): string {
  return ({ matching_effective_type: "Match", different_effective_type: "Type mismatch", catalog_defined_not_observed: "Not observed on host", observed_not_represented: "Not in catalog", observed_not_represented_in_incomplete_catalog: "Not represented in incomplete catalog", comparison_unknown: "Unable to compare" }[value] ?? value.replaceAll("_", " "));
}

function inventorySourceLabel(value: string | null): string {
  return ({ distribution: "Distribution", custom: "Local customization", unknown: "Unknown" }[value ?? ""] ?? "Not recorded");
}

function ListPagination({ label, pagination, onPage, onPageSize }: { label: string; pagination: Page; onPage: (page: number) => void; onPageSize: (size: number) => void }) {
  return pagination.total > pagination.page_size ? <div className="table-pagination"><Pagination itemCount={pagination.total} page={pagination.page} perPage={pagination.page_size} perPageOptions={PAGE_SIZES.map((value) => ({ title: String(value), value }))} titles={{ paginationAriaLabel: `${label} pagination` }} onSetPage={(_event, value) => onPage(value)} onPerPageSelect={(_event, size) => onPageSize(size)} /></div> : null;
}

function BooleanInventory({ data, search, onSearch, pagination, onPage, onPageSize }: { data: ConfigurationFleetResponse } & ListProps) {
  const rows = data.booleans?.catalog_overlay?.observed.rows ?? data.booleans?.inventory ?? [];
  const referenceAvailable = data.booleans?.catalog?.available === true;
  return (
    <Card aria-label="Boolean inventory"><CardBody>
      <Title headingLevel="h2" size="lg">Booleans</Title>
      <InventoryToolbar label="Booleans" search={search} total={pagination.total} onSearch={onSearch} />
      {rows.length === 0 ? <p>{search ? "No matching booleans." : "No observed booleans in the selected scope."}</p> : <div className="pf-v6-c-table__responsive-wrapper">
        <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label="Boolean inventory rows">
          <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
              <th className="pf-v6-c-table__th" scope="col">Boolean</th><th className="pf-v6-c-table__th" scope="col">{data.booleans?.selected_policy_identity ? "Cohort state" : "Fleet state"}</th>{referenceAvailable && <th className="pf-v6-c-table__th" scope="col">Reference</th>}
          </tr></thead>
          <tbody className="pf-v6-c-table__tbody">
            {rows.map((row) => (
              <tr className="pf-v6-c-table__tr" key={row.name}>
                <td className="pf-v6-c-table__td" data-label="Boolean">{row.name}<div className="pf-v6-u-color-200">{("catalog" in row ? row.catalog?.description : row.description) ?? ""}</div></td>
                <td className="pf-v6-c-table__td" data-label={data.booleans?.selected_policy_identity ? "Cohort state" : "Fleet state"}><BooleanStateSummary counts={"catalog" in row ? row.counts : { on: row.counts.enabled, off: row.counts.disabled, ...row.counts }} /></td>
                {referenceAvailable && <td className="pf-v6-c-table__td" data-label="Reference">{"catalog" in row ? <>{row.catalog?.default === true ? "Default on" : row.catalog?.default === false ? "Default off" : row.catalog_status} · {row.counts.reference_match} match · {row.counts.reference_difference} differ</> : "—"}</td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>}
      <ListPagination label="Boolean inventory" pagination={pagination} onPage={onPage} onPageSize={onPageSize} />
    </CardBody></Card>
  );
}

function PortInventory({ data, search, onSearch, pagination, onPage, onPageSize, protocol, onProtocolChange }: { data: ConfigurationFleetResponse; protocol: string; onProtocolChange: (protocol: string) => void } & ListProps) {
  const family = data.ports;
  const overlay = family?.catalog_overlay;
  const observed = overlay?.observed;
  const hasReference = overlay?.catalog.available === true;
  const mappings = overlay
    ? observed?.observed_mappings ?? []
    : (family?.rows ?? []).flatMap((row) => (row.ports ?? []).map((range) => ({
      protocol: row.protocol ?? "unknown", type: row.type ?? null, start: range.start, end: range.end,
      provenance: range.provenance, inventory_status: row.inventory_status, host_count: row.host_ids.length
    })));
  const rows = hasReference ? observed?.segments ?? [] : mappings;
  return <Card aria-label="Port inventory"><CardBody>
    <Title headingLevel="h2" size="lg">Ports</Title>
    <InventoryToolbar label="Ports" search={search} total={pagination.total} onSearch={onSearch} protocol={protocol} onProtocolChange={onProtocolChange} />
    {rows.length === 0 ? <p>{search ? "No matching port mappings." : "No observed port mappings."}</p> : <div className="pf-v6-c-table__responsive-wrapper">
      <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label="Port inventory rows">
        <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
          <th className="pf-v6-c-table__th" scope="col">Port</th>
          {hasReference ? <><th className="pf-v6-c-table__th" scope="col">Observed type</th><th className="pf-v6-c-table__th" scope="col">Source</th><th className="pf-v6-c-table__th" scope="col">Catalog type</th><th className="pf-v6-c-table__th" scope="col">Comparison</th><th className="pf-v6-c-table__th" scope="col">Hosts</th></> : <><th className="pf-v6-c-table__th" scope="col">SELinux type</th><th className="pf-v6-c-table__th" scope="col">Source</th><th className="pf-v6-c-table__th" scope="col">Hosts</th></>}
        </tr></thead>
        <tbody className="pf-v6-c-table__tbody">
          {hasReference ? observed?.segments.map((row, index) => <tr className="pf-v6-c-table__tr" key={`${row.protocol}-${row.start}-${row.end}-${index}`}>
            <td className="pf-v6-c-table__td" data-label="Port">{row.protocol}/{row.start === row.end ? row.start : `${row.start}-${row.end}`}</td>
            <td className="pf-v6-c-table__td" data-label="Observed types">{row.observed_types?.filter(Boolean).join(", ") || "—"}</td>
            <td className="pf-v6-c-table__td" data-label="Source">{portSourceLabel(row.local_classification)}</td>
            <td className="pf-v6-c-table__td" data-label="Catalog type">{row.catalog_types?.filter(Boolean).join(", ") || "—"}</td>
            <td className="pf-v6-c-table__td" data-label="Comparison"><Label color={row.relation === "matching_effective_type" ? "green" : row.relation === "comparison_unknown" ? "orange" : "red"} isCompact>{portRelationLabel(row.relation)}</Label></td>
            <td className="pf-v6-c-table__td" data-label="Hosts">{row.host_count ?? 1} host{(row.host_count ?? 1) === 1 ? "" : "s"}</td>
          </tr>) : mappings.map((row, index) => <tr className="pf-v6-c-table__tr" key={`${row.protocol}-${row.start}-${row.end}-${index}`}>
            <td className="pf-v6-c-table__td" data-label="Port">{row.protocol}/{row.start === row.end ? row.start : `${row.start}-${row.end}`}</td>
            <td className="pf-v6-c-table__td" data-label="SELinux type">{row.type ?? "—"}</td>
            <td className="pf-v6-c-table__td" data-label="Source">{Array.isArray(row.provenance) ? [...new Set(row.provenance.filter(Boolean))].map((value) => portSourceLabel(value)).join(", ") || "Not recorded" : portSourceLabel(row.provenance)}</td>
            <td className="pf-v6-c-table__td" data-label="Hosts">{row.host_count} host{row.host_count === 1 ? "" : "s"}{row.inventory_status === "partial" && <> · <Label color="orange" isCompact>Partial inventory</Label></>}</td>
          </tr>)}
        </tbody>
      </table>
    </div>}
    <ListPagination label="Port inventory" pagination={pagination} onPage={onPage} onPageSize={onPageSize} />
  </CardBody></Card>;
}

function RowFamily({ data, family, search, onSearch, pagination, onPage, onPageSize }: { data: ConfigurationFleetResponse; family: ConfigurationFamily } & ListProps) {
  const rows = data.rows ?? [];
  const label = family === "file_contexts" ? "File contexts" : "Modules";
  return (
    <Card aria-label={`${label} inventory`}><CardBody>
      <Title headingLevel="h2" size="lg">{label}</Title>
      <p>{data.observed_host_count ?? 0} host{data.observed_host_count === 1 ? "" : "s"} with fresh observations</p>
      {family === "file_contexts" && <p>Source is based on the effective and local custom file-context listings.</p>}
      <InventoryToolbar label={label} search={search} total={pagination.total} onSearch={onSearch} />
      {rows.length === 0 ? <p>{search ? `No matching ${label.toLowerCase()}.` : "No fresh observations."}</p> : <div className="pf-v6-c-table__responsive-wrapper">
        <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label={`${family} rows`}>
          <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
            <th className="pf-v6-c-table__th" scope="col">{family === "file_contexts" ? "Path pattern" : "Module"}</th>
            {family === "modules" && <th className="pf-v6-c-table__th" scope="col">Priority</th>}
            <th className="pf-v6-c-table__th" scope="col">Source</th><th className="pf-v6-c-table__th" scope="col">Hosts</th>
          </tr></thead>
          <tbody className="pf-v6-c-table__tbody">
            {rows.map((row, index) => (
              <tr className="pf-v6-c-table__tr" key={index}>
                <td className="pf-v6-c-table__td" data-label={family === "file_contexts" ? "Path pattern" : "Module"}>
                {family === "file_contexts" ? (
                  <>
                    {row.pattern}
                    <br />
                    <small>
                      {row.file_type} · {row.context}
                    </small>
                  </>
                ) : (
                  <>
                    {row.name}
                    {row.version && <small className="pf-v6-u-ml-sm">v{row.version}</small>}
                    <br />
                    <small>{row.source_package ?? ""}</small>
                  </>
                )}
                </td>
                {family === "modules" && <td className="pf-v6-c-table__td" data-label="Priority">{row.priority ?? "—"}</td>}
                <td className="pf-v6-c-table__td" data-label="Source">{[...new Set(row.provenance.filter(Boolean))].map((value) => inventorySourceLabel(value)).join(", ") || "Not recorded"}</td>
                <td className="pf-v6-c-table__td" data-label="Hosts">
                {row.host_ids.length} host{row.host_ids.length === 1 ? "" : "s"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>}
      <ListPagination label={label} pagination={pagination} onPage={onPage} onPageSize={onPageSize} />
    </CardBody></Card>
  );
}

function CohortSelect({ data, policyIdentity, onSelect }: { data: ConfigurationFleetResponse; policyIdentity: string | null; onSelect: (identity: string | null) => void }) {
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const cohorts = data.booleans?.cohort_details ?? data.ports?.cohort_details ?? [];
  const selected = policyIdentity ?? "all";
  const active = cohorts.find((cohort) => cohort.policy_identity === selected);
  const visibleCohorts = cohorts.filter((cohort) => cohortLabel(cohort).toLowerCase().includes(filter.toLowerCase()));
  return (
    <Select
      variant={cohorts.length > 5 ? "typeahead" : "default"}
      isOpen={open}
      selected={selected}
      onOpenChange={setOpen}
      onSelect={(_event, value) => {
        setOpen(false);
        setFilter("");
        onSelect(value === "all" ? null : (value as string));
      }}
      toggle={(toggleRef) => (
        cohorts.length > 5
          ? <SearchInput ref={toggleRef} aria-label="Search policy cohorts" placeholder="Search policy cohorts" value={open ? filter : selected === "all" ? "All hosts" : active ? cohortOption(active) : "Selected cohort"} onFocus={() => setOpen(true)} onChange={(_event, value) => { setFilter(value); setOpen(true); }} onClear={() => setFilter("")} />
          : <Button variant="secondary" isExpanded={open} onClick={() => setOpen(!open)} ref={toggleRef} aria-label={`Policy cohort: ${selected === "all" ? "All hosts" : active ? cohortOption(active) : "Selected cohort"}`}>Policy cohort: {selected === "all" ? "All hosts" : active ? cohortOption(active) : "Selected cohort"}</Button>
      )}
      className="configuration-cohort-select"
    >
      <SelectOption value="all">All hosts</SelectOption>
      {visibleCohorts.map((cohort) => (
        <SelectOption key={cohort.policy_identity} value={cohort.policy_identity}>
          {cohortOption(cohort)}
        </SelectOption>
      ))}
    </Select>
  );
}

function cohortLabel(cohort: ConfigurationPolicyCohort): string {
  if (cohort.platforms.length !== 1) return `Mixed platforms (${cohort.platforms.length} groups)`;
  const platform = cohort.platforms[0];
  const major = platform.os_version?.split(".")[0];
  return [ [osDisplayName(platform.os_id), major].filter(Boolean).join(" "), platform.policy_type, platform.architecture ].filter(Boolean).join(" · ") || "Platform details unavailable";
}

function cohortOption(cohort: ConfigurationPolicyCohort): string {
  return `${cohortLabel(cohort)} — ${cohort.host_count} host${cohort.host_count === 1 ? "" : "s"}`;
}

function latestObservation(value: string | null): string {
  if (!value) return "Latest observation time unavailable";
  const minutes = Math.max(0, Math.floor((Date.now() - Date.parse(value)) / 60_000));
  const relative = minutes < 60 ? `${minutes} min ago` : minutes < 1440 ? `${Math.floor(minutes / 60)} hr ago` : `${Math.floor(minutes / 1440)} days ago`;
  const exact = new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(value));
  return `Latest observation: ${relative} (${exact} UTC)`;
}

export function Configuration() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const family = (FAMILIES.some((entry) => entry.value === searchParams.get("family")) ? searchParams.get("family") : "booleans") as ConfigurationFamily;
  const policyIdentity = searchParams.get("policy_identity");
  const page = Math.max(1, Number(searchParams.get("page") || 1));
  const limit = pageSize(searchParams.get("limit"));
  const search = searchParams.get("q") ?? "";
  const protocol = searchParams.get("protocol") ?? "all";
  const hasCohort = family === "booleans" || family === "ports";

  const configQuery = useQuery({
    queryKey: ["configuration", family, policyIdentity ?? "", page, limit, search, protocol],
    queryFn: () => fetchConfiguration(family, { policyIdentity: policyIdentity ?? undefined, page, limit, q: search, protocol: family === "ports" && protocol !== "all" ? protocol as "tcp" | "udp" : undefined }),
    placeholderData: (previous) => previous?.family === family && (!hasCohort || (previous.booleans ?? previous.ports)?.selected_policy_identity === policyIdentity) ? previous : undefined,
  });

  const setParams = (updates: Record<string, string | null>) => {
    setSearchParams((previous) => {
      const next = new URLSearchParams(previous);
      for (const [key, value] of Object.entries(updates)) {
        if (value === null || value === "") {
          next.delete(key);
        } else {
          next.set(key, value);
        }
      }
      return next;
    });
  };

  const data = configQuery.data;
  const cohortFamily = data?.booleans ?? data?.ports;
  const selectedHostCount = Object.values(cohortFamily?.coverage ?? {}).reduce((sum, count) => sum + count, 0);
  const scoped = Boolean(cohortFamily?.selected_policy_identity);
  const cohortDetails = data?.booleans?.cohort_details ?? data?.ports?.cohort_details ?? [];
  const activeCohort = cohortDetails.find((cohort) => cohort.policy_identity === cohortFamily?.selected_policy_identity);
  const selection = data?.booleans?.selection ?? data?.ports?.selection;
  const catalog = data?.booleans?.catalog ?? data?.ports?.catalog;
  const missingCatalog = selection?.status === "absent" && selection.reason === "no_matching_candidates";

  const setPage = (value: number) => setParams({ page: value > 1 ? String(value) : null });
  const setPageSize = (value: number) => setParams({ limit: String(value), page: null });
  const setSearch = (value: string) => setParams({ q: value || null, page: null });
  const setProtocol = (value: string) => setParams({ protocol: value === "all" ? null : value, page: null });

  return (
    <div className="app-resource-page">
      <header className="app-resource-header app-page-header">
        <div>
          <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">SELinux configuration</Title>
          <p className="pf-v6-u-color-200">Observed fleet settings and reference comparisons where available.</p>
        </div>
        {missingCatalog && <Button variant="secondary" onClick={() => navigate("/catalogs/import")}>Import catalog</Button>}
      </header>

      {configQuery.isPending ? (
        <div aria-label="Loading configuration" style={{ padding: "var(--pf-v6-global--spacer--xl)" }}>
          <Spinner />
        </div>
      ) : configQuery.isError ? (
        <Alert variant="danger" title="Could not load configuration">
          {configQuery.error instanceof Error ? configQuery.error.message : "Unknown error"}
        </Alert>
      ) : (
        data && (
          <>
            {hasCohort && <Card className="pf-v6-u-mb-lg"><CardBody><Flex justifyContent={{ default: "justifyContentSpaceBetween" }} alignItems={{ default: "alignItemsCenter" }} flexWrap={{ default: "wrap" }} gap={{ default: "gapMd" }}>
              <FlexItem flex={{ default: "flex_1" }}>
                <Title headingLevel="h2" size="md">{scoped ? "Selected policy cohort" : "All hosts"}</Title>
                {scoped ? <>
                  {activeCohort && <p><strong>{cohortLabel(activeCohort)}</strong></p>}
                  <p>{selectedHostCount} of {data.hosts.total} monitored hosts selected</p>
                  {activeCohort && <p>{latestObservation(activeCohort.latest_observation_at)}</p>}
                  <p>{referenceLabel(catalog, selection)}</p>
                </> : <>
                  <p>{data.hosts.total} monitored hosts fleet-wide</p>
                  <p>Observed values across policy cohorts; matching names do not imply equivalent policies. Select a policy cohort for distribution-reference comparison.</p>
                </>}
                {catalog?.available && catalog.distribution_catalog_revision_id && <p><Link to={`/catalogs/${catalog.distribution_catalog_revision_id}`}>View distribution reference</Link></p>}
              </FlexItem>
              {(cohortDetails.length > 0 || policyIdentity) && <FlexItem><CohortSelect data={data} policyIdentity={policyIdentity} onSelect={(identity) => setParams({ policy_identity: identity, page: null })} /></FlexItem>}
            </Flex></CardBody></Card>}
            <Tabs
              activeKey={family}
              onSelect={(_event, key) => setParams({ family: String(key), policy_identity: null, page: null, q: null, protocol: null })}
              aria-label="Configuration families"
              className="pf-v6-u-mb-lg"
            >
              {FAMILIES.map((entry) => (
                <Tab key={entry.value} eventKey={entry.value} title={<TabTitleText>{entry.label}</TabTitleText>} />
              ))}
            </Tabs>
            {family === "booleans" && data.booleans && (
              <>
                <CoverageCards family="booleans" items={BOOLEAN_COVERAGE} counts={data.booleans.coverage} scoped={scoped} />
                <BooleanInventory data={data} search={search} onSearch={setSearch} pagination={data.booleans.pagination} onPage={setPage} onPageSize={setPageSize} />
              </>
            )}
            {family === "ports" && data.ports && (
              <>
                <CoverageCards family="ports" items={PORT_COVERAGE} counts={data.ports.coverage} scoped={scoped} />
                <PortInventory data={data} search={search} onSearch={setSearch} pagination={data.ports.pagination} onPage={setPage} onPageSize={setPageSize} protocol={protocol} onProtocolChange={setProtocol} />
              </>
            )}
            {(family === "file_contexts" || family === "modules") && <RowFamily data={data} family={family} search={search} onSearch={setSearch} pagination={data.pagination ?? { total: 0, page: 1, page_size: limit }} onPage={setPage} onPageSize={setPageSize} />}
          </>
        )
      )}
    </div>
  );
}
