import { Alert, Button, Card, CardBody, EmptyState, EmptyStateBody, Form, FormGroup, FormSelect, FormSelectOption, Label, MenuFooter, MenuToggle, Pagination, SearchInput, Select, SelectList, SelectOption, Spinner, Stack, TextInput, Title, ToggleGroup, ToggleGroupItem, Toolbar, ToolbarContent, ToolbarGroup, ToolbarItem } from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useQuery } from "@tanstack/react-query";
import { useDeferredValue, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { fetchSelinuxLog, searchLogHosts } from "../api/selinuxLog";
import type { SelinuxLogItem } from "../api/generated/types.gen";
import { formatUtc } from "../components/OccurrenceEvidence";
import { administrativeDescription, SelinuxActivitySummary } from "../components/SelinuxActivitySummary";
import { PAGE_SIZES, pageSize } from "../pagination";

const CATEGORIES = [{ value: "all", label: "All" }, { value: "avc", label: "AVCs" }, { value: "administrative", label: "Administrative activity" }];
const PRESETS = [{ value: "1", label: "Last hour" }, { value: "24", label: "Last 24 hours" }, { value: "168", label: "Last 7 days" }];

function preset(hours: number) {
  const end = new Date();
  return { start: new Date(end.getTime() - hours * 3_600_000).toISOString(), end: end.toISOString(), range: String(hours) };
}

function CustomRange({ start, end, apply }: { start: string; end: string; apply: (start: string, end: string) => void }) {
  const [from, setFrom] = useState(start);
  const [until, setUntil] = useState(end);
  return <Form onSubmit={(event) => { event.preventDefault(); apply(from, until); }}>
    <FormGroup label="Start (UTC, inclusive)" fieldId="log-start" isRequired>
      <TextInput id="log-start" value={from} onChange={(_event, value) => setFrom(value)} isRequired placeholder="2026-10-13T00:00:00.000000Z" />
    </FormGroup>
    <FormGroup label="End (UTC, exclusive)" fieldId="log-end" isRequired>
      <TextInput id="log-end" value={until} onChange={(_event, value) => setUntil(value)} isRequired placeholder="2026-10-14T00:00:00.000000Z" />
    </FormGroup>
    <Button type="submit" variant="secondary">Apply interval</Button>
  </Form>;
}

function LogSummary({ item }: { item: SelinuxLogItem }) {
  if (item.administrative) return <SelinuxActivitySummary activity={item.administrative} />;
  const avc = item.avc;
  if (!avc) return "Unknown AVC facts";
  return <>
    <code>{avc.source_type ?? "unknown domain"}</code> · {avc.permissions.join(", ") || "unknown permissions"} → <code>{avc.target_type ?? "unknown target"}</code> · {avc.target_class ?? "unknown class"}
    {avc.target_paths.length ? <div><code>{avc.target_paths.join("; ")}</code></div> : null}
    <div className="pf-v6-u-color-200">{avc.permissive === true ? "Non-enforced (AVC permissive=1)" : avc.permissive === false ? "Enforced (AVC permissive=0)" : "Enforcement unknown"}{avc.status !== "ok" ? " · Ungrouped occurrence" : ""}</div>
  </>;
}

export function GlobalLog() {
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const [hostMenuOpen, setHostMenuOpen] = useState(false);
  const customOpen = params.get("range") === "custom" || (!params.has("range") && (params.has("start") || params.has("end")));
  const hostSearch = useDeferredValue(search);
  const hostIds = [...new Set([...params.getAll("host_ids[]"), ...params.getAll("host_id")])].sort();
  const category = params.get("category") ?? "all";
  const requestedPage = Number(params.get("page") ?? 1);
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
  const perPage = pageSize(params.get("limit"));
  const timeFiltered = params.has("start") || params.has("end");
  const activeFilters = category !== "all" || hostIds.length > 0 || timeFiltered;
  const apiParams = new URLSearchParams();
  for (const key of ["category", "start", "end"]) {
    const value = params.get(key);
    if (value !== null) apiParams.set(key, value);
  }
  for (const id of hostIds) apiParams.append("host_ids[]", id);
  apiParams.set("page", String(page));
  apiParams.set("limit", String(perPage));
  const log = useQuery({ queryKey: ["selinux-log", apiParams.toString()], queryFn: () => fetchSelinuxLog(apiParams), refetchOnWindowFocus: false, refetchOnReconnect: false });
  const hosts = useQuery({ queryKey: ["log-hosts", hostSearch], queryFn: () => searchLogHosts(hostSearch) });
  const selectedHosts = useQuery({ queryKey: ["log-hosts-selected", hostIds], queryFn: () => searchLogHosts("", hostIds), enabled: hostIds.length > 0 });
  const options = new Map((hosts.data?.hosts ?? []).map((host) => [String(host.id), host]));
  for (const host of selectedHosts.data?.hosts ?? []) options.set(String(host.id), host);

  function update(values: Record<string, string | null>, pagination = false) {
    const next = new URLSearchParams(params);
    next.delete("before");
    if (!pagination) next.delete("page");
    for (const [key, value] of Object.entries(values)) {
      if (value === null || value === "") next.delete(key);
      else next.set(key, value);
    }
    setParams(next);
  }

  function selectHosts(ids: string[]) {
    const next = new URLSearchParams(params);
    for (const key of ["host_id", "host_ids[]", "page", "before"]) next.delete(key);
    for (const id of ids) next.append("host_ids[]", id);
    setParams(next);
  }

  return <div className="app-resource-page">
    <header className="app-resource-header">
      <Title headingLevel="h1" size="2xl">Global log</Title>
      <p className="pf-v6-u-color-200">Observed SELinux AVCs and administrative activity across monitored servers.</p>
    </header>
    <Stack hasGutter>
    <section aria-label="Global log controls">
    <Toolbar aria-label="Global log filters" hasNoPadding>
      <ToolbarContent>
        <ToolbarItem><ToggleGroup aria-label="Activity type">
          {CATEGORIES.map((entry) => <ToggleGroupItem key={entry.value} text={entry.label} buttonId={`log-type-${entry.value}`} isSelected={category === entry.value} onChange={() => update({ category: entry.value === "all" ? null : entry.value })} />)}
        </ToggleGroup></ToolbarItem>
      </ToolbarContent>
      <ToolbarContent>
        <ToolbarGroup gap={{ default: "gapMd" }} rowWrap={{ default: "wrap" }}>
        <ToolbarItem><SearchInput aria-label="Search hosts" placeholder="Search hostname" value={search} onChange={(_event, value) => setSearch(value)} onClear={() => setSearch("")} /></ToolbarItem>
        <ToolbarItem><Select role="menu" aria-label="Host options" isOpen={hostMenuOpen} selected={hostIds} onOpenChange={setHostMenuOpen} shouldFocusToggleOnSelect={false}
          onSelect={(_event, value) => {
            if (value === "all") selectHosts([]);
            else if (typeof value === "string") selectHosts(hostIds.includes(value) ? hostIds.filter((id) => id !== value) : [...hostIds, value]);
          }}
          toggle={(ref) => <MenuToggle ref={ref} aria-label="Host filter" isExpanded={hostMenuOpen} onClick={() => setHostMenuOpen(!hostMenuOpen)}>{hostIds.length ? `${hostIds.length} host${hostIds.length === 1 ? "" : "s"} selected` : "All hosts"}</MenuToggle>}
          maxMenuHeight="300px" isScrollable>
          <SelectList>
            <SelectOption value="all" isSelected={hostIds.length === 0}>All hosts</SelectOption>
            {[...options.values()].map((host) => <SelectOption key={host.id} value={String(host.id)} hasCheckbox isSelected={hostIds.includes(String(host.id))} isDisabled={hostIds.length >= 50 && !hostIds.includes(String(host.id))}>{host.hostname ?? `Host ${host.id}`}</SelectOption>)}
            {hostIds.filter((id) => !options.has(id)).map((id) => <SelectOption key={id} value={id} hasCheckbox isSelected>Host {id}</SelectOption>)}
          </SelectList>
          {hosts.data?.hosts.length === 50 ? <MenuFooter>Showing up to 50 matches. Refine hostname search for more.</MenuFooter> : null}
        </Select></ToolbarItem>
        <ToolbarItem><FormSelect aria-label="Time range" value={params.get("range") ?? (timeFiltered ? "custom" : "all")} onChange={(_event, value) => {
          if (value === "all") update({ range: null, start: null, end: null });
          else if (value === "custom") update({ range: "custom" });
          else update(preset(Number(value)));
        }}>
          {PRESETS.map((entry) => <FormSelectOption key={entry.value} value={entry.value} label={entry.label} />)}
          <FormSelectOption value="custom" label="Custom interval" />
          <FormSelectOption value="all" label="All retained time" />
        </FormSelect></ToolbarItem>
        </ToolbarGroup>
      </ToolbarContent>
    {customOpen ? <ToolbarContent><ToolbarItem><CustomRange key={`${params.get("start")}:${params.get("end")}`} start={params.get("start") ?? ""} end={params.get("end") ?? ""} apply={(start, end) => update({ start, end, range: "custom" })} /></ToolbarItem></ToolbarContent> : null}
    {activeFilters || search || customOpen ? <ToolbarContent aria-label="Active log filters">
      <ToolbarGroup gap={{ default: "gapSm" }} rowWrap={{ default: "wrap" }}>
      {category !== "all" ? <ToolbarItem variant="label-group"><Label closeBtnAriaLabel="Remove activity type filter" onClose={() => update({ category: null })}>Type: {CATEGORIES.find((entry) => entry.value === category)?.label ?? category}</Label></ToolbarItem> : null}
      {hostIds.map((id) => <ToolbarItem key={id} variant="label-group"><Label closeBtnAriaLabel={`Remove host ${options.get(id)?.hostname ?? id}`} onClose={() => selectHosts(hostIds.filter((value) => value !== id))}>Host: {options.get(id)?.hostname ?? id}</Label></ToolbarItem>)}
      {timeFiltered ? <ToolbarItem variant="label-group"><Label textMaxWidth="min(36ch, calc(100vw - 6rem))" closeBtnAriaLabel="Remove time filter" onClose={() => update({ range: null, start: null, end: null })}>{`${params.get("start") ?? "Unbounded"} → ${params.get("end") ?? "Unbounded"} (end exclusive)`}</Label></ToolbarItem> : null}
      <ToolbarItem><Button variant="link" onClick={() => { setSearch(""); setParams(new URLSearchParams()); }}>Clear filters</Button></ToolbarItem>
      </ToolbarGroup>
    </ToolbarContent> : null}
    </Toolbar>
    {hosts.isError || selectedHosts.isError ? <Alert isInline variant="warning" title="Could not load host options">{hosts.error?.message ?? selectedHosts.error?.message}</Alert> : null}
    </section>
    <Card component="section" className="resource-table-card" aria-label="Global log entries"><CardBody>
    <div className="table-section-heading">
      <Title headingLevel="h2" size="lg">Entries</Title>
      {log.data?.meta.total != null && !log.isError && <span className="pf-v6-u-color-200">{log.data.meta.total.toLocaleString("en-US")} entries</span>}
    </div>
    {log.isPending ? <Spinner aria-label="Loading global log" /> : log.isError ? <Alert variant="danger" isInline title="Could not load global log">{log.error.message}</Alert> : <>
      {log.data.items.length === 0 ? <EmptyState titleText={!activeFilters ? "No retained SELinux activity" : "No entries match this selection"}>
        <EmptyStateBody>Try another host or broaden the interval.</EmptyStateBody>
        {timeFiltered ? <Button variant="link" onClick={() => update({ range: null, start: null, end: null })}>Show all retained time</Button> : null}
      </EmptyState> : <Table role="table" aria-label="Global SELinux log" variant="compact" gridBreakPoint="grid-lg">
        <Thead><Tr><Th>Time</Th><Th>Host</Th><Th>Type</Th><Th>Summary</Th><Th>Origin</Th><Th>Details</Th></Tr></Thead>
        <Tbody>{log.data.items.map((item) => <Tr key={`${item.category}:${item.id}`}>
          <Td dataLabel="Time"><time dateTime={item.event_time} title={item.event_time}>{formatUtc(item.event_time)}</time></Td>
          <Td dataLabel="Host"><Link to={`/hosts/${item.host.id}`}>{item.host.hostname ?? `Host ${item.host.id}`}</Link></Td>
          <Td dataLabel="Type">{item.administrative ? administrativeDescription(item.administrative).typeLabel : "AVC"}</Td>
          <Td dataLabel="Summary" modifier="wrap"><LogSummary item={item} /></Td>
          <Td dataLabel="Origin" modifier="wrap">{item.category === "administrative" ? <>{item.actor?.login_uid != null ? `UID ${item.actor.login_uid}` : "Unknown user"} · <code>{item.actor?.command ?? item.actor?.executable ?? "Unknown command"}</code></> : <code>{item.avc?.command ?? item.avc?.executable ?? "Unknown process"}</code>}</Td>
          <Td dataLabel="Details"><Link to={item.category === "avc" ? `/hosts/${item.host.id}/occurrences/${item.id}` : `/hosts/${item.host.id}?selinux_activity=${item.id}#selinux-activity`}>View {item.category === "avc" ? "occurrence" : "activity"}</Link>{item.issue_id ? <div><Link to={`/issues/${item.issue_id}`}>Issue #{item.issue_id}</Link></div> : null}</Td>
        </Tr>)}</Tbody>
      </Table>}
      <div aria-label="Global log table navigation" className="table-pagination">
        <Pagination itemCount={log.data.meta.total ?? 0} page={log.data.meta.page ?? page} perPage={perPage}
          perPageOptions={PAGE_SIZES.map((value) => ({ title: String(value), value }))}
          titles={{ paginationAriaLabel: "Global log pagination" }} isDisabled={log.isFetching}
          onSetPage={(_event, value) => update({ page: String(value) }, true)}
          onPerPageSelect={(_event, value) => update({ limit: String(value), page: "1" }, true)} />
      </div>
    </>}
    </CardBody></Card>
    </Stack>
  </div>;
}
