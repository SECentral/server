import {
  Alert,
  Button,
  Card,
  CardBody,
  EmptyState,
  EmptyStateBody,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  Label,
  Pagination,
  Select,
  SelectOption,
  Spinner,
  Stack,
  TextInput,
  Title,
  ToggleGroup,
  ToggleGroupItem,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem
} from "@patternfly/react-core";
import { ExpandableRowContent, Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useQuery } from "@tanstack/react-query";
import { memo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { fetchIssues, fetchUngroupableEvents, type IssueListItem } from "../api/issues";
import { MetricCard } from "../components/MetricCard";
import { PAGE_SIZES } from "../pagination";

const ATTRIBUTE_FILTERS = [
  { key: "q", label: "Any field", placeholder: "Search source, target, path, host..." },
  { key: "source_type", label: "Source", placeholder: "Source" },
  { key: "target_type", label: "Target", placeholder: "Target" },
  { key: "permission", label: "Permission", placeholder: "Permission" },
  { key: "target_class", label: "Class", placeholder: "Class" },
  { key: "path", label: "Path", placeholder: "Path" },
  { key: "name", label: "Object name", placeholder: "Object name" },
  { key: "target", label: "Any target", placeholder: "Any target" },
  { key: "os_id", label: "OS", placeholder: "OS" },
  { key: "policy_version", label: "Policy version", placeholder: "Policy version" }
] as const;

const STATUS_OPTIONS = [
  { value: "open", label: "Open + regressed" },
  { value: "all", label: "All statuses" },
  { value: "resolved", label: "Resolved" },
  { value: "ignored", label: "Ignored" },
  { value: "regressed", label: "Regressed only" }
] as const;

const STATUS_STATUS: Record<string, "info" | "success" | "warning"> = {
  open: "info",
  resolved: "success",
  regressed: "warning"
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

function formatUtc(iso: string): string {
  return `${new Date(iso).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

const IssueRow = memo(function IssueRow({ issue, isExpanded, onExpand }: {
  issue: IssueListItem;
  isExpanded: boolean;
  onExpand: (id: number | null) => void;
}) {
  const visibleHosts = issue.hosts.slice(0, 3);
  return (
    <Tbody isExpanded={isExpanded}>
      <Tr isContentExpanded={isExpanded}>
        <Td width={40} dataLabel="Issue" modifier="wrap">
          <a className="issue-primary-link" href={`/issues/${issue.id}`}>
            <span><code>{issue.source_type}</code><span aria-hidden="true"> → </span><code>{issue.target_type}</code></span>
          </a>
          <div className="issue-secondary-line pf-v6-u-color-200"><code>{issue.target_class}</code> · {issue.permissions.join(", ")}{(issue.signatures_count ?? 0) > 1 && ` · ${issue.signatures_count} signatures`}</div>
        </Td>
        <Td width={10} dataLabel="Hosts" modifier="fitContent" className="pf-v6-u-text-align-right"><strong>{issue.hosts_count}</strong></Td>
        <Td width={10} dataLabel="Occurrences" modifier="fitContent" className="pf-v6-u-text-align-right"><strong>{issue.occurrences_count}</strong></Td>
        <Td width={15} dataLabel="Last seen" modifier="nowrap">
          <time dateTime={issue.last_seen_at} title={formatUtc(issue.last_seen_at)}>{timeAgo(issue.last_seen_at)} ago</time>
        </Td>
        <Td width={15} dataLabel="Status" modifier="fitContent">
          {issue.display_status === "ignored" ? (
            <Label color="grey" isCompact>{issue.display_status}</Label>
          ) : (
            <Label status={STATUS_STATUS[issue.display_status] ?? "info"} isCompact>{issue.display_status}</Label>
          )}
        </Td>
        <Td width={10} dataLabel="Details" hasAction>
          <Button
            variant="secondary"
            size="sm"
            aria-expanded={isExpanded}
            aria-controls={`issue-details-${issue.id}`}
            onClick={() => onExpand(isExpanded ? null : issue.id)}
          >
            {isExpanded ? "Hide details" : "Details"}
          </Button>
        </Td>
      </Tr>
      <Tr isExpanded={isExpanded} id={`issue-details-${issue.id}`}>
        <Td colSpan={6} dataLabel="Issue details">
          <ExpandableRowContent>
            <dl className="issue-expanded-details">
              <div>
                <dt>Affected hosts ({issue.hosts_count})</dt>
                <dd>
                  {visibleHosts.map((host, index) => (
                    <span key={host.id}>
                      {index > 0 && " · "}<a href={`/hosts?host_id=${host.id}`}>{host.hostname ?? `Host ${host.id}`}</a>
                    </span>
                  ))}
                  {issue.hosts.length > 3 && <span> · +{issue.hosts.length - 3} more</span>}
                </dd>
              </div>
              <div>
                <dt>Observed paths</dt>
                <dd>{issue.observed_paths.length > 0 ? issue.observed_paths.slice(0, 3).map((path, index) => (
                  <span key={path}>{index > 0 && ", "}<code>{path}</code></span>
                )) : "None recorded"}</dd>
              </div>
              <div><dt>First seen</dt><dd><time dateTime={issue.first_seen_at}>{formatUtc(issue.first_seen_at)}</time></dd></div>
              <div><dt>Last seen</dt><dd><time dateTime={issue.last_seen_at}>{formatUtc(issue.last_seen_at)}</time></dd></div>
            </dl>
            <div className="pf-v6-u-mt-md">
              <Button component="a" href={`/issues/${issue.id}`} variant="primary" size="sm">Investigate issue</Button>{" "}
              <Button component="a" href={`/issues/${issue.id}?tab=occurrences`} variant="secondary" size="sm">View AVC evidence</Button>
            </div>
          </ExpandableRowContent>
        </Td>
      </Tr>
    </Tbody>
  );
});

export function Issues() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [attribute, setAttribute] = useState<string>("q");
  const filterInput = useRef<HTMLInputElement>(null);
  const [hostMenuOpen, setHostMenuOpen] = useState(false);
  const [statusMenuOpen, setStatusMenuOpen] = useState(false);
  const [expandedIssue, setExpandedIssue] = useState<number | null>(null);

  const hostId = searchParams.get("host_id") ?? "";
  const status = searchParams.get("status") ?? "";
  const issuesKey = searchParams.toString();

  const issuesQuery = useQuery({
    queryKey: ["issues", issuesKey],
    queryFn: () => fetchIssues(searchParams)
  });
  const eventsQuery = useQuery({
    queryKey: ["ungroupable-events", hostId],
    queryFn: () => fetchUngroupableEvents(hostId || undefined)
  });

  const setParams = (updates: Record<string, string | null>) => {
    setExpandedIssue(null);
    const next = new URLSearchParams(searchParams);
    for (const [key, value] of Object.entries(updates)) {
      if (value === null || value === "") {
        next.delete(key);
      } else {
        next.set(key, value);
      }
    }
    if (!Object.entries(updates).some(([key]) => key === "page")) {
      next.delete("page");
    }
    setSearchParams(next);
  };

  const clearFilters = () => {
    if (filterInput.current) filterInput.current.value = "";
    setExpandedIssue(null);
    setSearchParams(new URLSearchParams());
  };

  const data = issuesQuery.data;
  const issues = data?.issues ?? [];
  const events = eventsQuery.data?.events ?? [];
  const selectedHost = data?.host_options.find((host) => String(host.id) === hostId);
  const selectedHostLabel = selectedHost ? (selectedHost.hostname ?? `Host ${selectedHost.id}`) : hostId ? `Host ${hostId}` : "All servers";
  const selectedStatusLabel = STATUS_OPTIONS.find((option) => option.value === status)?.label ?? STATUS_OPTIONS[0].label;

  const hasFilters = [...searchParams.keys()].some((key) => !["page", "limit"].includes(key));
  const selectedAttribute = ATTRIBUTE_FILTERS.find((filter) => filter.key === attribute)!;
  const activeAttributes = ATTRIBUTE_FILTERS.filter((filter) => searchParams.get(filter.key));
  const newOnly = ["1", "true"].includes(searchParams.get("new") ?? "");
  const multipleHosts = ["1", "true"].includes(searchParams.get("multiple_hosts") ?? "");

  return (
    <div className="app-resource-page">
      <header className="app-resource-header">
        <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">SELinux issues</Title>
        <p className="pf-v6-u-color-200">Grouped SELinux denials across your monitored infrastructure.</p>
      </header>

      <Stack hasGutter>
      {(data || eventsQuery.data) && <Grid hasGutter aria-label="Issue summary">
        {data && <GridItem sm={12} md={6}><MetricCard label="Regressed issues" value={data.summary.regressed_count} detail="Across the fleet" href="/issues?status=regressed" /></GridItem>}
        {eventsQuery.data && !eventsQuery.isError && <GridItem sm={12} md={6}><MetricCard label="Unclassified events" value={eventsQuery.data.total_count} detail={hostId ? "On the selected server" : "Across the fleet"} href={events.length > 0 ? "#unclassified-events" : undefined} /></GridItem>}
      </Grid>}

      <form onSubmit={(event) => { event.preventDefault(); setParams({ [attribute]: filterInput.current?.value || null }); }}>
      <Toolbar id="issues-filter-toolbar" aria-label="Issue filters" hasNoPadding>
        <ToolbarContent>
          <ToolbarGroup gap={{ default: "gapMd" }} rowWrap={{ default: "wrap" }}>
          <ToolbarItem>
            <FormSelect aria-label="Filter attribute" value={attribute} onChange={(_event, value) => { setAttribute(value); if (filterInput.current) filterInput.current.value = searchParams.get(value) ?? ""; }}>
              {ATTRIBUTE_FILTERS.map((filter) => <FormSelectOption key={filter.key} value={filter.key} label={filter.label} />)}
            </FormSelect>
          </ToolbarItem>
          <ToolbarItem><TextInput ref={filterInput} aria-label="Filter value" placeholder={selectedAttribute.placeholder} defaultValue={searchParams.get("q") ?? ""} /></ToolbarItem>
          <ToolbarItem><Button type="submit" variant="secondary">Apply filter</Button>
          </ToolbarItem>
          <ToolbarItem>
            <Select
              isOpen={hostMenuOpen}
              selected={selectedHostLabel}
              onOpenChange={(isOpen) => setHostMenuOpen(isOpen)}
              onSelect={(_event, value) => {
                setHostMenuOpen(false);
                setParams({ host_id: value === "All servers" ? null : value });
              }}
              toggle={(toggleRef) => (
                <Button
                  variant="secondary"
                  isExpanded={hostMenuOpen}
                  onClick={() => setHostMenuOpen(!hostMenuOpen)}
                  ref={toggleRef}
                  aria-label="Server filter"
                >
                  {selectedHostLabel}
                </Button>
              )}
            >
              <SelectOption value="All servers">All servers</SelectOption>
              {(data?.host_options ?? []).map((host) => (
                <SelectOption key={host.id} value={String(host.id)}>
                  {host.hostname ?? `Host ${host.id}`}
                </SelectOption>
              ))}
            </Select>
          </ToolbarItem>
          <ToolbarItem>
            <Select
              isOpen={statusMenuOpen}
              selected={selectedStatusLabel}
              onOpenChange={(isOpen) => setStatusMenuOpen(isOpen)}
              onSelect={(_event, value) => {
                setStatusMenuOpen(false);
                const option = STATUS_OPTIONS.find((option) => option.label === value);
                setParams({ status: option?.value === "open" ? null : option?.value ?? null });
              }}
              toggle={(toggleRef) => (
                <Button
                  variant="secondary"
                  isExpanded={statusMenuOpen}
                  onClick={() => setStatusMenuOpen(!statusMenuOpen)}
                  ref={toggleRef}
                  aria-label="Status filter"
                >
                  {selectedStatusLabel}
                </Button>
              )}
            >
              {STATUS_OPTIONS.map((option) => (
                <SelectOption key={option.value} value={option.label}>
                  {option.label}
                </SelectOption>
              ))}
            </Select>
          </ToolbarItem>
          <ToolbarItem>
            <ToggleGroup aria-label="Quick issue filters">
              <ToggleGroupItem text="New" buttonId="issues-new" isSelected={newOnly} onChange={() => setParams({ new: newOnly ? null : "1" })} />
              <ToggleGroupItem text="Multiple hosts" buttonId="issues-multiple-hosts" isSelected={multipleHosts} onChange={() => setParams({ multiple_hosts: multipleHosts ? null : "1" })} />
            </ToggleGroup>
          </ToolbarItem>
          </ToolbarGroup>
        </ToolbarContent>
        {hasFilters && <ToolbarContent aria-label="Active issue filters">
          <ToolbarGroup gap={{ default: "gapSm" }} rowWrap={{ default: "wrap" }}>
          {activeAttributes.map((filter) => <ToolbarItem key={filter.key}><Label isCompact closeBtnAriaLabel={`Remove ${filter.label} filter`} onClose={() => { setParams({ [filter.key]: null }); if (attribute === filter.key && filterInput.current) filterInput.current.value = ""; }}>{filter.label}: {searchParams.get(filter.key)}</Label></ToolbarItem>)}
          {hostId && <ToolbarItem><Label isCompact closeBtnAriaLabel="Remove server filter" onClose={() => setParams({ host_id: null })}>Server: {selectedHostLabel}</Label></ToolbarItem>}
          {status && <ToolbarItem><Label isCompact closeBtnAriaLabel="Remove status filter" onClose={() => setParams({ status: null })}>Status: {selectedStatusLabel}</Label></ToolbarItem>}
          {newOnly && <ToolbarItem><Label isCompact closeBtnAriaLabel="Remove new filter" onClose={() => setParams({ new: null })}>New</Label></ToolbarItem>}
          {multipleHosts && <ToolbarItem><Label isCompact closeBtnAriaLabel="Remove multiple hosts filter" onClose={() => setParams({ multiple_hosts: null })}>Multiple hosts</Label></ToolbarItem>}
          <ToolbarItem><Button variant="link" onClick={clearFilters}>Reset filters</Button></ToolbarItem>
          </ToolbarGroup>
        </ToolbarContent>}
      </Toolbar>
      </form>

      <Card component="section" aria-label="Grouped issues" className="resource-table-card"><CardBody>
      <div className="table-section-heading">
        <Title headingLevel="h2" size="lg">Grouped issues</Title>
        {data && !issuesQuery.isError && <span className="pf-v6-u-color-200">{data.meta.total} result{data.meta.total === 1 ? "" : "s"}</span>}
      </div>
      {issuesQuery.isPending ? (
        <div aria-label="Loading issues" style={{ padding: "var(--pf-v6-global--spacer--xl)" }}>
          <Spinner />
        </div>
      ) : issuesQuery.isError ? (
        <Alert variant="danger" title="Could not load issues">
          {issuesQuery.error instanceof Error ? issuesQuery.error.message : "Unknown error"}
        </Alert>
      ) : issues.length > 0 && data ? (
        <>
              <Table aria-label="Grouped issues" variant="compact" gridBreakPoint="grid-lg" isExpandable>
                <Thead>
                  <Tr>
                    <Th width={40}>Issue</Th>
                    <Th width={10} className="pf-v6-u-text-align-right">Hosts</Th>
                    <Th width={10} className="pf-v6-u-text-align-right">Occurrences</Th>
                    <Th width={15}>Last seen</Th>
                    <Th width={15}>Status</Th>
                    <Th width={10} screenReaderText="Actions" />
                  </Tr>
                </Thead>
                {issues.map((issue) => <IssueRow key={issue.id} issue={issue} isExpanded={expandedIssue === issue.id} onExpand={setExpandedIssue} />)}
              </Table>
                <div className="table-pagination">
                  <Pagination itemCount={data.meta.total} page={data.meta.page} perPage={data.meta.page_size}
                    perPageOptions={PAGE_SIZES.map((value) => ({ title: String(value), value }))}
                    titles={{ paginationAriaLabel: "Grouped issues pagination" }} isDisabled={issuesQuery.isFetching}
                    onSetPage={(_event, page) => setParams({ page: String(page) })}
                    onPerPageSelect={(_event, size) => setParams({ limit: String(size) })} />
                </div>
        </>
      ) : (
        <EmptyState titleText={hasFilters ? "No issues match the filters." : "No grouped issues to show."}>
          <EmptyStateBody>{hasFilters ? "Clear filters to widen the result set." : "No grouped issues were returned for this view."}</EmptyStateBody>
          {hasFilters && <Button variant="link" onClick={clearFilters}>Clear filters</Button>}
        </EmptyState>
      )}
      </CardBody></Card>

      {(eventsQuery.isPending || eventsQuery.isError || events.length > 0) && (
        <Card component="section" id="unclassified-events" aria-label="Unclassified events" className="resource-table-card"><CardBody>
          <div className="table-section-heading">
            <Title headingLevel="h2" size="lg">Unclassified events</Title>
            {eventsQuery.data && !eventsQuery.isError && <span className="pf-v6-u-color-200">{eventsQuery.data.total_count} event{eventsQuery.data.total_count === 1 ? "" : "s"}</span>}
          </div>
          <p className="pf-v6-u-mb-md">Evidence was retained, but it lacks the AVC fields needed for grouping. Only the server filter applies to this list.</p>
          {eventsQuery.isPending ? <Spinner aria-label="Loading unclassified events" />
            : eventsQuery.isError ? <Alert variant="warning" isInline title="Could not load unclassified events">{eventsQuery.error.message}</Alert>
            : <Table role="table" aria-label="Unclassified events" variant="compact" gridBreakPoint="grid-lg">
              <Thead><Tr><Th>Server</Th><Th>Missing fields</Th><Th>Occurred (UTC)</Th></Tr></Thead>
              <Tbody>{events.map((event) => <Tr key={event.id}>
                <Td dataLabel="Server"><a href={`/hosts?host_id=${event.host.id}`}>{event.host.hostname ?? `Host ${event.host.id}`}</a></Td>
                <Td dataLabel="Missing fields">{event.missing.join(", ") || "Not recorded"}</Td>
                <Td dataLabel="Occurred (UTC)"><time dateTime={event.occurred_at}>{formatUtc(event.occurred_at)}</time></Td>
              </Tr>)}</Tbody>
            </Table>}
        </CardBody></Card>
      )}
      </Stack>
    </div>
  );
}
