import {
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  EmptyState,
  EmptyStateBody,
  Grid,
  GridItem,
  Label,
  SearchInput,
  Select,
  SelectOption,
  Spinner,
  TextInput,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarFilter,
  ToolbarItem
} from "@patternfly/react-core";
import { ExpandableRowContent, Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { fetchIssues, fetchUngroupableEvents } from "../api/issues";

const TEXT_FILTERS = [
  { key: "source_type", label: "Source", placeholder: "Source" },
  { key: "target_type", label: "Target", placeholder: "Target" },
  { key: "permission", label: "Permission", placeholder: "Permission" },
  { key: "target_class", label: "Class", placeholder: "Class" }
] as const;

const MORE_FILTERS = [
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

export function Issues() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [moreOpen, setMoreOpen] = useState(false);
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

  const data = issuesQuery.data;
  const issues = data?.issues ?? [];
  const events = eventsQuery.data?.events ?? [];
  const selectedHost = data?.host_options.find((host) => String(host.id) === hostId);
  const selectedHostLabel = selectedHost ? (selectedHost.hostname ?? `Host ${selectedHost.id}`) : "All servers";
  const selectedStatusLabel = STATUS_OPTIONS.find((option) => option.value === status)?.label ?? STATUS_OPTIONS[0].label;

  const hasFilters = [...searchParams.keys()].some((key) => key !== "page");

  return (
    <div className="app-resource-page">
      <header className="app-resource-header">
        <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">SELinux issues</Title>
        <p className="pf-v6-u-color-200">Grouped SELinux denials across your monitored infrastructure.</p>
      </header>

      <Toolbar id="issues-filter-toolbar" className="pf-v6-u-mb-md">
        <ToolbarContent>
          <ToolbarItem>
            <SearchInput
              value={searchParams.get("q") ?? ""}
              onChange={(_event, value) => setParams({ q: value })}
              onClear={() => setParams({ q: null })}
              aria-label="Search issues"
              placeholder="Search source, target, path, host..."
            />
          </ToolbarItem>
          <ToolbarFilter
            categoryName="Server"
            labels={hostId ? [selectedHostLabel] : []}
            deleteLabelGroup={() => setParams({ host_id: null })}
          >
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
          </ToolbarFilter>
          <ToolbarFilter
            categoryName="Status"
            labels={status ? [selectedStatusLabel] : []}
            deleteLabelGroup={() => setParams({ status: null })}
          >
            <Select
              isOpen={statusMenuOpen}
              selected={selectedStatusLabel}
              onOpenChange={(isOpen) => setStatusMenuOpen(isOpen)}
              onSelect={(_event, value) => {
                setStatusMenuOpen(false);
                setParams({ status: value === "Open + regressed" ? null : value });
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
          </ToolbarFilter>
          {TEXT_FILTERS.map((filter) => (
            <ToolbarFilter
              key={filter.key}
              categoryName={filter.label}
              labels={searchParams.get(filter.key) ? [searchParams.get(filter.key)!] : []}
              deleteLabelGroup={() => setParams({ [filter.key]: null })}
            >
              <TextInput
                id={`issue-filter-${filter.key}`}
                value={searchParams.get(filter.key) ?? ""}
                onChange={(_event, value) => setParams({ [filter.key]: value })}
                placeholder={filter.placeholder}
                aria-label={filter.label}
              />
            </ToolbarFilter>
          ))}
          <ToolbarItem>
            <Button variant="link" isExpanded={moreOpen} onClick={() => setMoreOpen(!moreOpen)}>
              More filters
            </Button>
          </ToolbarItem>
          {moreOpen &&
            MORE_FILTERS.map((filter) => (
              <ToolbarFilter
                key={filter.key}
                categoryName={filter.label}
                labels={searchParams.get(filter.key) ? [searchParams.get(filter.key)!] : []}
                deleteLabelGroup={() => setParams({ [filter.key]: null })}
              >
                <TextInput
                  id={`issue-filter-${filter.key}`}
                  value={searchParams.get(filter.key) ?? ""}
                  onChange={(_event, value) => setParams({ [filter.key]: value })}
                  placeholder={filter.placeholder}
                  aria-label={filter.label}
                />
              </ToolbarFilter>
            ))}
        </ToolbarContent>
      </Toolbar>

      <div aria-label="Active filters and quick filters" className="pf-v6-u-mb-md">
        {searchParams.has("new") ? (
          <Label color="blue" isCompact onClose={() => setParams({ new: null })} className="pf-v6-u-mr-sm">New</Label>
        ) : (
          <Button variant="secondary" size="sm" className="pf-v6-u-mr-sm" onClick={() => setParams({ new: "1", status: status === "" || status === "all" ? null : status })}>New</Button>
        )}
        {searchParams.has("multiple_hosts") ? (
          <Label color="blue" isCompact onClose={() => setParams({ multiple_hosts: null })} className="pf-v6-u-mr-sm">Multiple hosts</Label>
        ) : (
          <Button variant="secondary" size="sm" className="pf-v6-u-mr-sm" onClick={() => setParams({ multiple_hosts: "1", status: status === "" || status === "all" ? null : status })}>Multiple hosts</Button>
        )}
        {hasFilters && (
          <Button variant="link" size="sm" onClick={() => setSearchParams(new URLSearchParams())}>
            Reset filters
          </Button>
        )}
      </div>

      {data && (
        <Grid hasGutter className="pf-v6-u-mb-lg">
          <GridItem sm={12} md={4}>
            <Card isCompact className="resource-summary-card">
              <CardTitle>Monitored servers</CardTitle>
              <CardBody>
                <Title headingLevel="h3" size="2xl">{data.summary.monitored_hosts}</Title>
                <span className="pf-v6-u-color-200">{data.summary.enforcing_hosts} enforcing ({data.summary.enforcement_percent}%)</span>
              </CardBody>
            </Card>
          </GridItem>
          <GridItem sm={12} md={4}>
            <Card isCompact className="resource-summary-card">
              <CardTitle>Open issues</CardTitle>
              <CardBody>
                <Title headingLevel="h3" size="2xl">{data.summary.open_count}</Title>
                <span className="pf-v6-u-color-200">{data.summary.regressed_count} regressed</span>
              </CardBody>
            </Card>
          </GridItem>
          <GridItem sm={12} md={4}>
            <Card isCompact className="resource-summary-card">
              <CardTitle>Unclassified events</CardTitle>
              <CardBody><Title headingLevel="h3" size="2xl">{data.summary.ungroupable_count}</Title></CardBody>
            </Card>
          </GridItem>
        </Grid>
      )}

      {issuesQuery.isPending ? (
        <div aria-label="Loading issues" style={{ padding: "var(--pf-v6-global--spacer--xl)" }}>
          <Spinner />
        </div>
      ) : issuesQuery.isError ? (
        <Alert variant="danger" title="Could not load issues">
          {issuesQuery.error instanceof Error ? issuesQuery.error.message : "Unknown error"}
        </Alert>
      ) : (
        <>
          {issues.length > 0 && data && (
            <section aria-label="Grouped issues">
              <div className="pf-v6-u-display-flex pf-v6-u-justify-content-space-between pf-v6-u-align-items-baseline">
                <Title headingLevel="h2" size="lg">Grouped issues</Title>
                <span className="pf-v6-u-color-200">{data.meta.total} result{data.meta.total === 1 ? "" : "s"}</span>
              </div>
              <Table aria-label="Grouped issues" gridBreakPoint="grid-md" isExpandable>
                <Thead>
                  <Tr>
                    <Th width={40}>Issue</Th>
                    <Th width={10}>Hosts</Th>
                    <Th width={10}>Occurrences</Th>
                    <Th width={15}>Last seen</Th>
                    <Th width={15}>Status</Th>
                    <Th width={10} screenReaderText="Actions" />
                  </Tr>
                </Thead>
                {issues.map((issue) => {
                  const isExpanded = expandedIssue === issue.id;
                  const visibleHosts = issue.hosts.slice(0, 3);
                  return (
                    <Tbody key={issue.id} isExpanded={isExpanded}>
                      <Tr isContentExpanded={isExpanded}>
                        <Td width={40} dataLabel="Issue" modifier="wrap">
                          <a className="issue-primary-link" href={`/issues/${issue.id}`}>
                            <span><code>{issue.source_type}</code><span aria-hidden="true"> → </span><code>{issue.target_type}</code></span>
                          </a>
                          <div className="issue-secondary-line pf-v6-u-color-200"><code>{issue.target_class}</code> · {issue.permissions.join(", ")}</div>
                        </Td>
                        <Td width={10} dataLabel="Hosts" modifier="fitContent"><strong>{issue.hosts_count}</strong></Td>
                        <Td width={10} dataLabel="Occurrences" modifier="fitContent"><strong>{issue.occurrences_count}</strong></Td>
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
                            onClick={() => setExpandedIssue(isExpanded ? null : issue.id)}
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
                })}
              </Table>
              {data.meta.total > data.meta.page_size && (
                <nav aria-label="Issue pages" className="pf-v6-u-mt-md">
                  <Button
                    variant="link"
                    isDisabled={data.meta.page === 1}
                    onClick={() => setParams({ page: String(data.meta.page - 1) })}
                  >
                    Previous
                  </Button>{" "}
                  <span>
                    Page {data.meta.page} of {data.meta.total_pages}
                  </span>{" "}
                  <Button
                    variant="link"
                    isDisabled={data.meta.page >= data.meta.total_pages}
                    onClick={() => setParams({ page: String(data.meta.page + 1) })}
                  >
                    Next
                  </Button>
                </nav>
              )}
            </section>
          )}

          {events.length > 0 && (
            <section aria-label="Unclassified events" className="pf-v6-u-mt-lg">
              <div style={{ display: "flex", alignItems: "baseline", gap: "var(--pf-v6-global--spacer--sm)" }}>
                <Title headingLevel="h2" size="lg">
                  Unclassified events
                </Title>
                <Label color="orange">{events.length}</Label>
              </div>
              <p>Evidence was retained, but it lacks the AVC fields needed for grouping.</p>
              {events.map((event) => (
                <Card key={event.id} isCompact isPlain className="pf-v6-u-mb-sm">
                  <CardBody>
                    <dl style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "var(--pf-v6-global--spacer--sm)" }}>
                      <div>
                        <dt>Server</dt>
                        <dd>
                          <a href={`/hosts?host_id=${event.host.id}`}>{event.host.hostname ?? `Host ${event.host.id}`}</a>
                        </dd>
                      </div>
                      <div>
                        <dt>Missing fields</dt>
                        <dd>{event.missing.join(", ")}</dd>
                      </div>
                      <div>
                        <dt>Occurred</dt>
                        <dd>
                          <time dateTime={event.occurred_at}>{formatUtc(event.occurred_at)}</time>
                        </dd>
                      </div>
                    </dl>
                  </CardBody>
                </Card>
              ))}
            </section>
          )}

          {issues.length === 0 && events.length === 0 && (
            <EmptyState titleText="No ingested errors found.">
              <EmptyStateBody>Adjust the filters to widen the result set.</EmptyStateBody>
            </EmptyState>
          )}
        </>
      )}
    </div>
  );
}
