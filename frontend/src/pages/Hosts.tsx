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
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem
} from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { fetchHosts } from "../api/hosts";
import { MetricCard } from "../components/MetricCard";
import { osDisplayName } from "../platform";
import { PAGE_SIZES } from "../pagination";

const TEXT_FILTERS = [
  { key: "os_id", label: "OS", placeholder: "OS" },
  { key: "policy_type", label: "Policy type", placeholder: "Policy type" },
  { key: "kernel_policy_version", label: "Policy version", placeholder: "Policy version" },
  { key: "agent_version", label: "Agent version", placeholder: "Agent version" },
  { key: "host_id", label: "Host ID", placeholder: "Host ID" }
] as const;

const ENFORCEMENT_OPTIONS = [
  { value: "enforcing", label: "Enforcing" },
  { value: "permissive", label: "Permissive" },
  { value: "disabled", label: "Disabled" }
] as const;

const STATUS_OPTIONS = [
  { value: "reporting", label: "Reporting" },
  { value: "stale", label: "Stale" },
  { value: "offline", label: "Offline" },
] as const;

const CONFIGURATION_FILTER_LABELS: Record<string, Record<string, string>> = {
  booleans: { observed: "Observed hosts", unavailable: "Boolean data unavailable", stale: "Stale host snapshots", unknown: "Unknown Boolean state" },
  ports: { observed: "Complete port inventory", partial: "Partial port inventory", unavailable: "Unavailable port inventory", unknown: "Unknown port inventory", stale: "Stale host snapshots", no_heartbeat: "No configuration snapshot" }
};

const AGENT_STATUS: Record<string, "success" | "warning" | "danger" | "info"> = {
  reporting: "success",
  stale: "warning",
  offline: "danger",
};

const OBSERVATION_STATUS: Record<string, "success" | "warning" | "info"> = {
  current: "success",
  stale: "warning",
  none: "info"
};

const ENFORCEMENT_STATUS: Record<string, "success" | "warning" | "info"> = {
  enforcing: "success",
  permissive: "warning",
  disabled: "info"
};

function timeAgo(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 90) return "<1m ago";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

function formatUtc(iso: string): string {
  return `${new Date(iso).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export function Hosts() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [enforcementOpen, setEnforcementOpen] = useState(false);
  const [statusOpen, setStatusOpen] = useState(false);
  const [attribute, setAttribute] = useState<string>("os_id");
  const [draft, setDraft] = useState("");

  const hostsKey = searchParams.toString();
  const hostsQuery = useQuery({
    queryKey: ["hosts", hostsKey],
    queryFn: () => fetchHosts(searchParams),
    placeholderData: keepPreviousData
  });
  const fleetQuery = useQuery({
    queryKey: ["hosts", ""],
    queryFn: () => fetchHosts(new URLSearchParams())
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

  const data = hostsQuery.data;
  const hosts = data?.hosts ?? [];
  const enforcement = searchParams.get("enforcement") ?? "";
  const status = searchParams.get("status") ?? "";
  const enforcementLabel = ENFORCEMENT_OPTIONS.find((option) => option.value === enforcement)?.label ?? "Any mode";
  const statusLabel = STATUS_OPTIONS.find((option) => option.value === status)?.label ?? "All agent states";
  const counts = fleetQuery.data?.summary.agent_state_counts;
  const activeFilters = [...searchParams.entries()].filter(([key, value]) => !["page", "limit", "configuration_family"].includes(key) && value !== "");
  const selectedAttribute = TEXT_FILTERS.find((filter) => filter.key === attribute)!;
  const clearFilters = () => {
    setDraft("");
    const next = new URLSearchParams();
    if (searchParams.has("limit")) next.set("limit", searchParams.get("limit")!);
    setSearchParams(next);
  };
  const filterLabel = (key: string, value: string) => {
    if (key === "configuration_status") return `${searchParams.get("configuration_family") === "ports" ? "Port coverage" : "Boolean coverage"}: ${CONFIGURATION_FILTER_LABELS[searchParams.get("configuration_family") ?? ""]?.[value] ?? value}`;
    if (key === "status") return `Agent state: ${STATUS_OPTIONS.find((option) => option.value === value)?.label ?? value}`;
    if (key === "enforcement") return `Enforcement: ${ENFORCEMENT_OPTIONS.find((option) => option.value === value)?.label ?? value}`;
    return `${TEXT_FILTERS.find((filter) => filter.key === key)?.label ?? key}: ${value}`;
  };

  return (
    <div className="app-resource-page">
      <header className="app-resource-header">
        <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">Monitored servers</Title>
        <p className="pf-v6-u-color-200">Agents, SELinux configuration freshness, and activity per monitored host.</p>
      </header>

      <Stack hasGutter>
      {fleetQuery.isError ? <Alert isInline variant="warning" title="Could not load fleet summary"><Button variant="link" onClick={() => void fleetQuery.refetch()}>Retry fleet summary</Button></Alert> : counts && (
        <Grid hasGutter aria-label="Fleet agent summary">
          {STATUS_OPTIONS.map((option) => (
            <GridItem key={option.value} sm={12} md={4}>
              <MetricCard label={option.label} value={counts[option.value]} detail="Hosts across the fleet" href={`/hosts?status=${option.value}`} />
            </GridItem>
          ))}
        </Grid>
      )}

      <form onSubmit={(event) => { event.preventDefault(); setParams({ [attribute]: draft.trim() || null }); }}>
      <Toolbar id="hosts-filter-toolbar" aria-label="Host filters" hasNoPadding>
        <ToolbarContent>
          <ToolbarGroup gap={{ default: "gapMd" }} rowWrap={{ default: "wrap" }}>
          <ToolbarItem>
            <FormSelect aria-label="Filter attribute" value={attribute} onChange={(_event, value) => { setAttribute(value); setDraft(searchParams.get(value) ?? ""); }}>
              {TEXT_FILTERS.map((filter) => <FormSelectOption key={filter.key} value={filter.key} label={filter.label} />)}
            </FormSelect>
          </ToolbarItem>
          <ToolbarItem>
            <TextInput
              value={draft}
              onChange={(_event, value) => setDraft(value)}
              placeholder={selectedAttribute.placeholder}
              aria-label="Filter value"
            />
          </ToolbarItem>
          <ToolbarItem><Button type="submit" variant="secondary">Apply filter</Button></ToolbarItem>
          <ToolbarItem>
        <Select
          isOpen={enforcementOpen}
          selected={enforcementLabel}
          onOpenChange={(isOpen) => setEnforcementOpen(isOpen)}
          onSelect={(_event, value) => {
            setEnforcementOpen(false);
            const option = ENFORCEMENT_OPTIONS.find((entry) => entry.label === value);
            setParams({ enforcement: option ? option.value : null });
          }}
          toggle={(toggleRef) => (
            <Button
              variant="secondary"
              isExpanded={enforcementOpen}
              onClick={() => setEnforcementOpen(!enforcementOpen)}
              ref={toggleRef}
              aria-label="Enforcement filter"
            >
              {enforcementLabel}
            </Button>
          )}
        >
          <SelectOption value="Any mode">Any mode</SelectOption>
          {ENFORCEMENT_OPTIONS.map((option) => (
            <SelectOption key={option.value} value={option.label}>
              {option.label}
            </SelectOption>
          ))}
        </Select>
          </ToolbarItem>
          <ToolbarItem>
        <Select
          isOpen={statusOpen}
          selected={statusLabel}
          onOpenChange={(isOpen) => setStatusOpen(isOpen)}
          onSelect={(_event, value) => {
            setStatusOpen(false);
            const option = STATUS_OPTIONS.find((entry) => entry.label === value);
            setParams({ status: option ? option.value : null });
          }}
          toggle={(toggleRef) => (
            <Button
              variant="secondary"
              isExpanded={statusOpen}
              onClick={() => setStatusOpen(!statusOpen)}
              ref={toggleRef}
              aria-label="Agent state filter"
            >
              {statusLabel}
            </Button>
          )}
        >
          <SelectOption value="All agent states">All agent states</SelectOption>
          {STATUS_OPTIONS.map((option) => (
            <SelectOption key={option.value} value={option.label}>
              {option.label}
            </SelectOption>
          ))}
        </Select>
          </ToolbarItem>
          </ToolbarGroup>
        </ToolbarContent>

      {activeFilters.length > 0 && (
        <ToolbarContent className="pf-v6-u-mt-md" aria-label="Active host filters">
          <ToolbarGroup gap={{ default: "gapMd" }} rowWrap={{ default: "wrap" }}>
          {activeFilters.map(([key, value]) => (
            <ToolbarItem key={key}><Label isCompact closeBtnAriaLabel={`Remove ${filterLabel(key, value)} filter`} onClose={() => {
              if (attribute === key) setDraft("");
              if (key === "configuration_status") setParams({ configuration_family: null, configuration_status: null });
              else setParams({ [key]: null });
            }}>{filterLabel(key, value)}</Label></ToolbarItem>
          ))}
          <ToolbarItem><Button variant="link" onClick={clearFilters}>
            Reset filters
          </Button></ToolbarItem>
          </ToolbarGroup>
        </ToolbarContent>
      )}
      </Toolbar>
      </form>

      <Card component="section" aria-label="Hosts" aria-busy={hostsQuery.isFetching} className="resource-table-card"><CardBody>
      <div className="table-section-heading">
        <Title headingLevel="h2" size="lg">Hosts</Title>
        {data && !hostsQuery.isError && !hostsQuery.isPlaceholderData && <span className="pf-v6-u-color-200">{data.meta.total} result{data.meta.total === 1 ? "" : "s"}</span>}
      </div>
      {hostsQuery.isFetching && !hostsQuery.isPending && <p role="status" className="pf-v6-u-mb-md"><Spinner size="md" aria-label="Updating hosts" /> {hostsQuery.isPlaceholderData ? "Updating hosts; showing previous results." : "Updating hosts."}</p>}
      {hostsQuery.isPending ? (
        <div aria-label="Loading hosts" className="pf-v6-u-p-xl">
          <Spinner />
        </div>
      ) : hostsQuery.isError ? (
        <Alert variant="danger" title="Could not load hosts">
          {hostsQuery.error instanceof Error ? hostsQuery.error.message : "Unknown error"}
          <Button variant="link" onClick={() => void hostsQuery.refetch()}>Retry hosts</Button>
        </Alert>
      ) : (
        <>
          {hosts.length > 0 && data && (
            <>
              <Table aria-label="Hosts" variant="compact" gridBreakPoint="grid-lg">
                <Thead>
                  <Tr>
                    <Th width={20}>Host</Th>
                    <Th width={10}>Agent</Th>
                    <Th width={10}>Config</Th>
                    <Th width={15}>Operating system</Th>
                    <Th width={15}>SELinux</Th>
                    <Th width={15} className="pf-v6-u-text-align-right">Activity</Th>
                    <Th width={15}>Last seen</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {hosts.map((host) => (
                    <Tr key={host.id}>
                      <Td width={20} dataLabel="Host" modifier="wrap">
                        <a className="host-primary-link" href={`/hosts/${host.id}`}>
                          {host.hostname ?? `Host ${host.id}`}
                        </a>
                      </Td>
                      <Td width={10} dataLabel="Agent">
                        <Label status={AGENT_STATUS[host.agent.reporting_state] ?? "info"} isCompact>
                          {host.agent.reporting_state}
                        </Label>
                        {host.agent.agent_version && <div className="pf-v6-u-color-200">v{host.agent.agent_version}</div>}
                      </Td>
                      <Td width={10} dataLabel="Config">
                        <Label status={OBSERVATION_STATUS[host.observation.status] ?? "info"} isCompact>
                          {host.observation.status}
                        </Label>
                      </Td>
                      <Td width={15} dataLabel="Operating system">
                        {host.platform.os_id ? `${osDisplayName(host.platform.os_id)} ${host.platform.os_version ?? ""}`.trim() : <span className="pf-v6-u-color-200">unknown</span>}
                      </Td>
                      <Td width={15} dataLabel="SELinux">
                        {host.selinux.enforcement ? (
                          <Label status={ENFORCEMENT_STATUS[host.selinux.enforcement] ?? "info"} isCompact>{host.selinux.enforcement}</Label>
                        ) : (
                          <span className="pf-v6-u-color-200">unknown</span>
                        )}
                        {host.selinux.configured_policy_type && <div className="pf-v6-u-color-200">{host.selinux.configured_policy_type}</div>}
                      </Td>
                      <Td width={15} dataLabel="Activity" className="pf-v6-u-text-align-right">
                        <div>
                          {host.counts.active_issues > 0 ? (
                            <a href={`/issues?host_id=${host.id}&status=open`}>{host.counts.active_issues} active issue{host.counts.active_issues === 1 ? "" : "s"}</a>
                          ) : (
                            <span>0 active issues</span>
                          )}
                        </div>
                        <div className="pf-v6-u-color-200">{host.counts.total_events} total events</div>
                        <div className="pf-v6-u-color-200">{host.counts.avcs_24h} AVCs / 24h</div>
                      </Td>
                      <Td width={15} dataLabel="Last seen">
                        {host.last_seen_at ? (
                          <time dateTime={host.last_seen_at} title={formatUtc(host.last_seen_at)}>{timeAgo(host.last_seen_at)}</time>
                        ) : (
                          <span className="pf-v6-u-color-200">never</span>
                        )}
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
              {!hostsQuery.isPlaceholderData && <div className="table-pagination"><Pagination itemCount={data.meta.total} page={data.meta.page} perPage={data.meta.page_size}
                perPageOptions={PAGE_SIZES.map((value) => ({ title: String(value), value }))}
                titles={{ paginationAriaLabel: "Host pagination" }} isDisabled={hostsQuery.isFetching}
                onSetPage={(_event, page) => setParams({ page: String(page) })}
                onPerPageSelect={(_event, size) => setParams({ limit: String(size) })} /></div>}
            </>
          )}
          {hosts.length === 0 && !hostsQuery.isPlaceholderData && (
            <EmptyState titleText={activeFilters.length > 0 ? "No hosts match the filters." : "No monitored hosts yet."}>
              <EmptyStateBody>{activeFilters.length > 0 ? "Clear filters to widen the result set." : "Connect an agent to start monitoring a host."}</EmptyStateBody>
              {activeFilters.length > 0 && <Button variant="link" onClick={clearFilters}>Clear filters</Button>}
            </EmptyState>
          )}
        </>
      )}
      </CardBody></Card>
      </Stack>
    </div>
  );
}
