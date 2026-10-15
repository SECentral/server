import {
  Alert,
  Button,
  Card,
  CardBody,
  EmptyState,
  EmptyStateBody,
  Label,
  Pagination,
  Select,
  SelectOption,
  Spinner,
  TextInput,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem
} from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { fetchHosts } from "../api/hosts";
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

function SummaryTile({
  label,
  count,
  status,
  onClick
}: {
  label: string;
  count: number;
  status: "success" | "warning" | "danger" | "info";
  onClick?: () => void;
}) {
  const body = (
    <CardBody className="hosts-summary-card-body">
      <Title headingLevel="h2" size="2xl" className="hosts-summary-count">{count}</Title>
      <div className="hosts-summary-copy">
        <Label status={status} isCompact>{label}</Label>
        <small className="hosts-summary-support">hosts</small>
      </div>
    </CardBody>
  );

  return onClick ? (
    <Card isClickable isCompact component="button" className="hosts-summary-card" onClick={onClick} aria-label={`${label} ${count} hosts`}>
      {body}
    </Card>
  ) : (
    <Card isCompact className="hosts-summary-card" aria-label={`${label} ${count} hosts`}>
      {body}
    </Card>
  );
}

export function Hosts() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [enforcementOpen, setEnforcementOpen] = useState(false);
  const [statusOpen, setStatusOpen] = useState(false);
  const [moreFiltersOpen, setMoreFiltersOpen] = useState(false);

  const hostsKey = searchParams.toString();
  const hostsQuery = useQuery({
    queryKey: ["hosts", hostsKey],
    queryFn: () => fetchHosts(searchParams)
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
  const counts = data?.summary.agent_state_counts;
  const activeFilters = [...searchParams.entries()].filter(([key, value]) => !["page", "limit"].includes(key) && value !== "");

  return (
    <div className="app-resource-page">
      <header className="app-resource-header">
        <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">Monitored servers</Title>
        <p className="pf-v6-u-color-200">Agents, SELinux configuration freshness, and activity per monitored host.</p>
      </header>

      {data && counts && (
        <div className="hosts-summary-grid pf-v6-u-mt-md" aria-label="Host summary">
          <SummaryTile label="Monitored hosts" count={data.summary.total} status="info" />
          {STATUS_OPTIONS.map((option) => (
            <SummaryTile
              key={option.value}
              label={option.label}
              count={counts[option.value]}
              status={AGENT_STATUS[option.value]}
              onClick={() => setParams({ status: status === option.value ? null : option.value })}
            />
          ))}
        </div>
      )}

      <Toolbar className="hosts-filter-toolbar pf-v6-u-mb-md" id="hosts-filter-toolbar">
        <ToolbarContent>
          <ToolbarItem>
            <TextInput
              id="host-filter-os_id"
              value={searchParams.get("os_id") ?? ""}
              onChange={(_event, value) => setParams({ os_id: value })}
              placeholder="Filter by OS"
              aria-label="OS"
            />
          </ToolbarItem>
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
          <ToolbarItem align={{ lg: "alignEnd" }}>
            <Button variant="link" isExpanded={moreFiltersOpen} onClick={() => setMoreFiltersOpen(!moreFiltersOpen)}>
              {moreFiltersOpen ? "Fewer filters" : "More filters"}
            </Button>
          </ToolbarItem>
          {moreFiltersOpen && TEXT_FILTERS.filter((filter) => filter.key !== "os_id").map((filter) => (
            <ToolbarItem key={filter.key}>
              <TextInput
                id={`host-filter-${filter.key}`}
                value={searchParams.get(filter.key) ?? ""}
                onChange={(_event, value) => setParams({ [filter.key]: value })}
                placeholder={filter.placeholder}
                aria-label={filter.label}
              />
            </ToolbarItem>
          ))}
        </ToolbarContent>
      </Toolbar>

      {activeFilters.length > 0 && (
        <div className="pf-v6-u-mb-md" aria-label="Active filters">
          <span className="pf-v6-u-mr-sm">Active filters:</span>
          {activeFilters.map(([key, value]) => (
            <Label key={key} color="blue" isCompact onClose={() => setParams({ [key]: null })} className="pf-v6-u-mr-sm">
              {key}: {value}
            </Label>
          ))}
          <Button variant="link" size="sm" onClick={() => setSearchParams(new URLSearchParams())}>
            Reset filters
          </Button>
        </div>
      )}

      {hostsQuery.isPending ? (
        <div aria-label="Loading hosts" style={{ padding: "var(--pf-v6-global--spacer--xl)" }}>
          <Spinner />
        </div>
      ) : hostsQuery.isError ? (
        <Alert variant="danger" title="Could not load hosts">
          {hostsQuery.error instanceof Error ? hostsQuery.error.message : "Unknown error"}
        </Alert>
      ) : (
        <>
          {hosts.length > 0 && data && (
            <section aria-label="Hosts">
              <Table aria-label="Hosts" variant="compact" gridBreakPoint="grid-lg">
                <Thead>
                  <Tr>
                    <Th width={20}>Host</Th>
                    <Th width={10}>Agent</Th>
                    <Th width={10}>Config</Th>
                    <Th width={15}>Operating system</Th>
                    <Th width={15}>SELinux</Th>
                    <Th width={15}>Activity</Th>
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
                      <Td width={15} dataLabel="Activity">
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
              <div className="table-pagination"><Pagination itemCount={data.meta.total} page={data.meta.page} perPage={data.meta.page_size}
                perPageOptions={PAGE_SIZES.map((value) => ({ title: String(value), value }))}
                titles={{ paginationAriaLabel: "Host pagination" }} isDisabled={hostsQuery.isFetching}
                onSetPage={(_event, page) => setParams({ page: String(page) })}
                onPerPageSelect={(_event, size) => setParams({ limit: String(size) })} /></div>
            </section>
          )}
          {hosts.length === 0 && (
            <EmptyState titleText="No hosts match the filters.">
              <EmptyStateBody>Adjust the filters to widen the result set.</EmptyStateBody>
            </EmptyState>
          )}
        </>
      )}
    </div>
  );
}
