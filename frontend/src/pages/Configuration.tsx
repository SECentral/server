import {
  Alert,
  Button,
  Card,
  CardBody,
  Grid,
  GridItem,
  Label,
  Select,
  SelectOption,
  Spinner,
  Tab,
  TabTitleText,
  Tabs,
  Title
} from "@patternfly/react-core";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { fetchConfiguration } from "../api/configuration";
import type { ConfigurationFleetResponse, ConfigurationFamily } from "../api/configuration";

const FAMILIES: { value: ConfigurationFamily; label: string }[] = [
  { value: "overview", label: "Overview" },
  { value: "booleans", label: "Booleans" },
  { value: "ports", label: "Ports" },
  { value: "file_contexts", label: "File contexts" },
  { value: "modules", label: "Modules" }
];

const BOOLEAN_COVERAGE: [string, string][] = [
  ["observed", "Observed"],
  ["unavailable", "Unavailable"],
  ["stale", "Stale"],
  ["unknown", "Unknown"]
];

const PORT_COVERAGE: [string, string][] = [
  ["observed", "Complete"],
  ["partial", "Partial"],
  ["unavailable", "Unavailable"],
  ["unknown", "Unknown"],
  ["stale", "Stale"],
  ["no_heartbeat", "No heartbeat"]
];

function CoverageCards({ items, counts }: { items: [string, string][]; counts: Record<string, number> }) {
  return (
    <Grid hasGutter className="pf-v6-u-mb-md" aria-label="Configuration coverage">
      {items.map(([key, label]) => (
        <GridItem key={key} sm={6} md={4} xl={2}>
          <Card isCompact variant="secondary" className="resource-summary-card">
            <CardBody>
              <span className="pf-v6-u-color-200">{label}</span>
              <Title headingLevel="h3" size="2xl">{counts[key] ?? 0}</Title>
            </CardBody>
          </Card>
        </GridItem>
      ))}
    </Grid>
  );
}

function CatalogCard({ data }: { data: ConfigurationFleetResponse }) {
  const catalog = data.booleans?.catalog ?? data.ports?.catalog;
  if (!catalog) {
    return (
      <Alert variant="info" isInline title="No catalog for this cohort">
        No reference catalog is available for the selected policy cohort.
      </Alert>
    );
  }
  return (
    <Card className="pf-v6-u-mb-md">
      <CardBody>
        <Title headingLevel="h3" size="md">
          Reference catalog
        </Title>
        <p>
          <strong>{catalog.version ?? "unknown version"}</strong> · {catalog.provenance ?? "unknown provenance"}
          {typeof catalog.completeness === "string" && catalog.completeness ? ` · ${catalog.completeness}` : ""}
        </p>
        {catalog.loaded_policy_digest && (
          <small className="pf-v6-u-color-200">
            {catalog.loaded_policy_digest}
            {catalog.distribution_catalog_revision_id ? ` · revision ${catalog.distribution_catalog_revision_id}` : ""}
          </small>
        )}
      </CardBody>
    </Card>
  );
}

function BooleanOverlay({ data }: { data: ConfigurationFleetResponse }) {
  const overlay = data.booleans?.catalog_overlay;
  if (!overlay) return null;
  const observed = overlay.observed;
  return (
    <section aria-label="Boolean catalog overlay">
      <Title headingLevel="h3" size="md">
        Catalog comparison
      </Title>
      <p>
        {observed.fresh_host_count} fresh · {observed.stale_host_count} stale · {observed.outside_cohort_host_count} outside
        cohort · {observed.no_current_configuration_host_count} without current configuration
      </p>
      <div className="pf-v6-c-table__responsive-wrapper">
        <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label="Catalog booleans">
          <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
            <th className="pf-v6-c-table__th" scope="col">Boolean</th><th className="pf-v6-c-table__th" scope="col">Catalog</th>
            <th className="pf-v6-c-table__th" scope="col">Default</th><th className="pf-v6-c-table__th" scope="col">Observed state</th>
            <th className="pf-v6-c-table__th" scope="col">Comparison</th>
          </tr></thead>
          <tbody className="pf-v6-c-table__tbody">
            {observed.rows.map((row) => (
              <tr className="pf-v6-c-table__tr" key={row.name}>
                <td className="pf-v6-c-table__td" data-label="Boolean">{row.name}<div className="pf-v6-u-color-200">{row.catalog?.description ?? ""}</div></td>
                <td className="pf-v6-c-table__td" data-label="Catalog">
                <Label color={row.catalog_status === "defined" ? "blue" : "grey"} isCompact>
                  {row.catalog_status}
                </Label>
                </td>
                <td className="pf-v6-c-table__td" data-label="Default">
                {row.catalog?.default === true ? "On" : row.catalog?.default === false ? "Off" : "—"}
                </td>
                <td className="pf-v6-c-table__td" data-label="Observed state">
                <Label color="green" isCompact>
                  on {row.counts.on}
                </Label>{" "}
                <Label color="grey" isCompact>
                  off {row.counts.off}
                </Label>{" "}
                <Label color="orange" isCompact>
                  unknown {row.counts.unknown}
                </Label>{" "}
                <Label color="red" isCompact>
                  unavailable {row.counts.unavailable}
                </Label>{" "}
                <Label color="orange" isCompact>
                  stale {row.counts.stale}
                </Label>
                </td>
                <td className="pf-v6-c-table__td" data-label="Comparison">
                <Label color={row.counts.reference_match > 0 ? "green" : "grey"} isCompact>
                  match {row.counts.reference_match}
                </Label>{" "}
                <Label color={row.counts.reference_difference > 0 ? "red" : "grey"} isCompact>
                  differs {row.counts.reference_difference}
                </Label>{" "}
                <Label color={row.counts.runtime_default_divergence > 0 ? "orange" : "grey"} isCompact>
                  default drift {row.counts.runtime_default_divergence}
                </Label>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {observed.unmatched_observed_names.length > 0 && (
        <p className="pf-v6-u-mt-sm">
          Observed names not in the catalog: {observed.unmatched_observed_names.join(", ")}
        </p>
      )}
    </section>
  );
}

function BooleanInventory({ data }: { data: ConfigurationFleetResponse }) {
  const rows = data.booleans?.inventory ?? [];
  if (rows.length === 0) {
    return <Alert variant="info" isInline title="No named boolean inventory">No observed booleans across the fleet.</Alert>;
  }
  const total = data.hosts.total;
  return (
    <section aria-label="Boolean inventory" className="pf-v6-u-mt-lg">
      <Title headingLevel="h3" size="md">
        Boolean inventory
      </Title>
      <div className="pf-v6-c-table__responsive-wrapper">
        <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label="Boolean inventory rows">
          <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
            <th className="pf-v6-c-table__th" scope="col">Boolean</th><th className="pf-v6-c-table__th" scope="col">Fleet states</th>
          </tr></thead>
          <tbody className="pf-v6-c-table__tbody">
            {rows.map((row) => (
              <tr className="pf-v6-c-table__tr" key={row.name}>
                <td className="pf-v6-c-table__td" data-label="Boolean">{row.name}<div className="pf-v6-u-color-200">{row.description ?? ""}</div></td>
                <td className="pf-v6-c-table__td" data-label="Fleet states">
                <Label color="green" isCompact>
                  on {row.counts.enabled} / {total}
                </Label>{" "}
                <Label color="grey" isCompact>
                  off {row.counts.disabled} / {total}
                </Label>{" "}
                <Label color="orange" isCompact>
                  unknown {row.counts.unknown} / {total}
                </Label>{" "}
                <Label color="red" isCompact>
                  unavailable {row.counts.unavailable} / {total}
                </Label>{" "}
                <Label color="orange" isCompact>
                  stale {row.counts.stale} / {total}
                </Label>{" "}
                <Label color="orange" isCompact>
                  drift {row.counts.drift}
                </Label>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function PortOverlay({ data }: { data: ConfigurationFleetResponse }) {
  const overlay = data.ports?.catalog_overlay;
  if (!overlay) return null;
  const observed = overlay.observed;
  return (
    <section aria-label="Port catalog overlay">
      <Title headingLevel="h3" size="md">
        Catalog comparison
      </Title>
      <p>
        {observed.fresh_complete_host_count} complete · {observed.partial_host_count} partial · {observed.unavailable_host_count}{" "}
        unavailable · {observed.unknown_host_count} unknown · {observed.stale_host_count} stale ·{" "}
        {observed.outside_cohort_host_count} outside cohort
      </p>
      <div className="pf-v6-c-table__responsive-wrapper">
        <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label="Port segments">
          <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
            <th className="pf-v6-c-table__th" scope="col">Port segment</th><th className="pf-v6-c-table__th" scope="col">Catalog types</th>
            <th className="pf-v6-c-table__th" scope="col">Observed types</th><th className="pf-v6-c-table__th" scope="col">Comparison</th>
            <th className="pf-v6-c-table__th" scope="col">Classification</th><th className="pf-v6-c-table__th" scope="col">Host</th>
          </tr></thead>
          <tbody className="pf-v6-c-table__tbody">
            {observed.segments.map((segment, index) => (
              <tr className="pf-v6-c-table__tr" key={`${segment.protocol}-${segment.start}-${index}`}>
                <td className="pf-v6-c-table__td" data-label="Port segment">
                {segment.protocol}/{segment.start === segment.end ? segment.start : `${segment.start}-${segment.end}`}
                </td>
                <td className="pf-v6-c-table__td" data-label="Catalog types">
                {(segment.catalog_types ?? []).filter(Boolean).join(", ") || "—"}
                </td>
                <td className="pf-v6-c-table__td" data-label="Observed types">
                {(segment.observed_types ?? []).filter(Boolean).join(", ") || "—"}
                </td>
                <td className="pf-v6-c-table__td" data-label="Comparison">
                <Label
                  color={segment.relation === "matching_effective_type" ? "green" : segment.relation === "comparison_unknown" ? "orange" : "red"}
                  isCompact
                >
                  {segment.relation}
                </Label>
                </td>
                <td className="pf-v6-c-table__td" data-label="Classification">{segment.local_classification ?? "—"}</td>
                <td className="pf-v6-c-table__td" data-label="Host">{segment.hostname ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {observed.observed_mappings.length > 0 && (
        <>
          <Title headingLevel="h4" size="md" className="pf-v6-u-mt-md">
            Observed mappings without catalog comparison
          </Title>
          <div className="pf-v6-c-table__responsive-wrapper">
            <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label="Observed port mappings">
              <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
                <th className="pf-v6-c-table__th" scope="col">Port</th><th className="pf-v6-c-table__th" scope="col">SELinux type</th>
                <th className="pf-v6-c-table__th" scope="col">Provenance</th><th className="pf-v6-c-table__th" scope="col">Host</th>
              </tr></thead>
              <tbody className="pf-v6-c-table__tbody">
                {observed.observed_mappings.map((mapping, index) => (
                  <tr className="pf-v6-c-table__tr" key={index}>
                    <td className="pf-v6-c-table__td" data-label="Port">
                    {mapping.protocol}/{mapping.start === mapping.end ? mapping.start : `${mapping.start}-${mapping.end}`}
                    </td>
                    <td className="pf-v6-c-table__td" data-label="SELinux type">{mapping.type ?? "—"}</td>
                    <td className="pf-v6-c-table__td" data-label="Provenance">{mapping.provenance ?? "—"}</td>
                    <td className="pf-v6-c-table__td" data-label="Host">{mapping.hostname ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

function RowFamily({ data, family }: { data: ConfigurationFleetResponse; family: ConfigurationFamily }) {
  const rows = data.rows ?? [];
  return (
    <section aria-label={`${family} rows`}>
      <Title headingLevel="h3" size="md">
        Observed {family === "file_contexts" ? "file contexts" : "modules"}
      </Title>
      <p>
        {data.observed_host_count ?? 0} hosts with fresh observations
      </p>
      <div className="pf-v6-c-table__responsive-wrapper">
        <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label={`${family} rows`}>
          <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
            <th className="pf-v6-c-table__th" scope="col">{family === "file_contexts" ? "Path pattern" : "Module"}</th>
            {family === "modules" && <th className="pf-v6-c-table__th" scope="col">Priority</th>}
            <th className="pf-v6-c-table__th" scope="col">Provenance</th><th className="pf-v6-c-table__th" scope="col">Hosts</th>
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
                <td className="pf-v6-c-table__td" data-label="Provenance">{row.provenance.filter(Boolean).join(", ") || "—"}</td>
                <td className="pf-v6-c-table__td" data-label="Hosts">
                {row.host_ids.length} host{row.host_ids.length === 1 ? "" : "s"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length === 0 && <Alert variant="info" isInline title="No fresh observations" />}
    </section>
  );
}

function CohortSelect({ data, policyIdentity, onSelect }: { data: ConfigurationFleetResponse; policyIdentity: string | null; onSelect: (identity: string | null) => void }) {
  const [open, setOpen] = useState(false);
  const cohorts = data.booleans?.policy_cohorts ?? data.ports?.policy_cohorts ?? [];
  const selected = policyIdentity ?? "auto";
  return (
    <Select
      isOpen={open}
      selected={selected === "auto" ? "Auto" : selected}
      onOpenChange={setOpen}
      onSelect={(_event, value) => {
        setOpen(false);
        onSelect(value === "Auto" ? null : (value as string));
      }}
      toggle={(toggleRef) => (
        <Button variant="secondary" isExpanded={open} onClick={() => setOpen(!open)} ref={toggleRef} aria-label="Policy cohort">
          Policy cohort: {selected === "auto" ? "auto" : selected.slice(0, 19) + "…"}
        </Button>
      )}
    >
      <SelectOption value="Auto">Auto</SelectOption>
      {cohorts.map((cohort) => (
        <SelectOption key={cohort} value={cohort}>
          {cohort.slice(0, 19)}…
        </SelectOption>
      ))}
    </Select>
  );
}

export function Configuration() {
  const [searchParams, setSearchParams] = useSearchParams();
  const family = (FAMILIES.some((entry) => entry.value === searchParams.get("family")) ? searchParams.get("family") : "overview") as ConfigurationFamily;
  const policyIdentity = searchParams.get("policy_identity");
  const hasCohort = family === "booleans" || family === "ports";

  const configQuery = useQuery({
    queryKey: ["configuration", family, policyIdentity ?? ""],
    queryFn: () => fetchConfiguration(family, policyIdentity ?? undefined),
    placeholderData: (previousData) => previousData
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
    setSearchParams(next);
  };

  const data = configQuery.data;

  return (
    <div className="app-resource-page">
      <header className="app-resource-header">
        <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">SELinux configuration</Title>
        <p className="pf-v6-u-color-200">Fleet-wide SELinux configuration, compared against reference catalogs where available.</p>
      </header>

      <Tabs
        activeKey={family}
        onSelect={(_event, key) => setParams({ family: String(key), policy_identity: null })}
        aria-label="Configuration families"
        className="pf-v6-u-mb-lg"
      >
        {FAMILIES.map((entry) => (
          <Tab key={entry.value} eventKey={entry.value} title={<TabTitleText>{entry.label}</TabTitleText>} />
        ))}
      </Tabs>

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
            <p className="pf-v6-u-mb-md">
              {data.hosts.total} monitored host{data.hosts.total === 1 ? "" : "s"}
            </p>
            {hasCohort && (
              <div className="pf-v6-u-mb-md" style={{ display: "flex", gap: "var(--pf-v6-global--spacer--sm)" }}>
                <CohortSelect data={data} policyIdentity={policyIdentity} onSelect={(identity) => setParams({ policy_identity: identity })} />
              </div>
            )}
            {family === "overview" && (
              <Alert variant="info" isInline title="Select a family">
                Choose booleans, ports, file contexts, or modules to explore fleet configuration.
              </Alert>
            )}
            {family === "booleans" && data.booleans && (
              <>
                <CoverageCards items={BOOLEAN_COVERAGE} counts={data.booleans.coverage} />
                <CatalogCard data={data} />
                <BooleanOverlay data={data} />
                <BooleanInventory data={data} />
              </>
            )}
            {family === "ports" && data.ports && (
              <>
                <CoverageCards items={PORT_COVERAGE} counts={data.ports.coverage} />
                <CatalogCard data={data} />
                <PortOverlay data={data} />
              </>
            )}
            {(family === "file_contexts" || family === "modules") && <RowFamily data={data} family={family} />}
          </>
        )
      )}
    </div>
  );
}
