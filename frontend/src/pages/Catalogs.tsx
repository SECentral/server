import { Alert, Button, Card, CardBody, EmptyState, EmptyStateBody, Label, Spinner, Title } from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { fetchCatalogs } from "../api/catalogs";

function importedDate(iso: string): string {
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" }).format(new Date(iso));
}

export function Catalogs() {
  const catalogsQuery = useQuery({
    queryKey: ["catalogs"],
    queryFn: fetchCatalogs
  });

  const data = catalogsQuery.data;

  return (
    <div className="app-resource-page">
      <header className="app-resource-header app-page-header">
        <div>
        <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">Distribution catalogs</Title>
        <p className="pf-v6-u-color-200">Imported distribution-format references. Import does not establish vendor review. Archived revisions remain inspectable but are excluded from new automatic selection.</p>
        </div>
        <Link className="pf-v6-c-button pf-m-primary" to="/catalogs/import">Import catalog</Link>
      </header>

      <Card component="section" aria-label="Distribution catalogs" className="resource-table-card"><CardBody>
        <div className="table-section-heading">
          <Title headingLevel="h2" size="lg">Catalog inventory</Title>
          {data && !catalogsQuery.isError && <span className="pf-v6-u-color-200">{data.catalogs.length} catalog{data.catalogs.length === 1 ? "" : "s"}</span>}
        </div>
      {catalogsQuery.isPending ? (
        <div aria-label="Loading catalogs" className="pf-v6-u-p-xl"><Spinner /></div>
      ) : catalogsQuery.isError ? (
        <Alert variant="danger" title="Could not load catalogs">
          {catalogsQuery.error instanceof Error ? catalogsQuery.error.message : "Unknown error"}
        </Alert>
      ) : !data || data.catalogs.length === 0 ? (
        <EmptyState titleText="No imported distribution catalogs">
          <EmptyStateBody>Importing a valid catalog makes it available here as reference knowledge.</EmptyStateBody>
        </EmptyState>
      ) : (
          <Table aria-label="Imported SELinux distribution catalogs" variant="compact" gridBreakPoint="grid-lg" className="catalog-table">
            <Thead>
              <Tr>
                <Th width={40}>Distribution and policy</Th>
                <Th width={25}>Inventory</Th>
                <Th width={15}>Imported</Th>
                <Th width={20}>Actions</Th>
              </Tr>
            </Thead>
            <Tbody>
              {data.catalogs.map((catalog) => (
                <Tr key={catalog.id}>
                   <Td width={40} dataLabel="Distribution and policy" modifier="wrap">
                    <Link className="catalog-primary-link" to={`/catalogs/${catalog.id}`}>
                       {catalog.display_name}
                     </Link>
                      <div>{catalog.lifecycle === "archived" ? <Label color="grey" isCompact>Archived</Label> : <span className="pf-v6-u-color-200">Active</span>}</div>
                    <div className="pf-v6-u-color-200">
                      {catalog.policy_type} · {catalog.architecture} · policy {catalog.kernel_policy_version}
                    </div>
                  </Td>
                   <Td width={25} dataLabel="Inventory">
                    <div className="catalog-inventory">
                       <div>{catalog.booleans_count} booleans · {catalog.booleans_complete ? "complete" : <Label status="warning" isCompact>incomplete</Label>}</div>
                       <div>{catalog.port_mappings_count} port mappings · {catalog.ports_complete ? "complete" : <Label status="warning" isCompact>incomplete</Label>}</div>
                    </div>
                  </Td>
                  <Td width={15} dataLabel="Imported">{importedDate(catalog.created_at)}</Td>
                   <Td width={20} dataLabel="Actions" hasAction>
                    <div className="catalog-action">
                     {catalog.lifecycle === "active" ? <Button
                      component="a"
                      href={`/configuration?family=booleans&policy_identity=${encodeURIComponent(catalog.loaded_policy_digest)}`}
                      variant="secondary"
                      size="sm"
                      aria-label="Compare in configuration"
                    >
                      Compare
                     </Button> : <Link to={`/catalogs/${catalog.id}`}>View archived reference</Link>}
                    </div>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
      )}
      </CardBody></Card>
    </div>
  );
}
