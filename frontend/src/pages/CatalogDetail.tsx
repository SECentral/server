import {
  Alert,
  Breadcrumb,
  BreadcrumbItem,
  Card,
  CardBody,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListTerm,
  Spinner,
  Title
} from "@patternfly/react-core";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { fetchCatalog } from "../api/catalogs";

function policyPackageLabel(packages: { [key: string]: unknown }[]): string {
  const package_ = packages[0] as Record<string, unknown> | undefined;
  if (!package_) return "Not recorded";
  return [package_.name, package_.epoch, package_.version, package_.release, package_.architecture]
    .filter((value) => value !== undefined && value !== null)
    .map(String)
    .join("-");
}

function utcTimestamp(iso: string): string {
  return `${new Date(iso).toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

export function CatalogDetail() {
  const { id } = useParams();
  const catalogQuery = useQuery({
    queryKey: ["catalog", id],
    queryFn: () => fetchCatalog(id as string),
    enabled: id !== undefined
  });

  const catalog = catalogQuery.data?.catalog;

  return (
    <>
      <Breadcrumb aria-label="Breadcrumb" className="pf-v6-u-mb-sm">
        <BreadcrumbItem>
          <Link to="/catalogs">Catalogs</Link>
        </BreadcrumbItem>
        {catalog && <BreadcrumbItem isActive>{catalog.display_name}</BreadcrumbItem>}
      </Breadcrumb>

      {catalogQuery.isPending ? (
        <div aria-label="Loading catalog" style={{ padding: "var(--pf-v6-global--spacer--xl)" }}>
          <Spinner />
        </div>
      ) : catalogQuery.isError ? (
        <Alert variant="danger" title="Could not load the catalog">
          {catalogQuery.error instanceof Error ? catalogQuery.error.message : "Unknown error"}
        </Alert>
      ) : catalog && (
        <>
          <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">
            {catalog.display_name} SELinux policy
          </Title>
          <p className="pf-v6-u-color-200">Imported reference knowledge, not observed host state.</p>

          <Card className="pf-v6-u-mb-md">
            <CardTitle>Identity and provenance</CardTitle>
            <CardBody>
              <DescriptionList>
                <DescriptionListTerm>Policy</DescriptionListTerm>
                <DescriptionListDescription>
                  {catalog.policy_type} / {catalog.architecture} · kernel policy {catalog.kernel_policy_version}
                </DescriptionListDescription>
                <DescriptionListTerm>Policy package</DescriptionListTerm>
                <DescriptionListDescription>{policyPackageLabel(catalog.policy_packages)}</DescriptionListDescription>
                <DescriptionListTerm>Loaded-policy digest</DescriptionListTerm>
                <DescriptionListDescription><code>{catalog.loaded_policy_digest}</code></DescriptionListDescription>
                <DescriptionListTerm>Catalog content digest</DescriptionListTerm>
                <DescriptionListDescription><code>{catalog.content_digest}</code></DescriptionListDescription>
                <DescriptionListTerm>Artifact schema version</DescriptionListTerm>
                <DescriptionListDescription>{catalog.schema_version}</DescriptionListDescription>
                <DescriptionListTerm>Collector semantics version</DescriptionListTerm>
                <DescriptionListDescription>{catalog.collector_semantics_version}</DescriptionListDescription>
                <DescriptionListTerm>Family completeness</DescriptionListTerm>
                <DescriptionListDescription>
                  Booleans: {catalog.booleans_complete ? "complete" : "incomplete"} · Ports: {catalog.ports_complete ? "complete" : "incomplete"}
                </DescriptionListDescription>
                <DescriptionListTerm>Imported</DescriptionListTerm>
                <DescriptionListDescription>{utcTimestamp(catalog.created_at)}</DescriptionListDescription>
                {catalog.imports.map((import_) => (
                  <DescriptionListTerm key={import_.id}>Import source</DescriptionListTerm>
                ))}
                {catalog.imports.map((import_) => (
                  <DescriptionListDescription key={import_.id}>
                    {import_.source_path ?? "No source path recorded"}
                    {import_.acquisition_metadata && Object.keys(import_.acquisition_metadata).length > 0 && (
                      <> · {JSON.stringify(import_.acquisition_metadata)}</>
                    )}
                    {` · ${utcTimestamp(import_.imported_at)}`}
                  </DescriptionListDescription>
                ))}
              </DescriptionList>
            </CardBody>
          </Card>

          <div style={{ display: "flex", gap: "var(--pf-v6-global--spacer--sm)" }} className="pf-v6-u-mb-md">
            <Link
              className="pf-v6-c-button pf-m-secondary"
              to={`/configuration?family=booleans&policy_identity=${encodeURIComponent(catalog.loaded_policy_digest)}`}
            >
              Compare booleans in configuration
            </Link>
            <Link
              className="pf-v6-c-button pf-m-secondary"
              to={`/configuration?family=ports&policy_identity=${encodeURIComponent(catalog.loaded_policy_digest)}`}
            >
              Compare ports in configuration
            </Link>
          </div>

          <Card className="pf-v6-u-mb-md">
            <CardTitle>Booleans ({catalog.booleans.length})</CardTitle>
            <CardBody>
              <div className="pf-v6-c-table__responsive-wrapper">
                <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label="Catalog boolean defaults">
                  <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
                    <th className="pf-v6-c-table__th" scope="col">Boolean</th>
                    <th className="pf-v6-c-table__th" scope="col">Reference default</th>
                    <th className="pf-v6-c-table__th" scope="col">Description</th>
                  </tr></thead>
                  <tbody className="pf-v6-c-table__tbody">
                    {catalog.booleans.map((boolean) => (
                      <tr className="pf-v6-c-table__tr" key={boolean.name}>
                        <td className="pf-v6-c-table__td" data-label="Boolean"><code>{boolean.name}</code></td>
                        <td className="pf-v6-c-table__td" data-label="Reference default">{boolean.default_value ? "On" : "Off"}</td>
                        <td className="pf-v6-c-table__td" data-label="Description">{boolean.description || "No description"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardTitle>Port mappings ({catalog.port_mappings.length})</CardTitle>
            <CardBody>
              <div className="pf-v6-c-table__responsive-wrapper">
                <table className="pf-v6-c-table pf-m-compact pf-m-grid-md" aria-label="Catalog port mappings">
                  <thead className="pf-v6-c-table__thead"><tr className="pf-v6-c-table__tr">
                    <th className="pf-v6-c-table__th" scope="col">Protocol</th>
                    <th className="pf-v6-c-table__th" scope="col">Port range</th>
                    <th className="pf-v6-c-table__th" scope="col">SELinux type</th>
                  </tr></thead>
                  <tbody className="pf-v6-c-table__tbody">
                    {catalog.port_mappings.map((port) => (
                      <tr className="pf-v6-c-table__tr" key={`${port.protocol}-${port.start}-${port.end}-${port.type}`}>
                        <td className="pf-v6-c-table__td" data-label="Protocol">{port.protocol}</td>
                        <td className="pf-v6-c-table__td" data-label="Port range">{port.start === port.end ? port.start : `${port.start}-${port.end}`}</td>
                        <td className="pf-v6-c-table__td" data-label="SELinux type"><code>{port.type}</code></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardBody>
          </Card>
        </>
      )}
    </>
  );
}
