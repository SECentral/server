import {
  Alert,
  Breadcrumb,
  BreadcrumbItem,
  Button,
  Card,
  CardBody,
  CardTitle,
  ClipboardCopy,
  CodeBlock,
  CodeBlockCode,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  ExpandableSection,
  Flex,
  Form,
  FormGroup,
  Label,
  Pagination,
  SearchInput,
  Spinner,
  Stack,
  Tab,
  Tabs,
  TabTitleText,
  TextInput,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem
} from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useLocation, useParams, useSearchParams } from "react-router-dom";
import { fetchCatalog, renameCatalog, setCatalogArchived, type CatalogDetail as CatalogData } from "../api/catalogs";
import { CatalogImportComparison } from "../components/CatalogImportComparison";
import { osDisplayName } from "../platform";
import PencilAltIcon from "@patternfly/react-icons/dist/esm/icons/pencil-alt-icon";
import { PAGE_SIZES, pageSize } from "../pagination";

function CatalogHeader({ catalog }: { catalog: CatalogData }) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: (action: "rename" | "archive" | "unarchive") => action === "rename"
      ? renameCatalog(catalog.id, name ?? catalog.display_name)
      : setCatalogArchived(catalog.id, action === "archive"),
    onSuccess: async (result) => {
      queryClient.setQueryData(["catalog", String(catalog.id)], result);
      setName(null);
      setEditing(false);
      await Promise.all(["catalogs", "configuration", "host-configuration"].map((key) => queryClient.invalidateQueries({ queryKey: [key] })));
    }
  });

  return (
    <header className="app-resource-header app-page-header">
      <div>
        <Flex alignItems={{ default: "alignItemsCenter" }} gap={{ default: "gapSm" }}>
          <Title headingLevel="h1" size="2xl">{catalog.display_name} SELinux policy</Title>
          <Button variant="plain" icon={<PencilAltIcon />} aria-label="Rename catalog" aria-controls={editing ? "catalog-name-edit" : undefined} isExpanded={editing} isDisabled={mutation.isPending} onClick={() => { setEditing(!editing); setName(null); }} />
          <Label color="grey" isCompact>{catalog.lifecycle === "archived" ? "Archived" : "Active"}</Label>
        </Flex>
        <p className="pf-v6-u-color-200">Imported reference knowledge, not observed host state. Import does not establish vendor review.</p>
        {mutation.isError && <Alert isInline variant="danger" title="Could not update catalog">{mutation.error.message}</Alert>}
        {mutation.isSuccess && <Alert isInline variant="success" title="Catalog management updated" />}
        {editing && <Form id="catalog-name-edit" onSubmit={(event) => { event.preventDefault(); mutation.mutate("rename"); }} className="pf-v6-u-mt-md">
          <FormGroup label="Display name" fieldId="catalog-display-name" isRequired>
            <TextInput id="catalog-display-name" autoFocus value={name ?? catalog.display_name} onChange={(_event, value) => setName(value)} maxLength={120} isRequired isDisabled={mutation.isPending} />
          </FormGroup>
          <Flex gap={{ default: "gapSm" }}>
            <Button type="submit" isDisabled={mutation.isPending || name === null || !name.trim()}>Save name</Button>
            <Button variant="link" isDisabled={mutation.isPending} onClick={() => { setEditing(false); setName(null); }}>Cancel rename</Button>
          </Flex>
        </Form>}
      </div>
      <Button variant="secondary" isDisabled={mutation.isPending} title={catalog.lifecycle === "archived" ? "Restore this revision to active reference selection." : "Archiving retains this revision and its evidence but excludes it from new automatic comparisons."} onClick={() => mutation.mutate(catalog.lifecycle === "archived" ? "unarchive" : "archive")}>
        {catalog.lifecycle === "archived" ? "Unarchive catalog" : "Archive catalog"}
      </Button>
    </header>
  );
}

function policyPackageLabel(package_: Record<string, unknown>): string {
  return [package_.name, package_.epoch, package_.version, package_.release, package_.architecture]
    .filter((value) => value !== undefined && value !== null)
    .map(String)
    .join("-") || "Not recorded";
}

function utcTimestamp(iso: string): string {
  return `${new Date(iso).toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

function inventoryPage(value: string | null, total: number, perPage: number): number {
  const requested = Number(value ?? 1);
  return Number.isSafeInteger(requested) && requested > 0 ? Math.min(requested, Math.max(1, Math.ceil(total / perPage))) : 1;
}

export function CatalogDetail() {
  const location = useLocation();
  const { id } = useParams();
  const [technicalCatalogId, setTechnicalCatalogId] = useState<string | null>(null);
  const [searchParams, setSearchParams] = useSearchParams();
  const catalogQuery = useQuery({
    queryKey: ["catalog", id],
    queryFn: () => fetchCatalog(id as string),
    enabled: id !== undefined
  });

  const catalog = catalogQuery.data?.catalog;
  const technicalExpanded = technicalCatalogId === id;
  const family = searchParams.get("family") === "ports" ? "ports" : "booleans";
  const booleanSearch = searchParams.get("boolean_q") ?? "";
  const portSearch = searchParams.get("port_q") ?? "";
  const booleans = catalog?.booleans.filter((item) => `${item.name} ${item.description}`.toLowerCase().includes(booleanSearch.toLowerCase())) ?? [];
  const ports = catalog?.port_mappings.filter((item) => `${item.protocol}/${item.start}-${item.end} ${item.type}`.toLowerCase().includes(portSearch.toLowerCase())) ?? [];
  const booleanSize = pageSize(searchParams.get("boolean_limit"));
  const portSize = pageSize(searchParams.get("port_limit"));
  const booleanPage = inventoryPage(searchParams.get("boolean_page"), booleans.length, booleanSize);
  const portPage = inventoryPage(searchParams.get("port_page"), ports.length, portSize);
  const update = (values: Record<string, string | null>) => setSearchParams((previous) => {
    const next = new URLSearchParams(previous);
    for (const [key, value] of Object.entries(values)) {
      if (!value) next.delete(key);
      else next.set(key, value);
    }
    return next;
  });

  return (
    <div className="app-resource-page">
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
          <CatalogHeader key={catalog.id} catalog={catalog} />
          <Stack hasGutter>
            {location.state?.catalogImportOutcome && <Alert isInline variant="success" title={location.state.catalogImportOutcome === "reuse_existing_revision" ? "Existing revision reused; import evidence appended" : "Catalog revision imported"}>
              {catalog.lifecycle === "archived" ? "This revision remains archived. Import did not change its name or availability." : "The revision is active under existing automatic applicability rules."}
            </Alert>}
            {catalog.lifecycle === "archived" && <Alert isInline variant="info" title="Archived reference">This revision remains inspectable. It is unavailable for new automatic comparisons; archive does not invalidate historical evidence.</Alert>}

            <Card component="section" aria-label="Catalog summary">
              <CardTitle component="h2">Reference details</CardTitle>
              <CardBody>
                <DescriptionList orientation={{ sm: "horizontal" }} isCompact className="catalog-reference-details">
                  <DescriptionListGroup><DescriptionListTerm>Distribution</DescriptionListTerm><DescriptionListDescription>{osDisplayName(catalog.distribution)} {catalog.major_version}</DescriptionListDescription></DescriptionListGroup>
                  <DescriptionListGroup><DescriptionListTerm>Policy</DescriptionListTerm><DescriptionListDescription>{catalog.policy_type} / {catalog.architecture} · kernel policy format {catalog.kernel_policy_version}</DescriptionListDescription></DescriptionListGroup>
                  <DescriptionListGroup><DescriptionListTerm>Policy packages</DescriptionListTerm><DescriptionListDescription>{catalog.policy_packages.length ? catalog.policy_packages.map((package_, index) => <div key={index}>{policyPackageLabel(package_)}</div>) : "Not recorded"}</DescriptionListDescription></DescriptionListGroup>
                  <DescriptionListGroup><DescriptionListTerm>Family completeness</DescriptionListTerm><DescriptionListDescription>Booleans: {catalog.booleans_complete ? "complete" : "incomplete"} · Ports: {catalog.ports_complete ? "complete" : "incomplete"}</DescriptionListDescription></DescriptionListGroup>
                  <DescriptionListGroup><DescriptionListTerm>Imported</DescriptionListTerm><DescriptionListDescription><time dateTime={catalog.created_at}>{utcTimestamp(catalog.created_at)}</time></DescriptionListDescription></DescriptionListGroup>
                </DescriptionList>
              </CardBody>
            </Card>

            <Tabs id="catalog-families" activeKey={family} onSelect={(_event, key) => update({ family: String(key) })} aria-label="Catalog families" tabListAriaLabel="Catalog families" mountOnEnter unmountOnExit>
              <Tab eventKey="booleans" title={<TabTitleText>Booleans ({catalog.booleans.length})</TabTitleText>}>
              <Card component="section" aria-label="Boolean reference" className="resource-table-card"><CardBody>
              <div className="table-section-heading">
                <Title headingLevel="h2" size="lg">Booleans ({catalog.booleans.length})</Title>
                {catalog.lifecycle === "active" && <Link className="pf-v6-c-button pf-m-link" to={`/configuration?family=booleans&policy_identity=${encodeURIComponent(catalog.loaded_policy_digest)}`}>Compare booleans in configuration</Link>}
              </div>
              <Toolbar aria-label="Catalog boolean filters" hasNoPadding className="pf-v6-u-mb-md"><ToolbarContent><ToolbarItem>
                <SearchInput aria-label="Search catalog booleans" placeholder="Search by name or description" value={booleanSearch} onChange={(_event, value) => update({ boolean_q: value, boolean_page: null })} onClear={() => update({ boolean_q: null, boolean_page: null })} />
              </ToolbarItem></ToolbarContent></Toolbar>
              {!catalog.booleans_complete && <p>Incomplete reference inventory; omitted booleans are not established as absent.</p>}
              {booleans.length ? <Table role="table" aria-label="Catalog boolean defaults" variant="compact" gridBreakPoint="grid-lg">
                <Thead><Tr><Th>Boolean</Th><Th>Reference default</Th><Th>Description</Th></Tr></Thead>
                <Tbody>{booleans.slice((booleanPage - 1) * booleanSize, booleanPage * booleanSize).map((boolean) => <Tr key={boolean.name}>
                  <Td dataLabel="Boolean"><code>{boolean.name}</code></Td><Td dataLabel="Reference default">{boolean.default_value ? "On" : "Off"}</Td><Td dataLabel="Description">{boolean.description || "No description"}</Td>
                </Tr>)}</Tbody>
              </Table> : <p>{booleanSearch ? "No booleans match this search." : "No Boolean entries included in this catalog."}</p>}
              <div className="table-pagination"><Pagination itemCount={booleans.length} page={booleanPage} perPage={booleanSize} perPageOptions={PAGE_SIZES.map((value) => ({ title: String(value), value }))} titles={{ paginationAriaLabel: "Catalog boolean pagination" }} onSetPage={(_event, page) => update({ boolean_page: String(page) })} onPerPageSelect={(_event, size) => update({ boolean_limit: String(size), boolean_page: null })} /></div>
              </CardBody></Card>
              </Tab>

              <Tab eventKey="ports" title={<TabTitleText>Ports ({catalog.port_mappings.length})</TabTitleText>}>
              <Card component="section" aria-label="Port reference" className="resource-table-card"><CardBody>
              <div className="table-section-heading">
                <Title headingLevel="h2" size="lg">Port mappings ({catalog.port_mappings.length})</Title>
                {catalog.lifecycle === "active" && <Link className="pf-v6-c-button pf-m-link" to={`/configuration?family=ports&policy_identity=${encodeURIComponent(catalog.loaded_policy_digest)}`}>Compare ports in configuration</Link>}
              </div>
              <Toolbar aria-label="Catalog port filters" hasNoPadding className="pf-v6-u-mb-md"><ToolbarContent><ToolbarItem>
                <SearchInput aria-label="Search catalog ports" placeholder="Search by port, protocol, or type" value={portSearch} onChange={(_event, value) => update({ port_q: value, port_page: null })} onClear={() => update({ port_q: null, port_page: null })} />
              </ToolbarItem></ToolbarContent></Toolbar>
              {!catalog.ports_complete && <p>Incomplete reference inventory; omitted port mappings are not established as absent.</p>}
              {ports.length ? <Table role="table" aria-label="Catalog port mappings" variant="compact" gridBreakPoint="grid-lg">
                <Thead><Tr><Th>Protocol</Th><Th>Port range</Th><Th>SELinux type</Th></Tr></Thead>
                <Tbody>{ports.slice((portPage - 1) * portSize, portPage * portSize).map((port) => <Tr key={`${port.protocol}-${port.start}-${port.end}-${port.type}`}>
                  <Td dataLabel="Protocol">{port.protocol}</Td><Td dataLabel="Port range">{port.start === port.end ? port.start : `${port.start}-${port.end}`}</Td><Td dataLabel="SELinux type"><code>{port.type}</code></Td>
                </Tr>)}</Tbody>
              </Table> : <p>{portSearch ? "No port mappings match this search." : "No port mappings included in this catalog."}</p>}
              <div className="table-pagination"><Pagination itemCount={ports.length} page={portPage} perPage={portSize} perPageOptions={PAGE_SIZES.map((value) => ({ title: String(value), value }))} titles={{ paginationAriaLabel: "Catalog port pagination" }} onSetPage={(_event, page) => update({ port_page: String(page) })} onPerPageSelect={(_event, size) => update({ port_limit: String(size), port_page: null })} /></div>
              </CardBody></Card>
              </Tab>
            </Tabs>

            <ExpandableSection toggleText="Technical details & policy digests" isExpanded={technicalExpanded} onToggle={(_event, open) => setTechnicalCatalogId(open ? id ?? null : null)}>
              {technicalExpanded && <Stack hasGutter>
                <p>Acquisition metadata is submitted evidence. Import and a valid digest do not establish review, trusted publisher identity or certified vendor origin.</p>
                <DescriptionList orientation={{ sm: "horizontal" }} isCompact isFluid>
                  <DescriptionListGroup><DescriptionListTerm>Immutable revision ID</DescriptionListTerm><DescriptionListDescription>{catalog.id}</DescriptionListDescription></DescriptionListGroup>
                  <DescriptionListGroup><DescriptionListTerm>Loaded-policy digest</DescriptionListTerm><DescriptionListDescription><ClipboardCopy variant="inline-compact" isReadOnly isCode copyAriaLabel="Copy loaded-policy digest" textAriaLabel="Loaded-policy digest">{catalog.loaded_policy_digest}</ClipboardCopy></DescriptionListDescription></DescriptionListGroup>
                  <DescriptionListGroup><DescriptionListTerm>Catalog content digest</DescriptionListTerm><DescriptionListDescription><ClipboardCopy variant="inline-compact" isReadOnly isCode copyAriaLabel="Copy catalog content digest" textAriaLabel="Catalog content digest">{catalog.content_digest}</ClipboardCopy></DescriptionListDescription></DescriptionListGroup>
                  <DescriptionListGroup><DescriptionListTerm>Artifact schema version</DescriptionListTerm><DescriptionListDescription>{catalog.schema_version}</DescriptionListDescription></DescriptionListGroup>
                  <DescriptionListGroup><DescriptionListTerm>Collector semantics version</DescriptionListTerm><DescriptionListDescription>{catalog.collector_semantics_version}</DescriptionListDescription></DescriptionListGroup>
                </DescriptionList>
                <section aria-label="Import history">
                  <Title headingLevel="h3" size="lg">Import history</Title>
                  {catalog.imports.length ? <DescriptionList isCompact>
                    {catalog.imports.map((import_) => <DescriptionListGroup key={import_.id}>
                      <DescriptionListTerm>Import #{import_.id}</DescriptionListTerm>
                      <DescriptionListDescription>
                        <p>{import_.source_kind === "operator_upload" ? "Operator upload" : import_.source_path ?? "No source recorded"}{import_.imported_by && ` · Imported by ${import_.imported_by}`}</p>
                        <time dateTime={import_.imported_at}>{utcTimestamp(import_.imported_at)}</time>
                        {import_.acquisition_metadata && Object.keys(import_.acquisition_metadata).length > 0 && <CodeBlock><CodeBlockCode>{JSON.stringify(import_.acquisition_metadata)}</CodeBlockCode></CodeBlock>}
                      </DescriptionListDescription>
                    </DescriptionListGroup>)}
                  </DescriptionList> : <p>No import records retained.</p>}
                </section>
                {catalog.imports.filter((record) => record.comparison_report && record.comparison_report.status !== "not_applicable").map((record) => <CatalogImportComparison key={record.id} report={record.comparison_report} />)}
              </Stack>}
            </ExpandableSection>
          </Stack>
        </>
      )}
    </div>
  );
}
