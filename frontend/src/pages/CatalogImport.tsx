import { Alert, Breadcrumb, BreadcrumbItem, Button, Card, CardBody, CardTitle, DescriptionList, DescriptionListDescription, DescriptionListTerm, Form, FormGroup, TextInput, Title } from "@patternfly/react-core";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { confirmCatalogImport, previewCatalogImport, type CatalogImportPreviewResponse } from "../api/catalogs";
import { ApiError } from "../api/client";

export function CatalogImport() {
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [preview, setPreview] = useState<CatalogImportPreviewResponse["preview"] | null>(null);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const validation = useMutation({
    mutationFn: () => previewCatalogImport(file!, name === "" ? undefined : name),
    onSuccess: (result) => setPreview(result.preview)
  });
  const confirmation = useMutation({
    mutationFn: () => {
      if (!file || !preview?.preview_token || !preview.expires_at || Date.now() >= Date.parse(preview.expires_at)) {
        throw new ApiError(422, "invalid_preview", "Preview expired or unavailable; validate again");
      }
      return confirmCatalogImport(file, preview.preview_token);
    },
    onSuccess: async (result) => {
      await Promise.all(["catalogs", "catalog", "configuration", "host-configuration"].map((key) => queryClient.invalidateQueries({ queryKey: [key] })));
      navigate(`/catalogs/${result.catalog.id}`, { replace: true, state: { catalogImportOutcome: result.outcome } });
    },
    onError: (error) => {
      if (error instanceof ApiError && ["invalid_preview", "preview_bytes_changed", "loaded_policy_conflict"].includes(error.code)) setPreview(null);
    }
  });
  const pending = validation.isPending || confirmation.isPending;
  const error = confirmation.error ?? validation.error;
  const resetPreview = () => { setPreview(null); validation.reset(); confirmation.reset(); };

  return (
    <>
      <Breadcrumb className="pf-v6-u-mb-sm"><BreadcrumbItem><Link to="/catalogs">Catalogs</Link></BreadcrumbItem><BreadcrumbItem isActive>Import catalog</BreadcrumbItem></Breadcrumb>
      <Title headingLevel="h1" size="2xl">Import catalog</Title>
      <p>Choose a UTF-8 JSON catalog artifact (up to 2 MiB). Validation previews the import without saving catalog data. Confirmation uploads the same file again and revalidates it.</p>
      <Alert isInline variant="info" title="Validation is not vendor review" className="pf-v6-u-my-md">
        A valid supported artifact does not establish that it was produced or reviewed by the distribution vendor or SECentral. Acquisition metadata is submitted evidence, not a trusted-publisher claim.
      </Alert>
      {error && <Alert isInline variant="danger" title="Catalog import could not proceed">{error.message}</Alert>}
      <Form onSubmit={(event) => { event.preventDefault(); setPreview(null); confirmation.reset(); validation.mutate(); }}>
        <FormGroup label="JSON artifact" fieldId="catalog-artifact" isRequired>
          <input id="catalog-artifact" type="file" accept=".json,application/json" required disabled={pending} onChange={(event) => { setFile(event.target.files?.[0] ?? null); resetPreview(); }} />
        </FormGroup>
        <FormGroup label="Initial display name (optional)" fieldId="catalog-initial-name">
          <TextInput id="catalog-initial-name" value={name} maxLength={120} isDisabled={pending} onChange={(_event, value) => { setName(value); resetPreview(); }} />
          <p>Leave empty for the distribution label. Used only for a new revision; existing names and archive state are preserved.</p>
        </FormGroup>
        <div>
          <Button type="submit" isDisabled={pending || !file} isLoading={validation.isPending}>Validate / Preview</Button>
          <Button variant="link" isDisabled={pending} onClick={() => navigate("/catalogs")}>Cancel</Button>
        </div>
      </Form>
      {preview && (
        <Card className="pf-v6-u-mt-lg">
          <CardTitle>Import preview — {preview.display_name}</CardTitle>
          <CardBody>
            <Alert isInline variant={preview.outcome === "conflict" ? "warning" : "info"} title={preview.outcome === "conflict" ? "Import conflict" : preview.outcome === "reuse_existing_revision" ? "Reuse existing revision" : "Create new revision"}>
              {preview.reason}
              {preview.existing_revision && <p>Revision {preview.existing_revision.id}: {preview.existing_revision.display_name} · {preview.existing_revision.lifecycle}. Reimport does not rename or unarchive it.</p>}
            </Alert>
            <DescriptionList className="pf-v6-u-my-md">
              <DescriptionListTerm>Compatibility</DescriptionListTerm><DescriptionListDescription>Supported schema {preview.schema_version} · collector semantics {preview.collector_semantics_version} · validation {preview.validation_status}</DescriptionListDescription>
              <DescriptionListTerm>Platform</DescriptionListTerm><DescriptionListDescription>{preview.platform.distribution} {preview.platform.major_version} · {preview.platform.architecture} · {preview.policy_type}</DescriptionListDescription>
              <DescriptionListTerm>Content digest</DescriptionListTerm><DescriptionListDescription><code>{preview.content_digest}</code></DescriptionListDescription>
              <DescriptionListTerm>Loaded-policy digest</DescriptionListTerm><DescriptionListDescription><code>{preview.loaded_policy_digest}</code></DescriptionListDescription>
              <DescriptionListTerm>Families</DescriptionListTerm><DescriptionListDescription>Booleans: {preview.families.booleans.status} ({preview.families.booleans.count}) · Ports: {preview.families.ports.status} ({preview.families.ports.count}) · {preview.families.ports.protocols.join(", ")}</DescriptionListDescription>
              <DescriptionListTerm>Policy packages</DescriptionListTerm><DescriptionListDescription>{preview.policy_packages.map((pkg, index) => <div key={index}>{pkg.name} {pkg.epoch}:{pkg.version}-{pkg.release}.{pkg.architecture}</div>)}</DescriptionListDescription>
              <DescriptionListTerm>Submitted acquisition</DescriptionListTerm><DescriptionListDescription>{preview.acquisition.collector_version} · {preview.acquisition.collected_at}</DescriptionListDescription>
            </DescriptionList>
            {preview.expires_at && <p>Preview expires at {new Date(preview.expires_at).toISOString()}. Database state is rechecked at confirmation.</p>}
            {preview.preview_token && preview.outcome !== "conflict" && <Button isDisabled={pending} isLoading={confirmation.isPending} onClick={() => confirmation.mutate()}>
              {preview.outcome === "reuse_existing_revision" ? "Record another import of existing revision" : "Import new catalog revision"}
            </Button>}
          </CardBody>
        </Card>
      )}
    </>
  );
}
