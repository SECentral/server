# Managing catalogs

Catalogs provide reference information for comparing a host's SELinux
configuration. Each catalog entry represents one immutable revision: changing
its name or availability does not change its contents.

## Rename a catalog

Open **Catalogs**, select a catalog, edit **Display name**, then select **Save
name**.

Names are trimmed, must contain 1–120 characters, and cannot contain control
characters. Duplicate names are allowed; use the revision ID and catalog content
digest to distinguish entries with the same name.

A name is an operator label, not a statement about the catalog's source. Renaming
a distribution reference does not turn it into an organizational baseline or
change its applicability.

## Archive or restore a catalog

On the catalog detail page, select **Archive** to exclude the revision from new
automatic reference selection. Archived catalogs remain listed and inspectable,
including their contents, identities and import provenance.

Select **Unarchive** to make the revision eligible again. Repeating either action
has no additional effect. Archiving does not delete the catalog or mean its
contents became invalid.

## Understand reference selection

Automatic comparisons consider active catalogs only. SECentral prefers a
reference with the host's exact loaded-policy digest. Otherwise, Boolean/port
comparison can use references for the same distribution, major release,
architecture and policy type when all eligible candidates agree on complete
Boolean/port content.

Archiving a catalog can therefore change the selected reference, leave another
eligible reference available, or leave no reference available. Restoring a
catalog does not guarantee selection: conflicting candidate content makes the
automatic reference unavailable rather than selecting the newest catalog.

Catalog contents and import evidence are retained after rename or archive.
A newly requested comparison uses current active references, even when its host
snapshot is older; it should not be treated as a saved historical comparison.

## Check identity and provenance

The detail page separates the editable name and Active/Archived status from:

- **Catalog content digest:** identifies the immutable reference contents.
- **Loaded-policy digest:** identifies the binary policy observed during acquisition.
- **Distribution and policy package information:** describes the source platform.
- **Import source and acquisition metadata:** records where and how the artifact
  was obtained.

Import and digest validation do not certify a publisher or establish vendor
review. Active/Archived describes availability for new comparisons, not trust.

## Manage catalogs through the API

Management requests require an operator session and the `X-CSRF-Token` header
obtained from a session/API response.

| Method and path | Input |
| --- | --- |
| `PATCH /api/v1/catalogs/:id/name` | JSON `{ "display_name": "RHEL reference" }` |
| `POST /api/v1/catalogs/:id/archive` | Empty body |
| `POST /api/v1/catalogs/:id/unarchive` | Empty body |

Successful requests return the current catalog detail, including its name,
lifecycle and immutable identity. Unexpected body/query fields and invalid names
are rejected with HTTP 422. Concurrent renames use the last accepted write;
rename and archive actions preserve each other's changes.

See the [OpenAPI contract](../openapi/openapi.yaml) for response schemas,
authentication requirements and error responses.
