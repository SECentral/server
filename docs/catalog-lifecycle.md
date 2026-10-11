# Managing catalogs

Catalogs provide reference information for comparing a host's SELinux
configuration. Each catalog entry represents one immutable revision: changing
its name or availability does not change its contents.

## Import a catalog

1. Open **Catalogs → Import catalog** and choose a UTF-8 JSON catalog artifact.
2. Optionally enter an initial display name. Leave it empty to use the
   distribution label. This name applies only when creating a new revision.
3. Select **Validate / Preview**. Review the schema/collector compatibility,
   immutable digests, platform/packages, submitted acquisition information,
   complete Boolean/port counts and proposed create/reuse outcome.
4. Select **Import new catalog revision** or **Record another import of existing
   revision** to confirm. A conflict has no confirmation action.

Selecting a file and previewing it save no catalog data. Confirmation sends the
same file again, revalidates it and rechecks current database state. A new revision
starts active. Reimport appends import evidence but does not rename an existing
catalog or unarchive it; those remain separate actions on its detail page.

Previews expire after ten minutes and belong to the signed-in session. If the
file or initial name changes, validate again. Cancel, reload or leaving the
import page discards the browser's preview; no artifact upload is retained on the
server between requests. Once confirmation has been sent, navigation does not
cancel the server transaction.

If confirmation succeeds but its response is lost, retrying can record another
import of the same revision. Semantic content is deduplicated; each successful
attempt retains its own import evidence. The result page explains whether a
revision was created or reused, including whether it remains archived.

The supported format is schema 1 / collector semantics V3 with complete Boolean
and port families. Organizational/custom-reference formats are not supported.
Artifacts are limited to 2 MiB, 32 JSON nesting levels, 20,000 entries per family
and 256 policy packages. Invalid, missing or incomplete families are rejected,
not shown as empty inventories. Validation does not establish vendor/SECentral
review or publisher authenticity.

Administrative validation/import tasks remain available inside the server's
Rails container and use the same validator/importer:

```sh
bundle exec rake 'secentral:catalog:validate[/path/to/catalog.json]'
bundle exec rake 'secentral:catalog:import[/path/to/catalog.json]'
```

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

Open a host's **SELinux configuration** page and use **Comparison reference**.
The default is **Automatic**. The page explains whether automatic selection used
the exact observed policy digest or major-release Boolean/port agreement.

To examine another reference, choose a specific active revision. This is an
**Explicit reference** for the viewed comparison, not proof that the reference
matches the host's loaded policy or is its distribution default. The page shows
the revision/content digest and warns when loaded-policy identities differ.
Known incompatible architecture or policy type makes family comparison unavailable.

The choice is encoded in `reference_revision_id` in the page URL, so reload/share
retains that view. It does not save a host/user/fleet preference. Select **Return
to automatic** to remove it. Revisions are listed with relevant platform context
first; relevance is not equivalence. Duplicate names are distinguished by revision
ID and content digest. Archived revisions are not ordinary selectable targets.

Selection outcomes are distinct:

| Outcome | Meaning |
| --- | --- |
| Automatic exact | Active revision selected by the trusted observed loaded-policy digest |
| Automatic agreement | Active major-release candidates agree on complete Boolean/port facts; this does not establish binary equivalence |
| Explicit | An operator chose this immutable active comparison target |
| Absent | No active applicable automatic reference exists, including archived-only matches |
| Ambiguous | Eligible candidates have incompatible Boolean/port facts; none is chosen |
| Unavailable | Missing trusted identity/context, incomplete reference facts, or an archived explicit target prevents selection/use |

Selecting a revision is separate from family usability. Boolean/port comparison
can remain Unknown, Unavailable, Partial or Stale. Missing host observations are
never filled from reference defaults. Partial port evidence cannot prove a missing
mapping; stale observations pause current comparison. These limits apply equally
to automatic and explicit selection. No other catalog families are compared.

Automatic comparisons consider active catalogs only. SECentral prefers a
reference with the host's exact loaded-policy digest. Otherwise, Boolean/port
comparison can use references for the same distribution, major release,
architecture and policy type when all eligible candidates agree on complete
Boolean/port content.

Archiving a catalog can therefore change the selected reference, leave another
eligible reference available, or leave no reference available. Restoring a
catalog does not guarantee selection: conflicting candidate content makes the
automatic reference unavailable rather than selecting the newest catalog.
Importing a new active revision can also change the candidate set or introduce
ambiguity. Import does not set a host preference or make a catalog the preferred
reference.

Catalog contents and import evidence are retained after rename or archive.
A newly requested comparison uses current active references, even when its host
snapshot is older; it should not be treated as a saved historical comparison.
The host configuration page uses the current heartbeat observation. Event-linked
snapshots and old revisions are retained separately, but there is no general
stored reference-selection pin/result. A fresh evaluation of an older snapshot
is today's comparison, not evidence of which catalog was used at event time.

## Check identity and provenance

The detail page separates the editable name and Active/Archived status from:

- **Catalog content digest:** identifies the immutable reference contents.
- **Loaded-policy digest:** identifies the binary policy observed during acquisition.
- **Distribution and policy package information:** describes the source platform.
- **Import source and acquisition metadata:** records where and how the artifact
  was obtained.

Import and digest validation do not certify a publisher or establish vendor
review. Active/Archived describes availability for new comparisons, not trust.
Browser imports record **Operator upload**, the authenticated operator, import
time and exact submitted bytes. The filename does not establish authority and
browser/server temporary paths are not recorded as upload provenance.

## Manage catalogs through the API

Management requests require an operator session and the `X-CSRF-Token` header
obtained from a session/API response.

Host comparison uses authenticated `GET /api/v1/hosts/:id/configuration`. Omit
`reference_revision_id` for automatic selection, or supply an immutable revision
ID for a temporary explicit target. The response adds `selection` with mode,
status, basis, selected identity, bounded candidate context and per-family
applicability, plus summary-only active `reference_options`.

Absent/ambiguous/family-unavailable outcomes are ordinary successful responses.
An archived explicit target returns `selection.status: unavailable` with reason
`archived_reference`, never a substituted reference. Malformed IDs return 422;
nonexistent revisions return 404. For row interpretation use `selection.families`:
the legacy `comparison.available` flag indicates displayable reference overlays,
not that every host family or row is comparable.

| Method and path | Input |
| --- | --- |
| `POST /api/v1/catalogs/import-preview` | Exact artifact bytes; optional `display_name` query parameter |
| `POST /api/v1/catalogs/import-confirm` | The same exact bytes and the returned receipt in `X-Catalog-Preview` |
| `PATCH /api/v1/catalogs/:id/name` | JSON `{ "display_name": "RHEL reference" }` |
| `POST /api/v1/catalogs/:id/archive` | Empty body |
| `POST /api/v1/catalogs/:id/unarchive` | Empty body |

Successful name/archive operations return current catalog detail, including name,
lifecycle and immutable identity. Unexpected body/query fields and invalid names
are rejected with HTTP 422. Concurrent renames use the last accepted write;
rename and archive actions preserve each other's changes.

See the [OpenAPI contract](../openapi/openapi.yaml) for response schemas,
authentication requirements and error responses.

Import endpoints require `Content-Type: application/octet-stream`, with JSON
artifact bytes as the raw body—not a JSON wrapper or multipart upload. Preview
returns a session-bound signed receipt, create/reuse/conflict classification and
an expiry. Confirmation rejects changed bytes or an expired/foreign receipt and
reruns authoritative validation and conflict checks. Preview is not a reservation:
a create preview can become reuse or conflict before confirmation. No preview
blob is stored server-side; the receipt is reusable within its expiry, not an
idempotency key.

Import validation errors include a bounded `error.code`, safe message and optional
field path. Oversize uploads return 413; incorrect media handling 415; validation,
name, preview or CSRF failures 422; a conflict discovered at confirmation 409.
No successful import evidence is recorded on failure.
