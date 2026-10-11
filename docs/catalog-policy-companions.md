# Exact-policy companions for catalog references

Catalog JSON remains the authoritative observed Boolean/port reference. An optional
compiled companion enables future exact-policy-derived reference facts only when
its exact SHA-256 equals that immutable revision's `loaded_policy_digest`.
Package/OS/module/filename similarity and Boolean/port fallback cannot authorize it.

## Acquire an exact companion

On a system prepared as a distribution reference, retain exact
`/sys/fs/selinux/policy` bytes and collect JSON with the standalone collector's
required cleanliness and before/after identity checks. The following offline
recipe needs Python 3 and the existing collector, no agent credentials or network.
Run in a new private directory with sufficient permission to read loaded policy:

```sh
umask 077
python3 - /path/to/secentral-catalog-collector <<'PY'
import hashlib, json, os, subprocess, sys
limit = 16 * 1024 * 1024
def loaded():
    with open('/sys/fs/selinux/policy', 'rb') as f:
        data = f.read(limit + 1)
    if not 0 < len(data) <= limit:
        raise SystemExit('Loaded policy exceeds the supported size bound')
    return data
def sha(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()
if os.path.lexists('catalog.json') or os.path.lexists('policy.bin'):
    raise SystemExit('Use new output files')
before = loaded()
subprocess.run([sys.argv[1], 'collect', '-output', 'catalog.json'], check=True)
with open('catalog.json') as f:
    expected = json.load(f)['catalog']['policy']['loaded_policy_digest']
if sha(before) != expected or sha(loaded()) != expected:
    raise SystemExit('Policy identity changed; recollect both files')
with os.fdopen(os.open('policy.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as f:
    f.write(before)
os.chmod('catalog.json', 0o600)
print(expected)
PY
```

Equality checks the observed identities at capture/collection/verification, not
absence of every possible intervening change or custom module. On any failure,
the files are not a verified pair; recollect rather than substituting other bytes.
Review the pair and retain it in operator-controlled offline storage. Do not infer
a binary from package versions or rebuild one and call it the observed policy.

## Attach through local administrative authority

First validate/import JSON normally, then identify its immutable revision ID.
Inside the Rails container, as a trusted server administrator:

```sh
bundle exec rake 'secentral:catalog:attach_policy[REVISION_ID,/canonical/path/policy.bin,Offline reference-system capture]'
```

The acquisition basis is required, limited to 500 characters and retained with
source kind `administrative_cli`, process-user attribution where known, and
attachment time. It is an operator assertion, not independent source certification.
Use a canonical regular file: traversal, symlinks (including parent paths), devices
and FIFOs are rejected. Reads stop at 16 MiB + 1; empty/oversize input or any SHA
mismatch fails before association. No binary parser runs on attachment.

The byte store is shared with exact host artifacts, but association is explicit.
An existing identical blob is reused without changing its original first-host
metadata; no Host, heartbeat or snapshot is created. Repeating attachment retains
the original association/source/time. JSON browser import and agent ingestion do
not create catalog companion authority. No binary upload/download UI or endpoint.

## Availability and retention

Backend callers use `revision.reference_policy_artifact` for an identity-bound
availability result with revision/content digest, expected/actual policy digest,
artifact ID and acquisition evidence. Missing companion returns
`reference_policy_artifact_unavailable`; corrupt/mismatched retained bytes return
`reference_policy_artifact_invalid`. Neither means an empty effective-policy set.

JSON-only revisions remain valid. Boolean/port comparison is unchanged. Archive
does not delete a companion; new imports do not replace older companions. Attached
blobs/associations have deletion restrictions and are retained in normal database
backups. There is no purge feature or active-state retention shortcut. Unique SHA
storage bounds each blob to 16 MiB but total storage grows with distinct policies;
administrators must account for database/backups capacity.

## Selection and Plan 0058

Consume `CatalogReferenceSelection` unchanged. Automatic exact selection can supply
a verified reference input; ADR 0010 fallback supplies Boolean/port authority only.
An active explicit nonidentical revision can supply a chosen, non-equivalent target;
new explicit archived selection remains unavailable. Future effective-policy families
remain unsupported until Plan 0058 implements extraction and applicability.

Availability is not extraction status or applicability. Existing host analysis caches
are exact-SHA-only and reusable; catalog-only creation defers automatic analysis.
Plan 0058 owns safe extractor execution, versioned results, comparison and presentation.
Retained results must pin host policy/checkpoint authority, catalog revision/content
digest, reference SHA and extractor/evaluator semantics; no historical result store
is added here.

## Licensing and distribution

The catalog JSON GPL-2.0-or-later default and MIT code licenses remain unchanged.
Initial companions are operator-supplied offline files, stored privately in PostgreSQL,
not committed to Git or automatically downloaded. Public redistribution of compiled
policy must satisfy its applicable policy license, including corresponding build
source/notices; the catalog JSON alone is not source for that binary. No public binary
bundle or per-binary licensing engine is introduced.

Architecture and parser-resource handoff:
[ADR 0019](../../docs/decisions/0019-verified-catalog-policy-companions.md).
