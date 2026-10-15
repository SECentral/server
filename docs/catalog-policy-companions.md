# Exact-policy companions for catalog references

Catalog JSON is the authoritative observed Boolean/port and effective permissive-domain
reference. Effective permissive membership is extracted by the standalone collector
and included inline; it requires neither a companion nor server reference analysis.
An optional compiled companion retains exact reference bytes for other uses only when
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

## Reference selection and applicability

Consume `CatalogReferenceSelection`. Automatic exact selection can supply a
reference. Major-release family-agreement fallback supplies Boolean/port authority;
it also supplies effective permissive authority only when all eligible candidates
have complete V4 inline membership, compatible extraction semantics and identical
domain sets.
An active explicit nonidentical revision can supply a chosen, non-equivalent target;
new explicit archived selection remains unavailable. Future effective-policy families
require their own comparison and applicability rules; only effective permissive
membership is currently added alongside Boolean/port comparisons.

Availability is not extraction status or applicability. Existing host analysis caches
are exact-SHA-only and reusable; catalog-only creation defers automatic analysis.
Extraction uses bounded execution and versioned results. The host's SELinux
configuration page compares effective permissive membership under exact,
unanimous compatible major-release-family, or explicit reference authority,
independently of Boolean/port comparison availability.
Retained results must pin host policy/checkpoint authority, catalog revision/content
digest, reference SHA and extractor/evaluator semantics; no historical result store
is added here.

### Inline reference extraction

`revision.reference_permissive_domains` reads the immutable imported inline family.
It does not read companion bytes, reuse a host cache, or enqueue reference jobs.
Semantics V4 catalogs require complete sorted unique domains (including `[]`),
extraction semantics 1 and the actual SETools version. All fields participate in
the canonical content digest. Missing facts remain unavailable, never empty;
incompatible extraction semantics prevent comparison.

These are collector-reported facts, not server-verified binary extraction. The
declared policy SHA binds the collector's claimed input identity; digest validation
does not independently prove the derivation or publisher authenticity. Archive
retains inline facts as well as any separately acquired companion. No dual-source
fallback or companion-storage purge is introduced.

Host analysis still uses verified exact retained bytes and bounded asynchronous
SETools execution. Host pending/failure/retry and cache-integrity behavior is
unchanged. Major-release agreement does not grant permissive authority by itself:
every eligible reference candidate must have current complete inline facts and the
same domain membership. Tool versions may differ when extraction semantics agree.

### Compare effective permissive membership

The configuration page shows **Matches reference**, **Unexpected on host**,
**Missing from host** or **Unknown**. Its API exposes all three sorted unique sets
and counts under `comparison.effective_permissive_domains`; Unknown has null sets
and counts with a stable side-specific reason. Successful empty sets on both sides
are a valid match. Tool versions may differ when both use current extraction semantics.

Automatic exact selection permits comparison when both sides are observed under
compatible extraction semantics. Automatic major-release-family selection permits
it only when all eligible references agree on complete inline membership under
compatible semantics. An active explicit target with compatible architecture/policy
type can compare nonidentical policies, without binary-equivalence assertion.
Missing/masked or stale host evidence, absent/ambiguous/archived selection,
unavailable/incompatible inline facts, candidate disagreement and pending/failed
host analysis remain Unknown. Pending host analysis refreshes asynchronously;
terminal failures are not reset by page reads and parser diagnostics are not
exposed as product reasons.

Counts and differences are prominent; matching membership and SHA/evaluator details
are secondary expandable information. Each domain list displays 20 rows per page.
The host-only effective membership view remains separate. The comparison identifies
host snapshot/observation, exact SHAs, reference revision/content digest, selection
basis and evaluator semantics/tool versions. This is current-state comparison, not
a persisted historical result or evidence of who changed policy and why.

## Licensing and distribution

The catalog JSON GPL-2.0-or-later default and MIT code licenses remain unchanged.
Initial companions are operator-supplied offline files, stored privately in PostgreSQL,
not committed to Git or automatically downloaded. Public redistribution of compiled
policy must satisfy its applicable policy license, including corresponding build
source/notices; the catalog JSON alone is not source for that binary. No public binary
bundle or per-binary licensing engine is introduced.
