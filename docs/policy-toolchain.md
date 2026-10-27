# Binary policy-analysis toolchain

Production and development containers use **SETools 4.6.0 with libsepol 3.11**.
Both images build the tools using `script/build_policy_tools.sh`, with upstream
release versions and SHA-256 checksums pinned in the script.

The tools are installed under `/opt/secentral-policy-tools`. The Python extension's
rpath selects the bundled libsepol instead of the older system library. Build
dependencies stay in a separate container stage; runtime source licenses are
retained with the tools.

## Compatibility and verification

SETools and libsepol must be tested together: updating the Python package alone
does not establish binary-policy format support. This configuration reads kernel
policy formats 33 and 35, including policies from AlmaLinux 9 and Fedora 44.

Both container builds assert the SETools version and libsepol support through
policy format 35. Rebuild the production and development images when changing
the toolchain. See [Testing](../TEST.md) for container build and regression-test
commands.

## Failure behavior

Policy subprocesses have bounded runtime, CPU, memory and combined output.
Failed stdout is retained alongside stderr as diagnostic output because
`sesearch` can write policy-load errors to stdout. Failed output is never accepted
as successful policy facts.

Rule failures record the evaluator version and exit status. A policy-load failure
may indicate an unsupported format in the installed SETools/libsepol toolchain;
it does not establish that the policy bytes are malformed. Identity mismatches,
missing tools, evaluation errors, successful no-match results and authoritative
empty domain sets remain distinct.

Cached analysis errors are not automatically retried when an image changes.
Re-evaluating policy analysis is separate from replaying retained audit events.
