"""Effective permissive type flags from an exact binary policy, never the host store."""
import json
import sys

try:
    import setools
except ImportError:
    print("SETools Python bindings are unavailable", file=sys.stderr)
    sys.exit(2)

policy = setools.SELinuxPolicy(sys.argv[1])
print(json.dumps({
    "domains": sorted({str(t) for t in setools.TypeQuery(policy, permissive=True).results()}),
    "evaluator_version": "SETools " + setools.__version__,
}))
