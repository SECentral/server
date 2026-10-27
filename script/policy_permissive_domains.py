"""Effective permissive type flags from an exact binary policy, never the host store."""
import json
import sys

from policy_tools import load_policy, setools

policy = load_policy(sys.argv[1])
print(json.dumps({
    "domains": sorted({str(t) for t in setools.TypeQuery(policy, permissive=True).results()}),
    "evaluator_version": "SETools " + setools.__version__,
}))
