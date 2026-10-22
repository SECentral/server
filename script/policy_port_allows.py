"""Applicable port types for one source/class/permission in an exact policy artifact."""
import json
import sys

import setools

policy = setools.SELinuxPolicy(sys.argv[1])
source, object_class, permission = sys.argv[2:5]
port_types = set(policy.lookup_typeattr("port_type").expand())
rules = []
for rule in setools.TERuleQuery(policy, ruletype=["allow"], source=source,
                              source_indirect=True, tclass=[object_class], perms=[permission]).results():
    targets = sorted(str(t) for t in rule.target.expand() if t in port_types)
    if targets:
        rules.append({"rule": str(rule), "target_types": targets})
protocol = object_class.removesuffix("_socket")
contexts = [{"type": str(p.context.type_), "start": p.ports.low, "end": p.ports.high}
            for p in policy.portcons() if str(p.protocol) == protocol]
print(json.dumps({"rules": sorted(rules, key=lambda r: r["rule"]),
                  "port_contexts": sorted(contexts, key=lambda p: (p["start"], p["end"], p["type"])),
                  "evaluator_version": "SETools " + setools.__version__}))
