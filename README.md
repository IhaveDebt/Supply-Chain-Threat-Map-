
---

# 7 — Supply-Chain Threat Map (package_graph.py)

**File:** `src/package_graph.py`
```python
#!/usr/bin/env python3
"""
Supply-Chain Threat Map - package_graph.py

- Build dependency graph from sample package manifests (simulated)
- Compute blast radius for a given package
"""

import json
from collections import defaultdict, deque

def build_graph(manifests):
    graph = defaultdict(list)
    for pkg, deps in manifests.items():
        for d in deps:
            graph[pkg].append(d)
    return graph

def blast_radius(graph, compromised_pkg, depth=3):
    q = deque([(compromised_pkg, 0)])
    seen = set([compromised_pkg])
    affected = set()
    while q:
        pkg, dist = q.popleft()
        if dist == 0:
            pass
        for p, deps in graph.items():
            if pkg in deps and p not in seen:
                seen.add(p)
                affected.add(p)
                if dist+1 < depth:
                    q.append((p, dist+1))
    return affected

def demo():
    manifests = {
        "appA": ["lib1","lib2"],
        "lib1": ["lib3"],
        "lib2": ["lib3","lib4"],
        "lib3": ["core"],
        "lib4": [],
        "core": []
    }
    g = build_graph(manifests)
    print("Blast from lib3:", blast_radius(g, "lib3", depth=3))

if __name__ == "__main__":
    demo()
