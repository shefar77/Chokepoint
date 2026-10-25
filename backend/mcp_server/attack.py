"""Attack-path enumeration and the hop predicates of PRD 7.1.

Uses the new app.graph modules for NetworkX-based analysis instead of FalkorDB.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterator

from app.graph.projection import SecurityProjection, load_projection
from app.graph.attack import (
    Modifications,
    enumerate_attack_paths as enumerate_paths,
    live_exploits,
    check_finding,
    blast_radius,
    reachable_set,
    total_weight,
)

log = logging.getLogger("chokepoint.attack")

CHAIN_CAP = 20000
CROWN_CLASSIFICATIONS = frozenset({"pci", "pii", "secrets"})

# Re-export the new implementations from app.graph.attack
Modifications = Modifications

# Re-export functions
enumerate_attack_paths = enumerate_paths
live_exploits = live_exploits
reachable_set = reachable_set
total_weight = total_weight
check_finding = check_finding
cypher_candidates = lambda proj, max_hops: (len(enumerate_attack_paths(proj, max_hops=max_hops, top_k=0)), "NetworkX enumeration")