"""Chokepoint solver and counterfactual simulation over NetworkX graph.

All graph operations work with NetworkX graphs loaded from SQLite projection.
No GRAPH.COPY or FalkorDB queries are used.
"""

from __future__ import annotations

from app.graph.solver import (
    COST_ADD_CONTROL,
    COST_HARDEN_EDGE,
    COST_PATCH_SERVICE,
    COST_UPGRADE_BASE,
    COST_UPGRADE_PER_SERVICE,
    COVERAGE_TARGET,
    MAX_CANDIDATES_PER_ROUND,
    Fix,
    SolverResult,
    find_chokepoints,
    fix_from_dict,
    simulate_fixes,
)

simulate = simulate_fixes  # alias for backwards compatibility

__all__ = [
    "COST_ADD_CONTROL",
    "COST_HARDEN_EDGE",
    "COST_PATCH_SERVICE",
    "COST_UPGRADE_BASE",
    "COST_UPGRADE_PER_SERVICE",
    "COVERAGE_TARGET",
    "MAX_CANDIDATES_PER_ROUND",
    "Fix",
    "SolverResult",
    "find_chokepoints",
    "fix_from_dict",
    "simulate_fixes",
    "simulate",
]
