"""Graph analysis: NetworkX-based attack paths, scoring, chokepoints, simulation."""

from typing import Any

from .projection import SecurityProjection, load_projection
from .attack import (
    enumerate_attack_paths,
    check_finding,
    blast_radius,
    Modifications,
)  # CallEdge, Projection are no longer exported from here

from .scoring import evaluate_finding, score_path, ExploitCheck, ScoreBreakdown
from .solver import find_chokepoints, simulate_fixes, Fix
from .algorithms import betweenness_centrality, pagerank, weakly_connected, shortest_path


def envelope(
    summary: str,
    data: Any = None,
    *,
    cypher: list[str] | None = None,
    touched_ids: list[str] | None = None,
    rows: int | None = None,
    latency_ms: float | None = None,
    **extra: Any,
) -> dict[str, Any]:
    res: dict[str, Any] = {
        "summary": summary,
        "data": data if data is not None else {},
        "cypher": list(cypher or []),
        "touched_ids": list(touched_ids or []),
        "rows": rows if rows is not None else (len(data) if isinstance(data, (list, dict)) else 0),
    }
    if latency_ms is not None:
        res["latency_ms"] = round(latency_ms, 2)
    res.update(extra)
    return res


def error_envelope(
    error: str,
    detail: str = "",
    *,
    cypher: list[str] | None = None,
    touched_ids: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    res: dict[str, Any] = {
        "error": error,
        "summary": error if not detail else f"{error}: {detail}",
        "detail": detail,
        "data": {},
        "cypher": list(cypher or []),
        "touched_ids": list(touched_ids or []),
        "rows": 0,
    }
    res.update(extra)
    return res


__all__ = [
    "SecurityProjection",
    "load_projection",
    "enumerate_attack_paths",
    "check_finding",
    "blast_radius",
    "evaluate_finding",
    "score_path",
    "ExploitCheck",
    "ScoreBreakdown",
    "find_chokepoints",
    "simulate_fixes",
    "Fix",
    "betweenness_centrality",
    "pagerank",
    "weakly_connected",
    "shortest_path",
    "envelope",
    "error_envelope",
]