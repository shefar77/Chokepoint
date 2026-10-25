"""Graph operations with SQLite + NetworkX backend.

All graph data is loaded from SQLite into NetworkX in-memory graphs.
No FalkorDB Cypher queries are used.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import networkx as nx

from app.config import settings
from app.db import execute, query_one
from app.graph.projection import load_projection, SecurityProjection
from app.graph.attack import Modifications

log = logging.getLogger("chokepoint.graph_ops")

EDGE_CYPHER = "MATCH (a)-[r]->(b) WHERE a.id IS NOT NULL AND b.id IS NOT NULL AND type(r) IN $types RETURN a.id AS src, type(r) AS rel, b.id AS dst LIMIT $limit"


@dataclass(slots=True)
class AlgoResult:
    engine: str
    cypher: list[str]
    data: dict[str, Any]
    rows: int


def load_edges(rel_types: list[str] | None = None, graph: str | None = None) -> tuple[list[tuple[str, str, str]], str]:
    """Load edges from the security projection into a list of (src, rel, dst) tuples."""
    proj = load_projection(graph)
    types = [t for t in (rel_types or proj.graph.nodes) if t in proj.graph.edges]
    cypher: list[str] = []
    rows = execute(
        EDGE_CYPHER,
        {"types": types, "limit": 200000},
    )
    edges = [(str(r["src"]), str(r["rel"]), str(r["dst"])) for r in rows.dicts()] if rows else []
    return edges, []


def build_digraph(edges: list[tuple[str, str, str]]) -> nx.DiGraph:
    """Build a NetworkX DiGraph from edge list."""
    g: nx.DiGraph = nx.DiGraph()
    for src, rel, dst in edges:
        g.add_edge(src, dst, relation=rel)
    return g


def calls_digraph(graph: str | None = None) -> tuple[nx.DiGraph, str]:
    """Build CALLS subgraph from the projection."""
    proj = load_projection(graph)
    edges = []
    for _, dst, data in proj.graph.in_edges("internet"):
        for src in proj.graph.predecessors(dst):
            if proj.graph.has_edge(src, dst):
                edge_data = proj.graph.get_edge_data(src, dst)
                edges.append((src, edge_data.get("relation", "CALLS"), dst))
    return build_digraph(edges), []


def pagerank(nodes: list[str] | None, graph: str | None = None) -> AlgoResult:
    """PageRank over the security graph."""
    proj = load_projection(graph)
    cypher: list[str] = []
    if nodes:
        g = proj.graph.subgraph([n for n in nodes if n in proj.graph]).copy()
    else:
        g = proj.graph
    if g.number_of_nodes() == 0:
        return AlgoResult("networkx", cypher, {"scores": {}}, 0)
    scores = nx.pagerank(g, alpha=0.85)
    return AlgoResult("networkx", cypher, {"scores": scores}, len(scores))


def betweenness(nodes: list[str] | None, graph: str | None = None) -> AlgoResult:
    """Betweenness centrality over the security graph."""
    proj = load_projection(graph)
    cypher: list[str] = []
    if nodes:
        g = proj.graph.subgraph([n for n in nodes if n in proj.graph]).copy()
    else:
        g = proj.graph
    if g.number_of_nodes() == 0:
        return AlgoResult("networkx", cypher, {"scores": {}}, 0)
    scores = nx.betweenness_centrality(g, normalized=True)
    return AlgoResult("networkx", cypher, {"scores": scores}, len(scores))


def weakly_connected(graph: str | None = None) -> AlgoResult:
    """Weakly connected components of the security graph."""
    proj = load_projection(graph)
    cypher: list[str] = []
    g = proj.graph
    if g.number_of_nodes() == 0:
        return AlgoResult("networkx", cypher, {"components": []}, 0)
    components = [sorted(c) for c in nx.weakly_connected_components(g)]
    components.sort(key=lambda c: (-len(c), c[0]))
    return AlgoResult("networkx", cypher, {"components": components}, len(components))


def bfs_levels(start: str, max_hops: int, graph: str | None = None) -> AlgoResult:
    """Depth per reachable node from start over usable CALLS edges."""
    proj = load_projection(graph)
    cypher: list[str] = []
    if start not in proj.graph:
        return AlgoResult("networkx", cypher, {"depths": {}}, 0)
    depths = nx.single_source_shortest_path_length(proj.graph, start, cutoff=int(max_hops))
    return AlgoResult("networkx", cypher, {"depths": depths}, len(depths))


def shortest_path(
    from_id: str, to_id: str, graph: str | None = None
) -> AlgoResult:
    """Shortest path between two nodes over chosen relationship types."""
    proj = load_projection(graph)
    cypher: list[str] = []
    if from_id not in proj.graph or to_id not in proj.graph:
        return AlgoResult(
            "networkx",
            cypher,
            {"found": False, "reason": "node not present in the graph"},
            0,
        )
    try:
        nodes = nx.shortest_path(proj.graph, from_id, to_id)
        directed = True
    except nx.NetworkXNoPath:
        undirected = proj.graph.to_undirected(as_view=True)
        try:
            nodes = nx.shortest_path(undirected, from_id, to_id)
            directed = False
        except nx.NetworkXNoPath:
            return AlgoResult(
                "networkx",
                cypher,
                {"found": False, "reason": f"no path between {from_id} and {to_id}"},
                0,
            )
    rels: list[str] = []
    for src, dst in zip(nodes, nodes[1:], strict=False):
        data = proj.graph.get_edge_data(src, dst) or proj.graph.get_edge_data(dst, src) or {}
        rels.append(str(data.get("relation", "")))
    return AlgoResult(
        "networkx",
        cypher,
        {
            "found": True,
            "directed": directed,
            "nodes": nodes,
            "rel_types": rels,
            "hops": len(nodes) - 1,
        },
        len(nodes),
    )