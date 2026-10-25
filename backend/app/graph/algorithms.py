"""Graph algorithms with NetworkX implementations."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import networkx as nx

log = logging.getLogger("chokepoint.graph.algorithms")


@dataclass(slots=True)
class AlgoResult:
    engine: str
    cypher: list[str]
    data: dict[str, Any]
    rows: int


def betweenness_centrality(nodes: list[str] | None, G: nx.DiGraph) -> AlgoResult:
    """Betweenness centrality over the graph, optionally on a subset."""
    cypher: list[str] = []
    if nodes:
        G = G.subgraph([n for n in nodes if n in G]).copy()
    if G.number_of_nodes() == 0:
        return AlgoResult("networkx", cypher, {"scores": {}}, 0)
    scores = nx.betweenness_centrality(G, normalized=True)
    return AlgoResult("networkx", cypher, {"scores": scores}, len(scores))


def pagerank(nodes: list[str] | None, G: nx.DiGraph) -> AlgoResult:
    """PageRank over the graph, optionally on a subset."""
    cypher: list[str] = []
    if nodes:
        G = G.subgraph([n for n in nodes if n in G]).copy()
    if G.number_of_nodes() == 0:
        return AlgoResult("networkx", cypher, {"scores": {}}, 0)
    scores = nx.pagerank(G, alpha=0.85)
    return AlgoResult("networkx", cypher, {"scores": scores}, len(scores))


def weakly_connected(G: nx.DiGraph) -> AlgoResult:
    """Weakly connected components of the graph."""
    cypher: list[str] = []
    if G.number_of_nodes() == 0:
        return AlgoResult("networkx", cypher, {"components": []}, 0)
    components = [sorted(c) for c in nx.weakly_connected_components(G)]
    components.sort(key=lambda c: (-len(c), c[0]))
    return AlgoResult("networkx", cypher, {"components": components}, len(components))


def bfs_levels(start: str, max_hops: int, G: nx.DiGraph) -> AlgoResult:
    """Depth per reachable node from start."""
    cypher: list[str] = []
    if start not in G:
        return AlgoResult("networkx", cypher, {"depths": {}}, 0)
    depths = nx.single_source_shortest_path_length(G, start, cutoff=int(max_hops))
    return AlgoResult("networkx", cypher, {"depths": depths}, len(depths))


def shortest_path(
    from_id: str, to_id: str, G: nx.DiGraph
) -> AlgoResult:
    """Shortest path between two nodes."""
    cypher: list[str] = []
    if from_id not in G or to_id not in G:
        return AlgoResult(
            "networkx",
            cypher,
            {"found": False, "reason": "node not present in the graph"},
            0,
        )
    try:
        nodes = nx.shortest_path(G, from_id, to_id)
        directed = True
    except nx.NetworkXNoPath:
        undirected = G.to_undirected(as_view=True)
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
        data = G.get_edge_data(src, dst) or G.get_edge_data(dst, src) or {}
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