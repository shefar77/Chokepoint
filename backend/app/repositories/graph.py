"""Graph node and edge persistence for NetworkX reconstruction."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.db import query_one, transaction

log = logging.getLogger("chokepoint.repo.graph")


class GraphRepository:
    """Store Graphify nodes and edges for later NetworkX rebuild."""

    @staticmethod
    def bulk_insert_nodes(nodes: list[dict[str, Any]]) -> int:
        """Insert graph nodes. Each must have id, scan_id, label, properties."""
        if not nodes:
            return 0
        rows = [
            (n["id"], n["scan_id"], n["label"], json.dumps(n.get("properties", {})))
            for n in nodes
        ]
        with transaction() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO graph_nodes (id, scan_id, label, properties_json) VALUES (?, ?, ?, ?)",
                rows,
            )
        log.info("inserted %d graph nodes", len(rows))
        return len(rows)

    @staticmethod
    def bulk_insert_edges(edges: list[dict[str, Any]]) -> int:
        """Insert graph edges. Each must have source_id, target_id, relation, scan_id."""
        if not edges:
            return 0
        rows = [
            (e["source_id"], e["target_id"], e["relation"], e["scan_id"], json.dumps(e.get("properties", {})))
            for e in edges
        ]
        with transaction() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO graph_edges (source_id, target_id, relation, scan_id, properties_json) VALUES (?, ?, ?, ?, ?)",
                rows,
            )
        log.info("inserted %d graph edges", len(rows))
        return len(rows)

    @staticmethod
    def load_nodes(scan_id: str) -> list[dict[str, Any]]:
        """Load all nodes for a scan."""
        rows = query_one(
            "SELECT id, label, properties_json FROM graph_nodes WHERE scan_id = ?",
            (scan_id,),
            many=True,
        ) or []
        if not rows:
            rows = query_one("SELECT id, label, properties_json FROM graph_nodes", (), many=True) or []
        return [{"id": r["id"], "label": r["label"], "properties": json.loads(r["properties_json"])} for r in rows]

    @staticmethod
    def load_edges(scan_id: str) -> list[dict[str, Any]]:
        """Load all edges for a scan."""
        rows = query_one(
            "SELECT source_id, target_id, relation, properties_json FROM graph_edges WHERE scan_id = ?",
            (scan_id,),
            many=True,
        ) or []
        if not rows:
            rows = query_one("SELECT source_id, target_id, relation, properties_json FROM graph_edges", (), many=True) or []
        return [
            {"source": r["source_id"], "target": r["target_id"], "relation": r["relation"], "properties": json.loads(r["properties_json"])}
            for r in rows
        ]

    @staticmethod
    def delete_all() -> None:
        """Delete all graph nodes and edges."""
        with transaction() as conn:
            conn.execute("DELETE FROM graph_nodes")
            conn.execute("DELETE FROM graph_edges")


