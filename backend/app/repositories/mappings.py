"""Finding-to-graph-node mappings."""

from __future__ import annotations

import logging
from typing import Any

from app.db import query_one, transaction

log = logging.getLogger("chokepoint.repo.mappings")


class MappingRepository:
    """Track how scanner findings map to code entities."""

    @staticmethod
    def bulk_insert(mappings: list[dict[str, Any]]) -> int:
        """Insert finding→node mappings."""
        if not mappings:
            return 0
        rows = [
            (m["finding_id"], m["node_id"], m["match_kind"], m["confidence"], m.get("evidence", ""))
            for m in mappings
        ]
        with transaction() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO finding_mappings (finding_id, node_id, match_kind, confidence, evidence) VALUES (?, ?, ?, ?, ?)",
                rows,
            )
        log.info("inserted %d mappings", len(rows))
        return len(rows)

    @staticmethod
    def for_finding(finding_id: str) -> list[dict[str, Any]]:
        """All mappings for one finding."""
        return query_one(
            "SELECT * FROM finding_mappings WHERE finding_id = ?", (finding_id,), many=True
        ) or []

    @staticmethod
    def for_node(node_id: str) -> list[dict[str, Any]]:
        """All findings mapped to one node."""
        return query_one(
            "SELECT * FROM finding_mappings WHERE node_id = ?", (node_id,), many=True
        ) or []

