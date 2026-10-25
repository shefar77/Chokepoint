"""Step persistence."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.db import query_one, transaction

log = logging.getLogger("chokepoint.repo.steps")


class StepRepository:
    """CRUD for investigation steps."""

    @staticmethod
    def create(
        step_id: str,
        investigation_id: str,
        n: int,
        agent: str,
        tool: str,
        args: dict[str, Any],
        cypher: list[str],
        rows: int,
        latency_ms: float,
        summary: str,
        touched_ids: list[str],
        engine: str,
        ok: bool,
        result: dict[str, Any],
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO steps (id, investigation_id, n, agent, tool, args, result, rows, latency_ms,
                                   summary, touched_ids, engine, ok, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    step_id,
                    investigation_id,
                    n,
                    agent,
                    tool,
                    json.dumps(args, default=str)[:4000],
                    json.dumps(result, default=str)[:20000],
                    rows,
                    latency_ms,
                    summary[:1200],
                    json.dumps(touched_ids, default=str)[:6000],
                    engine,
                    int(ok),
                    now,
                ),
            )
        return step_id

    @staticmethod
    def list_for_investigation(investigation_id: str) -> list[dict[str, Any]]:
        rows = (
            query_one(
                "SELECT * FROM steps WHERE investigation_id = ? ORDER BY n",
                (investigation_id,),
                many=True,
            )
            or []
        )
        for row in rows:
            for key, default in (("args", "{}"), ("result", "{}"), ("touched_ids", "[]")):
                try:
                    row[key] = json.loads(row.get(key) or default)
                except (json.JSONDecodeError, TypeError):
                    row[key] = json.loads(default)
        return rows

    @staticmethod
    def get_existing_step_ids(investigation_id: str, step_ids: list[str]) -> list[str]:
        if not step_ids:
            return []
        placeholders = ",".join("?" * len(step_ids))
        rows = query_one(
            f"SELECT id FROM steps WHERE investigation_id = ? AND id IN ({placeholders})",
            (investigation_id, *step_ids),
            many=True,
        ) or []
        return [r["id"] for r in rows]