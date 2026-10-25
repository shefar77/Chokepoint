"""Simulation persistence."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.db import query_one, transaction

log = logging.getLogger("chokepoint.repo.simulations")


class SimulationRepository:
    """CRUD for remediation simulations."""

    @staticmethod
    def create(
        simulation_id: str,
        investigation_id: str,
        verdict_id: str | None,
        baseline_weight: float,
        baseline_paths: int,
        after_weight: float,
        after_paths: int,
        fixes: list[dict[str, Any]],
        result: dict[str, Any],
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO simulations (id, investigation_id, verdict_id, baseline_weight, baseline_paths,
                                         after_weight, after_paths, fixes_json, result_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    simulation_id,
                    investigation_id,
                    verdict_id or None,
                    baseline_weight,
                    baseline_paths,
                    after_weight,
                    after_paths,
                    json.dumps(fixes, default=str),
                    json.dumps(result, default=str),
                    now,
                ),
            )
        return simulation_id

    @staticmethod
    def get(simulation_id: str) -> dict[str, Any] | None:
        row = query_one("SELECT * FROM simulations WHERE id = ?", (simulation_id,))
        if row:
            row["fixes_json"] = json.loads(row["fixes_json"] or "[]")
            row["result_json"] = json.loads(row["result_json"] or "{}")
        return row

    @staticmethod
    def list_for_investigation(investigation_id: str) -> list[dict[str, Any]]:
        rows = query_one(
            "SELECT * FROM simulations WHERE investigation_id = ? ORDER BY created_at DESC",
            (investigation_id,),
            many=True,
        ) or []
        for row in rows:
            row["fixes_json"] = json.loads(row["fixes_json"] or "[]")
            row["result_json"] = json.loads(row["result_json"] or "{}")
        return rows