"""Verdict persistence."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.db import query_one, transaction

log = logging.getLogger("chokepoint.repo.verdicts")


class VerdictRepository:
    """CRUD for verdicts."""

    @staticmethod
    def next_number(investigation_id: str) -> int:
        row = query_one(
            "SELECT COUNT(*) AS c FROM verdicts WHERE investigation_id = ?",
            (investigation_id,),
        )
        return int(row["c"]) + 1 if row else 1

    @staticmethod
    def create(
        verdict_id: str,
        investigation_id: str,
        finding_ids: list[str],
        kind: str,
        requested_kind: str | None,
        confidence: float,
        grounded: bool,
        safety_valve_applied: bool,
        safety_valve_reason: str,
        claims: list[dict[str, Any]],
        evidence_path_ids: list[str],
        grounding: dict[str, Any] | None = None,
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO verdicts (id, investigation_id, finding_ids, services, kind, requested_kind,
                                      confidence, grounded, safety_valve, safety_valve_reason,
                                      headline, claims, grounding_json, evidence_path_ids, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    verdict_id,
                    investigation_id,
                    json.dumps(finding_ids),
                    "[]",  # services computed from findings
                    kind,
                    requested_kind or "",
                    confidence,
                    int(grounded),
                    int(safety_valve_applied),
                    safety_valve_reason,
                    (claims[0].get("text") or claims[0].get("rationale") or str(claims[0])) if claims else "",
                    json.dumps(claims, default=str),
                    json.dumps(grounding or {}, default=str),
                    json.dumps(evidence_path_ids),
                    now,
                ),
            )
        return verdict_id

    @staticmethod
    def get(verdict_id: str) -> dict[str, Any] | None:
        row = query_one("SELECT * FROM verdicts WHERE id = ?", (verdict_id,))
        if row:
            row["finding_ids"] = json.loads(row["finding_ids"] or "[]")
            row["claims"] = json.loads(row["claims"] or "[]")
            row["evidence_path_ids"] = json.loads(row["evidence_path_ids"] or "[]")
            row["services"] = json.loads(row["services"] or "[]")
        return row

    @staticmethod
    def list_for_investigation(investigation_id: str) -> list[dict[str, Any]]:
        rows = query_one(
            "SELECT * FROM verdicts WHERE investigation_id = ? ORDER BY id",
            (investigation_id,),
            many=True,
        ) or []
        for row in rows:
            row["finding_ids"] = json.loads(row["finding_ids"] or "[]")
            row["claims"] = json.loads(row["claims"] or "[]")
            row["evidence_path_ids"] = json.loads(row["evidence_path_ids"] or "[]")
            row["services"] = json.loads(row["services"] or "[]")
        return rows