"""Blackboard persistence: hypotheses and challenges."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.db import query_one, transaction

log = logging.getLogger("chokepoint.repo.blackboard")


class BlackboardRepository:
    """Hypotheses, challenges, and blackboard reads."""

    @staticmethod
    def next_hypothesis_number(investigation_id: str) -> int:
        row = query_one(
            "SELECT COUNT(*) AS c FROM blackboard WHERE investigation_id = ? AND kind = 'hypothesis'",
            (investigation_id,),
        )
        return int(row["c"]) + 1 if row else 1

    @staticmethod
    def next_challenge_number(investigation_id: str) -> int:
        row = query_one(
            "SELECT COUNT(*) AS c FROM blackboard WHERE investigation_id = ? AND kind = 'challenge'",
            (investigation_id,),
        )
        return int(row["c"]) + 1 if row else 1

    @staticmethod
    def create_hypothesis(
        investigation_id: str,
        hypothesis_id: str,
        agent: str,
        claim: str,
        confidence: float,
        about_ids: list[str],
        based_on_step_ids: list[str],
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO blackboard (id, investigation_id, kind, agent, claim, status, confidence,
                                        about_ids, based_on_step_ids, created_at)
                VALUES (?, ?, 'hypothesis', ?, ?, 'open', ?, ?, ?, ?)
                """,
                (
                    hypothesis_id,
                    investigation_id,
                    agent,
                    claim,
                    confidence,
                    json.dumps(about_ids),
                    json.dumps(based_on_step_ids),
                    now,
                ),
            )
        return True

    @staticmethod
    def create_challenge(
        investigation_id: str,
        challenge_id: str,
        hypothesis_id: str = "",
        kind: str = "control_check",
        claim: str = "",
        outcome: str = "supported",
        based_on_step_ids: list[str] | None = None,
        agent: str = "skeptic",
        confidence: float = 0.8,
        contradicts: bool = False,
        about_ids: list[str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc).isoformat()
        new_status = "falsified" if outcome == "upheld" else "supported"
        with transaction() as conn:
            # Create challenge
            conn.execute(
                """
                INSERT INTO blackboard (id, investigation_id, kind, agent, claim, status, confidence,
                                        about_ids, based_on_step_ids, created_at)
                VALUES (?, ?, 'challenge', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_id,
                    investigation_id,
                    agent or "skeptic",
                    claim,
                    outcome or "open",
                    confidence,
                    json.dumps(about_ids or []),
                    json.dumps(based_on_step_ids or []),
                    now,
                ),
            )
            # Update hypothesis status
            if hypothesis_id:
                conn.execute(
                    "UPDATE blackboard SET status = ? WHERE id = ? AND investigation_id = ? AND kind = 'hypothesis'",
                    (new_status, hypothesis_id, investigation_id),
                )
            row = conn.execute(
                "SELECT status FROM blackboard WHERE id = ? AND investigation_id = ? AND kind = 'hypothesis'",
                (hypothesis_id, investigation_id),
            ).fetchone()
        return {"hypothesis_status": row["status"]} if row else None

    @staticmethod
    def weaken_hypothesis(investigation_id: str, hypothesis_id: str) -> bool:
        with transaction() as conn:
            cursor = conn.execute(
                "UPDATE blackboard SET status = 'weakened' WHERE id = ? AND investigation_id = ? AND kind = 'hypothesis'",
                (hypothesis_id, investigation_id),
            )
        return cursor.rowcount > 0

    @staticmethod
    def get_blackboard(investigation_id: str) -> dict[str, Any]:
        # Steps
        step_rows = query_one(
            """
            SELECT id, n, agent, tool, summary, rows, engine, touched_ids, ok
            FROM steps WHERE investigation_id = ? ORDER BY n LIMIT 80
            """,
            (investigation_id,),
            many=True,
        ) or []
        steps = []
        for row in step_rows:
            steps.append(
                {
                    "id": row["id"],
                    "n": row["n"],
                    "agent": row["agent"],
                    "tool": row["tool"],
                    "summary": (row["summary"] or "")[:140],
                    "rows": row["rows"] or 0,
                    "engine": row["engine"] or "",
                    "touched_ids": json.loads(row["touched_ids"] or "[]")[:8],
                    "ok": bool(row["ok"]),
                }
            )

        # Hypotheses
        hyp_rows = query_one(
            "SELECT * FROM blackboard WHERE investigation_id = ? AND kind = 'hypothesis' ORDER BY id",
            (investigation_id,),
            many=True,
        ) or []
        hypotheses = []
        for row in hyp_rows:
            hypotheses.append(
                {
                    "id": row["id"],
                    "agent": row["agent"],
                    "claim": row["claim"],
                    "status": row["status"] or "open",
                    "confidence": row["confidence"] or 0.0,
                    "about_ids": json.loads(row["about_ids"] or "[]"),
                    "based_on_step_ids": json.loads(row["based_on_step_ids"] or "[]"),
                }
            )

        # Challenges
        ch_rows = query_one(
            "SELECT * FROM blackboard WHERE investigation_id = ? AND kind = 'challenge' ORDER BY id",
            (investigation_id,),
            many=True,
        ) or []
        challenges = []
        for row in ch_rows:
            challenges.append(
                {
                    "id": row["id"],
                    "kind": row.get("about_ids") or "",  # we store kind in about_ids for challenge
                    "claim": row["claim"],
                    "outcome": row.get("status") or "rejected",  # we store outcome in status
                    "hypothesis_id": row.get("based_on_step_ids") or "",  # stored in based_on_step_ids
                    "hypothesis_claim": "",
                    "based_on_step_ids": json.loads(row["based_on_step_ids"] or "[]"),
                }
            )

        # Attack paths - need to join from investigations
        # This is populated by the orchestrator from the graph analysis

        # Verdicts
        verdict_rows = query_one(
            """
            SELECT v.id, v.kind, v.confidence, v.grounded, v.finding_ids
            FROM verdicts v WHERE v.investigation_id = ? ORDER BY v.id
            """,
            (investigation_id,),
            many=True,
        ) or []
        verdicts = []
        for row in verdict_rows:
            finding_ids = json.loads(row["finding_ids"] or "[]")
            verdicts.append(
                {
                    "id": row["id"],
                    "kind": row["kind"],
                    "confidence": row["confidence"],
                    "grounded": bool(row["grounded"]),
                    "finding_ids": finding_ids,
                }
            )

        upheld = [c for c in challenges if c["outcome"] == "upheld"]
        open_h = [h for h in hypotheses if h["status"] == "open"]

        return {
            "investigation_id": investigation_id,
            "steps": steps,
            "attack_paths": [],  # populated by caller from context
            "hypotheses": hypotheses,
            "challenges": challenges,
            "verdicts": verdicts,
            "counts": {
                "steps": len(steps),
                "paths": 0,
                "hypotheses": len(hypotheses),
                "open_hypotheses": len(open_h),
                "challenges": len(challenges),
                "upheld_challenges": len(upheld),
                "verdicts": len(verdicts),
            },
        }

    @staticmethod
    def get_paths_for_investigation(investigation_id: str) -> list[dict[str, Any]]:
        """Get paths from investigation snapshot."""
        row = query_one(
            "SELECT snapshot_json FROM investigations WHERE id = ?",
            (investigation_id,),
        )
        if not row or not row["snapshot_json"]:
            return []
        try:
            snapshot = json.loads(row["snapshot_json"])
            return snapshot.get("paths", [])
        except json.JSONDecodeError:
            return []

    @staticmethod
    def get_attack_paths_snapshot(investigation_id: str) -> list[dict[str, Any]]:
        """Get attack paths from the investigation's persisted paths."""
        # We'll need to reconstruct from the graph analysis; for now return empty
        # The orchestrator holds paths in context
        return []