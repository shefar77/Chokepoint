"""Feedback persistence."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.db import query, query_one, transaction
from app.repositories.lessons import LessonRepository

log = logging.getLogger("chokepoint.repo.feedback")


class FeedbackRepository:
    """CRUD for feedback on verdicts."""

    @staticmethod
    def create(
        feedback_id: str,
        verdict_id: str,
        action: str,
        new_kind: str | None,
        note: str,
        by_user: str,
        lesson_id: str = "",
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO feedback (id, verdict_id, action, new_kind, note, by_user, lesson_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (feedback_id, verdict_id, action, new_kind or "", note, by_user, lesson_id, now),
            )
        return feedback_id

    @staticmethod
    def set_lesson(feedback_id: str, lesson_id: str) -> None:
        with transaction() as conn:
            conn.execute(
                "UPDATE feedback SET lesson_id = ? WHERE id = ?", (lesson_id, feedback_id)
            )

    @staticmethod
    def get(feedback_id: str) -> dict[str, Any] | None:
        return query_one("SELECT * FROM feedback WHERE id = ?", (feedback_id,))

    @staticmethod
    def get_by_ids(ids: list[str]) -> list[dict[str, Any]]:
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        return query(f"SELECT * FROM feedback WHERE id IN ({placeholders})", tuple(ids))

    @staticmethod
    def list_for_verdict(verdict_id: str) -> list[dict[str, Any]]:
        return query(
            "SELECT * FROM feedback WHERE verdict_id = ? ORDER BY created_at",
            (verdict_id,),
        )

    @staticmethod
    def get_past_verdicts(subjects: list[str]) -> list[dict[str, Any]]:
        if not subjects:
            return []
        rows = query("SELECT * FROM verdicts ORDER BY created_at DESC LIMIT 50")
        results = []
        for r in rows:
            f_ids = json.loads(r.get("finding_ids") or "[]") if isinstance(r.get("finding_ids"), str) else (r.get("finding_ids") or [])
            s_ids = json.loads(r.get("services") or "[]") if isinstance(r.get("services"), str) else (r.get("services") or [])
            claims = json.loads(r.get("claims") or "[]") if isinstance(r.get("claims"), str) else (r.get("claims") or [])
            matched = any(s in f_ids or s in s_ids for s in subjects)
            if matched:
                results.append({
                    "verdict_id": r["id"],
                    "kind": r.get("kind"),
                    "rationale": claims[0].get("text", "") if claims and isinstance(claims[0], dict) else r.get("headline", ""),
                    "confidence": float(r.get("confidence") or 0.0),
                    "effect": r.get("kind"),
                    "scope_kind": "service",
                    "scope_value": s_ids[0] if s_ids else "",
                    "service_id": s_ids[0] if s_ids else "",
                    "uses": 1,
                    "created_at": r.get("created_at"),
                })
        return results


__all__ = ["FeedbackRepository", "LessonRepository"]
