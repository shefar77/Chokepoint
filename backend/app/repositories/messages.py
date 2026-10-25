"""Agent message persistence."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.db import query_one, transaction

log = logging.getLogger("chokepoint.repo.messages")


class MessageRepository:
    """CRUD for agent messages (prose between tool calls)."""

    @staticmethod
    def create(
        message_id: str,
        investigation_id: str,
        agent: str,
        text: str,
        seq: int,
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO agent_messages (id, investigation_id, agent, text, seq, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (message_id, investigation_id, agent, text, seq, now),
            )
        return message_id

    @staticmethod
    def list_for_investigation(investigation_id: str) -> list[dict[str, Any]]:
        rows = query_one(
            "SELECT * FROM agent_messages WHERE investigation_id = ? ORDER BY seq",
            (investigation_id,),
            many=True,
        ) or []
        return rows

    @staticmethod
    def create_lesson_used(
        record_id: str,
        investigation_id: str,
        lesson_id: str,
        similarity: float | None = None,
        via: str = "",
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO lessons_used (id, investigation_id, lesson_id, similarity, via, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (record_id, investigation_id, lesson_id, similarity or 0.0, via, now),
            )
        return record_id

    @staticmethod
    def list_lessons_used(investigation_id: str) -> list[dict[str, Any]]:
        return query_one(
            "SELECT * FROM lessons_used WHERE investigation_id = ? ORDER BY created_at",
            (investigation_id,),
            many=True,
        ) or []