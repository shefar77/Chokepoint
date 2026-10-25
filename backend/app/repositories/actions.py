"""Action persistence."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.db import query_one, transaction

log = logging.getLogger("chokepoint.repo.actions")


class ActionRepository:
    """CRUD for actions."""

    @staticmethod
    def next_number(investigation_id: str) -> int:
        row = query_one(
            "SELECT COUNT(*) AS c FROM actions WHERE investigation_id = ?",
            (investigation_id,),
        )
        return int(row["c"]) + 1 if row else 1

    @staticmethod
    def create(
        action_id: str,
        investigation_id: str,
        verdict_id: str,
        kind: str,
        title: str,
        body_md: str,
        team: str = "",
        slack_channel: str = "",
        on_call: list[str] | None = None,
        finding_ids: list[str] | None = None,
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO actions (id, investigation_id, verdict_id, kind, status, title, body_md,
                                     team, slack_channel, on_call, finding_ids, outbox_path, delivery, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action_id,
                    investigation_id,
                    # actions.verdict_id is a foreign key: an empty string is a
                    # value that matches no verdict and raises IntegrityError.
                    verdict_id or None,
                    kind,
                    "proposed",
                    title,
                    body_md,
                    team,
                    slack_channel,
                    json.dumps(on_call or []),
                    json.dumps(finding_ids or []),
                    "",
                    "[]",
                    now,
                ),
            )
        return action_id

    @staticmethod
    def get(action_id: str) -> dict[str, Any] | None:
        row = query_one("SELECT * FROM actions WHERE id = ?", (action_id,))
        if row:
            row["on_call"] = json.loads(row["on_call"] or "[]")
            row["finding_ids"] = json.loads(row["finding_ids"] or "[]")
            row["delivery"] = json.loads(row["delivery"] or "[]")
        return row

    @staticmethod
    def list_for_investigation(investigation_id: str) -> list[dict[str, Any]]:
        rows = query_one(
            "SELECT * FROM actions WHERE investigation_id = ? ORDER BY created_at",
            (investigation_id,),
            many=True,
        ) or []
        for row in rows:
            row["on_call"] = json.loads(row["on_call"] or "[]")
            row["finding_ids"] = json.loads(row["finding_ids"] or "[]")
            row["delivery"] = json.loads(row["delivery"] or "[]")
        return rows

    @staticmethod
    def update_status(action_id: str, status: str, outbox_path: str = "", delivery: list[str] | None = None) -> bool:
        fields = {"status": status}
        if outbox_path:
            fields["outbox_path"] = outbox_path
        if delivery is not None:
            fields["delivery"] = json.dumps(delivery)
        keys = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [action_id]
        with transaction() as conn:
            cursor = conn.execute(f"UPDATE actions SET {keys} WHERE id = ?", values)
        return cursor.rowcount > 0