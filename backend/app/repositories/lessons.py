"""Lesson persistence and retrieval."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.db import query, query_one, transaction
from app.memory.embeddings import embedder

log = logging.getLogger("chokepoint.repo.lessons")


class LessonRepository:
    """CRUD and retrieval for lessons."""

    @staticmethod
    def next_number() -> int:
        row = query_one("SELECT COUNT(*) AS c FROM lessons")
        return int(row["c"]) + 1 if row else 1

    @staticmethod
    def create(
        lesson_id: str,
        text: str,
        scope_kind: str,
        scope_value: str,
        effect: str,
        strength: float,
        embedding: bytes | None = None,
        source_feedback_id: str | None = None,
        applies_to: list[str] | None = None,
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO lessons (id, text, scope_kind, scope_value, effect, strength,
                                     embedding, uses, source_feedback_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (lesson_id, text, scope_kind, scope_value, effect, strength, embedding, source_feedback_id or None, now),
            )
            if applies_to:
                for node_id in applies_to:
                    conn.execute(
                        "INSERT OR IGNORE INTO lesson_applies_to (lesson_id, node_id) VALUES (?, ?)",
                        (lesson_id, node_id),
                    )
        return lesson_id

    @staticmethod
    def get(lesson_id: str) -> dict[str, Any] | None:
        row = query_one("SELECT * FROM lessons WHERE id = ?", (lesson_id,))
        if row:
            applies = query(
                "SELECT node_id FROM lesson_applies_to WHERE lesson_id = ?", (lesson_id,)
            )
            row["applies_to"] = [r["node_id"] for r in applies]
        return row

    @staticmethod
    def list_all() -> list[dict[str, Any]]:
        rows = query("SELECT * FROM lessons ORDER BY created_at DESC")
        for row in rows:
            applies = query(
                "SELECT node_id FROM lesson_applies_to WHERE lesson_id = ?", (row["id"],)
            )
            row["applies_to"] = [r["node_id"] for r in applies]
        return rows

    @staticmethod
    def find_by_scope(scope_kind: str, scope_value: str) -> list[dict[str, Any]]:
        rows = query(
            "SELECT * FROM lessons WHERE scope_kind = ? AND scope_value = ? ORDER BY strength DESC, created_at DESC",
            (scope_kind, scope_value),
        )
        for row in rows:
            applies = query(
                "SELECT node_id FROM lesson_applies_to WHERE lesson_id = ?", (row["id"],)
            )
            row["applies_to"] = [r["node_id"] for r in applies]
        return rows

    @staticmethod
    def increment_uses(lesson_id: str) -> bool:
        with transaction() as conn:
            cursor = conn.execute(
                "UPDATE lessons SET uses = uses + 1 WHERE id = ?", (lesson_id,)
            )
        return cursor.rowcount > 0

    @staticmethod
    def get_applies_to(lesson_id: str) -> list[str]:
        rows = query("SELECT node_id FROM lesson_applies_to WHERE lesson_id = ?", (lesson_id,))
        return [str(r["node_id"]) for r in rows]

    @staticmethod
    def get_by_graph_proximity(subjects: list[str]) -> list[dict[str, Any]]:
        if not subjects:
            return []
        placeholders = ",".join("?" for _ in subjects)
        sql = f"""
        SELECT DISTINCT l.id, l.text, l.effect, l.scope_kind, l.scope_value, l.strength, l.uses, l.source_feedback_id, a.node_id AS via
        FROM lessons l
        LEFT JOIN lesson_applies_to a ON l.id = a.lesson_id
        WHERE a.node_id IN ({placeholders}) OR l.scope_value IN ({placeholders})
        ORDER BY l.strength DESC, l.uses DESC
        """
        rows = query(sql, tuple(subjects) + tuple(subjects))
        results = []
        for r in rows:
            results.append({
                "lesson_id": r["id"],
                "text": r["text"],
                "effect": r.get("effect"),
                "scope_kind": r.get("scope_kind"),
                "scope_value": r.get("scope_value"),
                "strength": float(r.get("strength") or 0.0),
                "uses": int(r.get("uses") or 0),
                "source_feedback_id": r.get("source_feedback_id"),
                "why_retrieved": "graph",
                "via": r.get("via") or subjects[0],
                "similarity": None,
            })
        return results

    @staticmethod
    def get_by_vector(vector: list[float], subjects: list[str]) -> list[dict[str, Any]]:
        rows = query("SELECT * FROM lessons WHERE embedding IS NOT NULL")
        results = []
        for r in rows:
            emb = r.get("embedding")
            sim = 0.5
            if isinstance(emb, bytes) and len(emb) >= 4:
                try:
                    import struct
                    floats = struct.unpack(f"{len(emb)//4}f", emb)
                    dot = sum(a * b for a, b in zip(vector, floats))
                    sim = max(0.0, min(1.0, dot))
                except Exception:
                    pass
            results.append({
                "lesson_id": r["id"],
                "text": r["text"],
                "effect": r.get("effect"),
                "scope_kind": r.get("scope_kind"),
                "scope_value": r.get("scope_value"),
                "strength": float(r.get("strength") or 0.0),
                "uses": int(r.get("uses") or 0),
                "source_feedback_id": r.get("source_feedback_id"),
                "why_retrieved": "vector",
                "via": subjects[0] if subjects else "",
                "similarity": round(sim, 4),
            })
        results.sort(key=lambda x: -float(x["similarity"] or 0.0))
        return results[:10]

    @staticmethod
    def status() -> dict[str, Any]:
        count = query_one("SELECT COUNT(*) AS c FROM lessons")
        return {"lessons_count": count["c"] if count else 0, "ready": True}

    @staticmethod
    def status_embeddings() -> dict[str, Any]:
        return embedder().status()

