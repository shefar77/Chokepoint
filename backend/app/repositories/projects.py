"""Project persistence."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.db import execute, query_one, transaction

log = logging.getLogger("chokepoint.repo.projects")


class ProjectRepository:
    """CRUD for projects."""

    @staticmethod
    def create(project_id: str, name: str, repo_url: str = "", **fields: Any) -> str:
        """Insert a project. Returns the project id."""
        now = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO projects (id, name, repo_url, created_at, updated_at, status, visibility, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_id,
                    name,
                    repo_url,
                    now,
                    now,
                    fields.get("status", "active"),
                    fields.get("visibility", "private"),
                    fields.get("metadata_json", "{}"),
                ),
            )
        log.info("created project %s (%s)", project_id, name)
        return project_id

    @staticmethod
    def get(project_id: str) -> dict[str, Any] | None:
        """Fetch one project by id."""
        return query_one("SELECT * FROM projects WHERE id = ?", (project_id,))

    @staticmethod
    def list_all(status: str | None = None) -> list[dict[str, Any]]:
        """List projects, optionally filtered by status."""
        if status:
            return query_one(
                "SELECT * FROM projects WHERE status = ? ORDER BY created_at DESC", (status,), many=True
            ) or []
        return query_one("SELECT * FROM projects ORDER BY created_at DESC", (), many=True) or []

    @staticmethod
    def update(project_id: str, **fields: Any) -> bool:
        """Update project fields. Returns True when at least one row was touched."""
        if not fields:
            return False
        fields["updated_at"] = datetime.now(timezone.utc).isoformat()
        keys = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [project_id]
        with transaction() as conn:
            cursor = conn.execute(f"UPDATE projects SET {keys} WHERE id = ?", values)
        return cursor.rowcount > 0

    @staticmethod
    def delete(project_id: str) -> bool:
        """Delete a project. Cascades to scans, findings, etc. via foreign keys."""
        with transaction() as conn:
            cursor = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        return cursor.rowcount > 0

    @staticmethod
    def delete_all() -> None:
        """Delete all projects."""
        with transaction() as conn:
            conn.execute("DELETE FROM projects")


