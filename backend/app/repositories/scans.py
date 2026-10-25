"""Scan persistence."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.db import execute, query_one, transaction

log = logging.getLogger("chokepoint.repo.scans")


class ScanRepository:
    """CRUD for scans."""

    @staticmethod
    def create(scan_id: str, project_id: str, **fields: Any) -> str:
        """Insert a scan record. Returns the scan id."""
        now = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO scans (id, project_id, started_at, completed_at, status,
                                   source_type, source_ref, workspace_path, graphify_status,
                                   trivy_status, semgrep_status, error_message, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    project_id,
                    fields.get("started_at", now),
                    fields.get("completed_at"),
                    fields.get("status", "running"),
                    fields.get("source_type", "zip_upload"),
                    fields.get("source_ref", ""),
                    fields.get("workspace_path", ""),
                    fields.get("graphify_status", "pending"),
                    fields.get("trivy_status", "pending"),
                    fields.get("semgrep_status", "pending"),
                    fields.get("error_message", ""),
                    fields.get("metadata_json", "{}"),
                    fields.get("created_at", now),
                ),
            )
        log.info("created scan %s for project %s", scan_id, project_id)
        return scan_id

    @staticmethod
    def get(scan_id: str) -> dict[str, Any] | None:
        """Fetch one scan by id."""
        return query_one("SELECT * FROM scans WHERE id = ?", (scan_id,))

    @staticmethod
    def list_for_project(project_id: str) -> list[dict[str, Any]]:
        """List scans for a project, newest first."""
        return (
            query_one(
                "SELECT * FROM scans WHERE project_id = ? ORDER BY started_at DESC",
                (project_id,),
                many=True,
            )
            or []
        )

    @staticmethod
    def latest_completed(project_id: str) -> dict[str, Any] | None:
        """Most recent completed scan for a project."""
        return query_one(
            """
            SELECT * FROM scans
            WHERE project_id = ? AND status = 'completed'
            ORDER BY completed_at DESC LIMIT 1
            """,
            (project_id,),
        )

    @staticmethod
    def update(scan_id: str, **fields: Any) -> bool:
        """Update scan fields atomically."""
        if not fields:
            return False
        keys = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [scan_id]
        with transaction() as conn:
            cursor = conn.execute(f"UPDATE scans SET {keys} WHERE id = ?", values)
        return cursor.rowcount > 0

    @staticmethod
    def mark_completed(scan_id: str, status: str = "completed", error: str = "") -> bool:
        """Mark a scan finished, stamping completed_at."""
        now = datetime.now(timezone.utc).isoformat()
        return ScanRepository.update(scan_id, completed_at=now, status=status, error_message=error)

    @staticmethod
    def latest_scan() -> dict[str, Any] | None:
        """Get latest scan record."""
        return query_one("SELECT * FROM scans ORDER BY started_at DESC, created_at DESC, id DESC LIMIT 1")

    @staticmethod
    def delete_all() -> None:
        """Delete all scans."""
        with transaction() as conn:
            conn.execute("DELETE FROM scans")


