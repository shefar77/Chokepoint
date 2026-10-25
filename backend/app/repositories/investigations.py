"""Investigation persistence."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.db import query_one, transaction

log = logging.getLogger("chokepoint.repo.investigations")


class InvestigationRepository:
    """CRUD for investigations."""

    @staticmethod
    def create(
        investigation_id: str,
        project_id: str = "",
        scan_id: str = "",
        goal: str = "",
        mode: str = "scripted",
        preset: str = "",
        model: str = "",
        **kwargs: Any,
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        if not scan_id:
            from app.repositories.scans import ScanRepository
            latest = ScanRepository.latest_scan()
            if latest:
                scan_id = str(latest["id"])
                if not project_id and latest.get("project_id"):
                    project_id = str(latest["project_id"])
        if not project_id:
            from app.repositories.projects import ProjectRepository
            projects = ProjectRepository.list_all()
            if projects:
                project_id = str(projects[0]["id"])
            else:
                project_id = "default-project"
                ProjectRepository.create(project_id, "Default Project")
        if not scan_id:
            scan_id = "initial"
        with transaction() as conn:
            conn.execute(
                """
                INSERT INTO investigations (id, project_id, scan_id, goal, mode, preset, status, model, started_at, ended_at, error, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    investigation_id,
                    project_id,
                    scan_id,
                    goal,
                    mode,
                    preset,
                    "running",
                    model,
                    now,
                    None,
                    "",
                    now,
                ),
            )
        return investigation_id

    @staticmethod
    def get(investigation_id: str) -> dict[str, Any] | None:
        return query_one("SELECT * FROM investigations WHERE id = ?", (investigation_id,))

    @staticmethod
    def list_all(status: str | None = None) -> list[dict[str, Any]]:
        if status:
            return query_one(
                "SELECT * FROM investigations WHERE status = ? ORDER BY started_at DESC",
                (status,),
                many=True,
            ) or []
        return query_one("SELECT * FROM investigations ORDER BY started_at DESC", (), many=True) or []

    @staticmethod
    def list_for_project(project_id: str) -> list[dict[str, Any]]:
        return (
            query_one(
                "SELECT * FROM investigations WHERE project_id = ? ORDER BY started_at DESC",
                (project_id,),
                many=True,
            )
            or []
        )

    @staticmethod
    def get_paths_for_investigation(investigation_id: str) -> list[dict[str, Any]]:
        inv = InvestigationRepository.get(investigation_id)
        if not inv:
            return []
        snapshot_raw = inv.get("snapshot_json")
        if snapshot_raw:
            try:
                snap = json.loads(snapshot_raw) if isinstance(snapshot_raw, str) else snapshot_raw
                if snap and snap.get("paths"):
                    return snap["paths"]
            except Exception:
                pass
        try:
            from app.graph.projection import load_projection
            from app.graph.attack import enumerate_attack_paths
            proj = load_projection(inv.get("scan_id"))
            paths = enumerate_attack_paths(proj, top_k=8)
            return [p.as_dict() for p in paths]
        except Exception as e:
            log.warning("could not get paths for investigation %s: %s", investigation_id, e)
            return []

    @staticmethod
    def update(investigation_id: str, **fields: Any) -> bool:
        if not fields:
            return False
        keys = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [investigation_id]
        with transaction() as conn:
            cursor = conn.execute(f"UPDATE investigations SET {keys} WHERE id = ?", values)
        return cursor.rowcount > 0

    @staticmethod
    def finish(
        investigation_id: str,
        status: str,
        duration_ms: float,
        snapshot: dict[str, Any] | None,
        chokepoints: list[dict[str, Any]] | None,
        simulation: dict[str, Any] | None,
        memory_brief: dict[str, Any] | None,
        error: str = "",
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        return InvestigationRepository.update(
            investigation_id,
            status=status,
            ended_at=now,
            duration_ms=duration_ms,
            snapshot_json=json.dumps(snapshot or {}, default=str),
            chokepoints_json=json.dumps(chokepoints or [], default=str),
            simulation_json=json.dumps(simulation or {}, default=str),
            memory_json=json.dumps(memory_brief or {}, default=str),
            error=error,
        )

    @staticmethod
    def get_latest_completed(exclude_id: str = "") -> dict[str, Any] | None:
        sql = "SELECT * FROM investigations WHERE status = 'done' AND snapshot_json IS NOT NULL AND snapshot_json != ''"
        params: tuple = ()
        if exclude_id:
            sql += " AND id != ?"
            params = (exclude_id,)
        sql += " ORDER BY started_at DESC LIMIT 1"
        return query_one(sql, params)