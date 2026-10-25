"""Normalized scanner findings."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.db import query_one, transaction

log = logging.getLogger("chokepoint.repo.findings")


class FindingRepository:
    """CRUD for normalized findings from Trivy, Semgrep, etc."""

    @staticmethod
    def bulk_insert(findings: list[dict[str, Any]]) -> int:
        """Insert many findings. Returns the count written."""
        if not findings:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                f["finding_id"],
                f["scan_id"],
                f.get("scanner", ""),
                f.get("rule_id", ""),
                f.get("category", ""),
                f.get("severity", ""),
                f.get("cve", ""),
                f.get("cwe", ""),
                float(f.get("cvss") or 0.0),
                float(f.get("epss") or 0.0),
                int(bool(f.get("kev"))),
                f.get("attack_vector", ""),
                int(bool(f.get("requires_auth"))),
                f.get("ecosystem", ""),
                f.get("package_name", ""),
                f.get("installed_version", "") or f.get("package_version", ""),
                f.get("package_version", "") or f.get("installed_version", ""),
                f.get("fixed_version", "") or f.get("fixed_in", ""),
                f.get("fixed_in", ""),
                f.get("file_path", "") or f.get("source_file", ""),
                f.get("line_start"),
                f.get("line_end"),
                f.get("symbol", "") or f.get("source_symbol", ""),
                f.get("summary", ""),
                f.get("evidence_json", "{}"),
                f.get("references_json", "[]"),
                f.get("mapping_status", "unmatched"),
                f.get("provenance", ""),
                f.get("status", "open"),
                int(bool(f.get("reachable_code"))),
                f.get("reachability", "not_established"),
                now,
            )
            for f in findings
        ]
        with transaction() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO findings (
                    finding_id, scan_id, scanner, rule_id, category, severity, cve, cwe, cvss, epss, kev,
                    attack_vector, requires_auth, ecosystem, package_name, installed_version, package_version,
                    fixed_version, fixed_in, file_path, line_start, line_end, symbol, summary, evidence_json,
                    references_json, mapping_status, provenance, status, reachable_code, reachability, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        log.info("inserted %d findings", len(rows))
        return len(rows)

    @staticmethod
    def get(finding_id: str) -> dict[str, Any] | None:
        """Fetch one finding."""
        row = query_one("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
        if row:
            row["evidence"] = json.loads(row.pop("evidence_json", "{}"))
            row["references"] = json.loads(row.pop("references_json", "[]"))
        return row

    @staticmethod
    def list_for_scan(scan_id: str, status: str | None = None) -> list[dict[str, Any]]:
        """List findings for a scan, optionally filtered by status."""
        if status:
            rows = query_one(
                "SELECT * FROM findings WHERE scan_id = ? AND status = ? ORDER BY severity DESC, finding_id",
                (scan_id, status),
                many=True,
            ) or []
        else:
            rows = query_one(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity DESC, finding_id",
                (scan_id,),
                many=True,
            ) or []
        for row in rows:
            row["evidence"] = json.loads(row.pop("evidence_json", "{}"))
            row["references"] = json.loads(row.pop("references_json", "[]"))
        return rows

    @staticmethod
    def update_mapping(finding_id: str, mapping_status: str, provenance: str = "") -> bool:
        """Update the mapping status and provenance after graph enrichment."""
        with transaction() as conn:
            cursor = conn.execute(
                "UPDATE findings SET mapping_status = ?, provenance = ? WHERE finding_id = ?",
                (mapping_status, provenance, finding_id),
            )
        return cursor.rowcount > 0

    @staticmethod
    def mark_resolved(finding_id: str) -> bool:
        """Mark a finding resolved (status='resolved')."""
        with transaction() as conn:
            cursor = conn.execute(
                "UPDATE findings SET status = 'resolved' WHERE finding_id = ?", (finding_id,)
            )
        return cursor.rowcount > 0

    @staticmethod
    def delete_all() -> None:
        """Delete all findings and finding mappings."""
        with transaction() as conn:
            conn.execute("DELETE FROM findings")
            conn.execute("DELETE FROM finding_mappings")

    @staticmethod
    def _add_package(pid: str, name: str, version: str, ecosystem: str, internal: bool = False) -> None:
        pass

    @staticmethod
    def _mark_affected(pid: str, vid: str, fixed: str) -> None:
        pass


