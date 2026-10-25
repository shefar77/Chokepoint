"""Graph loading entry points and the import seam for real scanner output.

`generate` writes the synthetic estate. `load_findings` is the generic writer a
CycloneDX or Trivy importer would target: an importer only has to yield
:class:`ImportedFinding` rows, which keeps parser code out of the graph layer.
No importer ships with this build.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol

from app.config import settings
from app.repositories.findings import FindingRepository
from app.repositories.scans import ScanRepository
from app.repositories.graph import GraphRepository
from app.repositories.mappings import MappingRepository

from . import scenarios
from .generate import generate, package_id

log = logging.getLogger("chokepoint.seed.loader")


@dataclass(slots=True)
class ImportedFinding:
    """One scanner row, already normalised. The unit an importer must produce."""

    finding_id: str
    service_id: str
    package_name: str
    package_version: str
    ecosystem: str
    cve: str
    cvss: float
    epss: float
    kev: bool
    attack_vector: str
    requires_auth: bool
    fixed_in: str
    summary: str
    status: str = "open"
    reachable_code: bool = False
    scan_id: str = ""
    direct: bool = True
    internal_package: bool = False


class FindingSource(Protocol):
    """What an importer implements. `scan_id` labels the batch."""

    scan_id: str

    def __iter__(self) -> Iterable[ImportedFinding]:  # pragma: no cover - protocol
        ...


def load_findings(source: FindingSource) -> dict[str, Any]:
    """Upsert findings from any source into the estate layer."""
    now = datetime.now(timezone.utc).isoformat()
    findings_to_insert = []
    for row in source:
        findings_to_insert.append({
            "finding_id": row.finding_id,
            "scan_id": row.scan_id or source.scan_id,
            "scanner": "imported",
            "rule_id": row.cve,
            "category": "vulnerability",
            "severity": "CRITICAL",
            "cve": row.cve,
            "cvss": float(row.cvss),
            "epss": float(row.epss),
            "kev": bool(row.kev),
            "attack_vector": row.attack_vector,
            "requires_auth": bool(row.requires_auth),
            "ecosystem": row.ecosystem,
            "package_name": row.package_name,
            "package_version": row.package_version,
            "fixed_in": row.fixed_in,
            "summary": row.summary,
            "status": row.status,
            "reachable_code": bool(row.reachable_code),
            "scan_id": row.scan_id or source.scan_id,
        })
    FindingRepository.bulk_insert(findings_to_insert)
    return {"scan_id": source.scan_id, "findings_written": len(findings_to_insert), "finding_ids": [f["finding_id"] for f in findings_to_insert]}


def reset(scale: int | None = None) -> dict[str, Any]:
    """Drop the graph and regenerate the planted estate."""
    return generate(scale=scale)


def ensure_seeded(scale: int | None = None) -> dict[str, Any]:
    """Seed only when the database is empty, so a restart keeps existing work."""
    from app.db import query_one
    # Check if we have any projects
    row = query_one("SELECT COUNT(*) as c FROM projects")
    if row and row["c"] == 0:
        log.info("database is empty; seeding")
        return reset(scale)
    return {
        "graph": settings.graph_name,
        "scale": scale or settings.seed_scale,
        "nodes": 0,
        "relationships": 0,
        "findings": 0,
        "scan_id": scenarios.SCAN_DAY1,
        "seconds": 0.0,
        "ground_truth_path": str(settings.ground_truth_file),
        "indexes": {},
        "skipped": True,
    }


def read_ground_truth() -> dict[str, Any]:
    """Ground truth lives on disk, never in the graph."""
    path: Path = settings.ground_truth_file
    for candidate in (path, Path(settings.outbox_dir).parent / "ground_truth.json"):
        try:
            return json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
    log.warning("no ground_truth.json found; using the planted labels from scenarios.py")
    return scenarios.ground_truth()