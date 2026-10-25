"""The day-2 scan: scenario S7 plus the S6 follow-up.

Publishes `search.acme.example`, adds an injection finding on `search-api`
(which already calls `catalog-svc` with `authz:'none'`, and `catalog-svc`
reads `customers-pg`), and adds the `feature-lab` finding that the sandbox
lesson should downgrade.

All database operations use SQLite via repositories - no Cypher queries.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.config import settings
from app.repositories.findings import FindingRepository
from app.repositories.graph import GraphRepository
from app.repositories.scans import ScanRepository

from . import scenarios

log = logging.getLogger("chokepoint.seed.delta")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def already_applied() -> bool:
    """Check if the day-2 delta has already been applied."""
    from app.db import query_one
    for spec in scenarios.DELTA_FINDINGS:
        row = query_one("SELECT 1 FROM findings WHERE finding_id = ?", (spec["id"],))
        if row:
            return True
    return False


def apply_delta() -> dict[str, Any]:
    """Apply the day-2 scan. Idempotent: a second call reports nothing new."""
    if already_applied():
        return {
            "applied": False,
            "scan_id": scenarios.SCAN_DAY2,
            "new_findings": [],
            "new_ingress": [],
            "message": "Day-2 scan is already applied. Reset the seed to run it again.",
        }

    now = _now()
    ingress = scenarios.DELTA_INGRESS

    # Create scan record
    scan_id = ScanRepository.create(
        scan_id=scenarios.SCAN_DAY2,
        project_id="initial",
        kind="repository",
        source_type="generated",
        source_ref="day-2-delta",
        workspace_path="",
        status="completed",
    )

    # Add ingress as a graph node
    GraphRepository.bulk_insert_nodes([{
        "id": ingress["id"],
        "scan_id": scan_id,
        "label": "Ingress",
        "properties": {
            "id": ingress["id"],
            "host": ingress["host"],
            "public": bool(ingress["public"]),
            "waf": bool(ingress["waf"]),
            "authn": ingress["authn"],
            "created_at": now,
        }
    }])

    # Add REACHES edge from internet to ingress
    GraphRepository.bulk_insert_edges([{
        "source_id": "internet",
        "target_id": ingress["id"],
        "relation": "REACHES",
        "scan_id": scan_id,
        "properties": {},
    }])

    # Add ROUTES_TO edge from ingress to service
    GraphRepository.bulk_insert_edges([{
        "source_id": ingress["id"],
        "target_id": ingress["service"],
        "relation": "ROUTES_TO",
        "scan_id": scan_id,
        "properties": {"path_prefix": ingress["path_prefix"]},
    }])

    # Update service to be internet-facing
    from app.db import execute
    execute(
        "UPDATE graph_nodes SET properties = json_set(properties, '$.internet_facing', 1) WHERE id = ? AND scan_id = ?",
        (ingress["service"], scan_id),
    )

    created: list[str] = []
    for spec in scenarios.DELTA_FINDINGS:
        pkg_spec = next(p for p in scenarios.PLANTED_PACKAGES if p["name"] == spec["package"])
        vuln = next(v for v in scenarios.PLANTED_VULNERABILITIES if v["id"] == spec["cve"])
        FindingRepository.bulk_insert([{
            "finding_id": spec["id"],
            "scan_id": scan_id,
            "scanner": "synthetic",
            "rule_id": spec["cve"],
            "category": "vulnerability",
            "severity": "CRITICAL",
            "cve": spec["cve"],
            "cvss": float(vuln["cvss"]),
            "epss": float(vuln["epss"]),
            "kev": bool(vuln["kev"]),
            "attack_vector": vuln["attack_vector"],
            "requires_auth": bool(vuln["requires_auth"]),
            "ecosystem": pkg_spec["ecosystem"],
            "package_name": pkg_spec["name"],
            "package_version": pkg_spec["version"],
            "fixed_in": vuln["fixed_in"],
            "summary": vuln["summary"],
            "status": spec["status"],
            "reachable_code": bool(spec["reachable_code"]),
            "scan_id": scan_id,
        }])
        created.append(str(spec["id"]))

    log.info("day-2 delta applied: %s new findings, %s new ingress", len(created), 1)
    return {
        "applied": True,
        "scan_id": scenarios.SCAN_DAY2,
        "new_findings": created,
        "new_ingress": [str(ingress["id"])],
        "message": (
            f"Day-2 scan {scenarios.SCAN_DAY2}: {ingress['host']} is now public and routes to "
            f"{ingress['service']}; {len(created)} new findings."
        ),
    }