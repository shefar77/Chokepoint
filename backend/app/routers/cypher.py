"""Read-only SQL for the Explorer, using SQLite + NetworkX instead of FalkorDB.

The "Cypher" name is kept for API compatibility with the frontend, but all
queries are executed as plain SQL against the SQLite-backed graph nodes/edges.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from fastapi import APIRouter, HTTPException

from app.config import settings
from app.db import execute, query_one
from app.models import CypherRequest, CypherResponse, SchemaResponse
from app.graph.projection import load_projection

router = APIRouter(tags=["cypher"])

# Read-only SQL keywords
FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|attach|detach|pragma|vacuum|replace)\b",
    re.IGNORECASE,
)


def _get_projection():
    """Load the projection for the most recent completed scan."""
    scan_row = query_one(
        "SELECT id FROM scans WHERE status = 'completed' "
        "ORDER BY completed_at DESC, started_at DESC LIMIT 1"
    )
    scan_id = scan_row["id"] if scan_row else None
    return load_projection(scan_id)


def _schema() -> SchemaResponse:
    proj = _get_projection()

    # Node labels
    label_counts: dict[str, int] = {}
    for props in proj.nodes.values():
        label = props.get("label", "Unknown")
        label_counts[label] = label_counts.get(label, 0) + 1

    # Relationship types
    rel_counts: dict[str, int] = {}
    for _, _, data in proj.graph.edges(data=True):
        rel = data.get("relation", "UNKNOWN")
        rel_counts[rel] = rel_counts.get(rel, 0) + 1

    # Convert to list of dicts
    labels_list = [
        {"label": label, "count": count}
        for label, count in sorted(label_counts.items(), key=lambda x: -x[1])
    ]
    rels_list = [
        {"type": rel, "count": count}
        for rel, count in sorted(rel_counts.items(), key=lambda x: -x[1])
    ]

    # Saved examples. Every one of these runs against the real schema: the
    # previous set referenced an "attacks" table and findings.service_id,
    # graph_edges.source/protocol/rps and graph_nodes.classification/properties,
    # none of which exist, so six of the seven returned HTTP 400.
    examples = [
        {
            "name": "Highest-rated open findings",
            "description": "The naive view: open findings ordered by the severity their scanner reported.",
            "query": (
                "SELECT finding_id, scanner, cve, severity, cvss, package_name, "
                "installed_version, fixed_version, reachability "
                "FROM findings WHERE status = 'open' "
                "ORDER BY cvss DESC, severity, finding_id LIMIT 25"
            ),
        },
        {
            "name": "Findings whose reachability is not established",
            "description": "The honest middle: detected, mapped, but with no evidence the vulnerable code is reached.",
            "query": (
                "SELECT finding_id, cve, package_name, mapping_status, reachability "
                "FROM findings WHERE reachability != 'supported' "
                "ORDER BY cvss DESC LIMIT 25"
            ),
        },
        {
            "name": "Findings by mapping status",
            "description": "How many findings could be tied to a graph entity, and how.",
            "query": (
                "SELECT mapping_status, COUNT(*) AS findings "
                "FROM findings GROUP BY mapping_status ORDER BY findings DESC"
            ),
        },
        {
            "name": "Graph node types",
            "description": "What the security graph is made of for the latest scan.",
            "query": (
                "SELECT label, COUNT(*) AS nodes FROM graph_nodes "
                "GROUP BY label ORDER BY nodes DESC"
            ),
        },
        {
            "name": "Extracted versus inferred relationships",
            "description": "Code relationships Graphify extracted, against hops CHOKEPOINT modelled.",
            "query": (
                "SELECT relation, json_extract(properties_json, '$.provenance') AS provenance, "
                "COUNT(*) AS edges FROM graph_edges "
                "GROUP BY relation, provenance ORDER BY edges DESC"
            ),
        },
        {
            "name": "Dependency edges and their packages",
            "description": "Which component declares which package, from the manifests.",
            "query": (
                "SELECT e.source_id AS component, e.target_id AS package, "
                "json_extract(n.properties_json, '$.version') AS version, "
                "json_extract(n.properties_json, '$.ecosystem') AS ecosystem "
                "FROM graph_edges e JOIN graph_nodes n ON n.id = e.target_id "
                "AND n.scan_id = e.scan_id WHERE e.relation = 'DEPENDS_ON' "
                "ORDER BY package LIMIT 50"
            ),
        },
        {
            "name": "Verdicts and whether their claims were grounded",
            "description": "Every decision with the result of the grounding check.",
            "query": (
                "SELECT id, investigation_id, kind, confidence, grounded, headline "
                "FROM verdicts ORDER BY created_at DESC LIMIT 25"
            ),
        },
        {
            "name": "Lessons and what they apply to",
            "description": "The memory layer linked back into the graph.",
            "query": (
                "SELECT l.id, l.text, l.scope_kind, l.scope_value, l.effect, a.node_id "
                "FROM lessons l LEFT JOIN lesson_applies_to a ON a.lesson_id = l.id "
                "ORDER BY l.created_at DESC LIMIT 25"
            ),
        },
    ]

    return SchemaResponse(
        labels=labels_list,
        relationship_types=rels_list,
        examples=examples,
    )


def _run(query: str) -> dict:
    """Execute a read-only SQL query."""
    q = query.strip().rstrip(";")
    if not re.match(r"^\s*(select|with)\b", q, re.IGNORECASE):
        raise HTTPException(
            status_code=400, detail="Only SELECT (or WITH ... SELECT) statements are allowed."
        )
    if ";" in q:
        raise HTTPException(status_code=400, detail="Only a single statement is allowed.")
    if FORBIDDEN.search(q):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Write operations are not allowed. Use SELECT only."
            ),
        )
    started = time.perf_counter()
    try:
        # One execution: the previous version ran the statement a second time
        # just to read the column names, and reported latency_ms as a constant 0.
        cursor = execute(q)
        header = [d[0] for d in (cursor.description or [])]
        rows = cursor.fetchall()
        capped = rows[: settings.cypher_row_cap]
        return {
            "header": header,
            "rows": [list(r) for r in capped],
            "row_count": len(rows),
            "latency_ms": round((time.perf_counter() - started) * 1000.0, 2),
            "truncated": len(rows) > settings.cypher_row_cap,
            "query": q,
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"{exc.__class__.__name__}: {exc}") from exc


@router.get("/schema", response_model=SchemaResponse)
@router.get("/cypher/schema", response_model=SchemaResponse)
async def schema() -> SchemaResponse:
    return await asyncio.to_thread(_schema)


@router.post("/cypher/readonly", response_model=CypherResponse)
async def readonly(request: CypherRequest) -> CypherResponse:
    return await asyncio.to_thread(_run, request.query)