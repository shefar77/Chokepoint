"""Index and constraint creation. Idempotent: every statement may already exist."""

from __future__ import annotations

import logging

from app.db import try_query

log = logging.getLogger("chokepoint.seed.schema")

RANGE_INDEXES: tuple[str, ...] = (
    "CREATE INDEX FOR (n:Service) ON (n.id)",
    "CREATE INDEX FOR (n:Service) ON (n.name)",
    "CREATE INDEX FOR (n:Vulnerability) ON (n.cve)",
    "CREATE INDEX FOR (n:Vulnerability) ON (n.id)",
    "CREATE INDEX FOR (n:Finding) ON (n.id)",
    "CREATE INDEX FOR (n:Finding) ON (n.status)",
    "CREATE INDEX FOR (n:Package) ON (n.name)",
    "CREATE INDEX FOR (n:Package) ON (n.id)",
    "CREATE INDEX FOR (n:DataStore) ON (n.id)",
    "CREATE INDEX FOR (n:Ingress) ON (n.id)",
    "CREATE INDEX FOR (n:IAMRole) ON (n.id)",
    "CREATE INDEX FOR (n:Control) ON (n.id)",
    "CREATE INDEX FOR (n:Team) ON (n.id)",
    "CREATE INDEX FOR (n:Person) ON (n.id)",
    "CREATE INDEX FOR (n:Internet) ON (n.id)",
    "CREATE INDEX FOR (n:Investigation) ON (n.id)",
    "CREATE INDEX FOR (n:Step) ON (n.id)",
    "CREATE INDEX FOR (n:Event) ON (n.id)",
    "CREATE INDEX FOR (n:AttackPath) ON (n.id)",
    "CREATE INDEX FOR (n:Hypothesis) ON (n.id)",
    "CREATE INDEX FOR (n:Challenge) ON (n.id)",
    "CREATE INDEX FOR (n:Verdict) ON (n.id)",
    "CREATE INDEX FOR (n:Action) ON (n.id)",
    "CREATE INDEX FOR (n:Feedback) ON (n.id)",
    "CREATE INDEX FOR (n:Lesson) ON (n.id)",
)

FULLTEXT_INDEXES: tuple[str, ...] = (
    "CALL db.idx.fulltext.createNodeIndex('Service', 'name', 'repo')",
    "CALL db.idx.fulltext.createNodeIndex('Vulnerability', 'cve', 'summary')",
    "CALL db.idx.fulltext.createNodeIndex('Lesson', 'text', 'scope_value')",
)

VECTOR_INDEXES: tuple[str, ...] = (
    "CREATE VECTOR INDEX FOR (l:Lesson) ON (l.embedding) "
    "OPTIONS {dimension: 384, similarityFunction: 'cosine'}",
)


def ensure_indexes(graph: str | None = None) -> dict[str, str]:
    """Create every index, tolerating ones that already exist."""
    results: dict[str, str] = {}
    for statement in (*RANGE_INDEXES, *FULLTEXT_INDEXES, *VECTOR_INDEXES):
        results[statement] = try_query(statement, graph=graph)
    created = sum(1 for v in results.values() if v == "ok")
    log.info("indexes: %d created or confirmed, %d skipped", created, len(results) - created)
    return results
