"""Memory tools (PRD 8.3): hybrid lesson recall and the day-over-day diff.

All database operations use SQLite via repositories - no FalkorDB Cypher queries.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Annotated, Any

from pydantic import Field

from app.repositories.lessons import LessonRepository
from app.repositories.messages import MessageRepository
from app.repositories.feedback import FeedbackRepository
from app.repositories.investigations import InvestigationRepository
from app.graph.attack import enumerate_attack_paths, live_exploits, Modifications, total_weight
from app.graph.algorithms import shortest_path
from app.graph.projection import load_projection
from app.graph import envelope, error_envelope
from app.memory.embeddings import embedder

log = logging.getLogger("chokepoint.tools.memory")

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]+")


def _merge(records: dict[str, dict[str, Any]], row: dict[str, Any], why: str) -> None:
    key = str(row["id"])
    existing = records.get(key)
    if existing is None:
        records[key] = {
            "lesson_id": key,
            "text": row.get("text"),
            "effect": row.get("effect"),
            "scope_kind": row.get("scope_kind"),
            "scope_value": row.get("scope_value"),
            "strength": float(row.get("strength") or 0.0),
            "uses": int(row.get("uses") or 0),
            "why_retrieved": why,
            "via": row.get("via"),
            "similarity": round(float(row["score"], 4) if row.get("score") is not None else None, 4),
        }
        return
    if existing["why_retrieved"] != why:
        existing["why_retrieved"] = "both"
    if row.get("score") is not None and existing.get("similarity") is None:
        existing["similarity"] = round(float(row["score"], 4), 4)
    if row.get("via") and not existing.get("via"):
        existing["via"] = row.get("via")


def _keyword_rank(query_text: str, limit: int) -> tuple[list[dict[str, Any]], str]:
    """Fallback retrieval when vector search is off: token overlap on Lesson text."""
    all_lessons = LessonRepository.list_all()
    wanted = set(TOKEN_RE.findall(query_text.lower()))
    scored: list[tuple[float, dict[str, Any]]] = []
    for row in all_lessons:
        tokens = set(TOKEN_RE.findall(str(row.get("text") or "").lower()))
        tokens |= set(TOKEN_RE.findall(str(row.get("scope_value") or "").lower()))
        if not tokens:
            continue
        overlap = len(tokens & wanted)
        if overlap:
            scored.append((overlap / len(wanted or {"x"}), row))
    scored.sort(key=lambda pair: (-pair[0], str(pair[1]["id"])))
    rows = []
    for score, row in scored[:limit]:
        enriched = dict(row)
        enriched["score"] = round(score, 4)
        rows.append(enriched)
    return rows, "SELECT ''"


def recall(
    subject_ids: Annotated[
        list[str] | None, Field(description="Node ids the question is about: services, findings or packages.")
    ] = None,
    query_text: Annotated[str, Field(description="The question in words, used for similarity search.")] = "",
    query: Annotated[str, Field(description="Alias for query_text")] = "",
    limit: Annotated[int, Field(description="Maximum lessons to return")] = 5,
) -> dict[str, Any]:
    """Retrieve lessons and past verdicts relevant to these subjects, by graph and by similarity."""
    started = time.perf_counter()
    query_text = (query_text or query or "").strip()
    subject_ids = subject_ids or []
    subjects = [s for s in dict.fromkeys(subject_ids) if s][:12]

    # Get graph-based lessons
    graph_lessons = LessonRepository.get_by_graph_proximity(subjects)

    # Get vector-based lessons if available
    vector_used = False
    vector_lessons = []
    if subjects and query_text.strip():
        try:
            vector = embedder().embed(query_text)
            if vector:
                vector_lessons = LessonRepository.get_by_vector(vector, subjects)
                vector_used = True
        except Exception as exc:
            log.info("vector recall unavailable: %s", exc)

    # Combine and deduplicate
    all_records: dict[str, dict[str, Any]] = {}

    # Add graph-based lessons
    for lesson in graph_lessons:
        key = lesson["lesson_id"]
        if key not in all_records:
            all_records[key] = lesson
        else:
            existing = all_records[key]
            if lesson["why_retrieved"] != existing["why_retrieved"]:
                existing["why_retrieved"] = "both"
            if lesson["similarity"] is not None and existing.get("similarity") is None:
                existing["similarity"] = lesson["similarity"]
            if lesson["via"] and not existing.get("via"):
                existing["via"] = lesson["via"]

    # Add vector lessons
    for lesson in vector_lessons:
        key = lesson["lesson_id"]
        if key not in all_records:
            all_records[key] = lesson
        else:
            existing = all_records[key]
            if lesson["why_retrieved"] != existing["why_retrieved"]:
                existing["why_retrieved"] = "both"
            if lesson["similarity"] is not None and existing.get("similarity") is None:
                existing["similarity"] = lesson["similarity"]
            if lesson["via"] and not existing.get("via"):
                existing["via"] = lesson["via"]

    # Add past verdicts
    past_verdicts = FeedbackRepository.get_past_verdicts(subjects) if subjects else []
    for v in past_verdicts:
        key = f"verdict_{v['verdict_id']}"
        if key not in all_records:
            all_records[key] = {
                "lesson_id": key,
                "text": v.get("rationale", ""),
                "effect": v.get("effect"),
                "scope_kind": v.get("scope_kind"),
                "scope_value": v.get("scope_value"),
                "strength": v.get("confidence", 0.0),
                "uses": v.get("uses", 0),
                "why_retrieved": "verdict",
                "via": v.get("service_id", ""),
                "similarity": None,
            }

    # Sort by strength then uses
    lessons = sorted(
        all_records.values(),
        key=lambda r: (-float(r.get("strength") or 0.0), -int(r.get("uses") or 0), str(r["lesson_id"])),
    )

    # Get feedback info
    feedback_ids = set()
    for lesson in lessons:
        fid = lesson.get("source_feedback_id")
        if fid:
            feedback_ids.add(fid)

    feedback_map: dict[str, dict[str, Any]] = {}
    if feedback_ids:
        for fb in FeedbackRepository.get_by_ids(list(feedback_ids)):
            feedback_map[fb["id"]] = {
                "action": "override" if fb.get("action") == "override" else "agree",
                "new_kind": fb.get("new_kind"),
                "note": fb.get("note"),
                "by": fb.get("by_user"),
            }

    # Build lesson details
    lessons_list: list[dict[str, Any]] = []
    for lesson in lessons:
        fid = lesson.get("source_feedback_id")
        source = feedback_map.get(fid) if fid else None
        applies = LessonRepository.get_applies_to(lesson["lesson_id"])

        lessons_list.append({
            "lesson_id": lesson["lesson_id"],
            "text": lesson.get("text", ""),
            "scope_kind": lesson.get("scope_kind", ""),
            "scope_value": lesson.get("scope_value", ""),
            "effect": lesson.get("effect", ""),
            "strength": float(lesson.get("strength") or 0.0),
            "uses": int(lesson.get("uses") or 0),
            "why_retrieved": lesson.get("why_retrieved", "graph"),
            "applies_to": applies,
            "source_feedback": source,
            "investigations": lesson.get("investigations", []),
        })

    # Determine retrieval method
    retrieval = "graph + vector" if vector_used else "graph + keyword"
    if not vector_used and query_text.strip():
        retrieval = "graph + keyword"
    elif not vector_used:
        retrieval = "graph only"

    return envelope(
        summary=f"{len(lessons)} lesson(s) and {len(past_verdicts)} past verdict(s) for "
                f"{len(subjects)} subject(s) via {retrieval}",
        data={
            "lessons": lessons_list,
            "past_verdicts": past_verdicts,
            "subjects": subjects,
            "retrieval": retrieval,
            "vector_search": vector_used,
            "embeddings": LessonRepository.status_embeddings(),
        },
        cypher=[],
        touched_ids=[str(lesson["lesson_id"]) for lesson in lessons[:5]] + subjects,
        rows=len(lessons) + len(past_verdicts),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def diff_since_last(
    investigation_id: Annotated[str | None, Field(description="The current investigation id.")] = None,
) -> dict[str, Any]:
    """Compare current graph state and paths against the prior completed investigation."""
    started = time.perf_counter()
    prev = InvestigationRepository.get_latest_completed(exclude_id=investigation_id or "")
    if not prev or not prev.get("snapshot_json"):
        return envelope(
            summary="No prior completed investigation with snapshot found for comparison.",
            data={"previous_investigation_id": None, "new_paths": [], "resolved_paths": []},
            cypher=[],
            rows=0,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )

    prev_snapshot = (
        json.loads(prev["snapshot_json"])
        if isinstance(prev["snapshot_json"], str)
        else prev["snapshot_json"]
    )
    prev_paths = prev_snapshot.get("paths", [])
    proj = load_projection()
    curr_paths = enumerate_attack_paths(proj, top_k=0)
    prev_keys = {f"{p.get('entry')}->{p.get('target')}" for p in prev_paths if isinstance(p, dict)}
    curr_keys = {f"{p.entry}->{p.target}" for p in curr_paths}
    new_paths = [p.as_dict(verbose=False) for p in curr_paths if f"{p.entry}->{p.target}" not in prev_keys]
    resolved = [
        p for p in prev_paths
        if isinstance(p, dict) and f"{p.get('entry')}->{p.get('target')}" not in curr_keys
    ]

    data = {
        "previous_investigation_id": prev["id"],
        "new_paths": new_paths,
        "resolved_paths": resolved,
        "baseline_paths": len(prev_paths),
        "current_paths": len(curr_paths),
    }
    return envelope(
        summary=f"Compared with {prev['id']}: {len(new_paths)} new paths, {len(resolved)} resolved paths.",
        data=data,
        cypher=[],
        touched_ids=[prev["id"]],
        rows=len(new_paths) + len(resolved),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def register(mcp: Any) -> None:
    mcp.tool(
        name="recall",
        description="Retrieve lessons and past verdicts relevant to these subjects, by graph and by similarity.",
    )(recall)
    mcp.tool(
        name="diff_since_last",
        description="Compare current graph state and paths against the prior completed investigation.",
    )(diff_since_last)
