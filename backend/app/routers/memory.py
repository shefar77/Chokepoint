"""GET /api/memory/lessons - lessons with their scope, source and usage."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter

from app.db import query_one
from app.memory.embeddings import embedder
from app.models import EmbeddingStatus, FeedbackModel, GraphNode, LessonDetail, LessonsResponse
from app.repositories.feedback import LessonRepository

router = APIRouter(prefix="/memory", tags=["memory"])


@router.get("/lessons", response_model=LessonsResponse)
async def lessons() -> LessonsResponse:
    return await asyncio.to_thread(_collect)


def _collect() -> LessonsResponse:
    # Get all lessons from repository
    lessons = LessonRepository.list_all()

    # Get feedback for lessons that have source_feedback_id
    feedback_map: dict[str, FeedbackModel] = {}
    for lesson in lessons:
        source_feedback_id = lesson.get("source_feedback_id", "")
        if source_feedback_id:
            fb = query_one("SELECT * FROM feedback WHERE id = ?", (source_feedback_id,))
            if fb:
                new_kind = str(fb.get("new_kind") or "")
                feedback_map[source_feedback_id] = FeedbackModel(
                    id=str(fb["id"]),
                    action="override" if str(fb.get("action")) == "override" else "agree",
                    new_kind=new_kind if new_kind in ("FIX_NOW", "SCHEDULE", "ACCEPT", "SUPPRESS") else None,
                    note=str(fb.get("note") or ""),
                    by=str(fb.get("by_user") or ""),
                    at=str(fb.get("created_at") or ""),
                    lesson_id=str(fb.get("lesson_id") or ""),
                )

    # Get node details for applies_to
    node_map: dict[str, GraphNode] = {}
    all_node_ids = set()
    for lesson in lessons:
        all_node_ids.update(lesson.get("applies_to", []))
    if all_node_ids:
        for node_id in list(all_node_ids)[:400]:
            row = query_one(
                # the column is properties_json; "properties" never existed
                "SELECT id, label, properties_json FROM graph_nodes WHERE id = ?",
                (node_id,),
            )
            if row:
                import json
                props = json.loads(row["properties_json"] or "{}")
                node_map[node_id] = GraphNode(
                    id=row["id"],
                    label=row["label"],
                    props={"name": props.get("name") or row["id"]},
                )

    lesson_details: list[LessonDetail] = []
    for lesson in lessons:
        applies = [node_map[n] for n in lesson.get("applies_to", []) if n in node_map]
        source = feedback_map.get(lesson.get("source_feedback_id", ""), None)
        lesson_details.append(
            LessonDetail(
                id=lesson["id"],
                text=lesson.get("text", ""),
                scope_kind=lesson.get("scope_kind", ""),
                scope_value=lesson.get("scope_value", ""),
                effect=lesson.get("effect", ""),
                strength=float(lesson.get("strength") or 0.0),
                uses=int(lesson.get("uses") or 0),
                created_at=lesson.get("created_at", ""),
                applies_to=applies,
                source_feedback=source,
                investigations=lesson.get("investigations", []),
            )
        )

    status = embedder().status()
    note = (
        "Lessons are retrieved two ways: by graph proximity, when a lesson APPLIES_TO a node within "
        "two hops of the subject, and by embedding similarity on the question text."
    )
    if status.get("warning"):
        note += f" Vector memory is off: {status['warning']} Retrieval falls back to keyword plus graph proximity."
    return LessonsResponse(lessons=lesson_details, embeddings=EmbeddingStatus(**status), note=note)