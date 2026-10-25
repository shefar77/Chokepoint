"""Lesson distillation and feedback handling.

This module turns analyst overrides into lessons with embeddings and scope links.
All database operations use SQLite via repositories.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from app.repositories.lessons import LessonRepository
from app.repositories.feedback import FeedbackRepository

log = logging.getLogger("chokepoint.memory.lessons")


def record_feedback(
    verdict_id: str,
    request: Any,
) -> dict[str, Any]:
    """Record analyst feedback on a verdict and, for an override, distil a lesson.

    The feedback row is written first so the lesson can reference it; the lesson
    scope is taken from the verdict's own finding evidence (package, else file),
    never invented.
    """
    from app.models import FeedbackResponse, MemoryHit
    from app.repositories.verdicts import VerdictRepository

    verdict = VerdictRepository.get(verdict_id)
    if verdict is None:
        raise KeyError(verdict_id)

    action = str(getattr(request, "action", "agree"))
    new_kind = getattr(request, "new_kind", None)
    note = str(getattr(request, "note", "") or "")
    by = str(getattr(request, "by", "analyst") or "analyst")

    feedback_id = f"FB-{uuid.uuid4().hex[:8].upper()}"
    FeedbackRepository.create(
        feedback_id=feedback_id,
        verdict_id=verdict_id,
        action=action,
        new_kind=new_kind or "",
        note=note,
        by_user=by,
    )

    lesson_id = ""
    if action == "override" and new_kind:
        lesson_id = distill_lesson(verdict, str(new_kind), note, feedback_id)
        if lesson_id:
            FeedbackRepository.set_lesson(feedback_id, lesson_id)

    lesson_hit = None
    applies_to: list[str] = []
    if lesson_id:
        row = LessonRepository.get(lesson_id)
        if row:
            applies_to = [str(n) for n in (row.get("applies_to") or [])]
            lesson_hit = MemoryHit(
                lesson_id=lesson_id,
                text=str(row.get("text") or ""),
                effect=str(row.get("effect") or ""),
                scope_kind=str(row.get("scope_kind") or ""),
                scope_value=str(row.get("scope_value") or ""),
                strength=float(row.get("strength") or 0.0),
                uses=int(row.get("uses") or 0),
                why_retrieved="graph",
            )

    if action == "override" and new_kind:
        message = f"Override recorded: {verdict.get('kind')} -> {new_kind}."
        message += f" Lesson {lesson_id} stored." if lesson_id else " No lesson: the verdict carries no package or file evidence to scope one to."
    else:
        message = "Agreement recorded. No lesson needed."

    return FeedbackResponse(
        feedback_id=feedback_id,
        verdict_id=verdict_id,
        action=action,
        lesson=lesson_hit,
        lesson_applies_to=applies_to,
        message=message,
    )


def distill_lesson(
    verdict: dict[str, Any],
    new_kind: str,
    note: str,
    feedback_id: str,
) -> str:
    """Create a lesson from an override, scoped to the verdict's own evidence."""
    from app.repositories.findings import FindingRepository
    from app.repositories.mappings import MappingRepository

    finding_ids = verdict.get("finding_ids") or []
    if not finding_ids:
        return ""
    finding = FindingRepository.get(str(finding_ids[0]))
    if not finding:
        return ""

    # Scope the lesson to the strongest identifier the finding actually carries.
    if finding.get("package_name"):
        scope_kind, scope_value = "package", str(finding["package_name"])
    elif finding.get("cve"):
        scope_kind, scope_value = "cve", str(finding["cve"])
    elif finding.get("file_path"):
        scope_kind, scope_value = "file", str(finding["file_path"])
    else:
        return ""

    effect = {
        "ACCEPT": "downgrade",
        "SUPPRESS": "suppress",
        "SCHEDULE": "downgrade",
        "FIX_NOW": "upgrade",
    }.get(new_kind, "require_check")

    text = (
        f"An analyst overrode {verdict.get('kind') or 'the verdict'} to {new_kind} "
        f"for {scope_kind} {scope_value}."
    )
    if note:
        text = f"{text} Analyst note: {note}"

    # The lesson applies to the graph nodes this finding was actually mapped to.
    applies_to = [
        str(m["node_id"])
        for m in MappingRepository.for_finding(str(finding_ids[0]))
        if m.get("node_id")
    ]
    if not applies_to:
        applies_to = [scope_value]

    embedding = None
    try:
        from app.memory.embeddings import embedder

        vec = embedder().embed(text)
        if vec:
            import struct

            embedding = struct.pack(f"{len(vec)}f", *vec)
    except Exception:  # noqa: BLE001 - embeddings are optional
        embedding = None

    lesson_id = f"L-{LessonRepository.next_number():04d}"
    LessonRepository.create(
        lesson_id=lesson_id,
        text=text,
        scope_kind=scope_kind,
        scope_value=scope_value,
        effect=effect,
        strength=0.65,
        embedding=embedding,
        source_feedback_id=feedback_id,
        applies_to=applies_to,
    )
    return lesson_id


def list_lessons() -> list[dict[str, Any]]:
    """List all lessons with their scope links."""
    return LessonRepository.list_all()


def get_lesson(lesson_id: str) -> dict[str, Any] | None:
    """Get a lesson by id."""
    return LessonRepository.get(lesson_id)


def feedback_for_verdict(verdict_id: str) -> Any | None:
    """Fetch the latest feedback for a verdict."""
    from app.models import FeedbackModel

    items = FeedbackRepository.list_for_verdict(verdict_id)
    if not items:
        return None
    fb = items[-1]
    return FeedbackModel(
        id=str(fb.get("id") or ""),
        action=str(fb.get("action") or "agree"),
        new_kind=fb.get("new_kind") or None,
        note=str(fb.get("note") or ""),
        by=str(fb.get("by_user") or ""),
        at=str(fb.get("created_at") or ""),
        lesson_id=str(fb.get("lesson_id") or ""),
    )
