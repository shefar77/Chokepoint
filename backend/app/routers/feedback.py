"""POST /api/verdicts/{id}/feedback - agree, or override and teach a lesson."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException

from app.memory.lessons import record_feedback
from app.models import FeedbackRequest, FeedbackResponse

router = APIRouter(prefix="/verdicts", tags=["feedback"])
log = logging.getLogger("chokepoint.feedback")


@router.post("/{verdict_id}/feedback", response_model=FeedbackResponse)
async def submit_feedback(verdict_id: str, request: FeedbackRequest) -> FeedbackResponse:
    try:
        return await asyncio.to_thread(record_feedback, verdict_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"no verdict {verdict_id}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - report the cause to the analyst
        log.exception("feedback on %s failed", verdict_id)
        raise HTTPException(status_code=500, detail=f"{exc.__class__.__name__}: {exc}") from exc
