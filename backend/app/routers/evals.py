"""GET /api/evals/run - the evaluation that ships in the product (PRD 13)."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter

from app.evals.metrics import run_evaluation
from app.models import EvalResponse

router = APIRouter(prefix="/evals", tags=["evals"])


@router.get("/run", response_model=EvalResponse)
async def run() -> EvalResponse:
    return await asyncio.to_thread(run_evaluation)
