"""POST /api/seed/reset and POST /api/scan/delta."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter

from app.models import DeltaResponse, SeedRequest, SeedResponse
from app.seed.delta_day2 import apply_delta
from app.seed.loader import reset

router = APIRouter(tags=["admin"])
log = logging.getLogger("chokepoint.admin")


@router.post("/seed/reset", response_model=SeedResponse)
async def seed_reset(request: SeedRequest) -> SeedResponse:
    stats = await asyncio.to_thread(reset, request.scale)
    log.info("seed reset at scale %s", request.scale)
    return SeedResponse(
        graph=str(stats["graph"]),
        scale=int(stats["scale"]),
        nodes=int(stats["nodes"]),
        relationships=int(stats["relationships"]),
        findings=int(stats["findings"]),
        scan_id=str(stats["scan_id"]),
        seconds=float(stats.get("seconds") or 0.0),
        ground_truth_path=str(stats.get("ground_truth_path") or ""),
        indexes={k: v for k, v in (stats.get("indexes") or {}).items() if v != "ok"},
    )


@router.post("/scan/delta", response_model=DeltaResponse)
async def scan_delta() -> DeltaResponse:
    result = await asyncio.to_thread(apply_delta)
    return DeltaResponse(**result)
