"""Action approval. Approving writes the outbox files and the graph status."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from app.actions import github, outbox, slack
from app.config import settings
from app.repositories.actions import ActionRepository
from app.repositories.findings import FindingRepository
from app.models import ActionDecisionResponse, ActionModel

router = APIRouter(prefix="/actions", tags=["actions"])
log = logging.getLogger("chokepoint.actions")

# A ticket leaves findings open until an engineer actually ships the fix; only
# an approved suppression changes the finding state.
STATUS_FOR_KIND = {"suppress": "suppressed", "virtual_patch_request": "accepted"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_action(action_id: str) -> dict:
    """Read an action by id, including related data."""
    action = ActionRepository.get(action_id)
    if not action:
        raise KeyError(action_id)
    # Nullable columns come back as None, which the response model rejects, so
    # every string field is coerced here rather than at each call site.
    return {
        "id": str(action["id"]),
        "kind": str(action["kind"] or "ticket"),
        "status": str(action["status"] or "proposed"),
        "title": str(action.get("title") or ""),
        "body_md": str(action.get("body_md") or ""),
        "created_at": str(action.get("created_at") or ""),
        "verdict_id": str(action.get("verdict_id") or ""),
        "verdict_kind": str(action.get("verdict_kind") or ""),
        "team": str(action.get("team") or ""),
        "slack_channel": str(action.get("slack_channel") or ""),
        "on_call": [str(p) for p in (action.get("on_call") or [])],
        "finding_ids": [str(f) for f in (action.get("finding_ids") or [])],
        "outbox_path": str(action.get("outbox_path") or ""),
        "delivery": [str(d) for d in (action.get("delivery") or [])],
    }


@router.post("/{action_id}/approve", response_model=ActionDecisionResponse)
async def approve(action_id: str) -> ActionDecisionResponse:
    try:
        action = await asyncio.to_thread(_read_action, action_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"no action {action_id}") from exc
    if action["status"] in ("executed", "rejected"):
        raise HTTPException(status_code=409, detail=f"action {action_id} is already {action['status']}")

    written = await asyncio.to_thread(outbox.write_action, action)
    delivery = [f"outbox: {written.get('markdown') or written.get('error') or 'not written'}"]
    delivery.append(await slack.post_action(action))
    delivery.append(await github.create_issue(action))

    finding_status = STATUS_FOR_KIND.get(action["kind"])
    if finding_status and action["finding_ids"]:
        for fid in action["finding_ids"]:
            await asyncio.to_thread(FindingRepository.update_mapping, fid, "status", finding_status)
        delivery.append(f"graph: {len(action['finding_ids'])} finding(s) set to '{finding_status}'")
    else:
        delivery.append("graph: finding statuses unchanged until the fix ships")

    await asyncio.to_thread(
        ActionRepository.update_status,
        action_id,
        "executed",
        outbox_path=written.get("markdown", ""),
        delivery=delivery,
    )
    updated = await asyncio.to_thread(_read_action, action_id)
    return ActionDecisionResponse(
        action=ActionModel(**updated),
        message=f"Approved and executed. {delivery[0]}",
    )


@router.post("/{action_id}/reject", response_model=ActionDecisionResponse)
async def reject(action_id: str) -> ActionDecisionResponse:
    try:
        action = await asyncio.to_thread(_read_action, action_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"no action {action_id}") from exc
    if action["status"] == "executed":
        raise HTTPException(status_code=409, detail=f"action {action_id} is already executed")
    await asyncio.to_thread(
        ActionRepository.update_status,
        action_id,
        "rejected",
        outbox_path="",
        delivery=["rejected by analyst"],
    )
    updated = await asyncio.to_thread(_read_action, action_id)
    return ActionDecisionResponse(action=ActionModel(**updated), message="Rejected. Nothing was sent.")