"""Optional Slack delivery. Silent no-op when SLACK_WEBHOOK_URL is unset."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import settings

log = logging.getLogger("chokepoint.slack")

TIMEOUT_S = 8.0


def configured() -> bool:
    return bool(settings.slack_webhook_url.strip())


async def post_action(action: dict[str, Any]) -> str:
    """Post a short summary to the configured webhook. Returns a status line."""
    if not configured():
        return "slack: not configured"
    channel = str(action.get("slack_channel") or "")
    oncall = ", ".join(action.get("on_call") or []) or "nobody listed"
    text = (
        f"*{action.get('title')}*\n"
        f"action `{action.get('id')}` from verdict `{action.get('verdict_id')}`\n"
        f"team {action.get('team') or 'unrouted'} {channel} | on call: {oncall}\n"
        f"findings: {', '.join(action.get('finding_ids') or []) or 'none'}"
    )
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_S) as http:
            response = await http.post(settings.slack_webhook_url.strip(), json={"text": text})
        if response.status_code >= 400:
            return f"slack: failed with HTTP {response.status_code}"
        return f"slack: posted to {channel or 'webhook'}"
    except Exception as exc:  # noqa: BLE001 - delivery is best effort
        log.warning("slack delivery failed: %s", exc)
        return f"slack: failed ({exc.__class__.__name__})"
