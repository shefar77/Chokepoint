"""Optional GitHub issue creation. Silent no-op without a token and repo."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import settings

log = logging.getLogger("chokepoint.github")

TIMEOUT_S = 12.0
API = "https://api.github.com"


def configured() -> bool:
    return bool(settings.github_token.strip() and settings.github_repo.strip())


async def create_issue(action: dict[str, Any]) -> str:
    """Create an issue for an approved action. Returns a status line."""
    if not configured():
        return "github: not configured"
    repo = settings.github_repo.strip()
    labels = ["chokepoint", str(action.get("kind") or "ticket")]
    body = (
        f"{action.get('body_md') or ''}\n\n---\n"
        f"action `{action.get('id')}` | verdict `{action.get('verdict_id')}` | "
        f"team {action.get('team') or 'unrouted'}\n"
    )
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_S) as http:
            response = await http.post(
                f"{API}/repos/{repo}/issues",
                headers={
                    "Authorization": f"Bearer {settings.github_token.strip()}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json={"title": str(action.get("title") or action.get("id")), "body": body, "labels": labels},
            )
        if response.status_code >= 400:
            return f"github: failed with HTTP {response.status_code}"
        number = response.json().get("number")
        return f"github: opened {repo}#{number}"
    except Exception as exc:  # noqa: BLE001 - delivery is best effort
        log.warning("github delivery failed: %s", exc)
        return f"github: failed ({exc.__class__.__name__})"
