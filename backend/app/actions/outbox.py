"""Approved actions are written to disk so the demo has a real artefact."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import settings

log = logging.getLogger("chokepoint.outbox")


def outbox_dir() -> Path:
    path = settings.outbox_path
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_action(action: dict[str, Any]) -> dict[str, str]:
    """Write `<action id>.md` and `<action id>.json`. Returns the paths written."""
    directory = outbox_dir()
    action_id = str(action.get("id") or "action")
    stamp = datetime.now(timezone.utc).isoformat()
    front = [
        f"# {action.get('title') or action_id}",
        "",
        f"- action: `{action_id}`",
        f"- kind: `{action.get('kind')}`",
        f"- verdict: `{action.get('verdict_id')}`",
        f"- team: {action.get('team') or 'unrouted'} ({action.get('slack_channel') or 'no channel'})",
        f"- on call: {', '.join(action.get('on_call') or []) or 'nobody listed'}",
        f"- findings: {', '.join(action.get('finding_ids') or []) or 'none'}",
        f"- approved at: {stamp}",
        "",
        "---",
        "",
    ]
    md_path = directory / f"{action_id}.md"
    json_path = directory / f"{action_id}.json"
    try:
        md_path.write_text("\n".join(front) + str(action.get("body_md") or "") + "\n", encoding="utf-8")
        json_path.write_text(
            json.dumps({**action, "approved_at": stamp}, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        log.error("could not write outbox files for %s: %s", action_id, exc)
        return {"markdown": "", "json": "", "error": str(exc)}
    log.info("wrote %s and %s", md_path, json_path)
    return {"markdown": str(md_path), "json": str(json_path)}
