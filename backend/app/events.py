"""Event bus for the SSE stream, with SQLite persistence and replay.

Events are streamed to live subscribers and persisted in SQLite, so a finished
investigation can be replayed from the stored record alone.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from .db import query_one, _get_conn
from .models import StreamEvent

log = logging.getLogger("chokepoint.events")

# SQLite table for events (created by the shared schema)
EVENT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id            TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    n             INTEGER NOT NULL,
    type          TEXT NOT NULL,
    ts            TEXT NOT NULL,
    payload_json  TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
"""

# Simple in-memory event bus - persisted via SQLite
_event_queues: dict[str, asyncio.Queue] = {}
_event_subscribers: dict[str, list[asyncio.Queue]] = {}
_event_sequence: dict[str, int] = {}
_event_lock = asyncio.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _persist_event(event: dict[str, Any]) -> None:
    """Persist one event to SQLite."""
    conn = _get_conn()
    try:
        await asyncio.to_thread(
            conn.execute,
            """
            INSERT OR IGNORE INTO events (id, investigation_id, n, type, ts, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.get("id", ""),
                event.get("investigation_id", ""),
                event.get("n", 0),
                event.get("type", ""),
                event.get("ts", now_iso()),
                json.dumps(event.get("payload", {}), default=str)[:60000],
                now_iso(),
            ),
        )
        # autocommit mode: _get_conn sets isolation_level=None, so each execute auto-commits
    except Exception as exc:  # noqa: BLE001 - a dropped event must not break a run
        log.warning("could not persist event %s: %s", event.get("id"), exc)
    # autocommit mode: _get_conn sets isolation_level=None, so each execute auto-commits
    # (the COMMIT line below was removed - each execute auto-commits in autocommit mode)


async def emit(investigation_id: str, event_type: str, payload: dict[str, Any] | None = None) -> None:
    """Send one event to all subscribers and persist it."""
    async with _event_lock:
        seq = _event_sequence.get(investigation_id, 0) + 1
        _event_sequence[investigation_id] = seq

        event = {
            "id": f"{investigation_id}-E{seq}",
            "investigation_id": investigation_id,
            "n": seq,
            "type": event_type,
            "ts": now_iso(),
            "payload": payload or {},
        }

        # Initialize queue for this investigation
        if investigation_id not in _event_queues:
            _event_queues[investigation_id] = asyncio.Queue()
        if investigation_id not in _event_subscribers:
            _event_subscribers[investigation_id] = []

        # Put in queue
        queue = _event_queues[investigation_id]
        await queue.put(event)

        # Persist to SQLite
        await _persist_event(event)

        # Notify existing subscribers
        for subscriber in list(_event_subscribers.get(investigation_id, [])):
            try:
                await subscriber.put(event)
            except Exception:  # noqa: BLE001
                pass


def subscribe(investigation_id: str) -> asyncio.Queue:
    """Subscribe to events for an investigation."""
    if investigation_id not in _event_subscribers:
        _event_subscribers[investigation_id] = []
    queue: asyncio.Queue = asyncio.Queue()
    _event_subscribers[investigation_id].append(queue)
    if investigation_id not in _event_queues:
        _event_queues[investigation_id] = asyncio.Queue()
    return queue


def unsubscribe(investigation_id: str, queue: asyncio.Queue) -> None:
    """Unsubscribe from events."""
    if investigation_id in _event_subscribers:
        if queue in _event_subscribers[investigation_id]:
            _event_subscribers[investigation_id].remove(queue)
        if not _event_subscribers[investigation_id]:
            _event_subscribers.pop(investigation_id, None)


def history(investigation_id: str) -> list[dict[str, Any]]:
    """Read persisted events from SQLite for a finished investigation."""
    events: list[dict[str, Any]] = []
    try:
        rows = query_one(
            "SELECT id, n, type, ts, payload_json FROM events WHERE investigation_id = ? ORDER BY n",
            (investigation_id,),
            many=True,
        ) or []
        for row in rows:
            try:
                payload = json.loads(row.get("payload_json", "{}"))
            except json.JSONDecodeError:
                payload = {}
            events.append(
                {
                    "id": row.get("id", ""),
                    "n": int(row.get("n", 0)),
                    "type": str(row.get("type", "")),
                    "ts": str(row.get("ts", "")),
                    "payload": payload,
                }
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("could not read events for %s: %s", investigation_id, exc)
    return events


bus = type("obj", (), {"subscribe": subscribe, "unsubscribe": unsubscribe, "history": history, "emit": staticmethod(emit)})()


def sse_frame(event: dict[str, Any]) -> str:
    evt_type = event.get("type", "message")
    data_str = json.dumps(event, default=str)
    return f"event: {evt_type}\ndata: {data_str}\n\n"


async def event_stream(investigation_id: str, *, is_finished: bool) -> AsyncIterator[str]:
    """Replay persisted events, then follow live queue if investigation is in flight."""
    sent_ids: set[str] = set()

    for ev in history(investigation_id):
        eid = ev.get("id") or f"{ev.get('type')}-{ev.get('n')}"
        if eid not in sent_ids:
            sent_ids.add(eid)
            yield sse_frame(ev)

    if is_finished:
        yield ": closed\n\n"
        return

    queue = subscribe(investigation_id)
    try:
        while True:
            try:
                ev = await asyncio.wait_for(queue.get(), timeout=10.0)
                eid = ev.get("id") or f"{ev.get('type')}-{ev.get('n')}"
                if eid not in sent_ids:
                    sent_ids.add(eid)
                    yield sse_frame(ev)
                if ev.get("type") in ("run_finished", "error"):
                    break
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
    finally:
        unsubscribe(investigation_id, queue)