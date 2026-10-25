"""CHOKEPOINT backend: FastAPI app, routers and lifespan."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .actions.outbox import outbox_dir
from .config import settings
from .db import ping
from .memory.embeddings import warm_up
from .orchestrator.mcp_client import client
from .routers import (
    actions,
    admin,
    codebase,
    cypher,
    evals,
    feedback,
    graph,
    health,
    investigations,
    mcp_tools,
    memory,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
)
log = logging.getLogger("chokepoint")

_STARTUP_TASKS: set[asyncio.Task[None]] = set()

DESCRIPTION = (
    "Repository-focused security triage: Graphify extracts code relationships, "
    "scanners produce findings, NetworkX builds and analyses the enriched security graph, "
    "three agents investigate through MCP, deterministic scoring prioritises fixes."
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    log.info("CHOKEPOINT %s starting in '%s' agent mode", __version__, settings.effective_mode)
    if settings.mode_warning:
        log.warning(settings.mode_warning)
    try:
        outbox_dir()
    except OSError as exc:
        log.warning("outbox directory %s unavailable: %s", settings.outbox_dir, exc)

    # SQLite is always available - just ping it
    if await asyncio.to_thread(ping):
        log.info("SQLite ready: persistent store active")
    else:
        log.error("SQLite never became reachable; /api/health will report the problem")

    _track(asyncio.create_task(_connect_mcp()))
    if settings.embeddings_enabled:
        _track(asyncio.create_task(_warm_embeddings()))
    yield
    await client.close()
    log.info("CHOKEPOINT stopped")


def _track(task: asyncio.Task[None]) -> None:
    _STARTUP_TASKS.add(task)
    task.add_done_callback(_STARTUP_TASKS.discard)


async def _warm_embeddings() -> None:
    status = await asyncio.to_thread(warm_up)
    log.info("embeddings: %s", status)


async def _connect_mcp() -> None:
    for attempt in range(1, 16):
        if await client.connect():
            tools = await client.list_tools(refresh=True)
            log.info("discovered %d MCP tools from %s", len(tools), settings.mcp_url)
            return
        await asyncio.sleep(2.0 * attempt if attempt < 5 else 10.0)
    log.error("could not reach the MCP server at %s: %s", settings.mcp_url, client.last_error)


app = FastAPI(
    title="CHOKEPOINT",
    version=__version__,
    description=DESCRIPTION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list or ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

for module in (
    health,
    graph,
    codebase,
    cypher,
    investigations,
    feedback,
    actions,
    memory,
    evals,
    mcp_tools,
    admin,
):
    app.include_router(module.router, prefix="/api")


@app.get("/api", include_in_schema=False)
async def api_root() -> dict[str, str]:
    return {
        "name": "CHOKEPOINT",
        "version": __version__,
        "agent_mode": settings.effective_mode,
        "graph": "security-graph",
        "docs": "/docs",
    }