"""MCP client: tool discovery and role-scoped tool invocation.

The agents never touch the database. Everything goes through this client to the
`chokepoint-mcp` server. The three functions marked WRAPPER below are the only
places that touch the `mcp` SDK surface.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import AsyncExitStack
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from app.config import settings
from mcp_server.tools import TOOL_META, allowed, is_write, roles_for

from .providers.base import ToolCall, ToolOutcome, ToolSpec

log = logging.getLogger("chokepoint.mcp_client")

CONNECT_TIMEOUT_S = 20.0
CALL_TIMEOUT_S = 90.0


class RoleDenied(PermissionError):
    """The orchestrator refused the call before it reached the server."""


class McpClient:
    """One long-lived session, reconnected on demand."""

    def __init__(self, url: str | None = None) -> None:
        self.url = url or settings.mcp_url
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None
        self._tools: list[ToolSpec] = []
        # Created lazily: an asyncio.Lock built at import time binds to whatever
        # loop first awaits it, so a second event loop in the same process
        # (tests, or a restarted loop) fails with "bound to a different loop".
        self._lock_obj: asyncio.Lock | None = None
        self._lock_loop: asyncio.AbstractEventLoop | None = None
        self._stack_loop: asyncio.AbstractEventLoop | None = None
        self.last_error: str = ""

    @property
    def _lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock_obj is None or self._lock_loop is not loop:
            # A session belongs to the loop that opened it. Awaiting its exit
            # stack from a different loop raises from anyio's cancel scope, so
            # the reference is dropped instead and a fresh session is opened.
            self._lock_obj = asyncio.Lock()
            self._lock_loop = loop
            self._session = None
            self._stack = None
            self._stack_loop = None
        return self._lock_obj

    # --- WRAPPER 1: open a session ----------------------------------------
    async def _open(self) -> ClientSession:
        stack = AsyncExitStack()
        read_stream, write_stream, _get_session_id = await stack.enter_async_context(
            streamablehttp_client(self.url)
        )
        session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
        await session.initialize()
        self._stack = stack
        self._session = session
        self._stack_loop = asyncio.get_running_loop()
        return session

    async def connect(self) -> bool:
        if not self.url.strip():
            # An empty MCP_URL means "no MCP server configured": skip the
            # connect instead of waiting out the timeout on every call.
            self.last_error = "MCP_URL is not configured"
            return False
        async with self._lock:
            if self._session is not None:
                return True
            try:
                await asyncio.wait_for(self._open(), timeout=CONNECT_TIMEOUT_S)
                self.last_error = ""
                log.info("connected to MCP server at %s", self.url)
                return True
            except (Exception, asyncio.CancelledError) as exc:
                # A failed streamable-HTTP connect surfaces as a CancelledError
                # from anyio's cancel scope. CancelledError is a BaseException,
                # so it escaped this handler and killed the caller instead of
                # degrading to "MCP unavailable".
                self.last_error = f"{exc.__class__.__name__}: {exc}"
                log.warning("MCP connect to %s failed: %s", self.url, self.last_error)
                await self._discard()
                return False

    async def _discard(self) -> None:
        stack, self._stack = self._stack, None
        stack_loop, self._stack_loop = self._stack_loop, None
        self._session = None
        if stack is None:
            return
        try:
            if stack_loop is not None and stack_loop is not asyncio.get_running_loop():
                # Closing another loop's stack raises from anyio; drop it.
                return
            await stack.aclose()
        except Exception as exc:
            log.debug("MCP session teardown: %s", exc)

    async def close(self) -> None:
        async with self._lock:
            await self._discard()

    async def _ensure(self) -> ClientSession | None:
        if self._session is not None:
            return self._session
        await self.connect()
        return self._session

    # --- WRAPPER 2: list tools --------------------------------------------
    async def list_tools(self, refresh: bool = False) -> list[ToolSpec]:
        if self._tools and not refresh:
            return self._tools
        session = await self._ensure()
        if session is None:
            return []
        try:
            listing = await asyncio.wait_for(session.list_tools(), timeout=CONNECT_TIMEOUT_S)
        except (Exception, asyncio.CancelledError) as exc:
            self.last_error = f"list_tools failed: {exc.__class__.__name__}: {exc}"
            log.warning(self.last_error)
            await self.close()
            return []
        specs: list[ToolSpec] = []
        for tool in listing.tools:
            meta = TOOL_META.get(tool.name, {})
            specs.append(
                ToolSpec(
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=dict(tool.inputSchema or {}),
                    group=str(meta.get("group", "read")),
                    roles=list(meta.get("roles", [])),
                    write=bool(meta.get("write", False)),
                )
            )
        specs.sort(key=lambda s: (s.group, s.name))
        self._tools = specs
        return specs

    async def tools_for(self, role: str) -> list[ToolSpec]:
        return [t for t in await self.list_tools() if allowed(role, t.name)]

    # --- WRAPPER 3: call a tool -------------------------------------------
    async def _invoke(self, name: str, args: dict[str, Any]) -> tuple[bool, dict[str, Any], str]:
        session = await self._ensure()
        if session is None:
            return False, {}, f"MCP server unavailable at {self.url}: {self.last_error}"
        try:
            result = await asyncio.wait_for(session.call_tool(name, args), timeout=CALL_TIMEOUT_S)
        except (Exception, asyncio.CancelledError) as exc:
            # As in connect(): a broken stream can arrive as CancelledError.
            await self.close()
            return False, {}, f"{exc.__class__.__name__}: {exc}"
        payload = _decode(result)
        is_error = bool(getattr(result, "isError", False))
        if is_error:
            return False, payload, str(payload.get("error") or payload.get("summary") or "tool error")
        if isinstance(payload, dict) and payload.get("error"):
            return False, payload, str(payload["error"])
        return True, payload, ""

    async def call_tool(self, role: str, call: ToolCall) -> ToolOutcome:
        """Enforce the role allow-list, then call the tool over MCP."""
        if call.name not in TOOL_META:
            return ToolOutcome(
                call_id=call.id,
                name=call.name,
                ok=False,
                error=f"unknown tool '{call.name}'; use one of the tools you were given",
            )
        if not allowed(role, call.name):
            return ToolOutcome(
                call_id=call.id,
                name=call.name,
                ok=False,
                error=(
                    f"role '{role}' may not call {call.name}; allowed roles: "
                    f"{', '.join(roles_for(call.name))}"
                ),
            )
        args = dict(call.args)
        if is_write(call.name):
            args["role"] = role
        ok, payload, error = await self._invoke(call.name, args)
        return ToolOutcome(call_id=call.id, name=call.name, ok=ok, result=payload, error=error)

    async def ping(self) -> bool:
        tools = await self.list_tools(refresh=True)
        return bool(tools)


def _decode(result: Any) -> dict[str, Any]:
    """Turn an MCP CallToolResult into the JSON object our tools return."""
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        inner = structured.get("result")
        if isinstance(inner, dict):
            return inner
        return structured
    texts: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            texts.append(text)
    joined = "\n".join(texts).strip()
    if not joined:
        return {}
    try:
        parsed = json.loads(joined)
    except json.JSONDecodeError:
        return {"summary": joined[:2000], "data": {}, "rows": 0, "cypher": [], "touched_ids": []}
    if isinstance(parsed, dict):
        return parsed
    return {"summary": "non-object tool result", "data": parsed}


client = McpClient()
