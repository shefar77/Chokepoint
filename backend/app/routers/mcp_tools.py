"""GET /api/mcp/tools - tools discovered live from the MCP server (PRD 8.6)."""

from __future__ import annotations

from fastapi import APIRouter

from app.config import settings
from app.models import McpToolInfo, McpToolsResponse
from app.orchestrator.mcp_client import client
from mcp_server import SERVER_NAME

router = APIRouter(prefix="/mcp", tags=["mcp"])


@router.get("/tools", response_model=McpToolsResponse)
async def list_tools() -> McpToolsResponse:
    specs = await client.list_tools(refresh=True)
    return McpToolsResponse(
        server=SERVER_NAME,
        url=settings.mcp_url,
        connected=bool(specs),
        tools=[
            McpToolInfo(
                name=spec.name,
                description=spec.description,
                group=spec.group,
                roles=spec.roles,
                write=spec.write,
                input_schema=spec.input_schema,
            )
            for spec in specs
        ],
        error="" if specs else client.last_error,
    )
