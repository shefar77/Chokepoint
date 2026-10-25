"""chokepoint-mcp: the MCP server that exposes the graph as agent tools.

Nothing in this package calls an LLM. Every risk number produced here comes
from :mod:`mcp_server.scoring` or :mod:`mcp_server.solver`.
"""

__all__ = ["SERVER_NAME"]

SERVER_NAME = "chokepoint-mcp"
