"""chokepoint-mcp: FastMCP server exposing the graph as 21 agent tools.

Run it over streamable HTTP (the compose default) or over stdio for a desktop
MCP client:

    python -m mcp_server.server --transport streamable-http --port 8765
    python -m mcp_server.server --transport stdio
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.config import settings

from . import SERVER_NAME, algos
from .tools import actions, analysis, blackboard, catalog, memory, read

log = logging.getLogger("chokepoint.mcp")

INSTRUCTIONS = """
CHOKEPOINT exposes a Graphify + NetworkX code security graph that holds a software repository
(files, functions, classes, packages, vulnerabilities, findings, entry points),
owners), the reasoning of past investigations, and the lessons learned from
analyst feedback.

Tools are grouped: read, analysis, memory, blackboard, action. Risk numbers are
computed inside the tools; never recompute or estimate them yourself. Prefer
find_attack_paths and check_exploitability over list_open_findings: CVSS order
is not a plan. Write tools take a `role` argument and refuse roles that are not
allowed to call them.
""".strip()

TOOL_MODULES = (read, analysis, memory, blackboard, actions)


def build_server(host: str | None = None, port: int | None = None) -> FastMCP:
    """Create the FastMCP server with every tool registered."""
    mcp = FastMCP(
        SERVER_NAME,
        instructions=INSTRUCTIONS,
        host=host or settings.mcp_host,
        port=port or settings.mcp_port,
    )
    for module in TOOL_MODULES:
        module.register(mcp)
    return mcp


def log_capabilities() -> dict[str, Any]:
    """Probe algorithm procedures once at start-up (PRD 7.6)."""
    try:
        report = algos.capability_report()
        log.info("Graph algorithm support: %s", report["algorithms"])
        return report
    except Exception as exc:  # noqa: BLE001 - the database may not be up yet
        log.warning("capability detection deferred: %s", exc)
        return {"algorithms": {}, "procedures_detected": 0, "native_procedures": []}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp_server.server", description=f"{SERVER_NAME} MCP server")
    parser.add_argument(
        "--transport",
        choices=("streamable-http", "stdio"),
        default="streamable-http",
        help="Transport to serve on.",
    )
    parser.add_argument("--host", default=settings.mcp_host, help="Bind host for HTTP transport.")
    parser.add_argument("--port", type=int, default=settings.mcp_port, help="Bind port for HTTP transport.")
    parser.add_argument("--log-level", default="INFO", help="Python logging level.")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
        stream=sys.stderr,
    )
    log.info(
        "%s starting on %s (graph '%s' via NetworkX/SQLite), %d tools",
        SERVER_NAME,
        args.transport,
        settings.graph_name,


        len(catalog()),
    )
    log_capabilities()

    server = build_server(args.host, args.port)
    server.run(transport=args.transport)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
