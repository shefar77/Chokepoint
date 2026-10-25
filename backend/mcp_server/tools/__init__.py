"""Tool registry: groups, role allow-lists and the role re-check for writes.

The orchestrator enforces these allow-lists before a call leaves the backend,
and every write tool checks the role again here so the MCP server is safe to
expose on its own (for example to Claude Desktop over stdio).
"""

from __future__ import annotations

from typing import Any

ROLES = ("scout", "skeptic", "scribe", "backend", "memory")

TOOL_META: dict[str, dict[str, Any]] = {
    # 8.1 read and discovery
    "graph_overview": {"group": "read", "roles": ["scout", "skeptic", "scribe", "backend"], "write": False},
    "find_entities": {"group": "read", "roles": ["scout", "skeptic", "scribe", "backend"], "write": False},
    "get_service_context": {"group": "read", "roles": ["scout", "skeptic", "scribe"], "write": False},
    "list_open_findings": {"group": "read", "roles": ["scout", "skeptic", "backend"], "write": False},
    "owner_of": {"group": "read", "roles": ["scout", "skeptic", "scribe"], "write": False},
    # 8.2 analysis
    "find_attack_paths": {"group": "analysis", "roles": ["scout", "skeptic", "backend"], "write": False},
    "blast_radius": {"group": "analysis", "roles": ["scout", "skeptic", "scribe"], "write": False},
    "check_exploitability": {"group": "analysis", "roles": ["scout", "skeptic"], "write": False},
    "rank_centrality": {"group": "analysis", "roles": ["scout", "skeptic"], "write": False},
    "find_chokepoints": {"group": "analysis", "roles": ["scout", "skeptic", "scribe", "backend"], "write": False},
    "simulate_fix": {"group": "analysis", "roles": ["scout", "skeptic"], "write": False},
    "connected_components": {"group": "analysis", "roles": ["scout", "skeptic"], "write": False},
    "shortest_path": {"group": "analysis", "roles": ["scout", "skeptic"], "write": False},
    # 8.3 memory
    "recall": {"group": "memory", "roles": ["scout", "skeptic", "scribe", "backend", "memory"], "write": False},
    "diff_since_last": {"group": "memory", "roles": ["scout", "skeptic", "backend"], "write": False},
    # 8.4 blackboard
    "post_hypothesis": {"group": "blackboard", "roles": ["scout"], "write": True},
    "post_challenge": {"group": "blackboard", "roles": ["skeptic"], "write": True},
    "list_blackboard": {"group": "blackboard", "roles": ["scout", "skeptic", "scribe"], "write": False},
    # 8.5 verdicts and actions
    "record_verdict": {"group": "action", "roles": ["scribe"], "write": True},
    "propose_action": {"group": "action", "roles": ["scribe"], "write": True},
    "record_lesson": {"group": "action", "roles": ["backend"], "write": True},
}

TOOL_GROUPS = ("read", "analysis", "memory", "blackboard", "action")


class RoleError(PermissionError):
    """Raised when a role calls a tool it is not allowed to call."""


def roles_for(tool: str) -> list[str]:
    return list(TOOL_META.get(tool, {}).get("roles", []))


def group_for(tool: str) -> str:
    return str(TOOL_META.get(tool, {}).get("group", "read"))


def is_write(tool: str) -> bool:
    return bool(TOOL_META.get(tool, {}).get("write", False))


def allowed(role: str, tool: str) -> bool:
    return role.strip().lower() in roles_for(tool)


def require_role(role: str, tool: str) -> str:
    """Re-check the caller role inside a write tool."""
    normalised = (role or "").strip().lower()
    if normalised not in ROLES:
        raise RoleError(f"unknown role '{role}'; expected one of {', '.join(ROLES)}")
    if not allowed(normalised, tool):
        raise RoleError(
            f"role '{normalised}' may not call {tool}; allowed roles: {', '.join(roles_for(tool))}"
        )
    return normalised


def tools_for_role(role: str) -> list[str]:
    return sorted(name for name in TOOL_META if allowed(role, name))


def catalog() -> list[dict[str, Any]]:
    return [
        {"name": name, "group": meta["group"], "roles": list(meta["roles"]), "write": bool(meta["write"])}
        for name, meta in sorted(TOOL_META.items())
    ]
