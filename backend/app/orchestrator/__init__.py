"""Orchestrator: MCP client, LLM providers and the blackboard run loop."""

from app import __version__  # re-export so submodules can do `from . import __version__`

__all__: list[str] = ["__version__"]
