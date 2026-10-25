"""Provider interface shared by the live and scripted agent loops."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable


@dataclass(slots=True)
class ToolSpec:
    """A tool as discovered over MCP, plus the registry metadata."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    group: str = "read"
    roles: list[str] = field(default_factory=list)
    write: bool = False

    def agent_schema(self) -> dict[str, Any]:
        """The schema an agent sees: the `role` argument is injected by the client."""
        schema = dict(self.input_schema or {})
        properties = {k: v for k, v in dict(schema.get("properties") or {}).items() if k != "role"}
        required = [r for r in list(schema.get("required") or []) if r != "role"]
        schema["type"] = "object"
        schema["properties"] = properties
        if required:
            schema["required"] = required
        else:
            schema.pop("required", None)
        # `$defs` is kept: nested argument models (claims, fixes) reference it.
        return schema


@dataclass(slots=True)
class ToolCall:
    id: str
    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ToolOutcome:
    call_id: str
    name: str
    ok: bool
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    step_id: str = ""

    @property
    def summary(self) -> str:
        if self.ok:
            return str(self.result.get("summary") or "")
        return self.error or "tool call failed"


@dataclass(slots=True)
class AgentResult:
    text: str = ""
    tool_calls: int = 0
    stopped_because: str = "finished"


def for_llm(result: dict[str, Any]) -> dict[str, Any]:
    """Drop the orchestrator-only keys so the model only sees the clipped result."""
    return {key: value for key, value in result.items() if key not in ("full",)}


Executor = Callable[[ToolCall], Awaitable[ToolOutcome]]
Narrator = Callable[[str], Awaitable[None]]


class LLMProvider(ABC):
    """Chooses tools and writes prose. It never computes a risk number."""

    name: str = "base"

    @abstractmethod
    async def run_agent(
        self,
        *,
        agent: str,
        system: str,
        user: str,
        tools: list[ToolSpec],
        executor: Executor,
        max_tool_calls: int,
        narrate: Narrator,
        context: dict[str, Any],
    ) -> AgentResult:
        """Run one agent turn-loop until it concludes or runs out of budget."""

    async def distill_lesson(self, prompt: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Turn analyst feedback into a lesson document. Providers may override."""
        raise NotImplementedError
