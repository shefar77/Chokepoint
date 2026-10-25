"""Gemini LLM provider for live agent runs."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.config import settings
from .base import AgentResult, Executor, LLMProvider, Narrator, ToolCall, ToolOutcome, ToolSpec, for_llm

log = logging.getLogger("chokepoint.provider.gemini")

MAX_TURNS = 12
TOOL_RESULT_BUDGET = 12000


class GeminiProvider(LLMProvider):
    """Hosted LLM provider using Google GenAI SDK."""

    name = "gemini"

    def __init__(self) -> None:
        if not settings.gemini_api_key.strip():
            raise RuntimeError("GEMINI_API_KEY is not set")
        try:
            from google import genai
            self.client = genai.Client(api_key=settings.gemini_api_key)
        except Exception as exc:
            log.warning("Could not initialize google.genai: %s", exc)
            self.client = None
        self.model = settings.gemini_model

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
        if not self.client:
            log.warning("%s: Gemini client unavailable, falling back", agent)
            await narrate("Gemini client unavailable. Concluding with available context.")
            return AgentResult(text="Gemini unavailable", tool_calls=0, stopped_because="llm_error")

        texts: list[str] = []
        calls = 0
        stopped = "finished"
        try:
            prompt = f"System: {system}\n\nUser: {user}"
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
            )
            content = getattr(response, "text", "") or ""
            if content.strip():
                texts.append(content.strip())
                await narrate(content.strip())
        except Exception as exc:
            log.warning("%s: Gemini call failed: %s", agent, exc)
            await narrate(f"Model call failed: {exc}")
            stopped = "llm_error"

        return AgentResult(text="\n\n".join(texts), tool_calls=calls, stopped_because=stopped)

    async def distill_lesson(self, prompt: str, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "text": payload.get("note") or "Lesson from feedback",
            "scope_kind": "service",
            "scope_value": payload.get("service") or "",
            "effect": payload.get("new_kind") or "override",
            "strength": 0.8,
        }
