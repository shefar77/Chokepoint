"""Ollama local LLM provider for scripted+live agent runs.

Calls a local Ollama server (default http://localhost:11434) with the configured model.
Falls back gracefully if Ollama is not available.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

from app.config import settings
from .base import AgentResult, Executor, LLMProvider, Narrator, ToolCall, ToolOutcome, ToolSpec, for_llm

log = logging.getLogger("chokepoint.provider.ollama")

JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)
MAX_TURNS = 12
TOOL_RESULT_BUDGET = 12000


class OllamaProvider(LLMProvider):
    """Local LLM provider using Ollama API."""

    name = "ollama"

    def __init__(self) -> None:
        self.base_url = settings.ollama_base_url.rstrip("/")
        self.model = settings.ollama_model
        self.max_tokens = settings.llm_max_tokens
        self.temperature = settings.llm_temperature
        self.timeout_s = settings.agent_timeout_s
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout_s)

    async def _check_health(self) -> bool:
        """Check if Ollama is reachable and model is available."""
        try:
            resp = await self._client.get("/api/tags", timeout=5.0)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                return any(m.get("name", "").startswith(self.model.split(":")[0]) for m in models)
        except Exception as exc:
            log.warning("Ollama health check failed: %s", exc)
        return False

    def _build_tools(self, tools: list[ToolSpec]) -> list[dict[str, Any]]:
        """Convert tool specs to Ollama tool format (OpenAPI-like)."""
        ollama_tools = []
        for spec in tools:
            schema = spec.agent_schema()
            ollama_tools.append({
                "type": "function",
                "function": {
                    "name": spec.name,
                    "description": spec.description[:1024],
                    "parameters": schema if schema.get("properties") else {"type": "object", "properties": {}},
                }
            })
        return ollama_tools

    async def _chat(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> dict[str, Any]:
        """Send chat request to Ollama."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                *messages,
            ],
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
            "stream": False,
        }
        if tools:
            payload["tools"] = tools

        resp = await self._client.post("/api/chat", json=payload)
        resp.raise_for_status()
        return resp.json()

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
        ollama_tools = self._build_tools(tools)
        messages = [{"role": "user", "content": user}]
        calls = 0
        turns = 0
        texts: list[str] = []
        deadline = time.monotonic() + self.timeout_s
        stopped = "finished"

        while turns < MAX_TURNS:
            turns += 1
            try:
                response = await self._chat(system=system, messages=messages, tools=ollama_tools)
            except Exception as exc:  # noqa: BLE001
                log.warning("%s: Ollama call failed: %s", agent, exc)
                await narrate(f"The model call failed: {exc}. Concluding with what is on the blackboard.")
                return AgentResult(text="\n".join(texts), tool_calls=calls, stopped_because="llm_error")

            message = response.get("message", {})
            content = message.get("content", "")
            if content and content.strip():
                texts.append(content.strip())
                await narrate(content.strip())

            tool_calls = message.get("tool_calls", [])
            if not tool_calls:
                break

            responses: list[dict[str, Any]] = []
            for call in tool_calls:
                name = call.get("function", {}).get("name", "")
                if calls >= max_tool_calls:
                    stopped = "tool_budget"
                    responses.append({
                        "role": "tool",
                        "name": name,
                        "content": json.dumps({"error": "tool budget exhausted; write your conclusion now"}),
                    })
                    continue
                calls += 1
                args = call.get("function", {}).get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                outcome = await executor(ToolCall(id=f"{agent}-{calls}", name=name, args=args))
                body = for_llm(outcome.result) if outcome.ok else {"error": outcome.error}
                encoded = json.dumps(body, default=str)
                if len(encoded) > TOOL_RESULT_BUDGET:
                    payload = {"truncated": True, "result_json": encoded[:TOOL_RESULT_BUDGET]}
                else:
                    payload = body if isinstance(body, dict) else {"result": body}
                responses.append({"role": "tool", "name": name, "content": json.dumps(payload, default=str)})

            messages.append(message)
            for r in responses:
                messages.append(r)

            if calls >= max_tool_calls or time.monotonic() > deadline:
                stopped = "tool_budget" if calls >= max_tool_calls else "timeout"
                messages.append({
                    "role": "user",
                    "content": "Your tool budget is spent. Write your conclusion now from the results you already have, without calling any tool."
                })
                try:
                    final = await self._chat(system=system, messages=messages, tools=None)
                except Exception as exc:  # noqa: BLE001
                    log.warning("%s: final Ollama call failed: %s", agent, exc)
                    break
                final_msg = final.get("message", {})
                final_content = final_msg.get("content", "")
                if final_content and final_content.strip():
                    texts.append(final_content.strip())
                    await narrate(final_content.strip())
                break

        return AgentResult(text="\n\n".join(texts), tool_calls=calls, stopped_because=stopped)

    async def distill_lesson(self, prompt: str, payload: dict[str, Any]) -> dict[str, Any]:
        """One short call constrained to JSON output."""
        message = (
            "Feedback document:\n```json\n"
            + json.dumps(payload, indent=2, default=str)
            + "\n```\nReply with the JSON object only."
        )
        try:
            response = await self._chat(
                system=prompt,
                messages=[{"role": "user", "content": message}],
                tools=None,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Ollama distill_lesson failed: %s", exc)
            raise

        content = response.get("message", {}).get("content", "")
        match = JSON_BLOCK.search(content)
        if not match:
            raise ValueError("lesson distiller returned no JSON object")
        return json.loads(match.group(0))

    async def close(self) -> None:
        await self._client.aclose()