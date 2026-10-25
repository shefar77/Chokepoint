"""Ollama local LLM provider for scripted+live agent runs.

Calls a local Ollama server (default http://localhost:11434) with the configured model.
Falls back gracefully if Ollama is not available.
"""

from __future__ import annotations

import asyncio
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
# The prompt tool protocol carries tool results inline in the chat history, so
# a large result plus several turns can overflow a small context window and
# force the model runner to re-process the whole prompt (which destabilises
# gemma-class models). Keep each inlined result and the retained history small.
PROMPTED_TOOL_RESULT_BUDGET = 4000
PROMPTED_HISTORY_TURNS = 3


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
        self._capabilities: list[str] | None = None

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

    async def _model_capabilities(self) -> list[str]:
        """Read the model's capabilities from /api/show (cached per instance).

        Ollama lists 'tools' only for models with native function-calling. A
        model without it (e.g. gemma3:4b reports ['completion', 'vision'])
        returns 400 on any /api/chat that carries a `tools` field, so the
        provider must know this before choosing how to drive the model.
        """
        if self._capabilities is not None:
            return self._capabilities
        try:
            resp = await self._client.post("/api/show", json={"model": self.model}, timeout=10.0)
            resp.raise_for_status()
            caps = resp.json().get("capabilities") or []
            self._capabilities = [str(c) for c in caps]
        except Exception as exc:  # noqa: BLE001 - absence of capabilities is not fatal
            log.warning("could not read capabilities for %s: %s", self.model, exc)
            self._capabilities = []
        return self._capabilities

    async def _supports_tools(self) -> bool:
        """True when the model advertises native tool-calling."""
        return "tools" in await self._model_capabilities()

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
        """Send chat request to Ollama, retrying a transient runner crash once.

        A 500 "model runner has unexpectedly stopped" is Ollama's llama-server
        subprocess crashing (resource pressure / an internal llama.cpp error).
        Ollama restarts it on the next request, so one bounded retry usually
        recovers instead of forcing the whole agent into the fallback path.
        """
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

        last_body = ""
        for attempt in range(2):
            resp = await self._client.post("/api/chat", json=payload)
            if resp.status_code < 400:
                return resp.json()
            last_body = resp.text[:500]
            log.error(
                "Ollama /api/chat returned %s (model=%s, tools=%s, attempt=%d): %s",
                resp.status_code, self.model, bool(tools), attempt + 1, last_body,
            )
            # Only a crashed runner is worth retrying; a 400 (e.g. unsupported
            # tools) is deterministic and must surface immediately.
            runner_crashed = resp.status_code >= 500 and "unexpectedly stopped" in last_body
            if runner_crashed and attempt == 0:
                await asyncio.sleep(3.0)
                continue
            break
        raise httpx.HTTPStatusError(
            f"{resp.status_code} from /api/chat: {last_body}", request=resp.request, response=resp
        )

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
        """Drive one agent turn-loop.

        Models with native tool-calling use Ollama's `tools` field; models
        without it (gemma3, llama3.2-vision, …) are driven through a JSON tool
        protocol in the prompt, so the same agents work on either kind of model
        instead of 400-ing and falling back to the deterministic pipeline.
        """
        if await self._supports_tools():
            return await self._run_native_tools(
                agent=agent, system=system, user=user, tools=tools,
                executor=executor, max_tool_calls=max_tool_calls, narrate=narrate,
            )
        log.info(
            "%s: model %s has no native tool support (%s); using the prompt tool protocol",
            agent, self.model, self._capabilities,
        )
        return await self._run_prompted_tools(
            agent=agent, system=system, user=user, tools=tools,
            executor=executor, max_tool_calls=max_tool_calls, narrate=narrate,
        )

    async def _run_native_tools(
        self,
        *,
        agent: str,
        system: str,
        user: str,
        tools: list[ToolSpec],
        executor: Executor,
        max_tool_calls: int,
        narrate: Narrator,
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

    # ----------------------------------------------------------------- prompted
    @staticmethod
    def _describe_tools(tools: list[ToolSpec]) -> str:
        """A compact, model-readable catalogue of the available tools."""
        lines: list[str] = []
        for spec in tools:
            schema = spec.agent_schema()
            props = schema.get("properties") or {}
            if props:
                arg_bits = []
                for arg, meta in props.items():
                    typ = (meta or {}).get("type", "any") if isinstance(meta, dict) else "any"
                    required = arg in (schema.get("required") or [])
                    arg_bits.append(f"{arg}{'*' if required else ''}:{typ}")
                arg_desc = ", ".join(arg_bits)
            else:
                arg_desc = "none"
            lines.append(f"- {spec.name}: {spec.description[:160].strip()} | args: {arg_desc}")
        return "\n".join(lines)

    @staticmethod
    def _extract_tool_call(content: str) -> tuple[str, dict[str, Any]] | None:
        """Find the first JSON object naming a tool in the model's reply.

        Scans for a balanced `{...}` block and parses it, so a tool call wrapped
        in prose or a ```json fence is still recognised. Returns None when the
        reply is plain prose (the agent's final answer).
        """
        text = content.strip()
        if not text:
            return None
        start = text.find("{")
        while start != -1:
            depth = 0
            in_str = False
            escape = False
            for i in range(start, len(text)):
                ch = text[i]
                if in_str:
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        blob = text[start : i + 1]
                        try:
                            obj = json.loads(blob)
                        except json.JSONDecodeError:
                            break  # malformed; try the next '{'
                        if isinstance(obj, dict):
                            name = obj.get("tool") or obj.get("name")
                            if name:
                                args = obj.get("arguments")
                                if not isinstance(args, dict):
                                    args = obj.get("args") if isinstance(obj.get("args"), dict) else {}
                                return str(name), args
                        break
            start = text.find("{", start + 1)
        return None

    async def _run_prompted_tools(
        self,
        *,
        agent: str,
        system: str,
        user: str,
        tools: list[ToolSpec],
        executor: Executor,
        max_tool_calls: int,
        narrate: Narrator,
    ) -> AgentResult:
        tool_names = {spec.name for spec in tools}
        catalogue = self._describe_tools(tools)
        protocol_system = (
            f"{system}\n\n"
            "You can call tools to inspect the security graph. To call a tool, reply with "
            "ONLY a single JSON object and nothing else:\n"
            '{"tool": "<tool_name>", "arguments": {<arguments>}}\n'
            "Call one tool at a time. Do not wrap the JSON in markdown or add commentary around it. "
            "When you have gathered enough evidence, reply with your final analysis as plain prose "
            "and NO JSON object.\n\n"
            f"Available tools:\n{catalogue}"
        )
        messages: list[dict[str, Any]] = [{"role": "user", "content": user}]
        calls = 0
        bad_json_retries = 0
        texts: list[str] = []
        deadline = time.monotonic() + self.timeout_s
        stopped = "finished"

        for _turn in range(MAX_TURNS):
            if time.monotonic() > deadline:
                stopped = "timeout"
                break
            try:
                response = await self._chat(system=protocol_system, messages=messages, tools=None)
            except Exception as exc:  # noqa: BLE001
                log.warning("%s: Ollama call failed: %s", agent, exc)
                await narrate(f"The model call failed: {exc}. Concluding with what is on the blackboard.")
                return AgentResult(text="\n".join(texts), tool_calls=calls, stopped_because="llm_error")

            content = (response.get("message", {}) or {}).get("content", "") or ""
            call = self._extract_tool_call(content)

            if call is None:
                stripped = content.strip()
                # A malformed tool-call attempt (starts like JSON and mentions a
                # tool) is not a conclusion: nudge the model for valid JSON or
                # prose rather than leaking the broken JSON into the narration.
                if stripped.startswith("{") and '"tool"' in stripped and bad_json_retries < 2:
                    bad_json_retries += 1
                    messages.append({"role": "assistant", "content": content})
                    messages.append({
                        "role": "user",
                        "content": (
                            "That was not valid JSON. To call a tool, reply with exactly "
                            '{"tool": "<name>", "arguments": {<args>}} and nothing else, '
                            "or give your final answer as plain prose."
                        ),
                    })
                    continue
                # Plain prose: the agent's conclusion.
                if stripped:
                    texts.append(stripped)
                    await narrate(stripped)
                break

            # A tool call: narrate only the reasoning around it, never the raw
            # JSON, so "What the agents said" stays readable prose.
            prose = content[: content.find("{")].strip()
            if len(prose) > 20:
                texts.append(prose)
                await narrate(prose)

            name, args = call
            if name not in tool_names:
                messages.append({"role": "assistant", "content": content})
                messages.append({
                    "role": "user",
                    "content": (
                        f"'{name}' is not an available tool. Choose one of: "
                        f"{', '.join(sorted(tool_names))}, or give your final answer as plain prose."
                    ),
                })
                continue

            if calls >= max_tool_calls:
                messages.append({"role": "assistant", "content": content})
                messages.append({
                    "role": "user",
                    "content": "Your tool budget is spent. Write your final analysis now as plain prose, with no JSON.",
                })
                stopped = "tool_budget"
                try:
                    final = await self._chat(system=protocol_system, messages=messages, tools=None)
                except Exception as exc:  # noqa: BLE001
                    log.warning("%s: final Ollama call failed: %s", agent, exc)
                    break
                final_content = (final.get("message", {}) or {}).get("content", "") or ""
                # Ignore a trailing tool-call attempt; we only want prose here.
                if self._extract_tool_call(final_content) is None and final_content.strip():
                    texts.append(final_content.strip())
                    await narrate(final_content.strip())
                break

            calls += 1
            outcome = await executor(ToolCall(id=f"{agent}-{calls}", name=name, args=args))
            body = for_llm(outcome.result) if outcome.ok else {"error": outcome.error}
            encoded = json.dumps(body, default=str)
            if len(encoded) > PROMPTED_TOOL_RESULT_BUDGET:
                tool_payload = {"truncated": True, "result_json": encoded[:PROMPTED_TOOL_RESULT_BUDGET]}
            else:
                tool_payload = body if isinstance(body, dict) else {"result": body}

            messages.append({"role": "assistant", "content": content})
            messages.append({
                "role": "user",
                "content": f"Result of {name}:\n{json.dumps(tool_payload, default=str)}",
            })
            # Keep the opening task plus the most recent exchanges, so the
            # context cannot grow without bound across many tool calls.
            keep = PROMPTED_HISTORY_TURNS * 2
            if len(messages) > keep + 1:
                messages = messages[:1] + messages[-keep:]

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