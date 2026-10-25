"""Ollama provider: capability detection and the prompt tool protocol.

gemma3:4b (and other non-tool models) return 400 on any /api/chat that carries
a `tools` field. The provider must detect that from /api/show and drive those
models through a JSON tool protocol in the prompt instead, so the agents still
run on the local model rather than falling back to the deterministic pipeline.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from app.orchestrator.providers.base import ToolOutcome, ToolSpec
from app.orchestrator.providers.ollama_provider import OllamaProvider


class _FakeResponse:
    def __init__(self, status_code: int, body: str = "", data: dict | None = None) -> None:
        self.status_code = status_code
        self.text = body
        self._data = data or {}
        self.request = httpx.Request("POST", "http://ollama:11434/api/chat")

    def json(self) -> dict:
        return self._data


LIST_FINDINGS = ToolSpec(
    name="list_findings",
    description="List the open findings in the scan.",
    input_schema={"type": "object", "properties": {"limit": {"type": "integer"}}},
    roles=["scout"],
)


# ---------------------------------------------------------------- tool parser
@pytest.mark.parametrize(
    "content, expected",
    [
        ('{"tool": "list_findings", "arguments": {"limit": 5}}', ("list_findings", {"limit": 5})),
        ("Let me look.\n```json\n{\"tool\":\"list_findings\",\"arguments\":{}}\n```", ("list_findings", {})),
        ('{"name": "list_findings", "args": {}}', ("list_findings", {})),
        ("All findings are low severity; no action needed.", None),
        ("", None),
        ('noise {bad json} {"tool":"x","arguments":{"q":"a{b}c"}}', ("x", {"q": "a{b}c"})),
    ],
)
def test_extract_tool_call(content, expected) -> None:
    assert OllamaProvider._extract_tool_call(content) == expected


def test_describe_tools_marks_required_args() -> None:
    spec = ToolSpec(
        name="find_paths",
        description="Find attack paths.",
        input_schema={
            "type": "object",
            "properties": {"hops": {"type": "integer"}, "target": {"type": "string"}},
            "required": ["target"],
        },
    )
    text = OllamaProvider._describe_tools([spec])
    assert "find_paths" in text
    assert "target*:string" in text  # required marked with *
    assert "hops:integer" in text


# ------------------------------------------------------------- capability path
def test_supports_tools_reads_capabilities(monkeypatch) -> None:
    provider = OllamaProvider()

    async def fake_caps() -> list[str]:
        return ["completion", "vision"]

    monkeypatch.setattr(provider, "_model_capabilities", fake_caps)
    assert asyncio.run(provider._supports_tools()) is False
    asyncio.run(provider.close())


def test_supports_tools_true_for_tool_model(monkeypatch) -> None:
    provider = OllamaProvider()

    async def fake_caps() -> list[str]:
        return ["completion", "tools"]

    monkeypatch.setattr(provider, "_model_capabilities", fake_caps)
    assert asyncio.run(provider._supports_tools()) is True
    asyncio.run(provider.close())


# --------------------------------------------------------- prompted tool loop
def test_prompted_loop_calls_tool_then_concludes(monkeypatch) -> None:
    """A non-tool model: the provider must call the tool via JSON, feed the
    result back, and return the model's final prose."""
    provider = OllamaProvider()

    # Force the no-native-tools branch.
    async def no_tools() -> bool:
        return False

    monkeypatch.setattr(provider, "_supports_tools", no_tools)

    # The model first asks to call list_findings, then writes a conclusion.
    scripted = [
        {"message": {"content": '{"tool": "list_findings", "arguments": {"limit": 3}}'}},
        {"message": {"content": "There are 3 open findings; the top one is critical."}},
    ]
    sent_tools: list = []

    async def fake_chat(*, system, messages, tools):
        sent_tools.append(tools)
        return scripted.pop(0)

    monkeypatch.setattr(provider, "_chat", fake_chat)

    executed: list = []

    async def executor(call):
        executed.append((call.name, call.args))
        return ToolOutcome(call_id=call.id, name=call.name, ok=True, result={"summary": "3 findings", "rows": 3})

    narrated: list[str] = []

    async def narrate(text: str) -> None:
        narrated.append(text)

    result = asyncio.run(
        provider.run_agent(
            agent="scout",
            system="You are the scout.",
            user="Find the risks.",
            tools=[LIST_FINDINGS],
            executor=executor,
            max_tool_calls=5,
            narrate=narrate,
            context={},
        )
    )
    asyncio.run(provider.close())

    # The tool was actually invoked with parsed arguments.
    assert executed == [("list_findings", {"limit": 3})]
    # No /api/chat carried a tools field (that is what 400s on gemma3).
    assert all(t is None for t in sent_tools)
    # The final prose was narrated and returned, and the JSON call was not.
    assert any("3 open findings" in t for t in narrated)
    assert "3 open findings" in result.text
    assert result.tool_calls == 1
    assert result.stopped_because == "finished"


# ----------------------------------------------------------- _chat retry path
def test_chat_retries_once_on_runner_crash(monkeypatch) -> None:
    """A 500 'model runner has unexpectedly stopped' is transient; retry once."""
    provider = OllamaProvider()
    responses = [
        _FakeResponse(500, body='{"error":"model runner has unexpectedly stopped"}'),
        _FakeResponse(200, data={"message": {"content": "recovered"}}),
    ]
    posts: list = []

    async def fake_post(url, json):
        posts.append(url)
        return responses.pop(0)

    async def fast_sleep(_s):
        return None

    monkeypatch.setattr(provider._client, "post", fake_post)
    monkeypatch.setattr("app.orchestrator.providers.ollama_provider.asyncio.sleep", fast_sleep)

    out = asyncio.run(provider._chat(system="s", messages=[{"role": "user", "content": "u"}], tools=None))
    asyncio.run(provider.close())
    assert out["message"]["content"] == "recovered"
    assert len(posts) == 2  # it retried


def test_chat_does_not_retry_on_400(monkeypatch) -> None:
    """A 400 (e.g. unsupported tools) is deterministic; surface it at once."""
    provider = OllamaProvider()
    posts: list = []

    async def fake_post(url, json):
        posts.append(url)
        return _FakeResponse(400, body='{"error":"gemma3:4b does not support tools"}')

    monkeypatch.setattr(provider._client, "post", fake_post)
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(provider._chat(system="s", messages=[{"role": "user", "content": "u"}], tools=[{"x": 1}]))
    asyncio.run(provider.close())
    assert len(posts) == 1  # no retry on a 400


def test_prompted_loop_narrates_prose_not_raw_json(monkeypatch) -> None:
    """Reasoning before a tool-call JSON is narrated; the JSON itself is not."""
    provider = OllamaProvider()

    async def no_tools() -> bool:
        return False

    monkeypatch.setattr(provider, "_supports_tools", no_tools)
    scripted = [
        {"message": {"content": 'I should check the findings first. {"tool":"list_findings","arguments":{}}'}},
        {"message": {"content": "Done: one critical finding."}},
    ]

    async def fake_chat(*, system, messages, tools):
        return scripted.pop(0)

    monkeypatch.setattr(provider, "_chat", fake_chat)

    async def executor(call):
        return ToolOutcome(call_id=call.id, name=call.name, ok=True, result={"summary": "1 finding"})

    narrated: list[str] = []

    async def narrate(text: str) -> None:
        narrated.append(text)

    asyncio.run(
        provider.run_agent(
            agent="scout", system="s", user="u", tools=[LIST_FINDINGS],
            executor=executor, max_tool_calls=5, narrate=narrate, context={},
        )
    )
    asyncio.run(provider.close())
    joined = "\n".join(narrated)
    assert "check the findings first" in joined
    assert '"tool"' not in joined  # raw JSON never shown to the user
    assert "one critical finding" in joined


def test_prompted_loop_does_not_leak_malformed_json(monkeypatch) -> None:
    """Malformed tool-call JSON must be corrected, not narrated as prose."""
    provider = OllamaProvider()

    async def no_tools() -> bool:
        return False

    monkeypatch.setattr(provider, "_supports_tools", no_tools)
    scripted = [
        # Invalid JSON (set-like {"none"}), as small models sometimes emit.
        {"message": {"content": '{"tool": "graph_overview", "arguments": {"none"}}'}},
        {"message": {"content": "Final prose: the estate looks clean."}},
    ]

    async def fake_chat(*, system, messages, tools):
        return scripted.pop(0)

    monkeypatch.setattr(provider, "_chat", fake_chat)

    async def executor(call):
        raise AssertionError("no valid tool call was made")

    narrated: list[str] = []

    async def narrate(text: str) -> None:
        narrated.append(text)

    result = asyncio.run(
        provider.run_agent(
            agent="scout", system="s", user="u", tools=[LIST_FINDINGS],
            executor=executor, max_tool_calls=5, narrate=narrate, context={},
        )
    )
    asyncio.run(provider.close())
    joined = "\n".join(narrated)
    assert '"tool"' not in joined  # the broken JSON never reached the user
    assert "estate looks clean" in joined
    assert result.tool_calls == 0


def test_prompted_loop_rejects_unknown_tool(monkeypatch) -> None:
    provider = OllamaProvider()

    async def no_tools() -> bool:
        return False

    monkeypatch.setattr(provider, "_supports_tools", no_tools)

    scripted = [
        {"message": {"content": '{"tool": "does_not_exist", "arguments": {}}'}},
        {"message": {"content": "Final answer: nothing actionable."}},
    ]

    async def fake_chat(*, system, messages, tools):
        return scripted.pop(0)

    monkeypatch.setattr(provider, "_chat", fake_chat)

    async def executor(call):  # should never run
        raise AssertionError("unknown tool must not be executed")

    async def narrate(text: str) -> None:
        pass

    result = asyncio.run(
        provider.run_agent(
            agent="scout", system="s", user="u", tools=[LIST_FINDINGS],
            executor=executor, max_tool_calls=5, narrate=narrate, context={},
        )
    )
    asyncio.run(provider.close())
    assert result.tool_calls == 0
    assert "nothing actionable" in result.text
