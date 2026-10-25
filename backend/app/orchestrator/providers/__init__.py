"""LLM providers: the live Ollama loop, the live Gemini loop, and the scripted offline loop.

The primary inference option is a configurable local open-weight model through Ollama.
The scripted provider runs without any LLM API key.
"""

from __future__ import annotations

import logging
from functools import lru_cache

from app.config import settings

from .base import AgentResult, Executor, LLMProvider, Narrator, ToolCall, ToolOutcome, ToolSpec
from .scripted_provider import ScriptedProvider, classify

log = logging.getLogger("chokepoint.providers")

__all__ = [
    "AgentResult",
    "Executor",
    "LLMProvider",
    "Narrator",
    "ScriptedProvider",
    "ToolCall",
    "ToolOutcome",
    "ToolSpec",
    "classify",
    "get_provider",
]


@lru_cache(maxsize=2)
def _scripted() -> LLMProvider:
    return ScriptedProvider()


@lru_cache(maxsize=2)
def _ollama() -> LLMProvider:
    from .ollama_provider import OllamaProvider

    return OllamaProvider()


@lru_cache(maxsize=2)
def _live() -> LLMProvider:
    try:
        from .gemini_provider import GeminiProvider
        return GeminiProvider()
    except Exception as exc:
        log.warning("Gemini provider unavailable: %s", exc)
        return _scripted()


def get_provider(mode: str | None = None) -> LLMProvider:
    """Resolve the provider for a run.

    Priority:
    1. Ollama (local model) - primary for core workflow without API keys
    2. Scripted - if no local model or explicitly requested
    3. Gemini (hosted) - only if GEMINI_API_KEY is set and mode is live
    """
    wanted = (mode or settings.effective_mode).strip().lower()

    # Scripted mode explicitly requested
    if wanted == "scripted":
        return _scripted()

    # Live mode: try Ollama first (local, no API key needed)
    if wanted == "live":
        # Check if Ollama is available
        try:
            ollama = _ollama()
            # We can't easily check health here without async,
            # but we can try and fall back
            return ollama
        except Exception as exc:
            log.warning("Ollama provider unavailable: %s; falling back", exc)

        # Fall back to Gemini if API key available
        if settings.gemini_api_key.strip():
            try:
                return _live()
            except Exception as exc:
                log.warning("Gemini provider unavailable: %s", exc)

        # Final fallback: scripted
        log.warning("No live provider available; using scripted")
        return _scripted()

    # Default: scripted
    return _scripted()