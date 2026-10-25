"""GET /api/health - database, MCP, algorithms, embeddings and agent mode."""

from __future__ import annotations

from fastapi import APIRouter

from app.config import settings
from app.db import node_count, ping
from app.memory.embeddings import embedder
from app.models import CapabilityReport, EmbeddingStatus, HealthResponse
from app.orchestrator.mcp_client import client
from mcp_server import algos

router = APIRouter(tags=["health"])


async def _provider_status() -> tuple[str, str, str]:
    """Report the agent mode that a run would actually use right now.

    `effective_mode` only reflects configuration. A run falls back to the
    deterministic pipeline whenever no provider answers, and PRD FR-11 forbids
    presenting that as an LLM-driven run.
    """
    if settings.agent_mode.strip().lower() == "scripted":
        return "scripted", "deterministic", "AGENT_MODE=scripted; no model reasoning is used."
    if settings.gemini_api_key.strip():
        return "live", settings.gemini_model, ""
    try:
        from app.orchestrator.providers.ollama_provider import OllamaProvider

        provider = OllamaProvider()
        healthy = await provider._check_health()
        await provider.close()
    except Exception as exc:  # noqa: BLE001 - probing must not fail health
        return "scripted", "deterministic", f"model provider unreachable: {exc}"
    if healthy:
        return "live", settings.ollama_model, ""
    return (
        "scripted",
        "deterministic",
        (
            f"Ollama at {settings.ollama_base_url} does not offer {settings.ollama_model}; "
            "investigations run the deterministic pipeline over real MCP tools."
        ),
    )


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    sqlite_ok = ping()
    tools = await client.list_tools(refresh=True) if sqlite_ok else []
    # Probe the provider rather than assuming the configured mode: reporting
    # 'live' with a model name while no model is reachable is a false claim.
    agent_mode, model_label, mode_warning = await _provider_status()
    try:
        capabilities = CapabilityReport(**algos.capability_report()) if sqlite_ok else CapabilityReport()
    except Exception:  # noqa: BLE001 - capability probing is advisory
        capabilities = CapabilityReport()
    return HealthResponse(
        ok=sqlite_ok and bool(tools),
        graph_ok=sqlite_ok,
        graph="security-graph",
        node_count=node_count() if sqlite_ok else 0,
        mcp=bool(tools),
        mcp_url=settings.mcp_url,
        mcp_tools=len(tools),
        agent_mode=agent_mode,
        configured_agent_mode=settings.agent_mode,
        model=model_label,
        mode_warning=mode_warning or (client.last_error if not tools else ""),
        embeddings=EmbeddingStatus(**embedder().status()),
        capabilities=capabilities,
        seed_scale=settings.seed_scale,
        outbox_dir=settings.outbox_dir,
    )