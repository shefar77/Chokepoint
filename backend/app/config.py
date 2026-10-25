"""Environment-backed settings shared by the API and the MCP server."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_ROOT = Path(__file__).resolve().parent


class Settings(BaseSettings):
    """All runtime configuration. Names map to upper-case environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # LLM / Agent configuration
    # LLM / Agent configuration
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash-lite"
    agent_mode: str = "live"  # live | scripted

    # Ollama (local model) configuration
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "gemma3:4b"  # matches .env.example and docker-compose

    # SQLite persistence
    sqlite_path: str = "/data/chokepoint.db"
    graph_name: str = "security-graph"

    # Graphify integration
    graphify_path: str = "graphify"  # Path to graphify CLI
    graphify_workspace: str = "/data/graphify-workspaces"
    # Directory that /api/codebases/scan-directory and scan-manual are confined
    # to. Configurable so the app runs outside the container layout too.
    codebases_dir: str = "/data/codebases"

    # MCP server
    mcp_url: str = "http://localhost:8765/mcp"
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8765

    # Embeddings
    embeddings: str = "fastembed"  # fastembed | none
    embedding_model: str = "BAAI/bge-small-en-v1.5"

    # Repository ingestion
    max_repo_size_mb: int = 500
    max_extract_time_s: int = 300
    cleanup_workspaces_after_s: int = 3600

    # Scanner configuration
    trivy_path: str = "trivy"
    semgrep_path: str = "semgrep"
    scanner_timeout_s: int = 300

    # Seed / outbox
    seed_scale: int = 1
    outbox_dir: str = "/data/outbox"
    ground_truth_path: str = ""

    # Delivery targets
    slack_webhook_url: str = ""
    github_token: str = ""
    github_repo: str = ""

    # CORS
    cors_origins: str = "http://localhost:8080,http://localhost:5173,http://127.0.0.1:8080"

    # Agent limits
    scout_max_tool_calls: int = 14
    skeptic_max_tool_calls: int = 10
    scribe_max_tool_calls: int = 8
    agent_timeout_s: float = 180.0
    llm_max_tokens: int = 2600
    llm_temperature: float = 0.2

    # Graph analysis limits
    path_max_hops: int = 7
    path_candidate_limit: int = 4000
    tool_payload_budget_bytes: int = 6144
    cypher_row_cap: int = 200
    cypher_timeout_ms: int = 30000

    # Simulation
    sim_graph_prefix: str = Field(default="sim_", description="Prefix for scratch counterfactual graphs.")

    @property
    def effective_mode(self) -> str:
        """`live` when agent_mode is live; never fall back to scripted."""
        if self.agent_mode.strip().lower() == "scripted":
            return "scripted"
        return "live"

    @property
    def mode_warning(self) -> str:
        """Configuration-level warning only.

        Ollama is the primary provider and Gemini is optional, so an empty
        GEMINI_API_KEY is not a problem. Whether a model is actually reachable
        is probed at request time in the health router.
        """
        return ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def ground_truth_file(self) -> Path:
        if self.ground_truth_path.strip():
            return Path(self.ground_truth_path.strip())
        return PACKAGE_ROOT / "seed" / "ground_truth.json"

    @property
    def outbox_path(self) -> Path:
        return Path(self.outbox_dir)

    @property
    def embeddings_enabled(self) -> bool:
        return self.embeddings.strip().lower() == "fastembed"

    @property
    def ollama_enabled(self) -> bool:
        """True when a local Ollama model should be attempted.

        The previous expression returned True only in scripted mode, i.e. it was
        inverted: it reported Ollama as enabled exactly when no model was used.
        """
        return (
            self.agent_mode.strip().lower() != "scripted"
            and bool(self.ollama_base_url.strip())
            and bool(self.ollama_model.strip())
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()