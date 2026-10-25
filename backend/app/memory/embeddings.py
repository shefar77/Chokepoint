"""Lesson embeddings.

`fastembed` is optional. If the package or the model is unavailable, or
`EMBEDDINGS=none`, recall falls back to keyword matching plus graph proximity
and the UI shows "vector memory off".
"""

from __future__ import annotations

import logging
import threading
from functools import lru_cache
from typing import Any

from app.config import settings

log = logging.getLogger("chokepoint.embeddings")

DIMENSION = 384


class Embedder:
    """Lazily loaded text embedder with a clearly reported off state."""

    def __init__(self, mode: str, model_name: str) -> None:
        self._mode = "fastembed" if mode == "fastembed" else "none"
        self._model_name = model_name
        self._model: Any | None = None
        self._lock = threading.Lock()
        self._warning = "" if self._mode == "fastembed" else "EMBEDDINGS=none; vector memory is off"
        self._ready = False

    @property
    def enabled(self) -> bool:
        return self._mode == "fastembed" and not self._warning

    def _load(self) -> Any | None:
        if self._mode != "fastembed":
            return None
        with self._lock:
            if self._model is not None or self._warning:
                return self._model
            try:
                from fastembed import TextEmbedding
            except Exception as exc:  # noqa: BLE001 - optional dependency
                self._warning = f"fastembed is not importable ({exc}); vector memory is off"
                log.warning(self._warning)
                return None
            try:
                self._model = TextEmbedding(model_name=self._model_name)
                self._ready = True
                log.info("embedding model %s ready", self._model_name)
            except Exception as exc:  # noqa: BLE001 - model download can fail offline
                self._warning = f"embedding model {self._model_name} unavailable ({exc}); vector memory is off"
                log.warning(self._warning)
                self._model = None
            return self._model

    def embed(self, text: str) -> list[float] | None:
        """Return a 384-dimension vector, or None when embeddings are off."""
        if not text or not text.strip():
            return None
        model = self._load()
        if model is None:
            return None
        try:
            vectors = list(model.embed([text.strip()]))
        except Exception as exc:  # noqa: BLE001 - never fail a request over embeddings
            log.warning("embedding failed: %s", exc)
            return None
        if not vectors:
            return None
        return [float(v) for v in vectors[0]]

    def status(self) -> dict[str, Any]:
        return {
            "mode": self._mode,
            "model": self._model_name if self._mode == "fastembed" else "",
            "dimension": DIMENSION,
            "ready": bool(self._ready),
            "warning": self._warning,
        }


@lru_cache(maxsize=1)
def embedder() -> Embedder:
    return Embedder(settings.embeddings.strip().lower(), settings.embedding_model)


def warm_up() -> dict[str, Any]:
    """Load the model at start-up so the first recall is not slow."""
    inst = embedder()
    if inst.enabled:
        inst.embed("chokepoint warm up")
    return inst.status()
