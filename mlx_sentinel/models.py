from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ModelInfo:
    model_id: str
    cached: bool
    cache_path: str


class ModelRegistry:
    def __init__(self, current: str, configured: str | None = None) -> None:
        self.current = current
        names = [current]
        names.extend(item.strip() for item in (configured or os.environ.get("MLX_SENTINEL_MODELS", "")).split(",") if item.strip())
        self.models = list(dict.fromkeys(names))

    @staticmethod
    def cache_path(model_id: str) -> str:
        safe = model_id.replace("/", "--")
        return os.path.expanduser(f"~/.cache/huggingface/hub/models--{safe}")

    def list(self) -> list[ModelInfo]:
        return [ModelInfo(name, os.path.isdir(self.cache_path(name)), self.cache_path(name)) for name in self.models]

    def as_dict(self) -> dict:
        return {"current": self.current, "models": [item.__dict__ for item in self.list()], "download_policy": "explicit: start the service with MLX_SENTINEL_MODEL or download with your MLX/Hugging Face tooling"}
