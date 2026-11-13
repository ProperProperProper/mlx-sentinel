from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    model: str
    host: str
    port: int
    max_tokens: int
    mode: str
    security_url: str | None
    policy_path: str | None
    api_key: str | None
    rate_limit: int
    rate_window: int
    cors_origin: str
    max_request_bytes: int

    @classmethod
    def from_env(cls) -> "Settings":
        mode = os.environ.get("MLX_SENTINEL_MODE", "guard")
        if mode not in {"observe", "shadow", "guard", "enforce"}:
            mode = "guard"
        return cls(
            model=os.environ.get("MLX_SENTINEL_MODEL", "mlx-community/Qwen3-0.6B-4bit"),
            host=os.environ.get("MLX_SENTINEL_HOST", "127.0.0.1"),
            port=_int("MLX_SENTINEL_PORT", 8081, 1),
            max_tokens=_int("MLX_SENTINEL_MAX_TOKENS", 512, 1),
            mode=mode,
            security_url=os.environ.get("MLX_SENTINEL_SECURITY_URL"),
            policy_path=os.environ.get("MLX_SENTINEL_POLICY_PATH"),
            api_key=os.environ.get("MLX_SENTINEL_API_KEY") or None,
            rate_limit=_int("MLX_SENTINEL_RATE_LIMIT", 60, 1),
            rate_window=_int("MLX_SENTINEL_RATE_WINDOW", 60, 1),
            cors_origin=os.environ.get("MLX_SENTINEL_CORS_ORIGIN", ""),
            max_request_bytes=_int("MLX_SENTINEL_MAX_REQUEST_BYTES", 4 * 1024 * 1024, 1024),
        )
