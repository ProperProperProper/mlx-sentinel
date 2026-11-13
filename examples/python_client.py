"""Minimal MLX Sentinel client using only Python's standard library."""

from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen


BASE_URL = os.environ.get("MLX_SENTINEL_URL", "http://127.0.0.1:8081")
API_KEY = os.environ.get("MLX_SENTINEL_API_KEY")


def request(path: str, payload: dict | None = None) -> dict:
    headers = {"content-type": "application/json"}
    if API_KEY:
        headers["authorization"] = f"Bearer {API_KEY}"
    body = json.dumps(payload).encode() if payload is not None else None
    with urlopen(Request(BASE_URL + path, data=body, headers=headers, method="POST" if body else "GET"), timeout=120) as response:
        return json.loads(response.read())


if __name__ == "__main__":
    result = request("/v1/chat/completions", {"model": "local", "messages": [{"role": "user", "content": "Hello from Python"}], "max_tokens": 64})
    print(result["choices"][0]["message"]["content"])
