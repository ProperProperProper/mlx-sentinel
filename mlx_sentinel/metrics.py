from __future__ import annotations

import threading
import time


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started = time.time()
        self.requests = 0
        self.responses = 0
        self.errors = 0
        self.blocked = 0
        self.latency_ms = 0.0

    def observe(self, status: int, latency_ms: float = 0.0) -> None:
        with self._lock:
            self.requests += 1
            if status >= 400:
                self.errors += 1
            if status in {401, 403}:
                self.blocked += 1
            self.responses += 1
            self.latency_ms = latency_ms

    def prometheus(self) -> str:
        with self._lock:
            uptime = max(0.0, time.time() - self.started)
            values = {
                "mlx_sentinel_requests_total": self.requests,
                "mlx_sentinel_responses_total": self.responses,
                "mlx_sentinel_errors_total": self.errors,
                "mlx_sentinel_blocked_total": self.blocked,
                "mlx_sentinel_last_latency_ms": self.latency_ms,
                "mlx_sentinel_uptime_seconds": uptime,
            }
        return "\n".join(f"{name} {value}" for name, value in values.items()) + "\n"


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = [stamp for stamp in self._hits.get(key, []) if now - stamp < self.window_seconds]
            allowed = len(hits) < self.limit
            if allowed:
                hits.append(now)
            self._hits[key] = hits
            return allowed
