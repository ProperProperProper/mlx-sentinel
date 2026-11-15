from __future__ import annotations

import os
import re
import subprocess
import threading
import time


class ResourceGovernor:
    """Small macOS-aware admission controller that prevents inference pile-ups."""

    def __init__(self, max_load: float | None = None, cooldown_seconds: float = 5.0) -> None:
        self.cpu_count = max(1, os.cpu_count() or 1)
        self.max_load = max_load or max(1.0, self.cpu_count * 0.75)
        self.cooldown_seconds = cooldown_seconds
        self._lock = threading.Lock()
        self._last_check = 0.0
        self._cached: dict = {"allowed": True, "reasons": [], "load1": 0.0, "thermal": "unknown", "memory_pressure": "unknown"}

    @staticmethod
    def _thermal_state() -> tuple[str, float | None]:
        try:
            output = subprocess.run(["/usr/bin/pmset", "-g", "therm"], capture_output=True, text=True, timeout=1.0, check=False).stdout.lower()
        except (OSError, subprocess.SubprocessError):
            return "unknown", None
        limit = re.search(r"cpu_speed_limit\s*=\s*(\d+)", output)
        level = re.search(r"thermal level\s*[:=]\s*(\d+)", output)
        if limit and int(limit.group(1)) < 80:
            return "throttled", float(limit.group(1))
        if level and int(level.group(1)) >= 2:
            return "hot", float(level.group(1))
        return "nominal", float(limit.group(1)) if limit else None

    @staticmethod
    def _memory_pressure() -> str:
        try:
            output = subprocess.run(["/usr/bin/memory_pressure", "-Q"], capture_output=True, text=True, timeout=1.0, check=False).stdout.lower()
        except (OSError, subprocess.SubprocessError):
            return "unknown"
        if "critical" in output:
            return "critical"
        if "warn" in output or "pressure" in output and "normal" not in output:
            return "warning"
        return "nominal"

    def check(self, force: bool = False) -> dict:
        with self._lock:
            now = time.monotonic()
            if not force and now - self._last_check < self.cooldown_seconds:
                return dict(self._cached)
            load1 = os.getloadavg()[0]
            thermal, thermal_value = self._thermal_state()
            memory = self._memory_pressure()
            reasons = []
            if load1 > self.max_load:
                reasons.append("cpu-load-high")
            if thermal in {"hot", "throttled"}:
                reasons.append("thermal-pressure")
            if memory in {"warning", "critical"}:
                reasons.append("memory-pressure")
            self._cached = {"allowed": not reasons, "reasons": reasons, "load1": round(load1, 2), "load_limit": round(self.max_load, 2), "thermal": thermal, "thermal_value": thermal_value, "memory_pressure": memory, "timestamp": time.time()}
            self._last_check = now
            return dict(self._cached)
