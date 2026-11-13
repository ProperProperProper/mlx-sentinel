from __future__ import annotations

from dataclasses import dataclass, field
import math
import threading
import time
from collections import deque


@dataclass
class KVStats:
    model: str
    pages: float
    cache_tokens: float
    mean_norm: float
    max_norm: float
    attention_entropy: float | None = None
    source: str = "mlx_lm.KVCache"


@dataclass
class Decision:
    allowed: bool
    score: float
    action: str
    reasons: list[str] = field(default_factory=list)
    alert_level: str = "normal"
    timestamp: float = field(default_factory=time.time)


class Guard:
    def __init__(self, mode: str = "guard") -> None:
        self.mode = mode
        self.count = 0
        self.blocked = 0
        self._mean = 0.0
        self._m2 = 0.0
        self._lock = threading.Lock()
        self.events: deque[dict] = deque(maxlen=250)

    @staticmethod
    def level(score: float, reasons: list[str]) -> str:
        if any("injection" in r or "jailbreak" in r or "invalid" in r for r in reasons) or score >= 0.9:
            return "critical"
        if any("outlier" in r or "anomaly" in r for r in reasons) or score >= 0.7:
            return "high"
        if score >= 0.25 or reasons:
            return "medium"
        return "normal"

    def _finish(self, score: float, reasons: list[str]) -> Decision:
        level = self.level(score, reasons)
        blocked = self.mode == "enforce" and level in {"high", "critical"} or self.mode == "guard" and level == "critical"
        if blocked:
            self.blocked += 1
        decision = Decision(not blocked, min(score, 1.0), "block" if blocked else "allow", reasons or ["normal-behavior"], level)
        self.events.append({"timestamp": decision.timestamp, "level": level, "score": decision.score, "action": decision.action, "reasons": decision.reasons})
        return decision

    def inspect_prompt(self, text: str) -> Decision:
        with self._lock:
            lower = text.lower()
            score = 0.0
            reasons: list[str] = []
            for terms, weight, reason in [
                (("ignore previous", "ignore all instructions", "system prompt"), 0.7, "prompt-injection-pattern"),
                (("jailbreak", "developer mode", "do anything now"), 0.8, "jailbreak-pattern"),
                (("rm -rf", "delete repository", "git push --force"), 0.8, "destructive-action-pattern"),
                (("api key", "password", "private key", "credential"), 0.3, "sensitive-data-pattern"),
            ]:
                if any(term in lower for term in terms):
                    score += weight
                    reasons.append(reason)
            if len(text) > 12000:
                score += 0.25
                reasons.append("prompt-length-anomaly")
            return self._finish(score, reasons)

    def inspect(self, stats: KVStats) -> Decision:
        with self._lock:
            self.count += 1
            score = 0.0
            reasons: list[str] = []
            if not math.isfinite(stats.mean_norm) or not math.isfinite(stats.max_norm):
                score += 0.8
                reasons.append("invalid-kv-norm")
            if stats.max_norm > 100.0:
                score += 0.3
                reasons.append("kv-max-norm-outlier")
            if stats.attention_entropy is not None and not math.isfinite(stats.attention_entropy):
                score += 0.8
                reasons.append("invalid-attention-entropy")
            if self.count > 20:
                variance = self._m2 / max(self.count - 2, 1)
                if variance > 0 and abs(stats.mean_norm - self._mean) / math.sqrt(variance) >= 4:
                    score += 0.7
                    reasons.append("kv-mean-norm-anomaly")
            if score < 0.35 and math.isfinite(stats.mean_norm):
                n = self.count
                delta = stats.mean_norm - self._mean
                self._mean += delta / n
                self._m2 += delta * (stats.mean_norm - self._mean)
            return self._finish(score, reasons)

    def status(self) -> dict:
        with self._lock:
            return {"mode": self.mode, "observed": self.count, "blocked": self.blocked, "events": len(self.events), "levels": {level: sum(event["level"] == level for event in self.events) for level in ("normal", "medium", "high", "critical")}}

    def recent_events(self) -> list[dict]:
        with self._lock:
            return list(reversed(self.events))
