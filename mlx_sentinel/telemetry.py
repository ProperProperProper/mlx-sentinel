from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
import threading
import time
import uuid
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
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ml_probability: float | None = None


class RunningStats:
    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0

    def update(self, value: float) -> None:
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (value - self.mean)

    def zscore(self, value: float) -> float:
        if self.n < 20:
            return 0.0
        variance = self.m2 / max(self.n - 1, 1)
        if variance <= 0:
            return math.inf if value != self.mean else 0.0
        return abs(value - self.mean) / math.sqrt(variance)


class Guard:
    """Hybrid IPS: deterministic safety rules plus an online ML false-positive filter."""

    def __init__(self, mode: str = "guard") -> None:
        self.mode = mode
        self.count = 0
        self.blocked = 0
        self._mean_norm = RunningStats()
        self._max_norm = RunningStats()
        self._lock = threading.RLock()
        self.events: deque[dict] = deque(maxlen=250)
        self.feedback_count = 0
        self._weights = [0.0] * 5
        self.model_path = os.path.expanduser("~/Library/Application Support/MLX Sentinel/model.json")
        self._load_model()

    @staticmethod
    def level(score: float, reasons: list[str]) -> str:
        if any("injection" in r or "jailbreak" in r or "invalid" in r for r in reasons) or score >= 0.9:
            return "critical"
        if any("outlier" in r or "anomaly" in r or "malicious" in r for r in reasons) or score >= 0.7:
            return "high"
        if score >= 0.25 or reasons:
            return "medium"
        return "normal"

    def _load_model(self) -> None:
        try:
            with open(self.model_path, encoding="utf-8") as handle:
                saved = json.load(handle)
            weights = saved.get("weights", [])
            if len(weights) == 5:
                self._weights = [float(value) for value in weights]
            self.feedback_count = int(saved.get("feedback_count", 0))
        except (OSError, ValueError, TypeError):
            pass

    def _save_model(self) -> None:
        directory = os.path.dirname(self.model_path)
        os.makedirs(directory, exist_ok=True)
        temporary = self.model_path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"weights": self._weights, "feedback_count": self.feedback_count}, handle)
        os.replace(temporary, self.model_path)

    @staticmethod
    def _features(stats: KVStats) -> list[float]:
        return [1.0, stats.mean_norm / 20.0, math.log1p(max(stats.max_norm, 0.0)) / 10.0, stats.cache_tokens / 8192.0, stats.pages / 128.0]

    def _probability(self, features: list[float]) -> float | None:
        if self.feedback_count < 4:
            return None
        value = max(-30.0, min(30.0, sum(w * x for w, x in zip(self._weights, features))))
        return 1.0 / (1.0 + math.exp(-value))

    def _finish(self, score: float, reasons: list[str], features: list[float] | None = None, ml_probability: float | None = None) -> Decision:
        # ML may correct a learned KV false positive, but never overrides hard prompt safety rules.
        if features is not None and ml_probability is not None:
            if ml_probability >= 0.8:
                score = max(score, 0.8)
                reasons.append("ml-malicious-signal")
            elif ml_probability <= 0.2 and reasons and set(reasons).issubset({"kv-max-norm-outlier", "kv-mean-norm-anomaly"}):
                score = min(score, 0.2)
                reasons.append("ml-benign-correction")
        level = self.level(score, reasons)
        hard = any("injection" in r or "jailbreak" in r or "invalid" in r for r in reasons)
        blocked = hard or (self.mode == "enforce" and level in {"high", "critical"}) or (self.mode == "guard" and level == "critical")
        if blocked:
            self.blocked += 1
        decision = Decision(not blocked, min(score, 1.0), "block" if blocked else "allow", reasons or ["normal-behavior"], level, ml_probability=ml_probability)
        self.events.append({"event_id": decision.event_id, "timestamp": decision.timestamp, "level": level, "score": decision.score, "action": decision.action, "reasons": decision.reasons, "ml_probability": decision.ml_probability, "features": features, "feedback": None})
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
            finite = math.isfinite(stats.mean_norm) and math.isfinite(stats.max_norm)
            if not finite:
                score += 0.8
                reasons.append("invalid-kv-norm")
            if stats.attention_entropy is not None and not math.isfinite(stats.attention_entropy):
                score += 0.8
                reasons.append("invalid-attention-entropy")
            mean_z = self._mean_norm.zscore(stats.mean_norm) if finite else 0.0
            max_z = self._max_norm.zscore(stats.max_norm) if finite else 0.0
            if mean_z >= 4.0:
                score += 0.7
                reasons.append("kv-mean-norm-anomaly")
            if max_z >= 4.0:
                score += 0.7
                reasons.append("kv-max-norm-outlier")
            features = self._features(stats) if finite else None
            probability = self._probability(features) if features else None
            if finite:
                self._mean_norm.update(stats.mean_norm)
                self._max_norm.update(stats.max_norm)
            return self._finish(score, reasons, features, probability)

    def feedback(self, event_id: str, label: str) -> dict:
        if label not in {"benign", "malicious"}:
            raise ValueError("label must be benign or malicious")
        with self._lock:
            event = next((item for item in self.events if item["event_id"] == event_id), None)
            if event is None or not event.get("features"):
                raise KeyError("event not found or has no ML features")
            target = 1.0 if label == "malicious" else 0.0
            probability = self._probability(event["features"]) or 0.5
            error = target - probability
            for index, feature in enumerate(event["features"]):
                self._weights[index] += 0.25 * error * feature
            self.feedback_count += 1
            event["feedback"] = label
            self._save_model()
            return {"event_id": event_id, "feedback": label, "feedback_count": self.feedback_count, "ml_probability": self._probability(event["features"])}

    def status(self) -> dict:
        with self._lock:
            return {"mode": self.mode, "observed": self.count, "blocked": self.blocked, "events": len(self.events), "feedback_count": self.feedback_count, "ml_model": "online-logistic-kv-filter", "levels": {level: sum(event["level"] == level for event in self.events) for level in ("normal", "medium", "high", "critical")}}

    def recent_events(self) -> list[dict]:
        with self._lock:
            return list(reversed(self.events))
