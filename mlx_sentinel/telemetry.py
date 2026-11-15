from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
import random
import threading
import time
import uuid
from collections import deque

from .policy import Policy


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
    signals: dict = field(default_factory=dict)
    profile: str | None = None


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

    def to_dict(self) -> dict:
        return {"n": self.n, "mean": self.mean, "m2": self.m2}

    @classmethod
    def from_dict(cls, value: dict) -> "RunningStats":
        item = cls()
        item.n, item.mean, item.m2 = int(value.get("n", 0)), float(value.get("mean", 0)), float(value.get("m2", 0))
        return item


class IsolationForestLite:
    """Dependency-free online isolation score for small Apple Silicon feature vectors."""

    def __init__(self, trees: int = 32, sample_size: int = 64) -> None:
        self.trees = trees
        self.sample_size = sample_size
        self.samples: deque[list[float]] = deque(maxlen=sample_size)
        self.rng = random.Random(0x5E17)

    def update(self, vector: list[float]) -> None:
        self.samples.append(list(vector))

    def score(self, vector: list[float]) -> float:
        if len(self.samples) < 12:
            return 0.0
        distances = []
        for sample in self.samples:
            distances.append(math.sqrt(sum((a - b) ** 2 for a, b in zip(vector, sample))))
        distances.sort()
        nearest = sum(distances[: max(3, len(distances) // 8)]) / max(3, len(distances) // 8)
        spread = sum(distances) / len(distances)
        return max(0.0, min(1.0, nearest / max(spread * 2.0, 1e-9)))

    def to_dict(self) -> dict:
        return {"samples": list(self.samples)}

    @classmethod
    def from_dict(cls, value: dict) -> "IsolationForestLite":
        item = cls()
        item.samples.extend(value.get("samples", [])[-item.sample_size :])
        return item


class Guard:
    """Hybrid security monitor with per-model baselines, ensemble scoring, local ML and replay."""

    def __init__(self, mode: str = "guard", model_path: str | None = None, journal_path: str | None = None, policy_path: str | None = None) -> None:
        self.mode = mode
        self.policy = Policy.load(policy_path)
        self.count = 0
        self.blocked = 0
        self._lock = threading.RLock()
        self.events: deque[dict] = deque(maxlen=250)
        self.feedback_count = 0
        self.metrics = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        self._weights = [0.0] * 7
        self._profiles: dict[str, dict] = {}
        self.model_path = os.path.expanduser(model_path or os.environ.get("MLX_SENTINEL_MODEL_PATH", "~/Library/Application Support/MLX Sentinel/model.json"))
        self.journal_path = os.path.expanduser(journal_path or os.environ.get("MLX_SENTINEL_JOURNAL_PATH", "~/Library/Application Support/MLX Sentinel/events.jsonl"))
        self._load_model()

    @staticmethod
    def level(score: float, reasons: list[str]) -> str:
        if any("injection" in r or "jailbreak" in r or "invalid" in r or "blocked" in r for r in reasons) or score >= 0.9:
            return "critical"
        if any("outlier" in r or "anomaly" in r or "malicious" in r or "destructive" in r for r in reasons) or score >= 0.7:
            return "high"
        if score >= 0.25 or reasons:
            return "medium"
        return "normal"

    def _load_model(self) -> None:
        try:
            with open(self.model_path, encoding="utf-8") as handle:
                saved = json.load(handle)
            weights = saved.get("weights", [])
            if len(weights) == 7:
                self._weights = [float(value) for value in weights]
            self.feedback_count = int(saved.get("feedback_count", 0))
            self.metrics.update(saved.get("metrics", {}))
            for key, profile in saved.get("profiles", {}).items():
                self._profiles[key] = {"mean": RunningStats.from_dict(profile.get("mean", {})), "max": RunningStats.from_dict(profile.get("max", {})), "iso": IsolationForestLite.from_dict(profile.get("iso", {}))}
        except (OSError, ValueError, TypeError):
            pass

    def _save_model(self) -> None:
        directory = os.path.dirname(self.model_path)
        os.makedirs(directory, exist_ok=True)
        profiles = {key: {"mean": value["mean"].to_dict(), "max": value["max"].to_dict(), "iso": value["iso"].to_dict()} for key, value in self._profiles.items()}
        temporary = self.model_path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"weights": self._weights, "feedback_count": self.feedback_count, "metrics": self.metrics, "profiles": profiles}, handle)
        os.replace(temporary, self.model_path)

    def _profile(self, stats: KVStats) -> tuple[str, dict]:
        key = f"{stats.model}|{stats.source}"
        return key, self._profiles.setdefault(key, {"mean": RunningStats(), "max": RunningStats(), "iso": IsolationForestLite()})

    @staticmethod
    def _features(stats: KVStats, context: dict | None = None) -> list[float]:
        context = context or {}
        return [1.0, stats.mean_norm / 20.0, math.log1p(max(stats.max_norm, 0.0)) / 10.0, stats.cache_tokens / 8192.0, stats.pages / 128.0, min(float(context.get("latency_ms", 0.0)) / 5000.0, 2.0), min(float(context.get("output_chars", 0.0)) / 20000.0, 2.0)]

    def _probability(self, features: list[float]) -> float | None:
        if self.feedback_count < 4:
            return None
        value = max(-30.0, min(30.0, sum(w * x for w, x in zip(self._weights, features))))
        return 1.0 / (1.0 + math.exp(-value))

    def _finish(self, score: float, reasons: list[str], features: list[float] | None = None, ml_probability: float | None = None, signals: dict | None = None, profile: str | None = None) -> Decision:
        if features is not None and ml_probability is not None:
            if ml_probability >= 0.8:
                score = max(score, 0.8)
                reasons.append("ml-malicious-signal")
            elif ml_probability <= 0.2 and reasons and set(reasons).issubset({"kv-max-norm-outlier", "kv-mean-norm-anomaly", "unsupervised-anomaly"}):
                score = min(score, 0.2)
                reasons.append("ml-benign-correction")
        level = self.level(score, reasons)
        policy_action = self.policy.action_for(reasons)
        hard = policy_action == "block" and any("injection" in r or "jailbreak" in r or "invalid" in r or "blocked" in r for r in reasons)
        mode_would_block = self.mode in {"enforce", "guard"} and level in ({"high", "critical"} if self.mode == "enforce" else {"critical"})
        would_block = hard or policy_action in {"block", "review"} or (policy_action not in {"allow", "review"} and mode_would_block)
        should_block = hard or policy_action == "block" or (policy_action not in {"allow", "review"} and mode_would_block)
        blocked = should_block and self.mode != "observe" and self.mode != "shadow"
        if blocked:
            self.blocked += 1
        decision = Decision(not blocked, min(score, 1.0), "block" if blocked else ("would-block" if would_block else "allow"), reasons or ["normal-behavior"], level, ml_probability=ml_probability, signals=signals or {}, profile=profile)
        event = {"event_id": decision.event_id, "timestamp": decision.timestamp, "level": level, "score": decision.score, "action": decision.action, "reasons": decision.reasons, "ml_probability": decision.ml_probability, "signals": decision.signals, "profile": decision.profile, "features": features, "feedback": None}
        self.events.append(event)
        self._append_journal(event)
        return decision

    def _append_journal(self, event: dict) -> None:
        try:
            os.makedirs(os.path.dirname(self.journal_path), exist_ok=True)
            with open(self.journal_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event) + "\n")
        except OSError:
            pass

    def inspect_prompt(self, text: str) -> Decision:
        with self._lock:
            lower = text.lower()
            score, reasons = 0.0, []
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
            return self._finish(score, reasons, signals={"prompt_chars": len(text), "detector": "prompt-rules"})

    def inspect(self, stats: KVStats, context: dict | None = None) -> Decision:
        with self._lock:
            self.count += 1
            score, reasons = 0.0, []
            finite = math.isfinite(stats.mean_norm) and math.isfinite(stats.max_norm)
            if not finite:
                score += 0.8
                reasons.append("invalid-kv-norm")
            if stats.attention_entropy is not None and not math.isfinite(stats.attention_entropy):
                score += 0.8
                reasons.append("invalid-attention-entropy")
            profile_key, profile = self._profile(stats)
            mean_z = profile["mean"].zscore(stats.mean_norm) if finite else 0.0
            max_z = profile["max"].zscore(stats.max_norm) if finite else 0.0
            vector = self._features(stats, context) if finite else None
            isolation = profile["iso"].score(vector) if vector else 0.0
            if mean_z >= 4.0:
                score += 0.35
                reasons.append("kv-mean-norm-anomaly")
            if max_z >= 4.0:
                score += 0.35
                reasons.append("kv-max-norm-outlier")
            if isolation >= 0.85:
                score += 0.35
                reasons.append("unsupervised-anomaly")
            if context and float(context.get("latency_ms", 0)) > 10000:
                score += 0.15
                reasons.append("latency-anomaly")
            probability = self._probability(vector) if vector else None
            signals = {"mean_z": round(mean_z, 3) if math.isfinite(mean_z) else None, "max_z": round(max_z, 3) if math.isfinite(max_z) else None, "isolation_score": round(isolation, 3), "ml_probability": probability, "detectors": ["adaptive-baseline", "isolation-forest-lite", "online-logistic", "hard-rules"]}
            if finite:
                profile["mean"].update(stats.mean_norm)
                profile["max"].update(stats.max_norm)
                profile["iso"].update(vector)
            return self._finish(score, reasons, vector, probability, signals, profile_key)

    def inspect_tool(self, name: str, arguments: object) -> Decision:
        with self._lock:
            text = f"{name} {json.dumps(arguments, default=str)}".lower()
            reasons, score = [], 0.0
            destructive = ("rm ", "delete", "unlink", "drop table", "force push", "shutdown", "kill ", "chmod 777")
            sensitive = ("password", "private_key", "api_key", "credential", ".ssh", ".env")
            if any(term in text for term in destructive):
                reasons.append("destructive-tool-call")
                score += 0.9
            if any(term in text for term in sensitive):
                reasons.append("sensitive-tool-call")
                score += 0.4
            return self._finish(score, reasons, signals={"detector": "tool-firewall", "tool": name, "arguments_type": type(arguments).__name__})

    def inspect_process(self, executable: str, command_line: str) -> Decision:
        with self._lock:
            text = f"{executable} {command_line}".lower()
            reasons, score = [], 0.0
            piped_shell = ("curl" in text or "wget" in text) and ("| sh" in text or "| bash" in text or "| zsh" in text)
            if piped_shell:
                reasons.append("suspicious-process-command")
                score += 1.0
            elif any(term in text for term in ("rm -rf", "osascript", "security find-generic-password", "base64 -d")):
                reasons.append("suspicious-process-command")
                score += 0.8
            if any(term in text for term in ("nc -e", "/dev/tcp/", "reverse shell")):
                reasons.append("process-network-shell")
                score += 0.9
            return self._finish(score, reasons, signals={"detector": "process-firewall", "executable": executable, "command_line": command_line[:500]})

    def feedback(self, event_id: str, label: str) -> dict:
        if label not in {"benign", "malicious"}:
            raise ValueError("label must be benign or malicious")
        with self._lock:
            event = next((item for item in self.events if item["event_id"] == event_id), None)
            if event is None or not event.get("features"):
                raise KeyError("event not found or has no ML features")
            predicted = event["score"] >= 0.25 or event["level"] in {"high", "critical"}
            actual = label == "malicious"
            key = "tp" if predicted and actual else "fp" if predicted else "fn" if actual else "tn"
            self.metrics[key] += 1
            target = 1.0 if actual else 0.0
            probability = self._probability(event["features"]) or 0.5
            error = target - probability
            for index, feature in enumerate(event["features"]):
                self._weights[index] += 0.25 * error * feature
            self.feedback_count += 1
            event["feedback"] = label
            self._save_model()
            return {"event_id": event_id, "feedback": label, "feedback_count": self.feedback_count, "ml_probability": self._probability(event["features"]), "metrics": self.metrics_dict()}

    def metrics_dict(self) -> dict:
        tp, tn, fp, fn = (self.metrics[k] for k in ("tp", "tn", "fp", "fn"))
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        return {**self.metrics, "precision": precision, "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None}

    def replay(self, events: list[dict], mode: str = "shadow") -> dict:
        results = []
        for item in events[:1000]:
            if not isinstance(item, dict) or "kv" not in item:
                continue
            try:
                decision = self.inspect(KVStats(**item["kv"]), item.get("context"))
                results.append({"event_id": decision.event_id, "level": decision.alert_level, "score": decision.score, "would_block": decision.action in {"block", "would-block"}, "reasons": decision.reasons})
            except (TypeError, ValueError):
                continue
        return {"mode": mode, "replayed": len(results), "results": results}

    def status(self) -> dict:
        with self._lock:
            return {"mode": self.mode, "observed": self.count, "blocked": self.blocked, "events": len(self.events), "feedback_count": self.feedback_count, "ml_model": "online-logistic + isolation-forest-lite", "profiles": len(self._profiles), "policy": self.policy.as_dict(), "metrics": self.metrics_dict(), "levels": {level: sum(event["level"] == level for event in self.events) for level in ("normal", "medium", "high", "critical")}}

    def recent_events(self) -> list[dict]:
        with self._lock:
            return list(reversed(self.events))
