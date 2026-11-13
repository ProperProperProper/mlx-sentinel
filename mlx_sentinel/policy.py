from __future__ import annotations

import json
import os
from dataclasses import dataclass


VALID_ACTIONS = {"block", "review", "allow"}


@dataclass(frozen=True)
class Policy:
    prompt_injection: str = "block"
    destructive_tools: str = "block"
    suspicious_processes: str = "block"
    high_kv_anomaly: str = "block"

    @classmethod
    def load(cls, path: str | None = None) -> "Policy":
        configured = path or os.environ.get("MLX_SENTINEL_POLICY_PATH")
        if not configured:
            return cls()
        try:
            with open(os.path.expanduser(configured), encoding="utf-8") as handle:
                values = json.load(handle)
            if not isinstance(values, dict):
                return cls()
        except (OSError, ValueError, TypeError):
            return cls()
        fields = {field: values.get(field, getattr(cls(), field)) for field in cls.__dataclass_fields__}
        return cls(**{field: value if value in VALID_ACTIONS else getattr(cls(), field) for field, value in fields.items()})

    def action_for(self, reasons: list[str]) -> str:
        for reason in reasons:
            if "injection" in reason or "jailbreak" in reason:
                return self.prompt_injection
            if "destructive" in reason:
                return self.destructive_tools
            if "process" in reason:
                return self.suspicious_processes
            if "anomaly" in reason or "outlier" in reason or "invalid" in reason:
                return self.high_kv_anomaly
        return "allow"

    def as_dict(self) -> dict[str, str]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}
