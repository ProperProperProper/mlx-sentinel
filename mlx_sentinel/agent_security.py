"""Agent-facing safety gates inspired by smolagents' secure execution model.

This module validates agent plans; it does not execute untrusted model output.
Local AST validation is a first layer only. Strong isolation still requires a
real sandbox such as a separate container or VM.
"""

from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, field


_SAFE_IMPORTS = frozenset(
    item.strip()
    for item in os.environ.get("MLX_SENTINEL_ALLOWED_IMPORTS", "math,json,statistics").split(",")
    if item.strip()
)
_DANGEROUS_MODULES = frozenset({
    "os", "sys", "subprocess", "socket", "requests", "urllib", "http", "pathlib",
    "shutil", "ctypes", "multiprocessing", "importlib", "builtins", "plistlib",
})
_DANGEROUS_NAMES = frozenset({
    "eval", "exec", "compile", "__import__", "open", "input", "breakpoint", "help",
    "globals", "locals", "vars", "getattr", "setattr", "delattr", "memoryview",
})
_DANGEROUS_ATTRIBUTES = frozenset({
    "__class__", "__bases__", "__subclasses__", "__globals__", "__code__", "__dict__",
    "__getattribute__", "system", "popen", "run", "Popen", "connect", "send", "unlink",
})
_TOOL_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,63}$")


@dataclass(frozen=True)
class AgentDecision:
    allowed: bool
    action: str
    reasons: list[str] = field(default_factory=list)
    limits: dict[str, int] = field(default_factory=dict)


class AgentSecurityGate:
    """Deny-by-default controls for model-generated agent actions."""

    def __init__(self, max_steps: int | None = None, max_code_nodes: int | None = None) -> None:
        self.max_steps = max_steps or int(os.environ.get("MLX_SENTINEL_MAX_AGENT_STEPS", "20"))
        self.max_code_nodes = max_code_nodes or int(os.environ.get("MLX_SENTINEL_MAX_CODE_NODES", "1000"))
        configured = os.environ.get("MLX_SENTINEL_ALLOWED_TOOLS", "")
        self.allowed_tools = frozenset(item.strip() for item in configured.split(",") if item.strip())

    def inspect_step(self, name: str, arguments: object, step: int) -> AgentDecision:
        reasons: list[str] = []
        if step < 1 or step > self.max_steps:
            reasons.append("agent-step-limit")
        if not _TOOL_NAME.fullmatch(name):
            reasons.append("invalid-tool-name")
        if name not in self.allowed_tools:
            reasons.append("tool-not-explicitly-allowed")
        try:
            encoded = json.dumps(arguments, default=str)
        except (TypeError, ValueError):
            encoded = "<unserializable>"
            reasons.append("invalid-tool-arguments")
        if len(encoded) > 65536:
            reasons.append("tool-arguments-too-large")
        return AgentDecision(not reasons, "allow" if not reasons else "block", reasons, {"max_steps": self.max_steps})

    def inspect_code(self, source: str, allowed_imports: set[str] | None = None) -> AgentDecision:
        reasons: list[str] = []
        if not isinstance(source, str) or len(source) > 128 * 1024:
            return AgentDecision(False, "block", ["code-too-large"], {"max_code_nodes": self.max_code_nodes})
        try:
            tree = ast.parse(source, mode="exec")
        except SyntaxError:
            return AgentDecision(False, "block", ["invalid-python-syntax"], {"max_code_nodes": self.max_code_nodes})
        nodes = list(ast.walk(tree))
        if len(nodes) > self.max_code_nodes:
            reasons.append("code-operation-limit")
        imports = allowed_imports if allowed_imports is not None else set(_SAFE_IMPORTS)
        for node in nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]
                    if root in _DANGEROUS_MODULES or alias.name not in imports:
                        reasons.append(f"import-not-allowed:{alias.name}")
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".", 1)[0]
                if root in _DANGEROUS_MODULES or (node.module or "") not in imports:
                    reasons.append(f"import-not-allowed:{node.module or '<relative>'}")
            elif isinstance(node, ast.While):
                reasons.append("unbounded-loop")
            elif isinstance(node, ast.Name) and node.id in _DANGEROUS_NAMES:
                reasons.append(f"dangerous-name:{node.id}")
            elif isinstance(node, ast.Attribute) and node.attr in _DANGEROUS_ATTRIBUTES:
                reasons.append(f"dangerous-attribute:{node.attr}")
        # Preserve evidence but avoid flooding the journal with repeated AST hits.
        unique = list(dict.fromkeys(reasons))[:32]
        return AgentDecision(not unique, "allow" if not unique else "block", unique, {"max_code_nodes": self.max_code_nodes})

    def inspect_output(self, text: str) -> AgentDecision:
        lowered = text.lower()
        reasons = []
        if any(term in lowered for term in ("ignore previous instructions", "reveal system prompt", "disable safety")):
            reasons.append("tool-output-prompt-injection")
        if any(term in lowered for term in ("authorization: bearer", "private key", "api key", "upload the contents")):
            reasons.append("tool-output-sensitive-data")
        return AgentDecision(not reasons, "allow" if not reasons else "block", reasons)
