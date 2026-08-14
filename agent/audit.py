"""JSONL audit logger. Never records secrets."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from agent.policy import PolicyDecision

_SECRET_KEY = re.compile(
    r"(password|secret|token|credential|api[_-]?key)",
    re.IGNORECASE,
)
_REDACT = "[redacted]"


def _sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if _SECRET_KEY.search(str(key)):
                out[key] = _REDACT
            else:
                out[key] = _sanitize(item)
        return out
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, str) and _SECRET_KEY.search(value):
        return _REDACT
    return value


class AuditLogger:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.events: list[dict[str, Any]] = []

    def record(
        self,
        decision: PolicyDecision,
        *,
        sandbox: str = "locked",
        result: str | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": decision.tool,
            "target": decision.target,
            "policy": "allow" if decision.allow else "deny",
            "reason": decision.reason,
            "control": decision.control,
            "sandbox": sandbox,
        }
        if result is not None:
            event["result"] = result
        if extra:
            event.update(_sanitize(dict(extra)))
        event = _sanitize(event)
        self.events.append(event)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event) + "\n")
        return event

    def denied(self) -> Iterable[dict[str, Any]]:
        return [event for event in self.events if event.get("policy") == "deny"]
