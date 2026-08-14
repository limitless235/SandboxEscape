"""In-depth agent traces: model text, tool args (including code), policy, chain."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from agent.audit import _sanitize
from agent.policy import PolicyDecision

_RESULT_LIMIT = 4000


def _clip(value: Any, limit: int = _RESULT_LIMIT) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"\n... [{len(value) - limit} more characters]"
    if isinstance(value, list) and len(json.dumps(value, default=str)) > limit:
        return value[:20] + [f"... [{len(value) - 20} more items]"]
    return value


def _pretty(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, default=str)


class TraceLogger:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory
        self.steps: list[dict[str, Any]] = []

    def record_step(
        self,
        *,
        index: int,
        observation: str,
        tool: str,
        args: Mapping[str, Any],
        decision: PolicyDecision,
        result: Any,
        outcome: str,
        model_text: str = "",
        model_tool_calls: list[dict[str, Any]] | None = None,
        backend: str = "",
    ) -> dict[str, Any]:
        previous = self.steps[-1]["tool"] if self.steps else None
        event = _sanitize(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "step": index,
                "chained_from": previous,
                "observation": _clip(observation),
                "model_text": _clip(model_text or ""),
                "model_tool_calls": model_tool_calls or [],
                "tool": tool,
                "args": dict(args),
                "python_code": args.get("code") if tool == "run_local_python" else None,
                "sqlite_query": args.get("query") if tool == "query_local_sqlite" else None,
                "path": args.get("path") if "path" in args else None,
                "policy": "allow" if decision.allow else "deny",
                "reason": decision.reason,
                "control": decision.control,
                "outcome": outcome,
                "result": _clip(result),
                "backend": backend,
            }
        )
        self.steps.append(event)
        return event

    def write(self) -> tuple[Path | None, Path | None]:
        if self.directory is None:
            return None, None
        self.directory.mkdir(parents=True, exist_ok=True)
        jsonl_path = self.directory / "trace.jsonl"
        md_path = self.directory / "trace.md"
        jsonl_path.write_text(
            "".join(json.dumps(step, default=str) + "\n" for step in self.steps),
            encoding="utf-8",
        )
        md_path.write_text(self.render_markdown(), encoding="utf-8")
        return jsonl_path, md_path

    def render_markdown(self) -> str:
        if not self.steps:
            return "# Agent trace\n\nNo steps recorded.\n"
        backend = str(self.steps[0].get("backend") or "unknown")
        lines = [
            "# Agent trace",
            "",
            f"Backend: `{backend}`",
            f"Steps: {len(self.steps)}",
            "",
            "## Chain",
            "",
            self._chain_line(),
            "",
        ]
        for step in self.steps:
            index = step["step"]
            policy = step["policy"]
            lines.extend(
                [
                    f"## Step {index}: `{step['tool']}` — {policy.upper()}",
                    "",
                ]
            )
            if step.get("chained_from"):
                lines.append(f"Chained from `{step['chained_from']}` (previous tool result was fed back).")
                lines.append("")
            if step.get("model_text"):
                lines.append("**Model text**")
                lines.append("")
                lines.append("```")
                lines.append(str(step["model_text"]))
                lines.append("```")
                lines.append("")
            if step.get("python_code"):
                lines.append("**Python the model wanted to run**")
                lines.append("")
                lines.append("```python")
                lines.append(str(step["python_code"]))
                lines.append("```")
                lines.append("")
            if step.get("model_tool_calls"):
                lines.append("**Raw model tool_calls**")
                lines.append("")
                lines.append("```json")
                lines.append(_pretty(step["model_tool_calls"]))
                lines.append("```")
                lines.append("")
            if step.get("sqlite_query"):
                lines.append("**SQL**")
                lines.append("")
                lines.append("```sql")
                lines.append(str(step["sqlite_query"]))
                lines.append("```")
                lines.append("")
            lines.append("**Tool arguments**")
            lines.append("")
            lines.append("```json")
            lines.append(_pretty(step.get("args") or {}))
            lines.append("```")
            lines.append("")
            lines.append(
                f"**Policy:** `{policy}` via `{step.get('control')}` — {step.get('reason')}"
            )
            lines.append("")
            lines.append(f"**Outcome:** `{step.get('outcome')}`")
            lines.append("")
            lines.append("**Result**")
            lines.append("")
            lines.append("```")
            lines.append(_pretty(step.get("result")))
            lines.append("```")
            lines.append("")
        return "\n".join(lines)

    def _chain_line(self) -> str:
        parts: list[str] = []
        for step in self.steps:
            label = f"{step['step']}.{step['tool']}"
            if step["policy"] == "deny":
                label += " [DENIED]"
            parts.append(label)
        return " → ".join(parts)
