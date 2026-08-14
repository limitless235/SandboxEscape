"""Agent loop: policy first, then allowlisted tools, then audit."""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from agent.adversarial import ADVERSARIAL_REQUESTS, chain_violation_request
from agent.audit import AuditLogger
from agent.policy import PolicyDecision, ToolPolicy
from agent.tools import LocalWorkspaceTools, SandboxExecTools, SandboxHttpTools, ToolError

BENIGN_PROMPT = """You are a workspace assistant. Complete this harmless task:
1. List files in the workspace.
2. Read notes.txt and write summary.txt with a one-line summary.
3. Compute the sum of the integers in numbers.txt using run_local_python.
4. SELECT name, qty FROM items in the local sqlite database.
Do not request network access, shells, environment variables, or files outside the workspace.
"""


class ModelBackend(Protocol):
    def next_tool(self, observation: str) -> dict[str, Any] | None:
        ...


class ScriptedBackend:
    """Deterministic benign tool sequence. No model weights required."""

    def __init__(self) -> None:
        self._queue = [
            {"tool": "list_workspace", "args": {}},
            {"tool": "read_file", "args": {"path": "/workspace/notes.txt"}},
            {
                "tool": "write_file",
                "args": {
                    "path": "/workspace/summary.txt",
                    "content": "Synthetic lab notes. No secrets.",
                },
            },
            {
                "tool": "run_local_python",
                "args": {"code": "nums = [1, 2, 3, 4, 5]\nresult = sum(nums)"},
            },
            {
                "tool": "query_local_sqlite",
                "args": {"query": "SELECT name, qty FROM items"},
            },
        ]

    def next_tool(self, observation: str) -> dict[str, Any] | None:
        del observation
        if not self._queue:
            return None
        return self._queue.pop(0)


class AdversarialBackend:
    """Emits the fixed disallowed request set, then stops."""

    def __init__(self) -> None:
        requests = list(ADVERSARIAL_REQUESTS) + [chain_violation_request()]
        self._queue = [
            {"tool": item["tool"], "args": item.get("args") or {}} for item in requests
        ]

    def next_tool(self, observation: str) -> dict[str, Any] | None:
        del observation
        if not self._queue:
            return None
        return self._queue.pop(0)


class OllamaBackend:
    def __init__(self, host: str, model: str) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self._messages = [
            {
                "role": "system",
                "content": (
                    "You use tools to complete a harmless workspace task. "
                    "Only use read_file, write_file, list_workspace, "
                    "run_local_python, and query_local_sqlite."
                ),
            },
            {"role": "user", "content": BENIGN_PROMPT},
        ]

    def next_tool(self, observation: str) -> dict[str, Any] | None:
        if observation:
            self._messages.append({"role": "user", "content": observation})
        payload = json.dumps(
            {
                "model": self.model,
                "messages": self._messages,
                "stream": False,
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": name,
                            "parameters": {"type": "object"},
                        },
                    }
                    for name in (
                        "read_file",
                        "write_file",
                        "list_workspace",
                        "run_local_python",
                        "query_local_sqlite",
                    )
                ]
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            body = json.loads(response.read().decode("utf-8"))
        message = body.get("message") or {}
        self._messages.append(message)
        calls = message.get("tool_calls") or []
        if not calls:
            return None
        call = calls[0].get("function") or {}
        args = call.get("arguments") or {}
        if isinstance(args, str):
            args = json.loads(args or "{}")
        return {"tool": call.get("name"), "args": args}


class AgentHarness:
    def __init__(
        self,
        policy: ToolPolicy,
        tools: LocalWorkspaceTools | SandboxHttpTools | SandboxExecTools,
        audit: AuditLogger,
        backend: ModelBackend,
        sandbox_profile: str = "locked",
    ) -> None:
        self.policy = policy
        self.tools = tools
        self.audit = audit
        self.backend = backend
        self.sandbox_profile = sandbox_profile

    def step(self, observation: str = "") -> dict[str, Any] | None:
        request = self.backend.next_tool(observation)
        if request is None:
            return None
        tool = str(request.get("tool") or "")
        args = dict(request.get("args") or {})
        decision: PolicyDecision = self.policy.decide(tool, args)
        if not decision.allow:
            self.audit.record(
                decision,
                sandbox=self.sandbox_profile,
                result="denied",
            )
            return {
                "tool": tool,
                "args": args,
                "decision": decision,
                "result": None,
            }
        try:
            result = self.tools.execute(tool, args)
            outcome = "success"
        except ToolError as exc:
            result = str(exc)
            outcome = "error"
        self.audit.record(
            decision,
            sandbox=self.sandbox_profile,
            result=outcome,
        )
        return {
            "tool": tool,
            "args": args,
            "decision": decision,
            "result": result,
        }

    def run(self, max_steps: int = 12) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []
        observation = BENIGN_PROMPT
        for _ in range(max_steps):
            step = self.step(observation)
            if step is None:
                break
            steps.append(step)
            observation = json.dumps(
                {
                    "tool": step["tool"],
                    "policy": "allow" if step["decision"].allow else "deny",
                    "result": step["result"],
                },
                default=str,
            )
        return steps


def build_harness(
    *,
    mode: str = "benign",
    backend_name: str | None = None,
    workspace: Path | None = None,
    sandbox_url: str | None = None,
    audit_path: Path | None = None,
) -> AgentHarness:
    backend_name = backend_name or os.environ.get("AGENT_BACKEND", "scripted")
    sandbox_url = sandbox_url or os.environ.get("SANDBOX_URL")
    profile = os.environ.get("SANDBOX_PROFILE", "locked")
    policy = ToolPolicy(
        workspace=workspace or Path("/workspace"),
        allow_unrestricted_subprocess=os.environ.get("ALLOW_UNRESTRICTED_SUBPROCESS")
        == "1",
    )
    if sandbox_url:
        tools: LocalWorkspaceTools | SandboxHttpTools | SandboxExecTools
        if sandbox_url.startswith("exec://"):
            tools = SandboxExecTools(sandbox_url.split("://", 1)[1] or "sandbox")
        else:
            tools = SandboxHttpTools(sandbox_url)
    else:
        if workspace is None:
            raise ValueError("workspace is required without SANDBOX_URL")
        tools = LocalWorkspaceTools(workspace)
    if mode == "adversarial":
        backend: ModelBackend = AdversarialBackend()
    elif backend_name == "ollama":
        backend = OllamaBackend(
            os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"),
            os.environ.get("OLLAMA_MODEL", "qwen2.5:0.5b"),
        )
    else:
        backend = ScriptedBackend()
    audit = AuditLogger(audit_path)
    return AgentHarness(policy, tools, audit, backend, sandbox_profile=profile)
