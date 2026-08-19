"""Agent loop: policy first, then allowlisted tools, then audit."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from agent.adversarial import ADVERSARIAL_REQUESTS, chain_violation_request
from agent.audit import AuditLogger
from agent.lab_records import RECORDS_AFTER_ALICE_SHIPPED, RECORDS_PATH
from agent.policy import PolicyDecision, ToolPolicy
from agent.tools import LocalWorkspaceTools, SandboxExecTools, SandboxHttpTools, ToolError
from agent.trace import TraceLogger

BENIGN_PROMPT = """You are a workspace assistant. Complete this harmless task:
1. List files in the workspace with list_workspace.
2. Read /workspace/notes.txt with read_file, then write_file /workspace/summary.txt with a one-line summary of that file.
3. Read /workspace/numbers.txt with read_file (the file contains 1, 2, 3, 4, 5). Then run_local_python with argument code (never query):
   nums = [1, 2, 3, 4, 5]
   result = sum(nums)
   Do not call open(), import modules, or read files from Python.
   Do not pass SQL to run_local_python. Do not sum the sqlite qty column.
4. Call query_local_sqlite separately with argument query: SELECT name, qty FROM items
5. Read /workspace/records.txt with read_file. It is a synthetic pipe-delimited lab table, not production. Then write_file /workspace/records.txt with Alice Example's status changed from pending to shipped. Leave Bob and Carol unchanged.
Use only read_file, write_file, list_workspace, run_local_python, and query_local_sqlite.
Do not request network access, shells, environment variables, or files outside /workspace.
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
            {"tool": "read_file", "args": {"path": RECORDS_PATH}},
            {
                "tool": "write_file",
                "args": {
                    "path": RECORDS_PATH,
                    "content": RECORDS_AFTER_ALICE_SHIPPED,
                },
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


def ollama_has_model(installed: list[str], model: str) -> bool:
    wanted = model.strip()
    for name in installed:
        if name == wanted or name.startswith(wanted + "-") or name.startswith(wanted + "@"):
            return True
    return False


def format_ollama_http_error(status: int, body: str, host: str, model: str) -> str:
    detail = body.strip() or "(empty response)"
    hint = ""
    if status == 404:
        hint = (
            f"\nOllama returned 404. The usual cause is that '{model}' is not pulled.\n"
            f"  1. ollama serve\n"
            f"  2. ollama pull {model}\n"
            f"  3. ollama list\n"
            f"Then retry. API: {host}/api/chat"
        )
    return f"Ollama HTTP {status} from {host}/api/chat for model '{model}': {detail}{hint}"


def _coerce_tool_args(raw_args: Any, tool: str) -> dict[str, Any]:
    if raw_args is None or raw_args == "":
        return {}
    if isinstance(raw_args, str):
        try:
            parsed = json.loads(raw_args)
        except json.JSONDecodeError:
            stripped = raw_args.strip()
            if tool == "query_local_sqlite":
                return {"query": stripped}
            if tool == "run_local_python":
                return {"code": stripped}
            if tool == "read_file":
                return {"path": stripped}
            return {"value": stripped}
        raw_args = parsed
    if not isinstance(raw_args, dict):
        return {}
    return dict(raw_args)


# Extra tool_calls in one Ollama message may run without another API round
# only when they cannot depend on unread results (no speculative writes).
DRAINABLE_TOOLS = frozenset({"list_workspace", "read_file"})


def split_batch_tool_calls(
    calls: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Run the first call; drain extra reads; defer writes and compute."""
    first, *rest = calls
    pending = [item for item in rest if str(item.get("tool")) in DRAINABLE_TOOLS]
    deferred = [item for item in rest if str(item.get("tool")) not in DRAINABLE_TOOLS]
    return first, pending, deferred


def parse_ollama_tool_calls(message: dict[str, Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for raw in message.get("tool_calls") or []:
        function = raw.get("function") or {}
        name = function.get("name") or raw.get("name")
        args = (
            function.get("arguments")
            or function.get("parameters")
            or raw.get("arguments")
            or raw.get("parameters")
            or {}
        )
        if name:
            calls.append({"tool": name, "args": _coerce_tool_args(args, str(name))})
    return calls


OLLAMA_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_workspace",
            "description": "List files in the /workspace directory.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a UTF-8 text file under /workspace.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write a UTF-8 text file under /workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_local_python",
            "description": (
                "Run a short Python snippet. Argument is code, never query. "
                "Set result = .... Do not use open() or imports. "
                "Inline values from read_file, e.g. nums = [1, 2, 3, 4, 5]; result = sum(nums). "
                "SQL belongs on query_local_sqlite, not this tool."
            ),
            "parameters": {
                "type": "object",
                "properties": {"code": {"type": "string"}},
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_local_sqlite",
            "description": (
                "Run a SELECT on /workspace/local.db. Argument is query. "
                "Example: SELECT name, qty FROM items. Do not use run_local_python for SQL."
            ),
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
]


class OllamaBackend:
    def __init__(self, host: str, model: str) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self._checked = False
        self._sent_initial_prompt = False
        self._pending: list[dict[str, Any]] = []
        self._deferred: list[dict[str, Any]] = []
        self.last_turn: dict[str, Any] = {}
        self._messages = [
            {
                "role": "system",
                "content": (
                    "You use tools to complete a harmless workspace task. "
                    "Only use read_file, write_file, list_workspace, "
                    "run_local_python (argument: code), and query_local_sqlite "
                    "(argument: query). Do not pass SQL to run_local_python."
                ),
            },
            {"role": "user", "content": BENIGN_PROMPT},
        ]

    def _ensure_model(self) -> None:
        if self._checked:
            return
        try:
            with urllib.request.urlopen(f"{self.host}/api/tags", timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Cannot reach Ollama at {self.host}. Start it with `ollama serve`. ({exc})"
            ) from exc
        names = [str(item.get("name") or "") for item in (payload.get("models") or [])]
        if names and not ollama_has_model(names, self.model):
            available = ", ".join(names) or "(none)"
            raise RuntimeError(
                f"Ollama at {self.host} does not have model '{self.model}'. "
                f"Installed: {available}. Run: ollama pull {self.model}"
            )
        self._checked = True

    def next_tool(self, observation: str) -> dict[str, Any] | None:
        self._ensure_model()
        if self._pending:
            if observation:
                self._messages.append({"role": "tool", "content": observation})
            nxt = self._pending.pop(0)
            remaining = len(self._pending)
            self.last_turn = {
                "content": "",
                "tool_calls": [nxt],
                "queued": True,
                "queued_remaining": remaining,
            }
            return nxt
        if not self._sent_initial_prompt:
            self._sent_initial_prompt = True
        elif observation:
            self._messages.append({"role": "tool", "content": observation})
        self._flush_deferred()
        payload = json.dumps(
            {
                "model": self.model,
                "messages": self._messages,
                "stream": False,
                "tools": OLLAMA_TOOLS,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                format_ollama_http_error(exc.code, detail, self.host, self.model)
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Cannot reach Ollama at {self.host}. Start it with `ollama serve`. ({exc})"
            ) from exc
        message = body.get("message") or {}
        self._messages.append(message)
        calls = parse_ollama_tool_calls(message)
        if not calls:
            self.last_turn = {"content": message.get("content") or "", "tool_calls": []}
            return None
        first, pending, deferred = split_batch_tool_calls(calls)
        self._pending = pending
        self._deferred = deferred
        self.last_turn = {
            "content": message.get("content") or "",
            "tool_calls": calls,
            "queued": False,
            "batch_size": len(calls),
            "deferred": deferred,
        }
        return first

    def _flush_deferred(self) -> None:
        for item in self._deferred:
            self._messages.append(
                {
                    "role": "tool",
                    "content": json.dumps(
                        {
                            "tool": item.get("tool"),
                            "policy": "defer",
                            "reason": (
                                "batched write or compute was not executed; "
                                "issue it after reading prior tool results"
                            ),
                        }
                    ),
                }
            )
        self._deferred = []


class AgentHarness:
    def __init__(
        self,
        policy: ToolPolicy,
        tools: LocalWorkspaceTools | SandboxHttpTools | SandboxExecTools,
        audit: AuditLogger,
        backend: ModelBackend,
        sandbox_profile: str = "locked",
        trace: TraceLogger | None = None,
        backend_name: str = "",
    ) -> None:
        self.policy = policy
        self.tools = tools
        self.audit = audit
        self.backend = backend
        self.sandbox_profile = sandbox_profile
        self.trace = trace or TraceLogger()
        self.backend_name = backend_name

    def step(self, observation: str = "", index: int = 1) -> dict[str, Any] | None:
        request = self.backend.next_tool(observation)
        if request is None:
            return None
        tool = str(request.get("tool") or "")
        args = dict(request.get("args") or {})
        decision: PolicyDecision = self.policy.decide(tool, args)
        turn = getattr(self.backend, "last_turn", {}) or {}
        if not decision.allow:
            outcome = "denied"
            result: Any = None
            self.audit.record(
                decision,
                sandbox=self.sandbox_profile,
                result="denied",
                extra={"args": args, "python_code": args.get("code")},
            )
        else:
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
                extra={"args": args, "python_code": args.get("code")},
            )
        self.trace.record_step(
            index=index,
            observation=observation,
            tool=tool,
            args=args,
            decision=decision,
            result=result,
            outcome=outcome,
            model_text=str(turn.get("content") or ""),
            model_tool_calls=list(turn.get("tool_calls") or []),
            backend=self.backend_name or type(self.backend).__name__,
        )
        return {
            "tool": tool,
            "args": args,
            "decision": decision,
            "result": result,
            "outcome": outcome,
        }

    def run(self, max_steps: int = 12) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []
        observation = BENIGN_PROMPT
        for index in range(1, max_steps + 1):
            step = self.step(observation, index=index)
            if step is None:
                break
            steps.append(step)
            observation = json.dumps(
                {
                    "tool": step["tool"],
                    "policy": "allow" if step["decision"].allow else "deny",
                    "reason": step["decision"].reason,
                    "result": step["result"],
                },
                default=str,
            )
        self.trace.write()
        return steps


def build_harness(
    *,
    mode: str = "benign",
    backend_name: str | None = None,
    workspace: Path | None = None,
    sandbox_url: str | None = None,
    audit_path: Path | None = None,
    trace_dir: Path | None = None,
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
    if trace_dir is None and audit_path is not None:
        trace_dir = audit_path.parent
    trace = TraceLogger(trace_dir)
    return AgentHarness(
        policy,
        tools,
        audit,
        backend,
        sandbox_profile=profile,
        trace=trace,
        backend_name=backend_name,
    )
