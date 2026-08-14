"""Tool policy for the control-plane agent harness."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

ALLOWED_TOOLS = frozenset(
    {
        "read_file",
        "write_file",
        "list_workspace",
        "run_local_python",
        "query_local_sqlite",
    }
)

WORKSPACE_ROOT = Path("/workspace")

DENIED_TOOL_REASONS = {
    "network_request": "destination outside sandbox network",
    "run_shell": "unrestricted subprocess is not granted",
    "read_env": "environment access is not granted",
    "read_mount": "protected mounts are not granted",
    "docker_socket": "Docker daemon access is not granted",
}

_PYTHON_DENY_MARKERS = (
    "import socket",
    "import urllib",
    "import http",
    "import subprocess",
    "import ctypes",
    "from socket",
    "from urllib",
    "from http",
    "from subprocess",
    "os.system",
    "os.popen",
    "__import__",
    "open(",
)


@dataclass(frozen=True)
class PolicyDecision:
    allow: bool
    reason: str
    control: str
    tool: str
    target: str


def _target_of(tool: str, args: Mapping[str, Any]) -> str:
    if tool in {"read_file", "write_file"}:
        return str(args.get("path", ""))
    if tool == "run_local_python":
        return "workspace-python"
    if tool == "query_local_sqlite":
        return "workspace-sqlite"
    if tool == "list_workspace":
        return "/workspace"
    if tool == "network_request":
        return str(args.get("url") or args.get("host") or "protected-resource")
    if tool == "read_env":
        return str(args.get("name") or "environment")
    if tool == "read_mount":
        return str(args.get("path") or "protected-mount")
    if tool == "docker_socket":
        return "/var/run/docker.sock"
    if tool == "run_shell":
        return str(args.get("command") or "shell")
    return tool


def resolve_workspace_path(raw: str, workspace: Path = WORKSPACE_ROOT) -> Path:
    """Map virtual /workspace paths onto the real workspace directory."""
    if not raw or not str(raw).strip():
        raise ValueError("path is required")
    workspace = workspace.resolve()
    posix = str(raw).replace("\\", "/").strip()
    if posix == "/workspace" or posix.startswith("/workspace/"):
        rest = posix[len("/workspace") :].lstrip("/")
        candidate = workspace.joinpath(*rest.split("/")) if rest else workspace
    elif posix.startswith("/"):
        raise ValueError("path is outside /workspace")
    else:
        candidate = workspace / posix
    resolved = os_path_norm(candidate)
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("path is outside /workspace") from exc
    return resolved


def os_path_norm(candidate: Path) -> Path:
    """Normalize without requiring the path to exist on this host."""
    parts: list[str] = []
    for part in candidate.as_posix().split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return Path("/__outside__") / "workspace"
            parts.pop()
            continue
        parts.append(part)
    return Path("/") / Path(*parts) if parts else Path("/")


def _path_allowed(raw: str, workspace: Path) -> tuple[bool, str]:
    try:
        resolve_workspace_path(raw, workspace)
    except ValueError as exc:
        return False, str(exc)
    return True, "path is inside /workspace"


class ToolPolicy:
    def __init__(
        self,
        *,
        workspace: Path = WORKSPACE_ROOT,
        allow_unrestricted_subprocess: bool = False,
        extra_allowed_tools: frozenset[str] | None = None,
    ) -> None:
        self.workspace = workspace
        self.allow_unrestricted_subprocess = allow_unrestricted_subprocess
        allowed = set(ALLOWED_TOOLS)
        if extra_allowed_tools:
            allowed.update(extra_allowed_tools)
        if allow_unrestricted_subprocess:
            allowed.add("run_shell")
        self.allowed_tools = frozenset(allowed)

    def decide(self, tool: str, args: Mapping[str, Any] | None = None) -> PolicyDecision:
        args = args or {}
        target = _target_of(tool, args)

        if tool not in self.allowed_tools:
            reason = DENIED_TOOL_REASONS.get(tool, "tool is not granted")
            return PolicyDecision(
                allow=False,
                reason=reason,
                control="model-tool-policy",
                tool=tool,
                target=target,
            )

        if tool in {"read_file", "write_file"}:
            ok, reason = _path_allowed(str(args.get("path", "")), self.workspace)
            if not ok:
                return PolicyDecision(
                    allow=False,
                    reason=reason,
                    control="tool-sandbox-policy",
                    tool=tool,
                    target=target,
                )

        if tool == "run_local_python":
            code = str(args.get("code", "")).lower()
            for marker in _PYTHON_DENY_MARKERS:
                if marker in code:
                    return PolicyDecision(
                        allow=False,
                        reason="python snippet uses a disallowed module or call",
                        control="tool-sandbox-policy",
                        tool=tool,
                        target=target,
                    )

        if tool == "query_local_sqlite":
            query = str(args.get("query", "")).strip()
            upper = query.upper()
            if not query or upper.split(None, 1)[0] != "SELECT":
                return PolicyDecision(
                    allow=False,
                    reason="only SELECT queries are allowed",
                    control="tool-sandbox-policy",
                    tool=tool,
                    target=target,
                )
            if ";" in query.rstrip(";"):
                return PolicyDecision(
                    allow=False,
                    reason="multiple statements are not allowed",
                    control="tool-sandbox-policy",
                    tool=tool,
                    target=target,
                )
            if any(token in upper for token in ("ATTACH", "PRAGMA", "LOAD_EXTENSION")):
                return PolicyDecision(
                    allow=False,
                    reason="query uses a disallowed statement",
                    control="tool-sandbox-policy",
                    tool=tool,
                    target=target,
                )

        if tool == "run_shell" and not self.allow_unrestricted_subprocess:
            return PolicyDecision(
                allow=False,
                reason=DENIED_TOOL_REASONS["run_shell"],
                control="model-tool-policy",
                tool=tool,
                target=target,
            )

        return PolicyDecision(
            allow=True,
            reason="tool is allowlisted",
            control="model-tool-policy",
            tool=tool,
            target=target,
        )
