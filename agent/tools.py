"""Allowlisted tool execution backends."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from agent.policy import ALLOWED_TOOLS, python_args_deny_reason, resolve_workspace_path


class ToolError(RuntimeError):
    pass


class LocalWorkspaceTools:
    """In-process workspace tools used by unit tests and the scripted backend."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace.resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._ensure_sqlite()

    def _ensure_sqlite(self) -> None:
        db = self.workspace / "local.db"
        if db.exists():
            return
        conn = sqlite3.connect(db)
        conn.execute(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL, qty INTEGER NOT NULL)"
        )
        conn.executemany(
            "INSERT INTO items (name, qty) VALUES (?, ?)",
            [("widget", 3), ("gadget", 5), ("sprocket", 2)],
        )
        conn.commit()
        conn.close()

    def _path(self, raw: str) -> Path:
        return resolve_workspace_path(raw, self.workspace)

    def execute(self, tool: str, args: dict[str, Any]) -> Any:
        if tool not in ALLOWED_TOOLS:
            raise ToolError("tool is not granted")
        handler = {
            "read_file": self.read_file,
            "write_file": self.write_file,
            "list_workspace": self.list_workspace,
            "run_local_python": self.run_local_python,
            "query_local_sqlite": self.query_local_sqlite,
        }[tool]
        return handler(args)

    def read_file(self, args: dict[str, Any]) -> str:
        target = self._path(str(args.get("path", "")))
        return target.read_text(encoding="utf-8")

    def write_file(self, args: dict[str, Any]) -> str:
        target = self._path(str(args.get("path", "")))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(args.get("content", "")), encoding="utf-8")
        return str(target)

    def list_workspace(self, args: dict[str, Any]) -> list[str]:
        del args
        return sorted(
            str(path.relative_to(self.workspace))
            for path in self.workspace.rglob("*")
            if path.is_file()
        )

    def run_local_python(self, args: dict[str, Any]) -> str:
        deny_reason = python_args_deny_reason(args)
        if deny_reason:
            raise ToolError(deny_reason)
        code = str(args.get("code", ""))
        namespace: dict[str, object] = {}
        exec(  # noqa: S102
            code,
            {
                "__builtins__": {
                    "range": range,
                    "len": len,
                    "int": int,
                    "str": str,
                    "sum": sum,
                    "min": min,
                    "max": max,
                    "list": list,
                    "float": float,
                }
            },
            namespace,
        )
        result = namespace.get("result", namespace.get("out", ""))
        return "" if result is None else str(result)

    def query_local_sqlite(self, args: dict[str, Any]) -> list[list[object]]:
        query = str(args.get("query", "")).strip()
        db = self.workspace / "local.db"
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            rows = conn.execute(query).fetchall()
            return [list(row) for row in rows]
        finally:
            conn.close()


class SandboxExecTools:
    """Invoke the sandbox tool API over loopback via docker compose exec."""

    def __init__(self, service: str = "sandbox", timeout: float = 15.0) -> None:
        self.service = service
        self.timeout = timeout

    def execute(self, tool: str, args: dict[str, Any]) -> Any:
        payload = json.dumps({"tool": tool, "args": args})
        script = (
            "import json,sys,urllib.request\n"
            f"payload={payload!r}\n"
            "req=urllib.request.Request('http://127.0.0.1:8080/tool',"
            " data=payload.encode(), headers={'Content-Type':'application/json'}, method='POST')\n"
            "try:\n"
            "    body=urllib.request.urlopen(req, timeout=5).read().decode()\n"
            "except Exception as exc:\n"
            "    sys.stderr.write(str(exc))\n"
            "    sys.exit(2)\n"
            "print(body)\n"
        )
        result = subprocess.run(
            ["docker", "compose", "exec", "-T", self.service, "python3", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        if result.returncode != 0:
            raise ToolError(result.stderr.strip() or result.stdout.strip() or "sandbox exec failed")
        try:
            body = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ToolError(result.stdout.strip() or "invalid sandbox response") from exc
        if not body.get("ok"):
            raise ToolError(str(body.get("error") or "sandbox rejected the tool"))
        return body.get("result")


class SandboxHttpTools:
    """Call the allowlisted tool server inside the sandbox container."""

    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def execute(self, tool: str, args: dict[str, Any]) -> Any:
        payload = json.dumps({"tool": tool, "args": args}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/tool",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ToolError(detail or str(exc)) from exc
        except urllib.error.URLError as exc:
            raise ToolError(f"sandbox unreachable: {exc}") from exc
        if not body.get("ok"):
            raise ToolError(str(body.get("error") or "sandbox rejected the tool"))
        return body.get("result")
