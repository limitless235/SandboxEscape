#!/usr/bin/env python3
"""Allowlisted tool server that runs inside the hardened sandbox.

This process is not a security boundary by itself. The harness policy,
container hardening, and network segmentation are. The server only
implements the five approved tools and refuses everything else.
"""

from __future__ import annotations

import json
import os
import sqlite3
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WORKSPACE = Path("/workspace").resolve()
ALLOWED_TOOLS = frozenset(
    {
        "read_file",
        "write_file",
        "list_workspace",
        "run_local_python",
        "query_local_sqlite",
    }
)
SQLITE_PATH = WORKSPACE / "local.db"


def _workspace_path(raw: str) -> Path:
    if not raw:
        raise ValueError("path is required")
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = WORKSPACE / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(WORKSPACE)
    except ValueError as exc:
        raise ValueError("path is outside /workspace") from exc
    return resolved


def read_file(path: str) -> str:
    target = _workspace_path(path)
    if not target.is_file():
        raise FileNotFoundError(f"not a file: {target}")
    return target.read_text(encoding="utf-8")


def write_file(path: str, content: str) -> str:
    target = _workspace_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return str(target)


def list_workspace() -> list[str]:
    names = sorted(
        str(path.relative_to(WORKSPACE))
        for path in WORKSPACE.rglob("*")
        if path.is_file()
    )
    return names


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
)


def run_local_python(code: str) -> str:
    if not isinstance(code, str) or not code.strip():
        raise ValueError("code is required")
    lowered = code.lower()
    for marker in _PYTHON_DENY_MARKERS:
        if marker in lowered:
            raise ValueError("python snippet uses a disallowed module or call")
    namespace: dict[str, object] = {}
    exec(  # noqa: S102
        code,
        {
            "__builtins__": {
                "range": range,
                "len": len,
                "int": int,
                "str": str,
                "print": print,
                "sum": sum,
                "min": min,
                "max": max,
                "list": list,
                "float": float,
                "True": True,
                "False": False,
                "None": None,
            }
        },
        namespace,
    )
    result = namespace.get("result", namespace.get("out", ""))
    return "" if result is None else str(result)


def query_local_sqlite(query: str) -> list[list[object]]:
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query is required")
    stripped = query.strip().rstrip(";").strip()
    keyword = stripped.split(None, 1)[0].upper()
    if keyword != "SELECT":
        raise ValueError("only SELECT queries are allowed")
    upper = stripped.upper()
    for banned in ("ATTACH", "PRAGMA", "LOAD_EXTENSION", ";"):
        if banned in upper.replace(stripped, "") or (
            banned != ";" and banned in upper and keyword != "SELECT"
        ):
            raise ValueError("query uses a disallowed statement")
    if ";" in stripped:
        raise ValueError("multiple statements are not allowed")
    if "ATTACH" in upper or "PRAGMA" in upper or "LOAD_EXTENSION" in upper:
        raise ValueError("query uses a disallowed statement")
    if not SQLITE_PATH.is_file():
        raise FileNotFoundError("local sqlite database is missing")
    conn = sqlite3.connect(f"file:{SQLITE_PATH}?mode=ro", uri=True)
    try:
        cur = conn.execute(stripped)
        rows = cur.fetchall()
        return [list(row) for row in rows]
    finally:
        conn.close()


HANDLERS = {
    "read_file": lambda args: read_file(args.get("path", "")),
    "write_file": lambda args: write_file(args.get("path", ""), args.get("content", "")),
    "list_workspace": lambda args: list_workspace(),
    "run_local_python": lambda args: run_local_python(args.get("code", "")),
    "query_local_sqlite": lambda args: query_local_sqlite(args.get("query", "")),
}


class ToolHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, {"ok": True, "workspace": str(WORKSPACE)})
            return
        self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/tool":
            self._send(404, {"ok": False, "error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"ok": False, "error": "invalid json"})
            return
        tool = request.get("tool")
        args = request.get("args") or {}
        if tool not in ALLOWED_TOOLS:
            self._send(
                403,
                {
                    "ok": False,
                    "error": "tool is not granted",
                    "tool": tool,
                },
            )
            return
        try:
            result = HANDLERS[tool](args)
        except Exception as exc:  # noqa: BLE001
            self._send(
                400,
                {
                    "ok": False,
                    "error": str(exc),
                    "detail": traceback.format_exc(limit=1),
                },
            )
            return
        self._send(200, {"ok": True, "result": result})


def main() -> None:
    host = os.environ.get("SANDBOX_BIND", "0.0.0.0")
    port = int(os.environ.get("SANDBOX_PORT", "8080"))
    server = ThreadingHTTPServer((host, port), ToolHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
