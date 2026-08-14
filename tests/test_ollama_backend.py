from __future__ import annotations

import json

from agent.harness import (
    OllamaBackend,
    format_ollama_http_error,
    ollama_has_model,
    parse_ollama_tool_calls,
)


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_ollama_has_model_exact_and_prefix() -> None:
    names = ["qwen2.5:0.5b", "llama3.2:3b"]
    assert ollama_has_model(names, "qwen2.5:0.5b")
    assert ollama_has_model(names, "llama3.2:3b")
    assert not ollama_has_model(names, "mistral:7b")


def test_format_404_tells_user_to_pull_model() -> None:
    message = format_ollama_http_error(
        404,
        '{"error":"model \'qwen2.5:0.5b\' not found"}',
        "http://127.0.0.1:11434",
        "qwen2.5:0.5b",
    )
    assert "404" in message
    assert "ollama pull qwen2.5:0.5b" in message


def test_parse_ollama_tool_calls_dict_and_string_args() -> None:
    message = {
        "tool_calls": [
            {"function": {"name": "list_workspace", "arguments": {}}},
            {
                "function": {
                    "name": "read_file",
                    "arguments": '{"path": "/workspace/notes.txt"}',
                }
            },
        ]
    }
    calls = parse_ollama_tool_calls(message)
    assert calls[0] == {"tool": "list_workspace", "args": {}}
    assert calls[1]["args"]["path"] == "/workspace/notes.txt"


def test_parse_ollama_sqlite_bare_sql_string() -> None:
    message = {
        "tool_calls": [
            {
                "function": {
                    "name": "query_local_sqlite",
                    "arguments": "SELECT name, qty FROM items",
                }
            }
        ]
    }
    calls = parse_ollama_tool_calls(message)
    assert calls[0]["args"]["query"] == "SELECT name, qty FROM items"


def test_parse_ollama_top_level_name() -> None:
    message = {
        "tool_calls": [
            {"name": "query_local_sqlite", "arguments": {"query": "SELECT 1"}}
        ]
    }
    calls = parse_ollama_tool_calls(message)
    assert calls[0] == {"tool": "query_local_sqlite", "args": {"query": "SELECT 1"}}


def test_ollama_drains_batched_tool_calls(monkeypatch) -> None:
    chat_calls = {"count": 0}

    def fake_urlopen(req, timeout=None):
        url = req if isinstance(req, str) else req.full_url
        if str(url).endswith("/api/tags"):
            return _FakeResponse({"models": [{"name": "qwen2.5:3b"}]})
        chat_calls["count"] += 1
        return _FakeResponse(
            {
                "message": {
                    "role": "assistant",
                    "content": "planning",
                    "tool_calls": [
                        {"function": {"name": "list_workspace", "arguments": {}}},
                        {
                            "function": {
                                "name": "read_file",
                                "arguments": {"path": "/workspace/notes.txt"},
                            }
                        },
                    ],
                }
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    backend = OllamaBackend("http://127.0.0.1:11434", "qwen2.5:3b")
    first = backend.next_tool("")
    assert first == {"tool": "list_workspace", "args": {}}
    assert chat_calls["count"] == 1
    assert backend.last_turn["batch_size"] == 2
    second = backend.next_tool('{"tool":"list_workspace","policy":"allow"}')
    assert second["tool"] == "read_file"
    assert second["args"]["path"] == "/workspace/notes.txt"
    assert backend.last_turn["queued"] is True
    assert chat_calls["count"] == 1
