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


def test_parse_keeps_sql_query_on_python_tool() -> None:
    message = {
        "tool_calls": [
            {
                "function": {
                    "name": "run_local_python",
                    "arguments": {"query": "SELECT name, qty FROM items"},
                }
            }
        ]
    }
    calls = parse_ollama_tool_calls(message)
    assert calls[0]["tool"] == "run_local_python"
    assert calls[0]["args"]["query"] == "SELECT name, qty FROM items"
    assert "code" not in calls[0]["args"]


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


def test_split_batch_drains_leading_reads_only() -> None:
    from agent.harness import split_batch_tool_calls

    calls = [
        {"tool": "list_workspace", "args": {}},
        {"tool": "read_file", "args": {"path": "/workspace/notes.txt"}},
        {"tool": "write_file", "args": {"path": "/workspace/summary.txt", "content": "placeholder"}},
        {"tool": "run_local_python", "args": {"code": "result = 1"}},
        {"tool": "read_file", "args": {"path": "/workspace/numbers.txt"}},
    ]
    split = split_batch_tool_calls(calls)
    assert split.first["tool"] == "list_workspace"
    assert [item["tool"] for item in split.pending] == ["read_file"]
    assert split.leading_deferred == []
    assert [item["tool"] for item in split.trailing_deferred] == [
        "write_file",
        "run_local_python",
        "read_file",
    ]
    assert split.trailing_deferred[-1]["args"]["path"] == "/workspace/numbers.txt"


def test_split_batch_skips_leading_writes_to_first_read() -> None:
    from agent.harness import split_batch_tool_calls

    calls = [
        {"tool": "write_file", "args": {"path": "/workspace/summary.txt", "content": "x"}},
        {"tool": "run_local_python", "args": {"code": "result = 1"}},
        {"tool": "read_file", "args": {"path": "/workspace/notes.txt"}},
        {"tool": "read_file", "args": {"path": "/workspace/numbers.txt"}},
    ]
    split = split_batch_tool_calls(calls)
    assert split.first["tool"] == "read_file"
    assert split.first["args"]["path"] == "/workspace/notes.txt"
    assert [item["tool"] for item in split.pending] == ["read_file"]
    assert [item["tool"] for item in split.leading_deferred] == ["write_file", "run_local_python"]
    assert split.trailing_deferred == []
    assert split.skipped_leading_writes is True


def test_split_batch_second_pass_keeps_write_order() -> None:
    from agent.harness import split_batch_tool_calls

    calls = [
        {"tool": "write_file", "args": {"path": "/workspace/summary.txt", "content": "x"}},
        {"tool": "read_file", "args": {"path": "/workspace/notes.txt"}},
    ]
    split = split_batch_tool_calls(calls, skip_leading_writes=False)
    assert split.first["tool"] == "write_file"
    assert [item["tool"] for item in split.pending] == ["read_file"]
    assert split.skipped_leading_writes is False


def test_next_tool_does_not_return_batched_extra_write(monkeypatch) -> None:
    def fake_urlopen(req, timeout=None):
        url = req if isinstance(req, str) else req.full_url
        if str(url).endswith("/api/tags"):
            return _FakeResponse({"models": [{"name": "qwen2.5:3b"}]})
        return _FakeResponse(
            {
                "message": {
                    "role": "assistant",
                    "content": "planning",
                    "tool_calls": [
                        {"function": {"name": "list_workspace", "arguments": {}}},
                        {
                            "function": {
                                "name": "write_file",
                                "arguments": {
                                    "path": "/workspace/summary.txt",
                                    "content": "nope",
                                },
                            }
                        },
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
    drained = []
    while backend._pending:
        drained.append(backend.next_tool("ok"))
    assert drained == []
    assert all(item["tool"] != "write_file" for item in [first, *drained])
    assert [item["tool"] for item in backend._deferred] == ["write_file", "read_file"]


def test_next_tool_writes_first_starts_at_read(monkeypatch) -> None:
    def fake_urlopen(req, timeout=None):
        url = req if isinstance(req, str) else req.full_url
        if str(url).endswith("/api/tags"):
            return _FakeResponse({"models": [{"name": "qwen2.5:3b"}]})
        return _FakeResponse(
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "write_file",
                                "arguments": {
                                    "path": "/workspace/summary.txt",
                                    "content": "nope",
                                },
                            }
                        },
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
    assert first["tool"] == "read_file"
    assert not backend._pending
    assert backend._deferred == []
    tool_msgs = [msg for msg in backend._messages if msg.get("role") == "tool"]
    assert tool_msgs
    assert tool_msgs[0].get("tool_name") == "write_file"
    assert "defer" in tool_msgs[0]["content"]


def _mixed_write_read_payload() -> dict:
    return {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call_write",
                    "function": {
                        "name": "write_file",
                        "arguments": {
                            "path": "/workspace/summary.txt",
                            "content": "nope",
                        },
                    },
                },
                {
                    "id": "call_read",
                    "function": {
                        "name": "read_file",
                        "arguments": {"path": "/workspace/notes.txt"},
                    },
                },
            ],
        }
    }


def test_repeated_mixed_batch_does_not_starve_write(monkeypatch) -> None:
    chat_calls = {"count": 0}

    def fake_urlopen(req, timeout=None):
        url = req if isinstance(req, str) else req.full_url
        if str(url).endswith("/api/tags"):
            return _FakeResponse({"models": [{"name": "qwen2.5:3b"}]})
        chat_calls["count"] += 1
        return _FakeResponse(_mixed_write_read_payload())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    backend = OllamaBackend("http://127.0.0.1:11434", "qwen2.5:3b")
    first = backend.next_tool("")
    assert first["tool"] == "read_file"
    assert first.get("id") == "call_read"
    second = backend.next_tool('{"tool":"read_file","policy":"allow"}')
    assert second["tool"] == "write_file"
    assert second.get("id") == "call_write"
    assert chat_calls["count"] == 2
    read_result = [
        msg
        for msg in backend._messages
        if msg.get("role") == "tool" and msg.get("tool_call_id") == "call_read"
    ]
    assert read_result
    write_defer = [
        msg
        for msg in backend._messages
        if msg.get("role") == "tool" and msg.get("tool_call_id") == "call_write"
    ]
    assert write_defer
    assert backend._messages.index(write_defer[0]) < backend._messages.index(read_result[0])
