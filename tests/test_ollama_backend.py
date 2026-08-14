from agent.harness import format_ollama_http_error, ollama_has_model, parse_ollama_tool_calls


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
    assert "not found" in message.lower() or "qwen2.5:0.5b" in message


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
    assert calls[1]["tool"] == "read_file"
    assert calls[1]["args"]["path"] == "/workspace/notes.txt"


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
    assert "not found" in message.lower() or "qwen2.5:0.5b" in message
