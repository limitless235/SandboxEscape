from __future__ import annotations

from pathlib import Path

from agent.policy import PolicyDecision
from agent.trace import TraceLogger


def test_trace_includes_python_and_chain(tmp_path: Path) -> None:
    trace = TraceLogger(tmp_path)
    allow = PolicyDecision(True, "tool is allowlisted", "model-tool-policy", "read_file", "/workspace/notes.txt")
    deny = PolicyDecision(
        False,
        "python snippet uses a disallowed module or call",
        "tool-sandbox-policy",
        "run_local_python",
        "workspace-python",
    )
    trace.record_step(
        index=1,
        observation="start",
        tool="read_file",
        args={"path": "/workspace/notes.txt"},
        decision=allow,
        result="hello",
        outcome="success",
        model_text="I will read notes.txt",
        backend="ollama",
    )
    trace.record_step(
        index=2,
        observation='{"tool": "read_file", "result": "hello"}',
        tool="run_local_python",
        args={"code": "result = open('/workspace/numbers.txt').read()"},
        decision=deny,
        result=None,
        outcome="denied",
        model_text="I will sum the numbers",
        backend="ollama",
    )
    markdown = trace.render_markdown()
    assert "1.read_file → 2.run_local_python [DENIED]" in markdown
    assert "open('/workspace/numbers.txt')" in markdown
    assert "Chained from `read_file`" in markdown
    assert "I will read notes.txt" in markdown
    jsonl_path, md_path = trace.write()
    assert jsonl_path is not None and jsonl_path.is_file()
    assert md_path is not None and "DENIED" in md_path.read_text(encoding="utf-8")


def test_trace_redacts_secret_keys(tmp_path: Path) -> None:
    trace = TraceLogger(tmp_path)
    decision = PolicyDecision(False, "environment access is not granted", "model-tool-policy", "read_env", "POSTGRES_PASSWORD")
    event = trace.record_step(
        index=1,
        observation="",
        tool="read_env",
        args={"POSTGRES_PASSWORD": "synthetic-only-not-a-secret"},
        decision=decision,
        result=None,
        outcome="denied",
    )
    assert event["args"]["POSTGRES_PASSWORD"] == "[redacted]"
