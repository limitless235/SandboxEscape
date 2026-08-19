from __future__ import annotations

from agent.explain import explain_step, monitoring_summary, run_briefing_markdown
from agent.policy import PolicyDecision
from agent.trace import TraceLogger


def test_explain_sqlite_is_not_postgres() -> None:
    text = explain_step(
        tool="query_local_sqlite",
        args={"query": "SELECT name, qty FROM items"},
        policy="allow",
        reason="tool is allowlisted",
        target="workspace-sqlite",
    )
    assert "not" in text.lower()
    assert "postgres" in text.lower() or "production" in text.lower()


def test_explain_records_file_is_synthetic() -> None:
    text = explain_step(
        tool="write_file",
        args={"path": "/workspace/records.txt", "content": "x"},
        policy="allow",
        reason="tool is allowlisted",
        target="/workspace/records.txt",
    )
    assert "synthetic" in text.lower()
    assert "workspace" in text.lower()


def test_explain_deny_is_containment() -> None:
    text = explain_step(
        tool="network_request",
        args={"url": "https://example.invalid/"},
        policy="deny",
        reason="destination outside sandbox network",
        target="https://example.invalid/",
    )
    assert "containment" in text.lower() or "blocked" in text.lower()
    assert "dummy" in text.lower() or "prod" in text.lower()


def test_trace_markdown_explains_planes(tmp_path) -> None:
    trace = TraceLogger(tmp_path)
    allow = PolicyDecision(
        True, "tool is allowlisted", "model-tool-policy", "list_workspace", "/workspace"
    )
    trace.record_step(
        index=1,
        observation="start",
        tool="list_workspace",
        args={},
        decision=allow,
        result=["notes.txt"],
        outcome="success",
        backend="scripted",
    )
    markdown = trace.render_markdown()
    assert "How to read this" in markdown
    assert "Production" in markdown
    assert "ALLOW" in markdown
    assert "What this means" in markdown
    summary = monitoring_summary(trace.steps)
    assert summary["allowed"] == 1
    assert summary["denied"] == 0
    assert "control" in run_briefing_markdown().lower()


def test_plane_for_postgres_path_is_prod() -> None:
    from agent.explain import PLANE_OUTSIDE, PLANE_PROD, PLANE_SANDBOX, plane_for

    assert (
        plane_for(
            "write_file",
            {"path": "/var/lib/postgresql/data/customers.txt"},
        )
        == PLANE_PROD
    )
    assert plane_for("read_file", {"path": "/etc/hostname"}) == PLANE_OUTSIDE
    assert plane_for("read_file", {"path": "/workspace/notes.txt"}) == PLANE_SANDBOX
    assert plane_for("list_workspace", {}) == PLANE_SANDBOX
