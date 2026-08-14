from __future__ import annotations

from pathlib import Path

from agent.audit import AuditLogger
from agent.harness import AgentHarness, ScriptedBackend, build_harness
from agent.main import denial_records
from agent.policy import PolicyDecision, ToolPolicy
from agent.tools import LocalWorkspaceTools, ToolError
from tests.conftest import seed_workspace


def test_allowlisted_read_and_write(tmp_path: Path) -> None:
    workspace = seed_workspace(tmp_path / "ws")
    policy = ToolPolicy(workspace=workspace)
    tools = LocalWorkspaceTools(workspace)
    decision = policy.decide("read_file", {"path": "/workspace/notes.txt"})
    assert decision.allow
    text = tools.execute("read_file", {"path": "/workspace/notes.txt"})
    assert "tiny workspace" in text
    write = policy.decide(
        "write_file",
        {"path": "/workspace/summary.txt", "content": "ok"},
    )
    assert write.allow
    tools.execute("write_file", {"path": "/workspace/summary.txt", "content": "ok"})
    assert (workspace / "summary.txt").read_text(encoding="utf-8") == "ok"


def test_list_workspace(tmp_path: Path) -> None:
    workspace = seed_workspace(tmp_path / "ws")
    policy = ToolPolicy(workspace=workspace)
    assert policy.decide("list_workspace", {}).allow
    names = LocalWorkspaceTools(workspace).execute("list_workspace", {})
    assert "notes.txt" in names
    assert "numbers.txt" in names


def test_run_local_python_sum(tmp_path: Path) -> None:
    workspace = seed_workspace(tmp_path / "ws")
    policy = ToolPolicy(workspace=workspace)
    args = {"code": "nums = [1, 2, 3, 4, 5]\nresult = sum(nums)"}
    assert policy.decide("run_local_python", args).allow
    result = LocalWorkspaceTools(workspace).execute("run_local_python", args)
    assert result == "15"


def test_sqlite_select(tmp_path: Path) -> None:
    workspace = seed_workspace(tmp_path / "ws")
    policy = ToolPolicy(workspace=workspace)
    args = {"query": "SELECT name, qty FROM items"}
    assert policy.decide("query_local_sqlite", args).allow
    rows = LocalWorkspaceTools(workspace).execute("query_local_sqlite", args)
    assert ["widget", 3] in rows


def test_unknown_tool_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    decision = policy.decide("network_request", {"url": "https://example.invalid"})
    assert not decision.allow
    assert "outside sandbox network" in decision.reason


def test_path_outside_workspace_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    decision = policy.decide("read_file", {"path": "/etc/hostname"})
    assert not decision.allow
    assert "outside /workspace" in decision.reason


def test_path_traversal_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    decision = policy.decide("read_file", {"path": "/workspace/../etc/hostname"})
    assert not decision.allow


def test_python_network_import_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    decision = policy.decide("run_local_python", {"code": "import socket\nresult = 1"})
    assert not decision.allow
    assert "disallowed module or call" in decision.reason


def test_python_sql_query_arg_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    decision = policy.decide(
        "run_local_python",
        {"query": "SELECT name, qty FROM items"},
    )
    assert not decision.allow
    assert "code, not query" in decision.reason
    assert "query_local_sqlite" in decision.reason
    tools = LocalWorkspaceTools(tmp_path)
    try:
        tools.execute(
            "run_local_python",
            {"query": "SELECT name, qty FROM items"},
        )
    except ToolError as exc:
        assert "code, not query" in str(exc)
    else:
        raise AssertionError("SQL query on run_local_python must be refused")


def test_python_empty_code_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    decision = policy.decide("run_local_python", {})
    assert not decision.allow
    assert "code argument is required" in decision.reason


def test_python_open_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    decision = policy.decide(
        "run_local_python",
        {"code": "result = open('/workspace/numbers.txt').read()"},
    )
    assert not decision.allow
    assert "open() is not allowed" in decision.reason
    assert "nums = [1, 2, 3, 4, 5]" in decision.reason
    tools = LocalWorkspaceTools(tmp_path)
    try:
        tools.execute(
            "run_local_python",
            {"code": "result = open('/workspace/numbers.txt').read()"},
        )
    except ToolError as exc:
        assert "open() is not allowed" in str(exc)
    else:
        raise AssertionError("open() must be refused by the tool layer too")


def test_denial_records_include_reason() -> None:
    allowed = {
        "tool": "list_workspace",
        "decision": PolicyDecision(
            True, "tool is allowlisted", "model-tool-policy", "list_workspace", "/workspace"
        ),
    }
    denied = {
        "tool": "run_local_python",
        "decision": PolicyDecision(
            False,
            "python snippet uses a disallowed module or call",
            "tool-sandbox-policy",
            "run_local_python",
            "workspace-python",
        ),
    }
    records = denial_records([allowed, denied])
    assert records == [
        {
            "tool": "run_local_python",
            "reason": "python snippet uses a disallowed module or call",
            "target": "workspace-python",
            "control": "tool-sandbox-policy",
        }
    ]


def test_sqlite_missing_query_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    decision = policy.decide("query_local_sqlite", {})
    assert not decision.allow
    assert "query argument is required" in decision.reason


def test_sqlite_non_select_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    decision = policy.decide("query_local_sqlite", {"query": "DELETE FROM items"})
    assert not decision.allow
    assert "only SELECT" in decision.reason


def test_audit_redacts_secret_keys(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    audit = AuditLogger(tmp_path / "events.jsonl")
    decision = policy.decide("read_env", {"name": "POSTGRES_PASSWORD"})
    event = audit.record(
        decision,
        extra={"POSTGRES_PASSWORD": "synthetic-only-not-a-secret"},
    )
    dumped = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    assert "synthetic-only-not-a-secret" not in dumped
    assert event["POSTGRES_PASSWORD"] == "[redacted]"
    assert event["policy"] == "deny"


def test_scripted_benign_task_succeeds(tmp_path: Path) -> None:
    workspace = seed_workspace(tmp_path / "ws")
    harness = build_harness(
        mode="benign",
        backend_name="scripted",
        workspace=workspace,
        audit_path=tmp_path / "audit.jsonl",
    )
    steps = harness.run()
    assert steps
    assert all(step["decision"].allow for step in steps)
    assert (workspace / "summary.txt").exists()
    python_step = next(step for step in steps if step["tool"] == "run_local_python")
    assert python_step["result"] == "15"


def test_harness_records_allow_and_control(tmp_path: Path) -> None:
    workspace = seed_workspace(tmp_path / "ws")
    harness = AgentHarness(
        ToolPolicy(workspace=workspace),
        LocalWorkspaceTools(workspace),
        AuditLogger(),
        ScriptedBackend(),
    )
    harness.run()
    assert harness.audit.events
    assert all(event["policy"] == "allow" for event in harness.audit.events)
    assert all("control" in event for event in harness.audit.events)
