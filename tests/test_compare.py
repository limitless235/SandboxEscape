from __future__ import annotations

from pathlib import Path

from agent.compare import collect_profiles, render_compare, write_compare
from agent.demo import _run_agent
from tests.conftest import seed_workspace


def test_compare_table_shows_leaky_fail() -> None:
    text = render_compare(collect_profiles())
    assert "Locked vs leaky vs chained" in text
    assert "prod_net absent" in text
    assert "not an exploit demo" in text
    locked_line = [line for line in text.splitlines() if line.startswith("| prod_net absent")][0]
    assert "PASS" in locked_line
    assert "FAIL" in locked_line


def test_write_compare_and_demo_agents(tmp_path: Path) -> None:
    workspace = seed_workspace(tmp_path / "ws")
    chain = _run_agent("benign", workspace, tmp_path / "audit")
    path = write_compare(tmp_path / "compare.md", agent_chain=chain)
    text = path.read_text(encoding="utf-8")
    assert "Last agent chain" in text
    assert "list_workspace" in text
    assert "Alice Example|widget|shipped" in (workspace / "records.txt").read_text(
        encoding="utf-8"
    )
