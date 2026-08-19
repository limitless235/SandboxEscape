from __future__ import annotations

from pathlib import Path

from agent.demo import isolation_restored_to_locked, main, prepare_isolated_workspace
from agent.invariants import FAIL, PASS
from agent.lab_records import RECORDS_AFTER_ALICE_SHIPPED, RECORDS_SEED
from tests.conftest import seed_workspace


def test_prepare_isolated_workspace_resets_records(tmp_path: Path) -> None:
    src = seed_workspace(tmp_path / "src")
    (src / "records.txt").write_text(RECORDS_AFTER_ALICE_SHIPPED, encoding="utf-8")
    dest = prepare_isolated_workspace(src, tmp_path / "copy")
    assert dest != src
    assert (dest / "records.txt").read_text(encoding="utf-8") == RECORDS_SEED
    assert (src / "records.txt").read_text(encoding="utf-8") == RECORDS_AFTER_ALICE_SHIPPED


def test_demo_does_not_dirty_source_workspace(tmp_path: Path, monkeypatch) -> None:
    src = seed_workspace(tmp_path / "ws")
    original = (src / "records.txt").read_text(encoding="utf-8")
    monkeypatch.setattr("agent.demo.shutil.which", lambda _name: None)
    rc = main(["--workspace", str(src), "--out-dir", str(tmp_path / "audit")])
    assert rc == 0
    assert (src / "records.txt").read_text(encoding="utf-8") == original
    demo_records = (tmp_path / "audit" / "demo-workspace" / "records.txt").read_text(
        encoding="utf-8"
    )
    assert "Alice Example|widget|shipped" in demo_records
    assert (tmp_path / "audit" / "lab-report.md").is_file()
    assert (tmp_path / "audit" / "compare.md").is_file()
    assert (tmp_path / "audit" / "benign" / "trace.md").is_file()
    assert (tmp_path / "audit" / "adversarial" / "trace.md").is_file()


def test_isolation_restored_to_locked_checks_prod_net(monkeypatch) -> None:
    monkeypatch.setattr(
        "agent.demo.live_scorecard", lambda: {"prod_net absent": FAIL}
    )
    monkeypatch.setattr("agent.demo.sandbox_reaches_prod_db", lambda: False)
    assert isolation_restored_to_locked() is False

    monkeypatch.setattr(
        "agent.demo.live_scorecard", lambda: {"prod_net absent": PASS}
    )
    monkeypatch.setattr("agent.demo.sandbox_reaches_prod_db", lambda: True)
    assert isolation_restored_to_locked() is False

    monkeypatch.setattr("agent.demo.sandbox_reaches_prod_db", lambda: False)
    assert isolation_restored_to_locked() is True


def test_demo_live_restore_failure_does_not_claim_restored(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    src = seed_workspace(tmp_path / "ws")
    monkeypatch.setattr("agent.demo.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("agent.demo.sandbox_is_running", lambda: True)
    monkeypatch.setattr(
        "agent.demo.collect", lambda: {"prod_net absent": PASS, "DB TCP unreachable": PASS}
    )
    monkeypatch.setattr("agent.demo.render", lambda _card: "table\n")
    monkeypatch.setattr("agent.demo._compose_up", lambda *_files, **_kw: 0)
    monkeypatch.setattr("agent.demo.isolation_restored_to_locked", lambda: False)
    rc = main(["--live", "--workspace", str(src), "--out-dir", str(tmp_path / "audit")])
    captured = capsys.readouterr()
    assert rc == 1
    assert "stack restored to locked." not in captured.out
    assert "verification failed" in captured.err
