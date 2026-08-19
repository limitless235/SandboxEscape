from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agent.demo import (
    _compose_up,
    isolation_restored_to_locked,
    main,
    prepare_isolated_workspace,
)
from agent.invariants import FAIL, PASS, SCORECARD_CONTROLS
from agent.lab_records import RECORDS_AFTER_ALICE_SHIPPED, RECORDS_SEED
from agent.runtime_checks import PROBE_FAILED, PROBE_REACHED, PROBE_UNREACHABLE
from tests.conftest import seed_workspace


def _card(*, leaky: bool = False, **overrides: str) -> dict[str, str]:
    card = {control: PASS for control in SCORECARD_CONTROLS}
    card["container_running"] = PASS
    if leaky:
        card["prod_net absent"] = FAIL
        card["DB TCP unreachable"] = FAIL
    card.update(overrides)
    return card


def test_prepare_isolated_workspace_resets_records(tmp_path: Path) -> None:
    src = seed_workspace(tmp_path / "src")
    (src / "records.txt").write_text(RECORDS_AFTER_ALICE_SHIPPED, encoding="utf-8")
    dest = prepare_isolated_workspace(src, tmp_path / "copy")
    assert dest != src
    assert (dest / "records.txt").read_text(encoding="utf-8") == RECORDS_SEED
    assert (src / "records.txt").read_text(encoding="utf-8") == RECORDS_AFTER_ALICE_SHIPPED


def test_prepare_rejects_overlapping_destination(tmp_path: Path) -> None:
    src = seed_workspace(tmp_path / "src")
    with pytest.raises(ValueError, match="overlap"):
        prepare_isolated_workspace(src, src)
    with pytest.raises(ValueError, match="overlap"):
        prepare_isolated_workspace(src, src / "nested")


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


def test_isolation_restored_to_locked_checks_health_and_probe(monkeypatch) -> None:
    monkeypatch.setattr("agent.demo.compose_services_healthy", lambda *_names: True)
    monkeypatch.setattr(
        "agent.demo.live_scorecard",
        lambda: _card(**{"prod_net absent": FAIL}),
    )
    monkeypatch.setattr(
        "agent.demo.sandbox_prod_db_tcp_status", lambda: PROBE_UNREACHABLE
    )
    assert isolation_restored_to_locked() is False

    monkeypatch.setattr(
        "agent.demo.live_scorecard",
        lambda: _card(),
    )
    monkeypatch.setattr("agent.demo.sandbox_prod_db_tcp_status", lambda: PROBE_REACHED)
    assert isolation_restored_to_locked() is False

    monkeypatch.setattr("agent.demo.sandbox_prod_db_tcp_status", lambda: PROBE_FAILED)
    assert isolation_restored_to_locked() is False

    monkeypatch.setattr("agent.demo.compose_services_healthy", lambda *_names: False)
    monkeypatch.setattr(
        "agent.demo.sandbox_prod_db_tcp_status", lambda: PROBE_UNREACHABLE
    )
    assert isolation_restored_to_locked() is False

    monkeypatch.setattr("agent.demo.compose_services_healthy", lambda *_names: True)
    monkeypatch.setattr(
        "agent.demo.live_scorecard",
        lambda: _card(container_running=FAIL),
    )
    assert isolation_restored_to_locked() is False

    monkeypatch.setattr(
        "agent.demo.live_scorecard",
        lambda: _card(),
    )
    monkeypatch.setattr(
        "agent.demo.sandbox_prod_db_tcp_status", lambda: PROBE_UNREACHABLE
    )
    assert isolation_restored_to_locked() is True


def test_compose_up_does_not_fallback_on_unhealthy_wait(monkeypatch) -> None:
    calls: list[tuple] = []

    def fake_compose(*args: str):
        calls.append(args)
        if "--wait" in args:
            return subprocess.CompletedProcess(
                args, 1, stdout="", stderr="container sandbox unhealthy"
            )
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr("agent.demo._compose", fake_compose)
    assert _compose_up("compose.yaml", force_recreate=True) == 1
    assert len(calls) == 1
    assert "--wait" in calls[0]


def test_compose_up_fallbacks_only_when_wait_unsupported(monkeypatch) -> None:
    calls: list[tuple] = []

    def fake_compose(*args: str):
        calls.append(args)
        if "--wait" in args:
            return subprocess.CompletedProcess(
                args, 1, stdout="", stderr="unknown flag: --wait"
            )
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr("agent.demo._compose", fake_compose)
    monkeypatch.setattr("agent.demo.compose_services_healthy", lambda *_names: True)
    assert _compose_up("compose.yaml") == 0
    assert any("--wait" not in args and "up" in args for args in calls)


def test_demo_live_restore_failure_does_not_claim_restored(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    src = seed_workspace(tmp_path / "ws")
    cards = iter(
        [
            _card(),
            _card(leaky=True),
        ]
    )
    monkeypatch.setattr("agent.demo.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("agent.demo.sandbox_is_running", lambda: True)
    monkeypatch.setattr("agent.demo.live_scorecard", lambda: next(cards))
    monkeypatch.setattr("agent.demo.render", lambda _card: "table\n")
    monkeypatch.setattr("agent.demo._compose_up", lambda *_files, **_kw: 0)
    monkeypatch.setattr("agent.demo.isolation_restored_to_locked", lambda: False)
    rc = main(["--live", "--workspace", str(src), "--out-dir", str(tmp_path / "audit")])
    captured = capsys.readouterr()
    assert rc == 1
    assert "stack restored to locked." not in captured.out
    assert "verification failed" in captured.err


def test_demo_live_recreates_locked_when_already_running(
    tmp_path: Path, monkeypatch
) -> None:
    src = seed_workspace(tmp_path / "ws")
    ups: list[tuple] = []
    cards = iter(
        [
            _card(),
            _card(leaky=True),
        ]
    )

    def fake_up(*files: str, force_recreate: bool = False) -> int:
        ups.append((files, force_recreate))
        return 0

    monkeypatch.setattr("agent.demo.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("agent.demo.sandbox_is_running", lambda: True)
    monkeypatch.setattr("agent.demo.live_scorecard", lambda: next(cards))
    monkeypatch.setattr("agent.demo.render", lambda _card: "table\n")
    monkeypatch.setattr("agent.demo._compose_up", fake_up)
    monkeypatch.setattr("agent.demo.isolation_restored_to_locked", lambda: True)
    rc = main(["--live", "--workspace", str(src), "--out-dir", str(tmp_path / "audit")])
    assert rc == 0
    assert ups[0] == (("compose.yaml",), True)


def test_demo_live_fails_when_leaky_still_missing_prod_net(
    tmp_path: Path, monkeypatch
) -> None:
    src = seed_workspace(tmp_path / "ws")
    cards = iter(
        [
            _card(),
            _card(),
        ]
    )
    monkeypatch.setattr("agent.demo.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("agent.demo.sandbox_is_running", lambda: True)
    monkeypatch.setattr("agent.demo.live_scorecard", lambda: next(cards))
    monkeypatch.setattr("agent.demo.render", lambda _card: "table\n")
    monkeypatch.setattr("agent.demo._compose_up", lambda *_files, **_kw: 0)
    monkeypatch.setattr("agent.demo.isolation_restored_to_locked", lambda: True)
    rc = main(["--live", "--workspace", str(src), "--out-dir", str(tmp_path / "audit")])
    assert rc == 1


def test_demo_live_fails_when_locked_control_is_down(
    tmp_path: Path, monkeypatch
) -> None:
    src = seed_workspace(tmp_path / "ws")
    monkeypatch.setattr("agent.demo.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("agent.demo.sandbox_is_running", lambda: True)
    monkeypatch.setattr(
        "agent.demo.live_scorecard",
        lambda: _card(**{"Read-only root FS": FAIL}),
    )
    monkeypatch.setattr("agent.demo.render", lambda _card: "table\n")
    monkeypatch.setattr("agent.demo._compose_up", lambda *_files, **_kw: 0)
    rc = main(["--live", "--workspace", str(src), "--out-dir", str(tmp_path / "audit")])
    assert rc == 1
