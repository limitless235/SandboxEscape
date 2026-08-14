from __future__ import annotations

from pathlib import Path

from agent.invariants import (
    FAULTS,
    REPO_ROOT,
    apply_fault,
    evaluate_config,
    isolation_check_fails_when,
    load_locked_config,
)


def test_locked_config_cannot_reach_prod_db() -> None:
    scorecard = evaluate_config(load_locked_config())
    assert scorecard["prod_net absent"] == "PASS"
    assert scorecard["DB TCP unreachable"] == "PASS"


def test_locked_invariants_all_pass() -> None:
    scorecard = evaluate_config(load_locked_config())
    required = [
        "Non-root execution",
        "Read-only root FS",
        "no-new-privileges",
        "Dropped capabilities",
        "Docker socket absent",
        "prod_net absent",
        "DB TCP unreachable",
        "External DNS unavailable",
        "External HTTPS unavailable",
        "Host filesystem inaccessible",
        "Sandbox-local SQLite",
        "Workspace read/write",
        "Chained misconfiguration path",
    ]
    failed = [name for name in required if scorecard[name] != "PASS"]
    assert failed == []


def test_isolation_check_fails_when_sandbox_attached_to_prod_net() -> None:
    assert isolation_check_fails_when("attach_prod_net")


def test_leaky_overlay_file_attaches_prod_net() -> None:
    text = (REPO_ROOT / "compose.leaky.yaml").read_text(encoding="utf-8")
    assert "prod_net" in text
    assert "sandbox" in text
