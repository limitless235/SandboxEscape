from __future__ import annotations

from agent.invariants import apply_fault, evaluate_config, isolation_check_fails_when, load_locked_config


def test_single_fault_does_not_count_as_chained_path() -> None:
    locked = load_locked_config()
    for fault_id in ("attach_prod_net", "dns", "db_creds_env"):
        scorecard = evaluate_config(apply_fault(locked, fault_id))
        assert scorecard["Chained misconfiguration path"] == "PASS", fault_id


def test_chained_misconfig_fails_multiple_complementary_controls() -> None:
    assert isolation_check_fails_when("chained_misconfig")
    scorecard = evaluate_config(apply_fault(load_locked_config(), "chained_misconfig"))
    assert scorecard["prod_net absent"] == "FAIL"
    assert scorecard["DB TCP unreachable"] == "FAIL"
    assert scorecard["External DNS unavailable"] == "FAIL"
    assert scorecard["Secrets absent from sandbox env"] == "FAIL"
    assert scorecard["Chained misconfiguration path"] == "FAIL"


def test_locked_profile_has_no_chained_path() -> None:
    scorecard = evaluate_config(load_locked_config())
    assert scorecard["Chained misconfiguration path"] == "PASS"
