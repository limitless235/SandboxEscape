from __future__ import annotations

from agent.invariants import SCORECARD_CONTROLS, evaluate_config, load_locked_config
from agent.scorecard import render


def test_scorecard_table_includes_required_controls() -> None:
    scorecard = evaluate_config(load_locked_config())
    table = render(scorecard)
    for control in SCORECARD_CONTROLS:
        assert control in table
        assert "PASS" in table
    assert table.startswith("| Control | Expected | Status |")


def test_scorecard_preamble_explains_pass_fail() -> None:
    from agent.explain import scorecard_preamble

    text = scorecard_preamble()
    assert "PASS" in text
    assert "FAIL" in text
    assert "trace" in text.lower()
