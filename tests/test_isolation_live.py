from __future__ import annotations

import shutil

import pytest

from agent.invariants import PASS
from agent.runtime_checks import live_scorecard, sandbox_cannot_connect_to, sandbox_is_running

pytestmark = pytest.mark.integration

skip_without_docker = pytest.mark.skipif(
    shutil.which("docker") is None or not sandbox_is_running(),
    reason="Docker sandbox stack is not running",
)


@skip_without_docker
def test_sandbox_cannot_connect_to_prod_db() -> None:
    assert sandbox_cannot_connect_to("prod-db", 5432)


@skip_without_docker
def test_sandbox_is_not_attached_to_prod_net() -> None:
    scorecard = live_scorecard()
    assert scorecard["prod_net absent"] == PASS
    assert scorecard["DB TCP unreachable"] == PASS


@skip_without_docker
def test_sandbox_cannot_reach_public_https_or_dns() -> None:
    scorecard = live_scorecard()
    assert scorecard["External HTTPS unavailable"] == PASS
    assert scorecard["External DNS unavailable"] == PASS
