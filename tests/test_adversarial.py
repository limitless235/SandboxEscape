from __future__ import annotations

from pathlib import Path

import pytest

from agent.adversarial import ADVERSARIAL_REQUESTS, chain_violation_request
from agent.harness import AdversarialBackend, build_harness
from agent.policy import ToolPolicy
from tests.conftest import seed_workspace

pytestmark = pytest.mark.adversarial


def test_each_adversarial_request_is_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    for request in ADVERSARIAL_REQUESTS:
        decision = policy.decide(request["tool"], request.get("args") or {})
        assert not decision.allow, request["id"]


def test_chained_permitted_tool_with_bad_path_is_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    request = chain_violation_request()
    decision = policy.decide(request["tool"], request["args"])
    assert not decision.allow


def test_repeat_denied_tool_stays_denied(tmp_path: Path) -> None:
    policy = ToolPolicy(workspace=tmp_path)
    first = policy.decide("network_request", {"url": "https://example.invalid/"})
    second = policy.decide("network_request", {"url": "https://example.invalid/again"})
    assert not first.allow
    assert not second.allow


def test_adversarial_harness_denies_every_step(tmp_path: Path) -> None:
    workspace = seed_workspace(tmp_path / "ws")
    harness = build_harness(
        mode="adversarial",
        workspace=workspace,
        audit_path=tmp_path / "audit.jsonl",
    )
    assert isinstance(harness.backend, AdversarialBackend)
    steps = harness.run(max_steps=20)
    assert steps
    assert all(not step["decision"].allow for step in steps)
    assert all(event["policy"] == "deny" for event in harness.audit.events)
    assert all(event.get("result") == "denied" for event in harness.audit.events)


def test_adversarial_mode_does_not_write_outside_workspace(tmp_path: Path) -> None:
    workspace = seed_workspace(tmp_path / "ws")
    before = {path.name for path in workspace.iterdir()}
    harness = build_harness(mode="adversarial", workspace=workspace)
    harness.run(max_steps=20)
    after = {path.name for path in workspace.iterdir()}
    assert after == before
