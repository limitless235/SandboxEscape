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
def test_sandbox_process_is_not_root() -> None:
    scorecard = live_scorecard()
    assert scorecard["Non-root execution"] == PASS


@skip_without_docker
def test_readonly_rootfs_and_no_new_privileges() -> None:
    scorecard = live_scorecard()
    assert scorecard["Read-only root FS"] == PASS
    assert scorecard["no-new-privileges"] == PASS
    assert scorecard["Dropped capabilities"] == PASS


@skip_without_docker
def test_docker_socket_and_host_fs_absent() -> None:
    scorecard = live_scorecard()
    assert scorecard["Docker socket absent"] == PASS
    assert scorecard["Host filesystem inaccessible"] == PASS


@skip_without_docker
def test_workspace_and_sqlite_available() -> None:
    scorecard = live_scorecard()
    assert scorecard["Sandbox-local SQLite"] == PASS
    assert scorecard["Workspace read/write"] == PASS
