from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

from agent.runtime_checks import (
    PROBE_FAILED,
    PROBE_REACHED,
    PROBE_UNREACHABLE,
    _tcp_probe,
    _tcp_status,
    compose_services_healthy,
)


def test_tcp_probe_uses_stdout_markers(monkeypatch) -> None:
    def fake_exec(script: str, timeout: float = 8.0):
        del script, timeout
        return subprocess.CompletedProcess(
            ["python"], 1, stdout="", stderr="container not running"
        )

    monkeypatch.setattr("agent.runtime_checks._exec", fake_exec)
    assert _tcp_probe("prod-db", 5432) == PROBE_FAILED

    monkeypatch.setattr(
        "agent.runtime_checks._exec",
        lambda script, timeout=8.0: subprocess.CompletedProcess(
            ["python"], 0, stdout="PROBE_UNREACHABLE\n", stderr=""
        ),
    )
    assert _tcp_probe("prod-db", 5432) == PROBE_UNREACHABLE

    monkeypatch.setattr(
        "agent.runtime_checks._exec",
        lambda script, timeout=8.0: subprocess.CompletedProcess(
            ["python"], 0, stdout="PROBE_REACHED\n", stderr=""
        ),
    )
    assert _tcp_probe("prod-db", 5432) == PROBE_REACHED


def test_compose_services_healthy_requires_health(monkeypatch) -> None:
    rows = [
        {"Service": "sandbox", "Health": "healthy", "State": "running"},
        {"Service": "prod-db", "Health": "starting", "State": "running"},
    ]
    stdout = "\n".join(json.dumps(row) for row in rows)

    def fake_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr("agent.runtime_checks.subprocess.run", fake_run)
    assert compose_services_healthy("sandbox", "prod-db") is False

    rows[1]["Health"] = "healthy"
    stdout = "\n".join(json.dumps(row) for row in rows)

    def fake_run_ok(*_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr("agent.runtime_checks.subprocess.run", fake_run_ok)
    assert compose_services_healthy("sandbox", "prod-db") is True


def test_tcp_status_does_not_hide_failed_direct_ip_probe(monkeypatch) -> None:
    statuses = iter([PROBE_UNREACHABLE, PROBE_FAILED])
    monkeypatch.setattr(
        "agent.runtime_checks._tcp_probe", lambda _host, _port: next(statuses)
    )
    monkeypatch.setattr(
        "agent.runtime_checks._service_ip", lambda _service: "172.20.0.2"
    )
    assert _tcp_status("prod-db", 5432) == PROBE_FAILED
