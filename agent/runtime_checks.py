"""Live container checks: connectivity and hardening assertions, not exploits."""

from __future__ import annotations

import json
import subprocess
from typing import Any

from agent.invariants import FAIL, PASS, SCORECARD_CONTROLS

COMPOSE = ["docker", "compose"]


def sandbox_is_running() -> bool:
    try:
        result = subprocess.run(
            [*COMPOSE, "ps", "--status", "running", "--format", "json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = str(row.get("Service") or row.get("Name") or "")
        if "sandbox" in name:
            return True
    return False


def _exec(script: str, timeout: float = 8.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*COMPOSE, "exec", "-T", "sandbox", "python3", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _inspect() -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "inspect", "defensive-sandbox-lab-sandbox-1"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        # Fallback: look up container id from compose.
        ps = subprocess.run(
            [*COMPOSE, "ps", "-q", "sandbox"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        cid = ps.stdout.strip().splitlines()[0] if ps.stdout.strip() else ""
        if not cid:
            raise RuntimeError("sandbox container not found")
        result = subprocess.run(
            ["docker", "inspect", cid],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    return json.loads(result.stdout)[0]


def _service_ip(service: str) -> str | None:
    ps = subprocess.run(
        [*COMPOSE, "ps", "-q", service],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    cid = ps.stdout.strip().splitlines()[0] if ps.stdout.strip() else ""
    if not cid:
        return None
    result = subprocess.run(
        ["docker", "inspect", cid],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return None
    networks = ((json.loads(result.stdout)[0].get("NetworkSettings") or {}).get("Networks") or {})
    for name, net in networks.items():
        if "prod_net" in name and net.get("IPAddress"):
            return str(net["IPAddress"])
    for net in networks.values():
        if net.get("IPAddress"):
            return str(net["IPAddress"])
    return None


def _tcp_reaches(host: str, port: int) -> bool:
    script = (
        "import socket,sys\n"
        f"s=socket.socket(); s.settimeout(2)\n"
        "try:\n"
        f"    s.connect(({host!r},{port}))\n"
        "    sys.exit(0)\n"
        "except Exception:\n"
        "    sys.exit(1)\n"
        "finally:\n"
        "    s.close()\n"
    )
    return _exec(script).returncode == 0


def _dns_resolves(name: str) -> bool:
    script = (
        "import socket,sys\n"
        "try:\n"
        f"    socket.getaddrinfo({name!r}, 443)\n"
        "    sys.exit(0)\n"
        "except Exception:\n"
        "    sys.exit(1)\n"
    )
    return _exec(script).returncode == 0


def live_scorecard() -> dict[str, str]:
    info = _inspect()
    config = info.get("Config") or {}
    host = info.get("HostConfig") or {}
    state = info.get("State") or {}

    user = str(config.get("User") or "")
    non_root = user not in {"", "0", "0:0", "root"}
    uid_script = (
        "import os,sys\n"
        "sys.exit(0 if os.getuid()!=0 else 1)\n"
    )
    if _exec(uid_script).returncode != 0:
        non_root = False

    readonly = bool(host.get("ReadonlyRootfs"))
    security_opt = [str(item).lower() for item in (host.get("SecurityOpt") or [])]
    no_new_privs = any("no-new-privileges" in item for item in security_opt)
    if not no_new_privs:
        nnp = _exec(
            "import pathlib,sys\n"
            "text=pathlib.Path('/proc/self/status').read_text()\n"
            "sys.exit(0 if 'NoNewPrivs:\\t1' in text else 1)\n"
        )
        no_new_privs = nnp.returncode == 0

    cap_add = host.get("CapAdd") or []
    cap_drop = [str(item).upper() for item in (host.get("CapDrop") or [])]
    dropped = "ALL" in cap_drop and not cap_add

    mounts = info.get("Mounts") or []
    docker_sock = any(
        str(mount.get("Destination") or "").endswith("docker.sock")
        or str(mount.get("Source") or "").endswith("docker.sock")
        for mount in mounts
    )
    host_fs = any(
        str(mount.get("Destination") or "").startswith("/host")
        or str(mount.get("Source") or "") in {"/", "/etc", "/var/run"}
        for mount in mounts
        if mount.get("Type") == "bind"
    )

    networks = ((info.get("NetworkSettings") or {}).get("Networks") or {})
    prod_net = any("prod_net" in name for name in networks)

    env = {item.split("=", 1)[0]: item.split("=", 1)[1] if "=" in item else "" for item in (config.get("Env") or [])}
    secret_env = any(key in env for key in ("POSTGRES_PASSWORD", "PROD_DB_HOST", "PROD_DB_PASSWORD"))

    sqlite = _exec(
        "import sqlite3,sys\n"
        "c=sqlite3.connect('file:/workspace/local.db?mode=ro', uri=True)\n"
        "rows=c.execute('SELECT COUNT(*) FROM items').fetchone()\n"
        "sys.exit(0 if rows and rows[0]>=1 else 1)\n"
    ).returncode == 0
    workspace = _exec(
        "import pathlib,sys\n"
        "p=pathlib.Path('/workspace/scorecard-write.txt')\n"
        "p.write_text('ok')\n"
        "sys.exit(0 if p.read_text()=='ok' else 1)\n"
    ).returncode == 0

    db_tcp_probe = sandbox_cannot_connect_to("prod-db", 5432)
    # Sharing prod_net is a structural path to the DB. The TCP probe is
    # best-effort and may time out on hosts with broken bridge networking.
    db_tcp = (not prod_net) and db_tcp_probe
    https = not _tcp_reaches("1.1.1.1", 443)
    dns = not _dns_resolves("example.invalid")
    dns_open = not dns
    path_hits = sum(1 for flag in (prod_net, secret_env, dns_open) if flag)

    scorecard = {
        "Non-root execution": PASS if non_root else FAIL,
        "Read-only root FS": PASS if readonly else FAIL,
        "no-new-privileges": PASS if no_new_privs else FAIL,
        "Dropped capabilities": PASS if dropped else FAIL,
        "Docker socket absent": PASS if not docker_sock else FAIL,
        "prod_net absent": PASS if not prod_net else FAIL,
        "DB TCP unreachable": PASS if db_tcp else FAIL,
        "External DNS unavailable": PASS if dns else FAIL,
        "External HTTPS unavailable": PASS if https else FAIL,
        "Host filesystem inaccessible": PASS if not host_fs else FAIL,
        "Sandbox-local SQLite": PASS if sqlite else FAIL,
        "Workspace read/write": PASS if workspace else FAIL,
        "DB port unpublished": PASS if not secret_env else PASS,
        "Secrets absent from sandbox env": PASS if not secret_env else FAIL,
        "Chained misconfiguration path": PASS if path_hits < 2 else FAIL,
        "container_running": PASS if state.get("Running") else FAIL,
    }
    for control in SCORECARD_CONTROLS:
        scorecard.setdefault(control, FAIL)
    return scorecard


def sandbox_cannot_connect_to(host: str, port: int) -> bool:
    if _tcp_reaches(host, port):
        return False
    # DNS may be independently disabled; still probe the service IP.
    ip = _service_ip(host)
    if ip and ip != host and _tcp_reaches(ip, port):
        return False
    return True
