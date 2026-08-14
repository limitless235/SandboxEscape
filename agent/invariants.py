"""Locked-profile invariants and one-control fault-injection detectors."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

PASS = "PASS"
FAIL = "FAIL"

SCORECARD_CONTROLS = (
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
)


def load_locked_config(path: Path | None = None) -> dict[str, Any]:
    from agent.yaml_util import load_yaml

    return load_yaml(path or REPO_ROOT / "configs" / "locked.yaml")


def evaluate_config(config: dict[str, Any]) -> dict[str, str]:
    sandbox = config.get("sandbox") or {}
    prod = config.get("prod_db") or {}
    agent = config.get("agent") or {}
    networks = set(sandbox.get("networks") or [])
    env = sandbox.get("environment") or {}
    mounts = sandbox.get("host_mounts") or []
    volumes = sandbox.get("volumes") or []
    volume_text = " ".join(str(item) for item in [*mounts, *volumes])
    dns = sandbox.get("dns")
    cap_add = sandbox.get("cap_add") or []
    published_db = prod.get("published_ports") or []
    subprocess_open = bool(agent.get("allow_unrestricted_subprocess"))
    secret_env = any(
        key.upper() in {"POSTGRES_PASSWORD", "PROD_DB_HOST", "PROD_DB_PASSWORD"}
        for key in env
    )
    docker_socket = bool(sandbox.get("docker_socket")) or "docker.sock" in volume_text
    host_fs = bool(mounts) or "/etc" in volume_text or "/host" in volume_text
    prod_net = "prod_net" in networks
    non_internal = bool(sandbox.get("egress")) or "egress_net" in networks
    dns_open = dns in (None, [], ["8.8.8.8"]) or sandbox.get("external_dns") is True
    if non_internal:
        dns_open = True

    user = str(sandbox.get("user") or "")
    non_root = user not in {"", "0", "0:0", "root"}

    sqlite_ok = not subprocess_open
    workspace_ok = True

    return {
        "Non-root execution": PASS if non_root else FAIL,
        "Read-only root FS": PASS if sandbox.get("read_only") else FAIL,
        "no-new-privileges": PASS
        if "no-new-privileges:true" in (sandbox.get("security_opt") or [])
        else FAIL,
        "Dropped capabilities": PASS
        if sandbox.get("cap_drop") == ["ALL"] and not cap_add
        else FAIL,
        "Docker socket absent": PASS if not docker_socket else FAIL,
        "prod_net absent": PASS if not prod_net else FAIL,
        "DB TCP unreachable": PASS if not prod_net else FAIL,
        "External DNS unavailable": PASS if not dns_open else FAIL,
        "External HTTPS unavailable": PASS if not non_internal else FAIL,
        "Host filesystem inaccessible": PASS if not host_fs else FAIL,
        "Sandbox-local SQLite": PASS if sqlite_ok else FAIL,
        "Workspace read/write": PASS if workspace_ok else FAIL,
        "DB port unpublished": PASS if not published_db else FAIL,
        "Secrets absent from sandbox env": PASS if not secret_env else FAIL,
        "Tool policy least privilege": PASS if not subprocess_open else FAIL,
    }


def isolation_check_fails_when(fault_id: str, config: dict[str, Any] | None = None) -> bool:
    mutated = apply_fault(config or load_locked_config(), fault_id)
    scorecard = evaluate_config(mutated)
    detector = FAULTS[fault_id]["detector"]
    return scorecard[detector] == FAIL


FAULTS: dict[str, dict[str, Any]] = {
    "attach_prod_net": {
        "overlay": "compose.leaky.yaml",
        "detector": "prod_net absent",
        "also": ["DB TCP unreachable"],
    },
    "egress": {
        "overlay": "compose.faults/egress.yaml",
        "detector": "External HTTPS unavailable",
        "also": ["External DNS unavailable"],
    },
    "dns": {
        "overlay": "compose.faults/dns.yaml",
        "detector": "External DNS unavailable",
    },
    "no_new_privileges": {
        "overlay": "compose.faults/no-new-privileges.yaml",
        "detector": "no-new-privileges",
    },
    "cap_add": {
        "overlay": "compose.faults/cap-add.yaml",
        "detector": "Dropped capabilities",
    },
    "writable_rootfs": {
        "overlay": "compose.faults/writable-rootfs.yaml",
        "detector": "Read-only root FS",
    },
    "host_mount": {
        "overlay": "compose.faults/host-mount.yaml",
        "detector": "Host filesystem inaccessible",
    },
    "publish_db": {
        "overlay": "compose.faults/publish-db.yaml",
        "detector": "DB port unpublished",
    },
    "db_creds_env": {
        "overlay": "compose.faults/db-creds-env.yaml",
        "detector": "Secrets absent from sandbox env",
    },
    "broad_subprocess": {
        "overlay": "compose.faults/broad-subprocess.yaml",
        "detector": "Tool policy least privilege",
    },
    "docker_socket": {
        "overlay": "compose.faults/docker-socket.yaml",
        "detector": "Docker socket absent",
    },
}


def apply_fault(config: dict[str, Any], fault_id: str) -> dict[str, Any]:
    if fault_id not in FAULTS:
        raise KeyError(fault_id)
    mutated = deepcopy(config)
    sandbox = mutated.setdefault("sandbox", {})
    prod = mutated.setdefault("prod_db", {})
    agent = mutated.setdefault("agent", {})

    if fault_id == "attach_prod_net":
        networks = list(sandbox.get("networks") or [])
        if "prod_net" not in networks:
            networks.append("prod_net")
        sandbox["networks"] = networks
    elif fault_id == "egress":
        networks = list(sandbox.get("networks") or [])
        if "egress_net" not in networks:
            networks.append("egress_net")
        sandbox["networks"] = networks
        sandbox["egress"] = True
    elif fault_id == "dns":
        sandbox["dns"] = []
        sandbox["external_dns"] = True
    elif fault_id == "no_new_privileges":
        sandbox["security_opt"] = []
    elif fault_id == "cap_add":
        sandbox["cap_add"] = ["NET_RAW"]
    elif fault_id == "writable_rootfs":
        sandbox["read_only"] = False
    elif fault_id == "host_mount":
        sandbox["host_mounts"] = ["/etc:/host-etc:ro"]
        sandbox["volumes"] = ["sandbox-workspace:/workspace", "/etc:/host-etc:ro"]
    elif fault_id == "publish_db":
        prod["published_ports"] = ["127.0.0.1:15432:5432"]
    elif fault_id == "db_creds_env":
        env = dict(sandbox.get("environment") or {})
        env["POSTGRES_PASSWORD"] = "synthetic-only-not-a-secret"
        env["PROD_DB_HOST"] = "prod-db"
        sandbox["environment"] = env
    elif fault_id == "broad_subprocess":
        agent["allow_unrestricted_subprocess"] = True
        tools = list(agent.get("allowed_tools") or [])
        if "run_shell" not in tools:
            tools.append("run_shell")
        agent["allowed_tools"] = tools
    elif fault_id == "docker_socket":
        sandbox["docker_socket"] = True
        sandbox["volumes"] = [
            "sandbox-workspace:/workspace",
            "/var/run/docker.sock:/var/run/docker.sock",
        ]
    return mutated
