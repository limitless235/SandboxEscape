from __future__ import annotations

from agent.invariants import FAULTS, REPO_ROOT, apply_fault, evaluate_config, load_locked_config


def test_each_fault_is_detected_and_others_stay_mostly_green() -> None:
    locked = load_locked_config()
    baseline = evaluate_config(locked)
    baseline_fails = [name for name, status in baseline.items() if status != "PASS"]
    assert baseline_fails == [], baseline_fails

    for fault_id, meta in FAULTS.items():
        mutated = apply_fault(locked, fault_id)
        scorecard = evaluate_config(mutated)
        detector = meta["detector"]
        assert scorecard[detector] == "FAIL", f"{fault_id} should fail {detector}"
        for extra in meta.get("also") or []:
            assert scorecard[extra] == "FAIL", f"{fault_id} should also fail {extra}"
        overlay = REPO_ROOT / meta["overlay"]
        assert overlay.is_file(), overlay


def test_fault_overlays_change_one_documented_control() -> None:
    """Overlays exist so CI can distinguish insecure config from a broken app."""
    expected_snippets = {
        "attach_prod_net": "prod_net",
        "egress": "egress_net",
        "dns": "dns:",
        "no_new_privileges": "security_opt:",
        "cap_add": "NET_RAW",
        "writable_rootfs": "read_only: false",
        "host_mount": "/etc:/host-etc:ro",
        "publish_db": "15432:5432",
        "db_creds_env": "POSTGRES_PASSWORD",
        "broad_subprocess": "run_shell",
        "docker_socket": "docker.sock",
    }
    for fault_id, snippet in expected_snippets.items():
        overlay = REPO_ROOT / FAULTS[fault_id]["overlay"]
        text = overlay.read_text(encoding="utf-8")
        assert snippet in text, fault_id
