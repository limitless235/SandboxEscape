"""End-to-end lab walkthrough: agents + locked/leaky compare."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

from agent.compare import write_compare
from agent.explain import lab_report_markdown, monitoring_summary
from agent.harness import build_harness
from agent.invariants import FAIL, PASS, SCORECARD_CONTROLS
from agent.lab_records import RECORDS_SEED
from agent.main import run_exit_status
from agent.runtime_checks import (
    PROBE_UNREACHABLE,
    compose_services_healthy,
    live_scorecard,
    sandbox_is_running,
    sandbox_prod_db_tcp_status,
)
from agent.scorecard import collect, render, scorecard_preamble

REPO = Path(__file__).resolve().parent.parent


def _run_agent(mode: str, workspace: Path, trace_dir: Path) -> tuple[str, list]:
    harness = build_harness(
        mode=mode,
        backend_name="scripted",
        workspace=workspace,
        audit_path=trace_dir / f"events-{mode}.jsonl",
        trace_dir=trace_dir / mode,
    )
    steps = harness.run()
    chain = harness.trace.chain_line() if steps else "(no steps)"
    return chain, steps


def _compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=REPO,
        check=False,
        capture_output=True,
        text=True,
    )


def _wait_flag_unsupported(text: str) -> bool:
    lower = text.lower()
    if "unknown flag" in lower or "unknown shorthand flag" in lower:
        return True
    return "--wait" in lower and ("undefined" in lower or "not a valid" in lower)


def _paths_overlap(left: Path, right: Path) -> bool:
    left = left.resolve()
    right = right.resolve()
    if left == right:
        return True
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _compose_up(*compose_files: str, force_recreate: bool = False) -> int:
    flags: list[str] = []
    for name in compose_files:
        flags.extend(["-f", name])
    extra = ["--force-recreate"] if force_recreate else []
    waited = _compose(*flags, "up", "-d", *extra, "--wait", "--wait-timeout", "120")
    if waited.returncode == 0:
        return 0
    err = f"{waited.stderr or ''}{waited.stdout or ''}"
    if not _wait_flag_unsupported(err):
        return waited.returncode or 1
    fallback = _compose(*flags, "up", "-d", *extra)
    if fallback.returncode != 0:
        return fallback.returncode
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if compose_services_healthy("sandbox", "prod-db"):
            return 0
        time.sleep(2)
    return 1


def isolation_restored_to_locked() -> bool:
    if not compose_services_healthy("sandbox", "prod-db"):
        return False
    try:
        card = live_scorecard()
    except Exception:
        return False
    if not locked_scorecard_passes(card):
        return False
    return sandbox_prod_db_tcp_status() == PROBE_UNREACHABLE


def locked_scorecard_passes(card: dict[str, str]) -> bool:
    return card.get("container_running") == PASS and all(
        card.get(control) == PASS for control in SCORECARD_CONTROLS
    )


def leaky_scorecard_matches(card: dict[str, str]) -> bool:
    expected_failures = {"prod_net absent", "DB TCP unreachable"}
    return card.get("container_running") == PASS and all(
        card.get(control) == (FAIL if control in expected_failures else PASS)
        for control in SCORECARD_CONTROLS
    )


def prepare_isolated_workspace(src: Path, dest: Path) -> Path:
    src = src.expanduser().resolve()
    dest = dest.expanduser().resolve()
    if not src.is_dir():
        raise ValueError(f"workspace source is not a directory: {src}")
    if _paths_overlap(src, dest):
        raise ValueError(
            "demo workspace destination must not overlap the source "
            f"({src} vs {dest})"
        )
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dest)
    (dest / "records.txt").write_text(RECORDS_SEED, encoding="utf-8")
    return dest


def _step_status(mode: str, steps: list) -> int:
    allowed = sum(1 for step in steps if step["decision"].allow)
    denied = sum(1 for step in steps if not step["decision"].allow)
    return run_exit_status(
        mode=mode,
        backend="scripted",
        allowed=allowed,
        denied=denied,
        steps=len(steps),
    )


def _write_scorecard(path: Path, scorecard: dict[str, str]) -> None:
    path.write_text(scorecard_preamble() + render(scorecard), encoding="utf-8")


def _restore_locked() -> bool:
    if _compose_up("compose.yaml", force_recreate=True) != 0:
        return False
    return isolation_restored_to_locked()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the containment lab walkthrough")
    parser.add_argument(
        "--live",
        action="store_true",
        help="If Docker is available: locked scorecard, leaky overlay, then restore locked",
    )
    parser.add_argument("--workspace", default=str(REPO / "sandbox" / "workspace"))
    parser.add_argument("--out-dir", default="audit")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    source = Path(args.workspace)
    workspace = prepare_isolated_workspace(source, out_dir / "demo-workspace")

    print("=== 10-minute path (no Docker required) ===")
    print("1. Unit tests: make test-unit")
    print("2. Scripted benign + adversarial agents (copy under audit/demo-workspace)")
    print("3. Config compare: locked vs leaky vs chained → audit/compare.md")
    print()

    benign_chain, benign_steps = _run_agent("benign", workspace, out_dir)
    print(f"benign chain: {benign_chain}")
    print(f"benign trace: {out_dir / 'benign' / 'trace.md'}")
    adv_chain, adv_steps = _run_agent("adversarial", workspace, out_dir)
    print(f"adversarial chain: {adv_chain}")
    print(f"adversarial trace: {out_dir / 'adversarial' / 'trace.md'}")

    status = 0
    if _step_status("benign", benign_steps) != 0:
        print("benign walkthrough: expected every scripted step to be allowed", file=sys.stderr)
        status = 1
    if _step_status("adversarial", adv_steps) != 0:
        print("adversarial walkthrough: expected every request to be denied", file=sys.stderr)
        status = 1

    compare_path = write_compare(out_dir / "compare.md", agent_chain=benign_chain)
    print(f"wrote {compare_path}")

    summary = monitoring_summary(
        [
            {
                "policy": "allow" if step["decision"].allow else "deny",
                "control": step["decision"].control,
                "tool": step["tool"],
            }
            for step in benign_steps
        ]
    )
    scorecard_path = Path("scorecard.md")
    scorecard_table = scorecard_path.read_text(encoding="utf-8") if scorecard_path.is_file() else None
    report_path = out_dir / "lab-report.md"
    report_path.write_text(
        lab_report_markdown(
            mode="benign",
            backend="scripted",
            summary=summary,
            chain=benign_chain,
            scorecard_table=scorecard_table,
        ),
        encoding="utf-8",
    )
    print(f"wrote {report_path}")

    docker = shutil.which("docker") is not None
    live = sandbox_is_running()
    print()
    print("=== full isolation path (Docker Desktop) ===")
    if not docker:
        print("docker not on PATH — skip live scorecard. Install Docker Desktop, then:")
        print("  make locked-up && make test-isolation && make scorecard && make demo-full")
        return status

    if args.live:
        print("starting locked stack…")
        if _compose_up("compose.yaml", force_recreate=True) != 0:
            print("compose up failed", file=sys.stderr)
            return 1
        try:
            locked = live_scorecard()
        except Exception as exc:
            print(f"locked live scorecard failed: {exc}", file=sys.stderr)
            return 1
        _write_scorecard(out_dir / "scorecard-locked.md", locked)
        print("locked live scorecard:")
        print(render(locked))
        if not locked_scorecard_passes(locked):
            print("locked baseline has failing isolation controls", file=sys.stderr)
            return 1

        print("applying leaky overlay (sandbox on prod_net)…")
        if _compose_up("compose.yaml", "compose.leaky.yaml") != 0:
            print("leaky overlay failed", file=sys.stderr)
            print("attempting locked restore…", file=sys.stderr)
            if _restore_locked():
                print("stack restored to locked.")
            else:
                print("locked restore did not verify", file=sys.stderr)
            return 1
        try:
            leaky = live_scorecard()
        except Exception as exc:
            print(f"leaky scorecard failed: {exc}", file=sys.stderr)
            print("attempting locked restore…", file=sys.stderr)
            if _restore_locked():
                print("stack restored to locked.")
            else:
                print("locked restore did not verify", file=sys.stderr)
            return 1
        _write_scorecard(out_dir / "scorecard-leaky.md", leaky)
        print("leaky live scorecard (expect FAIL on prod_net / DB TCP):")
        print(render(leaky))
        if not leaky_scorecard_matches(leaky):
            print("leaky overlay did not produce the expected two-control failure", file=sys.stderr)
            status = 1

        print("restoring locked profile…")
        if not _restore_locked():
            print(
                "locked restore verification failed "
                "(unhealthy stack, prod_net still present, or TCP probe did not confirm isolation)",
                file=sys.stderr,
            )
            return 1
        print("stack restored to locked.")
        return status

    if live:
        scorecard = collect()
        _write_scorecard(out_dir / "scorecard-locked.md", scorecard)
        print("locked live scorecard:")
        print(render(scorecard))
    else:
        print("sandbox container not running. Start it with: make locked-up")
        print("Then: make test-isolation && make scorecard")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
