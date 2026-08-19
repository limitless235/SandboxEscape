"""End-to-end lab walkthrough: agents + locked/leaky compare."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from agent.compare import write_compare
from agent.harness import build_harness
from agent.runtime_checks import sandbox_is_running
from agent.scorecard import collect, render, scorecard_preamble

REPO = Path(__file__).resolve().parent.parent


def _run_agent(mode: str, workspace: Path, trace_dir: Path) -> str:
    harness = build_harness(
        mode=mode,
        backend_name="scripted",
        workspace=workspace,
        audit_path=trace_dir / f"events-{mode}.jsonl",
        trace_dir=trace_dir / mode,
    )
    steps = harness.run()
    return harness.trace.chain_line() if steps else "(no steps)"


def _compose(*args: str) -> int:
    return subprocess.run(["docker", "compose", *args], cwd=REPO, check=False).returncode


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
    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    print("=== 10-minute path (no Docker required) ===")
    print("1. Unit tests: make test-unit")
    print("2. Scripted benign + adversarial agents")
    print("3. Config compare: locked vs leaky vs chained → audit/compare.md")
    print()

    benign_chain = _run_agent("benign", workspace, out_dir)
    print(f"benign chain: {benign_chain}")
    adv_chain = _run_agent("adversarial", workspace, out_dir)
    print(f"adversarial chain: {adv_chain}")

    compare_path = write_compare(out_dir / "compare.md", agent_chain=benign_chain)
    print(f"wrote {compare_path}")

    docker = shutil.which("docker") is not None
    live = sandbox_is_running()
    print()
    print("=== full isolation path (Docker Desktop) ===")
    if not docker:
        print("docker not on PATH — skip live scorecard. Install Docker Desktop, then:")
        print("  make locked-up && make test-isolation && make scorecard && make demo-full")
        return 0

    if live or args.live:
        if not live:
            print("starting locked stack…")
            if _compose("-f", "compose.yaml", "up", "--build", "-d") != 0:
                print("compose up failed", file=sys.stderr)
                return 1
        scorecard = collect()
        (out_dir / "scorecard-locked.md").write_text(
            scorecard_preamble() + render(scorecard), encoding="utf-8"
        )
        print("locked live scorecard:")
        print(render(scorecard))
    else:
        print("sandbox container not running. Start it with: make locked-up")
        print("Then: make test-isolation && make scorecard")

    if args.live:
        print("applying leaky overlay (sandbox on prod_net)…")
        _compose("-f", "compose.yaml", "-f", "compose.leaky.yaml", "up", "-d")
        try:
            leaky = collect()
            (out_dir / "scorecard-leaky.md").write_text(
                scorecard_preamble() + render(leaky), encoding="utf-8"
            )
            print("leaky live scorecard (expect FAIL on prod_net / DB TCP):")
            print(render(leaky))
        finally:
            print("restoring locked profile…")
            _compose("-f", "compose.yaml", "up", "-d")
        print("stack restored to locked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
