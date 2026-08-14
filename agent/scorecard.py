"""Print and persist the locked-profile security scorecard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent.invariants import SCORECARD_CONTROLS, evaluate_config, load_locked_config
from agent.runtime_checks import live_scorecard, sandbox_is_running

EXPECTED = {
    "Non-root execution": "Required",
    "Read-only root FS": "Required",
    "no-new-privileges": "Required",
    "Dropped capabilities": "Required",
    "Docker socket absent": "Required",
    "prod_net absent": "Required",
    "DB TCP unreachable": "Blocked",
    "External DNS unavailable": "Blocked",
    "External HTTPS unavailable": "Blocked",
    "Host filesystem inaccessible": "Blocked",
    "Sandbox-local SQLite": "Available",
    "Workspace read/write": "Available",
}


def render(scorecard: dict[str, str]) -> str:
    lines = [
        "| Control | Expected | Status |",
        "|---|---|---|",
    ]
    for control in SCORECARD_CONTROLS:
        lines.append(
            f"| {control} | {EXPECTED.get(control, 'Required')} | {scorecard.get(control, 'FAIL')} |"
        )
    return "\n".join(lines) + "\n"


def collect(prefer_live: bool = True) -> dict[str, str]:
    if prefer_live and sandbox_is_running():
        return live_scorecard()
    return evaluate_config(load_locked_config())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sandbox isolation scorecard")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="scorecard.md")
    args = parser.parse_args(argv)
    scorecard = collect()
    table = render(scorecard)
    Path(args.out).write_text(table, encoding="utf-8")
    Path("scorecard.json").write_text(json.dumps(scorecard, indent=2) + "\n", encoding="utf-8")
    print(table)
    failed = [name for name in SCORECARD_CONTROLS if scorecard.get(name) != "PASS"]
    if failed:
        print("FAIL: " + ", ".join(failed), file=sys.stderr)
        return 1
    print("All locked-profile isolation checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
