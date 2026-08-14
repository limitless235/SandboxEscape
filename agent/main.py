"""Control-plane CLI for benign and adversarial tracks."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from agent.harness import build_harness


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Defensive sandbox agent harness")
    parser.add_argument(
        "--mode",
        choices=("benign", "adversarial"),
        default="benign",
    )
    parser.add_argument("--backend", default=os.environ.get("AGENT_BACKEND", "scripted"))
    parser.add_argument("--workspace", default=os.environ.get("WORKSPACE"))
    parser.add_argument("--sandbox-url", default=os.environ.get("SANDBOX_URL"))
    parser.add_argument(
        "--audit",
        default=os.environ.get("AUDIT_LOG", "audit/events.jsonl"),
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace) if args.workspace else None
    harness = build_harness(
        mode=args.mode,
        backend_name=args.backend,
        workspace=workspace,
        sandbox_url=args.sandbox_url,
        audit_path=Path(args.audit),
    )
    steps = harness.run()
    allowed = sum(1 for step in steps if step["decision"].allow)
    denied = sum(1 for step in steps if not step["decision"].allow)
    print(
        json.dumps(
            {
                "mode": args.mode,
                "steps": len(steps),
                "tools": [step["tool"] for step in steps],
                "allowed": allowed,
                "denied": denied,
                "audit_events": len(harness.audit.events),
            },
            indent=2,
        )
    )
    if args.mode == "benign" and args.backend == "ollama" and len(steps) < 4:
        print(
            "note: this model stopped after "
            f"{len(steps)} tool call(s). qwen2.5:0.5b often does that. "
            "Try OLLAMA_MODEL=qwen2.5:3b or llama3.2:3b.",
            file=sys.stderr,
        )
    if args.mode == "adversarial":
        if denied != len(steps) or allowed != 0:
            print("adversarial track: expected every request to be denied", file=sys.stderr)
            return 1
    elif args.mode == "benign":
        errors = sum(1 for step in steps if step["decision"].allow and step.get("result") in (None, ""))
        failed = [step for step in steps if not step["decision"].allow]
        if failed or allowed == 0:
            print("benign track: expected allowlisted tools to succeed", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
