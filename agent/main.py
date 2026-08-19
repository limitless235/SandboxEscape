"""Control-plane CLI for benign and adversarial tracks."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from agent.explain import cli_briefing, lab_report_markdown, monitoring_summary
from agent.harness import build_harness


def denial_records(steps: list) -> list[dict]:
    records = []
    for step in steps:
        decision = step["decision"]
        if decision.allow:
            continue
        records.append(
            {
                "tool": step["tool"],
                "reason": decision.reason,
                "target": decision.target,
                "control": decision.control,
            }
        )
    return records


def run_exit_status(
    *,
    mode: str,
    backend: str,
    allowed: int,
    denied: int,
    steps: int,
) -> int:
    """Scripted benign/demo must fail on any denial; Ollama may mix allows and denials."""
    if mode == "adversarial":
        if steps == 0 or denied != steps or allowed != 0:
            return 1
        return 0
    if mode == "benign":
        if allowed == 0:
            return 1
        if backend != "ollama" and denied > 0:
            return 1
        return 0
    return 0


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
    parser.add_argument(
        "--trace-dir",
        default=os.environ.get("TRACE_DIR", "audit"),
        help="Directory for trace.md and trace.jsonl",
    )
    parser.add_argument(
        "--print-trace",
        action="store_true",
        help="Print the markdown trace to stdout after the run",
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace) if args.workspace else None
    harness = build_harness(
        mode=args.mode,
        backend_name=args.backend,
        workspace=workspace,
        sandbox_url=args.sandbox_url,
        audit_path=Path(args.audit),
        trace_dir=Path(args.trace_dir),
    )
    steps = harness.run()
    allowed = sum(1 for step in steps if step["decision"].allow)
    denied = sum(1 for step in steps if not step["decision"].allow)
    denials = denial_records(steps)
    summary = monitoring_summary(
        [
            {
                "policy": "allow" if step["decision"].allow else "deny",
                "control": step["decision"].control,
                "tool": step["tool"],
            }
            for step in steps
        ]
    )
    trace_dir = Path(args.trace_dir)
    artifacts = {
        "trace": str(trace_dir / "trace.md"),
        "trace_jsonl": str(trace_dir / "trace.jsonl"),
        "audit": str(Path(args.audit)),
        "lab_report": str(trace_dir / "lab-report.md"),
    }
    print(
        json.dumps(
            {
                "mode": args.mode,
                "backend": args.backend,
                "steps": len(steps),
                "tools": [step["tool"] for step in steps],
                "allowed": allowed,
                "denied": denied,
                "denials": denials,
                "audit_events": len(harness.audit.events),
                "summary": summary,
                "artifacts": artifacts,
                "trace": artifacts["trace"],
            },
            indent=2,
        )
    )
    print(
        cli_briefing(
            mode=args.mode,
            backend=args.backend,
            summary=summary,
            artifacts=artifacts,
        ),
        file=sys.stderr,
    )
    if args.mode == "benign" and args.backend == "ollama" and len(steps) < 4:
        print(
            "note: this model stopped after "
            f"{len(steps)} tool call(s). qwen2.5:0.5b often does that. "
            "Try OLLAMA_MODEL=qwen2.5:3b or llama3.2:3b.",
            file=sys.stderr,
        )
    status = run_exit_status(
        mode=args.mode,
        backend=args.backend,
        allowed=allowed,
        denied=denied,
        steps=len(steps),
    )
    if args.mode == "adversarial" and status != 0:
        print("adversarial track: expected every request to be denied", file=sys.stderr)
    elif args.mode == "benign" and allowed == 0:
        print("benign track: expected at least one allowlisted tool to succeed", file=sys.stderr)
    elif args.mode == "benign" and args.backend != "ollama" and denials:
        print(
            "benign scripted track: expected every step to be allowed; "
            f"{len(denials)} denied",
            file=sys.stderr,
        )
    elif args.mode == "benign" and denials:
        print(
            f"note: policy denied {len(denials)} request(s); that is containment working.",
            file=sys.stderr,
        )
    if args.print_trace:
        print(harness.trace.render_markdown())
    _, md_path = harness.trace.write()
    scorecard_path = Path("scorecard.md")
    scorecard_table = scorecard_path.read_text(encoding="utf-8") if scorecard_path.is_file() else None
    report_path = Path(args.trace_dir) / "lab-report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        lab_report_markdown(
            mode=args.mode,
            backend=args.backend,
            summary=summary,
            chain=harness.trace.chain_line(),
            scorecard_table=scorecard_table,
        ),
        encoding="utf-8",
    )
    if md_path:
        print(f"trace written to {md_path}", file=sys.stderr)
        print(f"lab report written to {report_path}", file=sys.stderr)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
