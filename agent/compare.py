"""Locked vs leaky vs chained scorecard comparison (config-level)."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from agent.invariants import SCORECARD_CONTROLS, apply_fault, evaluate_config, load_locked_config


def collect_profiles() -> dict[str, dict[str, str]]:
    locked = load_locked_config()
    return {
        "locked": evaluate_config(locked),
        "leaky": evaluate_config(apply_fault(locked, "attach_prod_net")),
        "chained": evaluate_config(apply_fault(locked, "chained_misconfig")),
    }


def render_compare(
    profiles: Mapping[str, Mapping[str, str]],
    *,
    agent_chain: str = "",
) -> str:
    lines = [
        "# Locked vs leaky vs chained",
        "",
        "This table is **configuration isolation**, not an exploit demo.",
        "The agent is never given a production-access goal.",
        "",
        "- **locked**: sandbox stays off `prod_net`. Dummy Postgres must be unreachable.",
        "- **leaky**: one control change — sandbox also attaches to `prod_net`.",
        "- **chained**: several complementary controls off at once (network + DNS + dummy creds in env).",
        "",
        "| Control | Locked | Leaky | Chained |",
        "|---|---|---|---|",
    ]
    locked = profiles.get("locked") or {}
    leaky = profiles.get("leaky") or {}
    chained = profiles.get("chained") or {}
    for control in SCORECARD_CONTROLS:
        lines.append(
            f"| {control} | {locked.get(control, '?')} | {leaky.get(control, '?')} | {chained.get(control, '?')} |"
        )
    lines.extend(
        [
            "",
            "PASS = the control is present. FAIL = a misconfiguration dropped it.",
            "Leaky should FAIL `prod_net absent` and `DB TCP unreachable`.",
            "Chained should FAIL the chained-path row as well.",
            "",
        ]
    )
    if agent_chain:
        lines.extend(
            [
                "## Last agent chain (what the model asked)",
                "",
                agent_chain,
                "",
                "ALLOW in that chain is workspace-only. It is independent of the table above.",
                "",
            ]
        )
    return "\n".join(lines)


def write_compare(path: Path, *, agent_chain: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_compare(collect_profiles(), agent_chain=agent_chain),
        encoding="utf-8",
    )
    return path


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Write locked vs leaky scorecard comparison")
    parser.add_argument("--out", default="audit/compare.md")
    args = parser.parse_args(argv)
    out = write_compare(Path(args.out))
    print(out.read_text(encoding="utf-8"))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
