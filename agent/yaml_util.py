"""Minimal YAML loader for lab config files (no extra runtime dependency)."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def load_yaml(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        return _simple_yaml(text)


def _simple_yaml(text: str) -> Any:
    """Parse the subset of YAML used by configs/*.yaml."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        pass
    # Prefer PyYAML when tests installed it; otherwise a tiny indent parser.
    return _indent_parse(text)


def _indent_parse(text: str) -> Any:
    lines = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))
    value, _ = _parse_block(lines, 0, 0)
    return value


def _parse_value(token: str) -> Any:
    if token in {"true", "True"}:
        return True
    if token in {"false", "False"}:
        return False
    if token in {"null", "None", "~", ""}:
        return None
    if token.startswith('"') and token.endswith('"'):
        return token[1:-1]
    if token.startswith("'") and token.endswith("'"):
        return token[1:-1]
    if token.isdigit() or (token.startswith("-") and token[1:].isdigit()):
        return int(token)
    return token


def _parse_block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    mapping: dict[str, Any] = {}
    sequence: list[Any] | None = None
    while index < len(lines):
        current_indent, content = lines[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise ValueError(f"unexpected indent at {content}")
        if content.startswith("- "):
            if sequence is None:
                sequence = []
            item = content[2:].strip()
            if item and ":" in item and not item.startswith("{"):
                # nested single-line not used
                sequence.append(_parse_value(item))
                index += 1
                continue
            if item:
                sequence.append(_parse_value(item))
                index += 1
                continue
            child, index = _parse_block(lines, index + 1, indent + 2)
            sequence.append(child)
            continue
        key, sep, rest = content.partition(":")
        key = key.strip()
        rest = rest.strip()
        index += 1
        if rest:
            mapping[key] = _parse_value(rest)
            continue
        if index < len(lines) and lines[index][0] > current_indent:
            child, index = _parse_block(lines, index, lines[index][0])
            mapping[key] = child
        else:
            mapping[key] = {}
    if sequence is not None and not mapping:
        return sequence, index
    if sequence is not None:
        raise ValueError("mixed sequence and mapping")
    return mapping, index
