from __future__ import annotations

import sqlite3
from pathlib import Path


def seed_workspace(workspace: Path) -> Path:
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "notes.txt").write_text(
        "A tiny workspace used by the benign agent task.\n",
        encoding="utf-8",
    )
    (workspace / "numbers.txt").write_text("1\n2\n3\n4\n5\n", encoding="utf-8")
    conn = sqlite3.connect(workspace / "local.db")
    conn.execute(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL, qty INTEGER NOT NULL)"
    )
    conn.executemany(
        "INSERT INTO items (name, qty) VALUES (?, ?)",
        [("widget", 3), ("gadget", 5), ("sprocket", 2)],
    )
    conn.commit()
    conn.close()
    return workspace
