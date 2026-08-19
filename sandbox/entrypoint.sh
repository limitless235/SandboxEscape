#!/bin/sh
set -eu

if [ ! -f /workspace/notes.txt ]; then
  cp -a /opt/sandbox/workspace-seed/. /workspace/
fi

if [ ! -f /workspace/records.txt ]; then
  cp /opt/sandbox/workspace-seed/records.txt /workspace/records.txt
fi

if [ ! -f /workspace/local.db ]; then
  python3 - <<'PY'
import sqlite3
from pathlib import Path

db = Path("/workspace/local.db")
conn = sqlite3.connect(db)
conn.execute(
    "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL, qty INTEGER NOT NULL)"
)
conn.executemany(
    "INSERT INTO items (name, qty) VALUES (?, ?)",
    [("widget", 3), ("gadget", 5), ("sprocket", 2)],
)
conn.commit()
conn.close()
PY
fi

exec python3 /opt/sandbox/sandbox_server.py
