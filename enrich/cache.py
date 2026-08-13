"""Local SQLite cache for enrichment API calls, so re-running the pipeline
repeatedly during the hackathon (dashboard reloads, demo rehearsals) doesn't
re-hit rate-limited APIs or repeatedly spawn `searchsploit`.
"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Callable

from common.paths import cache_db_path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    source TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    PRIMARY KEY (source, key)
)
"""


def _connect() -> sqlite3.Connection:
    path = cache_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(_SCHEMA)
    return conn


def get_or_fetch(source: str, key: str, fetch_fn: Callable[[], object], ttl_days: float) -> object:
    """Returns the cached value for (source, key) if fresher than ttl_days, else
    calls fetch_fn(), caches the result (including None — a confirmed miss is
    still worth not re-fetching), and returns it."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT value, fetched_at FROM cache WHERE source=? AND key=?", (source, key)
        ).fetchone()
        if row is not None:
            value, fetched_at = row
            if time.time() - fetched_at < ttl_days * 86400:
                return json.loads(value)

        result = fetch_fn()
        conn.execute(
            "INSERT OR REPLACE INTO cache (source, key, value, fetched_at) VALUES (?, ?, ?, ?)",
            (source, key, json.dumps(result), time.time()),
        )
        conn.commit()
        return result
    finally:
        conn.close()
