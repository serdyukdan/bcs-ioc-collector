"""SQLite storage with atomic replacement of each provider's last good snapshot."""

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Iterable

from .normalize import Indicator
from .sources import Source


SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ok', 'error')),
    last_attempt TEXT NOT NULL,
    last_success TEXT,
    error TEXT,
    valid_count INTEGER NOT NULL DEFAULT 0,
    invalid_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL CHECK (type IN ('ipv4', 'ipv6', 'domain')),
    value TEXT NOT NULL,
    source_count INTEGER NOT NULL DEFAULT 1 CHECK (source_count >= 1),
    level TEXT GENERATED ALWAYS AS (
        CASE WHEN source_count >= 3 THEN 'Critical'
             WHEN source_count = 2 THEN 'High' ELSE 'Medium' END
    ) STORED,
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(type, value)
);
CREATE TABLE IF NOT EXISTS observations (
    indicator_id INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL REFERENCES sources(id),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY(indicator_id, source_id)
);
CREATE INDEX IF NOT EXISTS observations_by_source ON observations(source_id, indicator_id);
CREATE INDEX IF NOT EXISTS indicators_by_level ON indicators(level, type, value);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class Database:
    def __init__(self, path: Path | str, *, dataset: str | None = None, readonly: bool = False):
        self.path = Path(path)
        if readonly:
            self.conn = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 30000")
        try:
            if not readonly:
                self.conn.execute("PRAGMA journal_mode = WAL")
                self.conn.executescript(SCHEMA)
                with self.conn:
                    self.conn.execute("INSERT OR IGNORE INTO metadata VALUES ('schema_version', '1')")
                    if dataset:
                        self.conn.execute("INSERT OR IGNORE INTO metadata VALUES ('dataset', ?)",
                                          (dataset,))
            version = self.conn.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
            if not version or version[0] != "1":
                raise ValueError("Unsupported database schema")
            row = self.conn.execute("SELECT value FROM metadata WHERE key='dataset'").fetchone()
            self.dataset = row[0] if row else "unspecified"
            if dataset and dataset != self.dataset:
                raise ValueError("Demo and live data must use separate database files")
        except Exception:
            self.conn.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.conn.close()

    def replace_snapshot(self, source: Source, indicators: Iterable[Indicator], *,
                         invalid: int = 0, now: str | None = None) -> None:
        """Replace links, recompute priorities and remove orphans in one transaction."""
        now = now or utc_now()
        with self.conn:
            self.conn.execute("""
                INSERT INTO sources(id,name,status,last_attempt,last_success)
                VALUES (?,?,'ok',?,?) ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,status='ok',last_attempt=excluded.last_attempt,
                last_success=excluded.last_success,error=NULL
            """, (source.id, source.name, now, now))
            self.conn.execute("CREATE TEMP TABLE IF NOT EXISTS incoming (type TEXT, value TEXT, PRIMARY KEY(type,value))")
            self.conn.execute("CREATE TEMP TABLE IF NOT EXISTS affected (id INTEGER PRIMARY KEY)")
            self.conn.execute("DELETE FROM incoming")
            self.conn.execute("DELETE FROM affected")
            self.conn.executemany("INSERT OR IGNORE INTO incoming VALUES (?,?)",
                                  ((ioc.type, ioc.value) for ioc in indicators))
            self.conn.execute("INSERT INTO affected SELECT indicator_id FROM observations WHERE source_id=?",
                              (source.id,))
            self.conn.execute("""
                INSERT INTO indicators(type,value,first_seen,updated_at)
                SELECT type,value,?,? FROM incoming WHERE 1
                ON CONFLICT(type,value) DO NOTHING
            """, (now, now))
            self.conn.execute("""
                INSERT OR IGNORE INTO affected
                SELECT i.id FROM indicators i JOIN incoming n ON i.type=n.type AND i.value=n.value
            """)
            self.conn.execute("""
                DELETE FROM observations WHERE source_id=? AND indicator_id NOT IN (
                    SELECT i.id FROM indicators i JOIN incoming n ON i.type=n.type AND i.value=n.value
                )
            """, (source.id,))
            self.conn.execute("""
                INSERT INTO observations(indicator_id,source_id,first_seen,last_seen)
                SELECT i.id,?,?,? FROM indicators i JOIN incoming n
                ON i.type=n.type AND i.value=n.value WHERE 1
                ON CONFLICT(indicator_id,source_id) DO UPDATE SET last_seen=excluded.last_seen
            """, (source.id, now, now))
            self.conn.execute("""
                DELETE FROM indicators WHERE id IN (SELECT id FROM affected)
                AND NOT EXISTS (SELECT 1 FROM observations o WHERE o.indicator_id=indicators.id)
            """)
            self.conn.execute("""
                UPDATE indicators SET source_count=(
                    SELECT COUNT(*) FROM observations o WHERE o.indicator_id=indicators.id
                ), updated_at=? WHERE id IN (SELECT id FROM affected)
            """, (now,))
            self.conn.execute("""
                UPDATE sources SET valid_count=(SELECT COUNT(*) FROM incoming),invalid_count=? WHERE id=?
            """, (invalid, source.id))

    def record_failure(self, source: Source, error: str) -> None:
        with self.conn:
            self.conn.execute("""
                INSERT INTO sources(id,name,status,last_attempt,error) VALUES (?,?,'error',?,?)
                ON CONFLICT(id) DO UPDATE SET status='error',last_attempt=excluded.last_attempt,error=excluded.error
            """, (source.id, source.name, utc_now(), error[:1000]))

    def query(self, *, level: str, limit: int = 100, offset: int = 0) -> list[dict]:
        rows = self.conn.execute("""
            SELECT id,value,type,source_count,level,updated_at FROM indicators
            WHERE level=? ORDER BY type,value LIMIT ? OFFSET ?
        """, (level, -1 if limit == 0 else limit, offset)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            source_rows = self.conn.execute("""
                SELECT s.id,s.status,s.last_success,o.last_seen FROM observations o
                JOIN sources s ON s.id=o.source_id WHERE o.indicator_id=? ORDER BY s.id
            """, (item.pop("id"),)).fetchall()
            item["sources"] = [s["id"] for s in source_rows]
            item["source_details"] = [dict(s) for s in source_rows]
            result.append(item)
        return result

    def stats(self) -> dict:
        levels = {"Critical": 0, "High": 0, "Medium": 0}
        levels.update(dict(self.conn.execute("SELECT level,COUNT(*) FROM indicators GROUP BY level")))
        return {"dataset": self.dataset, "total": sum(levels.values()), "levels": levels,
                "types": dict(self.conn.execute("SELECT type,COUNT(*) FROM indicators GROUP BY type")),
                "sources": [dict(row) for row in self.conn.execute("SELECT * FROM sources ORDER BY id")]}
