"""SQLite run history: what each check found on each run, for drift detection."""

import json
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    sections TEXT NOT NULL,
    counts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
    run_id INTEGER NOT NULL REFERENCES runs(id),
    section TEXT NOT NULL,
    check_id TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    observed TEXT,
    PRIMARY KEY (run_id, check_id, target)
);
-- First/last time each distinct observed value was seen, e.g. to estimate
-- how long a DKIM key has been unchanged.
CREATE TABLE IF NOT EXISTS observations (
    check_id TEXT NOT NULL,
    target TEXT NOT NULL,
    observed TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (check_id, target, observed)
);
"""


class History:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.executescript(SCHEMA)

    def previous(self, sections):
        """{key: row} from the latest earlier run of each section, plus that run's time.

        Returns ({}, None) when no section has run before (first run).
        """
        prev, when = {}, None
        for section in sections:
            row = self.conn.execute(
                "SELECT id, started_at FROM runs WHERE (',' || sections || ',') LIKE ? ORDER BY id DESC LIMIT 1",
                (f"%,{section},%",),
            ).fetchone()
            if not row:
                continue
            run_id, started = row
            when = max(when, started) if when else started
            for check_id, target, status, title, observed in self.conn.execute(
                "SELECT check_id, target, status, title, observed FROM results WHERE run_id=? AND section=?",
                (run_id, section),
            ):
                prev[f"{check_id}|{target}"] = {
                    "check": check_id, "target": target, "status": status,
                    "title": title, "observed": observed, "section": section,
                }
        return prev, when

    def first_seen(self, check_id, target, observed):
        row = self.conn.execute(
            "SELECT first_seen FROM observations WHERE check_id=? AND target=? AND observed=?",
            (check_id, target, observed),
        ).fetchone()
        return row[0] if row else None

    def save(self, started_at, sections, results, counts):
        cur = self.conn.execute(
            "INSERT INTO runs (started_at, sections, counts) VALUES (?, ?, ?)",
            (started_at, ",".join(sections), json.dumps(counts)),
        )
        run_id = cur.lastrowid
        self.conn.executemany(
            "INSERT OR REPLACE INTO results (run_id, section, check_id, target, status, title, observed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(run_id, r.section, r.check, r.target, r.status, r.title, r.observed) for r in results],
        )
        self.conn.executemany(
            "INSERT INTO observations (check_id, target, observed, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (check_id, target, observed) DO UPDATE SET last_seen = excluded.last_seen",
            [(r.check, r.target, r.observed, started_at, started_at) for r in results if r.observed is not None],
        )
        self.conn.commit()
        return run_id
