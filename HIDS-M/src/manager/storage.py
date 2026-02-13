import sqlite3
import json
import csv
import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("hids_manager.storage")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL,
  summary TEXT NOT NULL,
  details TEXT NOT NULL,
  raw TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_ts ON events(ts);
"""

class Storage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init()

    def _init(self):
        conn = sqlite3.connect(self.db_path)
        try:
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    conn.execute(statement)
            conn.commit()
            logger.info(f"Database initialized: {self.db_path}")
        finally:
            conn.close()

    def insert(self, e: Dict[str, Any], raw: str):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """INSERT INTO events(ts, source, kind, severity, summary, details, raw)
                   VALUES(?, ?, ?, ?, ?, ?, ?)""",
                (
                    e["ts"],
                    e["source"],
                    e["kind"],
                    e["severity"],
                    e["summary"],
                    json.dumps(e.get("details", {})),
                    raw
                )
            )
            conn.commit()
        finally:
            conn.close()

    def latest(self, limit: int = 200) -> List[Tuple]:
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """SELECT id, ts, severity, source, kind, summary, details
                   FROM events ORDER BY id DESC LIMIT ?""",
                (limit,)
            )
            rows = cur.fetchall()
            return rows
        finally:
            conn.close()

    def count(self) -> int:
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM events")
            return cur.fetchone()[0]
        finally:
            conn.close()

    def clear(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM events")
            conn.commit()
            logger.warning("All events cleared from database")
        finally:
            conn.close()

    def export_csv(self, filename: str):
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """SELECT id, ts, severity, source, kind, summary, details
                   FROM events ORDER BY id DESC"""
            )
            rows = cur.fetchall()
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Timestamp', 'Severity', 'Source', 'Kind', 'Summary', 'Details'])
                writer.writerows(rows)
            logger.info(f"Exported {len(rows)} events to {filename}")
        finally:
            conn.close()