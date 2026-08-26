"""
Storage layer. Uses stdlib sqlite3 with JSON-serialized rows rather than
an ORM — deliberately simple for an MVP, and it means the whole backend
runs with zero extra native dependencies. Swapping to SQLAlchemy/Postgres
later only touches this one file (see docs/deployment.md).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock

DB_PATH = Path(__file__).resolve().parent.parent / "graphsoc.db"

_lock = Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock, _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                event_type TEXT,
                user_id TEXT,
                device_id TEXT,
                data TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                created_at TEXT,
                data TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                created_at TEXT,
                severity TEXT,
                data TEXT
            )
        """)
        conn.commit()


def insert_event(event: dict):
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO events VALUES (?, ?, ?, ?, ?, ?)",
            (event.get("event_id"), str(event.get("timestamp")), event.get("event_type"),
             event.get("user_id"), event.get("device_id"), json.dumps(event, default=str)),
        )
        conn.commit()


def insert_events(events: list[dict]):
    with _lock, _connect() as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO events VALUES (?, ?, ?, ?, ?, ?)",
            [(e.get("event_id"), str(e.get("timestamp")), e.get("event_type"),
              e.get("user_id"), e.get("device_id"), json.dumps(e, default=str)) for e in events],
        )
        conn.commit()


def get_events(limit: int = 500, event_type: str | None = None, user_id: str | None = None) -> list[dict]:
    with _lock, _connect() as conn:
        q = "SELECT data FROM events"
        clauses, params = [], []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if user_id:
            clauses.append("user_id = ?")
            params.append(user_id)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(q, params).fetchall()
        return [json.loads(r["data"]) for r in rows]


def get_event(event_id: str) -> dict | None:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT data FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return json.loads(row["data"]) if row else None


def count_events() -> int:
    with _lock, _connect() as conn:
        return conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]


def insert_alert(alert: dict):
    with _lock, _connect() as conn:
        conn.execute("INSERT OR REPLACE INTO alerts VALUES (?, ?, ?)",
                      (alert.get("alert_id"), str(alert.get("created_at")), json.dumps(alert, default=str)))
        conn.commit()


def get_alerts(limit: int = 100) -> list[dict]:
    with _lock, _connect() as conn:
        rows = conn.execute("SELECT data FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r["data"]) for r in rows]


def insert_incident(incident: dict):
    with _lock, _connect() as conn:
        conn.execute("INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?)",
                      (incident.get("incident_id"), str(incident.get("created_at")),
                       incident.get("severity"), json.dumps(incident, default=str)))
        conn.commit()


def get_incidents(limit: int = 100) -> list[dict]:
    with _lock, _connect() as conn:
        rows = conn.execute("SELECT data FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r["data"]) for r in rows]


def get_incident(incident_id: str) -> dict | None:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT data FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return json.loads(row["data"]) if row else None


def reset_db():
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM incidents")
        conn.commit()
