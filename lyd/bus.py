"""Event bus: one SQLite table of events.

Nodes never call each other. A node publishes an event; the orchestrator
picks pending events and hands each to the nodes subscribed to its type.
Every event records which event caused it (parent_id), so a whole chain can
be traced afterwards, which is how the demo proves the agents are linked.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Event:
    id: int
    seq: int
    type: str
    source: str
    payload: dict
    parent_id: int | None
    status: str


class EventBus:
    def __init__(self, path: str | Path = ":memory:"):
        # The dashboard serves requests on worker threads; access is serialised by its lock.
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS events (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   type TEXT NOT NULL,
                   source TEXT NOT NULL,
                   payload TEXT NOT NULL,
                   parent_id INTEGER,
                   status TEXT NOT NULL DEFAULT 'pending',
                   handled_by TEXT NOT NULL DEFAULT '[]'
               )"""
        )
        self.db.commit()

    def publish(self, type_: str, source: str, payload: dict | None = None,
                parent_id: int | None = None) -> int:
        cur = self.db.execute(
            "INSERT INTO events (type, source, payload, parent_id) VALUES (?, ?, ?, ?)",
            (type_, source, json.dumps(payload or {}, sort_keys=True), parent_id),
        )
        self.db.commit()
        return int(cur.lastrowid)

    def next_pending(self) -> Event | None:
        row = self.db.execute(
            "SELECT id, type, source, payload, parent_id, status FROM events "
            "WHERE status = 'pending' ORDER BY id LIMIT 1"
        ).fetchone()
        return self._event(row) if row else None

    def mark_done(self, event_id: int, handled_by: list[str]) -> None:
        self.db.execute("UPDATE events SET status = 'done', handled_by = ? WHERE id = ?",
                        (json.dumps(handled_by), event_id))
        self.db.commit()

    def all(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT id, type, source, payload, parent_id, status, handled_by FROM events ORDER BY id"
        ).fetchall()
        return [{"id": r[0], "type": r[1], "source": r[2], "payload": json.loads(r[3]),
                 "parent_id": r[4], "status": r[5], "handled_by": json.loads(r[6])} for r in rows]

    def chain(self, event_id: int) -> list[dict]:
        """The event and every event it caused, depth first."""
        events = self.all()
        children: dict[int, list[dict]] = {}
        for e in events:
            if e["parent_id"] is not None:
                children.setdefault(e["parent_id"], []).append(e)
        by_id = {e["id"]: e for e in events}
        out: list[dict] = []

        def walk(eid: int) -> None:
            out.append(by_id[eid])
            for child in children.get(eid, []):
                walk(child["id"])

        walk(event_id)
        return out

    @staticmethod
    def _event(row) -> Event:
        return Event(id=row[0], seq=row[0], type=row[1], source=row[2],
                     payload=json.loads(row[3]), parent_id=row[4], status=row[5])
