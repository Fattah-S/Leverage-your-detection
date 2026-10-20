"""Decision memory: every engineer decision with its reason.

A simple stand-in for the RAG store. The builder checks it before proposing,
so a use case rejected before is not proposed again.
"""
from __future__ import annotations

import json
from pathlib import Path


class Memory:
    def __init__(self, path: Path | None = None):
        self.path = path
        self.items: list[dict] = []
        if path and path.exists():
            self.items = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def add(self, kind: str, **fields) -> None:
        item = {"kind": kind, **fields}
        self.items.append(item)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(item, sort_keys=True) + "\n")

    def search(self, **match) -> list[dict]:
        return [i for i in self.items if all(i.get(k) == v for k, v in match.items())]

    def was_rejected(self, key: str) -> dict | None:
        hits = self.search(kind="decision", key=key, decision="rejected")
        return hits[-1] if hits else None
