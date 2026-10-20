"""MITRE ATT&CK reference data (compact file built by scripts/build_attack_data.py)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "attack" / "enterprise-compact.json"


@lru_cache(maxsize=1)
def load() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def technique(tid: str) -> dict | None:
    return load()["techniques"].get(tid)


def name(tid: str) -> str:
    t = technique(tid)
    return t["name"] if t else "unknown technique"


def group_techniques(group_ids: list[str]) -> dict[str, list[str]]:
    """technique id -> names of the listed groups known to use it."""
    data = load()
    out: dict[str, list[str]] = {}
    for gid in group_ids:
        g = data["groups"].get(gid)
        if not g:
            continue
        for tid in g["techniques"]:
            out.setdefault(tid, []).append(g["name"])
    return out
