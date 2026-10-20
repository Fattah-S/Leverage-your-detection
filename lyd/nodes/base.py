"""Shared node interface and the context every node can read."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..bus import Event
from ..memory import Memory

Emit = list[tuple[str, dict]]


@dataclass
class Context:
    profile: dict
    library: dict[str, dict]            # use cases in the repo, by id
    intel_inbox: list[dict]
    alert_stats: list[dict]
    review_policy: dict
    memory: Memory
    llm: Any
    week: str = "week-1"
    review_mode: str = "auto"           # "auto": review policy decides; "manual": wait for an engineer
    intel_seen: list[dict] = field(default_factory=list)
    proposals: dict[str, dict] = field(default_factory=dict)
    coverage_history: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    out_dir: Path | None = None


class Node:
    name: str = "node"
    subscribes: tuple[str, ...] = ()

    def handle(self, event: Event, ctx: Context) -> Emit:  # pragma: no cover - interface
        raise NotImplementedError
