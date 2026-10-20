"""Orchestrator: routes each event to the nodes subscribed to its type."""
from __future__ import annotations

from collections import defaultdict

from .bus import EventBus
from .nodes.base import Context, Node


class Orchestrator:
    def __init__(self, bus: EventBus, ctx: Context, nodes: list[Node], max_events: int = 10_000):
        self.bus = bus
        self.ctx = ctx
        self.nodes = nodes
        self.max_events = max_events
        self.routes: dict[str, list[Node]] = defaultdict(list)
        for node in nodes:
            for event_type in node.subscribes:
                self.routes[event_type].append(node)

    def run(self) -> int:
        """Process pending events until none are left. Returns events processed."""
        processed = 0
        while (event := self.bus.next_pending()) is not None:
            handlers = self.routes.get(event.type, [])
            for node in handlers:
                for new_type, payload in node.handle(event, self.ctx) or []:
                    self.bus.publish(new_type, node.name, payload, parent_id=event.id)
            self.bus.mark_done(event.id, [n.name for n in handlers])
            processed += 1
            if processed >= self.max_events:
                raise RuntimeError("event limit reached: possible loop between nodes")
        return processed

    def routing_table(self) -> dict[str, list[str]]:
        return {t: [n.name for n in ns] for t, ns in sorted(self.routes.items())}
