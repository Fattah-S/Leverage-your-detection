"""The platform: agents, orchestrator, event bus, memory and saved state together.

The demo, the chatbot, the dashboard and the GitHub pull-request sync all use
this one object, so they see and change the same state.

State on disk (in the output folder):
    state.json      use-case library, proposals, coverage history, intel seen
    memory.jsonl    engineer decisions with reasons
    events.sqlite   every event, for tracing
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .bus import EventBus
from .llm import MockLLM
from .memory import Memory
from .nodes import all_nodes
from .nodes.base import Context
from .nodes.coverage import score
from .nodes.review import apply_decision
from .orchestrator import Orchestrator

ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


class Platform:
    def __init__(self, out: Path | str = ROOT / "docs" / "demo", llm=None, fresh: bool = False,
                 review_mode: str | None = None):
        self.out = Path(out)
        if fresh and self.out.exists():
            shutil.rmtree(self.out)
        self.out.mkdir(parents=True, exist_ok=True)
        state = load_json(self.out / "state.json") if (self.out / "state.json").exists() else {}
        library = state.get("library") or {u["id"]: u for u in
                                           load_json(ROOT / "samples" / "use_cases.json")["use_cases"]}
        self.bus = EventBus(self.out / "events.sqlite")
        self.ctx = Context(
            profile=load_json(ROOT / "config" / "profile.json"), library=library, intel_inbox=[],
            alert_stats=[], review_policy=load_json(ROOT / "config" / "review_policy.json"),
            memory=Memory(self.out / "memory.jsonl"), llm=llm or MockLLM(), out_dir=self.out,
            week=state.get("week", "week-1"), review_mode=review_mode or state.get("review_mode", "auto"),
            proposals=state.get("proposals", {}), coverage_history=state.get("coverage_history", []),
            intel_seen=state.get("intel_seen", []))
        self.orch = Orchestrator(self.bus, self.ctx, all_nodes(self.bus))

    # ------------------------------------------------------------------ state
    def save(self) -> None:
        state = {"week": self.ctx.week, "review_mode": self.ctx.review_mode, "library": self.ctx.library,
                 "proposals": self.ctx.proposals, "coverage_history": self.ctx.coverage_history,
                 "intel_seen": self.ctx.intel_seen}
        (self.out / "state.json").write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")

    def score(self) -> dict:
        return score(self.ctx)

    # ------------------------------------------------------------- operations
    def run_week(self, week: str, intel: list, stats: list) -> dict:
        ctx = self.ctx
        ctx.week, ctx.intel_inbox, ctx.alert_stats = week, intel, stats
        baseline = score(ctx)
        ctx.coverage_history.append({"week": week, "point": "start", **baseline})
        first_event = self.last_event_id()
        self.bus.publish("tick", "scheduler", {"week": week})
        self.orch.run()
        self.report(week, baseline, first_event)
        self.save()
        return {"week": week, "before": baseline["pct"], "after": score(ctx)["pct"]}

    def report(self, week: str | None = None, baseline: dict | None = None, first_event: int = 0) -> None:
        week = week or self.ctx.week
        if baseline is None:
            starts = [h for h in self.ctx.coverage_history if h["week"] == week and h.get("point") == "start"]
            baseline = starts[0] if starts else score(self.ctx)
            if not first_event:
                ticks = [e for e in self.bus.all() if e["type"] == "tick" and e["payload"].get("week") == week]
                first_event = ticks[0]["id"] - 1 if ticks else 0
        self.bus.publish("report_requested", "scheduler",
                         {"week": week, "baseline": baseline, "first_event": first_event})
        self.orch.run()

    def submit(self, event_type: str, payload: dict, source: str = "engineer_chat") -> list[dict]:
        """Put one event on the bus (e.g. from chat), run the agents, return the chain it caused."""
        eid = self.bus.publish(event_type, source, payload)
        self.orch.run()
        self.save()
        return self.bus.chain(eid)

    def decide(self, pid: str, decision: str, reason: str, by: str = "engineer") -> list[dict]:
        """An engineer merges or rejects a proposal (dashboard, chat or GitHub sync)."""
        prop = self.ctx.proposals.get(pid)
        if not prop:
            raise KeyError(f"unknown proposal {pid}")
        if prop["status"] != "awaiting_review":
            raise ValueError(f"{pid} is {prop['status']}, not awaiting review")
        if decision not in ("merged", "rejected"):
            raise ValueError("decision must be 'merged' or 'rejected'")
        if decision == "rejected" and not reason.strip():
            raise ValueError("a reason is required when rejecting (it is what the platform learns from)")
        root = self.bus.publish("engineer_decision", by, {"proposal": pid, "decision": decision})
        for t, p in apply_decision(self.ctx, pid, decision, reason or "approved", by=by):
            self.bus.publish(t, "engineer_review", p, parent_id=root)
        self.bus.mark_done(root, ["engineer_review"])
        self.orch.run()
        self.save()
        return self.bus.chain(root)

    def last_event_id(self) -> int:
        events = self.bus.all()
        return events[-1]["id"] if events else 0

    def awaiting(self) -> list[dict]:
        return [p for p in self.ctx.proposals.values() if p["status"] == "awaiting_review"]
