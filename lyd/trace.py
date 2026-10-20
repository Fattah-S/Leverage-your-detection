"""Run trace: the proof that the agents are linked.

Writes the routing table, one Mermaid diagram per chain (drawn from the real
events of the run, parent -> child) and the full event log.
"""
from __future__ import annotations

from .bus import EventBus

SHOW = {"new_ttp", "exposure", "broken_rule", "noisy_rule"}


def _label(e: dict) -> str:
    p = e["payload"]
    detail = p.get("technique") or p.get("use_case") or p.get("proposal") or p.get("account") or p.get("key") or ""
    return f'E{e["id"]} {e["type"]}<br/><i>{e["source"]}</i><br/>{detail}'.replace('"', "'")


def mermaid_chain(bus: EventBus, root_id: int) -> str:
    chain = bus.chain(root_id)
    lines = ["```mermaid", "flowchart LR"]
    for e in chain:
        lines.append(f'  E{e["id"]}["{_label(e)}"]')
    for e in chain[1:]:
        lines.append(f'  E{e["parent_id"]} --> E{e["id"]}')
    lines.append("```")
    return "\n".join(lines)


def pick_chains(bus: EventBus) -> list[tuple[str, int]]:
    """One representative chain per story, chosen from the run itself."""
    events = bus.all()
    picks: list[tuple[str, int]] = []

    def first(pred, title):
        for e in events:
            if pred(e):
                picks.append((title, e["id"]))
                return

    def chain_types(e):
        return {x["type"] for x in bus.chain(e["id"])}

    first(lambda e: e["type"] == "new_ttp" and "rule_merged" in chain_types(e),
          "Threat intel → coverage gap → builder → validation → engineer merge → coverage re-scored")
    first(lambda e: e["type"] == "new_ttp" and "proposal_rejected" in chain_types(e),
          "Gap proposed, engineer rejects it (reason stored in memory)")
    first(lambda e: e["type"] == "new_ttp" and "skipped_previously_rejected" in chain_types(e),
          "Week 2: the same gap is not proposed again (memory)")
    first(lambda e: e["type"] == "exposure" and "rule_merged" in chain_types(e),
          "Exposure intel → watchlist use case")
    first(lambda e: e["type"] == "broken_rule" and "rule_merged" in chain_types(e),
          "Rule health → fix proposal → merged")
    first(lambda e: e["type"] == "noisy_rule" and "validation_failed" in chain_types(e),
          "Noise tuning → exclusion too broad → validation blocks it")
    first(lambda e: e["type"] == "noisy_rule" and "rule_merged" in chain_types(e),
          "Noise tuning → narrow exclusion → merged")
    return picks


def write(bus: EventBus, routes: dict[str, list[str]], header: str) -> str:
    lines = [header, "", "## Routing table (which agent listens to which event)", "",
             "| Event | Handled by |", "| --- | --- |"]
    for t, ns in routes.items():
        lines.append(f"| `{t}` | {', '.join(ns)} |")
    lines += ["", "## Chains from this run", "",
              "Each box is a real event from the run: its number, type, the agent that emitted it and its subject. "
              "Arrows go from an event to the events it caused.", ""]
    for title, root in pick_chains(bus):
        lines += [f"### {title}", "", mermaid_chain(bus, root), ""]
    lines += ["## Full event log", "", "| # | Event | Emitted by | Caused by | Handled by | Subject |",
              "| --- | --- | --- | --- | --- | --- |"]
    for e in bus.all():
        p = e["payload"]
        subject = p.get("technique") or p.get("use_case") or p.get("proposal") or p.get("account") \
            or p.get("key") or p.get("intel_id") or p.get("week") or ""
        lines.append(f"| {e['id']} | `{e['type']}` | {e['source']} | {e['parent_id'] or ''} "
                     f"| {', '.join(e['handled_by']) or '-'} | {subject} |")
    return "\n".join(lines) + "\n"
