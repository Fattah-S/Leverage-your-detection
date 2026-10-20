"""Threat intel node: scores each intel item for relevance to the organisation.

TTP items with a high score become `new_ttp` events (one per technique).
Exposure items (accounts seen in a leak tracker) become `exposure` events.
Intel is treated as data: only the structured fields are read.
"""
from __future__ import annotations

from .. import attack
from .base import Context, Emit, Node


def relevance(item: dict, profile: dict) -> int:
    s = 0
    if item.get("sector") in profile["sectors"]:
        s += 40
    if item.get("region") in profile["regions"]:
        s += 30
    if set(item.get("groups", [])) & set(profile["threat_groups"]):
        s += 20
    prio = attack.group_techniques(profile["threat_groups"])
    if any(t in prio for t in item.get("techniques", [])):
        s += 10
    return s


class ThreatIntelNode(Node):
    name = "threat_intel"
    subscribes = ("tick",)

    def handle(self, event, ctx: Context) -> Emit:
        out: Emit = []
        threshold = ctx.profile.get("relevance_threshold", 60)
        for item in ctx.intel_inbox:
            ctx.intel_seen.append({"week": ctx.week, **item})
            if item.get("type") == "exposure":
                out.append(("exposure", {"intel_id": item["id"], "account": item["account"],
                                         "source": item["source"], "seen": item["seen"]}))
                continue
            r = relevance(item, ctx.profile)
            if r < threshold:
                out.append(("intel_ignored", {"intel_id": item["id"], "relevance": r}))
                continue
            for tid in item.get("techniques", []):
                if attack.technique(tid) is None:
                    out.append(("intel_ignored", {"intel_id": item["id"], "technique": tid,
                                                  "reason": "not an ATT&CK v20 technique"}))
                    continue
                out.append(("new_ttp", {"intel_id": item["id"], "technique": tid, "relevance": r,
                                        "trigger": f"intel {item['id']}: {item['title']}"}))
        return out
