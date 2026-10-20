"""Coverage node: which priority ATT&CK techniques have a validated, active use case.

Priority techniques = techniques used by the threat groups in the
organisation profile (from MITRE ATT&CK group data). A technique counts as
covered only when an active use case mapped to it has passed validation.
"""
from __future__ import annotations

from .. import attack
from .base import Context, Emit, Node


def priority_techniques(ctx: Context) -> dict[str, list[str]]:
    return attack.group_techniques(ctx.profile["threat_groups"])


def covered_techniques(ctx: Context) -> set[str]:
    return {t for uc in ctx.library.values()
            if uc.get("status") == "active" and uc.get("validated")
            for t in uc.get("techniques", [])}


def score(ctx: Context) -> dict:
    prio = priority_techniques(ctx)
    covered = covered_techniques(ctx) & set(prio)
    no_data = set(ctx.profile.get("no_visibility", [])) & set(prio)
    pct = round(100 * len(covered) / len(prio), 1) if prio else 0.0
    return {"priority": len(prio), "covered": len(covered), "pct": pct,
            "no_data": len(no_data), "covered_ids": sorted(covered)}


class CoverageNode(Node):
    name = "coverage"
    subscribes = ("new_ttp", "rule_merged")

    def handle(self, event, ctx: Context) -> Emit:
        if event.type == "rule_merged":
            s = score(ctx)
            ctx.coverage_history.append({"week": ctx.week, "after_event": event.id, **s})
            return [("coverage_updated", {"pct": s["pct"], "covered": s["covered"], "priority": s["priority"]})]

        tid = event.payload["technique"]
        prio = priority_techniques(ctx)
        if tid in covered_techniques(ctx):
            return [("covered", {"technique": tid})]
        if tid in ctx.profile.get("no_visibility", []):
            return [("needs_log_source", {"technique": tid, "technique_name": attack.name(tid),
                                          "reason": "no log source gives visibility of this technique"})]
        groups = prio.get(tid, [])
        priority = "high" if len(groups) >= 2 or event.payload.get("relevance", 0) >= 80 else "medium"
        return [("gap", {"technique": tid, "technique_name": attack.name(tid), "groups": groups,
                         "priority": priority, "trigger": event.payload.get("trigger", "coverage review")})]
