"""Posture node: weekly report and ATT&CK Navigator layer.

All numbers come from code. The LLM only writes the short summary paragraph.
"""
from __future__ import annotations

import json

from .. import attack
from .base import Context, Emit, Node
from .coverage import covered_techniques, priority_techniques, score


def navigator_layer(ctx: Context, week: str) -> dict:
    prio = priority_techniques(ctx)
    covered = covered_techniques(ctx)
    no_data = set(ctx.profile.get("no_visibility", []))
    techniques = []
    for tid, groups in sorted(prio.items()):
        if tid in covered:
            color, state = "#1d9e75", "covered"
        elif tid in no_data:
            color, state = "#9c9a92", "no log source"
        else:
            color, state = "#e24b4a", "gap"
        techniques.append({"techniqueID": tid, "color": color, "score": len(groups),
                           "comment": f"{state}; used by {', '.join(groups)}", "enabled": True})
    release = attack.load()["attack_release"]
    return {
        "name": f"Priority coverage {week}",
        "versions": {"attack": release.split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Techniques used by {', '.join(ctx.profile['threat_groups'])}; score = number of those groups",
        "techniques": techniques,
        "legendItems": [{"label": "covered (validated use case)", "color": "#1d9e75"},
                        {"label": "gap", "color": "#e24b4a"},
                        {"label": "no log source", "color": "#9c9a92"}],
        "hideDisabled": False,
    }


def report_markdown(ctx: Context, week: str, before: dict, after: dict, events: list[dict]) -> str:
    props = [p for p in ctx.proposals.values() if p["week"] == week]
    merged = [p for p in props if p["status"] == "merged"]
    rejected = [p for p in props if p["status"] == "rejected"]
    prio = priority_techniques(ctx)
    covered = covered_techniques(ctx)
    no_data = set(ctx.profile.get("no_visibility", []))
    open_gaps = sorted(((t, g) for t, g in prio.items() if t not in covered and t not in no_data),
                       key=lambda x: (-len(x[1]), x[0]))
    summary = ctx.llm.write("report_summary", {"before": before["pct"], "after": after["pct"],
                                               "merged": len(merged), "rejected": len(rejected),
                                               "open_gaps": len(open_gaps)})
    count = lambda t: sum(1 for e in events if e["type"] == t)  # noqa: E731

    lines = [f"# Weekly posture report: {week}", "",
             f"Organisation profile: {ctx.profile['name']} · threat groups: "
             + ", ".join(f"{attack.load()['groups'][g]['name']} ({g})" for g in ctx.profile["threat_groups"])
             + f" · ATT&CK v{attack.load()['attack_release']} · LLM: {ctx.llm.name}", "",
             "> Prototype run on placeholder use cases and placeholder intel. It proves the agents work together; "
             "it does not measure real detection quality.", "",
             "## Summary", "", summary, "",
             "## Coverage of priority techniques", "",
             "| | Start of week | End of week |", "| --- | --- | --- |",
             f"| Covered | {before['covered']} of {before['priority']} ({before['pct']}%) "
             f"| {after['covered']} of {after['priority']} ({after['pct']}%) |",
             f"| No log source | {before['no_data']} | {after['no_data']} |", "",
             "## Agent activity", "",
             "| Event | Count |", "| --- | --- |"]
    for t in ["new_ttp", "intel_ignored", "exposure", "gap", "covered", "needs_log_source", "broken_rule",
              "noisy_rule", "proposal_opened", "validation_passed", "validation_failed", "review_requested",
              "rule_merged", "proposal_rejected", "skipped_previously_rejected"]:
        lines.append(f"| `{t}` | {count(t)} |")
    lines += ["", "## Proposals (pull requests)", "",
              "| ID | Kind | Use case | Status | Reason |", "| --- | --- | --- | --- | --- |"]
    for p in props:
        reason = p["reason"].replace("|", "/")
        if p["status"] == "rejected":
            reason = f"Rejected: {p.get('decision_reason', '')}"
        elif p["status"] == "failed":
            reason = "Failed checks: " + ", ".join(c["check"] for c in p["checks"] if not c["ok"])
        status = "awaiting review" if p["status"] == "awaiting_review" else p["status"]
        lines.append(f"| {p['id']} | {p['kind']} | {p['use_case']['id']} | {status} | {reason} |")
    skipped = [e for e in events if e["type"] == "skipped_previously_rejected"]
    if skipped:
        lines += ["", "## Not proposed again (rejected before)", ""]
        for e in skipped:
            lines.append(f"- `{e['payload']['key']}`: rejected in {e['payload']['rejected_in']} "
                         f"({e['payload']['reason']})")
    needs = [e["payload"] for e in events if e["type"] == "needs_log_source"]
    if needs:
        lines += ["", "## Needs a log source, not a rule", ""]
        for n in needs:
            lines.append(f"- {n['technique']} {n['technique_name']}")
    lines += ["", "## Top open gaps (next actions)", "",
              "| Technique | Name | Used by |", "| --- | --- | --- |"]
    for tid, groups in open_gaps[:10]:
        lines.append(f"| {tid} | {attack.name(tid)} | {', '.join(groups)} |")
    lines += ["", f"Navigator layer: `navigator-layer.json` (load it at "
                  "https://mitre-attack.github.io/attack-navigator/).", ""]
    return "\n".join(lines)


class PostureNode(Node):
    name = "posture"
    subscribes = ("report_requested",)

    def __init__(self, bus=None):
        self.bus = bus

    def handle(self, event, ctx: Context) -> Emit:
        week = event.payload["week"]
        before = event.payload["baseline"]
        after = score(ctx)
        events = [e for e in (self.bus.all() if self.bus else [])
                  if e["id"] > event.payload.get("first_event", 0)]
        if ctx.out_dir:
            d = ctx.out_dir / week
            d.mkdir(parents=True, exist_ok=True)
            (d / "report.md").write_text(report_markdown(ctx, week, before, after, events), encoding="utf-8")
            (d / "navigator-layer.json").write_text(json.dumps(navigator_layer(ctx, week), indent=1), encoding="utf-8")
        return [("report_written", {"week": week, "pct_before": before["pct"], "pct_after": after["pct"]})]
