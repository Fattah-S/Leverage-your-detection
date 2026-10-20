"""Monthly use-case advisory.

Code ranks every open priority gap; the LLM only writes the short intro.

Score (0-100) per technique:
    threat groups in the profile that use it   20 points each, up to 60
    named in relevant intel during the period   +20
    likely log source is collected              +20

Gaps are moved out of the ranking (with the reason) when the engineer
already rejected them, when a proposal is already in progress, or when no
log source can see them (those become "onboard a log source" actions).
"""
from __future__ import annotations

from . import attack
from .nodes.builder import guess_log_source
from .nodes.coverage import covered_techniques, priority_techniques
from .nodes.intel import relevance


def rank(ctx, top: int = 10) -> dict:
    prio = priority_techniques(ctx)
    covered = covered_techniques(ctx)
    no_data = set(ctx.profile.get("no_visibility", []))
    sources = set(ctx.profile["log_sources"])
    threshold = ctx.profile.get("relevance_threshold", 60)
    intel_hits: dict[str, list[str]] = {}
    for item in ctx.intel_seen:
        if item.get("type") == "ttp" and relevance(item, ctx.profile) >= threshold:
            for t in item.get("techniques", []):
                intel_hits.setdefault(t, []).append(item["id"])
    in_progress = {p["key"].split(":", 1)[1]: p["id"] for p in ctx.proposals.values()
                   if p["kind"] == "new_use_case" and p["status"] in ("open", "validated", "awaiting_review")}

    untested = {t: u["id"] for u in ctx.library.values() if u.get("status") == "active" and not u.get("validated")
                for t in u.get("techniques", [])}
    ranked, rejected, progress, onboard, validate = [], [], [], [], []
    for tid, groups in prio.items():
        if tid in covered:
            continue
        if tid in no_data:
            onboard.append({"technique": tid, "name": attack.name(tid), "groups": groups})
            continue
        prev = ctx.memory.was_rejected(f"new:{tid}")
        if prev:
            rejected.append({"technique": tid, "name": attack.name(tid), "reason": prev["reason"], "week": prev["week"]})
            continue
        if tid in in_progress:
            progress.append({"technique": tid, "name": attack.name(tid), "proposal": in_progress[tid]})
            continue
        if tid in untested:
            validate.append({"technique": tid, "name": attack.name(tid), "use_case": untested[tid], "groups": groups})
            continue
        source = guess_log_source(tid)
        parts = {"threat groups": min(60, 20 * len(groups)),
                 "recent intel": 20 if tid in intel_hits else 0,
                 "data available": 20 if source in sources else 0}
        ranked.append({"technique": tid, "name": attack.name(tid), "groups": groups, "score": sum(parts.values()),
                       "parts": parts, "intel": sorted(set(intel_hits.get(tid, []))), "log_source": source})
    ranked.sort(key=lambda r: (-r["score"], -len(r["groups"]), r["technique"]))
    return {"top": ranked[:top], "total_open": len(ranked), "rejected": rejected,
            "in_progress": progress, "onboard": onboard, "validate": validate}


def markdown(ctx, period: str, top: int = 10) -> str:
    r = rank(ctx, top)
    intro = ctx.llm.write("advisory_intro", {"period": period, "open_gaps": r["total_open"],
                                             "recommended": len(r["top"]),
                                             "first": r["top"][0]["technique"] if r["top"] else None})
    lines = [f"# Monthly use-case advisory: {period}", "", intro, "",
             "> Ranked by code (threat-group usage, recent intel, data availability). "
             "Placeholder data: the ranking method is real, the inputs are not.", "",
             f"## Recommended next use cases (top {len(r['top'])} of {r['total_open']} ranked gaps)", "",
             "| # | Technique | Name | Score | Why | Likely log source |", "| --- | --- | --- | --- | --- | --- |"]
    for i, x in enumerate(r["top"], 1):
        why = [f"used by {', '.join(x['groups'])}"]
        if x["intel"]:
            why.append(f"in intel {', '.join(x['intel'])}")
        lines.append(f"| {i} | {x['technique']} | {x['name']} | {x['score']} | {'; '.join(why)} | {x['log_source']} |")
    if r["validate"]:
        lines += ["", "## Test an existing use case instead of writing a new one", ""]
        lines += [f"- {x['technique']} {x['name']}: {x['use_case']} exists but has not passed validation"
                  for x in r["validate"]]
    if r["in_progress"]:
        lines += ["", "## Already in progress", ""]
        lines += [f"- {x['technique']} {x['name']}: proposal {x['proposal']}" for x in r["in_progress"]]
    if r["rejected"]:
        lines += ["", "## Not recommended (rejected by an engineer before)", ""]
        lines += [f"- {x['technique']} {x['name']}: {x['reason']} ({x['week']})" for x in r["rejected"]]
    if r["onboard"]:
        lines += ["", "## Onboard a log source first", ""]
        lines += [f"- {x['technique']} {x['name']} (used by {', '.join(x['groups'])})" for x in r["onboard"]]
    lines += ["", "To start one, ask the chat: \"build a use case for <technique>\".", ""]
    return "\n".join(lines)
