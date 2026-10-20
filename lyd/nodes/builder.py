"""Use-case builder / fixer node: turns findings into proposals (the prototype's
stand-in for pull requests).

It checks decision memory first: a proposal an engineer already rejected is
not proposed again. Drafts are metadata only; the detection logic itself is
written later by the LLM and the engineer, outside this prototype.
"""
from __future__ import annotations

from .. import attack
from .base import Context, Emit, Node

# Coarse first guess of where a technique is visible, by tactic. The engineer confirms it.
TACTIC_SOURCE = [
    ("command-and-control", "network"),
    ("exfiltration", "network"),
    ("lateral-movement", "authentication"),
    ("initial-access", "authentication"),
]


def guess_log_source(tid: str) -> str:
    tactics = (attack.technique(tid) or {}).get("tactics", [])
    for tactic, source in TACTIC_SOURCE:
        if tactic in tactics:
            return source
    return "endpoint_process"


class BuilderNode(Node):
    name = "builder"
    subscribes = ("gap", "exposure", "broken_rule", "noisy_rule")

    def handle(self, event, ctx: Context) -> Emit:
        p = event.payload
        if event.type == "gap":
            key = f"new:{p['technique']}"
            draft = {"kind": "new_use_case", "key": key, "technique": p["technique"],
                     "use_case": {"id": f"UC-{p['technique']}", "title": f"{p['technique_name']}",
                                  "techniques": [p["technique"]], "log_source": guess_log_source(p["technique"]),
                                  "owner": ctx.profile["default_owner"], "status": "active"},
                     "reason": ctx.llm.write("justification", {**p})}
        elif event.type == "exposure":
            key = f"watch:{p['account']}"
            draft = {"kind": "watchlist", "key": key,
                     "use_case": {"id": f"WL-{p['account'].split('@')[0]}",
                                  "title": f"Exposure watchlist: unusual sign-in for {p['account']}",
                                  "techniques": ["T1078.004"], "log_source": "cloud_signin",
                                  "owner": ctx.profile["default_owner"], "status": "active",
                                  "expires_days": ctx.profile.get("watchlist_days", 90)},
                     "reason": f"Account seen in {p['source']} on {p['seen']}; watch its sign-ins until reset."}
        elif event.type == "broken_rule":
            key = f"fix:{p['use_case']}:" + ",".join(sorted(x["check"] for x in p["problems"]))
            uc = dict(ctx.library[p["use_case"]])
            changes = []
            for prob in p["problems"]:
                if prob["check"] == "stale_technique":
                    remap = {t: attack.load()["revoked_by"].get(t) for t in prob["techniques"]}
                    uc["techniques"] = [remap.get(t) or t for t in uc["techniques"]]
                    changes.append("remap " + ", ".join(f"{a} -> {b}" for a, b in remap.items() if b))
                elif prob["check"] == "missing_log_source":
                    uc["status"] = "paused"
                    changes.append("pause until the log source is onboarded")
                elif prob["check"] == "no_owner":
                    uc["owner"] = ctx.profile["default_owner"]
                    changes.append(f"assign owner {uc['owner']}")
            draft = {"kind": "fix", "key": key, "use_case": uc,
                     "reason": "; ".join(x["detail"] for x in p["problems"]) + ". Proposed: " + "; ".join(changes)}
        else:  # noisy_rule
            c = p["cluster"]
            key = f"tune:{p['use_case']}:" + ",".join(f"{k}={v}" for k, v in sorted(c["fields"].items()))
            uc = dict(ctx.library[p["use_case"]])
            uc["exclusions"] = list(uc.get("exclusions", [])) + [c["fields"]]
            draft = {"kind": "tuning", "key": key, "use_case": uc, "exclusion": c["fields"],
                     "reason": (f"{p['alerts_7d']} alerts in 7 days, {int(p['fp_closed_ratio'] * 100)}% closed as "
                                f"false positive; {int(c['share'] * 100)}% come from one pattern "
                                f"({', '.join(f'{k}={v}' for k, v in c['fields'].items())}). "
                                f"Expected after exclusion: about {round(p['alerts_7d'] * (1 - c['share']))} alerts.")}

        if draft["kind"] in ("new_use_case", "watchlist") and draft["use_case"]["id"] in ctx.library:
            return [("skipped_duplicate", {"key": key, "reason": "already in the library"})]
        previous = ctx.memory.was_rejected(key)
        if previous:
            return [("skipped_previously_rejected", {"key": key, "rejected_in": previous["week"],
                                                     "reason": previous["reason"]})]
        if any(pr["key"] == key and pr["status"] == "open" for pr in ctx.proposals.values()):
            return [("skipped_duplicate", {"key": key})]

        pid = f"PR-{len(ctx.proposals) + 1:03d}"
        ctx.proposals[pid] = {"id": pid, "status": "open", "week": ctx.week, "trigger_event": event.id, **draft}
        return [("proposal_opened", {"proposal": pid, "kind": draft["kind"], "key": key})]
