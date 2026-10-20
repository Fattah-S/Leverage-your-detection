"""Rule health node: finds use cases that are broken at the metadata level.

Checks (all deterministic):
- mapped to a technique that no longer exists in the current ATT&CK release
- needs a log source the organisation does not collect
- no owner
"""
from __future__ import annotations

from .. import attack
from .base import Context, Emit, Node


class RuleHealthNode(Node):
    name = "rule_health"
    subscribes = ("tick",)

    def handle(self, event, ctx: Context) -> Emit:
        out: Emit = []
        sources = set(ctx.profile["log_sources"])
        release = attack.load()["attack_release"]
        for uc in sorted(ctx.library.values(), key=lambda u: u["id"]):
            if uc.get("status") != "active":
                continue
            problems = []
            stale = [t for t in uc.get("techniques", []) if attack.technique(t) is None]
            if stale:
                problems.append({"check": "stale_technique", "detail": f"{', '.join(stale)} not in ATT&CK v{release}",
                                 "techniques": stale})
            if uc.get("log_source") not in sources:
                problems.append({"check": "missing_log_source",
                                 "detail": f"needs '{uc.get('log_source')}', which is not collected"})
            if not uc.get("owner"):
                problems.append({"check": "no_owner", "detail": "no owner set"})
            if problems:
                out.append(("broken_rule", {"use_case": uc["id"], "title": uc["title"], "problems": problems}))
        return out
