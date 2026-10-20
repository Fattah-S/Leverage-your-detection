"""Engineer review step.

In the product this is a person merging or rejecting a pull request. In the
prototype a review policy file plays the engineer, so the demo can run
unattended. Every decision and its reason go into memory.
"""
from __future__ import annotations

from .base import Context, Emit, Node


class EngineerReviewNode(Node):
    name = "engineer_review"
    subscribes = ("validation_passed",)

    def handle(self, event, ctx: Context) -> Emit:
        pid = event.payload["proposal"]
        prop = ctx.proposals[pid]
        reject = ctx.review_policy.get("reject", {})
        if prop["key"] in reject:
            reason = reject[prop["key"]]
            prop["status"] = "rejected"
            ctx.memory.add("decision", key=prop["key"], decision="rejected", reason=reason,
                           proposal=pid, week=ctx.week)
            return [("proposal_rejected", {"proposal": pid, "reason": reason})]

        uc = dict(prop["use_case"])
        uc["validated"] = True
        ctx.library[uc["id"]] = uc
        prop["status"] = "merged"
        ctx.memory.add("decision", key=prop["key"], decision="merged", reason="approved",
                       proposal=pid, week=ctx.week)
        return [("rule_merged", {"proposal": pid, "use_case": uc["id"], "kind": prop["kind"]})]
