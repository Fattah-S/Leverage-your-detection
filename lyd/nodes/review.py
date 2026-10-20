"""Engineer review step.

- manual mode (the product): a validated proposal waits in the review queue
  (dashboard, chat or a real GitHub pull request) until an engineer decides.
- auto mode (unattended demo): a review policy file plays the engineer.

Every decision and its reason go into memory.
"""
from __future__ import annotations

from .base import Context, Emit, Node


def apply_decision(ctx: Context, pid: str, decision: str, reason: str, by: str) -> Emit:
    prop = ctx.proposals[pid]
    if decision == "rejected":
        prop["status"] = "rejected"
        prop["decision_reason"] = reason
        ctx.memory.add("decision", key=prop["key"], decision="rejected", reason=reason,
                       proposal=pid, week=ctx.week, by=by)
        return [("proposal_rejected", {"proposal": pid, "reason": reason, "by": by})]
    uc = dict(prop["use_case"])
    uc["validated"] = True
    ctx.library[uc["id"]] = uc
    prop["status"] = "merged"
    prop["decision_reason"] = reason
    ctx.memory.add("decision", key=prop["key"], decision="merged", reason=reason,
                   proposal=pid, week=ctx.week, by=by)
    return [("rule_merged", {"proposal": pid, "use_case": uc["id"], "kind": prop["kind"], "by": by})]


class EngineerReviewNode(Node):
    name = "engineer_review"
    subscribes = ("validation_passed",)

    def handle(self, event, ctx: Context) -> Emit:
        pid = event.payload["proposal"]
        prop = ctx.proposals[pid]
        if ctx.review_mode == "manual":
            prop["status"] = "awaiting_review"
            return [("review_requested", {"proposal": pid, "key": prop["key"]})]
        reject = ctx.review_policy.get("reject", {})
        if prop["key"] in reject:
            return apply_decision(ctx, pid, "rejected", reject[prop["key"]], by="review_policy")
        return apply_decision(ctx, pid, "merged", "approved", by="review_policy")
