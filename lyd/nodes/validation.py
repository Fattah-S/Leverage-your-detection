"""Validation node: the CI step. Deterministic checks only; the LLM is never asked
whether its own work is good.

Prototype checks are at the metadata level. Replay tests against recorded
telemetry belong here too once detection logic is added.
"""
from __future__ import annotations

from .. import attack
from .base import Context, Emit, Node


def checks_for(prop: dict, ctx: Context) -> list[dict]:
    uc = prop["use_case"]
    sources = set(ctx.profile["log_sources"])
    res = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        res.append({"check": name, "ok": bool(ok), "detail": detail})

    check("techniques_valid", all(attack.technique(t) for t in uc["techniques"]),
          ", ".join(uc["techniques"]))
    check("owner_set", bool(uc.get("owner")))
    if uc.get("status") == "active":
        check("log_source_collected", uc.get("log_source") in sources, uc.get("log_source", ""))
    if prop["kind"] == "new_use_case":
        dup = [u["id"] for u in ctx.library.values() if u.get("status") == "active"
               and set(u["techniques"]) & set(uc["techniques"]) and u.get("log_source") == uc.get("log_source")]
        check("no_duplicate", not dup, ", ".join(dup))
    if prop["kind"] == "watchlist":
        check("expiry_set", 0 < uc.get("expires_days", 0) <= 90, f"{uc.get('expires_days')} days")
    if prop["kind"] == "tuning":
        check("exclusion_is_narrow", len(prop["exclusion"]) >= 2,
              f"{len(prop['exclusion'])} fields (minimum 2)")
    return res


class ValidationNode(Node):
    name = "validation"
    subscribes = ("proposal_opened",)

    def handle(self, event, ctx: Context) -> Emit:
        pid = event.payload["proposal"]
        prop = ctx.proposals[pid]
        res = checks_for(prop, ctx)
        prop["checks"] = res
        failed = [c["check"] for c in res if not c["ok"]]
        if failed:
            prop["status"] = "failed"
            return [("validation_failed", {"proposal": pid, "failed": failed})]
        prop["status"] = "validated"
        return [("validation_passed", {"proposal": pid, "checks": len(res)})]
