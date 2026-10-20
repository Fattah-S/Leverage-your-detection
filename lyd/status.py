"""Status report: the current situation, on demand or on a schedule.

    python -m lyd report                  write one now
    python -m lyd schedule --every weekly --day sun --at 08:00

Numbers come from code; the LLM writes only the summary paragraph. Each report
is saved as <out>/status-YYYY-MM-DD/report.md (+ Navigator layer), appears in
the dashboard under Weekly reports, and records a snapshot so the next report
can show what changed.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from pathlib import Path

from . import advisory, attack
from .nodes.coverage import score
from .nodes.posture import navigator_layer

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def markdown(platform, now: datetime) -> str:
    ctx = platform.ctx
    s = score(ctx)
    snaps = [h for h in ctx.coverage_history if h.get("point") == "status_report"]
    prev = snaps[-1] if snaps else None
    since = prev["at"] if prev else None
    decisions = [m for m in ctx.memory.items if m.get("kind") == "decision"
                 and (since is None or m.get("at", "") > since)]
    waiting = platform.awaiting()
    r = advisory.rank(ctx, top=5)
    change = (f"{prev['pct']}% → {s['pct']}% since the last report ({prev['at'][:10]})" if prev
              else f"{s['pct']}% (first status report)")
    summary = ctx.llm.write("status_summary", {
        "date": now.strftime("%Y-%m-%d"), "coverage_pct": s["pct"], "covered": s["covered"], "priority": s["priority"],
        "previous_pct": prev["pct"] if prev else None, "waiting_review": len(waiting),
        "decisions_since_last": len(decisions), "top_gap": r["top"][0]["technique"] if r["top"] else None,
        "needs_log_source": len(r["onboard"])})
    groups = ", ".join(attack.load()["groups"][g]["name"] for g in ctx.profile["threat_groups"])
    lines = [f"# Status report: {now.strftime('%Y-%m-%d %H:%M')}", "",
             f"{ctx.profile['name']} · threat groups: {groups} · ATT&CK v{attack.load()['attack_release']} · LLM: {ctx.llm.name}",
             "", "## Summary", "", summary, "",
             "## Coverage of priority techniques", "",
             f"- Covered: {s['covered']} of {s['priority']} ({change})",
             f"- Need a log source first: {s['no_data']}", "",
             "## Waiting for your review", ""]
    lines += [f"- {p['id']} {p['kind']} {p['use_case']['id']}: {p['reason']}" for p in waiting] or ["- Nothing waiting."]
    lines += ["", "## Decisions since the last report", ""]
    lines += [f"- {m.get('proposal')}: {m['decision']} by {m.get('by', 'engineer')} ({m['reason']})" for m in decisions] \
        or ["- None."]
    lines += ["", "## Recommended next use cases", "", "| Technique | Name | Score | Used by |", "| --- | --- | --- | --- |"]
    lines += [f"| {x['technique']} | {x['name']} | {x['score']} | {', '.join(x['groups'])} |" for x in r["top"]]
    if r["validate"]:
        lines += ["", "Test before writing new ones: " + ", ".join(f"{x['use_case']} ({x['technique']})" for x in r["validate"])]
    if r["onboard"]:
        lines += ["", "Onboard a log source first: " + ", ".join(f"{x['technique']} {x['name']}" for x in r["onboard"])]
    lines += ["", "> Prototype on placeholder data: the method is real, the inputs are not.", ""]
    return "\n".join(lines)


def write(platform, now: datetime | None = None) -> Path:
    now = now or datetime.now()
    text = markdown(platform, now)
    d = platform.out / f"status-{now.strftime('%Y-%m-%d')}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.md").write_text(text, encoding="utf-8")
    (d / "navigator-layer.json").write_text(json.dumps(navigator_layer(platform.ctx, d.name), indent=1), encoding="utf-8")
    s = score(platform.ctx)
    platform.ctx.coverage_history.append({"point": "status_report", "at": now.isoformat(timespec="seconds"), **s})
    platform.save()
    return d / "report.md"


def next_run(now: datetime, every: str, at: str, day: str = "mon") -> datetime:
    """Next time the schedule fires, strictly after `now`."""
    hh, mm = (int(x) for x in at.split(":"))
    candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if every == "daily":
        return candidate if candidate > now else candidate + timedelta(days=1)
    if every == "weekly":
        ahead = (DAYS.index(day) - now.weekday()) % 7
        candidate += timedelta(days=ahead)
        return candidate if candidate > now else candidate + timedelta(days=7)
    raise ValueError("every must be 'daily' or 'weekly'")


def run_schedule(make_platform, every: str, at: str, day: str = "mon", check_seconds: int = 30) -> None:
    """Built-in scheduler: works the same on macOS, Windows and Linux.

    It checks the clock every `check_seconds`, so if the computer was asleep at
    the scheduled time, the report is written as soon as it wakes up.
    """
    due = next_run(datetime.now(), every, at, day)
    print(f"Scheduler running: {every} at {at}" + (f" on {day}" if every == "weekly" else "")
          + f". Next report: {due:%Y-%m-%d %H:%M}. Leave this window open; Ctrl+C to stop.")
    try:
        while True:
            if datetime.now() >= due:
                p = make_platform()
                path = write(p)
                p.bus.db.close()
                print(f"{datetime.now():%Y-%m-%d %H:%M} report written: {path}")
                due = next_run(datetime.now(), every, at, day)
                print(f"Next report: {due:%Y-%m-%d %H:%M}")
            time.sleep(check_seconds)
    except KeyboardInterrupt:
        print("\nScheduler stopped.")
