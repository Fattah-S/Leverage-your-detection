"""Chatbot for detection engineers.

Questions are answered from the platform's own data. Requests ("build a use
case for T1204.002", "approve PR-015") become events on the bus, so the same
agents handle them as handle scheduled work. Anything else goes to retrieval
memory (RAG); with a local LLM the retrieved documents are summarised.
"""
from __future__ import annotations

import re

from . import advisory, attack, rag
from .nodes.coverage import covered_techniques, priority_techniques, score
from .platform import Platform

TID = r"T\d{4}(?:\.\d{3})?"
HELP = """I can answer from the platform's data:
- "what's our coverage?" or "coverage for credential access"
- "what should we build next?" (monthly advisory)
- "build a use case for T1204.002"
- "what's waiting for review?", "approve PR-015", "reject PR-016 because <reason>"
- "why was PR-009 rejected?" or "explain PR-007"
- "which rules are noisy?", "any broken rules?"
- "tell me about T1003.001"
- "what changed this week?"
Anything else, I search the platform's memory."""


class Chat:
    def __init__(self, platform: Platform):
        self.p = platform

    # ----------------------------------------------------------------- routing
    def ask(self, text: str) -> str:
        q = text.strip()
        low = q.lower()
        if not q or low in ("help", "?"):
            return HELP
        m = re.search(r"\b(approve|merge)\s+(pr-\d{3})\b", low)
        if m:
            return self.decide(m.group(2).upper(), "merged", "approved in chat")
        m = re.search(r"\breject\s+(pr-\d{3})\b(?:\s*(?:because|:|-)\s*(.*))?", q, re.I)
        if m:
            return self.decide(m.group(1).upper(), "rejected", (m.group(2) or "").strip())
        m = re.search(rf"\b(build|create|draft|write|add)\b.*?\b({TID})\b", q, re.I)
        if m:
            return self.build(m.group(2).upper())
        m = re.search(r"\bpr-\d{3}\b", low)
        if m:
            return self.proposal(m.group(0).upper())
        if "coverage" in low:
            return self.coverage(low)
        if re.search(r"\b(next|recommend|advis|priorit|gaps?)\b", low):
            return self.next_steps()
        if re.search(r"\b(review|queue|pending|awaiting)\b", low):
            return self.queue()
        if re.search(r"\b(noisy|noise|false positives?|fp)\b", low):
            return self.noise()
        if re.search(r"\b(broken|health|stale|fix)\b", low):
            return self.health()
        m = re.search(rf"\b({TID})\b", q, re.I)
        if m:
            return self.technique(m.group(1).upper())
        if re.search(r"\b(report|this week|changed|summary)\b", low):
            return self.latest_report()
        return self.search(q)

    # ------------------------------------------------------------------ intents
    def coverage(self, low: str) -> str:
        ctx = self.p.ctx
        s = score(ctx)
        prio = priority_techniques(ctx)
        covered = covered_techniques(ctx)
        data = attack.load()
        lines = [f"Priority coverage: {s['covered']} of {s['priority']} techniques ({s['pct']}%) used by "
                 + ", ".join(data["groups"][g]["name"] for g in ctx.profile["threat_groups"])
                 + f". {s['no_data']} need a log source first."]
        wanted = [t for t in data["tactic_order"] if t.replace("-", " ") in low]
        tactics = wanted or data["tactic_order"]
        lines.append("")
        for tactic in tactics:
            ids = [t for t in prio if tactic in (attack.technique(t) or {}).get("tactics", [])]
            if not ids:
                continue
            got = [t for t in ids if t in covered]
            lines.append(f"- {tactic}: {len(got)} of {len(ids)} covered"
                         + (f" ({', '.join(sorted(got))})" if got and wanted else ""))
        if wanted:
            gaps = [t for t in prio if t not in covered and any(w in (attack.technique(t) or {}).get("tactics", [])
                                                              for w in wanted)]
            if gaps:
                lines.append(f"Open in {', '.join(wanted)}: " + ", ".join(sorted(gaps)[:12]))
        return "\n".join(lines)

    def next_steps(self) -> str:
        r = advisory.rank(self.p.ctx, top=5)
        lines = [f"Top 5 of {r['total_open']} ranked priority gaps:"]
        for i, x in enumerate(r["top"], 1):
            lines.append(f"{i}. {x['technique']} {x['name']} (score {x['score']}; used by {', '.join(x['groups'])}"
                         + (f"; in intel {', '.join(x['intel'])}" if x["intel"] else "") + ")")
        if r["rejected"]:
            lines.append("Left out because an engineer rejected them: "
                         + ", ".join(f"{x['technique']} ({x['reason']})" for x in r["rejected"]))
        if r["validate"]:
            lines.append("Test before writing new ones: " + ", ".join(f"{x['use_case']} ({x['technique']})" for x in r["validate"]))
        lines.append('Say "build a use case for <technique>" to start one.')
        return "\n".join(lines)

    def build(self, tid: str) -> str:
        if attack.technique(tid) is None:
            new = attack.load()["revoked_by"].get(tid)
            if new:
                return f"{tid} was retired in ATT&CK v{attack.load()['attack_release']}; it is now {new} {attack.name(new)}. Ask for {new}."
            return f"{tid} is not a technique in ATT&CK v{attack.load()['attack_release']}."
        chain = self.p.submit("new_ttp", {"technique": tid, "relevance": 100,
                                          "trigger": "engineer request in chat"})
        types = [e["type"] for e in chain]
        path = " → ".join(f"{e['type']} ({e['source']})" for e in chain)
        name = attack.name(tid)
        if "covered" in types:
            ucs = [u["id"] for u in self.p.ctx.library.values() if tid in u["techniques"] and u.get("validated")]
            return f"{tid} {name} is already covered by {', '.join(ucs)}.\nAgents: {path}"
        if "needs_log_source" in types:
            return f"{tid} {name}: no collected log source can see it, so a rule would never fire. Onboard a log source first.\nAgents: {path}"
        skip = next((e for e in chain if e["type"] == "skipped_previously_rejected"), None)
        if skip:
            return (f"Not proposed: an engineer rejected {tid} in {skip['payload']['rejected_in']} "
                    f"(\"{skip['payload']['reason']}\").\nAgents: {path}")
        dup = next((e for e in chain if e["type"] == "skipped_duplicate"), None)
        if dup:
            return f"Not proposed: {dup['payload'].get('reason', 'a proposal for this is already open')}.\nAgents: {path}"
        opened = next((e for e in chain if e["type"] == "proposal_opened"), None)
        if not opened:
            return f"No proposal was opened.\nAgents: {path}"
        pid = opened["payload"]["proposal"]
        prop = self.p.ctx.proposals[pid]
        if prop["status"] == "failed":
            failed = [c for c in prop["checks"] if not c["ok"]]
            return (f"Drafted {pid} for {tid} {name}, but validation blocked it: "
                    + "; ".join(f"{c['check']} {c['detail']}".strip() for c in failed) + f".\nAgents: {path}")
        state = {"awaiting_review": "is waiting for your review (say \"approve " + pid + "\" or \"reject " + pid + " because ...\")",
                 "merged": "was merged", "rejected": "was rejected"}.get(prop["status"], prop["status"])
        return f"Drafted {pid} for {tid} {name}. Validation passed; it {state}.\nWhy: {prop['reason']}\nAgents: {path}"

    def decide(self, pid: str, decision: str, reason: str) -> str:
        try:
            chain = self.p.decide(pid, decision, reason, by="engineer_chat")
        except (KeyError, ValueError) as exc:
            return str(exc).strip("'")
        upd = next((e for e in chain if e["type"] == "coverage_updated"), None)
        tail = f" Coverage is now {upd['payload']['pct']}%." if upd else ""
        verb = "Merged" if decision == "merged" else "Rejected"
        extra = f' Reason saved to memory: "{reason}".' if decision == "rejected" else ""
        return f"{verb} {pid}.{extra}{tail}"

    def proposal(self, pid: str) -> str:
        prop = self.p.ctx.proposals.get(pid)
        if not prop:
            return f"There is no {pid}."
        lines = [f"{pid}: {prop['kind']} for {prop['use_case']['id']} ({prop['use_case']['title']}), "
                 f"{prop['week']}, status {prop['status'].replace('_', ' ')}.", f"Why proposed: {prop['reason']}"]
        if prop.get("checks"):
            lines.append("Checks: " + ", ".join(f"{c['check']} {'ok' if c['ok'] else 'FAILED'}" for c in prop["checks"]))
        if prop["status"] in ("rejected", "merged"):
            mem = [m for m in self.p.ctx.memory.items if m.get("proposal") == pid]
            if mem:
                m = mem[-1]
                lines.append(f"Decision: {m['decision']} by {m.get('by', 'engineer')}: \"{m['reason']}\"")
        return "\n".join(lines)

    def queue(self) -> str:
        items = self.p.awaiting()
        if not items:
            return "Nothing is waiting for review."
        return "Waiting for review:\n" + "\n".join(
            f"- {p['id']} {p['kind']} {p['use_case']['id']}: {p['reason'][:140]}" for p in items)

    def noise(self) -> str:
        props = [p for p in self.p.ctx.proposals.values() if p["kind"] == "tuning"]
        if not props:
            return "No noisy rules found so far."
        return "Noise tuning proposals:\n" + "\n".join(
            f"- {p['id']} ({p['week']}, {p['status'].replace('_', ' ')}): {p['use_case']['id']}: {p['reason']}" for p in props)

    def health(self) -> str:
        props = [p for p in self.p.ctx.proposals.values() if p["kind"] == "fix"]
        if not props:
            return "Rule health found no broken use cases."
        return "Rule health fixes:\n" + "\n".join(
            f"- {p['id']} ({p['week']}, {p['status'].replace('_', ' ')}): {p['use_case']['id']}: {p['reason']}" for p in props)

    def technique(self, tid: str) -> str:
        t = attack.technique(tid)
        if not t:
            new = attack.load()["revoked_by"].get(tid)
            return f"{tid} is not in ATT&CK v{attack.load()['attack_release']}" + (f"; it was replaced by {new} {attack.name(new)}." if new else ".")
        groups = priority_techniques(self.p.ctx).get(tid, [])
        ucs = [u["id"] for u in self.p.ctx.library.values() if tid in u["techniques"]]
        covered = tid in covered_techniques(self.p.ctx)
        props = [p["id"] for p in self.p.ctx.proposals.values() if tid in p["use_case"]["techniques"]]
        return (f"{tid} {t['name']} (tactics: {', '.join(t['tactics'])}).\n"
                f"Used by profile groups: {', '.join(groups) or 'none'}.\n"
                f"Covered: {'yes' if covered else 'no'}. Use cases: {', '.join(ucs) or 'none'}. "
                f"Proposals: {', '.join(props) or 'none'}.")

    def latest_report(self) -> str:
        weeks = sorted(d.name for d in self.p.out.iterdir() if d.is_dir() and (d / "report.md").exists())
        if not weeks:
            return "No weekly report yet."
        text = (self.p.out / weeks[-1] / "report.md").read_text()
        m = re.search(r"## Summary\n\n(.+?)\n", text)
        return f"{weeks[-1]}: {m.group(1) if m else 'see the report'} (full report: {self.p.out / weeks[-1] / 'report.md'})"

    def search(self, q: str) -> str:
        reports = {d.name: (d / "report.md").read_text() for d in self.p.out.iterdir()
                   if d.is_dir() and (d / "report.md").exists()}
        hits = rag.build(self.p.ctx, reports).search(q, k=4)
        if not hits:
            return "I found nothing in the platform's memory for that. Type \"help\" for what I can do."
        def preview(d):
            if d.kind == "report":
                m = re.search(r"## Summary\n\n(.+?)\n", d.text)
                return m.group(1) if m else ""
            return d.text[:200]
        facts = "\n".join(f"- [{d.kind}] {d.title}: {preview(d)}" for _, d in hits)
        answer = "From the platform's memory:\n" + facts
        if self.p.ctx.llm.name != "mock":
            try:
                return self.p.ctx.llm.write("chat_answer", {"question": q, "answer": "",
                                                            "documents": [f"{d.title}: {d.text[:500]}" for _, d in hits]})
            except OSError:
                return answer + "\n(local LLM not reachable; showing retrieved documents)"
        return answer


def repl(platform: Platform) -> None:
    chat = Chat(platform)
    print("Leverage your detection chat. Type 'help', or 'exit' to quit.")
    while True:
        try:
            q = input("\nyou> ")
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if q.strip().lower() in ("exit", "quit"):
            return
        print("\n" + chat.ask(q))
