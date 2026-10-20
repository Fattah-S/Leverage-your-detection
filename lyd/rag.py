"""Retrieval memory (RAG search) in pure Python.

A TF-IDF index over everything the platform knows: ATT&CK techniques and
groups, the use-case library, proposals with their reasons, engineer
decisions, intel items and weekly reports. The chatbot and the monthly
advisory retrieve from it; with a local LLM, retrieved documents are passed
to the model as data so its answers stay grounded.

Swappable later for an embedding model and a vector database.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from . import attack

TOKEN = re.compile(r"[a-z0-9]+(?:\.[0-9]+)?")
STOP = set("a an and are as at be by for from has have in is it its of on or that the this to was were with "
           "what which why who how our we you your do does did not no".split())


KIND_WEIGHT = {"technique": 0.6}   # reference data ranks below the platform's own records


def stem(t: str) -> str:
    if len(t) > 4 and not t[0].isdigit():
        for suffix in ("ing", "ed", "es", "s"):
            if t.endswith(suffix) and len(t) - len(suffix) >= 3:
                return t[: -len(suffix)]
    return t


def tokens(text: str) -> list[str]:
    return [stem(t) for t in TOKEN.findall(text.lower()) if t not in STOP]


@dataclass
class Doc:
    id: str
    kind: str
    title: str
    text: str
    ref: dict


class Index:
    def __init__(self, docs: list[Doc]):
        self.docs = docs
        self.tf = [Counter(tokens(d.title + " " + d.text)) for d in docs]
        df = Counter(t for tf in self.tf for t in tf)
        n = len(docs)
        self.idf = {t: math.log((1 + n) / (1 + c)) + 1 for t, c in df.items()}
        self.norm = [math.sqrt(sum((c * self.idf[t]) ** 2 for t, c in tf.items())) or 1.0 for tf in self.tf]

    def search(self, query: str, k: int = 5, kinds: tuple[str, ...] | None = None) -> list[tuple[float, Doc]]:
        q = Counter(tokens(query))
        qv = {t: c * self.idf.get(t, 0.0) for t, c in q.items()}
        qn = math.sqrt(sum(v * v for v in qv.values())) or 1.0
        scored = []
        for i, d in enumerate(self.docs):
            if kinds and d.kind not in kinds:
                continue
            dot = sum(v * self.tf[i].get(t, 0) * self.idf.get(t, 0.0) for t, v in qv.items())
            if dot > 0:
                scored.append((KIND_WEIGHT.get(d.kind, 1.0) * dot / (qn * self.norm[i]), d))
        scored.sort(key=lambda x: -x[0])
        return scored[:k]


def build(ctx, reports: dict[str, str] | None = None) -> Index:
    data = attack.load()
    prio = attack.group_techniques(ctx.profile["threat_groups"])
    docs: list[Doc] = []
    for tid, t in data["techniques"].items():
        groups = prio.get(tid, [])
        docs.append(Doc(f"tech:{tid}", "technique", f"{tid} {t['name']}",
                        f"tactics {' '.join(t['tactics'])}" + (f" used by {' '.join(groups)}" if groups else ""),
                        {"technique": tid}))
    for uc in ctx.library.values():
        docs.append(Doc(f"uc:{uc['id']}", "use_case", f"{uc['id']} {uc['title']}",
                        f"techniques {' '.join(uc['techniques'])} log source {uc.get('log_source')} "
                        f"status {uc.get('status')} owner {uc.get('owner')}", {"use_case": uc["id"]}))
    for p in ctx.proposals.values():
        docs.append(Doc(f"pr:{p['id']}", "proposal", f"{p['id']} {p['kind']} {p['use_case']['id']}",
                        f"{p['key']} status {p['status']} week {p['week']} {p['reason']} "
                        f"{p.get('decision_reason', '')}", {"proposal": p["id"]}))
    for i, m in enumerate(ctx.memory.items):
        docs.append(Doc(f"mem:{i}", "decision", f"decision {m.get('proposal')} {m.get('decision')}",
                        f"{m.get('key')} {m.get('reason')} {m.get('week')} by {m.get('by', '')}", m))
    for item in ctx.intel_seen:
        docs.append(Doc(f"intel:{item['id']}:{item['week']}", "intel", f"{item['id']} {item.get('title', item.get('type'))}",
                        " ".join(str(v) for k, v in item.items() if k not in ("id", "title")), item))
    for week, text in (reports or {}).items():
        docs.append(Doc(f"report:{week}", "report", f"weekly report {week}", text, {"week": week}))
    return Index(docs)
