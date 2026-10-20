"""Local web dashboard (Python standard library only).

    python3 -m lyd serve            # then open http://127.0.0.1:8765

Pages: overview (coverage, review queue, proposals), weekly reports, monthly
advisory, run trace and chat. Approve / reject in the review queue goes
through the same platform as chat and GitHub sync. Listens on localhost only.
"""
from __future__ import annotations

import html
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

from . import advisory, attack
from .chat import Chat
from .nodes.coverage import covered_techniques, priority_techniques, score
from .platform import Platform

esc = html.escape

CSS = """
:root{--bg:#f7f6f2;--card:#fff;--ink:#1f1f1d;--muted:#6b6a65;--line:#e2e0d8;--accent:#185fa5;--good:#1d9e75;--bad:#c4413f;--warn:#b7791f}
@media (prefers-color-scheme:dark){:root{--bg:#1b1b19;--card:#242422;--ink:#ecebe6;--muted:#a3a29b;--line:#3a3a36;--accent:#6aa9e9;--good:#4cc29a;--bad:#ef7a78;--warn:#e0b25a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,Segoe UI,Helvetica,Arial,sans-serif}
header{display:flex;gap:20px;align-items:center;padding:14px 24px;border-bottom:1px solid var(--line);background:var(--card);flex-wrap:wrap}
header b{font-size:16px}header a{color:var(--muted);text-decoration:none}header a:hover,header a.on{color:var(--ink)}
main{max-width:1100px;margin:0 auto;padding:24px 16px}h1{font-size:22px;font-weight:600;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}h3{font-size:15px}
.note{color:var(--muted);font-size:13px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.kpi{font-size:26px;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:500}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;min-width:120px}.bar i{display:block;height:100%;background:var(--good)}
.pill{display:inline-block;padding:1px 8px;border-radius:9px;font-size:12px;border:1px solid var(--line)}
.merged{color:var(--good)}.rejected,.failed{color:var(--bad)}.awaiting_review{color:var(--warn)}
form.inline{display:flex;gap:6px;flex-wrap:wrap}input[type=text]{flex:1;min-width:180px;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink)}
button{padding:6px 12px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink);cursor:pointer}button.ok{border-color:var(--good)}button.no{border-color:var(--bad)}
code{background:var(--line);padding:1px 5px;border-radius:4px;font-size:13px}blockquote{margin:12px 0;padding:8px 14px;border-left:3px solid var(--accent);color:var(--muted)}
#log{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;min-height:240px;white-space:pre-wrap;font-size:14px}
#log .you{color:var(--accent);margin-top:10px}pre.mermaid{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px;overflow:auto}
.flash{background:var(--card);border:1px solid var(--accent);border-radius:8px;padding:10px 14px;margin-bottom:12px}
"""


def inline(text: str) -> str:
    t = esc(text)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r'<a href="\2">\1</a>', t)
    return t


def md(text: str) -> str:
    """Small Markdown renderer for the platform's own reports."""
    out, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            lang = line[3:].strip()
            block = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                block.append(lines[i])
                i += 1
            cls = ' class="mermaid"' if lang == "mermaid" else ""
            out.append(f"<pre{cls}>{esc(chr(10).join(block))}</pre>")
        elif line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            i -= 1
            head, body = rows[0], [r for r in rows[1:] if not set("".join(r)) <= set("-: ")]
            out.append("<table><tr>" + "".join(f"<th>{inline(c)}</th>" for c in head) + "</tr>"
                       + "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in body)
                       + "</table>")
        elif re.match(r"#{1,4} ", line):
            n = len(line.split(" ")[0])
            out.append(f"<h{n}>{inline(line[n + 1:])}</h{n}>")
        elif line.startswith("> "):
            out.append(f"<blockquote>{inline(line[2:])}</blockquote>")
        elif re.match(r"(- |\d+\. )", line):
            items = []
            while i < len(lines) and re.match(r"(- |\d+\. )", lines[i]):
                items.append(re.sub(r"^(- |\d+\. )", "", lines[i]))
                i += 1
            i -= 1
            out.append("<ul>" + "".join(f"<li>{inline(x)}</li>" for x in items) + "</ul>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
        i += 1
    return "\n".join(out)


class App:
    def __init__(self, platform: Platform):
        self.p = platform
        self.chat = Chat(platform)
        self.lock = threading.Lock()

    def page(self, title: str, body: str, active: str = "", mermaid: bool = False) -> str:
        nav = "".join(f'<a href="{u}" class="{"on" if active == u else ""}">{n}</a>' for u, n in
                      [("/", "Overview"), ("/reports", "Weekly reports"), ("/advisory", "Monthly advisory"),
                       ("/trace", "Run trace"), ("/chat", "Chat")])
        script = ('<script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"></script>'
                  '<script>mermaid.initialize({startOnLoad:true,securityLevel:"strict",theme:'
                  'matchMedia("(prefers-color-scheme: dark)").matches?"dark":"default"});</script>') if mermaid else ""
        return (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                f"<title>{esc(title)} · Leverage your detection</title><style>{CSS}</style></head><body>"
                f"<header><b>Leverage your detection</b>{nav}</header><main>{body}</main>{script}</body></html>")

    def overview(self, flash: str = "") -> str:
        ctx = self.p.ctx
        s = score(ctx)
        prio = priority_techniques(ctx)
        covered = covered_techniques(ctx)
        data = attack.load()
        props = list(ctx.proposals.values())
        counts = {k: sum(1 for p in props if p["status"] == k) for k in ("awaiting_review", "merged", "rejected", "failed")}
        b = [f'<div class="flash">{esc(flash)}</div>' if flash else "",
             f"<h1>{esc(ctx.profile['name'])}</h1>",
             f"<div class=note>Threat groups: {esc(', '.join(data['groups'][g]['name'] for g in ctx.profile['threat_groups']))}"
             f" · ATT&amp;CK v{esc(data['attack_release'])} · current period {esc(ctx.week)} · review mode {esc(ctx.review_mode)}"
             f" · placeholder data</div>",
             '<div class=grid>',
             f'<div class=card><div class=note>Priority coverage</div><div class=kpi>{s["pct"]}%</div><div class=note>{s["covered"]} of {s["priority"]} techniques</div></div>',
             f'<div class=card><div class=note>Waiting for review</div><div class=kpi>{counts["awaiting_review"]}</div><div class=note>proposals</div></div>',
             f'<div class=card><div class=note>Merged / rejected</div><div class=kpi>{counts["merged"]} / {counts["rejected"]}</div><div class=note>{counts["failed"]} blocked by validation</div></div>',
             f'<div class=card><div class=note>Needs a log source</div><div class=kpi>{s["no_data"]}</div><div class=note>techniques</div></div>',
             "</div>"]
        queue = self.p.awaiting()
        b.append("<h2>Review queue</h2>")
        if queue:
            b.append("<table><tr><th>Proposal</th><th>Why</th><th>Decision</th></tr>")
            for p in queue:
                b.append(f"<tr><td><b>{esc(p['id'])}</b><br><span class=note>{esc(p['kind'])} · {esc(p['use_case']['id'])}</span></td>"
                         f"<td>{esc(p['reason'])}</td><td><form class=inline method=post action=/review>"
                         f"<input type=hidden name=pid value='{esc(p['id'])}'>"
                         f"<input type=text name=reason placeholder='Reason (required to reject)'>"
                         f"<button class=ok name=decision value=merged>Approve</button>"
                         f"<button class=no name=decision value=rejected>Reject</button></form></td></tr>")
            b.append("</table>")
        else:
            b.append("<p class=note>Nothing waiting. Ask the chat to build a use case, or run a week in manual review mode.</p>")
        b.append("<h2>Coverage by tactic</h2><table><tr><th>Tactic</th><th>Covered</th><th></th></tr>")
        for tactic in data["tactic_order"]:
            ids = [t for t in prio if tactic in (attack.technique(t) or {}).get("tactics", [])]
            if not ids:
                continue
            got = sum(1 for t in ids if t in covered)
            pct = round(100 * got / len(ids))
            b.append(f"<tr><td>{esc(tactic)}</td><td>{got} of {len(ids)}</td><td><div class=bar><i style='width:{pct}%'></i></div></td></tr>")
        b.append("</table><h2>Top recommended use cases</h2><table><tr><th>Technique</th><th>Score</th><th>Used by</th></tr>")
        for x in advisory.rank(ctx, top=5)["top"]:
            b.append(f"<tr><td><b>{esc(x['technique'])}</b> {esc(x['name'])}</td><td>{x['score']}</td><td>{esc(', '.join(x['groups']))}</td></tr>")
        b.append("</table><h2>All proposals</h2><table><tr><th>ID</th><th>Kind</th><th>Use case</th><th>Period</th><th>Status</th><th>PR</th></tr>")
        for p in sorted(props, key=lambda x: x["id"], reverse=True):
            pr = p.get("pr")
            link = f"<a href='{esc(pr['url'])}'>#{pr['number']}</a>" if pr else ""
            b.append(f"<tr><td>{esc(p['id'])}</td><td>{esc(p['kind'])}</td><td>{esc(p['use_case']['id'])}</td>"
                     f"<td>{esc(p['week'])}</td><td class='{esc(p['status'])}'>{esc(p['status'].replace('_', ' '))}</td><td>{link}</td></tr>")
        b.append("</table>")
        return self.page("Overview", "".join(b), "/")

    def reports(self, week: str | None) -> str:
        weeks = sorted(d.name for d in self.p.out.iterdir() if d.is_dir() and (d / "report.md").exists())
        if week and week in weeks:
            text = (self.p.out / week / "report.md").read_text(encoding="utf-8")
            body = (f"<p class=note><a href='/reports'>All reports</a> · <a href='/layer?week={esc(week)}'>Download Navigator layer</a> "
                    f"(open it in the <a href='https://mitre-attack.github.io/attack-navigator/'>ATT&amp;CK Navigator</a>)</p>" + md(text))
            return self.page(week, body, "/reports")
        items = "".join(f"<li><a href='/reports?week={esc(w)}'>{esc(w)}</a></li>" for w in weeks) or "<li>No reports yet.</li>"
        return self.page("Weekly reports", f"<h1>Weekly reports</h1><ul>{items}</ul>", "/reports")

    def advisory_page(self) -> str:
        return self.page("Monthly advisory", md(advisory.markdown(self.p.ctx, "this month")), "/advisory")

    def trace(self) -> str:
        f = self.p.out / "run-trace.md"
        body = md(f.read_text(encoding="utf-8")) if f.exists() else "<p>No run trace yet. Run the demo first: <code>python3 -m lyd demo</code> on Mac, <code>py -m lyd demo</code> on Windows.</p>"
        return self.page("Run trace", body, "/trace", mermaid=True)

    def chat_page(self) -> str:
        body = ("<h1>Chat</h1><p class=note>Try: what's our coverage? · what should we build next? · "
                "build a use case for T1204.001 · what's waiting for review? · why was PR-009 rejected?</p>"
                "<div id=log></div><form id=f class=inline style='margin-top:10px'>"
                "<input type=text id=q autocomplete=off placeholder='Ask the platform' autofocus><button>Send</button></form>"
                "<script>const log=document.getElementById('log'),q=document.getElementById('q');"
                "function add(c,t){const d=document.createElement('div');d.className=c;d.textContent=t;log.appendChild(d);}"
                "document.getElementById('f').onsubmit=async e=>{e.preventDefault();const t=q.value.trim();if(!t)return;"
                "add('you','you> '+t);q.value='';try{const r=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},"
                "body:JSON.stringify({q:t})});const j=await r.json();add('bot',j.answer);}catch(err){add('bot','Error: '+err);}"
                "log.scrollTop=log.scrollHeight;};</script>")
        return self.page("Chat", body, "/chat")


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # quiet
            pass

        def send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8", extra: dict | None = None):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            with app.lock:
                if u.path == "/":
                    return self.send(200, app.overview(qs.get("msg", [""])[0]))
                if u.path == "/reports":
                    return self.send(200, app.reports(qs.get("week", [None])[0]))
                if u.path == "/advisory":
                    return self.send(200, app.advisory_page())
                if u.path == "/trace":
                    return self.send(200, app.trace())
                if u.path == "/chat":
                    return self.send(200, app.chat_page())
                if u.path == "/layer":
                    week = qs.get("week", [""])[0]
                    f = app.p.out / week / "navigator-layer.json"
                    if re.fullmatch(r"[\w-]+", week) and f.exists():
                        return self.send(200, f.read_text(encoding="utf-8"), "application/json",
                                         {"Content-Disposition": f'attachment; filename="{week}-layer.json"'})
            self.send(404, app.page("Not found", "<p>Not found.</p>"))

        def do_POST(self):
            length = min(int(self.headers.get("Content-Length") or 0), 100_000)
            raw = self.rfile.read(length).decode()
            u = urlparse(self.path)
            with app.lock:
                if u.path == "/api/chat":
                    try:
                        q = str(json.loads(raw).get("q", ""))[:2000]
                    except ValueError:
                        return self.send(400, json.dumps({"answer": "bad request"}), "application/json")
                    return self.send(200, json.dumps({"answer": app.chat.ask(q)}), "application/json")
                if u.path == "/review":
                    f = parse_qs(raw)
                    pid, decision = f.get("pid", [""])[0], f.get("decision", [""])[0]
                    reason = f.get("reason", [""])[0][:500]
                    msg = app.chat.decide(pid, decision, reason or ("approved in dashboard" if decision == "merged" else ""))
                    self.send_response(303)
                    self.send_header("Location", "/?msg=" + quote(msg[:300]))
                    self.end_headers()
                    return
            self.send(404, "not found", "text/plain")

    return Handler


def serve(platform: Platform, port: int = 8765) -> None:
    app = App(platform)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    print(f"Dashboard: http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()
