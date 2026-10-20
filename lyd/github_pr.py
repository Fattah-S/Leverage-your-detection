"""Real GitHub pull requests for proposals (Detection-as-Code).

open:  every proposal waiting for review becomes a branch with one file,
       detections/<use-case id>.json, and a pull request whose description
       holds the reason and the validation checks.
sync:  merged pull requests become "merged" decisions; pull requests closed
       without merging become "rejected" decisions, with the last comment on
       the PR as the reason. Decisions go into memory like any other.

Authentication: GITHUB_TOKEN environment variable, or the GitHub CLI (`gh auth
login`). Pull requests are opened under that account. Branches are created in
a temporary git worktree, so your working folder is not touched.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from .platform import ROOT, Platform

API = "https://api.github.com"
MARKER = "<!-- lyd:{pid} -->"


def token() -> str | None:
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    if shutil.which("gh"):
        r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    return None


def http(method: str, path: str, tok: str, body: dict | None = None) -> dict | list:
    req = urllib.request.Request(f"{API}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {tok}", "Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "leverage-your-detection"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read() or b"{}")


def use_case_file(prop: dict) -> tuple[str, str]:
    uc = {k: v for k, v in prop["use_case"].items() if k != "validated"}
    doc = {**uc, "proposal": prop["id"], "proposal_kind": prop["kind"], "reason": prop["reason"],
           "detection": "Detection logic is written here by the engineer (or the LLM) before merge."}
    return f"detections/{uc['id']}.json", json.dumps(doc, indent=2) + "\n"


def title(prop: dict) -> str:
    verb = {"new_use_case": "New use case", "watchlist": "Exposure watchlist", "fix": "Fix",
            "tuning": "Tune"}.get(prop["kind"], prop["kind"])
    return f"[{prop['id']}] {verb}: {prop['use_case']['id']} {prop['use_case']['title']}"[:240]


def body(prop: dict) -> str:
    checks = "\n".join(f"| {c['check']} | {'pass' if c['ok'] else 'FAIL'} | {c['detail']} |" for c in prop.get("checks", []))
    return (f"{MARKER.format(pid=prop['id'])}\n"
            f"Opened by the **{prop['kind']}** flow of Leverage your detection.\n\n"
            f"**Why:** {prop['reason']}\n\n"
            f"| Check | Result | Detail |\n| --- | --- | --- |\n{checks}\n\n"
            "**To decide:** merge this pull request to accept it, or close it with a comment explaining why. "
            "The comment is saved to the platform's memory, so the same proposal is not made again.\n")


def open_prs(platform: Platform, repo: str, base: str = "main", dry_run: bool = True,
             tok: str | None = None, api=http) -> list[dict]:
    pending = [p for p in platform.awaiting() if not p.get("pr")]
    results = []
    if dry_run:
        out = platform.out / "pull-requests"
        out.mkdir(parents=True, exist_ok=True)
        for p in pending:
            path, content = use_case_file(p)
            (out / f"{p['id']}.md").write_text(f"# {title(p)}\n\nBranch: `lyd/{p['id'].lower()}` → `{base}`\n\n"
                                               f"{body(p)}\n## File `{path}`\n\n```json\n{content}```\n", encoding="utf-8")
            results.append({"proposal": p["id"], "dry_run": True, "file": str(out / f"{p['id']}.md")})
        return results

    tok = tok or token()
    if not tok:
        raise RuntimeError("No GitHub token: set GITHUB_TOKEN or run `gh auth login`.")
    subprocess.run(["git", "-C", str(ROOT), "fetch", "-q", "origin", base], check=True)
    for p in pending:
        branch = f"lyd/{p['id'].lower()}"
        path, content = use_case_file(p)
        tmp = Path(tempfile.mkdtemp(prefix="lyd-pr-"))
        wt = tmp / "wt"
        try:
            subprocess.run(["git", "-C", str(ROOT), "worktree", "add", "-q", "-B", branch, str(wt), f"origin/{base}"],
                           check=True)
            (wt / path).parent.mkdir(parents=True, exist_ok=True)
            (wt / path).write_text(content, encoding="utf-8")
            subprocess.run(["git", "-C", str(wt), "add", path], check=True)
            subprocess.run(["git", "-C", str(wt), "commit", "-q", "-m", title(p)], check=True)
            subprocess.run(["git", "-C", str(wt), "push", "-q", "-f", "origin", branch], check=True)
        finally:
            subprocess.run(["git", "-C", str(ROOT), "worktree", "remove", "--force", str(wt)], capture_output=True)
            shutil.rmtree(tmp, ignore_errors=True)
        pr = api("POST", f"/repos/{repo}/pulls", tok, {"title": title(p), "head": branch, "base": base, "body": body(p)})
        p["pr"] = {"number": pr["number"], "url": pr["html_url"], "branch": branch}
        results.append({"proposal": p["id"], "number": pr["number"], "url": pr["html_url"]})
    platform.save()
    return results


def sync_prs(platform: Platform, repo: str, tok: str | None = None, api=http) -> list[dict]:
    tok = tok or token()
    if not tok:
        raise RuntimeError("No GitHub token: set GITHUB_TOKEN or run `gh auth login`.")
    results = []
    for p in platform.awaiting():
        pr = p.get("pr")
        if not pr:
            continue
        info = api("GET", f"/repos/{repo}/pulls/{pr['number']}", tok)
        if info.get("merged_at"):
            who = (info.get("merged_by") or {}).get("login", "engineer")
            platform.decide(p["id"], "merged", f"merged on GitHub by {who}", by=f"github:{who}")
            results.append({"proposal": p["id"], "decision": "merged"})
        elif info.get("state") == "closed":
            comments = api("GET", f"/repos/{repo}/issues/{pr['number']}/comments", tok) or []
            reason = (comments[-1]["body"].strip() if comments else "") or "closed on GitHub without a comment"
            who = (comments[-1]["user"]["login"] if comments else "engineer")
            platform.decide(p["id"], "rejected", reason, by=f"github:{who}")
            results.append({"proposal": p["id"], "decision": "rejected", "reason": reason})
    return results
