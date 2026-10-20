"""Tests for chat, memory search, monthly advisory, GitHub pull-request flow and the dashboard."""
import json
import shutil
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from lyd import advisory, github_pr, rag
from lyd.chat import Chat
from lyd.platform import ROOT, Platform, load_json
from lyd.web import App, make_handler


def fresh_platform(tmp: Path, review: str = "auto") -> Platform:
    p = Platform(tmp / "out", fresh=True, review_mode=review)
    intel = load_json(ROOT / "samples" / "intel.json")
    stats = load_json(ROOT / "samples" / "alert_stats.json")
    for w in ("week-1", "week-2"):
        p.run_week(w, intel[w], stats[w])
    p.ctx.review_mode = "manual"   # from now on an engineer decides
    p.save()
    return p


class ChatTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.p = fresh_platform(self.tmp)
        self.chat = Chat(self.p)

    def tearDown(self):
        self.p.bus.db.close()
        shutil.rmtree(self.tmp)

    def test_coverage_answer_uses_real_numbers(self):
        s = self.p.score()
        self.assertIn(f"{s['covered']} of {s['priority']}", self.chat.ask("what's our coverage?"))

    def test_build_then_approve_raises_coverage(self):
        before = self.p.score()["covered"]
        answer = self.chat.ask("build a use case for T1204.001")
        self.assertIn("waiting for your review", answer)
        pid = self.p.awaiting()[0]["id"]
        self.assertIn("Merged", self.chat.ask(f"approve {pid}"))
        self.assertEqual(self.p.score()["covered"], before + 1)

    def test_reject_needs_reason_and_is_remembered(self):
        self.chat.ask("build a use case for T1555")
        pid = self.p.awaiting()[0]["id"]
        self.assertIn("reason is required", self.chat.ask(f"reject {pid}"))
        self.assertIn("Rejected", self.chat.ask(f"reject {pid} because browser data is out of scope"))
        again = self.chat.ask("build a use case for T1555")
        self.assertIn("Not proposed", again)
        self.assertIn("browser data is out of scope", again)

    def test_no_log_source_and_retired_technique(self):
        self.assertIn("Onboard a log source", self.chat.ask("build a use case for T1505.003"))
        self.assertIn("T1685", self.chat.ask("build a use case for T1562.001"))

    def test_explains_rejection(self):
        self.assertIn("Already alerted by the EDR", self.chat.ask("why was PR-009 rejected?"))

    def test_memory_search_finds_platform_records(self):
        hits = rag.build(self.p.ctx).search("leaked account watchlist", k=2)
        self.assertTrue(all(d.kind == "proposal" and d.title.startswith(("PR-001", "PR-011")) for _, d in hits))

    def test_state_survives_restart(self):
        self.chat.ask("build a use case for T1204.001")
        self.p.bus.db.close()
        p2 = Platform(self.tmp / "out", review_mode="manual")
        self.assertEqual(len(p2.awaiting()), 1)
        p2.bus.db.close()
        self.p = Platform(self.tmp / "out")


class AdvisoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.p = fresh_platform(cls.tmp)
        cls.r = advisory.rank(cls.p.ctx, top=10)

    @classmethod
    def tearDownClass(cls):
        cls.p.bus.db.close()
        shutil.rmtree(cls.tmp)

    def test_rejected_excluded_with_reason(self):
        self.assertEqual([x["technique"] for x in self.r["rejected"]], ["T1105"])
        self.assertNotIn("T1105", [x["technique"] for x in self.r["top"]])

    def test_untested_use_case_flagged_not_rewritten(self):
        self.assertEqual([x["use_case"] for x in self.r["validate"]], ["UC-010"])

    def test_no_data_goes_to_onboarding(self):
        self.assertEqual([x["technique"] for x in self.r["onboard"]], ["T1505.003"])

    def test_sorted_by_score(self):
        scores = [x["score"] for x in self.r["top"]]
        self.assertEqual(scores, sorted(scores, reverse=True))


class GitHubPRTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.p = fresh_platform(self.tmp)
        chat = Chat(self.p)
        chat.ask("build a use case for T1204.001")
        chat.ask("build a use case for T1555")

    def tearDown(self):
        self.p.bus.db.close()
        shutil.rmtree(self.tmp)

    def test_dry_run_writes_previews(self):
        res = github_pr.open_prs(self.p, "owner/repo", dry_run=True)
        self.assertEqual(len(res), 2)
        text = Path(res[0]["file"]).read_text()
        self.assertIn("detections/UC-T1204.001.json", text)
        self.assertIn("<!-- lyd:", text)

    def test_sync_turns_github_decisions_into_memory(self):
        a, b = self.p.awaiting()
        a["pr"], b["pr"] = {"number": 1, "url": "u1", "branch": "x"}, {"number": 2, "url": "u2", "branch": "y"}

        def fake_api(method, path, tok, body=None):
            if path.endswith("/pulls/1"):
                return {"merged_at": "2026-10-20T10:00:00Z", "merged_by": {"login": "Fattah-S"}, "state": "closed"}
            if path.endswith("/pulls/2"):
                return {"merged_at": None, "state": "closed"}
            if path.endswith("/issues/2/comments"):
                return [{"body": "Covered by email gateway controls", "user": {"login": "Fattah-S"}}]
            raise AssertionError(path)

        res = github_pr.sync_prs(self.p, "owner/repo", tok="t", api=fake_api)
        self.assertEqual({r["decision"] for r in res}, {"merged", "rejected"})
        self.assertEqual(self.p.ctx.proposals[a["id"]]["status"], "merged")
        rej = self.p.ctx.memory.was_rejected(b["key"])
        self.assertEqual(rej["reason"], "Covered by email gateway controls")
        self.assertEqual(rej["by"], "github:Fattah-S")


class DashboardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.p = fresh_platform(cls.tmp)
        Chat(cls.p).ask("build a use case for T1204.001")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(App(cls.p)))
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.p.bus.db.close()
        shutil.rmtree(cls.tmp)

    def get(self, path):
        with urllib.request.urlopen(self.base + path) as r:
            return r.read().decode()

    def test_pages_render(self):
        for path in ["/", "/reports", "/reports?week=week-1", "/advisory", "/trace", "/chat"]:
            self.assertIn("Leverage your detection", self.get(path), path)

    def test_chat_api(self):
        req = urllib.request.Request(self.base + "/api/chat", data=json.dumps({"q": "what's our coverage?"}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as r:
            self.assertIn("Priority coverage", json.loads(r.read())["answer"])

    def test_review_form_merges(self):
        pid = self.p.awaiting()[0]["id"]
        data = urllib.parse.urlencode({"pid": pid, "decision": "merged", "reason": ""}).encode()
        with urllib.request.urlopen(urllib.request.Request(self.base + "/review", data=data)) as r:
            self.assertIn("Merged", r.read().decode())
        self.assertEqual(self.p.ctx.proposals[pid]["status"], "merged")

    def test_output_is_escaped(self):
        req = urllib.request.Request(self.base + "/api/chat", data=json.dumps({"q": "<script>alert(1)</script>"}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as r:
            json.loads(r.read())
        self.assertNotIn("<script>alert", self.get("/"))


if __name__ == "__main__":
    unittest.main()
