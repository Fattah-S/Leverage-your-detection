"""End-to-end tests of the agent wiring. Run: python3 -m unittest -v"""
import json
import tempfile
import unittest
from pathlib import Path

from lyd.__main__ import ROOT, build, load_json, run_week
from lyd.llm import MockLLM, OllamaLLM


class FlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.bus, cls.ctx, cls.orch = build(Path(cls.tmp.name) / "out", MockLLM())
        intel = load_json(ROOT / "samples" / "intel.json")
        stats = load_json(ROOT / "samples" / "alert_stats.json")
        cls.weeks = [run_week(cls.bus, cls.ctx, cls.orch, w, intel[w], stats[w]) for w in ("week-1", "week-2")]
        cls.events = cls.bus.all()

    @classmethod
    def tearDownClass(cls):
        cls.bus.db.close()
        cls.tmp.cleanup()

    def types(self, root_id):
        return [e["type"] for e in self.bus.chain(root_id)]

    def test_every_event_is_handled(self):
        self.assertTrue(all(e["status"] == "done" for e in self.events))

    def test_every_agent_takes_part(self):
        emitters = {e["source"] for e in self.events}
        for agent in ["threat_intel", "coverage", "rule_health", "noise_tuning", "builder",
                      "validation", "engineer_review", "posture"]:
            self.assertIn(agent, emitters, agent)

    def test_intel_gap_to_merge_chain(self):
        root = next(e for e in self.events if e["type"] == "new_ttp" and e["payload"]["technique"] == "T1003.001")
        self.assertEqual(self.types(root["id"]),
                         ["new_ttp", "gap", "proposal_opened", "validation_passed", "rule_merged", "coverage_updated"])

    def test_low_relevance_intel_is_ignored(self):
        ignored = [e for e in self.events if e["type"] == "intel_ignored"]
        self.assertEqual([e["payload"]["intel_id"] for e in ignored], ["intel-002"])

    def test_rejected_gap_not_proposed_again(self):
        skipped = [e for e in self.events if e["type"] == "skipped_previously_rejected"]
        self.assertEqual([e["payload"]["key"] for e in skipped], ["new:T1105"])

    def test_no_log_source_is_not_a_rule(self):
        needs = [e["payload"]["technique"] for e in self.events if e["type"] == "needs_log_source"]
        self.assertEqual(needs, ["T1505.003"])

    def test_retired_technique_is_remapped(self):
        self.assertEqual(self.ctx.library["UC-005"]["techniques"], ["T1685"])

    def test_broad_exclusion_blocked_narrow_one_merged(self):
        tunings = [p for p in self.ctx.proposals.values() if p["kind"] == "tuning"]
        status = {(p["use_case"]["id"], p["week"]): p["status"] for p in tunings}
        self.assertEqual(status[("UC-004", "week-1")], "failed")
        self.assertEqual(status[("UC-004", "week-2")], "merged")
        self.assertEqual(status[("UC-001", "week-1")], "merged")

    def test_duplicate_use_case_blocked(self):
        p = next(p for p in self.ctx.proposals.values() if p["key"] == "new:T1547.001")
        self.assertEqual(p["status"], "failed")

    def test_health_issues_fixed_by_week_2(self):
        week2_start = next(e["id"] for e in self.events if e["type"] == "tick" and e["payload"]["week"] == "week-2")
        self.assertFalse([e for e in self.events if e["type"] == "broken_rule" and e["id"] > week2_start])

    def test_coverage_rises(self):
        self.assertLess(self.weeks[0]["before"], self.weeks[0]["after"])
        self.assertLess(self.weeks[1]["before"], self.weeks[1]["after"])

    def test_reports_written(self):
        out = Path(self.tmp.name) / "out"
        for w in ("week-1", "week-2"):
            self.assertTrue((out / w / "report.md").exists())
            layer = json.loads((out / w / "navigator-layer.json").read_text())
            self.assertEqual(layer["domain"], "enterprise-attack")
            self.assertTrue(layer["techniques"])


class OllamaClientTest(unittest.TestCase):
    def test_unreachable_server_raises(self):
        llm = OllamaLLM(host="http://127.0.0.1:9", timeout=2)
        with self.assertRaises(OSError):
            llm.write("report_summary", {"before": 1, "after": 2, "merged": 0, "rejected": 0, "open_gaps": 0})


if __name__ == "__main__":
    unittest.main()
