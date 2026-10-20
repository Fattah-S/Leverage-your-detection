"""Status reports and the built-in scheduler."""
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from lyd import status
from lyd.chat import Chat
from lyd.platform import ROOT, Platform, load_json


def fresh(tmp: Path) -> Platform:
    p = Platform(tmp / "out", fresh=True, review_mode="auto")
    intel = load_json(ROOT / "samples" / "intel.json")
    stats = load_json(ROOT / "samples" / "alert_stats.json")
    for w in ("week-1", "week-2"):
        p.run_week(w, intel[w], stats[w])
    p.ctx.review_mode = "manual"
    p.save()
    return p


class StatusReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.p = fresh(self.tmp)

    def tearDown(self):
        self.p.bus.db.close()
        shutil.rmtree(self.tmp)

    def test_first_report(self):
        path = status.write(self.p, datetime(2026, 10, 25, 8, 0))
        text = path.read_text(encoding="utf-8")
        self.assertEqual(path.parent.name, "status-2026-10-25")
        self.assertIn("first status report", text)
        self.assertIn("13 of 134", text)
        self.assertTrue((path.parent / "navigator-layer.json").exists())

    def test_second_report_shows_change_and_decisions(self):
        status.write(self.p, datetime.now() - timedelta(days=7))
        chat = Chat(self.p)
        chat.ask("build a use case for T1204.001")
        pid = self.p.awaiting()[0]["id"]
        chat.ask(f"approve {pid}")
        text = status.write(self.p, datetime.now() + timedelta(minutes=1)).read_text(encoding="utf-8")
        self.assertIn("9.7% → 10.4% since the last report", text)
        self.assertIn(f"{pid}: merged by engineer_chat", text)

    def test_chat_can_write_report(self):
        self.assertIn("Status report written", Chat(self.p).ask("write a status report"))


class ScheduleTest(unittest.TestCase):
    def test_daily(self):
        self.assertEqual(status.next_run(datetime(2026, 10, 20, 7, 0), "daily", "08:00"), datetime(2026, 10, 20, 8, 0))
        self.assertEqual(status.next_run(datetime(2026, 10, 20, 9, 0), "daily", "08:00"), datetime(2026, 10, 21, 8, 0))

    def test_weekly(self):
        tue = datetime(2026, 10, 20, 9, 0)  # a Tuesday
        self.assertEqual(status.next_run(tue, "weekly", "08:00", "sun"), datetime(2026, 10, 25, 8, 0))
        self.assertEqual(status.next_run(tue, "weekly", "08:00", "tue"), datetime(2026, 10, 27, 8, 0))
        self.assertEqual(status.next_run(tue, "weekly", "10:00", "tue"), datetime(2026, 10, 20, 10, 0))

    def test_loop_writes_when_due(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            fresh(tmp).bus.db.close()
            made = []

            def make():
                p = Platform(tmp / "out")
                made.append(p)
                return p

            past = datetime.now() - timedelta(minutes=1)
            with mock.patch.object(status, "next_run", side_effect=[past, datetime.now() + timedelta(days=1)]), \
                    mock.patch.object(status.time, "sleep", side_effect=KeyboardInterrupt):
                status.run_schedule(make, "daily", "08:00")
            self.assertEqual(len(made), 1)
            self.assertTrue(list((tmp / "out").glob("status-*/report.md")))
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
