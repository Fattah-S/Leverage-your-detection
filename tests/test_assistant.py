"""Team instructions for the LLM: sent with every request, editable in the dashboard."""
import json
import shutil
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from lyd import llm
from lyd.platform import Platform
from lyd.web import App, make_handler


class InstructionsSentTest(unittest.TestCase):
    def test_system_prompt_contains_team_text_and_guardrails(self):
        got = {}

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                got.update(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                body = json.dumps({"response": "ok"}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            out = llm.OllamaLLM(host=f"http://127.0.0.1:{srv.server_address[1]}").write("report_summary", {"x": 1})
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(out, "ok")
        self.assertIn("detection engineering assistant of our SOC", got["system"])
        self.assertTrue(got["system"].endswith(llm.GUARDRAILS))


class AssistantPageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.file = self.tmp / "assistant.md"
        self.file.write_text("# Old instructions\n", encoding="utf-8")
        self.patch = mock.patch.object(llm, "INSTRUCTIONS", self.file)
        self.patch.start()
        self.p = Platform(self.tmp / "out", fresh=True)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(App(self.p)))
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.p.bus.db.close()
        self.patch.stop()
        shutil.rmtree(self.tmp)

    def test_edit_and_save(self):
        with urllib.request.urlopen(self.base + "/assistant") as r:
            self.assertIn("Old instructions", r.read().decode())
        data = urllib.parse.urlencode({"text": "# New\nWork with us to evolve detection."}).encode()
        with urllib.request.urlopen(urllib.request.Request(self.base + "/assistant", data=data)) as r:
            self.assertIn("Saved", r.read().decode())
        self.assertIn("evolve detection", self.file.read_text(encoding="utf-8"))
        self.assertIn("evolve detection", llm.instructions())


if __name__ == "__main__":
    unittest.main()
