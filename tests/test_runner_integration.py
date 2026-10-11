"""Integration tests: the runner against a real local HTTP server (no Docker required)."""
import csv
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from simulator.log_correlator import TRACE_HEADER
from simulator.runner import ExperimentRunner


class _Handler(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        self.seen.append((self.path, self.headers.get(TRACE_HEADER)))
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.end_headers()
            return
        status = 403 if "blocked" in self.path else 200
        body = b"hello"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.seen.append((self.path, self.rfile.read(length).decode()))
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    _Handler.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _runner(url, mode="baseline"):
    port = 3001 if mode == "baseline" else 8080
    runner = ExperimentRunner(f"http://127.0.0.1:{port}", mode, delay_seconds=0, enable_log_correlation=False)
    runner.delay = 0  # tests only; the CLI enforces the 0.1 s floor
    runner.base_url = url  # the validator only allows lab ports; point at the ephemeral mock server
    return runner


def test_redirect_is_not_followed(server):
    row = _runner(server).execute_test({"test_id": "R-1", "path": "/redirect", "expected_class": "benign"}, "r")
    assert row["http_status"] == 302
    assert [p for p, _ in _Handler.seen] == ["/redirect"]


def test_status_body_and_trace_header(server):
    row = _runner(server).execute_test(
        {"test_id": "B-1", "path": "/search", "params": {"q": "a b"}, "expected_class": "benign"}, "r")
    assert row["http_status"] == 200 and row["response_size_bytes"] == 5
    assert row["path"] == "/search?q=a+b"
    assert _Handler.seen[-1][1] == row["trace_id"]


def test_json_body_posted(server):
    _runner(server).execute_test(
        {"test_id": "P-1", "method": "POST", "path": "/api", "body": {"k": "v"}, "expected_class": "benign"}, "r")
    assert json.loads(_Handler.seen[-1][1]) == {"k": "v"}


def test_waf_mode_status_fallback_without_logs(server):
    row = _runner(server, "waf").execute_test({"test_id": "X-1", "path": "/blocked", "expected_class": "malicious"}, "r")
    assert row["waf_intervention"] is True and row["observed_outcome"] == "blocked_by_waf"


def test_transport_error_recorded():
    runner = _runner("http://127.0.0.1:1")
    row = runner.execute_test({"test_id": "E-1", "path": "/", "expected_class": "benign"}, "r")
    assert row["transport_error"] and row["observed_outcome"] == "transport_error"


def test_run_suite_writes_repeats_and_metadata(server, tmp_path, monkeypatch):
    monkeypatch.setattr("simulator.runner._container_image", lambda name: "stub")
    cases = [{"test_id": "B-1", "category": "normal", "path": "/", "expected_class": "benign"},
             {"test_id": "B-2", "category": "normal", "path": "/x", "expected_class": "benign"}]
    out = tmp_path / "baseline.csv"
    _runner(server).run_suite(cases, out, repeat=3, warmup=2)
    rows = list(csv.DictReader(out.open()))
    assert len(rows) == 6
    assert sorted({r["repeat_index"] for r in rows}) == ["0", "1", "2"]
    assert rows[0]["category"] == "normal"
    meta = json.loads(out.with_suffix(".meta.json").read_text())
    assert meta["repeat"] == 3 and meta["case_count"] == 2 and len(meta["dataset_sha256"]) == 64
    assert len(_Handler.seen) == 8  # 2 warm-up + 6 measured
