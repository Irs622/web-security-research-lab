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


def test_v2_columns_separate_alert_block_source_and_backend(server):
    runner = _runner(server, "waf")
    blocked = runner.execute_test({"test_id": "X-1", "path": "/blocked", "expected_class": "malicious",
                                   "scenario_applicability": "pattern_only"}, "r")
    # No audit log in this test: the 403 is a status heuristic, never a confirmed block.
    assert blocked["intervention_evidence"] == "status_heuristic"
    assert blocked["block_source"] == "waf" and blocked["backend_outcome"] == "not_reached"
    assert blocked["waf_alert"] is False and blocked["scenario_applicability"] == "pattern_only"
    ok = runner.execute_test({"test_id": "B-1", "path": "/", "expected_class": "benign"}, "r")
    assert ok["block_source"] == "none" and ok["backend_outcome"] == "2xx"
    assert ok["scenario_applicability"] == "unspecified"


def test_application_403_is_not_attributed_to_waf(server):
    runner = _runner(server, "waf")

    class _Correlator:
        last_producer = None

        def correlate_request(self, *args, **kwargs):
            return [], False, 403, "trace_id"  # audit record exists, but nothing interrupted

    runner.correlator = _Correlator()
    row = runner.execute_test({"test_id": "A-1", "path": "/blocked", "expected_class": "benign"}, "r")
    assert row["http_status"] == 403 and row["waf_intervention"] is False
    assert row["intervention_evidence"] == "audit_log"
    assert row["block_source"] == "application" and row["backend_outcome"] == "4xx"
    baseline = _runner(server).execute_test({"test_id": "A-2", "path": "/blocked", "expected_class": "benign"}, "r")
    assert baseline["block_source"] == "application" and baseline["waf_alert"] == ""


def test_payload_urls_are_never_contacted(server):
    """SSRF/RFI-style parameter values are sent as text; the harness only talks to the target."""
    _runner(server).execute_test({"test_id": "S-1", "path": "/search", "expected_class": "malicious",
                                  "params": {"q": "http://127.0.0.1:1/"}}, "r")
    assert len(_Handler.seen) == 1 and _Handler.seen[0][0].startswith("/search?q=http")


def test_metadata_records_dataset_file_and_request_counts(server, tmp_path, monkeypatch):
    monkeypatch.setattr("simulator.runner._container_image", lambda name: "stub")
    dataset = tmp_path / "cases.json"
    cases = [{"test_id": "B-1", "category": "normal", "path": "/", "expected_class": "benign"}]
    dataset.write_text(json.dumps(cases))
    out = tmp_path / "baseline.csv"
    _runner(server).run_suite(cases, out, repeat=2, dataset_path=dataset)
    meta = json.loads(out.with_suffix(".meta.json").read_text())
    assert meta["dataset_path"] == str(dataset) and len(meta["dataset_file_sha256"]) == 64
    assert meta["requests_attempted"] == 2 and meta["requests_completed"] == 2
    assert meta["target"] == _runner(server).base_url and "git_dirty" in meta
    rows = list(csv.DictReader(out.open()))
    assert set(rows[0]) >= {"waf_alert", "intervention_evidence", "block_source", "backend_outcome",
                            "scenario_applicability"}


def test_waf_metadata_records_runtime_and_producer(server, tmp_path, monkeypatch):
    monkeypatch.setattr("simulator.runner._container_image", lambda name: "stub")
    monkeypatch.setattr("simulator.runner._container_env", lambda name, keys: {"PARANOIA": "2"})
    monkeypatch.setattr("simulator.runner._container_mounts", lambda name: ["/x.conf"])
    monkeypatch.setenv("TUNED", "1")
    runner = _runner(server, "waf")

    class _Correlator:
        last_producer = {"modsecurity": "ModSecurity v3", "components": ["OWASP_CRS/4.25.2"]}

        def correlate_request(self, *args, **kwargs):
            return ["942100"], True, 403, "trace_id"

    runner.correlator = _Correlator()
    out = tmp_path / "waf.csv"
    runner.run_suite([{"test_id": "M-1", "path": "/", "expected_class": "malicious"}], out)
    meta = json.loads(out.with_suffix(".meta.json").read_text())
    assert meta["waf_runtime"] == {"env": {"PARANOIA": "2"}, "mounts": ["/x.conf"]}
    assert meta["waf_producer"]["components"] == ["OWASP_CRS/4.25.2"]
    assert meta["audit_log_correlation"] == {"trace_id": 1}
    assert meta["tuned_exclusions"] is True and len(meta["exclusions_sha256"]) == 64


def test_outbound_only_block_marks_backend_as_reached(server):
    runner = _runner(server, "waf")

    class _Correlator:
        last_producer = None

        def correlate_request(self, *args, **kwargs):
            return ["920350", "950100", "959100"], True, 403, "trace_id"

    runner.correlator = _Correlator()
    row = runner.execute_test({"test_id": "O-1", "path": "/", "expected_class": "benign"}, "r")
    assert row["block_source"] == "waf" and row["backend_outcome"] == "reached_response_blocked"
