"""Unit tests for audit-log correlation and WAF intervention attribution."""
import urllib.error

from evaluation.analyze_results import evaluate_waf_performance, filter_attack_rules
from simulator.log_correlator import TRACE_HEADER, WafLogCorrelator
from simulator.runner import ExperimentRunner


def _tx(uri, rules, interrupted, trace=None, method="GET"):
    headers = {"Host": "127.0.0.1:8080"}
    if trace:
        headers[TRACE_HEADER.lower()] = trace
    return {
        "request": {"method": method, "uri": uri, "headers": headers},
        "messages": [{"details": {"ruleId": r}} for r in rules],
        "is_interrupted": interrupted,
        "response": {"http_code": 403 if interrupted else 200},
    }


def test_trace_id_match_beats_more_recent_uri_match():
    # Two requests share a base path; the newer one would win under URI matching.
    txs = [
        _tx("/ftp/a", ["930100"], True, trace="aaa"),
        _tx("/ftp/a", ["920350"], False, trace="bbb"),
    ]
    rules, interrupted, _, how = WafLogCorrelator().correlate_request("GET", "/ftp/a", txs, trace_id="aaa")
    assert how == "trace_id"
    assert rules == ["930100"]
    assert interrupted is True


def test_uri_fallback_when_trace_missing_from_log():
    txs = [_tx("/search?q=x", ["942100"], True)]
    rules, interrupted, _, how = WafLogCorrelator().correlate_request("GET", "/search?q=x", txs, trace_id="zzz")
    assert how == "uri"
    assert rules == ["942100"]


def test_no_match_returns_none():
    rules, interrupted, code, how = WafLogCorrelator().correlate_request("GET", "/x?a=1", [], trace_id="t")
    assert (rules, interrupted, code, how) == ([], False, None, "none")


class _FakeCorrelator:
    def __init__(self, result):
        self.result = result
        self.trace_id = None

    def correlate_request(self, method, path, trace_id=None, **kwargs):
        self.trace_id = trace_id
        return self.result


def _runner_with(result, status):
    runner = ExperimentRunner("http://127.0.0.1:8080", "waf", enable_log_correlation=False)
    runner.correlator = _FakeCorrelator(result)

    def fake_open(req, timeout):
        runner.sent_headers = dict(req.header_items())
        raise urllib.error.HTTPError(req.full_url, status, "x", {}, None)

    runner.opener.open = fake_open
    return runner


def test_backend_403_not_counted_as_waf_block_when_log_says_not_interrupted():
    # Juice Shop returns its own 403; the audit log shows only the lab protocol rule.
    runner = _runner_with((["920350"], False, 403, "trace_id"), status=403)
    row = runner.execute_test({"test_id": "TRAV-007", "path": "/ftp/x", "expected_class": "malicious"}, "r")
    assert row["waf_intervention"] is False
    assert row["observed_outcome"] == "passed_clean"
    assert row["log_match"] == "trace_id"


def test_trace_header_is_sent_and_recorded():
    runner = _runner_with((["942100", "949110"], True, 403, "trace_id"), status=403)
    row = runner.execute_test({"test_id": "SQLI-001", "path": "/", "expected_class": "malicious"}, "r")
    sent = {k.lower(): v for k, v in runner.sent_headers.items()}
    assert sent[TRACE_HEADER.lower()] == row["trace_id"]
    assert runner.correlator.trace_id == row["trace_id"]
    assert "accept" in sent  # avoids CRS 920300 (missing Accept) lab artifact
    assert row["observed_outcome"] == "blocked_by_waf"


def test_status_fallback_when_no_audit_evidence():
    runner = _runner_with(([], False, None, "none"), status=403)
    row = runner.execute_test({"test_id": "X-1", "path": "/", "expected_class": "malicious"}, "r")
    assert row["waf_intervention"] is True


def test_analyzer_ignores_raw_403_without_intervention_flag():
    rows = [{"expected_class": "malicious", "waf_rule_ids": "920350", "waf_intervention": "False",
             "http_status": "403", "latency_ms": "5"}]
    res = evaluate_waf_performance(rows)
    assert res["confusion_matrix"]["FN"] == 1
    assert res["blocking_rate"] == 0.0


def test_filter_attack_rules():
    assert filter_attack_rules(["920350", "942100", "949110"]) == ["942100"]


def test_zero_latency_not_reported_as_none():
    rows = [{"expected_class": "benign", "waf_rule_ids": "", "waf_intervention": "False", "latency_ms": "0"}]
    assert evaluate_waf_performance(rows)["latency_waf"]["mean_ms"] == 0.0


def test_polls_log_until_trace_id_appears(monkeypatch):
    batches = [[], [_tx("/a", ["942100"], True, trace="t1")]]
    corr = WafLogCorrelator()
    monkeypatch.setattr(corr, "fetch_recent_logs", lambda tail_lines=100: batches.pop(0))
    monkeypatch.setattr("simulator.log_correlator.time.sleep", lambda s: None)
    rules, interrupted, _, how = corr.correlate_request("GET", "/a", trace_id="t1", poll_attempts=3)
    assert how == "trace_id" and rules == ["942100"] and interrupted is True


def test_nginx_400_without_audit_record_is_rejected_by_proxy():
    runner = _runner_with(([], False, None, "none"), status=400)
    row = runner.execute_test({"test_id": "TRAV-001", "path": "/ftp/x", "expected_class": "malicious"}, "r")
    assert row["waf_intervention"] is False
    assert row["observed_outcome"] == "rejected_by_proxy"
    res = evaluate_waf_performance([dict(row, waf_intervention=str(row["waf_intervention"]))])
    assert res["confusion_matrix"]["FN"] == 1
    assert res["malicious_rejected_by_proxy"] == 1 and res["overall_mitigation_rate"] == 1.0
