"""Unit tests for research evaluation metrics and statistical calculations."""
import pytest
from evaluation.analyze_results import calculate_percentile, evaluate_waf_performance


def test_percentile_calculation():
    data = [10.0, 20.0, 30.0, 40.0, 50.0]
    assert calculate_percentile(data, 0.50) == 30.0
    assert calculate_percentile(data, 0.0) == 10.0
    assert calculate_percentile(data, 1.0) == 50.0
    assert calculate_percentile([], 0.50) is None


def test_evaluation_confusion_matrix_perfect():
    waf_rows = [
        {"expected_class": "malicious", "waf_rule_ids": "942100", "waf_intervention": "True", "http_status": "403", "latency_ms": "12.0"},
        {"expected_class": "malicious", "waf_rule_ids": "941100", "waf_intervention": "True", "http_status": "403", "latency_ms": "14.0"},
        {"expected_class": "benign", "waf_rule_ids": "", "waf_intervention": "False", "http_status": "200", "latency_ms": "10.0"},
        {"expected_class": "benign", "waf_rule_ids": "", "waf_intervention": "False", "http_status": "200", "latency_ms": "8.0"},
    ]
    res = evaluate_waf_performance(waf_rows)
    assert res["confusion_matrix"] == {"TP": 2, "FP": 0, "TN": 2, "FN": 0}
    assert res["detection_rate_recall"] == 1.0
    assert res["precision"] == 1.0
    assert res["false_positive_rate"] == 0.0
    assert res["blocking_rate"] == 1.0


def test_evaluation_zero_division_guard():
    # Only benign rows -> TP + FN == 0 (no malicious requests)
    waf_rows = [
        {"expected_class": "benign", "waf_rule_ids": "", "waf_intervention": "False", "http_status": "200", "latency_ms": "10.0"},
    ]
    res = evaluate_waf_performance(waf_rows)
    assert res["confusion_matrix"]["TP"] == 0
    assert res["detection_rate_recall"] == 0.0
    assert res["precision"] == 0.0
    assert res["false_positive_rate"] == 0.0
    assert res["blocking_rate"] == 0.0


def test_evaluation_latency_overhead():
    waf_rows = [
        {"expected_class": "benign", "latency_ms": "25.0", "waf_rule_ids": "", "waf_intervention": "False", "http_status": "200"},
        {"expected_class": "benign", "latency_ms": "35.0", "waf_rule_ids": "", "waf_intervention": "False", "http_status": "200"},
    ]
    base_rows = [
        {"expected_class": "benign", "latency_ms": "10.0", "http_status": "200"},
        {"expected_class": "benign", "latency_ms": "20.0", "http_status": "200"},
    ]
    res = evaluate_waf_performance(waf_rows, base_rows)
    assert res["latency_waf"]["mean_ms"] == 30.0
    assert res["latency_baseline"]["mean_ms"] == 15.0
    assert res["latency_overhead_mean_ms"] == 15.0
