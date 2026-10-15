"""Unit tests for research evaluation metrics and statistical calculations."""
from evaluation.analyze_results import (
    LAB_ENVIRONMENT_PROTOCOL_RULES,
    SCORING_META_RULES,
    calculate_percentile,
    wilson_interval,
    mann_whitney_u,
    evaluate_waf_performance,
)


def test_percentile_calculation():
    data = [10.0, 20.0, 30.0, 40.0, 50.0]
    assert calculate_percentile(data, 0.50) == 30.0
    assert calculate_percentile(data, 0.0) == 10.0
    assert calculate_percentile(data, 1.0) == 50.0
    assert calculate_percentile([], 0.50) is None


def test_evaluation_confusion_matrix_perfect():
    waf_rows = [
        {"expected_class": "malicious", "waf_rule_ids": "942100", "waf_intervention": "True", "http_status": "403", "latency_ms": "12.0", "log_match": "trace_id"},
        {"expected_class": "malicious", "waf_rule_ids": "941100", "waf_intervention": "True", "http_status": "403", "latency_ms": "14.0", "log_match": "trace_id"},
        {"expected_class": "benign", "waf_rule_ids": "", "waf_intervention": "False", "http_status": "200", "latency_ms": "10.0"},
        {"expected_class": "benign", "waf_rule_ids": "", "waf_intervention": "False", "http_status": "200", "latency_ms": "8.0"},
    ]
    res = evaluate_waf_performance(waf_rows)
    assert res["specificity"] == 1.0
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
    # No malicious rows: recall/precision/blocking are undefined, not 0%.
    assert res["detection_rate_recall"] is None
    assert res["precision"] is None
    assert res["f1_score"] is None
    assert res["false_positive_rate"] == 0.0
    assert res["blocking_rate"] is None


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


def test_transport_error_rows_excluded_from_metrics():
    # Rows with transport_error must be excluded from sample_count and confusion matrix.
    waf_rows = [
        {
            "expected_class": "malicious",
            "waf_rule_ids": "942100",
            "waf_intervention": "True",
            "http_status": "403",
            "latency_ms": "12.0",
            "transport_error": "TimeoutError: timed out",
        },
        {
            "expected_class": "malicious",
            "waf_rule_ids": "941100",
            "waf_intervention": "True",
            "http_status": "403",
            "latency_ms": "14.0",
            "transport_error": "",
        },
    ]
    res = evaluate_waf_performance(waf_rows)
    assert res["sample_count"] == 1
    assert res["confusion_matrix"]["TP"] == 1
    assert res["confusion_matrix"]["FN"] == 0


def test_empty_waf_intervention_string_treated_as_false():
    # waf_intervention stored as empty string (not "True") must not trigger is_blocked.
    # Attack rule present → TP via has_attack_detection, not via blocking.
    waf_rows = [
        {
            "expected_class": "malicious",
            "waf_rule_ids": "942100",
            "waf_intervention": "",
            "http_status": "200",
            "latency_ms": "12.0",
        },
    ]
    res = evaluate_waf_performance(waf_rows)
    assert res["confusion_matrix"]["TP"] == 1
    assert res["confusion_matrix"]["FN"] == 0
    assert res["blocking_rate"] == 0.0


def test_lab_environment_rule_excluded_from_fp():
    # Rule 920350 (numeric IP host) fires on all lab requests. A benign request
    # carrying only 920350 must still count as TN, not FP.
    lab_rule = next(iter(LAB_ENVIRONMENT_PROTOCOL_RULES))
    waf_rows = [
        {
            "expected_class": "benign",
            "waf_rule_ids": lab_rule,
            "waf_intervention": "False",
            "http_status": "200",
            "latency_ms": "15.0",
        },
    ]
    res = evaluate_waf_performance(waf_rows)
    assert res["confusion_matrix"]["FP"] == 0
    assert res["confusion_matrix"]["TN"] == 1


def test_scoring_meta_rule_excluded_from_detection():
    # Rule 949110 (anomaly score exceeded) must not count as an attack rule on its own.
    meta_rule = next(iter(SCORING_META_RULES))
    waf_rows = [
        {
            "expected_class": "malicious",
            "waf_rule_ids": meta_rule,
            "waf_intervention": "False",
            "http_status": "200",
            "latency_ms": "12.0",
        },
    ]
    res = evaluate_waf_performance(waf_rows)
    assert res["confusion_matrix"]["FN"] == 1
    assert res["confusion_matrix"]["TP"] == 0


def test_unknown_expected_class_not_counted():
    # Rows with unexpected class values must not affect TP/FP/TN/FN counts.
    waf_rows = [
        {
            "expected_class": "unknown",
            "waf_rule_ids": "942100",
            "waf_intervention": "True",
            "http_status": "403",
            "latency_ms": "10.0",
        },
    ]
    res = evaluate_waf_performance(waf_rows)
    cm = res["confusion_matrix"]
    assert cm["TP"] == cm["FP"] == cm["TN"] == cm["FN"] == 0


def test_zero_division_guard_only_malicious_rows():
    # When FP + TN == 0 (no benign rows), FPR is undefined (None), not a ZeroDivisionError.
    waf_rows = [
        {
            "expected_class": "malicious",
            "waf_rule_ids": "942100",
            "waf_intervention": "True",
            "http_status": "403",
            "latency_ms": "12.0",
        },
    ]
    res = evaluate_waf_performance(waf_rows)
    assert res["false_positive_rate"] is None
    assert res["confusion_matrix"]["TN"] == 0
    assert res["confusion_matrix"]["FP"] == 0


def test_wilson_interval_bounds():
    assert wilson_interval(0, 0) is None
    lo, hi = wilson_interval(0, 12)
    assert lo == 0.0 and 0.2 < hi < 0.3  # FPR 0/12 is still compatible with ~24%
    lo, hi = wilson_interval(27, 28)
    assert lo < 0.9643 < hi


def test_category_field_and_misclassified_listing():
    rows = [
        {"test_id": "TRAV-007", "category": "path-traversal", "expected_class": "malicious",
         "waf_rule_ids": "920350", "waf_intervention": "False", "path": "/ftp/x", "latency_ms": "5"},
        {"test_id": "BENIGN-001", "category": "normal", "expected_class": "benign",
         "waf_rule_ids": "942100", "waf_intervention": "False", "path": "/", "latency_ms": "5"},
    ]
    res = evaluate_waf_performance(rows)
    assert set(res["category_breakdown"]) == {"path-traversal", "normal"}
    assert [(m["type"], m["test_id"]) for m in res["misclassified"]] == [("FN", "TRAV-007"), ("FP", "BENIGN-001")]


def test_repeats_counted_once_for_detection_but_all_for_latency():
    row = {"expected_class": "malicious", "waf_rule_ids": "942100", "waf_intervention": "True"}
    rows = [dict(row, repeat_index=str(i), latency_ms=str(10 + i)) for i in range(3)]
    res = evaluate_waf_performance(rows)
    assert res["confusion_matrix"]["TP"] == 1
    assert res["latency_stats"]["waf"]["n"] == 3


def test_mann_whitney_detects_shift_and_handles_small_samples():
    assert mann_whitney_u([1.0], [2.0]) is None
    res = mann_whitney_u([float(x) for x in range(20, 40)], [float(x) for x in range(0, 20)])
    assert res["p_value"] < 0.001
    same = mann_whitney_u([5.0, 5.0, 5.0], [5.0, 5.0, 5.0])
    assert same["p_value"] == 1.0


def test_print_report_handles_undefined_metrics(capsys):
    from evaluation.analyze_results import print_report
    rows = [{"expected_class": "benign", "waf_rule_ids": "", "waf_intervention": "False", "latency_ms": "5"}]
    print_report(evaluate_waf_performance(rows))
    assert "n/a" in capsys.readouterr().out


def _row(cls, rules="", blocked=False, evidence="audit_log", category="sqli", applicability="pattern_only"):
    return {"expected_class": cls, "category": category, "waf_rule_ids": rules,
            "waf_intervention": str(blocked), "intervention_evidence": evidence,
            "scenario_applicability": applicability, "latency_ms": "10"}


def test_blocking_rate_counts_only_audit_confirmed_interventions():
    rows = [_row("malicious", "942100", True), _row("malicious", "", True, evidence="status_heuristic")]
    res = evaluate_waf_performance(rows)
    # Both are detections, but only the audit-log-backed one is a confirmed block.
    assert res["confusion_matrix"]["TP"] == 2
    assert res["malicious_blocked"] == 1 and res["malicious_blocked_unverified"] == 1
    assert res["blocking_rate"] == 0.5


def test_legacy_rows_derive_evidence_from_log_match():
    rows = [
        {"expected_class": "malicious", "waf_rule_ids": "942100", "waf_intervention": "True", "log_match": "uri"},
        {"expected_class": "malicious", "waf_rule_ids": "", "waf_intervention": "True", "log_match": "none"},
    ]
    res = evaluate_waf_performance(rows)
    assert res["malicious_blocked"] == 1 and res["malicious_blocked_unverified"] == 1
    assert "unspecified" in res["applicability_breakdown"]


def test_category_and_applicability_breakdown():
    rows = ([_row("malicious", "932100", True, category="cmdi")] * 3
            + [_row("malicious", category="cmdi")]
            + [_row("malicious", "942100", True, category="sqli", applicability="sink_present")]
            + [_row("benign", "942100", category="normal", applicability="benign_control"),
               _row("benign", category="normal", applicability="benign_control")])
    res = evaluate_waf_performance(rows)
    cmdi = res["category_breakdown"]["cmdi"]
    assert (cmdi["tp"], cmdi["fn"], cmdi["recall"], cmdi["blocking_rate"]) == (3, 1, 0.75, 0.75)
    assert cmdi["small_sample"] is True and cmdi["recall_ci95"] is not None
    normal = res["category_breakdown"]["normal"]
    assert normal["false_positive_rate"] == 0.5 and normal["recall"] is None and normal["small_sample"] is False
    assert res["applicability_breakdown"]["sink_present"]["recall"] == 1.0
    assert res["applicability_breakdown"]["pattern_only"]["malicious"] == 4
    assert res["specificity"] == 0.5


def test_outbound_only_alert_is_counted_separately():
    res = evaluate_waf_performance([_row("benign", "920350;950100", category="normal")])
    assert res["confusion_matrix"]["FP"] == 1 and res["alerts_outbound_only"] == 1


def test_latency_overhead_p50():
    waf = [{"expected_class": "benign", "latency_ms": v} for v in ("20", "30", "40")]
    base = [{"latency_ms": v} for v in ("10", "12", "14")]
    res = evaluate_waf_performance(waf, base)
    assert res["latency_overhead_p50_ms"] == 18.0
