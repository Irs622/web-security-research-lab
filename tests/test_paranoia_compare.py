"""Unit tests for the Paranoia Level comparison collector."""
import json

from evaluation.compare_paranoia import collect


def _summary(recall, fpr):
    return {
        "detection_rate_recall": recall, "false_positive_rate": fpr, "precision": 1.0,
        "f1_score": 0.9, "blocking_rate": recall, "latency_waf": {"p50_ms": 10.0},
        "confusion_matrix": {"TP": 1, "FP": 0, "TN": 1, "FN": 0},
        "confidence_intervals_95": {"detection_rate_recall": [0.5, 1.0], "false_positive_rate": [0.0, 0.2]},
    }


def test_collect_sorts_levels_and_ignores_other_dirs(tmp_path):
    for name, recall in (("pl2", 0.98), ("pl1", 0.96), ("plx", 0.0), ("pl2-tuned", 0.97)):
        d = tmp_path / name
        d.mkdir()
        (d / "summary_metrics.json").write_text(json.dumps(_summary(recall, 0.0)))
    rows = collect(tmp_path)
    assert [r["scenario"] for r in rows] == ["pl1", "pl2", "pl2-tuned"]
    assert rows[1]["recall"] == 0.98 and rows[2]["tuned"] is True
    assert rows[0]["recall_ci95"] == [0.5, 1.0]
