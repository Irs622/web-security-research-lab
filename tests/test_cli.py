"""Tests for the CLI entry points: dataset loading, chart generation and paranoia comparison."""
import json

import pytest

from evaluation import compare_paranoia, generate_charts
from evaluation.analyze_results import evaluate_waf_performance
from simulator.run_tests import CASES_FILE, DatasetError, load_cases


def _write(tmp_path, data):
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_cases_accepts_bundled_dataset():
    assert len(load_cases(CASES_FILE)) > 0


@pytest.mark.parametrize("data, message", [
    ([], "non-empty"),
    ([{"test_id": "A", "path": "http://evil", "expected_class": "benign"}], "Invalid"),
    ([{"test_id": "A", "path": "/", "expected_class": "maybe"}], "Invalid"),
    ([{"test_id": "A", "path": "/", "expected_class": "benign"},
      {"test_id": "A", "path": "/x", "expected_class": "malicious"}], "Duplicate"),
])
def test_load_cases_rejects_bad_datasets(tmp_path, data, message):
    with pytest.raises(DatasetError, match=message):
        load_cases(_write(tmp_path, data))


def test_load_cases_missing_file(tmp_path):
    with pytest.raises(DatasetError, match="not found"):
        load_cases(tmp_path / "nope.json")


def _summary():
    rows = [
        {"expected_class": "malicious", "category": "SQLI", "waf_rule_ids": "942100",
         "waf_intervention": "True", "latency_ms": "12"},
        {"expected_class": "benign", "category": "BENIGN", "waf_rule_ids": "",
         "waf_intervention": "False", "latency_ms": "8"},
    ]
    return evaluate_waf_performance(rows, [{"latency_ms": "5"}, {"latency_ms": "6"}])


def test_generate_charts_writes_pngs(tmp_path):
    summary = tmp_path / "summary.json"
    summary.write_text(json.dumps(_summary()), encoding="utf-8")
    generate_charts.main(["--summary", str(summary), "--output-dir", str(tmp_path / "out")])
    for name in ("confusion_matrix.png", "latency_comparison.png", "category_breakdown.png"):
        assert (tmp_path / "out" / name).stat().st_size > 0


def test_compare_paranoia_main_writes_outputs(tmp_path):
    for name in ("pl1", "pl2", "pl2-tuned"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "summary_metrics.json").write_text(json.dumps(_summary()), encoding="utf-8")
    compare_paranoia.main(tmp_path)
    rows = json.loads((tmp_path / "paranoia_comparison.json").read_text(encoding="utf-8"))
    assert [r["scenario"] for r in rows] == ["pl1", "pl2", "pl2-tuned"]
    assert (tmp_path / "paranoia_tradeoff.png").exists()


def test_compare_paranoia_main_fails_without_results(tmp_path):
    with pytest.raises(SystemExit):
        compare_paranoia.main(tmp_path)


def test_analyzer_refuses_baseline_from_another_dataset(tmp_path, monkeypatch, capsys):
    from evaluation import analyze_results
    waf, base = tmp_path / "waf.csv", tmp_path / "baseline.csv"
    header = "test_id,expected_class,waf_rule_ids,waf_intervention,latency_ms\nA,benign,,False,5\n"
    for path, sha in ((waf, "a" * 64), (base, "b" * 64)):
        path.write_text(header, encoding="utf-8")
        path.with_suffix(".meta.json").write_text(json.dumps({"dataset_sha256": sha, "case_count": 1}))
    monkeypatch.setattr("sys.argv", ["analyze", "--waf", str(waf), "--baseline", str(base),
                                     "--output", str(tmp_path / "s.json")])
    with pytest.raises(SystemExit):
        analyze_results.main()
    assert "different datasets" in capsys.readouterr().err
    # Same dataset hash: the pair is accepted.
    base.with_suffix(".meta.json").write_text(json.dumps({"dataset_sha256": "a" * 64}))
    analyze_results.main()
    assert (tmp_path / "s.json").exists()


def test_load_cases_accepts_extended_dataset():
    from simulator.run_tests import ROOT
    cases = load_cases(ROOT / "simulator" / "attack_cases_extended.json")
    assert len(cases) > len(load_cases(CASES_FILE))
