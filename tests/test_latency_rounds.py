"""Tests for the multi-round latency aggregation."""
import csv
import json

import pytest

from evaluation import latency_rounds

FIELDS = ["test_id", "expected_class", "latency_ms", "transport_error"]


def _write(path, rows, sha="a" * 64, started="2026-10-15T10:00:00"):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    path.with_suffix(".meta.json").write_text(json.dumps(
        {"dataset_sha256": sha, "started_utc": started, "host_load_avg_start": [1.0, 1.0, 1.0]}))


def _rows(benign_ms, malicious_ms):
    rows = [{"test_id": f"B{i}", "expected_class": "benign", "latency_ms": v, "transport_error": ""}
            for i, v in enumerate(benign_ms)]
    rows += [{"test_id": f"M{i}", "expected_class": "malicious", "latency_ms": v, "transport_error": ""}
             for i, v in enumerate(malicious_ms)]
    rows.append({"test_id": "E", "expected_class": "benign", "latency_ms": "999", "transport_error": "Timeout"})
    return rows


def test_summary_uses_benign_rows_and_alternation(tmp_path):
    # Blocked malicious requests are fast at the WAF; they must not hide the benign overhead.
    _write(tmp_path / "round1" / "baseline.csv", _rows([10, 10, 10], [10, 10, 10, 10]), started="2026-10-15T10:00:00")
    _write(tmp_path / "round1" / "waf.csv", _rows([13, 13, 13], [2, 2, 2, 2]), started="2026-10-15T10:05:00")
    _write(tmp_path / "round2" / "waf.csv", _rows([14, 14, 14], [2, 2, 2, 2]), started="2026-10-15T11:00:00")
    _write(tmp_path / "round2" / "baseline.csv", _rows([10, 10, 10], [10, 10, 10, 10]), started="2026-10-15T11:05:00")
    s = latency_rounds.summarize(tmp_path)
    assert s["rounds"] == 2
    assert [r["waf_first"] for r in s["per_round"]] == [False, True]
    assert s["benign"]["overhead_p50_ms_per_round"] == [3.0, 4.0]
    assert s["benign"]["overhead_p50_ms_median_of_rounds"] == 3.5
    assert s["all"]["overhead_p50_ms_per_round"][0] < 3.0
    assert s["per_round"][0]["benign"]["waf"]["n"] == 3  # transport error excluded
    lo, hi = s["benign"]["pooled_overhead_p50_ci95_bootstrap"]
    assert 3.0 <= lo <= hi <= 4.0


def test_bootstrap_is_reproducible_and_guards_small_samples():
    a, b = [12.0, 13.0, 14.0, 15.0], [10.0, 11.0, 10.5, 9.5]
    assert latency_rounds.bootstrap_p50_diff(a, b) == latency_rounds.bootstrap_p50_diff(a, b)
    assert latency_rounds.bootstrap_p50_diff([1.0], b) is None


def test_mixed_datasets_rejected(tmp_path):
    _write(tmp_path / "round1" / "baseline.csv", _rows([10], []), sha="a" * 64)
    _write(tmp_path / "round1" / "waf.csv", _rows([12], []), sha="b" * 64)
    with pytest.raises(ValueError, match="different datasets"):
        latency_rounds.summarize(tmp_path)


def test_main_writes_summary_and_fails_without_rounds(tmp_path):
    with pytest.raises(SystemExit):
        latency_rounds.main(["--rounds-dir", str(tmp_path)])
    _write(tmp_path / "round1" / "baseline.csv", _rows([10, 11], []))
    _write(tmp_path / "round1" / "waf.csv", _rows([12, 13], []))
    latency_rounds.main(["--rounds-dir", str(tmp_path)])
    assert json.loads((tmp_path / "latency_summary.json").read_text())["rounds"] == 1
