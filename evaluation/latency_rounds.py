"""Aggregate latency across repeated, order-alternated baseline/WAF rounds.

A single baseline run followed by a single WAF run confounds the WAF overhead with whatever the
host was doing at the time. ``make experiment-latency`` runs several rounds (alternating which
mode goes first) and this script reports the per-round p50 overhead and its spread, plus a
bootstrap confidence interval on the pooled p50 difference.

The primary figure uses benign requests only: a malicious request blocked by the WAF never
reaches the backend, so including it would make the WAF look faster than it is for real users.
"""
from __future__ import annotations
import argparse
import json
import random
import re
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evaluation.analyze_results import calculate_percentile, load_csv, safe_float  # noqa: E402

BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 20261015


def latencies(rows: List[Dict[str, Any]], benign_only: bool) -> List[float]:
    out = []
    for r in rows:
        if r.get("transport_error") or (benign_only and r.get("expected_class") != "benign"):
            continue
        lat = safe_float(r.get("latency_ms"))
        if lat is not None:
            out.append(lat)
    return out


def _p50(values: List[float]) -> Optional[float]:
    return calculate_percentile(values, 0.50)


def bootstrap_p50_diff(waf: List[float], base: List[float], resamples: int = BOOTSTRAP_RESAMPLES,
                       seed: int = BOOTSTRAP_SEED) -> Optional[List[float]]:
    """Percentile bootstrap 95% CI for p50(waf) - p50(base); seeded so reports are reproducible."""
    if len(waf) < 2 or len(base) < 2:
        return None
    rng = random.Random(seed)
    diffs = sorted(
        _p50(rng.choices(waf, k=len(waf))) - _p50(rng.choices(base, k=len(base)))
        for _ in range(resamples)
    )
    return [round(calculate_percentile(diffs, 0.025), 2), round(calculate_percentile(diffs, 0.975), 2)]


def _round2(v: Optional[float]) -> Optional[float]:
    return round(v, 2) if v is not None else None


def _mode_stats(values: List[float]) -> Dict[str, Any]:
    return {"n": len(values), "p50_ms": _round2(_p50(values)),
            "p95_ms": _round2(calculate_percentile(values, 0.95)),
            "mean_ms": _round2(statistics.mean(values)) if values else None}


def _meta(csv_path: Path) -> Dict[str, Any]:
    meta = csv_path.with_suffix(".meta.json")
    return json.loads(meta.read_text(encoding="utf-8")) if meta.is_file() else {}


def summarize(rounds_dir: Path) -> Dict[str, Any]:
    round_dirs = sorted((d for d in rounds_dir.glob("round*") if d.is_dir()),
                        key=lambda d: int(re.sub(r"\D", "", d.name) or 0))
    per_round, pooled = [], {True: {"waf": [], "baseline": []}, False: {"waf": [], "baseline": []}}
    for d in round_dirs:
        base_csv, waf_csv = d / "baseline.csv", d / "waf.csv"
        if not base_csv.exists() or not waf_csv.exists():
            continue
        base_meta, waf_meta = _meta(base_csv), _meta(waf_csv)
        if base_meta.get("dataset_sha256") != waf_meta.get("dataset_sha256"):
            raise ValueError(f"{d}: baseline and WAF runs used different datasets")
        base_rows, waf_rows = load_csv(base_csv), load_csv(waf_csv)
        entry: Dict[str, Any] = {
            "round": d.name,
            "waf_first": (waf_meta.get("started_utc") or "") < (base_meta.get("started_utc") or ""),
            "host_load_avg": {"baseline": base_meta.get("host_load_avg_start"),
                              "waf": waf_meta.get("host_load_avg_start")},
        }
        for benign_only, key in ((True, "benign"), (False, "all")):
            w, b = latencies(waf_rows, benign_only), latencies(base_rows, benign_only)
            pooled[benign_only]["waf"] += w
            pooled[benign_only]["baseline"] += b
            wp, bp = _p50(w), _p50(b)
            entry[key] = {"waf": _mode_stats(w), "baseline": _mode_stats(b),
                          "overhead_p50_ms": _round2(wp - bp) if wp is not None and bp is not None else None}
        per_round.append(entry)

    summary: Dict[str, Any] = {"rounds": len(per_round), "per_round": per_round}
    for benign_only, key in ((True, "benign"), (False, "all")):
        overheads = [r[key]["overhead_p50_ms"] for r in per_round if r[key]["overhead_p50_ms"] is not None]
        w, b = pooled[benign_only]["waf"], pooled[benign_only]["baseline"]
        summary[key] = {
            "overhead_p50_ms_per_round": overheads,
            "overhead_p50_ms_median_of_rounds": _round2(statistics.median(overheads)) if overheads else None,
            "overhead_p50_ms_range": [min(overheads), max(overheads)] if overheads else None,
            "pooled": {"waf": _mode_stats(w), "baseline": _mode_stats(b)},
            "pooled_overhead_p50_ms": _round2(_p50(w) - _p50(b)) if w and b else None,
            "pooled_overhead_p50_ci95_bootstrap": bootstrap_p50_diff(w, b),
        }
    return summary


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Summarize multi-round latency experiments.")
    parser.add_argument("--rounds-dir", required=True, help="Directory containing round<N>/{baseline,waf}.csv")
    args = parser.parse_args(argv)
    rounds_dir = Path(args.rounds_dir)
    try:
        summary = summarize(rounds_dir)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    if not summary["rounds"]:
        print(f"Error: no round*/baseline.csv + waf.csv under {rounds_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"  {'Round':<8} | {'WAF first':<9} | {'Benign Δp50 ms':<14} | {'All Δp50 ms':<11} | load avg (base/waf)")
    for r in summary["per_round"]:
        load = r["host_load_avg"]
        print(f"  {r['round']:<8} | {str(r['waf_first']):<9} | {str(r['benign']['overhead_p50_ms']):<14} | "
              f"{str(r['all']['overhead_p50_ms']):<11} | {load['baseline']} / {load['waf']}")
    b = summary["benign"]
    print(f"\n  Benign-only overhead p50: median of rounds {b['overhead_p50_ms_median_of_rounds']} ms, "
          f"range {b['overhead_p50_ms_range']}, pooled {b['pooled_overhead_p50_ms']} ms "
          f"(bootstrap 95% CI {b['pooled_overhead_p50_ci95_bootstrap']})")
    out = rounds_dir / "latency_summary.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\n[OK] Latency summary written to {out}")


if __name__ == "__main__":
    main()
