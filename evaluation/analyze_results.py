"""Research-grade evaluation metrics analyzer for WAF experimental data."""
from __future__ import annotations
import argparse
import csv
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"

# Rule 920350: "Host header is a numeric IP address" — fires on every request because the lab
# uses 127.0.0.1 as the Host value. It contributes anomaly score 3 (below blocking threshold 5)
# and has no bearing on attack-class detection. Excluded from all TP/FP calculations.
LAB_ENVIRONMENT_PROTOCOL_RULES = {"920350"}

# Rule 949110: "Inbound Anomaly Score Exceeded" — a CRS meta-rule that fires when the
# accumulated anomaly score reaches the blocking threshold. It reflects the sum of scores from
# other attack rules already counted above; including it would double-count every TP that was
# blocked. Excluded from has_attack_detection to avoid that double-count.
SCORING_META_RULES = {"949110"}


def filter_attack_rules(rule_ids: List[str]) -> List[str]:
    """Returns only attack-relevant rule IDs (drops lab protocol artifacts and scoring meta-rules)."""
    return [
        r for r in rule_ids
        if r not in LAB_ENVIRONMENT_PROTOCOL_RULES and r not in SCORING_META_RULES
    ]


def load_csv(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def safe_float(val: Any) -> Optional[float]:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def calculate_percentile(data: List[float], p: float) -> Optional[float]:
    if not data:
        return None
    data_sorted = sorted(data)
    idx = (len(data_sorted) - 1) * p
    lo, hi = int(idx), min(int(idx) + 1, len(data_sorted) - 1)
    return data_sorted[lo] + (data_sorted[hi] - data_sorted[lo]) * (idx - lo)


def wilson_interval(successes: int, total: int, z: float = 1.96) -> Optional[List[float]]:
    """Wilson score 95% confidence interval for a binomial proportion (robust for small n)."""
    if total <= 0:
        return None
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = z * ((p * (1 - p) / total + z * z / (4 * total * total)) ** 0.5) / denom
    return [round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4)]


def _is_primary(row: Dict[str, Any]) -> bool:
    """First repetition of a case (rows from single-run CSVs have no repeat_index)."""
    return str(row.get("repeat_index", "") or "0") == "0"


def latency_summary(values: List[float]) -> Dict[str, Optional[float]]:
    def r(v: Optional[float]) -> Optional[float]:
        return round(v, 2) if v is not None else None

    q1, q3 = calculate_percentile(values, 0.25), calculate_percentile(values, 0.75)
    return {
        "n": len(values),
        "mean_ms": r(statistics.mean(values)) if values else None,
        "p50_ms": r(calculate_percentile(values, 0.50)),
        "p95_ms": r(calculate_percentile(values, 0.95)),
        "iqr_ms": r(q3 - q1) if values else None,
    }


def mann_whitney_u(a: List[float], b: List[float]) -> Optional[Dict[str, float]]:
    """Two-sided Mann-Whitney U test (normal approximation, tie-corrected)."""
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return None
    combined = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    ranks = [0.0] * len(combined)
    tie_term = 0.0
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[k] = avg
        t = j - i + 1
        tie_term += t ** 3 - t
        i = j + 1
    r1 = sum(rk for rk, (_, g) in zip(ranks, combined) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2
    n = n1 + n2
    sigma = math.sqrt(n1 * n2 / 12 * ((n + 1) - tie_term / (n * (n - 1))))
    if sigma == 0:
        return {"u": u1, "z": 0.0, "p_value": 1.0}
    z = (u1 - n1 * n2 / 2) / sigma
    p = math.erfc(abs(z) / math.sqrt(2))
    return {"u": round(u1, 2), "z": round(z, 4), "p_value": round(p, 6)}


def evaluate_waf_performance(
    waf_rows: List[Dict[str, Any]],
    baseline_rows: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Calculates scientific evaluation metrics: Confusion Matrix, Recall, Precision, FPR, Latency."""
    if not waf_rows:
        return {"error": "No WAF rows provided"}

    all_valid_waf = [r for r in waf_rows if not r.get("transport_error")]
    # Detection is evaluated once per case; repetitions only add latency samples.
    valid_waf = [r for r in all_valid_waf if _is_primary(r)]

    tp = 0  # Expected malicious, attack rule fired or blocked
    fn = 0  # Expected malicious, missed by attack rules and not blocked
    tn = 0  # Expected benign, no attack rule fired and not blocked
    fp = 0  # Expected benign, attack rule fired or blocked

    malicious_blocked = 0
    malicious_proxy_rejected = 0
    total_malicious = 0

    category_stats: Dict[str, Dict[str, int]] = {}
    misclassified: List[Dict[str, Any]] = []

    for row in valid_waf:
        exp_class = row.get("expected_class", "").lower()
        test_id = row.get("test_id", "")
        cat = (row.get("category") or "").strip() or (test_id.split("-")[0] if "-" in test_id else "OTHER")
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "detected": 0, "blocked": 0}
        category_stats[cat]["total"] += 1

        all_rules = [r.strip() for r in row.get("waf_rule_ids", "").split(";") if r.strip()]
        attack_rules = filter_attack_rules(all_rules)
        # waf_intervention is decided by the runner from the audit log (is_interrupted).
        # A raw HTTP 403 is not used here because the backend can return 403 on its own.
        is_blocked = str(row.get("waf_intervention", "")).lower() == "true"
        has_attack_detection = len(attack_rules) > 0 or is_blocked

        if is_blocked:
            category_stats[cat]["blocked"] += 1
        if has_attack_detection:
            category_stats[cat]["detected"] += 1

        if exp_class == "malicious":
            total_malicious += 1
            if is_blocked:
                malicious_blocked += 1
            elif row.get("observed_outcome") == "rejected_by_proxy":
                malicious_proxy_rejected += 1
            if has_attack_detection:
                tp += 1
            else:
                fn += 1
                misclassified.append({"type": "FN", "test_id": test_id, "category": cat,
                                      "path": row.get("path", ""), "rules": all_rules,
                                      "outcome": row.get("observed_outcome", "")})
        elif exp_class == "benign":
            if has_attack_detection:
                fp += 1
                misclassified.append({"type": "FP", "test_id": test_id, "category": cat,
                                      "path": row.get("path", ""), "rules": all_rules})
            else:
                tn += 1

    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    blocking_rate = (malicious_blocked / total_malicious) if total_malicious > 0 else 0.0

    waf_latencies = [lat for r in all_valid_waf if (lat := safe_float(r.get("latency_ms"))) is not None]
    waf_p50 = calculate_percentile(waf_latencies, 0.50)
    waf_p95 = calculate_percentile(waf_latencies, 0.95)
    waf_mean = statistics.mean(waf_latencies) if waf_latencies else None

    base_latencies: List[float] = []
    base_p50, base_p95, base_mean, latency_overhead = None, None, None, None
    if baseline_rows:
        valid_base = [r for r in baseline_rows if not r.get("transport_error")]
        base_latencies = [lat for r in valid_base if (lat := safe_float(r.get("latency_ms"))) is not None]
        if base_latencies:
            base_p50 = calculate_percentile(base_latencies, 0.50)
            base_p95 = calculate_percentile(base_latencies, 0.95)
            base_mean = statistics.mean(base_latencies)
            if waf_mean is not None:
                latency_overhead = round(waf_mean - base_mean, 2)

    return {
        "sample_count": len(valid_waf),
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "detection_rate_recall": round(recall, 4),
        "precision": round(precision, 4),
        "false_positive_rate": round(fpr, 4),
        "f1_score": round(f1, 4),
        "blocking_rate": round(blocking_rate, 4),
        "malicious_blocked": malicious_blocked,
        "malicious_rejected_by_proxy": malicious_proxy_rejected,
        "overall_mitigation_rate": round(
            (malicious_blocked + malicious_proxy_rejected) / total_malicious, 4) if total_malicious else 0.0,
        "total_malicious": total_malicious,
        "latency_waf": {
            "mean_ms": round(waf_mean, 2) if waf_mean is not None else None,
            "p50_ms": round(waf_p50, 2) if waf_p50 is not None else None,
            "p95_ms": round(waf_p95, 2) if waf_p95 is not None else None,
        },
        "latency_baseline": {
            "mean_ms": round(base_mean, 2) if base_mean is not None else None,
            "p50_ms": round(base_p50, 2) if base_p50 is not None else None,
            "p95_ms": round(base_p95, 2) if base_p95 is not None else None,
        },
        "latency_overhead_mean_ms": latency_overhead,
        "latency_stats": {
            "waf": latency_summary(waf_latencies),
            "baseline": latency_summary(base_latencies),
            "mann_whitney_u": mann_whitney_u(waf_latencies, base_latencies),
        },
        "confidence_intervals_95": {
            "detection_rate_recall": wilson_interval(tp, tp + fn),
            "precision": wilson_interval(tp, tp + fp),
            "false_positive_rate": wilson_interval(fp, fp + tn),
            "blocking_rate": wilson_interval(malicious_blocked, total_malicious),
        },
        "category_breakdown": category_stats,
        "misclassified": misclassified,
    }


def print_report(metrics: Dict[str, Any]):
    print("=" * 65)
    print("      WAF SECURITY TESTING LAB - EXPERIMENTAL EVALUATION")
    print("=" * 65)
    print(f"Total Evaluated Samples: {metrics['sample_count']}")

    cm = metrics["confusion_matrix"]
    print("\n--- CONFUSION MATRIX (Attack Detection vs Ground Truth) ---")
    print(f"  True Positives  (TP) : {cm['TP']:<4} (Malicious correctly detected)")
    print(f"  False Positives (FP) : {cm['FP']:<4} (Benign incorrectly flagged as attack)")
    print(f"  True Negatives  (TN) : {cm['TN']:<4} (Benign correctly allowed without alert)")
    print(f"  False Negatives (FN) : {cm['FN']:<4} (Malicious attack missed)")

    print("\n--- CORE RESEARCH METRICS ---")
    print(f"  Detection Rate / Recall (TPR) : {metrics['detection_rate_recall'] * 100:.2f}%")
    print(f"  Precision                     : {metrics['precision'] * 100:.2f}%")
    print(f"  False Positive Rate (FPR)     : {metrics['false_positive_rate'] * 100:.2f}%")
    print(f"  F1-Score                      : {metrics['f1_score']:.4f}")
    print(f"  Enforcement / Blocking Rate   : {metrics['blocking_rate'] * 100:.2f}% "
          f"({metrics['malicious_blocked']}/{metrics['total_malicious']})")
    print(f"  Rejected by Nginx (pre-WAF)   : {metrics['malicious_rejected_by_proxy']} "
          f"-> overall mitigation {metrics['overall_mitigation_rate'] * 100:.2f}%")

    ci = metrics.get("confidence_intervals_95", {})
    print("\n--- 95% CONFIDENCE INTERVALS (Wilson) ---")
    for name, bounds in ci.items():
        if bounds:
            print(f"  {name:<30}: [{bounds[0] * 100:.2f}%, {bounds[1] * 100:.2f}%]")

    print("\n--- LATENCY & PERFORMANCE OVERHEAD ---")
    w_lat = metrics["latency_waf"]
    b_lat = metrics["latency_baseline"]
    if b_lat["mean_ms"] is not None:
        print(f"  Baseline Latency  : Mean={b_lat['mean_ms']} ms | p50={b_lat['p50_ms']} ms | p95={b_lat['p95_ms']} ms")
    print(f"  WAF Latency       : Mean={w_lat['mean_ms']} ms | p50={w_lat['p50_ms']} ms | p95={w_lat['p95_ms']} ms")
    if metrics["latency_overhead_mean_ms"] is not None:
        print(f"  Inspection Overhead: +{metrics['latency_overhead_mean_ms']} ms mean latency per request")
    stats = metrics.get("latency_stats", {})
    print(f"  Samples (WAF/Base): {stats.get('waf', {}).get('n')} / {stats.get('baseline', {}).get('n')} "
          f"| IQR WAF={stats.get('waf', {}).get('iqr_ms')} ms, Base={stats.get('baseline', {}).get('iqr_ms')} ms")
    mw = stats.get("mann_whitney_u")
    if mw:
        verdict = "significant" if mw["p_value"] < 0.05 else "not significant"
        print(f"  Mann-Whitney U    : U={mw['u']} z={mw['z']} p={mw['p_value']} ({verdict} at a=0.05)")

    print("\n--- BREAKDOWN BY ATTACK CATEGORY ---")
    print(f"  {'Category':<16} | {'Total':<6} | {'Detected':<9} | {'Blocked':<8}")
    print("  " + "-" * 48)
    for cat, data in metrics["category_breakdown"].items():
        print(f"  {cat:<16} | {data['total']:<6} | {data['detected']:<9} | {data['blocked']:<8}")

    if metrics.get("misclassified"):
        print("\n--- MISCLASSIFIED CASES (FN / FP) ---")
        for m in metrics["misclassified"]:
            rules = ";".join(m["rules"]) or "-"
            note = "  (rejected by nginx before WAF)" if m.get("outcome") == "rejected_by_proxy" else ""
            print(f"  [{m['type']}] {m['test_id']:<12} {m['path']}  rules={rules}{note}")
    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(description="Compute WAF evaluation metrics from experiment CSVs.")
    parser.add_argument("--waf", default=str(RESULTS_DIR / "waf.csv"), help="WAF-mode results CSV")
    parser.add_argument("--baseline", default=str(RESULTS_DIR / "baseline.csv"), help="Baseline results CSV")
    parser.add_argument("--output", default=str(RESULTS_DIR / "summary_metrics.json"), help="Summary JSON path")
    args = parser.parse_args()
    baseline_file = Path(args.baseline)
    waf_file = Path(args.waf)

    if not waf_file.exists():
        print(f"Error: {waf_file} does not exist. Run WAF simulator first.", file=sys.stderr)
        sys.exit(1)

    waf_data = load_csv(waf_file)
    baseline_data = load_csv(baseline_file) if baseline_file.exists() else None

    metrics = evaluate_waf_performance(waf_data, baseline_data)
    print_report(metrics)

    summary_path = Path(args.output)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"\n[OK] Summary metrics exported to {summary_path}")


if __name__ == "__main__":
    main()
