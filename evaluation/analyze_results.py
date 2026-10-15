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


# Categories with fewer malicious cases than this get a "small sample" flag in the report:
# a Wilson interval at n < 10 is too wide to support a per-category claim.
MIN_CATEGORY_SAMPLE = 10

# Response-phase CRS rules (RESPONSE-95x). They react to what the application answered (e.g. 950100 on an
# HTTP 5xx), not to the request payload, and are reported separately so readers can tell them apart.
OUTBOUND_RULE_PREFIXES = ("95",)


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


def _intervention_evidence(row: Dict[str, Any]) -> str:
    """'audit_log' when the block decision came from ModSecurity's audit record.

    CSVs written before the column existed are classified from ``log_match`` the same way the
    runner does it, so old and new result files are evaluated identically.
    """
    evidence = row.get("intervention_evidence")
    if evidence:
        return evidence
    return "audit_log" if row.get("log_match") in {"trace_id", "uri"} else "status_heuristic"


def _new_bucket() -> Dict[str, Any]:
    return {"total": 0, "detected": 0, "blocked": 0, "malicious": 0, "benign": 0,
            "tp": 0, "fn": 0, "fp": 0, "tn": 0, "blocked_confirmed": 0}


def _finish_bucket(b: Dict[str, Any]) -> Dict[str, Any]:
    b["recall"] = _round(_ratio(b["tp"], b["tp"] + b["fn"]))
    b["recall_ci95"] = wilson_interval(b["tp"], b["tp"] + b["fn"])
    b["blocking_rate"] = _round(_ratio(b["blocked_confirmed"], b["malicious"]))
    b["false_positive_rate"] = _round(_ratio(b["fp"], b["fp"] + b["tn"]))
    b["small_sample"] = 0 < b["malicious"] < MIN_CATEGORY_SAMPLE
    return b


def _is_primary(row: Dict[str, Any]) -> bool:
    """First repetition of a case (rows from single-run CSVs have no repeat_index)."""
    return str(row.get("repeat_index", "") or "0") == "0"


def _ratio(num: int, denom: int) -> Optional[float]:
    return num / denom if denom > 0 else None


def _round(v: Optional[float]) -> Optional[float]:
    return round(v, 4) if v is not None else None


def _pct(v: Optional[float]) -> str:
    return f"{v * 100:.2f}%" if v is not None else "n/a"


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
    malicious_blocked_unverified = 0
    malicious_proxy_rejected = 0
    total_malicious = 0
    outbound_only_alerts = 0

    category_stats: Dict[str, Dict[str, Any]] = {}
    applicability_stats: Dict[str, Dict[str, Any]] = {}
    misclassified: List[Dict[str, Any]] = []

    for row in valid_waf:
        exp_class = row.get("expected_class", "").lower()
        test_id = row.get("test_id", "")
        cat = (row.get("category") or "").strip() or (test_id.split("-")[0] if "-" in test_id else "OTHER")
        applicability = (row.get("scenario_applicability") or "").strip() or "unspecified"
        buckets = [category_stats.setdefault(cat, _new_bucket()),
                   applicability_stats.setdefault(applicability, _new_bucket())]

        all_rules = [r.strip() for r in row.get("waf_rule_ids", "").split(";") if r.strip()]
        attack_rules = filter_attack_rules(all_rules)
        # waf_intervention is decided by the runner from the audit log (is_interrupted).
        # A raw HTTP 403 is not used here because the backend can return 403 on its own.
        is_blocked = str(row.get("waf_intervention", "")).lower() == "true"
        # Only an audit-log-backed interruption counts as a confirmed block; a status-code
        # fallback (no audit record) is reported separately as unverified.
        is_confirmed_block = is_blocked and _intervention_evidence(row) == "audit_log"
        has_attack_detection = len(attack_rules) > 0 or is_blocked
        if attack_rules and all(r.startswith(OUTBOUND_RULE_PREFIXES) for r in attack_rules) and not is_blocked:
            outbound_only_alerts += 1

        for b in buckets:
            b["total"] += 1
            b["blocked"] += int(is_blocked)
            b["detected"] += int(has_attack_detection)

        if exp_class == "malicious":
            total_malicious += 1
            if is_confirmed_block:
                malicious_blocked += 1
            elif is_blocked:
                malicious_blocked_unverified += 1
            elif row.get("observed_outcome") == "rejected_by_proxy":
                malicious_proxy_rejected += 1
            outcome = "tp" if has_attack_detection else "fn"
            for b in buckets:
                b["malicious"] += 1
                b[outcome] += 1
                b["blocked_confirmed"] += int(is_confirmed_block)
            if has_attack_detection:
                tp += 1
            else:
                fn += 1
                misclassified.append({"type": "FN", "test_id": test_id, "category": cat,
                                      "path": row.get("path", ""), "rules": all_rules,
                                      "outcome": row.get("observed_outcome", ""),
                                      "scenario_applicability": applicability})
        elif exp_class == "benign":
            outcome = "fp" if has_attack_detection else "tn"
            for b in buckets:
                b["benign"] += 1
                b[outcome] += 1
            if has_attack_detection:
                fp += 1
                misclassified.append({"type": "FP", "test_id": test_id, "category": cat,
                                      "path": row.get("path", ""), "rules": all_rules,
                                      "outcome": row.get("observed_outcome", "")})
            else:
                tn += 1

    # Ratios with an empty denominator are undefined (None), not 0.0: a benign-only hold-out set
    # has no recall, and reporting 0% would read as "detected nothing".
    recall = _ratio(tp, tp + fn)
    precision = _ratio(tp, tp + fp)
    fpr = _ratio(fp, fp + tn)
    specificity = _ratio(tn, tn + fp)
    if recall is None or precision is None:
        f1 = None
    else:
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    blocking_rate = _ratio(malicious_blocked, total_malicious)

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
    latency_overhead_p50 = round(waf_p50 - base_p50, 2) if waf_p50 is not None and base_p50 is not None else None

    return {
        "sample_count": len(valid_waf),
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "detection_rate_recall": _round(recall),
        "precision": _round(precision),
        "false_positive_rate": _round(fpr),
        "specificity": _round(specificity),
        "f1_score": _round(f1),
        "blocking_rate": _round(blocking_rate),
        "malicious_blocked": malicious_blocked,
        "malicious_blocked_unverified": malicious_blocked_unverified,
        "malicious_rejected_by_proxy": malicious_proxy_rejected,
        "alerts_outbound_only": outbound_only_alerts,
        "overall_mitigation_rate": _round(_ratio(malicious_blocked + malicious_proxy_rejected, total_malicious)),
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
        "latency_overhead_p50_ms": latency_overhead_p50,
        "latency_stats": {
            "waf": latency_summary(waf_latencies),
            "baseline": latency_summary(base_latencies),
            "mann_whitney_u": mann_whitney_u(waf_latencies, base_latencies),
        },
        "confidence_intervals_95": {
            "detection_rate_recall": wilson_interval(tp, tp + fn),
            "precision": wilson_interval(tp, tp + fp),
            "false_positive_rate": wilson_interval(fp, fp + tn),
            "specificity": wilson_interval(tn, tn + fp),
            "blocking_rate": wilson_interval(malicious_blocked, total_malicious),
        },
        "category_breakdown": {k: _finish_bucket(v) for k, v in category_stats.items()},
        "applicability_breakdown": {k: _finish_bucket(v) for k, v in applicability_stats.items()},
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
    f1 = metrics["f1_score"]
    print(f"  Detection Rate / Recall (TPR) : {_pct(metrics['detection_rate_recall'])}")
    print(f"  Precision                     : {_pct(metrics['precision'])}")
    print(f"  False Positive Rate (FPR)     : {_pct(metrics['false_positive_rate'])}")
    print(f"  Specificity (TNR)             : {_pct(metrics.get('specificity'))}")
    print(f"  F1-Score                      : {f'{f1:.4f}' if f1 is not None else 'n/a'}")
    print(f"  Enforcement / Blocking Rate   : {_pct(metrics['blocking_rate'])} "
          f"({metrics['malicious_blocked']}/{metrics['total_malicious']}, audit-log confirmed)")
    if metrics.get("malicious_blocked_unverified"):
        print(f"  Unverified blocks (status only): {metrics['malicious_blocked_unverified']} "
              "(no audit record; NOT counted in the blocking rate)")
    if metrics.get("alerts_outbound_only"):
        print(f"  Outbound-only alerts (95xxxx) : {metrics['alerts_outbound_only']} "
              "(response-phase rule only; counted as detection)")
    print(f"  Rejected by Nginx (pre-WAF)   : {metrics['malicious_rejected_by_proxy']} "
          f"-> overall mitigation {_pct(metrics['overall_mitigation_rate'])}")

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
        print(f"  Inspection Overhead: {metrics['latency_overhead_mean_ms']:+} ms mean, "
              f"{metrics.get('latency_overhead_p50_ms')} ms p50 per request")
    stats = metrics.get("latency_stats", {})
    print(f"  Samples (WAF/Base): {stats.get('waf', {}).get('n')} / {stats.get('baseline', {}).get('n')} "
          f"| IQR WAF={stats.get('waf', {}).get('iqr_ms')} ms, Base={stats.get('baseline', {}).get('iqr_ms')} ms")
    mw = stats.get("mann_whitney_u")
    if mw:
        verdict = "significant" if mw["p_value"] < 0.05 else "not significant"
        print(f"  Mann-Whitney U    : U={mw['u']} z={mw['z']} p={mw['p_value']} ({verdict} at a=0.05)")

    groups = (("ATTACK CATEGORY", "category_breakdown"), ("SCENARIO APPLICABILITY", "applicability_breakdown"))
    for title, key in groups:
        print(f"\n--- BREAKDOWN BY {title} ---")
        print(f"  {'Group':<20} | {'n':<4} | {'Detected':<8} | {'Blocked':<7} | {'Recall':<8} | "
              f"{'Block rate':<10} | {'FPR':<8}")
        print("  " + "-" * 82)
        for name, d in metrics.get(key, {}).items():
            flag = "  (n<%d)" % MIN_CATEGORY_SAMPLE if d.get("small_sample") else ""
            print(f"  {name:<20} | {d['total']:<4} | {d['detected']:<8} | {d['blocked']:<7} | "
                  f"{_pct(d.get('recall')):<8} | {_pct(d.get('blocking_rate')):<10} | "
                  f"{_pct(d.get('false_positive_rate')):<8}{flag}")

    if metrics.get("misclassified"):
        print("\n--- MISCLASSIFIED CASES (FN / FP) ---")
        for m in metrics["misclassified"]:
            rules = ";".join(m["rules"]) or "-"
            note = "  (rejected by nginx before WAF)" if m.get("outcome") == "rejected_by_proxy" else ""
            print(f"  [{m['type']}] {m['test_id']:<12} {m['path']}  rules={rules}{note}")
    print("=" * 65)


def _read_meta(csv_path: Path) -> Optional[Dict[str, Any]]:
    meta = csv_path.with_suffix(".meta.json")
    try:
        return json.loads(meta.read_text(encoding="utf-8")) if meta.is_file() else None
    except (OSError, ValueError):
        return None


def dataset_mismatch(waf_csv: Path, baseline_csv: Path) -> Optional[str]:
    """Explains why a WAF and a baseline CSV must not be combined, or returns None.

    Latency overhead is only meaningful when both runs sent the same requests; comparing a
    WAF run on the extended dataset with a stale baseline from the original one is a silent error.
    """
    waf_meta, base_meta = _read_meta(waf_csv), _read_meta(baseline_csv)
    if not waf_meta or not base_meta:
        return None
    if waf_meta.get("dataset_sha256") != base_meta.get("dataset_sha256"):
        return (f"{waf_csv} and {baseline_csv} were produced from different datasets "
                f"({waf_meta.get('case_count')} vs {base_meta.get('case_count')} cases). "
                "Re-run the baseline with the same --cases file.")
    return None


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

    mismatch = dataset_mismatch(waf_file, baseline_file)
    if mismatch:
        print(f"Error: {mismatch}", file=sys.stderr)
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
