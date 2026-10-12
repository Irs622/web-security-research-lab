"""Generate academic charts and figures from experiment results."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"

try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive headless backend for automated scripts
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError as err:
    print(f"Error: Required visualization libraries not available: {err}", file=sys.stderr)
    sys.exit(1)


def plot_confusion_matrix(cm: dict, output_file: Path):
    """Plots a 2x2 confusion matrix heatmap."""
    matrix = np.array([
        [cm["TP"], cm["FN"]],
        [cm["FP"], cm["TN"]]
    ])

    fig, ax = plt.subplots(figsize=(6, 5))
    cax = ax.matshow(matrix, cmap="Blues")
    fig.colorbar(cax)

    labels = [
        [f"TP\n{cm['TP']}", f"FN\n{cm['FN']}"],
        [f"FP\n{cm['FP']}", f"TN\n{cm['TN']}"]
    ]

    for i in range(2):
        for j in range(2):
            ax.text(j, i, labels[i][j], ha="center", va="center", color="black", fontsize=14, weight="bold")

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Detected (Positive)", "Missed (Negative)"], fontsize=10)
    ax.set_yticklabels(["Malicious (True)", "Benign (False)"], fontsize=10)
    ax.set_xlabel("WAF Observation", fontsize=11, labelpad=10)
    ax.set_ylabel("Ground Truth Class", fontsize=11, labelpad=10)
    ax.set_title("WAF Detection Confusion Matrix", fontsize=12, pad=15, weight="bold")

    plt.tight_layout()
    fig.savefig(output_file, dpi=300)
    plt.close(fig)
    print(f"[OK] Generated: {output_file}")


def plot_latency_comparison(metrics: dict, output_file: Path):
    """Plots latency metrics comparison between Baseline and WAF."""
    b_lat = metrics.get("latency_baseline", {})
    w_lat = metrics.get("latency_waf", {})

    categories = ["Mean", "p50 (Median)", "p95"]
    baseline_vals = [b_lat.get("mean_ms", 0) or 0, b_lat.get("p50_ms", 0) or 0, b_lat.get("p95_ms", 0) or 0]
    waf_vals = [w_lat.get("mean_ms", 0) or 0, w_lat.get("p50_ms", 0) or 0, w_lat.get("p95_ms", 0) or 0]

    x = np.arange(len(categories))
    width = 0.35

    fig, ax = plt.subplots(figsize=(7, 5))
    rects1 = ax.bar(x - width/2, baseline_vals, width, label="Baseline (Direct)", color="#4A90E2")
    rects2 = ax.bar(x + width/2, waf_vals, width, label="WAF (ModSecurity)", color="#E94E77")

    ax.set_ylabel("Latency (milliseconds)", fontsize=11)
    ax.set_title("Response Latency Comparison (Baseline vs WAF)", fontsize=12, weight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=10)
    ax.legend(fontsize=10)
    ax.grid(axis="y", linestyle="--", alpha=0.6)

    # Label heights
    for rect in rects1:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}", xy=(rect.get_x() + rect.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=9)
    for rect in rects2:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}", xy=(rect.get_x() + rect.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    fig.savefig(output_file, dpi=300)
    plt.close(fig)
    print(f"[OK] Generated: {output_file}")


def plot_category_breakdown(breakdown: dict, output_file: Path):
    """Plots category breakdown of Total, Detected, and Blocked."""
    cats = list(breakdown.keys())
    totals = [breakdown[c]["total"] for c in cats]
    detected = [breakdown[c]["detected"] for c in cats]
    blocked = [breakdown[c]["blocked"] for c in cats]

    x = np.arange(len(cats))
    width = 0.25

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(x - width, totals, width, label="Total Requests", color="#7F8C8D")
    ax.bar(x, detected, width, label="WAF Detected", color="#F39C12")
    ax.bar(x + width, blocked, width, label="WAF Blocked (403)", color="#27AE60")

    ax.set_ylabel("Request Count", fontsize=11)
    ax.set_title("WAF Evaluation Breakdown by Attack Category", fontsize=12, weight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels([c.upper() for c in cats], fontsize=10)
    ax.legend(fontsize=10)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    plt.tight_layout()
    fig.savefig(output_file, dpi=300)
    plt.close(fig)
    print(f"[OK] Generated: {output_file}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate thesis charts from summary_metrics.json.")
    parser.add_argument("--summary", default=str(RESULTS_DIR / "summary_metrics.json"), help="Summary JSON path")
    parser.add_argument("--output-dir", default=str(RESULTS_DIR), help="Directory for PNG output")
    args = parser.parse_args(argv)
    summary_path = Path(args.summary)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if not summary_path.exists():
        print(f"Error: {summary_path} not found. Run analyze_results.py first.", file=sys.stderr)
        sys.exit(1)

    with summary_path.open(encoding="utf-8") as f:
        metrics = json.load(f)

    plot_confusion_matrix(metrics["confusion_matrix"], out_dir / "confusion_matrix.png")
    plot_latency_comparison(metrics, out_dir / "latency_comparison.png")
    plot_category_breakdown(metrics["category_breakdown"], out_dir / "category_breakdown.png")
    print("\n[OK] All evaluation charts generated successfully.")


if __name__ == "__main__":
    main()
