"""Compare detection/false-positive trade-offs across CRS Paranoia Levels."""
from __future__ import annotations
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
MATRIX_DIR = ROOT / "results" / "paranoia"


def collect(matrix_dir: Path) -> List[Dict[str, Any]]:
    """Reads results/paranoia/pl<N>/summary_metrics.json into one row per level."""
    rows = []
    for summary in sorted(matrix_dir.glob("pl*/summary_metrics.json")):
        level = summary.parent.name[2:]
        if not level.isdigit():
            continue
        m = json.loads(summary.read_text(encoding="utf-8"))
        ci = m.get("confidence_intervals_95", {})
        rows.append({
            "paranoia_level": int(level),
            "recall": m["detection_rate_recall"],
            "recall_ci95": ci.get("detection_rate_recall"),
            "false_positive_rate": m["false_positive_rate"],
            "fpr_ci95": ci.get("false_positive_rate"),
            "precision": m["precision"],
            "f1_score": m["f1_score"],
            "blocking_rate": m["blocking_rate"],
            "waf_p50_ms": m["latency_waf"]["p50_ms"],
            "confusion_matrix": m["confusion_matrix"],
        })
    return sorted(rows, key=lambda r: r["paranoia_level"])


def plot(rows: List[Dict[str, Any]], output_file: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    levels = [r["paranoia_level"] for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for key, label, marker in (("recall", "Detection Rate (Recall)", "o"),
                               ("false_positive_rate", "False Positive Rate", "s"),
                               ("f1_score", "F1-Score", "^")):
        ax.plot(levels, [r[key] * 100 for r in rows], marker=marker, label=label)
    ax.set_xticks(levels)
    ax.set_xlabel("CRS Paranoia Level")
    ax.set_ylabel("Persentase (%)")
    ax.set_ylim(-2, 102)
    ax.set_title("Trade-off Deteksi vs False Positive per Paranoia Level")
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output_file, dpi=200)
    plt.close(fig)


def main():
    rows = collect(MATRIX_DIR)
    if not rows:
        print(f"Error: no pl*/summary_metrics.json under {MATRIX_DIR}. Run `make experiment-matrix` first.",
              file=sys.stderr)
        sys.exit(1)

    print(f"  {'PL':<3} | {'Recall':<8} | {'FPR':<8} | {'Precision':<9} | {'F1':<6} | {'p50 ms':<7}")
    print("  " + "-" * 52)
    for r in rows:
        print(f"  {r['paranoia_level']:<3} | {r['recall'] * 100:6.2f}% | {r['false_positive_rate'] * 100:6.2f}% | "
              f"{r['precision'] * 100:7.2f}% | {r['f1_score']:.4f} | {r['waf_p50_ms']}")

    (MATRIX_DIR / "paranoia_comparison.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    plot(rows, MATRIX_DIR / "paranoia_tradeoff.png")
    print(f"\n[OK] Comparison written to {MATRIX_DIR}")


if __name__ == "__main__":
    main()
