"""Compare detection/false-positive trade-offs across CRS Paranoia Levels."""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
MATRIX_DIR = ROOT / "results" / "paranoia"


def collect(matrix_dir: Path) -> List[Dict[str, Any]]:
    """Reads results/paranoia/pl<N>[-tuned]/summary_metrics.json into one row per scenario."""
    rows = []
    for summary in sorted(matrix_dir.glob("pl*/summary_metrics.json")):
        match = re.fullmatch(r"pl(\d+)(-tuned)?", summary.parent.name)
        if not match:
            continue
        m = json.loads(summary.read_text(encoding="utf-8"))
        ci = m.get("confidence_intervals_95", {})
        rows.append({
            "scenario": summary.parent.name,
            "paranoia_level": int(match.group(1)),
            "tuned": bool(match.group(2)),
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
    return sorted(rows, key=lambda r: (r["paranoia_level"], r["tuned"]))


def plot(rows: List[Dict[str, Any]], output_file: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    tuned = [r for r in rows if r["tuned"]]
    rows = [r for r in rows if not r["tuned"]]
    levels = [r["paranoia_level"] for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for key, label, marker in (("recall", "Detection Rate (Recall)", "o"),
                               ("false_positive_rate", "False Positive Rate", "s"),
                               ("f1_score", "F1-Score", "^")):
        ax.plot(levels, [r[key] * 100 if r[key] is not None else float("nan") for r in rows],
                marker=marker, label=label)
    for r in tuned:
        ax.scatter([r["paranoia_level"]] * 2, [r["recall"] * 100, r["false_positive_rate"] * 100],
                   marker="*", s=160, color="black", zorder=5)
        ax.annotate(f"PL{r['paranoia_level']} tuned", (r["paranoia_level"], r["false_positive_rate"] * 100),
                    textcoords="offset points", xytext=(8, -4), fontsize=8)
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


def main(matrix_dir: Path = MATRIX_DIR):
    rows = collect(matrix_dir)
    if not rows:
        print(f"Error: no pl*/summary_metrics.json under {matrix_dir}. Run `make experiment-matrix` first.",
              file=sys.stderr)
        sys.exit(1)

    print(f"  {'Scenario':<10} | {'Recall':<8} | {'FPR':<8} | {'Precision':<9} | {'F1':<6} | {'p50 ms':<7}")
    print("  " + "-" * 59)
    def pct(v):
        return f"{v * 100:6.2f}%" if v is not None else "    n/a"

    for r in rows:
        f1 = f"{r['f1_score']:.4f}" if r["f1_score"] is not None else "n/a"
        print(f"  {r['scenario']:<10} | {pct(r['recall'])} | {pct(r['false_positive_rate'])} | "
              f"{pct(r['precision'])}  | {f1:<6} | {r['waf_p50_ms']}")

    (matrix_dir / "paranoia_comparison.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    plot(rows, matrix_dir / "paranoia_tradeoff.png")
    print(f"\n[OK] Comparison written to {matrix_dir}")


if __name__ == "__main__":
    main()
