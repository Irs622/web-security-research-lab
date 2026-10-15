#!/usr/bin/env python3
"""CLI interface for running controlled security test experiments."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from simulator.runner import ExperimentRunner

CASES_FILE = ROOT / "simulator" / "attack_cases.json"
RESULTS_DIR = ROOT / "results"


class DatasetError(ValueError):
    """Raised when a test-case dataset is missing or malformed."""


def load_cases(path: Path) -> List[Dict[str, Any]]:
    """Loads and validates a labelled dataset: relative paths, known classes, unique test ids."""
    if not path.exists():
        raise DatasetError(f"Cases file not found at {path}")
    try:
        cases = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise DatasetError(f"Cannot load test cases: {exc}") from exc
    if not isinstance(cases, list) or not cases:
        raise DatasetError("Dataset must be a non-empty JSON array of test cases.")
    invalid = [
        str(c.get("test_id", f"#{i}")) if isinstance(c, dict) else f"#{i}"
        for i, c in enumerate(cases)
        if not isinstance(c, dict)
        or not str(c.get("path", "")).startswith("/")
        or c.get("expected_class") not in {"benign", "malicious"}
    ]
    if invalid:
        raise DatasetError(f"Invalid test cases (need relative path and benign/malicious class): {invalid}")
    ids = [c.get("test_id") for c in cases]
    duplicates = sorted({str(i) for i in ids if i is not None and ids.count(i) > 1})
    if duplicates:
        raise DatasetError(f"Duplicate test_id values would corrupt per-case metrics: {duplicates}")
    return cases


def main():
    parser = argparse.ArgumentParser(
        description="Controlled WAF security test simulator for academic evaluation."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target base URL: http://127.0.0.1:3001 (baseline) or http://127.0.0.1:8080 (WAF)",
    )
    parser.add_argument(
        "--mode",
        choices=["baseline", "waf"],
        required=True,
        help="Evaluation mode to execute",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.25,
        help="Inter-request delay in seconds (minimum 0.1s to prevent DoS)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP request timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--cases",
        type=str,
        default=str(CASES_FILE),
        help="Path to JSON test cases dataset",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Custom output CSV path (default: results/{mode}.csv)",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Repeat the whole suite N times for latency statistics (default: 1)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=5,
        help="Unrecorded warm-up requests before measuring (default: 5)",
    )
    parser.add_argument(
        "--no-docker-logs",
        action="store_true",
        help="Disable automatic WAF audit log correlation via Docker CLI",
    )
    args = parser.parse_args()

    cases_path = Path(args.cases)
    try:
        cases = load_cases(cases_path)
    except DatasetError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    if args.repeat < 1 or args.warmup < 0:
        print("Error: --repeat must be >= 1 and --warmup >= 0.", file=sys.stderr)
        sys.exit(1)
    if args.delay < 0.1:
        print("Error: --delay must be >= 0.1 s (rate limit to avoid stressing the lab).", file=sys.stderr)
        sys.exit(1)
    if args.timeout <= 0:
        print("Error: --timeout must be greater than 0.", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output) if args.output else RESULTS_DIR / f"{args.mode}.csv"

    print(f"=== WAF Research Lab: Starting {args.mode.upper()} Experiment ===")
    print(f"Target:       {args.target}")
    print(f"Dataset:      {cases_path} (N={len(cases)} cases)")
    print(f"Delay:        {args.delay} s")
    print(f"Repeat:       {args.repeat}x (warm-up: {args.warmup})")
    print(f"Output CSV:   {output_path}\n")

    try:
        runner = ExperimentRunner(
            base_url=args.target,
            mode=args.mode,
            delay_seconds=args.delay,
            timeout_seconds=args.timeout,
            enable_log_correlation=not args.no_docker_logs,
        )
        runner.run_suite(cases=cases, output_path=output_path, repeat=args.repeat, warmup=args.warmup,
                         dataset_path=cases_path)
    except Exception as exc:
        print(f"\nExecution Aborted: {exc}", file=sys.stderr)
        sys.exit(1)

    print("\n[OK] Experiment run completed successfully.")
    print(f"[OK] Results written to: {output_path}")


if __name__ == "__main__":
    main()
