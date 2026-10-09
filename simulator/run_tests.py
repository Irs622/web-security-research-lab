#!/usr/bin/env python3
"""CLI interface for running controlled security test experiments."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from simulator.runner import ExperimentRunner

CASES_FILE = ROOT / "simulator" / "attack_cases.json"
RESULTS_DIR = ROOT / "results"


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
        "--no-docker-logs",
        action="store_true",
        help="Disable automatic WAF audit log correlation via Docker CLI",
    )
    args = parser.parse_args()

    cases_path = Path(args.cases)
    if not cases_path.exists():
        print(f"Error: Cases file not found at {cases_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with cases_path.open(encoding="utf-8") as f:
            cases = json.load(f)
    except Exception as exc:
        print(f"Error loading test cases: {exc}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output) if args.output else RESULTS_DIR / f"{args.mode}.csv"

    print(f"=== WAF Research Lab: Starting {args.mode.upper()} Experiment ===")
    print(f"Target:       {args.target}")
    print(f"Dataset:      {cases_path} (N={len(cases)} cases)")
    print(f"Delay:        {args.delay} s")
    print(f"Output CSV:   {output_path}\n")

    try:
        runner = ExperimentRunner(
            base_url=args.target,
            mode=args.mode,
            delay_seconds=args.delay,
            timeout_seconds=args.timeout,
            enable_log_correlation=not args.no_docker_logs,
        )
        runner.run_suite(cases=cases, output_path=output_path)
    except Exception as exc:
        print(f"\nExecution Aborted: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[OK] Experiment run completed successfully.")
    print(f"[OK] Results written to: {output_path}")


if __name__ == "__main__":
    main()
