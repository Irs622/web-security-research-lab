"""Controlled security test runner for baseline and WAF lab evaluation."""
from __future__ import annotations
import csv
import hashlib
import json
import os
import platform
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from simulator.target_validator import StrictNoRedirectHandler, validate_target_url
from simulator.log_correlator import TRACE_HEADER, WafLogCorrelator
from evaluation.analyze_results import filter_attack_rules

CSV_FIELDS = [
    "run_id",
    "test_id",
    "category",
    "repeat_index",
    "mode",
    "timestamp_utc",
    "method",
    "path",
    "http_status",
    "latency_ms",
    "response_size_bytes",
    "transport_error",
    "waf_rule_ids",
    "waf_intervention",
    "trace_id",
    "log_match",
    "expected_class",
    "observed_outcome",
]


def _git_sha() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _container_image(name: str) -> str:
    try:
        out = subprocess.run(["docker", "inspect", "--format", "{{.Config.Image}}|{{.Image}}", name],
                             capture_output=True, text=True, timeout=5, check=False)
        ref, _, image_id = out.stdout.strip().partition("|")
        if not ref:
            return "unavailable"
        # A pinned reference already carries its digest; otherwise append the local image id.
        return ref if "@sha256:" in ref else f"{ref}@{image_id}"
    except Exception:
        return "unavailable"


def build_run_metadata(run_id: str, mode: str, cases: List[Dict[str, Any]], repeat: int, warmup: int) -> Dict[str, Any]:
    """Captures what is needed to reproduce a run: code version, dataset hash, images, WAF tuning."""
    dataset_hash = hashlib.sha256(json.dumps(cases, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "run_id": run_id,
        "mode": mode,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "git_sha": _git_sha(),
        "dataset_sha256": dataset_hash,
        "case_count": len(cases),
        "repeat": repeat,
        "warmup": warmup,
        "paranoia_level": os.environ.get("PARANOIA", "1"),
        "anomaly_inbound": os.environ.get("ANOMALY_INBOUND", "5"),
        "tuned_exclusions": os.environ.get("TUNED") == "1",
        "images": {
            "waf": _container_image("waflab-modsecurity"),
            "juice_shop": _container_image("waflab-juice-shop"),
        },
        "python": platform.python_version(),
        "platform": platform.platform(),
    }


class ExperimentRunner:
    """Executes controlled test requests against the lab environment."""

    def __init__(
        self,
        base_url: str,
        mode: str,
        delay_seconds: float = 0.25,
        timeout_seconds: float = 5.0,
        enable_log_correlation: bool = True,
    ):
        self.mode = mode
        self.base_url = validate_target_url(base_url, expected_mode=mode)
        self.delay = max(0.1, delay_seconds)
        self.timeout = timeout_seconds
        self.enable_log_correlation = enable_log_correlation and (mode == "waf")
        self.correlator = WafLogCorrelator() if self.enable_log_correlation else None

        # Build custom opener with strict redirect blocking
        self.opener = urllib.request.build_opener(StrictNoRedirectHandler())

    def execute_test(self, case: Dict[str, Any], run_id: str) -> Dict[str, Any]:
        """Executes a single test case and captures metrics."""
        method = case.get("method", "GET").upper()
        path = case.get("path", "/")
        params = case.get("params", {})
        headers = dict(case.get("headers", {}))
        body = case.get("body")
        expected_class = case.get("expected_class", "unknown")

        headers.setdefault("User-Agent", "WAF-Research-Lab-Simulator/2.0")
        # Real browsers always send Accept; omitting it trips CRS 920300 at PL2+ on every
        # request, which would measure the simulator rather than the WAF.
        headers.setdefault("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
        trace_id = uuid.uuid4().hex
        headers[TRACE_HEADER] = trace_id

        query_str = urllib.parse.urlencode(params, doseq=True) if params else ""
        full_path = path + (f"?{query_str}" if query_str else "")
        target_url = self.base_url + full_path

        data_bytes: Optional[bytes] = None
        if body:
            data_bytes = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            url=target_url,
            data=data_bytes,
            headers=headers,
            method=method,
        )

        started = time.perf_counter()
        status: Optional[int] = None
        response_bytes = 0
        transport_error = ""

        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                status = resp.status
                body_content = resp.read(65536)
                response_bytes = len(body_content)
        except urllib.error.HTTPError as http_err:
            status = http_err.code
            try:
                body_content = http_err.read(65536)
                response_bytes = len(body_content)
            except Exception:
                pass
        except Exception as exc:
            transport_error = f"{type(exc).__name__}: {exc}"

        latency_ms = round((time.perf_counter() - started) * 1000, 2)

        # Correlate with ModSecurity logs if in WAF mode
        waf_rules: List[str] = []
        waf_intervention = False
        log_match = "disabled"
        if self.mode == "waf" and status is not None:
            if self.correlator:
                # Poll the audit log until this request's trace id appears (bounded wait).
                r_ids, interrupted, _, log_match = self.correlator.correlate_request(
                    method, full_path, trace_id=trace_id, poll_attempts=5, poll_interval=0.1
                )
                waf_rules = r_ids
            if log_match != "none" and log_match != "disabled":
                # Audit log is authoritative: a 403 produced by the backend application
                # itself (e.g. Juice Shop's own /ftp guard) is NOT a WAF intervention.
                waf_intervention = interrupted
            else:
                # No audit evidence available: fall back to the status code heuristic.
                waf_intervention = status in {403, 406}

        attack_rules = filter_attack_rules(waf_rules)

        # Determine observed outcome
        if transport_error:
            observed_outcome = "transport_error"
        elif self.mode == "baseline":
            observed_outcome = "allowed_baseline"
        else:
            if waf_intervention:
                observed_outcome = "blocked_by_waf"
            elif status == 400 and log_match == "none":
                # Nginx rejects malformed/root-escaping URIs before ModSecurity runs, so no
                # audit record exists. Mitigated, but not by the WAF rule engine.
                observed_outcome = "rejected_by_proxy"
            elif attack_rules:
                observed_outcome = "detected_alert_only"
            else:
                observed_outcome = "passed_clean"

        return {
            "run_id": run_id,
            "test_id": case.get("test_id", "UNKNOWN"),
            "category": case.get("category", ""),
            "mode": self.mode,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "path": full_path,
            "http_status": status if status is not None else "",
            "latency_ms": latency_ms,
            "response_size_bytes": response_bytes,
            "transport_error": transport_error,
            "waf_rule_ids": ";".join(waf_rules) if waf_rules else "",
            "waf_intervention": waf_intervention if self.mode == "waf" else "",
            "trace_id": trace_id,
            "log_match": log_match if self.mode == "waf" else "",
            "expected_class": expected_class,
            "observed_outcome": observed_outcome,
        }

    def warm_up(self, requests: int) -> None:
        """Sends unrecorded benign requests so connection setup and JIT effects do not skew latency."""
        for _ in range(max(0, requests)):
            try:
                with self.opener.open(urllib.request.Request(self.base_url + "/"), timeout=self.timeout) as resp:
                    resp.read(1024)
            except Exception:
                pass
            time.sleep(self.delay)

    def run_suite(
        self,
        cases: List[Dict[str, Any]],
        output_path: Path,
        repeat: int = 1,
        warmup: int = 0,
    ) -> List[Dict[str, Any]]:
        """Runs the test suite ``repeat`` times and persists results to CSV.

        Only ``repeat_index == 0`` rows feed detection metrics; all rows feed latency statistics.
        """
        run_id = f"run_{self.mode}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        results = []
        metadata = build_run_metadata(run_id, self.mode, cases, repeat, warmup)
        self.warm_up(warmup)
        schedule = [(rep, case) for rep in range(max(1, repeat)) for case in cases]

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()

            for idx, (rep, case) in enumerate(schedule, 1):
                res = self.execute_test(case, run_id=run_id)
                res["repeat_index"] = rep
                writer.writerow(res)
                results.append(res)

                rule_info = f" [Rules: {res['waf_rule_ids']}]" if res.get("waf_rule_ids") else ""
                err_info = f" [ERR: {res['transport_error']}]" if res.get("transport_error") else ""
                print(
                    f"[{idx:03d}/{len(schedule):03d}] {res['test_id']} ({res['expected_class']}) "
                    f"HTTP {res['http_status']} ({res['latency_ms']} ms) -> {res['observed_outcome']}"
                    f"{rule_info}{err_info}"
                )
                time.sleep(self.delay)

        metadata["finished_utc"] = datetime.now(timezone.utc).isoformat()
        metadata["transport_errors"] = sum(1 for r in results if r["transport_error"])
        output_path.with_suffix(".meta.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return results
