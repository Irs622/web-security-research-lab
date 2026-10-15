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
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from simulator.target_validator import StrictNoRedirectHandler, validate_target_url
from simulator.log_correlator import TRACE_HEADER, WafLogCorrelator
from evaluation.analyze_results import filter_attack_rules, is_outbound_only

ROOT = Path(__file__).resolve().parents[1]

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
    # Appended (v2 schema) so older CSVs remain readable column-for-column.
    "waf_alert",
    "intervention_evidence",
    "block_source",
    "backend_outcome",
    "scenario_applicability",
]

# Status codes a backend uses to refuse a request on its own (not a WAF decision).
APPLICATION_REFUSAL_STATUSES = {401, 403}


def _git_sha() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _git_dirty() -> Optional[bool]:
    """True when tracked code/config differs from HEAD, i.e. git_sha alone does not identify it.

    results/ is excluded: an experiment pipeline rewrites tracked result files from earlier
    stages, which says nothing about the code that produced the current run.
    """
    try:
        out = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no", "--", ".",
                              ":(exclude)results"],
                             capture_output=True, text=True, timeout=5, check=False)
        return bool(out.stdout.strip()) if out.returncode == 0 else None
    except Exception:
        return None


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


def _container_env(name: str, keys: Tuple[str, ...]) -> Dict[str, str]:
    """Reads selected environment variables of a running container (what the WAF really uses)."""
    try:
        out = subprocess.run(["docker", "inspect", "--format", "{{json .Config.Env}}", name],
                             capture_output=True, text=True, timeout=5, check=False)
        pairs = (item.partition("=") for item in json.loads(out.stdout or "null") or [])
        return {k: v for k, _, v in pairs if k in keys}
    except Exception:
        return {}


def _container_mounts(name: str) -> List[str]:
    """Bind-mount destinations, e.g. the tuned exclusion file mounted over the CRS default."""
    try:
        out = subprocess.run(["docker", "inspect", "--format", "{{json .Mounts}}", name],
                             capture_output=True, text=True, timeout=5, check=False)
        return sorted(m.get("Destination", "") for m in json.loads(out.stdout or "null") or [])
    except Exception:
        return []


def _load_average() -> Optional[List[float]]:
    """1/5/15-minute host load average; a busy host inflates latency tails."""
    try:
        return [round(v, 2) for v in os.getloadavg()]
    except (AttributeError, OSError):
        return None


def _file_sha256(path: Optional[Path]) -> Optional[str]:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest() if path else None
    except OSError:
        return None


def build_run_metadata(run_id: str, mode: str, cases: List[Dict[str, Any]], repeat: int, warmup: int,
                       dataset_path: Optional[Path] = None, target: str = "") -> Dict[str, Any]:
    """Captures what is needed to reproduce a run: code version, dataset hash, images, WAF tuning."""
    dataset_hash = hashlib.sha256(json.dumps(cases, sort_keys=True).encode("utf-8")).hexdigest()
    tuned = os.environ.get("TUNED") == "1"
    exclusions = ROOT / "lab" / "tuning" / "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
    metadata = {
        "run_id": run_id,
        "mode": mode,
        "target": target,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "git_sha": _git_sha(),
        "git_dirty": _git_dirty(),
        "dataset_path": str(dataset_path) if dataset_path else None,
        "dataset_file_sha256": _file_sha256(dataset_path),
        "dataset_sha256": dataset_hash,
        "case_count": len(cases),
        "repeat": repeat,
        "warmup": warmup,
        "paranoia_level": os.environ.get("PARANOIA", "1"),
        "anomaly_inbound": os.environ.get("ANOMALY_INBOUND", "5"),
        "tuned_exclusions": tuned,
        "exclusions_file": str(exclusions.relative_to(ROOT)) if tuned else None,
        "exclusions_sha256": _file_sha256(exclusions) if tuned else None,
        "images": {
            "waf": _container_image("waflab-modsecurity"),
            "juice_shop": _container_image("waflab-juice-shop"),
        },
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "host_load_avg_start": _load_average(),
    }
    if mode == "waf":
        # The environment variables above describe what the operator *intended*; the running
        # container is what was actually measured. Record both so a mismatch is visible.
        metadata["waf_runtime"] = {
            "env": _container_env("waflab-modsecurity", ("PARANOIA", "BLOCKING_PARANOIA", "DETECTION_PARANOIA",
                                                         "ANOMALY_INBOUND",
                                                         "ANOMALY_OUTBOUND", "MODSEC_RULE_ENGINE")),
            "mounts": _container_mounts("waflab-modsecurity"),
        }
    return metadata


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
        applicability = case.get("scenario_applicability", "unspecified")

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
        intervention_evidence = ""
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
                intervention_evidence = "audit_log"
            else:
                # No audit evidence available: fall back to the status code heuristic. Such
                # rows are reported separately and never count as a confirmed block.
                waf_intervention = status in {403, 406}
                intervention_evidence = "status_heuristic"

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

        # Who refused the request, if anyone. A 401/403 that the WAF did not intervene on came
        # from the application itself and says nothing about the WAF.
        if transport_error:
            block_source = ""
        elif observed_outcome == "blocked_by_waf":
            block_source = "waf"
        elif observed_outcome == "rejected_by_proxy":
            block_source = "proxy"
        elif status in APPLICATION_REFUSAL_STATUSES:
            block_source = "application"
        else:
            block_source = "none"

        if transport_error:
            backend_outcome = "transport_error"
        elif block_source == "waf" and is_outbound_only(attack_rules):
            # Outbound anomaly blocking (e.g. 950100 on an HTTP 5xx): the application already
            # processed the request; only its response was replaced by the WAF.
            backend_outcome = "reached_response_blocked"
        elif block_source in {"waf", "proxy"}:
            backend_outcome = "not_reached"
        else:
            backend_outcome = f"{str(status)[0]}xx"

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
            "waf_alert": bool(attack_rules) if self.mode == "waf" else "",
            "intervention_evidence": intervention_evidence,
            "block_source": block_source,
            "backend_outcome": backend_outcome,
            "scenario_applicability": applicability,
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
        dataset_path: Optional[Path] = None,
    ) -> List[Dict[str, Any]]:
        """Runs the test suite ``repeat`` times and persists results to CSV.

        Only ``repeat_index == 0`` rows feed detection metrics; all rows feed latency statistics.
        """
        run_id = f"run_{self.mode}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        results = []
        metadata = build_run_metadata(run_id, self.mode, cases, repeat, warmup,
                                      dataset_path=dataset_path, target=self.base_url)
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
        metadata["host_load_avg_end"] = _load_average()
        metadata["requests_attempted"] = len(schedule)
        metadata["requests_completed"] = sum(1 for r in results if not r["transport_error"])
        metadata["transport_errors"] = sum(1 for r in results if r["transport_error"])
        if self.correlator:
            metadata["audit_log_correlation"] = dict(Counter(r["log_match"] for r in results))
            # ModSecurity's own audit-log "producer" names the engine and CRS versions actually loaded.
            metadata["waf_producer"] = self.correlator.last_producer
        output_path.with_suffix(".meta.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return results
