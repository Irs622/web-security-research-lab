"""ModSecurity audit log parser and correlation engine."""
from __future__ import annotations
import json
import subprocess
import time
from typing import Dict, List, Optional, Tuple


TRACE_HEADER = "X-Lab-Trace-Id"


def _header_value(headers: Dict, name: str) -> Optional[str]:
    """Case-insensitive header lookup on an audit-log header mapping."""
    if not isinstance(headers, dict):
        return None
    lname = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lname:
            return str(value)
    return None


class WafLogCorrelator:
    """Fetches and correlates ModSecurity audit logs from the WAF container."""

    def __init__(self, container_name: str = "waflab-modsecurity"):
        self.container_name = container_name

    def fetch_recent_logs(self, tail_lines: int = 200) -> List[Dict]:
        """Fetches the latest JSON audit log transactions from the ModSecurity container."""
        try:
            res = subprocess.run(
                ["docker", "logs", f"--tail={tail_lines}", self.container_name],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except Exception:
            return []

        transactions = []
        raw_output = (res.stdout or "") + "\n" + (res.stderr or "")
        for line in raw_output.splitlines():
            line = line.strip()
            if line.startswith('{"transaction":'):
                try:
                    data = json.loads(line)
                    if "transaction" in data:
                        transactions.append(data["transaction"])
                except Exception:
                    continue
        return transactions

    def correlate_request(
        self,
        method: str,
        path_with_query: str,
        transactions: Optional[List[Dict]] = None,
        trace_id: Optional[str] = None,
        poll_attempts: int = 1,
        poll_interval: float = 0.1,
    ) -> Tuple[List[str], bool, Optional[int], str]:
        """Matches a sent request to a ModSecurity audit transaction.

        Matching prefers the unique per-request trace header, which removes the
        ambiguity of URI-based matching between requests sharing a base path.
        URI matching is kept as a fallback when the header is absent from the log.

        Returns:
            Tuple of (rule_ids_list, was_interrupted, http_code, match_method)
            where match_method is "trace_id", "uri", or "none".

        When ``transactions`` is not supplied, the container log is polled up to
        ``poll_attempts`` times so a slow audit-log flush does not cause a missed match.
        """
        fetch = transactions is None
        attempts = max(1, poll_attempts) if fetch else 1
        for attempt in range(attempts):
            if fetch:
                transactions = self.fetch_recent_logs(tail_lines=100)
            if not trace_id:
                break
            for tx in reversed(transactions):
                headers = tx.get("request", {}).get("headers", {})
                if _header_value(headers, TRACE_HEADER) == trace_id:
                    return (*self._extract(tx), "trace_id")
            if attempt < attempts - 1:
                time.sleep(poll_interval)

        # If the log records trace headers at all, a missing trace id means this request's
        # transaction is not (yet) in the log. Falling back to URI matching would then pick up
        # an older transaction for the same URI (warm-up or an earlier repetition).
        if trace_id and any(
            _header_value(tx.get("request", {}).get("headers", {}), TRACE_HEADER) for tx in transactions
        ):
            return [], False, None, "none"

        # Iterate in reverse order (most recent first)
        for tx in reversed(transactions):
            req = tx.get("request", {})
            tx_method = req.get("method", "").upper()
            tx_uri = req.get("uri", "")

            # Prefer exact URI match. Fall back to exact base-path match (both sides
            # stripped of query string) only when the request itself has no query
            # component — prevents cross-matching between requests that share a base
            # path but carry different payloads.
            tx_base = tx_uri.split("?")[0]
            req_base = path_with_query.split("?")[0]
            has_query = "?" in path_with_query
            matched = tx_uri == path_with_query or (not has_query and tx_base == req_base)
            if tx_method == method.upper() and matched:
                return (*self._extract(tx), "uri")

        return [], False, None, "none"

    @staticmethod
    def _extract(tx: Dict) -> Tuple[List[str], bool, Optional[int]]:
        rule_ids: List[str] = []
        for msg in tx.get("messages", []):
            details = msg.get("details", {})
            rid = str(details.get("ruleId", "")).strip()
            if rid and rid not in rule_ids:
                rule_ids.append(rid)
        is_interrupted = bool(tx.get("is_interrupted", False))
        http_code = tx.get("response", {}).get("http_code")
        return rule_ids, is_interrupted, http_code
