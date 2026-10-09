"""Target URL validation and containment security handlers."""
from __future__ import annotations
import urllib.parse
import urllib.request
from typing import Set

ALLOWED_HOSTS: Set[str] = {"127.0.0.1", "localhost", "::1"}
ALLOWED_PORTS: Set[int] = {3001, 8080}
ALLOWED_SCHEMES: Set[str] = {"http"}


class ContainmentSecurityError(Exception):
    """Raised when an out-of-scope target or security containment violation is detected."""
    pass


class StrictNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom HTTP handler that stops automatic redirect following to prevent host leakage."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not automatically follow redirects; capture response as-is for analysis
        return None


def validate_target_url(base_url: str, expected_mode: str | None = None) -> str:
    """Validates that the target base URL strictly adheres to loopback laboratory boundaries.

    Args:
        base_url: The target root URL (e.g., http://127.0.0.1:3001).
        expected_mode: 'baseline' or 'waf' to enforce mode-to-port mapping.

    Returns:
        The normalized base URL string.

    Raises:
        ContainmentSecurityError: If the URL is external, malformed, or unauthorized.
    """
    if not base_url:
        raise ContainmentSecurityError("Target URL cannot be empty.")

    try:
        parsed = urllib.parse.urlparse(base_url.strip())
    except Exception as exc:
        raise ContainmentSecurityError(f"Malformed URL: {exc}") from exc

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ContainmentSecurityError(
            f"Unsupported scheme '{parsed.scheme}'. Only {sorted(ALLOWED_SCHEMES)} are permitted."
        )

    if parsed.username or parsed.password:
        raise ContainmentSecurityError("Credentials in target URLs are forbidden.")

    hostname = (parsed.hostname or "").lower()
    if hostname not in ALLOWED_HOSTS:
        raise ContainmentSecurityError(
            f"Host '{hostname}' is not in the authorized loopback allowlist: {sorted(ALLOWED_HOSTS)}. "
            "Public and LAN testing is strictly prohibited."
        )

    try:
        port = parsed.port
    except ValueError as exc:
        raise ContainmentSecurityError("Invalid target port number.") from exc

    if port not in ALLOWED_PORTS:
        raise ContainmentSecurityError(
            f"Port {port} is not authorized. Authorized lab ports: {sorted(ALLOWED_PORTS)}."
        )

    if expected_mode:
        expected_port = 3001 if expected_mode == "baseline" else 8080
        if port != expected_port:
            raise ContainmentSecurityError(
                f"Mode '{expected_mode}' requires port {expected_port}, but target specified port {port}."
            )

    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ContainmentSecurityError(
            "Base target URL must not contain a sub-path, query string, or fragment."
        )

    return f"http://{hostname}:{port}"
