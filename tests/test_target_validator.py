"""Unit tests for simulator target validation and containment security."""
import pytest
from simulator.target_validator import (
    ContainmentSecurityError,
    StrictNoRedirectHandler,
    validate_target_url,
)


def test_valid_loopback_targets():
    assert validate_target_url("http://127.0.0.1:3001") == "http://127.0.0.1:3001"
    assert validate_target_url("http://localhost:8080") == "http://localhost:8080"
    assert validate_target_url("http://[::1]:3001") == "http://[::1]:3001"


def test_reject_external_domain():
    with pytest.raises(ContainmentSecurityError, match="not in the authorized loopback allowlist"):
        validate_target_url("http://example.com:8080")

    with pytest.raises(ContainmentSecurityError, match="not in the authorized loopback allowlist"):
        validate_target_url("http://192.168.1.50:8080")


def test_reject_unauthorized_ports():
    with pytest.raises(ContainmentSecurityError, match="Port 80 is not authorized"):
        validate_target_url("http://127.0.0.1:80")

    with pytest.raises(ContainmentSecurityError, match="Port 443 is not authorized"):
        validate_target_url("http://127.0.0.1:443")


def test_reject_credentials_in_url():
    with pytest.raises(ContainmentSecurityError, match="Credentials in target URLs are forbidden"):
        validate_target_url("http://admin:secret@127.0.0.1:8080")


def test_reject_paths_in_base_url():
    with pytest.raises(ContainmentSecurityError, match="Base target URL must not contain a sub-path"):
        validate_target_url("http://127.0.0.1:8080/api/search")


def test_mode_port_enforcement():
    with pytest.raises(ContainmentSecurityError, match="Mode 'baseline' requires port 3001"):
        validate_target_url("http://127.0.0.1:8080", expected_mode="baseline")

    with pytest.raises(ContainmentSecurityError, match="Mode 'waf' requires port 8080"):
        validate_target_url("http://127.0.0.1:3001", expected_mode="waf")


def test_no_redirect_handler_returns_none():
    handler = StrictNoRedirectHandler()
    assert handler.redirect_request(None, None, 302, "Found", {}, "http://evil.com") is None
