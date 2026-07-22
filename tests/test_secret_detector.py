"""Tests for secret detection in HTTP responses."""

from aist.evidence.secret_detector import scan_response_secrets


def test_detects_aws_key() -> None:
    """AWS access keys are flagged as high severity."""
    body = "config key AKIAIOSFODNN7EXAMPLE here"
    findings = scan_response_secrets(body)
    assert any(f.pattern == "aws_key" for f in findings)
    assert findings[0].severity == "High"


def test_detects_private_key_header() -> None:
    """Private key PEM headers are detected."""
    body = "-----BEGIN RSA PRIVATE KEY-----\nMII..."
    findings = scan_response_secrets(body)
    assert any(f.pattern == "private_key" for f in findings)


def test_detects_internal_ip() -> None:
    """RFC1918 addresses are medium severity."""
    body = "connect to 10.0.0.5 for internal service"
    findings = scan_response_secrets(body)
    assert any(f.pattern == "internal_ip" for f in findings)
    assert findings[0].severity == "Medium"


def test_detects_stack_trace() -> None:
    """Stack traces are low severity."""
    body = "Error at com.example.Service.run(Service.java:42)"
    findings = scan_response_secrets(body)
    assert any(f.pattern == "stack_trace" for f in findings)
