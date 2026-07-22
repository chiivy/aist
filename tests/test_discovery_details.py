"""Tests for rich JS secret and endpoint discovery details."""

from aist.auth.profile import (
    build_discovery_block,
    classify_endpoint_detail,
    endpoint_paths,
    js_files_count,
    scan_js_content,
    secret_preview,
)
from aist.auth.traffic_observer import TrafficObservation, TrafficObserver


def test_secret_preview_redacts_to_six_chars() -> None:
    """Preview keeps first 6 characters then ****."""
    assert secret_preview("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") == (
        "eyJhbG****"
    )
    assert secret_preview("Bearer eyJhbGciOiJIUzI1NiJ9.abc") == (
        "eyJhbG****"
    )
    assert secret_preview("short") == "****"


def test_scan_js_content_returns_rich_secrets() -> None:
    """JS scan returns detail dicts without full secret values."""
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    )
    content = (
        f"const cfg = {{ authorization: 'Bearer {token}' }};\n"
        "const key = 'AKIAIOSFODNN7EXAMPLE';\n"
        "fetch('/api/config/settings');\n"
    )
    findings = scan_js_content(
        content,
        file_url="https://app.example.com/static/bundle.js",
    )
    assert findings["secrets"]
    secret = findings["secrets"][0]
    assert secret["file_url"].endswith("bundle.js")
    assert secret["secret_type"] in {"api_key", "jwt", "aws_key"}
    assert secret["preview"].endswith("****")
    assert len(secret["preview"]) == 10  # 6 + ****
    assert token not in secret["preview"]
    assert token not in secret["line_context"]
    assert "****" in secret["line_context"]
    assert secret["severity"] == "high"
    assert any("/api/config/settings" in ep for ep in findings["endpoints"])


def test_classify_endpoint_detail_includes_reason() -> None:
    """Endpoint classification includes reason and severity."""
    detail = classify_endpoint_detail(
        "/api/config/settings",
        full_url="https://app.example.com/api/config/settings",
    )
    assert detail is not None
    assert detail["path"] == "/api/config/settings"
    assert detail["full_url"].endswith("/api/config/settings")
    assert detail["classification"] == "config"
    assert detail["severity"] == "medium"
    assert "config" in detail["reason"].lower()
    assert detail["auth_enforced"] is None


def test_traffic_observation_stores_rich_endpoints() -> None:
    """TrafficObservation stores classified endpoint records."""
    data = TrafficObservation()
    data.register_path("https://app.example.com/api/chat")
    data.register_path("https://app.example.com/api/config/settings")
    assert "/api/chat" in data.discovered_endpoints
    assert data.discovered_endpoints["/api/chat"]["classification"] == (
        "observed"
    )
    config = data.discovered_endpoints["/api/config/settings"]
    assert config["classification"] == "config"
    assert config["reason"]


def test_build_profile_saves_full_discovery_details() -> None:
    """Profile includes js_secrets list and js URL list."""
    observer = TrafficObserver()
    observer.data.register_path(
        "https://app.example.com/api/config/settings"
    )
    observer.data.js_files_scanned = [
        "https://app.example.com/static/bundle.js",
        "https://app.example.com/static/vendor.js",
    ]
    observer.data.js_secrets = [
        {
            "file_url": "https://app.example.com/static/bundle.js",
            "secret_type": "api_key",
            "pattern_matched": "Bearer token",
            "preview": "eyJhbG****",
            "line_context": "...authorization: 'Bearer eyJhbG****'...",
            "severity": "high",
        }
    ]
    profile = observer.build_profile(
        "https://app.example.com/api/chat"
    )
    assert isinstance(profile["discovered_endpoints"], list)
    assert all(
        isinstance(item, dict) for item in profile["discovered_endpoints"]
    )
    config = next(
        item
        for item in profile["discovered_endpoints"]
        if item["path"] == "/api/config/settings"
    )
    assert config["classification"] == "config"
    assert "reason" in config
    assert profile["js_files_scanned"] == [
        "https://app.example.com/static/bundle.js",
        "https://app.example.com/static/vendor.js",
    ]
    assert profile["js_secrets"][0]["preview"] == "eyJhbG****"
    assert profile["js_secrets_found"] == 1
    assert "full secret" not in str(profile["js_secrets"]).lower()


def test_endpoint_paths_normalises_legacy_and_rich() -> None:
    """endpoint_paths accepts string paths and rich records."""
    paths = endpoint_paths([
        "/api/chat",
        {
            "path": "/api/config",
            "full_url": "https://app.example.com/api/config",
        },
        {"path": "/api/chat"},
    ])
    assert paths == ["/api/chat", "/api/config"]


def test_js_files_count_accepts_list_or_int() -> None:
    """js_files_count handles legacy int and new URL list."""
    assert js_files_count(3) == 3
    assert js_files_count(["a.js", "b.js"]) == 2
    assert js_files_count(None) == 0


def test_build_discovery_block_with_rich_secrets() -> None:
    """Discovery findings use rich secret details safely."""
    block = build_discovery_block(
        discovered_endpoints=[
            {
                "path": "/api/config",
                "full_url": "https://app.example.com/api/config",
                "classification": "config",
                "severity": "medium",
                "reason": "Path contains 'config' keyword",
                "auth_enforced": None,
            }
        ],
        js_files_scanned=[
            "https://app.example.com/static/bundle.js",
        ],
        js_secrets=[
            {
                "file_url": "https://app.example.com/static/bundle.js",
                "secret_type": "api_key",
                "pattern_matched": "Bearer token",
                "preview": "eyJhbG****",
                "line_context": "...Bearer eyJhbG****...",
                "severity": "high",
            }
        ],
    )
    assert block["stats"]["js_files_scanned"] == 1
    assert block["stats"]["total_endpoints"] == 1
    types = {item["type"] for item in block["findings"]}
    assert "endpoint_discovered" in types
    assert "js_secret" in types
    secret = next(
        item for item in block["findings"] if item["type"] == "js_secret"
    )
    assert "eyJhbG****" in secret["evidence"]
