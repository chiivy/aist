"""
Executive report helpers.

Keeps executive-facing copy out of the main HTML
template module where possible.
"""

from __future__ import annotations

from typing import Any, Optional


def discovery_executive_paragraph(
    discovery: Optional[dict[str, Any]],
) -> Optional[str]:
    """
    Build an executive paragraph for passive discovery.

    Returns None when there are no discovery findings.
    """
    if not discovery:
        return None
    findings = discovery.get("findings") or []
    stats = discovery.get("stats") or {}
    findings_count = stats.get("findings_count", len(findings))
    if not findings_count:
        return None

    endpoints = stats.get("total_endpoints", 0)
    js_files = stats.get("js_files_scanned", 0)
    return (
        f"Passive browser session analysis identified "
        f"{findings_count} security findings across "
        f"{endpoints} observed endpoints and "
        f"{js_files} JavaScript files."
    )
