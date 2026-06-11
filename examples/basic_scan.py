"""
AIST Basic Scan Example

Demonstrates how to use AIST programmatically.

For CLI usage see README.md:
    aist scan --target https://your-agent.com
              --tools email,files,database
              --output report.html

Requirements:
    pip install -e .
    Copy .env.example to .env and fill in values
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aist.config import load_config
from aist.logger import setup_logging
from aist.scanner.orchestrator import run_full_scan


async def basic_scan_example():
    """
    Run a basic AIST scan programmatically.

    This example shows the minimum configuration
    needed to run a scan and access results.
    """

    # Set up logging
    setup_logging(log_level="INFO")

    # Load configuration
    # In production these come from .env file
    # Here we show them explicitly for clarity
    config = load_config(
        target_endpoint="https://your-agent-endpoint.com",
        tools=["email", "files", "database"],
        mode="active",
        runs=3,
    )

    # Run the scan
    results = await run_full_scan(
        config=config,
        output_path="reports/example-report.html",
    )

    # Access results programmatically
    print(f"\nScan complete:")
    print(f"  Total findings: {results['total_findings']}")
    print(f"  Critical:       {results['critical']}")
    print(f"  High:           {results['high']}")
    print(f"  Medium:         {results['medium']}")
    print(f"  Low:            {results['low']}")
    print(f"  Canary triggered: {results['canary_triggered']}")
    print(f"  Duration:       {results['duration_seconds']}s")
    print(f"\nReports:")
    print(f"  HTML:  {results['html_report']}")
    print(f"  JSON:  {results['json_report']}")
    print(f"  SARIF: {results['sarif_report']}")

    return results


async def passive_discovery_example():
    """
    Run discovery only without sending any
    injection payloads.

    Safe to run against production agents.
    """
    from aist.recon.probe import run_recon
    from aist.recon.discovery import run_discovery
    from aist.recon.fingerprint import run_fingerprinting

    setup_logging(log_level="INFO")

    config = load_config(
        target_endpoint="https://your-agent-endpoint.com",
        mode="passive",
    )

    print("Running passive discovery...")

    recon_report = await run_recon(config)
    discovery_result = await run_discovery(
        config, recon_report
    )
    fingerprint = await run_fingerprinting(
        config,
        initial_hint=recon_report.model_hint,
    )

    print(f"\nAttack Surface Map:")
    print(f"  Model:           {recon_report.model_hint}")
    print(
        f"  Declared tools:  "
        f"{recon_report.declared_tools}"
    )
    print(
        f"  Discovered tools: "
        f"{recon_report.discovered_tools}"
    )
    print(f"  Has memory:      {recon_report.has_memory}")
    print(
        f"  RAG detected:    "
        f"{getattr(discovery_result, 'rag_detected', False)}"
    )
    print(
        f"  SSRF potential:  "
        f"{getattr(discovery_result, 'ssrf_potential', False)}"
    )
    print(
        f"  Severity multiplier: "
        f"{getattr(discovery_result, 'severity_multiplier', 1.0)}x"
    )

    return recon_report, discovery_result


async def targeted_category_scan():
    """
    Run a scan testing only specific payload
    categories rather than the full suite.

    Useful when you want to test a specific
    attack class quickly.
    """
    setup_logging(log_level="INFO")

    config = load_config(
        target_endpoint="https://your-agent-endpoint.com",
        tools=["email"],
        mode="active",
        runs=1,
        categories=["A", "B", "G"],
    )

    results = await run_full_scan(
        config=config,
        output_path="reports/targeted-report.html",
    )

    print(f"Targeted scan complete: "
          f"{results['total_findings']} findings")

    return results


if __name__ == "__main__":
    print("AIST Basic Scan Examples")
    print("=" * 40)
    print("\nRunning basic scan example...")
    print("Note: Update target_endpoint in this file")
    print("before running against a real agent.\n")

    asyncio.run(basic_scan_example())