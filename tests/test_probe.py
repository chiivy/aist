"""Tests for recon probes including domain mapping."""

import asyncio
from unittest.mock import AsyncMock, patch

from aist.config import AISTConfig
from aist.recon.probe import (
    DOMAIN_MAPPING_PROBES,
    ReconReport,
    domain_mapping_probes,
)


def test_domain_mapping_probes_count() -> None:
    """Domain mapping sends 6–8 probes."""
    assert 6 <= len(DOMAIN_MAPPING_PROBES) <= 8


def test_domain_mapping_stores_responses() -> None:
    """Non-empty probe replies are stored on the report."""
    config = AISTConfig()
    config.target.endpoint = "http://localhost/chat"
    report = ReconReport(
        target=config.target.endpoint,
        agent_responding=True,
    )
    replies = [
        f"domain reply {i}"
        for i in range(len(DOMAIN_MAPPING_PROBES))
    ]

    with patch(
        "aist.recon.probe.send_probe",
        new_callable=AsyncMock,
        side_effect=replies,
    ):
        result = asyncio.run(
            domain_mapping_probes(config, report)
        )

    assert result.domain_mapping_responses == replies


def test_domain_mapping_skips_empty_responses() -> None:
    """Empty probe replies are not stored."""
    config = AISTConfig()
    config.target.endpoint = "http://localhost/chat"
    report = ReconReport(
        target=config.target.endpoint,
        agent_responding=True,
    )
    side_effect = [""] * (
        len(DOMAIN_MAPPING_PROBES) - 1
    ) + ["roles: admin, user"]

    with patch(
        "aist.recon.probe.send_probe",
        new_callable=AsyncMock,
        side_effect=side_effect,
    ):
        result = asyncio.run(
            domain_mapping_probes(config, report)
        )

    assert result.domain_mapping_responses == [
        "roles: admin, user"
    ]


def test_domain_mapping_skipped_when_not_responding(
) -> None:
    """Skip domain mapping if basic recon failed."""
    config = AISTConfig()
    config.target.endpoint = "http://localhost/chat"
    report = ReconReport(
        target=config.target.endpoint,
        agent_responding=False,
    )

    with patch(
        "aist.recon.probe.send_probe",
        new_callable=AsyncMock,
    ) as mock_send:
        result = asyncio.run(
            domain_mapping_probes(config, report)
        )

    mock_send.assert_not_called()
    assert result.domain_mapping_responses == []
