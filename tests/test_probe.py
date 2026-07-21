"""Tests for recon probes including domain mapping."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from aist.config import AISTConfig
from aist.recon.probe import (
    DOMAIN_MAPPING_PROBES,
    ReconReport,
    _extract_envelope_model,
    domain_mapping_probes,
)


def test_domain_mapping_probes_count() -> None:
    """Domain mapping sends 6–8 probes."""
    assert 6 <= len(DOMAIN_MAPPING_PROBES) <= 8


def test_extract_envelope_model_from_json() -> None:
    """Top-level model field is read from response JSON."""
    response = MagicMock()
    response.json.return_value = {
        "model": "claude-sonnet-4-5",
        "response": "Hello",
    }
    assert (
        _extract_envelope_model(response)
        == "claude-sonnet-4-5"
    )


def test_extract_envelope_model_missing() -> None:
    """Missing model field returns empty string."""
    response = MagicMock()
    response.json.return_value = {"response": "Hello"}
    assert _extract_envelope_model(response) == ""


def test_extract_envelope_model_non_json() -> None:
    """Non-JSON bodies return empty string."""
    import json

    response = MagicMock()
    response.json.side_effect = json.JSONDecodeError(
        "err", "", 0
    )
    assert _extract_envelope_model(response) == ""


def test_send_probe_sets_model_detected() -> None:
    """run_recon probes capture envelope model field."""
    from aist.recon.probe import send_probe

    config = AISTConfig()
    config.target.endpoint = "http://localhost/chat"
    report = ReconReport(target=config.target.endpoint)

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "model": "gpt-4o",
        "response": "Hi there",
    }
    mock_response.headers = {"content-type": "application/json"}
    mock_response.text = (
        '{"model":"gpt-4o","response":"Hi there"}'
    )

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch(
        "aist.recon.streaming.collect_response",
        new_callable=AsyncMock,
    ) as mock_collect:
        mock_collect.return_value = MagicMock(
            content="Hi there"
        )
        result = asyncio.run(
            send_probe(
                mock_client,
                config,
                "Hello",
                recon_report=report,
            )
        )

    assert result == "Hi there"
    assert report.model_detected == "gpt-4o"
    assert report.model_hint == "gpt-4o"


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
