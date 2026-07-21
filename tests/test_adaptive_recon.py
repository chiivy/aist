"""Tests for adaptive recon AgentProfile."""

from aist.recon.adaptive import AgentProfile, PROFILE_COMPLETE_WHEN


def test_profile_is_complete():
    """Profile complete when all required fields set."""
    profile = AgentProfile(
        agent_purpose="Data assistant",
        data_types=["records"],
        tools_available=["email"],
        access_restrictions=["no external send"],
        scope_boundaries=["other teams"],
    )
    assert profile.is_complete(PROFILE_COMPLETE_WHEN)


def test_profile_missing_fields():
    """Missing fields are reported correctly."""
    profile = AgentProfile(agent_purpose="Helper")
    missing = profile.missing_fields()
    assert "data_types" in missing
    assert "agent_purpose" not in missing


def test_profile_update_merges_lists():
    """List fields merge without duplicates."""
    profile = AgentProfile()
    profile.update({"tools_available": ["email"]})
    profile.update({"tools_available": ["web", "email"]})
    assert sorted(profile.tools_available) == [
        "email", "web"
    ]


def test_to_recon_report():
    """AgentProfile converts to ReconReport."""
    profile = AgentProfile(
        tools_available=["files"],
        raw_conversation=[{
            "sent": "Hello",
            "received": "Hi",
        }],
    )
    report = profile.to_recon_report("http://localhost/chat")
    assert report.agent_responding is True
    assert "files" in report.discovered_tools
    assert len(report.domain_mapping_responses) == 1
