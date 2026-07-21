"""Tests for built-in scheduler."""

import json
from pathlib import Path

from aist.scheduler import Schedule, Scheduler, ScanDiff


def test_add_and_list_schedule(tmp_path, monkeypatch):
    """Schedules persist to JSON storage."""
    monkeypatch.setattr(
        Scheduler, "CONFIG_DIR", tmp_path
    )
    sched = Schedule(
        name="weekly",
        target="http://localhost/chat",
        cron="0 9 * * 1",
        profile="standard",
    )
    manager = Scheduler()
    manager.add_schedule(sched)
    loaded = manager.load_schedules()
    assert "weekly" in loaded
    assert loaded["weekly"]["target"] == (
        "http://localhost/chat"
    )


def test_scan_diff_baseline():
    """First scan diff is baseline."""
    diff = ScanDiff(is_baseline=True)
    assert diff.new_count == 0
    assert diff.critical_change == 0


def test_scan_diff_changes():
    """Diff computes severity changes."""
    manager = Scheduler()
    current = {"critical": 3, "high": 1, "findings": [
        {"payload_id": "A1"},
        {"payload_id": "B1"},
    ]}
    previous = {"critical": 4, "high": 0, "findings": [
        {"payload_id": "A1"},
    ]}
    diff = manager.diff(current, previous)
    assert diff.critical_change == -1
    assert diff.new_count == 1
