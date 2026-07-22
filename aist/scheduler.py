"""
Built-in scan scheduler and history storage.

Persists schedules in ~/.aist/schedules.json and
scan results in ~/.aist/history.db (SQLite).
"""

from __future__ import annotations

import json
import os
import signal
import smtplib
import sqlite3
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

import httpx

from aist.logger import get_logger

log = get_logger(__name__)


@dataclass
class ScanDiff:
    """Change summary between two scan runs."""

    is_baseline: bool = False
    critical_change: int = 0
    high_change: int = 0
    new_count: int = 0
    resolved_count: int = 0


@dataclass
class Schedule:
    """One scheduled scan definition."""

    name: str
    target: str
    cron: str
    profile: str = "standard"
    categories: Optional[list] = None
    tools: list = field(default_factory=list)
    notify_email: Optional[str] = None
    notify_slack: Optional[str] = None
    fail_on: Optional[str] = None
    operator: str = "scheduler"

    def to_dict(self) -> dict:
        """Serialise for JSON storage."""
        return asdict(self)


class Scheduler:
    """
    Manage scheduled scans and scan history.

    Uses the ``schedule`` library for cron-like timing.
    """

    CONFIG_DIR = Path.home() / ".aist"

    def __init__(self) -> None:
        self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.schedules_path = self.CONFIG_DIR / "schedules.json"
        self.history_path = self.CONFIG_DIR / "history.db"
        self._init_history_db()

    def _init_history_db(self) -> None:
        """Create history table if missing."""
        with sqlite3.connect(self.history_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    schedule_name TEXT,
                    target TEXT,
                    profile TEXT,
                    scan_date TEXT,
                    critical INTEGER,
                    high INTEGER,
                    medium INTEGER,
                    low INTEGER,
                    unvalidated INTEGER,
                    score REAL,
                    report_path TEXT,
                    findings_json TEXT
                )
                """
            )

    def load_schedules(self) -> dict:
        """Load all schedules from disk."""
        if not self.schedules_path.exists():
            return {}
        try:
            return json.loads(
                self.schedules_path.read_text(
                    encoding="utf-8"
                )
            )
        except json.JSONDecodeError:
            return {}

    def save_schedules(self, schedules: dict) -> None:
        """Persist schedules to disk."""
        self.schedules_path.write_text(
            json.dumps(schedules, indent=2),
            encoding="utf-8",
        )

    def add_schedule(self, schedule: Schedule) -> None:
        """Add or replace a named schedule."""
        schedules = self.load_schedules()
        schedules[schedule.name] = schedule.to_dict()
        self.save_schedules(schedules)
        log.info(
            "schedule_added",
            name=schedule.name,
            next_run=self.next_run(schedule.cron),
        )

    def remove_schedule(self, name: str) -> bool:
        """Remove schedule by name."""
        schedules = self.load_schedules()
        if name not in schedules:
            return False
        del schedules[name]
        self.save_schedules(schedules)
        return True

    def cron_to_time(self, cron: str) -> str:
        """
        Simplified cron -> daily time for schedule lib.

        Supports ``M H * * *`` (minute hour).
        """
        parts = cron.split()
        if len(parts) >= 2:
            minute, hour = parts[0], parts[1]
            return f"{hour.zfill(2)}:{minute.zfill(2)}"
        return "09:00"

    def next_run(self, cron: str) -> str:
        """Human-readable next run estimate."""
        return f"daily at {self.cron_to_time(cron)} UTC"

    def store_result(
        self,
        schedule_name: str,
        result: dict,
        profile: str,
    ) -> None:
        """Persist scan result to history database."""
        with sqlite3.connect(self.history_path) as conn:
            conn.execute(
                """
                INSERT INTO scan_history (
                    schedule_name, target, profile,
                    scan_date, critical, high, medium,
                    low, unvalidated, score,
                    report_path, findings_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    schedule_name,
                    result.get("target", ""),
                    profile,
                    datetime.now(timezone.utc).isoformat(),
                    result.get("critical", 0),
                    result.get("high", 0),
                    result.get("medium", 0),
                    result.get("low", 0),
                    result.get("unvalidated", 0),
                    result.get("score", 0.0),
                    result.get("html_report", ""),
                    json.dumps(result.get("findings", [])),
                ),
            )

    def get_previous(
        self, schedule_name: str
    ) -> Optional[dict]:
        """Fetch most recent history row for schedule."""
        with sqlite3.connect(self.history_path) as conn:
            row = conn.execute(
                """
                SELECT critical, high, medium, low,
                       score, findings_json
                FROM scan_history
                WHERE schedule_name = ?
                ORDER BY id DESC LIMIT 1 OFFSET 1
                """,
                (schedule_name,),
            ).fetchone()
        if not row:
            return None
        return {
            "critical": row[0],
            "high": row[1],
            "medium": row[2],
            "low": row[3],
            "score": row[4],
            "findings": json.loads(row[5] or "[]"),
        }

    def count_new_findings(
        self, current: dict, previous: dict
    ) -> int:
        """Count findings not in previous scan."""
        prev_ids = {
            f.get("payload_id")
            for f in previous.get("findings", [])
        }
        return sum(
            1 for f in current.get("findings", [])
            if f.get("payload_id") not in prev_ids
        )

    def count_resolved(
        self, current: dict, previous: dict
    ) -> int:
        """Count findings resolved since previous scan."""
        curr_ids = {
            f.get("payload_id")
            for f in current.get("findings", [])
        }
        return sum(
            1 for f in previous.get("findings", [])
            if f.get("payload_id") not in curr_ids
        )

    def diff(
        self, current: dict, previous: Optional[dict]
    ) -> ScanDiff:
        """Compute change summary between scans."""
        if not previous:
            return ScanDiff(is_baseline=True)
        return ScanDiff(
            critical_change=(
                current.get("critical", 0)
                - previous.get("critical", 0)
            ),
            high_change=(
                current.get("high", 0)
                - previous.get("high", 0)
            ),
            new_count=self.count_new_findings(
                current, previous
            ),
            resolved_count=self.count_resolved(
                current, previous
            ),
        )

    def send_slack(
        self,
        webhook: str,
        summary: str,
        result: dict,
    ) -> None:
        """Post scan summary to Slack webhook."""
        color = (
            "danger"
            if result.get("critical", 0) > 0
            else "warning"
            if result.get("high", 0) > 0
            else "good"
        )
        httpx.post(
            webhook,
            json={
                "attachments": [{
                    "color": color,
                    "title": f"AIST: {result.get('target')}",
                    "text": summary,
                    "footer": "github.com/chiivy/aist",
                }]
            },
            timeout=10.0,
        )

    def send_email(self, to: str, summary: str) -> None:
        """Send email via SMTP when configured."""
        smtp_host = os.getenv("AIST_SMTP_HOST")
        if not smtp_host:
            log.info(
                "email_notification_skipped",
                reason="AIST_SMTP_HOST not set",
            )
            return

        msg = EmailMessage()
        msg["Subject"] = "AIST Scheduled Scan Complete"
        msg["From"] = os.getenv(
            "AIST_SMTP_FROM", "aist@localhost"
        )
        msg["To"] = to
        msg.set_content(summary)

        port = int(os.getenv("AIST_SMTP_PORT", "587"))
        with smtplib.SMTP(smtp_host, port) as server:
            if os.getenv("AIST_SMTP_TLS", "true") == "true":
                server.starttls()
            user = os.getenv("AIST_SMTP_USER")
            password = os.getenv("AIST_SMTP_PASSWORD")
            if user and password:
                server.login(user, password)
            server.send_message(msg)

    def notify(
        self,
        schedule: dict,
        result: dict,
        diff: ScanDiff,
    ) -> None:
        """Send configured notifications."""
        summary = (
            f"AIST Scan: {schedule['name']}\n"
            f"Target: {result.get('target')}\n"
            f"Score: {result.get('score', 0)}/10\n"
            f"Critical: {result.get('critical', 0)} "
            f"({diff.critical_change:+d})\n"
            f"High: {result.get('high', 0)} "
            f"({diff.high_change:+d})\n"
            f"New findings: {diff.new_count}\n"
            f"Resolved: {diff.resolved_count}\n"
            f"Report: {result.get('html_report')}"
        )

        if schedule.get("notify_email"):
            self.send_email(
                schedule["notify_email"], summary
            )

        if schedule.get("notify_slack"):
            self.send_slack(
                schedule["notify_slack"],
                summary,
                result,
            )

    def build_config(self, schedule: dict):
        """Build AISTConfig from schedule dict."""
        from aist.config import load_config
        from aist.scan_profiles import apply_profile_to_config

        config = load_config(
            target_endpoint=schedule["target"],
            tools=schedule.get("tools", []),
            operator=schedule.get("operator", "scheduler"),
        )
        apply_profile_to_config(
            config,
            schedule.get("profile", "standard"),
            categories_override=schedule.get("categories"),
        )
        if schedule.get("fail_on"):
            config.scan.fail_on = schedule["fail_on"]
        if schedule.get("notify_slack"):
            config.scan.notify_slack = schedule[
                "notify_slack"
            ]
        if schedule.get("notify_email"):
            config.scan.notify_email = schedule[
                "notify_email"
            ]
        return config

    def execute(self, schedule: dict) -> dict:
        """Run one scheduled scan synchronously."""
        import asyncio
        from aist.scanner.orchestrator import run_full_scan

        log.info(
            "scheduled_scan_starting",
            name=schedule["name"],
        )
        config = self.build_config(schedule)
        timestamp = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d-%H-%M"
        )
        safe_target = schedule["target"].replace(
            "://", "-"
        ).replace("/", "-")[:30]
        output = (
            f"reports/{timestamp}-{safe_target}/"
            f"report.html"
        )
        result = asyncio.run(
            run_full_scan(config=config, output_path=output)
        )
        self.store_result(
            schedule["name"],
            result,
            schedule.get("profile", "standard"),
        )
        previous = self.get_previous(schedule["name"])
        diff = self.diff(result, previous)
        self.notify(schedule, result, diff)

        fail_on = schedule.get("fail_on")
        if fail_on:
            count = result.get(fail_on, 0)
            if count > 0:
                log.warning(
                    "scheduled_scan_failed",
                    level=fail_on,
                    count=count,
                )
                sys.exit(1)

        return result

    def run_daemon(self) -> None:
        """Run scheduler daemon until SIGTERM."""
        import schedule as sched_lib

        def _handle_sigterm(signum, frame) -> None:
            log.info("scheduler_shutdown", signal=signum)
            self.save_schedules(self.load_schedules())
            sys.exit(0)

        signal.signal(signal.SIGTERM, _handle_sigterm)
        signal.signal(signal.SIGINT, _handle_sigterm)

        for name, sched in self.load_schedules().items():
            sched["name"] = name
            run_time = self.cron_to_time(sched["cron"])
            sched_lib.every().day.at(run_time).do(
                self.execute, sched
            )

        log.info("scheduler_daemon_started")
        while True:
            sched_lib.run_pending()
            time.sleep(60)

    def list_history(
        self,
        name: Optional[str] = None,
        target: Optional[str] = None,
        limit: int = 20,
    ) -> list:
        """Query scan history with optional filters."""
        query = (
            "SELECT schedule_name, target, profile, "
            "scan_date, critical, high, medium, "
            "score FROM scan_history WHERE 1=1"
        )
        params: list = []
        if name:
            query += " AND schedule_name = ?"
            params.append(name)
        if target:
            query += " AND target = ?"
            params.append(target)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.history_path) as conn:
            return conn.execute(query, params).fetchall()
