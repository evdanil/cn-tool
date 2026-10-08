from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Dict, Iterable, List, Optional

from cn_tool.core.base import BaseModule, ScriptContext
from cn_tool.utils import oscompat
from cn_tool.utils.file_io import write_excel_sheets


STATS_SCHEMA_NAME = "cn_tool_stats"
STATS_SCHEMA_VERSION = 1

ACTIVE_STATUSES = {"active"}
FINAL_STATUSES = {"completed", "failed", "interrupted", "abandoned"}
VALID_SESSION_STATUSES = ACTIVE_STATUSES | FINAL_STATUSES
VALID_RUN_STATUSES = {"active", "completed", "failed", "interrupted"}

MODULE_BASELINE_CONFIG_KEYS = {
    "1": "stats_ip_request_baseline_seconds",
    "2": "stats_subnet_request_baseline_seconds",
    "3": "stats_fqdn_request_baseline_seconds",
    "4": "stats_location_request_baseline_seconds",
    "5": "stats_config_search_baseline_seconds",
    "8": "stats_demob_check_baseline_seconds",
    "9": "stats_device_query_baseline_seconds",
    "o": "stats_e911_info_baseline_seconds",
}

# Menu item 1 took IPv6 and lost "(IPv4)" from its title. Runs saved under the old title still count
# as the same module: both reports read the runs through ``_normalized_runs``.
_RENAMED_TITLES = {"IP Information (IPv4)": "IP Information"}

SAFE_DETAIL_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
STAT_FILE_RE = re.compile(
    r"^[A-Za-z0-9_.-]+\.\d+\.\d{8}T\d{6}Z\.[a-f0-9]{32}\.json\.gz$"
)
STATS_BUCKETS = "0123456789abcdefghijklmnopqrstuvwxyz"
SHARED_STATS_DIR_MODE = 0o1777
SHARED_STATS_SUBDIR_MODE = 0o755
SHARED_STATS_FILE_MODE = 0o644


@dataclass(frozen=True)
class PeriodPreset:
    key: str
    label: str
    window: Optional[timedelta]


PERIOD_PRESETS: List[PeriodPreset] = [
    PeriodPreset("all", "All time", None),
    PeriodPreset("7d", "Last 7 days", timedelta(days=7)),
    PeriodPreset("4w", "Last 4 weeks", timedelta(weeks=4)),
    PeriodPreset("1m", "Last month", timedelta(days=30)),
    PeriodPreset("12m", "Last 12 months", timedelta(days=365)),
]

IDLE_DURATION_MULTIPLIER = 3.0
IDLE_DURATION_GRACE_SECONDS = 300.0
CREDITED_DURATION_MULTIPLIER = 1.5
CREDITED_DURATION_GRACE_SECONDS = 60.0


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc_iso(value: str | None) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def format_compact_utc(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def format_display_ts(value: str | None) -> str:
    ts = parse_utc_iso(value)
    if not ts:
        return "N/A"
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def round_duration_seconds(seconds: float | int | None) -> int:
    try:
        return max(0, int(round(float(seconds or 0))))
    except (TypeError, ValueError):
        return 0


def format_duration(seconds: float | int | None) -> str:
    total_seconds = round_duration_seconds(seconds)
    if total_seconds < 60:
        return "<1 min"

    total_minutes = max(1, int(round(total_seconds / 60)))
    days, remaining_minutes = divmod(total_minutes, 24 * 60)
    hours, minutes = divmod(remaining_minutes, 60)

    parts: List[str] = []
    if days:
        day_label = "day" if days == 1 else "days"
        parts.append(f"{days} {day_label}")
    if hours:
        parts.append(f"{hours} hr")
    if minutes:
        parts.append(f"{minutes} min")
    return " ".join(parts) or "1 min"


def format_utilization(active_seconds: float | int | None, session_elapsed_seconds: float | int | None) -> str:
    elapsed_seconds = round_duration_seconds(session_elapsed_seconds)
    if elapsed_seconds <= 0:
        return "N/A"
    active_total = max(0.0, float(active_seconds or 0.0))
    utilization = min(100, max(0, int(round((active_total / elapsed_seconds) * 100))))
    return f"{utilization}%"


def safe_stats_username(value: str | None) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", (value or "").strip())
    return cleaned or "unknown"


def _pid_exists(pid: int) -> bool:
    return oscompat.pid_exists(pid)


def period_choices() -> List[tuple[str, str]]:
    return [(preset.key, preset.label) for preset in PERIOD_PRESETS]


def _period_label(period_key: str) -> str:
    for preset in PERIOD_PRESETS:
        if preset.key == period_key:
            return preset.label
    return PERIOD_PRESETS[0].label


class StatsManager:
    """Tracks session/module stats and aggregates shared stats files."""

    def __init__(self, ctx: ScriptContext) -> None:
        self.ctx = ctx
        self.logger = ctx.logger
        self.event_bus = ctx.event_bus
        self.collect_enabled = bool(ctx.cfg.get("stats_collect_enabled", False))
        self.menu_enabled = bool(ctx.cfg.get("stats_menu_enabled", False))
        self.read_shared_on_startup = bool(ctx.cfg.get("stats_read_shared_on_startup", False))
        raw_directory = ctx.cfg.get("stats_directory", "/tmp")
        self.directory = Path(raw_directory).expanduser() if raw_directory else Path("/tmp")
        self.report_file = Path(ctx.cfg.get("stats_report_file", "~/stats.xlsx")).expanduser()
        self.session_path: Optional[Path] = None
        self.session: Dict[str, Any] = {}
        self.active_run_index: Optional[int] = None
        self.subscription_token: Optional[int] = None
        self.cached_shared_report: Optional[Dict[str, Any]] = None

        self._prepare_directory()
        self.subscription_token = self.event_bus.subscribe("stats:module_detail", self._handle_module_detail_event)

        if self.collect_enabled:
            self._start_session()
        if self.read_shared_on_startup:
            self.cached_shared_report = self.build_report("all")

    @property
    def enabled(self) -> bool:
        return self.collect_enabled or self.menu_enabled or self.read_shared_on_startup

    def _prepare_directory(self) -> None:
        try:
            if self.directory != Path("/tmp"):
                self.directory.mkdir(parents=True, exist_ok=True)
                self._ensure_directory_mode(self.directory, SHARED_STATS_DIR_MODE)
        except OSError as exc:
            self.logger.warning("STATS: Unable to prepare stats directory %s: %s", self.directory, exc)
            self.collect_enabled = False
            self.menu_enabled = False
            self.read_shared_on_startup = False

    def _start_session(self) -> None:
        started_at = utc_now()
        # The statistics identity ignores [auth] renames on purpose: it is the account, not the device login.
        username = self.ctx.username or os.getenv("USERNAME" if oscompat.is_windows() else "USER") or "unknown"
        safe_username = safe_stats_username(username)
        pid = os.getpid()
        start_stamp = format_compact_utc(started_at)

        for _ in range(5):
            filename = f"{safe_username}.{pid}.{start_stamp}.{uuid.uuid4().hex}.json.gz"
            candidate_dir = self._bucket_dir_for_name(filename, safe_username)
            try:
                candidate_dir.mkdir(parents=True, exist_ok=True)
                user_dir = self.directory / safe_username
                if user_dir != Path("/tmp"):
                    self._ensure_directory_mode(user_dir, SHARED_STATS_SUBDIR_MODE)
                if candidate_dir != Path("/tmp"):
                    self._ensure_directory_mode(candidate_dir, SHARED_STATS_SUBDIR_MODE)
            except OSError:
                continue
            candidate = candidate_dir / filename
            try:
                fd = os.open(str(candidate), os.O_CREAT | os.O_EXCL | os.O_WRONLY, SHARED_STATS_FILE_MODE)
                os.close(fd)
                self.session_path = candidate
                break
            except FileExistsError:
                continue

        if self.session_path is None:
            self.logger.warning("STATS: Unable to reserve unique stats file in %s", self.directory)
            self.collect_enabled = False
            return

        self.session = {
            "schema_name": STATS_SCHEMA_NAME,
            "schema_version": STATS_SCHEMA_VERSION,
            "app_version": self.ctx.cfg.get("version", ""),
            "username": username,
            "pid": pid,
            "started_at": utc_iso(started_at),
            "ended_at": None,
            "last_updated_at": utc_iso(started_at),
            "status": "active",
            "runs": [],
            "summary": self._summarize_runs(
                [],
                include_active_session=True,
                include_estimated_saved=False,
                credit_idle_time=False,
            ),
        }
        self._flush_session()

    def _handle_module_detail_event(self, payload: Any | None) -> None:
        if not isinstance(payload, dict):
            return
        self.record_module_detail(payload)

    def start_module_run(self, module: BaseModule) -> None:
        if not self.collect_enabled or not self.session:
            return

        if self.active_run_index is not None:
            self._finish_active_run("interrupted", utc_now())

        started_at = utc_now()
        run_record = {
            "module_key": module.menu_key,
            "module_title": module.menu_title,
            "started_at": utc_iso(started_at),
            "ended_at": None,
            "duration_seconds": None,
            "status": "active",
            "metrics": {},
        }
        self.session.setdefault("runs", []).append(run_record)
        self.active_run_index = len(self.session["runs"]) - 1
        self._touch_session(started_at)

    def record_module_detail(self, payload: Dict[str, Any]) -> None:
        if not self.collect_enabled or self.active_run_index is None:
            return

        run = self.session["runs"][self.active_run_index]
        metrics = run.setdefault("metrics", {})

        for key, value in payload.items():
            if not SAFE_DETAIL_KEY_RE.match(str(key)):
                continue

            sanitized = self._sanitize_detail_value(value)
            if sanitized is None:
                continue

            if isinstance(sanitized, (int, float)) and isinstance(metrics.get(key), (int, float)):
                metrics[key] = round(float(metrics[key]) + float(sanitized), 3)
            else:
                metrics[key] = sanitized

        self._touch_session(utc_now())

    def finish_module_run(self, status: str) -> None:
        if not self.collect_enabled or self.active_run_index is None:
            return
        normalized_status = status if status in VALID_RUN_STATUSES else "failed"
        self._finish_active_run(normalized_status, utc_now())

    def prepare_for_shutdown(self, final_status: str) -> None:
        if not self.collect_enabled or not self.session:
            return

        shutdown_time = utc_now()
        if self.active_run_index is not None:
            run_status = "completed" if final_status == "completed" else final_status
            if run_status not in VALID_RUN_STATUSES:
                run_status = "failed"
            self._finish_active_run(run_status, shutdown_time)

        self.session["status"] = final_status if final_status in VALID_SESSION_STATUSES else "failed"
        self._touch_session(shutdown_time)

    def finalize_session(self, final_status: str) -> None:
        if not self.collect_enabled or not self.session:
            return

        final_time = utc_now()
        if self.active_run_index is not None:
            run_status = "completed" if final_status == "completed" else final_status
            if run_status not in VALID_RUN_STATUSES:
                run_status = "failed"
            self._finish_active_run(run_status, final_time)

        self.session["status"] = final_status if final_status in VALID_SESSION_STATUSES else "failed"
        self.session["ended_at"] = utc_iso(final_time)
        self.session["last_updated_at"] = utc_iso(final_time)
        self.session["summary"] = self._summarize_runs(
            self.session.get("runs", []),
            include_active_session=False,
            include_estimated_saved=False,
            credit_idle_time=False,
            session_started_at=self.session.get("started_at"),
            session_ended_at=self.session.get("ended_at"),
        )
        self._flush_session()

    def close(self) -> None:
        if self.subscription_token is not None:
            self.event_bus.unsubscribe(self.subscription_token)
            self.subscription_token = None

    def build_report(self, period_key: str) -> Dict[str, Any]:
        period_start, period_end = self._resolve_period(period_key)
        sessions = self._load_sessions_from_directory()

        included_sessions: List[Dict[str, Any]] = []
        for session in sessions:
            effective_status = self._effective_session_status(session)
            if effective_status == "active":
                continue
            started_at = parse_utc_iso(session.get("started_at"))
            effective_end = self._effective_session_end(session, effective_status)
            if not started_at or not effective_end:
                continue
            if period_start and effective_end < period_start:
                continue
            if period_end and started_at > period_end:
                continue

            normalized = {
                "path": str(session.get("_path", "")),
                "username": str(session.get("username") or "unknown"),
                "pid": int(session.get("pid") or 0),
                "status": effective_status,
                "started_at": session.get("started_at"),
                "ended_at": session.get("ended_at"),
                "effective_end_at": utc_iso(effective_end),
                "runs": self._normalized_runs(session),
            }
            normalized["summary"] = self._summarize_runs(
                normalized["runs"],
                include_active_session=False,
                include_estimated_saved=True,
                credit_idle_time=True,
                session_started_at=normalized["started_at"],
                session_ended_at=normalized["effective_end_at"],
                effective_status=effective_status,
            )
            included_sessions.append(normalized)

        covered_start = min(
            (parse_utc_iso(item["started_at"]) for item in included_sessions if parse_utc_iso(item["started_at"])),
            default=None,
        )
        covered_end = max(
            (parse_utc_iso(item["effective_end_at"]) for item in included_sessions if parse_utc_iso(item["effective_end_at"])),
            default=None,
        )

        summary = self._aggregate_summary(included_sessions)
        by_user_rows = self._aggregate_by_user(included_sessions)
        by_module_rows = self._aggregate_by_module(included_sessions)
        pivot_rows = self._build_user_pivot(included_sessions, by_module_rows)

        return {
            "period_key": period_key,
            "period_label": _period_label(period_key),
            "period_window_start": utc_iso(period_start) if period_start else None,
            "period_window_end": utc_iso(period_end) if period_end else None,
            "covered_start": utc_iso(covered_start) if covered_start else None,
            "covered_end": utc_iso(covered_end) if covered_end else None,
            "covered_range_display": self._covered_range_display(covered_start, covered_end),
            "sessions": included_sessions,
            "summary": summary,
            "by_user": by_user_rows,
            "by_module": by_module_rows,
            "user_pivot": pivot_rows,
            "user_pivot_columns": self.user_pivot_columns,
        }

    def export_report_to_excel(self, report: Dict[str, Any]) -> None:
        summary_rows = [
            ["Selected period", report.get("period_label", "All time")],
            ["Covered range", report.get("covered_range_display", "N/A")],
            ["Covered range start", format_display_ts(report.get("covered_start"))],
            ["Covered range end", format_display_ts(report.get("covered_end"))],
            ["Sessions", report["summary"]["session_count"]],
            ["Completed runs", report["summary"]["completed_run_count"]],
            ["Completed actions", report["summary"]["completed_action_count"]],
            ["Failed runs", report["summary"]["failed_run_count"]],
            ["Interrupted runs", report["summary"]["interrupted_run_count"]],
            ["Abandoned sessions", report["summary"]["abandoned_session_count"]],
            ["Observed active time (s)", report["summary"]["observed_active_seconds"]],
            ["Observed active time", format_duration(report["summary"]["observed_active_seconds"])],
            ["Total active time (s)", report["summary"]["actual_active_seconds"]],
            ["Total active time", format_duration(report["summary"]["actual_active_seconds"])],
            ["Session elapsed (s)", report["summary"]["session_elapsed_seconds"]],
            ["Session elapsed", format_duration(report["summary"]["session_elapsed_seconds"])],
            ["Uncredited idle time (s)", report["summary"]["uncredited_idle_seconds"]],
            ["Uncredited idle time", format_duration(report["summary"]["uncredited_idle_seconds"])],
            ["Utilization", report["summary"]["utilization_display"]],
            ["Estimated time saved (s)", report["summary"]["estimated_saved_seconds"]],
            ["Estimated time saved", format_duration(report["summary"]["estimated_saved_seconds"])],
        ]

        by_user_columns = [
            "User",
            "Sessions",
            "Completed Runs",
            "Completed Actions",
            "Failed Runs",
            "Interrupted Runs",
            "Abandoned Sessions",
            "Avg Run Duration (s)",
            "Avg Run Duration",
            "Total Active Time (s)",
            "Total Active Time",
            "Session Elapsed (s)",
            "Session Elapsed",
            "Utilization",
            "Estimated Saved (s)",
            "Estimated Saved",
        ]
        by_user_data = [
            [
                row["User"],
                row["Sessions"],
                row["Completed Runs"],
                row["Completed Actions"],
                row["Failed Runs"],
                row["Interrupted Runs"],
                row["Abandoned Sessions"],
                row["Avg Run Duration (s)"],
                row["Avg Run Duration"],
                row["Total Active Time (s)"],
                row["Total Active Time"],
                row["Session Elapsed (s)"],
                row["Session Elapsed"],
                row["Utilization"],
                row["Estimated Saved (s)"],
                row["Estimated Saved"],
            ]
            for row in report.get("by_user", [])
        ]

        by_module_columns = [
            "Module",
            "Module Key",
            "Runs",
            "Completed Runs",
            "Completed Actions",
            "Failed Runs",
            "Interrupted Runs",
            "Total Duration (s)",
            "Total Duration",
            "Avg Duration (s)",
            "Avg Duration",
            "Estimated Saved (s)",
            "Estimated Saved",
        ]
        by_module_data = [
            [
                row["Module"],
                row["Module Key"],
                row["Runs"],
                row["Completed Runs"],
                row["Completed Actions"],
                row["Failed Runs"],
                row["Interrupted Runs"],
                row["Total Duration (s)"],
                row["Total Duration"],
                row["Avg Duration (s)"],
                row["Avg Duration"],
                row["Estimated Saved (s)"],
                row["Estimated Saved"],
            ]
            for row in report.get("by_module", [])
        ]

        pivot_columns = list(report.get("user_pivot_columns", []))
        pivot_data = [
            [row.get(column, "") for column in pivot_columns]
            for row in report.get("user_pivot", [])
        ]

        write_excel_sheets(
            self.ctx,
            self.report_file,
            [
                {
                    "columns": ["Metric", "Value"],
                    "raw_data": summary_rows,
                    "sheet_name": "Stats Summary",
                    "force_header": True,
                    "truncate_sheet": True,
                    "to_excel_kwargs": {"index": False},
                },
                {
                    "columns": by_user_columns,
                    "raw_data": by_user_data,
                    "sheet_name": "Stats By User",
                    "force_header": True,
                    "truncate_sheet": True,
                    "to_excel_kwargs": {"index": False},
                },
                {
                    "columns": by_module_columns,
                    "raw_data": by_module_data,
                    "sheet_name": "Stats By Module",
                    "force_header": True,
                    "truncate_sheet": True,
                    "to_excel_kwargs": {"index": False},
                },
                {
                    "columns": pivot_columns,
                    "raw_data": pivot_data,
                    "sheet_name": "Stats User Pivot",
                    "force_header": True,
                    "truncate_sheet": True,
                    "to_excel_kwargs": {"index": False},
                },
            ],
        )

    def _baseline_seconds_for_module(self, module_key: str) -> float:
        config_key = MODULE_BASELINE_CONFIG_KEYS.get(module_key)
        raw = self.ctx.cfg.get(config_key, self.ctx.cfg.get("stats_default_baseline_seconds", 0)) if config_key else self.ctx.cfg.get("stats_default_baseline_seconds", 0)
        try:
            return max(0.0, float(raw or 0))
        except (TypeError, ValueError):
            return 0.0

    def _sanitize_detail_value(self, value: Any) -> Optional[Any]:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return max(0, value)
        if isinstance(value, float):
            return max(0.0, round(value, 3))
        if isinstance(value, str):
            cleaned = value.strip().lower()
            if len(cleaned) > 64:
                return None
            return cleaned
        return None

    def _unit_count_for_run(self, run: Dict[str, Any]) -> int:
        metrics = run.get("metrics", {})
        if not isinstance(metrics, dict):
            return 1
        raw_unit_count = metrics.get("unit_count")
        if isinstance(raw_unit_count, (int, float)):
            return max(1, int(round(float(raw_unit_count))))
        return 1

    def _credited_duration_seconds_for_run(self, run: Dict[str, Any]) -> float:
        observed_duration_seconds = max(0.0, float(run.get("duration_seconds") or 0.0))
        if observed_duration_seconds <= 0:
            return 0.0
        if str(run.get("status") or "failed").lower() != "completed":
            return observed_duration_seconds

        baseline_seconds = self._baseline_seconds_for_module(str(run.get("module_key") or ""))
        if baseline_seconds <= 0:
            return observed_duration_seconds

        expected_duration_seconds = baseline_seconds * self._unit_count_for_run(run)
        idle_detection_threshold = max(
            expected_duration_seconds * IDLE_DURATION_MULTIPLIER,
            expected_duration_seconds + IDLE_DURATION_GRACE_SECONDS,
        )
        if observed_duration_seconds <= idle_detection_threshold:
            return observed_duration_seconds

        credited_duration_limit = max(
            expected_duration_seconds * CREDITED_DURATION_MULTIPLIER,
            expected_duration_seconds + CREDITED_DURATION_GRACE_SECONDS,
        )
        return min(observed_duration_seconds, credited_duration_limit)

    def _estimated_saved_seconds_for_run(
        self,
        run: Dict[str, Any],
        *,
        credited_duration_seconds: Optional[float] = None,
    ) -> float:
        if str(run.get("status") or "failed").lower() != "completed":
            return 0.0

        baseline_seconds = self._baseline_seconds_for_module(str(run.get("module_key") or ""))
        duration_seconds = (
            max(0.0, float(credited_duration_seconds))
            if credited_duration_seconds is not None
            else self._credited_duration_seconds_for_run(run)
        )
        unit_count = self._unit_count_for_run(run)
        return max(0.0, (baseline_seconds * unit_count) - duration_seconds)

    def _finish_active_run(self, status: str, ended_at: datetime) -> None:
        if self.active_run_index is None or not self.collect_enabled:
            return

        run = self.session["runs"][self.active_run_index]
        started_at = parse_utc_iso(run.get("started_at")) or ended_at
        duration_seconds = max(0.0, round((ended_at - started_at).total_seconds(), 3))
        run["ended_at"] = utc_iso(ended_at)
        run["duration_seconds"] = duration_seconds
        run["status"] = status if status in VALID_RUN_STATUSES else "failed"

        self.active_run_index = None
        self._touch_session(ended_at)

    def _touch_session(self, now: datetime) -> None:
        if not self.collect_enabled or not self.session:
            return

        self.session["last_updated_at"] = utc_iso(now)
        self.session["summary"] = self._summarize_runs(
            self.session.get("runs", []),
            include_active_session=True,
            include_estimated_saved=False,
            credit_idle_time=False,
            session_started_at=self.session.get("started_at"),
            session_ended_at=self.session.get("ended_at"),
            effective_status=self.session.get("status"),
        )
        self._flush_session()

    def _flush_session(self) -> None:
        if not self.collect_enabled or not self.session_path:
            return

        tmp_path = self.session_path.with_name(f".{self.session_path.name}.tmp")
        try:
            with gzip.open(tmp_path, "wt", encoding="utf-8") as handle:
                json.dump(self.session, handle, sort_keys=True)
            os.chmod(tmp_path, SHARED_STATS_FILE_MODE)
            os.replace(tmp_path, self.session_path)
        except OSError as exc:
            self.logger.warning("STATS: Failed to flush session data to %s: %s", self.session_path, exc)
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass

    def _load_sessions_from_directory(self) -> List[Dict[str, Any]]:
        if not self.directory.exists():
            return []

        sessions: List[Dict[str, Any]] = []
        try:
            candidates = sorted(self.directory.iterdir())
        except OSError as exc:
            self.logger.warning("STATS: Unable to list %s: %s", self.directory, exc)
            return []

        for path in candidates:
            if path.is_dir() and path.name in STATS_BUCKETS:
                try:
                    nested_files = sorted(path.iterdir())
                except OSError:
                    continue
                for nested in nested_files:
                    loaded = self._read_session_candidate(nested)
                    if loaded:
                        sessions.append(loaded)
                continue

            if path.is_dir():
                try:
                    nested_candidates = sorted(path.iterdir())
                except OSError:
                    continue
                for nested in nested_candidates:
                    if nested.is_dir() and nested.name in STATS_BUCKETS:
                        try:
                            bucket_files = sorted(nested.iterdir())
                        except OSError:
                            continue
                        for bucket_file in bucket_files:
                            loaded = self._read_session_candidate(bucket_file)
                            if loaded:
                                sessions.append(loaded)
                        continue

                    loaded = self._read_session_candidate(nested)
                    if loaded:
                        sessions.append(loaded)
                continue

            loaded = self._read_session_candidate(path)
            if loaded:
                sessions.append(loaded)
        return sessions

    def _read_session_candidate(self, path: Path) -> Optional[Dict[str, Any]]:
        if not path.is_file():
            return None
        if path.name.startswith(".") or not path.name.endswith(".json.gz"):
            return None
        if not STAT_FILE_RE.match(path.name):
            return None
        loaded = self._read_session_file(path)
        if loaded:
            loaded["_path"] = str(path)
        return loaded

    def _read_session_file(self, path: Path) -> Optional[Dict[str, Any]]:
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None

        if not isinstance(payload, dict):
            return None
        if payload.get("schema_name") != STATS_SCHEMA_NAME:
            return None
        if int(payload.get("schema_version") or 0) != STATS_SCHEMA_VERSION:
            return None
        return payload

    def _effective_session_status(self, session: Dict[str, Any]) -> str:
        stored = str(session.get("status") or "abandoned").lower()
        if stored in FINAL_STATUSES:
            return stored
        if stored != "active":
            return "abandoned"

        pid = int(session.get("pid") or 0)
        if _pid_exists(pid):
            return "active"
        return "abandoned"

    def _effective_session_end(self, session: Dict[str, Any], effective_status: str) -> Optional[datetime]:
        if effective_status == "active":
            return None
        ended_at = parse_utc_iso(session.get("ended_at"))
        if ended_at:
            return ended_at
        return parse_utc_iso(session.get("last_updated_at"))

    def _normalized_runs(self, session: Dict[str, Any]) -> List[Dict[str, Any]]:
        normalized_runs: List[Dict[str, Any]] = []
        for raw_run in session.get("runs", []):
            if not isinstance(raw_run, dict):
                continue
            status = str(raw_run.get("status") or "failed").lower()
            if status not in VALID_RUN_STATUSES:
                status = "failed"

            metrics = raw_run.get("metrics", {})
            if not isinstance(metrics, dict):
                metrics = {}

            title = str(raw_run.get("module_title") or "Unknown Module")
            normalized_runs.append(
                {
                    "module_key": str(raw_run.get("module_key") or ""),
                    "module_title": _RENAMED_TITLES.get(title, title),
                    "started_at": raw_run.get("started_at"),
                    "ended_at": raw_run.get("ended_at"),
                    "duration_seconds": float(raw_run.get("duration_seconds") or 0.0),
                    "status": status,
                    "metrics": metrics,
                }
            )
        return normalized_runs

    def _summarize_runs(
        self,
        runs: Iterable[Dict[str, Any]],
        *,
        include_active_session: bool,
        include_estimated_saved: bool,
        credit_idle_time: bool,
        session_started_at: str | None = None,
        session_ended_at: str | None = None,
        effective_status: str | None = None,
    ) -> Dict[str, Any]:
        completed_run_count = 0
        failed_run_count = 0
        interrupted_run_count = 0
        observed_active_seconds = 0.0
        credited_active_seconds = 0.0
        estimated_saved_seconds = 0.0
        completed_action_count = 0

        for run in runs:
            status = str(run.get("status") or "failed").lower()
            if status == "completed":
                completed_run_count += 1
            elif status == "failed":
                failed_run_count += 1
            elif status == "interrupted":
                interrupted_run_count += 1

            observed_duration_seconds = max(0.0, float(run.get("duration_seconds") or 0.0))
            observed_active_seconds += observed_duration_seconds
            credited_duration_seconds = (
                self._credited_duration_seconds_for_run(run)
                if credit_idle_time
                else observed_duration_seconds
            )
            credited_active_seconds += credited_duration_seconds
            if status == "completed":
                estimated_saved_seconds += self._estimated_saved_seconds_for_run(
                    run,
                    credited_duration_seconds=credited_duration_seconds,
                )
                completed_action_count += self._unit_count_for_run(run)

        session_elapsed_seconds = 0.0
        started_at = parse_utc_iso(session_started_at)
        ended_at = parse_utc_iso(session_ended_at)
        if started_at and ended_at:
            session_elapsed_seconds = max(0.0, round((ended_at - started_at).total_seconds(), 3))

        status = str(effective_status or "active").lower()
        abandoned_session_count = 1 if status == "abandoned" and not include_active_session else 0

        summary = {
            "completed_run_count": completed_run_count,
            "completed_action_count": completed_action_count,
            "failed_run_count": failed_run_count,
            "interrupted_run_count": interrupted_run_count,
            "abandoned_session_count": abandoned_session_count,
            "actual_active_seconds": round(credited_active_seconds, 3),
            "session_elapsed_seconds": round(session_elapsed_seconds, 3),
        }
        if credit_idle_time:
            summary["observed_active_seconds"] = round(observed_active_seconds, 3)
            summary["uncredited_idle_seconds"] = round(
                max(0.0, observed_active_seconds - credited_active_seconds),
                3,
            )
        if include_estimated_saved:
            summary["estimated_saved_seconds"] = round(estimated_saved_seconds, 3)
        return summary

    def _aggregate_summary(self, sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        summary = {
            "session_count": len(sessions),
            "completed_run_count": 0,
            "completed_action_count": 0,
            "failed_run_count": 0,
            "interrupted_run_count": 0,
            "abandoned_session_count": 0,
            "actual_active_seconds": 0.0,
            "observed_active_seconds": 0.0,
            "session_elapsed_seconds": 0.0,
            "uncredited_idle_seconds": 0.0,
            "estimated_saved_seconds": 0.0,
        }

        for session in sessions:
            session_summary = session.get("summary", {})
            observed_active_seconds = float(
                session_summary.get("observed_active_seconds", session_summary.get("actual_active_seconds") or 0.0)
            )
            actual_active_seconds = float(session_summary.get("actual_active_seconds") or 0.0)
            summary["completed_run_count"] += int(session_summary.get("completed_run_count") or 0)
            summary["completed_action_count"] += int(session_summary.get("completed_action_count") or 0)
            summary["failed_run_count"] += int(session_summary.get("failed_run_count") or 0)
            summary["interrupted_run_count"] += int(session_summary.get("interrupted_run_count") or 0)
            summary["abandoned_session_count"] += int(session_summary.get("abandoned_session_count") or 0)
            summary["actual_active_seconds"] += actual_active_seconds
            summary["observed_active_seconds"] += observed_active_seconds
            summary["session_elapsed_seconds"] += float(session_summary.get("session_elapsed_seconds") or 0.0)
            summary["uncredited_idle_seconds"] += float(
                session_summary.get("uncredited_idle_seconds", max(0.0, observed_active_seconds - actual_active_seconds))
                or 0.0
            )
            summary["estimated_saved_seconds"] += float(session_summary.get("estimated_saved_seconds") or 0.0)

        summary["actual_active_seconds"] = round_duration_seconds(summary["actual_active_seconds"])
        summary["observed_active_seconds"] = round_duration_seconds(summary["observed_active_seconds"])
        summary["session_elapsed_seconds"] = round_duration_seconds(summary["session_elapsed_seconds"])
        summary["uncredited_idle_seconds"] = round_duration_seconds(summary["uncredited_idle_seconds"])
        summary["estimated_saved_seconds"] = round_duration_seconds(summary["estimated_saved_seconds"])
        summary["utilization_display"] = format_utilization(
            summary["actual_active_seconds"],
            summary["session_elapsed_seconds"],
        )
        return summary

    def _aggregate_by_user(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        aggregates: Dict[str, Dict[str, Any]] = {}

        for session in sessions:
            username = session.get("username") or "unknown"
            row = aggregates.setdefault(
                username,
                {
                    "User": username,
                    "Sessions": 0,
                    "Completed Runs": 0,
                    "Completed Actions": 0,
                    "Failed Runs": 0,
                    "Interrupted Runs": 0,
                    "Abandoned Sessions": 0,
                    "Run Count": 0,
                    "Total Active Time (s)": 0.0,
                    "Session Elapsed (s)": 0.0,
                    "Estimated Saved (s)": 0.0,
                },
            )
            row["Sessions"] += 1
            session_summary = session.get("summary", {})
            row["Completed Runs"] += int(session_summary.get("completed_run_count") or 0)
            row["Completed Actions"] += int(session_summary.get("completed_action_count") or 0)
            row["Failed Runs"] += int(session_summary.get("failed_run_count") or 0)
            row["Interrupted Runs"] += int(session_summary.get("interrupted_run_count") or 0)
            row["Abandoned Sessions"] += int(session_summary.get("abandoned_session_count") or 0)
            row["Total Active Time (s)"] += float(session_summary.get("actual_active_seconds") or 0.0)
            row["Session Elapsed (s)"] += float(session_summary.get("session_elapsed_seconds") or 0.0)
            row["Estimated Saved (s)"] += float(session_summary.get("estimated_saved_seconds") or 0.0)
            row["Run Count"] += len(session.get("runs", []))

        results: List[Dict[str, Any]] = []
        for username in sorted(aggregates):
            row = aggregates[username]
            run_count = max(1, int(row.pop("Run Count") or 0))
            average_seconds = (row["Total Active Time (s)"] / run_count) if row["Total Active Time (s)"] else 0.0
            row["Avg Run Duration (s)"] = round_duration_seconds(average_seconds)
            row["Avg Run Duration"] = format_duration(average_seconds)
            row["Total Active Time (s)"] = round_duration_seconds(row["Total Active Time (s)"])
            row["Session Elapsed (s)"] = round_duration_seconds(row["Session Elapsed (s)"])
            row["Estimated Saved (s)"] = round_duration_seconds(row["Estimated Saved (s)"])
            row["Total Active Time"] = format_duration(row["Total Active Time (s)"])
            row["Session Elapsed"] = format_duration(row["Session Elapsed (s)"])
            row["Utilization"] = format_utilization(row["Total Active Time (s)"], row["Session Elapsed (s)"])
            row["Estimated Saved"] = format_duration(row["Estimated Saved (s)"])
            results.append(row)
        return results

    def _aggregate_by_module(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        aggregates: Dict[str, Dict[str, Any]] = {}

        for session in sessions:
            for run in session.get("runs", []):
                title = run.get("module_title") or "Unknown Module"
                row = aggregates.setdefault(
                    title,
                    {
                        "Module": title,
                        "Module Key": run.get("module_key") or "",
                        "Runs": 0,
                        "Completed Runs": 0,
                        "Completed Actions": 0,
                        "Failed Runs": 0,
                        "Interrupted Runs": 0,
                        "Total Duration (s)": 0.0,
                        "Estimated Saved (s)": 0.0,
                    },
                )
                row["Runs"] += 1
                credited_duration_seconds = self._credited_duration_seconds_for_run(run)
                row["Total Duration (s)"] += credited_duration_seconds
                status = run.get("status")
                if status == "completed":
                    row["Completed Runs"] += 1
                    row["Completed Actions"] += self._unit_count_for_run(run)
                    row["Estimated Saved (s)"] += self._estimated_saved_seconds_for_run(
                        run,
                        credited_duration_seconds=credited_duration_seconds,
                    )
                elif status == "failed":
                    row["Failed Runs"] += 1
                elif status == "interrupted":
                    row["Interrupted Runs"] += 1

        results: List[Dict[str, Any]] = []
        for module_name in sorted(aggregates):
            row = aggregates[module_name]
            average_seconds = float(row["Total Duration (s)"]) / max(1, row["Runs"])
            row["Total Duration (s)"] = round_duration_seconds(row["Total Duration (s)"])
            row["Estimated Saved (s)"] = round_duration_seconds(row["Estimated Saved (s)"])
            row["Avg Duration (s)"] = round_duration_seconds(average_seconds)
            row["Total Duration"] = format_duration(row["Total Duration (s)"])
            row["Avg Duration"] = format_duration(average_seconds)
            row["Estimated Saved"] = format_duration(row["Estimated Saved (s)"])
            results.append(row)
        return results

    def _build_user_pivot(self, sessions: List[Dict[str, Any]], by_module_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        module_names = [row["Module"] for row in by_module_rows]
        columns = [
            "User",
            "Sessions",
            "Completed Runs",
            "Completed Actions",
            "Total Active Time (s)",
            "Session Elapsed (s)",
            "Utilization",
            "Estimated Saved (s)",
        ]

        user_rows: Dict[str, Dict[str, Any]] = {}
        for session in sessions:
            username = session.get("username") or "unknown"
            row = user_rows.setdefault(
                username,
                {
                    "User": username,
                    "Sessions": 0,
                    "Completed Runs": 0,
                    "Completed Actions": 0,
                    "Total Active Time (s)": 0.0,
                    "Session Elapsed (s)": 0.0,
                    "Estimated Saved (s)": 0.0,
                },
            )
            row["Sessions"] += 1
            session_summary = session.get("summary", {})
            row["Completed Runs"] += int(session_summary.get("completed_run_count") or 0)
            row["Completed Actions"] += int(session_summary.get("completed_action_count") or 0)
            row["Total Active Time (s)"] += float(session_summary.get("actual_active_seconds") or 0.0)
            row["Session Elapsed (s)"] += float(session_summary.get("session_elapsed_seconds") or 0.0)
            row["Estimated Saved (s)"] += float(session_summary.get("estimated_saved_seconds") or 0.0)

            for run in session.get("runs", []):
                module_name = run.get("module_title") or "Unknown Module"
                row.setdefault(f"{module_name} Runs", 0)
                row.setdefault(f"{module_name} Avg Duration (s)", 0.0)
                row.setdefault(f"{module_name} Total Duration (s)", 0.0)
                row.setdefault(f"{module_name} Estimated Saved (s)", 0.0)

                row[f"{module_name} Runs"] += 1
                credited_duration_seconds = self._credited_duration_seconds_for_run(run)
                row[f"{module_name} Total Duration (s)"] += credited_duration_seconds
                row[f"{module_name} Estimated Saved (s)"] += self._estimated_saved_seconds_for_run(
                    run,
                    credited_duration_seconds=credited_duration_seconds,
                )

        results: List[Dict[str, Any]] = []
        for username in sorted(user_rows):
            row = user_rows[username]
            for module_name in module_names:
                runs_key = f"{module_name} Runs"
                avg_key = f"{module_name} Avg Duration (s)"
                total_key = f"{module_name} Total Duration (s)"
                saved_key = f"{module_name} Estimated Saved (s)"
                row.setdefault(runs_key, 0)
                row.setdefault(total_key, 0.0)
                row.setdefault(saved_key, 0.0)
                total_seconds = float(row[total_key])
                row[total_key] = round_duration_seconds(total_seconds)
                row[saved_key] = round_duration_seconds(row[saved_key])
                row[avg_key] = round_duration_seconds(total_seconds / max(1, int(row[runs_key]))) if row[runs_key] else 0

            row["Total Active Time (s)"] = round_duration_seconds(row["Total Active Time (s)"])
            row["Session Elapsed (s)"] = round_duration_seconds(row["Session Elapsed (s)"])
            row["Utilization"] = format_utilization(row["Total Active Time (s)"], row["Session Elapsed (s)"])
            row["Estimated Saved (s)"] = round_duration_seconds(row["Estimated Saved (s)"])
            results.append(row)

        pivot_columns = columns[:]
        for module_name in module_names:
            pivot_columns.extend(
                [
                    f"{module_name} Runs",
                    f"{module_name} Avg Duration (s)",
                    f"{module_name} Total Duration (s)",
                    f"{module_name} Estimated Saved (s)",
                ]
            )

        self._last_user_pivot_columns = pivot_columns
        return results

    def _covered_range_display(self, covered_start: Optional[datetime], covered_end: Optional[datetime]) -> str:
        if not covered_start or not covered_end:
            return "N/A"
        return f"{format_display_ts(utc_iso(covered_start))} -> {format_display_ts(utc_iso(covered_end))}"

    def _ensure_directory_mode(self, path: Path, expected_mode: int) -> None:
        if oscompat.is_windows():
            return  # no POSIX modes (a directory reports 0o777, never 0o1777) and no os.geteuid()
        current_mode = stat.S_IMODE(path.stat().st_mode)
        if current_mode == expected_mode:
            return

        if path.stat().st_uid != os.geteuid():
            return

        os.chmod(path, expected_mode)

    def _bucket_dir_for_name(self, filename: str, safe_username: str) -> Path:
        digest = hashlib.sha256(filename.encode("utf-8")).digest()
        bucket = STATS_BUCKETS[digest[0] % len(STATS_BUCKETS)]
        return self.directory / safe_username / bucket

    def _resolve_period(self, period_key: str) -> tuple[Optional[datetime], Optional[datetime]]:
        now = utc_now()
        for preset in PERIOD_PRESETS:
            if preset.key == period_key:
                if preset.window is None:
                    return None, now
                return now - preset.window, now
        return None, now

    @property
    def user_pivot_columns(self) -> List[str]:
        return list(getattr(self, "_last_user_pivot_columns", []))
