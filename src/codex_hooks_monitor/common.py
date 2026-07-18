from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import msvcrt
except ImportError:  # pragma: no cover
    msvcrt = None


RUNTIME_DIR_NAME = "hooks-monitor"

DEFAULT_SETTINGS: dict[str, Any] = {
    "_comment": "Machine-managed runtime settings. Edit values if needed. Keep the key names unchanged.",
    "enabled": False,
    "guardian": {
        "_comment": "Fixed guardian thread. Register once, then keep reusing the same thread.",
        "thread_id": "",
        "title_hint": "",
        "send_model": "",
        "reasoning_effort": "low",
        "resend_cooldown_seconds": 1800,
        "completion_timeout_seconds": 90,
    },
    "watchdog": {
        "_comment": "Low-frequency watchdog loop and local file retention.",
        "poll_interval_seconds": 30,
        "event_retention_days": 14,
        "alert_retention_days": 30,
        "deep_check_timeout_seconds": 20,
    },
    "thresholds": {
        "_comment": "Default stuck-detection thresholds. A=10 min with multi-signal gate. B=20 min hard-timeout review.",
        "suspect_after_seconds": 600,
        "high_confidence_after_seconds": 600,
        "hard_timeout_seconds": 1200,
        "log_stale_seconds": 300,
        "cpu_idle_percent_max": 2.0,
        "gpu_idle_percent_max": 3.0,
        "stderr_error_grace_seconds": 120,
        "min_signals_for_guardian": 3,
    },
    "actions": {
        "_comment": "Action policy. observe means notify only. interrupt means watchdog waits for guardian JSON and lets guardian execute any approved kill action itself.",
        "mode": "observe",
        "send_guardian_message": True,
        "show_user_popup": True,
    },
}

SUPPORTED_ACTION_MODES = ("observe", "interrupt")


def utc_now() -> datetime:
    return datetime.now().astimezone()


def utc_now_iso() -> str:
    return utc_now().isoformat()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return deepcopy(default)
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return deepcopy(default)


def _lock_file(lock_path: Path):
    ensure_parent(lock_path)
    lock_file = lock_path.open("a+b")
    if msvcrt is None:
        return lock_file
    while True:
        try:
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            return lock_file
        except OSError:
            time.sleep(0.02)


def _unlock_file(lock_file) -> None:
    if msvcrt is not None:
        lock_file.seek(0)
        try:
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    lock_file.close()


def write_json_atomic(path: Path, payload: Any) -> None:
    ensure_parent(path)
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_file = _lock_file(lock_path)
    try:
        tmp_fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
        os.close(tmp_fd)
        tmp_path = Path(tmp_name)
        tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp_path, path)
    finally:
        _unlock_file(lock_file)


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    ensure_parent(path)
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_file = _lock_file(lock_path)
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
    finally:
        _unlock_file(lock_file)


def read_jsonl_bytes(path: Path, offset: int) -> tuple[list[dict[str, Any]], int]:
    if not path.exists():
        return [], offset

    events: list[dict[str, Any]] = []
    with path.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read()
        new_offset = fh.tell()

    if not chunk:
        return [], new_offset

    for line in chunk.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events, new_offset


def parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def format_ts(epoch_seconds: float | int | None) -> str:
    if epoch_seconds is None:
        return ""
    local_tz = datetime.now().astimezone().tzinfo
    return datetime.fromtimestamp(float(epoch_seconds), tz=local_tz).isoformat()


def prune_old_files(directory: Path, pattern: str, retain_days: int) -> int:
    if not directory.exists():
        return 0
    cutoff = time.time() - retain_days * 86400
    removed = 0
    for path in directory.glob(pattern):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except FileNotFoundError:
            continue
    return removed


def backup_file(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, backup)
    return backup


@dataclass(frozen=True)
class RuntimeLayout:
    root: Path

    @property
    def package_root(self) -> Path:
        return self.root / "codex_hooks_monitor"

    @property
    def settings_file(self) -> Path:
        return self.root / "settings.json"

    @property
    def state_file(self) -> Path:
        return self.root / "state" / "watchdog-state.json"

    @property
    def pid_file(self) -> Path:
        return self.root / "state" / "watchdog.pid"

    @property
    def events_dir(self) -> Path:
        return self.root / "events"

    @property
    def alerts_dir(self) -> Path:
        return self.root / "alerts"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def hooks_file(self) -> Path:
        return self.root.parent / "hooks.json"


def ensure_layout(layout: RuntimeLayout) -> None:
    for path in (
        layout.root,
        layout.events_dir,
        layout.alerts_dir,
        layout.logs_dir,
        layout.state_file.parent,
    ):
        path.mkdir(parents=True, exist_ok=True)


def load_settings(layout: RuntimeLayout) -> dict[str, Any]:
    ensure_layout(layout)
    data = load_json(layout.settings_file, DEFAULT_SETTINGS)
    return deep_merge(DEFAULT_SETTINGS, data)


def save_settings(layout: RuntimeLayout, settings: dict[str, Any]) -> None:
    write_json_atomic(layout.settings_file, settings)


def effective_action_mode(settings: dict[str, Any]) -> str:
    mode = str(settings.get("actions", {}).get("mode", "")).strip().lower()
    if mode in SUPPORTED_ACTION_MODES:
        return mode
    return "observe"


def guardian_delivery_enabled(settings: dict[str, Any]) -> bool:
    return bool(settings.get("actions", {}).get("send_guardian_message", True))


def user_popup_enabled(settings: dict[str, Any]) -> bool:
    return bool(settings.get("actions", {}).get("show_user_popup", True))
