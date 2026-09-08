from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from codex_hooks_monitor.app_server_client import CodexAppServerClient
from codex_hooks_monitor.watchdog import find_matching_transcript_call


PYTHON_EXE = Path(sys.executable)
RUNTIME_ROOT = Path.home() / ".codex" / "hooks-monitor"
SETTINGS_PATH = RUNTIME_ROOT / "settings.json"
PID_PATH = RUNTIME_ROOT / "state" / "watchdog.pid"
RUNTIME_WATCHDOG = RUNTIME_ROOT / "codex_hooks_monitor" / "watchdog.py"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
START_PS1 = ROOT / "scripts" / "start-watchdog.ps1"
STOP_PS1 = ROOT / "scripts" / "stop-watchdog.ps1"


def write_result(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def run_ps1(script_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path), *args],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=True,
        timeout=45,
    )


def derive_mode_profile(settings: dict[str, Any]) -> str:
    action_mode = str(settings.get("actions", {}).get("mode", "")).strip().lower()
    if action_mode == "interrupt":
        return "interrupt"
    if bool(settings.get("actions", {}).get("send_guardian_message", False)):
        return "guardian"
    return "observe"


def read_settings_text() -> str:
    return SETTINGS_PATH.read_text(encoding="utf-8-sig")


def load_settings() -> dict[str, Any]:
    return json.loads(read_settings_text())


def save_settings(payload: dict[str, Any]) -> None:
    SETTINGS_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def grep_event(session_id: str, turn_id: str, hook_name: str, started_at: float) -> dict[str, Any] | None:
    for path in sorted((RUNTIME_ROOT / "events").glob("events-*.jsonl"), reverse=True):
        if path.stat().st_mtime + 2 < started_at:
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if session_id not in line or turn_id not in line:
                    continue
                if f'"hook_event_name": "{hook_name}"' not in line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("session_id") == session_id and row.get("turn_id") == turn_id:
                    return row
        except OSError:
            continue
    return None


def wait_for_event(
    session_id: str, turn_id: str, hook_name: str, timeout_seconds: int, started_at: float
) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        hit = grep_event(session_id, turn_id, hook_name, started_at)
        if hit:
            return hit
        time.sleep(0.5)
    raise RuntimeError(f"timed out waiting for {hook_name}: {session_id}/{turn_id}")


def grep_alert(session_id: str, turn_id: str, started_at: float) -> dict[str, Any] | None:
    for path in sorted((RUNTIME_ROOT / "alerts").glob("alerts-*.jsonl"), reverse=True):
        if path.stat().st_mtime + 2 < started_at:
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if session_id not in line or turn_id not in line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                open_item = row.get("open_item", {})
                if open_item.get("session_id") == session_id and open_item.get("turn_id") == turn_id:
                    return row
        except OSError:
            continue
    return None


def watchdog_heartbeat() -> dict[str, Any]:
    path = RUNTIME_ROOT / "state" / "watchdog-state.json"
    if not path.exists():
        return {"state_file": "missing"}
    try:
        state = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"state_error": repr(exc)}
    return {
        key: state.get(key)
        for key in (
            "last_run_started_at",
            "last_run_stage",
            "last_run_candidate_key",
            "last_run_completed_at",
        )
    }


def wait_for_alert(session_id: str, turn_id: str, timeout_seconds: int, started_at: float) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        hit = grep_alert(session_id, turn_id, started_at)
        if hit:
            return hit
        time.sleep(1)
    raise RuntimeError(
        f"timed out waiting for alert: {session_id}/{turn_id}; watchdog={watchdog_heartbeat()}"
    )


def open_command_present(session_id: str, turn_id: str) -> bool:
    state_path = RUNTIME_ROOT / "state" / "watchdog-state.json"
    if not state_path.exists():
        return False
    try:
        state = json.loads(state_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return False
    for item in state.get("open_commands", {}).values():
        if item.get("session_id") == session_id and item.get("turn_id") == turn_id:
            return True
    return False


def run_completion_scan() -> dict[str, Any]:
    completed = subprocess.run(
        [str(PYTHON_EXE), str(RUNTIME_WATCHDOG), "--runtime-root", str(RUNTIME_ROOT), "--once"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=True,
        timeout=30,
    )
    return json.loads(completed.stdout)


def wait_for_transcript_completion(pre_event: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    transcript_path = str(pre_event.get("transcript_path") or "").replace("\\\\?\\", "")
    open_item = {
        "command": pre_event.get("tool_input_command"),
        "tool_use_id": pre_event.get("tool_use_id"),
    }
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        match = find_matching_transcript_call(transcript_path, open_item)
        if match and match.get("completion_evidence"):
            return match
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for CommandExecution completion: {transcript_path}")


def start_test_watchdog() -> subprocess.Popen[str]:
    stdout_log = RUNTIME_ROOT / "logs" / "watchdog.live-verify.stdout.log"
    stderr_log = RUNTIME_ROOT / "logs" / "watchdog.live-verify.stderr.log"
    stdout_log.parent.mkdir(parents=True, exist_ok=True)
    stdout_handle = stdout_log.open("w", encoding="utf-8")
    stderr_handle = stderr_log.open("w", encoding="utf-8")
    return subprocess.Popen(
        [str(PYTHON_EXE), str(RUNTIME_WATCHDOG), "--runtime-root", str(RUNTIME_ROOT)],
        cwd=str(ROOT),
        text=True,
        stdout=stdout_handle,
        stderr=stderr_handle,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-path", required=True)
    parser.add_argument("--sleep-seconds", type=int, default=45)
    parser.add_argument("--alert-timeout-seconds", type=int, default=90)
    parser.add_argument("--model", default="gpt-5.6-terra")
    args = parser.parse_args()
    if args.sleep_seconds < 20:
        raise SystemExit("--sleep-seconds must be at least 20 seconds")

    result_path = Path(args.result_path)
    result: dict[str, Any] = {
        "stage": "init",
        "runtime_root": str(RUNTIME_ROOT),
        "settings_path": str(SETTINGS_PATH),
    }
    test_started_at = time.time()
    write_result(result_path, result)

    original_settings_text = read_settings_text()
    original_settings = json.loads(original_settings_text)
    original_enabled = bool(original_settings.get("enabled"))
    original_mode = derive_mode_profile(original_settings)
    test_watchdog: subprocess.Popen[str] | None = None

    try:
        run_ps1(STOP_PS1)
        run_ps1(INSTALL_PS1)

        settings = load_settings()
        settings["enabled"] = True
        settings["actions"]["mode"] = "observe"
        settings["actions"]["send_guardian_message"] = False
        settings["actions"]["show_user_popup"] = False
        settings["watchdog"]["poll_interval_seconds"] = 2
        settings["watchdog"]["deep_check_timeout_seconds"] = 20
        settings["thresholds"]["suspect_after_seconds"] = 5
        settings["thresholds"]["high_confidence_after_seconds"] = 5
        settings["thresholds"]["hard_timeout_seconds"] = 12
        settings["thresholds"]["log_stale_seconds"] = 2
        save_settings(settings)

        result["stage"] = "settings_applied"
        result["test_settings"] = {
            "mode": settings["actions"]["mode"],
            "send_guardian_message": settings["actions"]["send_guardian_message"],
            "show_user_popup": settings["actions"]["show_user_popup"],
            "poll_interval_seconds": settings["watchdog"]["poll_interval_seconds"],
            "thresholds": settings["thresholds"],
        }
        write_result(result_path, result)

        test_watchdog = start_test_watchdog()
        result["stage"] = "watchdog_started"
        result["test_watchdog_pid"] = test_watchdog.pid
        write_result(result_path, result)

        marker = f"hm-fcall-live-{int(time.time())}"
        command = (
            f'powershell -NoProfile -Command "Write-Output \\"{marker}-start\\"; '
            f'Start-Sleep -Seconds {args.sleep_seconds}; '
            f'Write-Output \\"{marker}-end\\""'
        )
        result["marker"] = marker
        result["command"] = command
        write_result(result_path, result)

        with CodexAppServerClient(timeout_seconds=90) as client:
            thread = client.thread_start(cwd=str(ROOT), model=args.model)
            thread_id = thread["thread"]["id"]
            result["thread_id"] = thread_id
            result["model"] = args.model
            try:
                client.thread_set_name(thread_id, f"Hooks Monitor Live Verify {marker}")
            except Exception as exc:
                result["thread_name_error"] = repr(exc)
            prompt = (
                "Use the shell command tool exactly once. "
                f"Run this exact command and nothing else: `{command}`. "
                "Do not inspect files. Do not ask questions. "
                "After the command completes, reply with exactly: done."
            )
            turn = client.turn_start(thread_id, prompt, effort="low", wait_for_completion=False, timeout_seconds=60)
            turn_id = turn["turn"]["id"]
            result["turn_id"] = turn_id
            result["stage"] = "turn_started"
            write_result(result_path, result)

            pre = wait_for_event(thread_id, turn_id, "PreToolUse", timeout_seconds=60, started_at=test_started_at)
            result["pre_event"] = pre
            result["stage"] = "pre_seen"
            write_result(result_path, result)

            alert = wait_for_alert(
                thread_id, turn_id, timeout_seconds=args.alert_timeout_seconds, started_at=test_started_at
            )
            result["first_alert"] = alert
            result["stage"] = "alert_seen"
            write_result(result_path, result)

            stop = grep_event(thread_id, turn_id, "Stop", test_started_at)
            result["stop_event"] = stop
            result["stage"] = "stop_checked"
            write_result(result_path, result)

            completed_call = wait_for_transcript_completion(pre, timeout_seconds=60)
            result["transcript_match_after_completion"] = completed_call
            result["stage"] = "command_completed"
            write_result(result_path, result)

            if test_watchdog is not None and test_watchdog.poll() is None:
                test_watchdog.terminate()
                test_watchdog.wait(timeout=10)
            result["completion_scan"] = run_completion_scan()

            result["turn_after_completion"] = {
                "skipped": True,
                "reason": "transcript_command_completion_is_authoritative_for_unified_exec",
            }
            result["open_command_cleared"] = not open_command_present(thread_id, turn_id)
            if not result["open_command_cleared"]:
                raise RuntimeError("completion scan did not clear the target open command")
            result["ok"] = True
            result["stage"] = "done"
            write_result(result_path, result)

    except Exception as exc:
        result["ok"] = False
        result["stage"] = "error"
        result["error"] = repr(exc)
        write_result(result_path, result)
        return 1
    finally:
        if test_watchdog is not None and test_watchdog.poll() is None:
            try:
                test_watchdog.terminate()
                test_watchdog.wait(timeout=10)
            except Exception:
                try:
                    test_watchdog.kill()
                    test_watchdog.wait(timeout=10)
                except Exception as exc:
                    result.setdefault("cleanup_errors", []).append(f"kill_test_watchdog:{exc!r}")
        try:
            SETTINGS_PATH.write_text(original_settings_text, encoding="utf-8")
        except Exception as exc:
            result.setdefault("cleanup_errors", []).append(f"restore_settings:{exc!r}")
        if original_enabled:
            try:
                run_ps1(START_PS1, "-Mode", original_mode)
            except Exception as exc:
                result.setdefault("cleanup_errors", []).append(f"restart_original:{exc!r}")
        write_result(result_path, result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
