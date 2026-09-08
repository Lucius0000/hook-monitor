from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from codex_hooks_monitor.common import (
    RuntimeLayout,
    effective_action_mode,
    guardian_delivery_enabled,
    load_settings,
    save_settings,
    user_popup_enabled,
    utc_now,
)
from codex_hooks_monitor.app_server_client import AppServerError, CodexAppServerClient
from codex_hooks_monitor.watchdog import (
    classify_runtime,
    cached_thread_snapshot,
    extract_json_object,
    find_matching_transcript_call,
    is_terminal_turn_snapshot,
    load_state,
    mark_alert_recorded,
    maybe_emit_user_popup,
    maybe_interrupt_target,
    maybe_send_guardian_alert,
    prune_unmonitorable_open_commands,
    reduce_events,
    run_once,
    scan_new_events,
    should_record_alert,
)


class FailIfCalledClient:
    def thread_resume(self, thread_id: str) -> None:  # pragma: no cover - should never run
        raise AssertionError(f"thread_resume should not be called: {thread_id}")

    def turn_start(self, *args, **kwargs) -> None:  # pragma: no cover - should never run
        raise AssertionError("turn_start should not be called")

    def turn_interrupt(self, *args, **kwargs) -> None:  # pragma: no cover - should never run
        raise AssertionError("turn_interrupt should not be called")


class RecordingClient:
    def __init__(self) -> None:
        self.interrupt_calls: list[tuple[str, str]] = []

    def turn_interrupt(self, thread_id: str, turn_id: str) -> dict[str, object]:
        self.interrupt_calls.append((thread_id, turn_id))
        return {"ok": True}


class FailingInterruptClient:
    def turn_interrupt(self, thread_id: str, turn_id: str) -> dict[str, object]:
        raise AppServerError('{"code": -32600, "message": "thread not found"}')


class FailingGuardianClient:
    def thread_resume(self, thread_id: str) -> None:
        raise AppServerError('{"code": -32600, "message": "thread not found"}')

    def turn_start(self, *args, **kwargs) -> dict[str, object]:
        raise AssertionError("turn_start should not be reached after thread_resume failure")


class RecordingGuardianClient:
    def thread_resume(self, thread_id: str) -> None:
        self.thread_id = thread_id

    def turn_start(self, thread_id: str, *args, **kwargs) -> dict[str, object]:
        return {"turn": {"id": "guardian-turn"}}


def run_logger(runtime_root: Path, payload: dict[str, object]) -> None:
    subprocess.run(
        [sys.executable, str(SRC / "codex_hooks_monitor" / "hook_logger.py"), "--runtime-root", str(runtime_root)],
        input=json.dumps(payload, ensure_ascii=False),
        text=True,
        check=True,
        cwd=str(ROOT),
    )


def main() -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="hooks-monitor-smoke-"))
    try:
        layout = RuntimeLayout(temp_root)
        settings = load_settings(layout)
        settings["enabled"] = True
        save_settings(layout, settings)

        base_payload = {
            "cwd": str(ROOT),
            "transcript_path": str(ROOT / "tests" / "fixture-rollout.jsonl"),
            "model": "gpt-5",
            "permission_mode": "default",
            "source": "smoke-test",
        }
        run_logger(
            temp_root,
            {
                **base_payload,
                "hook_event_name": "PreToolUse",
                "session_id": "thread-a",
                "turn_id": "turn-a",
                "tool_name": "Bash",
                "tool_use_id": "tool-a",
                "tool_input": {"command": "ping 127.0.0.1 -n 10"},
            },
        )
        run_logger(
            temp_root,
            {
                **base_payload,
                "hook_event_name": "PostToolUse",
                "session_id": "thread-a",
                "turn_id": "turn-a",
                "tool_name": "Bash",
                "tool_use_id": "tool-a",
                "tool_input": {"command": "ping 127.0.0.1 -n 10"},
            },
        )
        run_logger(
            temp_root,
            {
                **base_payload,
                "hook_event_name": "PreToolUse",
                "session_id": "thread-b",
                "turn_id": "turn-b",
                "tool_name": "mcp__demo__lookup",
                "tool_use_id": "tool-b",
                "tool_input": {"query": "demo"},
            },
        )
        run_logger(
            temp_root,
            {
                **base_payload,
                "hook_event_name": "PreToolUse",
                "session_id": "thread-unmonitorable",
                "turn_id": "turn-unmonitorable",
                "tool_name": "apply_patch",
                "tool_use_id": "tool-unmonitorable",
                "tool_input": {"patch": "*** Begin Patch"},
            },
        )
        run_logger(
            temp_root,
            {
                **base_payload,
                "hook_event_name": "Stop",
                "session_id": "thread-b",
                "turn_id": "turn-b",
            },
        )

        state = load_state(layout)
        events = scan_new_events(layout, state)
        reduce_events(state, events)
        if len(events) != 5:
            raise AssertionError(f"expected 5 events, got {len(events)}")
        if state.get("open_commands"):
            raise AssertionError(f"expected no open commands, got {state['open_commands']}")
        state["open_commands"]["legacy-unmonitorable"] = {"tool_name": "apply_patch", "command": ""}
        state["alerts"]["legacy-unmonitorable"] = {"fingerprint": "legacy"}
        if prune_unmonitorable_open_commands(state) != 1:
            raise AssertionError("expected one legacy unmonitorable item to be pruned")
        if "legacy-unmonitorable" in state["alerts"]:
            raise AssertionError("expected matching legacy alert state to be pruned")

        stop_now = utc_now()
        stop_state = {"open_commands": {}, "alerts": {}}
        stop_events = [
            {
                "hook_event_name": "PreToolUse",
                "session_id": "thread-stop",
                "turn_id": "turn-stop",
                "tool_name": "Bash",
                "tool_use_id": "tool-stop",
                "tool_input_command": "Start-Sleep -Seconds 60",
                "observed_at": stop_now.isoformat(),
            },
            {
                "hook_event_name": "Stop",
                "session_id": "thread-stop",
                "turn_id": "turn-stop",
                "observed_at": stop_now.isoformat(),
            },
        ]
        reduce_events(stop_state, stop_events)
        stopped_key = "thread-stop|turn-stop|tool-stop|Bash"
        stopped_item = stop_state["open_commands"].get(stopped_key)
        if not stopped_item or not stopped_item.get("turn_stopped_at"):
            raise AssertionError("Stop must retain an unclosed shell command for background execution")

        cached_snapshot = cached_thread_snapshot(
            {
                "session_thread_cache": {"thread-cached": "thread-id-cached"},
                "session_thread_name_cache": {"thread-cached": "Cached Thread Name"},
            },
            {"session_id": "thread-cached", "command": "Start-Sleep -Seconds 60"},
        )
        if cached_snapshot["thread_id"] != "thread-id-cached" or cached_snapshot["thread_name"] != "Cached Thread Name":
            raise AssertionError(f"expected cached thread label, got {cached_snapshot}")

        alert_state = {"alerts": {}}
        alert_item = {"key": "thread-alert|turn-alert|tool-alert|Bash", "command": "Start-Sleep -Seconds 60"}
        alert_analysis = {"level": "hard_timeout_review", "signals": ["runtime_exceeded"]}
        if not should_record_alert(alert_state, alert_item, alert_analysis):
            raise AssertionError("expected first alert record")
        mark_alert_recorded(alert_state, alert_item, alert_analysis)
        if should_record_alert(alert_state, alert_item, alert_analysis):
            raise AssertionError("expected duplicate alert record to be suppressed")

        now = utc_now()
        thresholds = load_settings(layout)
        normal_item = {
            "started_at": (now - timedelta(minutes=5)).isoformat(),
            "last_event_at": (now - timedelta(minutes=5)).isoformat(),
        }
        suspect_item = {
            "started_at": (now - timedelta(minutes=11)).isoformat(),
            "last_event_at": (now - timedelta(minutes=11)).isoformat(),
        }
        long_item = {
            "started_at": (now - timedelta(minutes=21)).isoformat(),
            "last_event_at": (now - timedelta(minutes=21)).isoformat(),
        }
        normal = classify_runtime(
            normal_item,
            {
                "log_stale_seconds": 60,
                "process_alive": True,
                "cpu_percent": 28.0,
                "gpu_percent": 41.0,
                "has_error_output": False,
            },
            thresholds,
        )
        suspected = classify_runtime(
            suspect_item,
            {
                "log_stale_seconds": 360,
                "process_alive": True,
                "cpu_percent": 28.0,
                "gpu_percent": 41.0,
                "has_error_output": False,
            },
            thresholds,
        )
        high_conf = classify_runtime(
            suspect_item,
            {
                "log_stale_seconds": 720,
                "process_alive": True,
                "cpu_percent": 0.2,
                "gpu_percent": 0.0,
                "has_error_output": True,
            },
            thresholds,
        )
        hard_timeout = classify_runtime(
            long_item,
            {
                "log_stale_seconds": 60,
                "process_alive": True,
                "cpu_percent": None,
                "gpu_percent": None,
                "has_error_output": False,
            },
            thresholds,
        )
        if normal["level"] != "normal_slow":
            raise AssertionError(f"expected normal_slow, got {normal}")
        if suspected["level"] != "suspected_stuck":
            raise AssertionError(f"expected suspected_stuck, got {suspected}")
        if high_conf["level"] != "high_confidence_stuck":
            raise AssertionError(f"expected high_confidence_stuck, got {high_conf}")
        if hard_timeout["level"] != "hard_timeout_review":
            raise AssertionError(f"expected hard_timeout_review, got {hard_timeout}")

        demo_command = "powershell -NoProfile -Command Start-Sleep"
        transcript_fixture = temp_root / "function-call-rollout.jsonl"
        transcript_fixture.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call",
                                "name": "shell_command",
                                "call_id": "call-demo",
                                "arguments": json.dumps({"command": demo_command}),
                            },
                        },
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "function_call_output",
                                "call_id": "call-demo",
                                "output": "Process running with session ID 12345",
                            },
                        },
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        {
                            "type": "event_msg",
                            "payload": {
                                "type": "item_completed",
                                "item": {
                                    "type": "CommandExecution",
                                    "id": "call-demo",
                                    "process_id": "12345",
                                    "command": [
                                        "powershell",
                                        "-NoProfile",
                                        "-Command",
                                        "Start-Sleep",
                                    ],
                                    "status": "completed",
                                    "stdout": "Exit code: 0",
                                    "stderr": "",
                                },
                            },
                        },
                        ensure_ascii=False,
                    ),
                ]
            ),
            encoding="utf-8",
        )
        transcript_match = find_matching_transcript_call(
            str(transcript_fixture),
            {"command": demo_command},
        )
        if not transcript_match or transcript_match.get("status") != "completed":
            raise AssertionError(f"expected completed transcript match, got {transcript_match}")
        if not is_terminal_turn_snapshot(transcript_match):
            raise AssertionError(f"expected completion evidence, got {transcript_match}")

        custom_transcript_fixture = temp_root / "custom-tool-rollout.jsonl"
        custom_command = "powershell -NoProfile -Command \"Start-Sleep -Seconds 45\""
        custom_tool_input = f"const r = await tools.exec_command({json.dumps({'cmd': custom_command})});"
        custom_transcript_fixture.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "custom_tool_call",
                                "name": "exec",
                                "call_id": "call-wrapper",
                                "input": custom_tool_input,
                            },
                        },
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "custom_tool_call_output",
                                "call_id": "call-wrapper",
                                "output": [{"type": "input_text", "text": "Process running with session ID 54321"}],
                            },
                        },
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        {
                            "type": "event_msg",
                            "payload": {
                                "type": "item_completed",
                                "item": {
                                    "type": "CommandExecution",
                                    "id": "exec-custom",
                                    "process_id": "54321",
                                    "command": ["pwsh.exe", "-Command", custom_command],
                                    "status": "completed",
                                    "stdout": "done",
                                },
                            },
                        },
                        ensure_ascii=False,
                    ),
                ]
            ),
            encoding="utf-8",
        )
        custom_transcript_match = find_matching_transcript_call(
            str(custom_transcript_fixture),
            {"command": custom_command, "tool_use_id": "exec-custom"},
        )
        if not custom_transcript_match or not is_terminal_turn_snapshot(custom_transcript_match):
            raise AssertionError(f"expected custom tool completion match, got {custom_transcript_match}")

        run_logger(
            temp_root,
            {
                **base_payload,
                "hook_event_name": "PreToolUse",
                "session_id": "thread-complete",
                "turn_id": "turn-complete",
                "tool_name": "Bash",
                "tool_use_id": "exec-custom",
                "transcript_path": str(custom_transcript_fixture),
                "tool_input": {"command": custom_command},
            },
        )
        completion_run = run_once(layout)
        completion_state = load_state(layout)
        if any(item.get("session_id") == "thread-complete" for item in completion_state["open_commands"].values()):
            raise AssertionError(f"completed custom tool remained open: {completion_run}")

        local_only = load_settings(layout)
        local_only["actions"]["mode"] = "reserved"
        local_only["actions"]["send_guardian_message"] = False
        local_only["actions"]["show_user_popup"] = False
        if effective_action_mode(local_only) != "observe":
            raise AssertionError(f"expected observe fallback, got {effective_action_mode(local_only)}")
        if guardian_delivery_enabled(local_only) is not False:
            raise AssertionError("expected guardian delivery to be disabled")
        if user_popup_enabled(local_only) is not False:
            raise AssertionError("expected user popup to be disabled")
        delivery = maybe_send_guardian_alert(
            FailIfCalledClient(),
            layout,
            {"alerts": {}},
            {
                "key": "thread-c|turn-c|tool-c|Bash",
                "session_id": "thread-c",
                "turn_id": "turn-c",
                "tool_name": "Bash",
                "command": "ping 127.0.0.1 -n 20",
                "started_at": suspect_item["started_at"],
            },
            {
                "thread_id": "thread-c",
                "log_updated_at": "",
                "process_id": None,
                "process_alive": None,
                "cpu_percent": None,
                "gpu_percent": None,
                "thread_status": "running",
                "turn_status": "in_progress",
            },
            high_conf,
            local_only,
        )
        if delivery["reason"] != "guardian_delivery_disabled":
            raise AssertionError(f"expected guardian_delivery_disabled, got {delivery}")
        popup_result = maybe_emit_user_popup(
            {"alerts": {}},
            {
                "session_id": "thread-c",
                "key": "thread-c|turn-c|tool-c|Bash",
                "tool_name": "Bash",
                "command": "ping 127.0.0.1 -n 20",
            },
            {"thread_id": "thread-c"},
            high_conf,
            local_only,
            notifier=lambda *_args: None,
        )
        if popup_result["reason"] != "user_popup_disabled":
            raise AssertionError(f"expected user_popup_disabled, got {popup_result}")

        popup_hits: list[tuple[str, str]] = []
        local_notify = load_settings(layout)
        local_notify["actions"]["show_user_popup"] = True
        popup_enabled = maybe_emit_user_popup(
            {"alerts": {}},
            {
                "session_id": "thread-c",
                "key": "thread-c|turn-c|tool-c|Bash",
                "tool_name": "Bash",
                "command": "ping 127.0.0.1 -n 20",
            },
            {"thread_id": "thread-c", "thread_name": "Smoke Thread"},
            high_conf,
            local_notify,
            notifier=lambda title, message: popup_hits.append((title, message)),
        )
        if popup_enabled["reason"] != "user_popup_spawned":
            raise AssertionError(f"expected user_popup_spawned, got {popup_enabled}")
        time.sleep(0.05)
        if not popup_hits:
            raise AssertionError("expected popup notifier to be called")
        popup_message = popup_hits[0][1]
        if "线程名称: Smoke Thread" not in popup_message or "线程 ID: thread-c" not in popup_message:
            raise AssertionError(f"expected popup thread name and ID, got {popup_message!r}")

        shared_alert_state = {
            "alerts": {
                "thread-c|turn-c|tool-c|Bash": {
                    "last_popup_fingerprint": "preserve-me",
                    "last_popup_at": "2026-07-16T00:00:00Z",
                }
            }
        }
        guardian_notify = load_settings(layout)
        guardian_notify["actions"]["send_guardian_message"] = True
        guardian_notify["guardian"]["thread_id"] = "guardian-thread"
        guardian_delivery = maybe_send_guardian_alert(
            RecordingGuardianClient(),
            layout,
            shared_alert_state,
            {
                "key": "thread-c|turn-c|tool-c|Bash",
                "session_id": "thread-c",
                "turn_id": "turn-c",
                "tool_name": "Bash",
                "command": "ping 127.0.0.1 -n 20",
                "started_at": suspect_item["started_at"],
            },
            {
                "thread_id": "thread-c",
                "log_updated_at": "",
                "process_id": None,
                "process_alive": None,
                "cpu_percent": None,
                "gpu_percent": None,
                "thread_status": "running",
                "turn_status": "in_progress",
            },
            high_conf,
            guardian_notify,
        )
        if not guardian_delivery["sent"]:
            raise AssertionError(f"expected guardian delivery, got {guardian_delivery}")
        preserved = shared_alert_state["alerts"]["thread-c|turn-c|tool-c|Bash"]
        if preserved.get("last_popup_fingerprint") != "preserve-me":
            raise AssertionError(f"guardian delivery erased popup cooldown state: {preserved}")
        if is_terminal_turn_snapshot({"turn_status": "completed"}):
            raise AssertionError("turn completion alone must not close a background command")
        if is_terminal_turn_snapshot({"matched_item_status": "inProgress"}):
            raise AssertionError("in-progress command evidence must not be terminal")

        # Legacy helper verification only. The shipped interrupt flow now goes through guardian JSON.
        interrupt_settings = load_settings(layout)
        interrupt_settings["actions"]["mode"] = "interrupt"
        interrupt_settings["actions"]["send_guardian_message"] = False
        interrupt_settings["actions"]["show_user_popup"] = False
        interrupt_client = RecordingClient()
        interrupt_result = maybe_interrupt_target(
            interrupt_client,
            {"alerts": {}},
            {
                "key": "thread-d|turn-d|tool-d|Bash",
                "session_id": "thread-d",
                "turn_id": "turn-d",
                "tool_name": "Bash",
                "command": "ping 127.0.0.1 -n 20",
                "started_at": suspect_item["started_at"],
            },
            {
                "thread_id": "thread-d",
            },
            high_conf,
            interrupt_settings,
        )
        if interrupt_result["reason"] != "turn_interrupted":
            raise AssertionError(f"expected turn_interrupted, got {interrupt_result}")
        if interrupt_client.interrupt_calls != [("thread-d", "turn-d")]:
            raise AssertionError(f"unexpected interrupt calls: {interrupt_client.interrupt_calls}")

        interrupt_error = maybe_interrupt_target(
            FailingInterruptClient(),
            {"alerts": {}},
            {
                "key": "thread-e|turn-e|tool-e|Bash",
                "session_id": "thread-e",
                "turn_id": "turn-e",
                "tool_name": "Bash",
                "command": "ping 127.0.0.1 -n 20",
                "started_at": suspect_item["started_at"],
            },
            {
                "thread_id": "thread-e",
            },
            high_conf,
            interrupt_settings,
        )
        if interrupt_error["reason"] != "interrupt_delivery_error":
            raise AssertionError(f"expected interrupt_delivery_error, got {interrupt_error}")

        guardian_settings = load_settings(layout)
        guardian_settings["actions"]["send_guardian_message"] = True
        guardian_settings["guardian"]["thread_id"] = "guardian-thread"
        guardian_error = maybe_send_guardian_alert(
            FailingGuardianClient(),
            layout,
            {"alerts": {}},
            {
                "key": "thread-f|turn-f|tool-f|Bash",
                "session_id": "thread-f",
                "turn_id": "turn-f",
                "tool_name": "Bash",
                "command": "ping 127.0.0.1 -n 20",
                "started_at": suspect_item["started_at"],
            },
            {
                "thread_id": "thread-f",
                "log_updated_at": "",
                "process_id": None,
                "process_alive": None,
                "cpu_percent": None,
                "gpu_percent": None,
                "thread_status": "running",
                "turn_status": "in_progress",
            },
            high_conf,
            guardian_settings,
        )
        if guardian_error["reason"] != "guardian_delivery_error":
            raise AssertionError(f"expected guardian_delivery_error, got {guardian_error}")

        parsed_json = extract_json_object('{"decision":"kill","confidence":"high"}')
        if parsed_json != {"decision": "kill", "confidence": "high"}:
            raise AssertionError(f"unexpected parsed_json: {parsed_json}")

        # A silent app-server must honour the caller timeout instead of blocking readline().
        silent_server = temp_root / "silent-app-server.cmd"
        silent_server.write_text("@echo off\r\nmore > nul\r\n", encoding="ascii")
        original_codex_path = os.environ.get("CODEX_CLI_PATH")
        os.environ["CODEX_CLI_PATH"] = str(silent_server)
        started = time.monotonic()
        try:
            try:
                CodexAppServerClient(timeout_seconds=1)
            except AppServerError as exc:
                if "Timed out waiting" not in str(exc):
                    raise AssertionError(f"unexpected silent app-server error: {exc}") from exc
            else:
                raise AssertionError("silent app-server unexpectedly initialized")
        finally:
            if original_codex_path is None:
                os.environ.pop("CODEX_CLI_PATH", None)
            else:
                os.environ["CODEX_CLI_PATH"] = original_codex_path
        if time.monotonic() - started > 2.5:
            raise AssertionError("app-server timeout exceeded its bounded wait")

        print(
            json.dumps(
                {
                    "logged_events": len(events),
                    "open_commands_after_reduce": len(state.get("open_commands", {})),
                    "legacy_unmonitorable_pruned": True,
                    "classify_runtime": {
                        "normal": normal["level"],
                        "suspected": suspected["level"],
                        "high_confidence": high_conf["level"],
                        "hard_timeout": hard_timeout["level"],
                    },
                    "actions": {
                        "effective_mode_fallback": effective_action_mode(local_only),
                        "guardian_delivery_disabled": delivery["reason"],
                        "user_popup_disabled": popup_result["reason"],
                        "user_popup_enabled": popup_enabled["reason"],
                        "popup_cooldown_preserved": preserved["last_popup_fingerprint"],
                        "completed_turn_pruning": True,
                        "legacy_interrupt_helper_result": interrupt_result["reason"],
                        "legacy_interrupt_helper_error": interrupt_error["reason"],
                        "guardian_json_parse": parsed_json["decision"],
                        "guardian_error_result": guardian_error["reason"],
                        "transcript_function_call_match": transcript_match["status"],
                        "app_server_silent_timeout": True,
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
