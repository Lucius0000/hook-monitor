from __future__ import annotations

import json
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
from codex_hooks_monitor.app_server_client import AppServerError
from codex_hooks_monitor.watchdog import (
    classify_runtime,
    extract_json_object,
    find_matching_transcript_call,
    is_terminal_turn_snapshot,
    load_state,
    maybe_emit_user_popup,
    maybe_interrupt_target,
    maybe_send_guardian_alert,
    reduce_events,
    scan_new_events,
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
        [r"C:\ProgramData\anaconda3\python.exe", str(SRC / "codex_hooks_monitor" / "hook_logger.py"), "--runtime-root", str(runtime_root)],
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
                "hook_event_name": "Stop",
                "session_id": "thread-b",
                "turn_id": "turn-b",
            },
        )

        state = load_state(layout)
        events = scan_new_events(layout, state)
        reduce_events(state, events)
        if len(events) != 4:
            raise AssertionError(f"expected 4 events, got {len(events)}")
        if state.get("open_commands"):
            raise AssertionError(f"expected no open commands, got {state['open_commands']}")

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
                                "arguments": json.dumps({"command": "powershell -ExecutionPolicy Bypass -File D:\\demo\\long.ps1"}),
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
                                "output": "Exit code: 0",
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
            {"command": "powershell -ExecutionPolicy Bypass -File D:\\demo\\long.ps1"},
        )
        if not transcript_match or transcript_match.get("status") != "completed":
            raise AssertionError(f"expected completed transcript match, got {transcript_match}")

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
            {"thread_id": "thread-c"},
            high_conf,
            local_notify,
            notifier=lambda title, message: popup_hits.append((title, message)),
        )
        if popup_enabled["reason"] != "user_popup_spawned":
            raise AssertionError(f"expected user_popup_spawned, got {popup_enabled}")
        time.sleep(0.05)
        if not popup_hits:
            raise AssertionError("expected popup notifier to be called")

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
        if not is_terminal_turn_snapshot({"turn_status": "completed"}):
            raise AssertionError("completed turns must be terminal")
        if is_terminal_turn_snapshot({"turn_status": "in_progress"}):
            raise AssertionError("in-progress turns must not be terminal")

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

        print(
            json.dumps(
                {
                    "logged_events": len(events),
                    "open_commands_after_reduce": len(state.get("open_commands", {})),
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
