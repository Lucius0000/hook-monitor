from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue
from typing import Any

import psutil

if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from codex_hooks_monitor.app_server_client import AppServerError, CodexAppServerClient
from codex_hooks_monitor.common import (
    RuntimeLayout,
    append_jsonl,
    ensure_layout,
    effective_action_mode,
    format_ts,
    guardian_delivery_enabled,
    load_json,
    load_settings,
    parse_iso8601,
    prune_old_files,
    utc_now,
    utc_now_iso,
    user_popup_enabled,
    write_json_atomic,
)


ERROR_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\berror\b",
        r"\btraceback\b",
        r"\bexception\b",
        r"\bfailed\b",
        r"\btimeout\b",
    )
]


def shorten_text(value: str | None, limit: int = 400) -> str:
    if not value:
        return ""
    text = str(value).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def load_state(layout: RuntimeLayout) -> dict[str, Any]:
    return load_json(
        layout.state_file,
        {
            "file_offsets": {},
            "open_commands": {},
            "alerts": {},
            "session_thread_cache": {},
            "last_cleanup_at": "",
        },
    )


def save_state(layout: RuntimeLayout, state: dict[str, Any]) -> None:
    write_json_atomic(layout.state_file, state)


def make_key(event: dict[str, Any]) -> str:
    return "|".join(
        [
            str(event.get("session_id") or ""),
            str(event.get("turn_id") or ""),
            str(event.get("tool_use_id") or ""),
            str(event.get("tool_name") or ""),
        ]
    )


def is_monitorable_command_event(event: dict[str, Any]) -> bool:
    """Only shell commands have a process lifecycle this watchdog can verify."""
    return event.get("tool_name") == "Bash" and bool(str(event.get("tool_input_command") or "").strip())


def is_monitorable_open_item(item: dict[str, Any]) -> bool:
    return item.get("tool_name") == "Bash" and bool(str(item.get("command") or "").strip())


def prune_unmonitorable_open_commands(state: dict[str, Any]) -> int:
    open_commands = state.setdefault("open_commands", {})
    removed = 0
    for key, item in list(open_commands.items()):
        if is_monitorable_open_item(item):
            continue
        open_commands.pop(key, None)
        state.setdefault("alerts", {}).pop(key, None)
        removed += 1
    return removed


def scan_new_events(layout: RuntimeLayout, state: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    offsets = state.setdefault("file_offsets", {})
    for path in sorted(layout.events_dir.glob("events-*.jsonl")):
        offset = int(offsets.get(str(path), 0))
        from codex_hooks_monitor.common import read_jsonl_bytes

        new_events, new_offset = read_jsonl_bytes(path, offset)
        offsets[str(path)] = new_offset
        events.extend(new_events)
    return events


def reduce_events(state: dict[str, Any], events: list[dict[str, Any]]) -> None:
    open_commands = state.setdefault("open_commands", {})
    for event in events:
        name = event.get("hook_event_name")
        if name == "PreToolUse":
            key = make_key(event)
            if not is_monitorable_command_event(event):
                # Hooks still retain the event, but non-shell tools have no reliable PID or command lifecycle.
                open_commands.pop(key, None)
                state.setdefault("alerts", {}).pop(key, None)
                continue
            open_commands[key] = {
                "key": key,
                "session_id": event.get("session_id"),
                "turn_id": event.get("turn_id"),
                "tool_use_id": event.get("tool_use_id"),
                "tool_name": event.get("tool_name"),
                "cwd": event.get("cwd"),
                "transcript_path": event.get("transcript_path"),
                "command": event.get("tool_input_command"),
                "started_at": event.get("observed_at"),
                "last_event_at": event.get("observed_at"),
            }
        elif name == "PostToolUse":
            key = make_key(event)
            open_commands.pop(key, None)
        elif name == "Stop":
            session_id = event.get("session_id")
            turn_id = event.get("turn_id")
            for item in open_commands.values():
                if item.get("session_id") == session_id and item.get("turn_id") == turn_id:
                    # A unified exec call can emit Stop before its background commandExecution item completes.
                    # Keep the shell command open until PostToolUse or explicit command-completion evidence arrives.
                    item["turn_stopped_at"] = event.get("observed_at")
                    item["last_event_at"] = event.get("observed_at")


def classify_runtime(open_item: dict[str, Any], snapshot: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    thresholds = settings["thresholds"]
    now = utc_now()
    started_at = parse_iso8601(open_item.get("started_at"))
    last_event_at = parse_iso8601(open_item.get("last_event_at"))
    runtime_seconds = (now - started_at).total_seconds() if started_at else 0
    log_stale_seconds = snapshot.get("log_stale_seconds")
    cpu_percent = snapshot.get("cpu_percent")
    gpu_percent = snapshot.get("gpu_percent")
    process_alive = snapshot.get("process_alive")
    has_error_output = snapshot.get("has_error_output", False)

    signals: list[str] = []
    if runtime_seconds >= thresholds["suspect_after_seconds"]:
        signals.append("runtime_exceeded")
    if log_stale_seconds is not None and log_stale_seconds >= thresholds["log_stale_seconds"]:
        signals.append("log_stale")
    if process_alive is False:
        signals.append("process_missing")
    if snapshot.get("thread_lookup_error"):
        signals.append("thread_lookup_error")
    if cpu_percent is not None and cpu_percent <= thresholds["cpu_idle_percent_max"]:
        signals.append("cpu_idle")
    if gpu_percent is not None and gpu_percent <= thresholds["gpu_idle_percent_max"]:
        signals.append("gpu_idle")
    if has_error_output and runtime_seconds >= thresholds["stderr_error_grace_seconds"]:
        signals.append("stderr_error")

    resource_idle = ("cpu_idle" in signals) and (gpu_percent is None or "gpu_idle" in signals)
    high_confidence_gate = runtime_seconds >= thresholds["high_confidence_after_seconds"] and (
        ("log_stale" in signals and resource_idle)
        or "process_missing" in signals
        or len(signals) >= thresholds["min_signals_for_guardian"]
    )
    hard_timeout_gate = runtime_seconds >= thresholds["hard_timeout_seconds"]
    level = "normal_slow"
    escalation_reason = ""
    if high_confidence_gate:
        level = "high_confidence_stuck"
        escalation_reason = "multi_signal_high_confidence"
    elif hard_timeout_gate:
        level = "hard_timeout_review"
        escalation_reason = "hard_timeout_only"
    elif runtime_seconds >= thresholds["suspect_after_seconds"] and (
        ("log_stale" in signals and resource_idle) or len(signals) >= 2
    ):
        level = "suspected_stuck"

    return {
        "level": level,
        "runtime_seconds": round(runtime_seconds, 1),
        "last_event_at": last_event_at.isoformat() if last_event_at else "",
        "signals": signals,
        "hard_timeout_reached": hard_timeout_gate,
        "guardian_escalation_reason": escalation_reason,
    }


def detect_gpu_percent() -> float | None:
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    try:
        values = [float(line.split(",")[0].strip()) for line in lines]
    except ValueError:
        return None
    return max(values) if values else None


def find_matching_item(turn: dict[str, Any], open_item: dict[str, Any]) -> dict[str, Any] | None:
    command = open_item.get("command") or ""
    tool_name = open_item.get("tool_name")
    items = turn.get("items", [])
    if tool_name == "Bash":
        for item in reversed(items):
            if item.get("type") != "commandExecution":
                continue
            if item.get("status") == "inProgress":
                return item
            if command and item.get("command") == command:
                return item
        for item in reversed(items):
            payload_text = json.dumps(item, ensure_ascii=False)
            if command and command not in payload_text:
                continue
            if item.get("type") in {"functionCall", "function_call", "customToolCall", "custom_tool_call"}:
                return item
        return None
    if isinstance(tool_name, str) and tool_name.startswith("mcp__"):
        target_tool = tool_name.split("__", 2)[-1]
        for item in reversed(items):
            if item.get("type") == "mcpToolCall" and item.get("tool") == target_tool:
                return item
    return None


def parse_tool_arguments(raw_arguments: Any) -> dict[str, Any]:
    if isinstance(raw_arguments, dict):
        return raw_arguments
    if not raw_arguments:
        return {}
    try:
        parsed = json.loads(raw_arguments)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def normalize_tool_output(output: Any) -> str:
    if isinstance(output, str):
        return output
    if isinstance(output, list):
        return "\n".join(
            str(item.get("text") or item.get("output") or "") if isinstance(item, dict) else str(item)
            for item in output
        )
    return str(output or "")


def normalize_command_text(command: Any) -> str:
    return str(command or "").replace(r'\"', '"').strip()


def extract_command_from_tool_input(raw_input: Any) -> str:
    arguments = parse_tool_arguments(raw_input)
    candidate = arguments.get("command") or arguments.get("cmd")
    if candidate:
        return str(candidate)
    if not isinstance(raw_input, str):
        return ""
    match = re.search(r'["\'](?:command|cmd)["\']\s*:\s*("(?:\\.|[^"\\])*")', raw_input)
    if not match:
        return ""
    try:
        return str(json.loads(match.group(1)))
    except json.JSONDecodeError:
        return ""


def find_matching_transcript_call(transcript_path: str | None, open_item: dict[str, Any]) -> dict[str, Any] | None:
    if not transcript_path:
        return None
    path = Path(str(transcript_path))
    if not path.exists():
        return None

    command = open_item.get("command") or ""
    if not command:
        return None

    matched_call: dict[str, Any] | None = None
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            payload = entry.get("payload", {})
            if entry.get("type") == "event_msg" and matched_call:
                if payload.get("type") != "item_completed":
                    continue
                item = payload.get("item", {})
                if item.get("type") != "CommandExecution":
                    continue
                expected_ids = {str(matched_call.get("call_id") or ""), str(open_item.get("tool_use_id") or "")}
                if str(item.get("id") or "") not in expected_ids:
                    continue
                command_parts = item.get("command") or []
                command_text = " ".join(str(part) for part in command_parts)
                if normalize_command_text(command) not in normalize_command_text(command_text):
                    continue
                output = item.get("aggregated_output") or item.get("stdout") or ""
                matched_call.update(
                    {
                        "type": "CommandExecution",
                        "status": "completed",
                        "processId": item.get("process_id"),
                        "aggregatedOutput": output,
                        "result": {"output": output, "stderr": item.get("stderr") or ""},
                        "completion_evidence": "transcript_command_execution_completed",
                    }
                )
                continue
            if entry.get("type") != "response_item":
                continue
            payload_type = payload.get("type")
            if payload_type in {"function_call", "custom_tool_call"}:
                raw_input = payload.get("arguments") or payload.get("input") or ""
                candidate_command = extract_command_from_tool_input(raw_input)
                if normalize_command_text(candidate_command) != normalize_command_text(command):
                    continue
                matched_call = {
                    "type": payload_type,
                    "tool": payload.get("name"),
                    "status": "inProgress",
                    "command": command,
                    "call_id": payload.get("call_id"),
                    "aggregatedOutput": "",
                    "result": {},
                    "completion_evidence": "",
                }
            elif payload_type in {"function_call_output", "custom_tool_call_output"} and matched_call:
                if payload.get("call_id") != matched_call.get("call_id"):
                    continue
                output = normalize_tool_output(payload.get("output"))
                matched_call["aggregatedOutput"] = output
                matched_call["result"] = {"output": output}
                session_match = re.search(r"Process running with session ID\s+(\d+)", output, re.IGNORECASE)
                if session_match:
                    # function_call_output is a progress response from unified exec, not completion.
                    matched_call["status"] = "inProgress"
                    matched_call["processId"] = session_match.group(1)
    except OSError:
        return None

    if not matched_call:
        return None
    return matched_call


def command_markers(command: str) -> list[str]:
    markers: list[str] = []
    for match in re.findall(r"[A-Za-z]:\\[^\s\"']+", command):
        normalized = match.replace("/", "\\").lower()
        markers.append(normalized)
        markers.append(Path(normalized).name)
    if not markers:
        for token in re.split(r"\s+", command):
            token = token.strip("\"'").lower()
            if len(token) < 5 or token.startswith("-"):
                continue
            markers.append(token)
    seen: set[str] = set()
    result: list[str] = []
    for marker in sorted(markers, key=len, reverse=True):
        if marker in seen:
            continue
        seen.add(marker)
        result.append(marker)
    return result


def find_process_by_command(command: str, started_at: str | None) -> int | None:
    markers = command_markers(command)
    if not markers:
        return None

    started = parse_iso8601(started_at)
    best_score = 0.0
    best_pid: int | None = None
    normalized_command = command.replace("/", "\\").lower()

    for proc in psutil.process_iter(["pid", "cmdline", "create_time", "name"]):
        try:
            cmdline = proc.info.get("cmdline") or []
            if not cmdline:
                continue
            cmd_text = " ".join(cmdline).replace("/", "\\").lower()
            if not cmd_text:
                continue
            score = 0.0
            if normalized_command in cmd_text:
                score += 100.0
            for marker in markers:
                if marker and marker in cmd_text:
                    score += max(8.0, min(float(len(marker)), 64.0))
            if score <= 0:
                continue
            create_time = proc.info.get("create_time")
            if started and create_time:
                delta = create_time - started.timestamp()
                if delta < -120:
                    continue
                if delta > 3600:
                    continue
                score -= abs(delta) / 30.0
            if score > best_score:
                best_score = score
                best_pid = int(proc.info["pid"])
        except (psutil.Error, OSError, ValueError, TypeError):
            continue
    return best_pid


def enrich_process_snapshot(snapshot: dict[str, Any], process_id: Any) -> None:
    snapshot["process_id"] = process_id
    if not process_id or not str(process_id).isdigit():
        return
    pid = int(process_id)
    try:
        if psutil.pid_exists(pid):
            proc = psutil.Process(pid)
            proc.cpu_percent(interval=None)
            time.sleep(0.15)
            snapshot["process_alive"] = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
            snapshot["cpu_percent"] = round(proc.cpu_percent(interval=None), 2)
            snapshot["child_pids"] = [child.pid for child in proc.children(recursive=True)]
        else:
            snapshot["process_alive"] = False
    except (psutil.Error, OSError):
        snapshot["process_alive"] = None


def resolve_thread_id(client: CodexAppServerClient, state: dict[str, Any], open_item: dict[str, Any]) -> str | None:
    session_id = open_item.get("session_id")
    cache = state.setdefault("session_thread_cache", {})
    cached = cache.get(session_id)
    if cached:
        return cached

    candidate = str(session_id or "")
    if candidate:
        try:
            client.thread_read(candidate, include_turns=False)
            cache[session_id] = candidate
            return candidate
        except AppServerError:
            pass

    try:
        data = client.thread_list(limit=200, archived=False, useStateDbOnly=True).get("data", [])
    except AppServerError:
        return None
    for thread in data:
        if thread.get("sessionId") == session_id and thread.get("parentThreadId") is None:
            cache[session_id] = thread["id"]
            thread_name = str(thread.get("name") or "").strip()
            if thread_name:
                state.setdefault("session_thread_name_cache", {})[session_id] = thread_name
            return thread["id"]
    return None


def cached_thread_snapshot(state: dict[str, Any], open_item: dict[str, Any]) -> dict[str, Any]:
    snapshot = empty_snapshot(open_item)
    session_id = open_item.get("session_id")
    snapshot["thread_id"] = state.get("session_thread_cache", {}).get(session_id) or session_id
    snapshot["thread_name"] = state.get("session_thread_name_cache", {}).get(session_id, "")
    return snapshot


def resolve_thread_label_bounded(
    state: dict[str, Any], open_item: dict[str, Any], timeout_seconds: int = 2
) -> dict[str, Any]:
    snapshot = cached_thread_snapshot(state, open_item)
    if snapshot["thread_name"]:
        return snapshot

    result: Queue[dict[str, Any]] = Queue(maxsize=1)
    client_ref: list[CodexAppServerClient] = []

    def worker() -> None:
        try:
            with CodexAppServerClient(timeout_seconds=timeout_seconds) as client:
                client_ref.append(client)
                thread_id = resolve_thread_id(client, state, open_item)
                if not thread_id:
                    result.put(snapshot)
                    return
                thread = client.thread_read(thread_id, include_turns=False).get("thread", {})
                thread_name = str(thread.get("name") or "").strip()
                state.setdefault("session_thread_cache", {})[open_item.get("session_id")] = thread_id
                if thread_name:
                    state.setdefault("session_thread_name_cache", {})[open_item.get("session_id")] = thread_name
                result.put(cached_thread_snapshot(state, open_item))
        except Exception:
            result.put(snapshot)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=max(1, timeout_seconds))
    if thread.is_alive():
        for client in client_ref:
            client.close()
        return snapshot
    try:
        return result.get_nowait()
    except Empty:
        return snapshot


def inspect_candidate(client: CodexAppServerClient, state: dict[str, Any], open_item: dict[str, Any]) -> dict[str, Any]:
    snapshot = empty_snapshot(open_item)
    thread_id = resolve_thread_id(client, state, open_item)
    snapshot["thread_id"] = thread_id
    transcript_path = open_item.get("transcript_path")
    if transcript_path:
        path = Path(str(transcript_path))
        if path.exists():
            mtime = path.stat().st_mtime
            snapshot["log_updated_at"] = format_ts(mtime)
            snapshot["log_stale_seconds"] = round(time.time() - mtime, 1)
            snapshot["log_source"] = "hook_transcript_path"
    if not thread_id:
        return snapshot

    try:
        thread = client.thread_read(thread_id, include_turns=True).get("thread", {})
    except AppServerError as exc:
        state.setdefault("session_thread_cache", {}).pop(open_item.get("session_id"), None)
        snapshot["thread_lookup_error"] = str(exc)
        return snapshot
    snapshot["thread_name"] = str(thread.get("name") or "").strip()
    if snapshot["thread_name"]:
        state.setdefault("session_thread_name_cache", {})[open_item.get("session_id")] = snapshot["thread_name"]
    snapshot["thread_status"] = thread.get("status", {}).get("type", "")
    thread_path = thread.get("path")
    if thread_path:
        path = Path(thread_path)
        if path.exists():
            mtime = path.stat().st_mtime
            snapshot["log_updated_at"] = format_ts(mtime)
            snapshot["log_stale_seconds"] = round(time.time() - mtime, 1)
            snapshot["log_source"] = "thread_path"

    turns = thread.get("turns", [])
    if turns:
        target_turn_id = open_item.get("turn_id")
        turn = next((item for item in turns if item.get("id") == target_turn_id), turns[-1])
        snapshot["turn_status"] = turn.get("status", "")
        matched = find_matching_item(turn, open_item)
        transcript_match = find_matching_transcript_call(open_item.get("transcript_path"), open_item)
        if transcript_match and transcript_match.get("completion_evidence"):
            # The transcript supplies the completion event for unified exec calls even when the turn ended earlier.
            matched = transcript_match
        elif not matched:
            matched = transcript_match
        if matched:
            snapshot["matched_item_type"] = matched.get("type", "")
            snapshot["matched_item_status"] = matched.get("status", "")
            snapshot["completion_evidence"] = matched.get("completion_evidence", "")
            output = matched.get("aggregatedOutput") or json.dumps(matched.get("result"), ensure_ascii=False)
            snapshot["has_error_output"] = any(pattern.search(output or "") for pattern in ERROR_PATTERNS)
            snapshot["stderr_summary"] = shorten_text(output)
            process_id = matched.get("processId") or matched.get("process_id")
            if process_id is None and matched.get("type") in {"function_call", "custom_tool_call", "functionCall", "customToolCall"}:
                process_id = find_process_by_command(str(open_item.get("command") or ""), open_item.get("started_at"))
            enrich_process_snapshot(snapshot, process_id)
            snapshot["gpu_percent"] = detect_gpu_percent()
    return snapshot


def empty_snapshot(open_item: dict[str, Any]) -> dict[str, Any]:
    return {
        "thread_id": None,
        "thread_name": "",
        "command": open_item.get("command"),
        "process_id": None,
        "child_pids": [],
        "process_alive": None,
        "cpu_percent": None,
        "gpu_percent": None,
        "log_updated_at": "",
        "log_stale_seconds": None,
        "thread_status": "",
        "turn_status": "",
        "has_error_output": False,
        "stderr_summary": "",
        "matched_item_type": "",
        "matched_item_status": "",
        "completion_evidence": "",
        "thread_lookup_error": "",
        "log_source": "",
    }


def inspect_candidate_bounded(
    state: dict[str, Any], open_item: dict[str, Any], timeout_seconds: int
) -> dict[str, Any]:
    result: Queue[dict[str, Any]] = Queue(maxsize=1)
    client_ref: list[CodexAppServerClient] = []

    def worker() -> None:
        try:
            with CodexAppServerClient(timeout_seconds=timeout_seconds) as client:
                client_ref.append(client)
                result.put({"snapshot": inspect_candidate(client, state, open_item)})
        except Exception as exc:
            result.put({"error": repr(exc)})

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=max(1, timeout_seconds))
    if thread.is_alive():
        for client in client_ref:
            client.close()
        snapshot = empty_snapshot(open_item)
        snapshot["thread_lookup_error"] = "deep_check_timeout"
        return snapshot
    try:
        payload = result.get_nowait()
    except Empty:
        payload = {"error": "deep_check_no_result"}
    if "snapshot" in payload:
        return payload["snapshot"]
    snapshot = empty_snapshot(open_item)
    snapshot["thread_lookup_error"] = str(payload.get("error") or "deep_check_error")
    return snapshot


def alert_hash(open_item: dict[str, Any], analysis: dict[str, Any]) -> str:
    payload = json.dumps(
        {
            "key": open_item.get("key"),
            "level": analysis.get("level"),
            "signals": analysis.get("signals"),
            "command": open_item.get("command"),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def should_record_alert(state: dict[str, Any], open_item: dict[str, Any], analysis: dict[str, Any]) -> bool:
    prior = state.setdefault("alerts", {}).get(open_item["key"], {})
    return prior.get("last_recorded_alert_fingerprint") != alert_hash(open_item, analysis)


def mark_alert_recorded(state: dict[str, Any], open_item: dict[str, Any], analysis: dict[str, Any]) -> None:
    alert_state = state.setdefault("alerts", {}).setdefault(open_item["key"], {})
    alert_state["last_recorded_alert_fingerprint"] = alert_hash(open_item, analysis)
    alert_state["last_recorded_alert_at"] = utc_now_iso()


def build_guardian_prompt(open_item: dict[str, Any], snapshot: dict[str, Any], analysis: dict[str, Any], settings: dict[str, Any]) -> str:
    action_mode = effective_action_mode(settings)
    process_id = snapshot.get("process_id")
    kill_process_command = ""
    kill_tree_command = ""
    if process_id and str(process_id).isdigit():
        python_exe = Path(sys.executable)
        admin_script = Path(__file__).resolve().parent / "admin.py"
        kill_process_command = (
            f'"{python_exe}" "{admin_script}" '
            f"kill-process --pid {process_id} --scope process"
        )
        kill_tree_command = (
            f'"{python_exe}" "{admin_script}" '
            f"kill-process --pid {process_id} --scope process_tree"
        )

    recommended_action = "notify"
    escalation_reason = analysis.get("guardian_escalation_reason") or ""
    if action_mode == "interrupt" and analysis.get("level") == "high_confidence_stuck":
        recommended_action = "kill"
    elif guardian_delivery_enabled(settings):
        recommended_action = "suggest_stop"

    structured = {
        "target_thread_id": snapshot.get("thread_id") or open_item.get("session_id"),
        "target_thread_name": snapshot.get("thread_name") or "",
        "target_turn_id": open_item.get("turn_id"),
        "session_id": open_item.get("session_id"),
        "command": open_item.get("command"),
        "pid": process_id,
        "child_pids": snapshot.get("child_pids"),
        "started_at": open_item.get("started_at"),
        "last_event_at": analysis.get("last_event_at"),
        "log_updated_at": snapshot.get("log_updated_at"),
        "process_alive": snapshot.get("process_alive"),
        "cpu_percent": snapshot.get("cpu_percent"),
        "gpu_percent": snapshot.get("gpu_percent"),
        "stderr_summary": snapshot.get("stderr_summary"),
        "signals": analysis.get("signals"),
        "watchdog_judgement": analysis.get("level"),
        "escalation_reason": escalation_reason,
        "recommended_action": recommended_action,
        "thread_status": snapshot.get("thread_status"),
        "turn_status": snapshot.get("turn_status"),
        "kill_process_command": kill_process_command,
        "kill_process_tree_command": kill_tree_command,
    }
    if action_mode == "interrupt":
        return (
            "你是固定 guardian 线程，只能基于下面的结构化监测信息作出决策。\n"
            "你必须只返回一个 JSON 对象，不要加代码块，不要加额外解释。\n"
            "允许的 decision 只有 wait、notify、suggest_stop、kill。\n"
            "如果 watchdog_judgement=high_confidence_stuck、recommended_action=kill、PID 存活且没有明显反证，默认应选择 kill。\n"
            "如果 escalation_reason=hard_timeout_only，默认不要自动 kill，优先返回 notify 或 suggest_stop；只有存在额外强证据时才可返回 kill。\n"
            "如果 decision 不是 kill，不要运行任何工具。\n"
            "如果 decision 是 kill：\n"
            "1. 先判断 kill_scope 应为 process 还是 process_tree。\n"
            "2. 只运行下面给出的对应 kill 命令之一，不能改写成别的命令。\n"
            "3. 运行完成后，再返回 JSON。\n"
            "4. action_taken 只能写 succeeded、failed、not_run 三种值。\n"
            "5. 如果 shell 权限被拒绝、命令失败、或 PID 已不存在，也返回 decision=kill，但 action_taken 必须写 failed，并把失败原因写进 action_result。\n"
            "返回 JSON 必须包含这些字段：decision, confidence, reason, kill_scope, target_pid, action_taken, action_result。\n\n"
            "结构化监测信息：\n"
            f"```json\n{json.dumps(structured, ensure_ascii=False, indent=2)}\n```\n"
        )
    return (
        "你是固定监护线程。请只基于下面的本地告警判断目标线程当前更像：继续等待、提醒用户、建议中止，或执行中止。\n"
        "优先避免误杀正常长跑任务；如果证据不足，默认不要自动中止。\n\n"
        "结构化告警：\n"
        f"```json\n{json.dumps(structured, ensure_ascii=False, indent=2)}\n```\n"
    )


def build_user_popup_text(open_item: dict[str, Any], snapshot: dict[str, Any], analysis: dict[str, Any], settings: dict[str, Any]) -> str:
    action_mode = effective_action_mode(settings)
    action_line = "当前动作：仅提醒，不自动中止。"
    if action_mode == "interrupt" and analysis.get("level") == "high_confidence_stuck":
        action_line = "当前动作：高置信度命中后，将交由 guardian 判断；如其判定 kill，将由 guardian 执行进程中止。"
    elif analysis.get("level") == "hard_timeout_review":
        action_line = "当前动作：运行时间已超过硬超时阈值，将交由 guardian 做强制复核；默认不自动中止。"
    command = open_item.get("command") or open_item.get("tool_name") or "<unknown>"
    thread_name = str(snapshot.get("thread_name") or "").strip() or "<未命名或未解析>"
    thread_id = snapshot.get("thread_id") or open_item.get("session_id") or "<unknown>"
    return (
        "Codex Hooks Monitor 检测到高置信度异常。\n\n"
        f"线程名称: {thread_name}\n"
        f"线程 ID: {thread_id}\n"
        f"命令/工具: {command}\n"
        f"判定: {analysis.get('level')}\n"
        f"信号: {', '.join(analysis.get('signals') or [])}\n"
        f"运行时长(秒): {analysis.get('runtime_seconds')}\n\n"
        f"{action_line}"
    )


def default_popup_notifier(title: str, message: str) -> None:
    try:
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        executable = str(pythonw if pythonw.exists() else Path(sys.executable))
        icon_path = Path(__file__).resolve().parent / "assets" / "hooks-monitor.ico"
        popup_code = f"""
import tkinter as tk
from tkinter import scrolledtext

title = {json.dumps(title, ensure_ascii=False)}
message = {json.dumps(message, ensure_ascii=False)}
icon_path = {json.dumps(str(icon_path), ensure_ascii=False)}

root = tk.Tk()
root.title(title)
try:
    root.iconbitmap(icon_path)
except tk.TclError:
    pass
root.attributes('-topmost', True)
root.resizable(False, False)
root.geometry('720x420')

frame = tk.Frame(root, padx=12, pady=12)
frame.pack(fill='both', expand=True)

text = scrolledtext.ScrolledText(frame, width=78, height=18, wrap='word', font=('Microsoft YaHei UI', 10))
text.insert('1.0', message)
text.configure(state='disabled')
text.pack(fill='both', expand=True)

button = tk.Button(frame, text='OK', width=10, command=root.destroy)
button.pack(anchor='e', pady=(12, 0))

root.after(50, root.lift)
root.after(100, root.focus_force)
root.mainloop()
"""
        subprocess.Popen(
            [
                executable,
                "-c",
                popup_code,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return


def maybe_emit_user_popup(
    state: dict[str, Any],
    open_item: dict[str, Any],
    snapshot: dict[str, Any],
    analysis: dict[str, Any],
    settings: dict[str, Any],
    notifier: callable | None = None,
) -> dict[str, Any]:
    if not user_popup_enabled(settings):
        return {"sent": False, "reason": "user_popup_disabled"}

    alert_key = open_item["key"]
    fingerprint = alert_hash(open_item, analysis)
    alerts = state.setdefault("alerts", {})
    prior = alerts.get(alert_key, {})
    cooldown = settings["guardian"].get("resend_cooldown_seconds", 1800)
    last_popup = parse_iso8601(prior.get("last_popup_at"))
    if prior.get("last_popup_fingerprint") == fingerprint and last_popup:
        if (utc_now() - last_popup).total_seconds() < cooldown:
            return {"sent": False, "reason": "user_popup_cooldown"}

    title = "Codex Hooks Monitor"
    message = build_user_popup_text(open_item, snapshot, analysis, settings)
    popup_notifier = notifier or default_popup_notifier
    thread = threading.Thread(target=popup_notifier, args=(title, message), daemon=True)
    thread.start()
    alerts.setdefault(alert_key, {})
    alerts[alert_key]["last_popup_fingerprint"] = fingerprint
    alerts[alert_key]["last_popup_at"] = utc_now_iso()
    return {"sent": True, "reason": "user_popup_spawned", "title": title, "message": message}


def terminate_process_fallback(process_id: Any) -> dict[str, Any]:
    if process_id is None or not str(process_id).isdigit():
        return {"sent": False, "reason": "process_kill_target_missing"}

    pid = int(process_id)
    try:
        proc = psutil.Process(pid)
    except (psutil.Error, OSError):
        return {"sent": False, "reason": "process_kill_target_missing", "process_id": pid}

    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
            return {"sent": True, "reason": "process_terminated_fallback", "process_id": pid}
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            return {"sent": True, "reason": "process_killed_fallback", "process_id": pid}
    except (psutil.Error, OSError) as exc:
        return {"sent": False, "reason": "process_kill_failed", "process_id": pid, "error": repr(exc)}


def extract_json_object(text: str) -> dict[str, Any] | None:
    candidate = text.strip()
    if not candidate:
        return None
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start >= 0 and end > start:
        try:
            parsed = json.loads(candidate[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None


def read_turn_result(client: CodexAppServerClient, thread_id: str, turn_id: str) -> dict[str, Any]:
    thread = client.thread_read(thread_id, include_turns=True).get("thread", {})
    turns = thread.get("turns", [])
    turn = next((item for item in turns if item.get("id") == turn_id), None)
    if not turn:
        return {"turn_found": False}

    final_text = ""
    command_results: list[dict[str, Any]] = []
    for item in turn.get("items", []):
        if item.get("type") == "agentMessage" and item.get("phase") == "final_answer":
            final_text = item.get("text", "")
        if item.get("type") == "commandExecution":
            command_results.append(
                {
                    "command": item.get("command"),
                    "status": item.get("status"),
                    "exit_code": item.get("exitCode"),
                    "aggregated_output": shorten_text(item.get("aggregatedOutput")),
                }
            )
    parsed = extract_json_object(final_text)
    return {
        "turn_found": True,
        "turn_status": turn.get("status"),
        "final_text": final_text,
        "parsed_json": parsed,
        "command_results": command_results,
    }


def maybe_interrupt_target(
    client: CodexAppServerClient,
    state: dict[str, Any],
    open_item: dict[str, Any],
    snapshot: dict[str, Any],
    analysis: dict[str, Any],
    settings: dict[str, Any],
) -> dict[str, Any]:
    if effective_action_mode(settings) != "interrupt":
        return {"sent": False, "reason": "interrupt_mode_disabled"}

    alert_key = open_item["key"]
    alerts = state.setdefault("alerts", {})
    if alerts.get(alert_key, {}).get("last_interrupt_fingerprint") == alert_hash(open_item, analysis):
        return {"sent": False, "reason": "interrupt_already_attempted"}

    thread_id = snapshot.get("thread_id")
    turn_id = open_item.get("turn_id")
    if not thread_id or not turn_id:
        return {"sent": False, "reason": "interrupt_target_missing"}

    try:
        result = client.turn_interrupt(thread_id, turn_id)
    except AppServerError as exc:
        return {
            "sent": False,
            "reason": "interrupt_delivery_error",
            "thread_id": thread_id,
            "turn_id": turn_id,
            "error": str(exc),
        }
    alerts.setdefault(alert_key, {})
    alerts[alert_key]["last_interrupt_fingerprint"] = alert_hash(open_item, analysis)
    alerts[alert_key]["last_interrupted_at"] = utc_now_iso()
    return {"sent": True, "reason": "turn_interrupted", "thread_id": thread_id, "turn_id": turn_id, "result": result}


def maybe_send_guardian_alert(
    client: CodexAppServerClient | None,
    layout: RuntimeLayout,
    state: dict[str, Any],
    open_item: dict[str, Any],
    snapshot: dict[str, Any],
    analysis: dict[str, Any],
    settings: dict[str, Any],
) -> dict[str, Any]:
    prompt = build_guardian_prompt(open_item, snapshot, analysis, settings)
    if not guardian_delivery_enabled(settings):
        return {"sent": False, "reason": "guardian_delivery_disabled", "prompt": prompt}

    guardian = settings["guardian"]
    alert_key = open_item["key"]
    alert_fingerprint = alert_hash(open_item, analysis)
    alerts = state.setdefault("alerts", {})
    prior = alerts.get(alert_key, {})
    cooldown = guardian.get("resend_cooldown_seconds", 1800)
    last_sent = parse_iso8601(prior.get("last_sent_at"))
    if prior.get("fingerprint") == alert_fingerprint and last_sent:
        if (utc_now() - last_sent).total_seconds() < cooldown:
            return {"sent": False, "reason": "cooldown"}

    thread_id = guardian.get("thread_id", "").strip()
    if not thread_id:
        return {"sent": False, "reason": "guardian_thread_missing", "prompt": prompt}
    if client is None:
        return {"sent": False, "reason": "guardian_client_unavailable", "prompt": prompt}

    action_mode = effective_action_mode(settings)
    try:
        client.thread_resume(thread_id)
        result = client.turn_start(
            thread_id,
            prompt,
            model=guardian.get("send_model") or None,
            effort=guardian.get("reasoning_effort") or None,
            wait_for_completion=action_mode == "interrupt",
            timeout_seconds=guardian.get("completion_timeout_seconds", 90),
        )
    except AppServerError as exc:
        return {"sent": False, "reason": "guardian_delivery_error", "prompt": prompt, "error": str(exc)}

    delivery: dict[str, Any] = {
        "sent": True,
        "guardian_thread_id": thread_id,
        "guardian_turn_id": result["turn"]["id"],
        "prompt": prompt,
    }
    if action_mode == "interrupt":
        turn_result = read_turn_result(client, thread_id, result["turn"]["id"])
        delivery["guardian_turn_result"] = turn_result
        parsed_json = turn_result.get("parsed_json")
        if not parsed_json:
            delivery["sent"] = False
            delivery["reason"] = "guardian_invalid_json"
        else:
            delivery["decision"] = parsed_json

    alert_state = alerts.setdefault(alert_key, {})
    alert_state.update(
        {
            "fingerprint": alert_fingerprint,
            "last_sent_at": utc_now_iso(),
            "level": analysis["level"],
            "guardian_thread_id": thread_id,
            "guardian_turn_id": result["turn"]["id"],
        }
    )
    return delivery


def send_guardian_alert_bounded(
    layout: RuntimeLayout,
    state: dict[str, Any],
    open_item: dict[str, Any],
    snapshot: dict[str, Any],
    analysis: dict[str, Any],
    settings: dict[str, Any],
) -> dict[str, Any]:
    if not guardian_delivery_enabled(settings):
        return maybe_send_guardian_alert(None, layout, state, open_item, snapshot, analysis, settings)

    action_mode = effective_action_mode(settings)
    timeout_seconds = settings["watchdog"]["deep_check_timeout_seconds"]
    if action_mode == "interrupt":
        timeout_seconds = settings["guardian"].get("completion_timeout_seconds", timeout_seconds)
    result: Queue[dict[str, Any]] = Queue(maxsize=1)
    client_ref: list[CodexAppServerClient] = []

    def worker() -> None:
        try:
            with CodexAppServerClient(timeout_seconds=timeout_seconds) as client:
                client_ref.append(client)
                result.put(maybe_send_guardian_alert(client, layout, state, open_item, snapshot, analysis, settings))
        except Exception as exc:
            result.put({"sent": False, "reason": "guardian_delivery_error", "error": repr(exc)})

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=max(1, timeout_seconds))
    if thread.is_alive():
        for client in client_ref:
            client.close()
        return {"sent": False, "reason": "guardian_delivery_timeout"}
    try:
        return result.get_nowait()
    except Empty:
        return {"sent": False, "reason": "guardian_delivery_no_result"}


def is_terminal_turn_snapshot(snapshot: dict[str, Any]) -> bool:
    return (
        str(snapshot.get("matched_item_status") or snapshot.get("status") or "").lower() == "completed"
        and bool(snapshot.get("completion_evidence"))
    )


def prune_runtime(layout: RuntimeLayout, settings: dict[str, Any], state: dict[str, Any]) -> None:
    now = utc_now()
    last_cleanup = parse_iso8601(state.get("last_cleanup_at"))
    if last_cleanup and (now - last_cleanup).total_seconds() < 21600:
        return
    watchdog_settings = settings["watchdog"]
    prune_old_files(layout.events_dir, "events-*.jsonl", watchdog_settings["event_retention_days"])
    prune_old_files(layout.alerts_dir, "alerts-*.jsonl", watchdog_settings["alert_retention_days"])
    state["last_cleanup_at"] = utc_now_iso()


def run_once(layout: RuntimeLayout) -> dict[str, Any]:
    settings = load_settings(layout)
    state = load_state(layout)
    state["last_run_started_at"] = utc_now_iso()
    state["last_run_stage"] = "scanning_events"
    events = scan_new_events(layout, state)
    reduce_events(state, events)
    pruned_unmonitorable = prune_unmonitorable_open_commands(state)
    prune_runtime(layout, settings, state)
    state["last_run_stage"] = "events_reduced"
    save_state(layout, state)

    results = {
        "processed_events": len(events),
        "open_commands": len(state.get("open_commands", {})),
        "pruned_unmonitorable_open_commands": pruned_unmonitorable,
        "alerts": [],
    }
    if not settings.get("enabled", False):
        state["last_run_stage"] = "disabled"
        state["last_run_completed_at"] = utc_now_iso()
        save_state(layout, state)
        return results

    for open_item in list(state.get("open_commands", {}).values()):
        try:
            state["last_run_candidate_key"] = open_item["key"]
            state["last_run_stage"] = "transcript_completion_check"
            save_state(layout, state)
            transcript_match = find_matching_transcript_call(open_item.get("transcript_path"), open_item)
            if transcript_match and is_terminal_turn_snapshot(transcript_match):
                state.get("open_commands", {}).pop(open_item["key"], None)
                state.get("alerts", {}).pop(open_item["key"], None)
                continue
            state["last_run_stage"] = "coarse_hard_timeout_check"
            save_state(layout, state)
            # B threshold must not wait for app-server or process inspection.
            coarse_snapshot = resolve_thread_label_bounded(state, open_item)
            coarse_analysis = classify_runtime(open_item, coarse_snapshot, settings)
            if coarse_analysis["level"] == "hard_timeout_review":
                should_record = should_record_alert(state, open_item, coarse_analysis)
                popup_result = maybe_emit_user_popup(state, open_item, coarse_snapshot, coarse_analysis, settings)
                alert_result = send_guardian_alert_bounded(
                    layout, state, open_item, coarse_snapshot, coarse_analysis, settings
                )
                payload = {
                    "observed_at": utc_now_iso(),
                    "open_item": open_item,
                    "snapshot": coarse_snapshot,
                    "analysis": coarse_analysis,
                    "user_notification": popup_result,
                    "guardian_delivery": alert_result,
                    "interrupt_delivery": {"sent": False, "reason": "hard_timeout_review_only"},
                }
                if should_record or popup_result.get("sent") or alert_result.get("sent"):
                    day = utc_now_iso()[:10]
                    append_jsonl(layout.alerts_dir / f"alerts-{day}.jsonl", payload)
                    mark_alert_recorded(state, open_item, coarse_analysis)
                    results["alerts"].append(payload)
                continue
            state["last_run_stage"] = "bounded_deep_check"
            save_state(layout, state)
            snapshot = inspect_candidate_bounded(
                state, open_item, settings["watchdog"]["deep_check_timeout_seconds"]
            )
            if is_terminal_turn_snapshot(snapshot):
                state.get("open_commands", {}).pop(open_item["key"], None)
                state.get("alerts", {}).pop(open_item["key"], None)
                continue
            analysis = classify_runtime(open_item, snapshot, settings)
            if analysis["level"] not in {"high_confidence_stuck", "hard_timeout_review"}:
                continue
            should_record = should_record_alert(state, open_item, analysis)
            state["last_run_stage"] = "dispatching_alert"
            save_state(layout, state)
            popup_result = maybe_emit_user_popup(state, open_item, snapshot, analysis, settings)
            alert_result = send_guardian_alert_bounded(layout, state, open_item, snapshot, analysis, settings)
            interrupt_result = {"sent": False, "reason": "interrupt_mode_disabled"}
            if effective_action_mode(settings) == "interrupt":
                decision = alert_result.get("decision") or {}
                action_taken = str(decision.get("action_taken", "")).lower()
                success_actions = {"succeeded", "killed", "terminated", "completed"}
                interrupt_result = {
                    "sent": action_taken in success_actions,
                    "reason": action_taken or "guardian_no_action",
                    "decision": decision,
                    "guardian_turn_id": alert_result.get("guardian_turn_id"),
                }
            payload = {
                "observed_at": utc_now_iso(),
                "open_item": open_item,
                "snapshot": snapshot,
                "analysis": analysis,
                "user_notification": popup_result,
                "guardian_delivery": alert_result,
                "interrupt_delivery": interrupt_result,
            }
            if should_record or popup_result.get("sent") or alert_result.get("sent") or interrupt_result.get("sent"):
                day = utc_now_iso()[:10]
                append_jsonl(layout.alerts_dir / f"alerts-{day}.jsonl", payload)
                mark_alert_recorded(state, open_item, analysis)
                results["alerts"].append(payload)
            if interrupt_result.get("sent"):
                state.get("open_commands", {}).pop(open_item["key"], None)
        except Exception as exc:
            day = utc_now_iso()[:10]
            append_jsonl(
                layout.logs_dir / f"watchdog-errors-{day}.jsonl",
                {
                    "observed_at": utc_now_iso(),
                    "open_item": open_item,
                    "error": repr(exc),
                },
            )
    state["last_run_stage"] = "idle"
    state["last_run_completed_at"] = utc_now_iso()
    state.pop("last_run_candidate_key", None)
    save_state(layout, state)
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    layout = RuntimeLayout(Path(args.runtime_root))
    ensure_layout(layout)

    if args.once:
        print(json.dumps(run_once(layout), ensure_ascii=False, indent=2))
        return 0

    while True:
        settings = load_settings(layout)
        if not settings.get("enabled", False):
            return 0
        try:
            run_once(layout)
        except Exception as exc:  # pragma: no cover
            day = utc_now_iso()[:10]
            append_jsonl(
                layout.logs_dir / f"watchdog-errors-{day}.jsonl",
                {"observed_at": utc_now_iso(), "error": repr(exc)},
            )
        time.sleep(settings["watchdog"]["poll_interval_seconds"])


if __name__ == "__main__":
    raise SystemExit(main())
