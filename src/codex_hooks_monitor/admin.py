from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import psutil

if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from codex_hooks_monitor.app_server_client import AppServerError, CodexAppServerClient
from codex_hooks_monitor.common import (
    DEFAULT_SETTINGS,
    RuntimeLayout,
    backup_file,
    ensure_layout,
    effective_action_mode,
    guardian_delivery_enabled,
    load_json,
    load_settings,
    save_settings,
    SUPPORTED_ACTION_MODES,
    user_popup_enabled,
    write_json_atomic,
)


def _runtime_hook_commands(layout: RuntimeLayout) -> dict[str, Any]:
    python_exe = sys.executable
    logger = layout.package_root / "hook_logger.py"
    win_command = f'"{python_exe}" "{logger}" --runtime-root "{layout.root}"'
    posix_command = win_command.replace("\\", "/")
    return {
        "type": "command",
        "command": posix_command,
        "commandWindows": win_command,
        "timeout": 30,
        "statusMessage": "Hooks Monitor event logging",
    }


def _managed_group(layout: RuntimeLayout, matcher: str | None) -> dict[str, Any]:
    group: dict[str, Any] = {"hooks": [_runtime_hook_commands(layout)]}
    if matcher is not None:
        group["matcher"] = matcher
    return group


def desired_hooks(layout: RuntimeLayout) -> dict[str, list[dict[str, Any]]]:
    return {
        "SessionStart": [_managed_group(layout, "startup|resume|clear|compact")],
        "PreToolUse": [_managed_group(layout, ".*")],
        "PostToolUse": [_managed_group(layout, ".*")],
        "Stop": [_managed_group(layout, None)],
    }


def _is_our_group(layout: RuntimeLayout, group: dict[str, Any]) -> bool:
    runtime_fragment = str(layout.root).lower()
    for hook in group.get("hooks", []):
        text = " ".join(
            str(hook.get(name, ""))
            for name in ("command", "commandWindows", "command_windows", "statusMessage")
        ).lower()
        if runtime_fragment in text or "hooks monitor event logging" in text:
            return True
    return False


def enable_hooks(layout: RuntimeLayout) -> dict[str, Any]:
    hooks_path = layout.hooks_file
    existing = load_json(hooks_path, {"hooks": {}})
    hooks = existing.get("hooks", {})
    changed = False
    for event_name, groups in desired_hooks(layout).items():
        current_groups = hooks.get(event_name, [])
        filtered = [group for group in current_groups if not _is_our_group(layout, group)]
        if len(filtered) != len(current_groups):
            changed = True
        updated_groups = filtered + groups
        if updated_groups != current_groups:
            changed = True
        hooks[event_name] = updated_groups
    if changed or not hooks_path.exists():
        backup = backup_file(hooks_path)
        write_json_atomic(hooks_path, {"hooks": hooks})
        return {"changed": True, "path": str(hooks_path), "backup": str(backup) if backup else ""}
    return {"changed": False, "path": str(hooks_path), "backup": ""}


def disable_hooks(layout: RuntimeLayout) -> dict[str, Any]:
    hooks_path = layout.hooks_file
    existing = load_json(hooks_path, {"hooks": {}})
    hooks = existing.get("hooks", {})
    changed = False
    for event_name in list(hooks.keys()):
        groups = hooks.get(event_name, [])
        filtered = [group for group in groups if not _is_our_group(layout, group)]
        if len(filtered) != len(groups):
            changed = True
        if filtered:
            hooks[event_name] = filtered
        else:
            hooks.pop(event_name, None)
    if changed:
        backup = backup_file(hooks_path)
        write_json_atomic(hooks_path, {"hooks": hooks})
        return {"changed": True, "path": str(hooks_path), "backup": str(backup) if backup else ""}
    return {"changed": False, "path": str(hooks_path), "backup": ""}


def deploy_runtime(project_root: Path, layout: RuntimeLayout) -> dict[str, Any]:
    ensure_layout(layout)
    src_package = project_root / "src" / "codex_hooks_monitor"
    if layout.package_root.exists():
        shutil.rmtree(layout.package_root)
    shutil.copytree(src_package, layout.package_root)
    settings = load_settings(layout)
    write_json_atomic(layout.settings_file, settings)
    return {"runtime_root": str(layout.root), "package_root": str(layout.package_root)}


def list_threads(search_term: str | None, limit: int) -> list[dict[str, Any]]:
    with CodexAppServerClient() as client:
        params: dict[str, Any] = {"limit": limit, "archived": False, "useStateDbOnly": True}
        if search_term:
            params["searchTerm"] = search_term
        return client.thread_list(**params).get("data", [])


def create_guardian_thread(layout: RuntimeLayout, cwd: str, title: str, model: str) -> dict[str, Any]:
    with CodexAppServerClient(timeout_seconds=60) as client:
        result = client.thread_start(cwd=cwd, model=model)
        thread_id = result["thread"]["id"]
        if title:
            client.thread_set_name(thread_id, title)
    settings = load_settings(layout)
    settings["guardian"]["thread_id"] = thread_id
    settings["guardian"]["title_hint"] = title
    save_settings(layout, settings)
    return {"thread_id": thread_id, "title_hint": title, "cwd": cwd, "model": model}


def register_guardian(layout: RuntimeLayout, thread_id: str, title_hint: str | None) -> dict[str, Any]:
    with CodexAppServerClient() as client:
        thread = client.thread_read(thread_id, include_turns=False).get("thread", {})
    settings = load_settings(layout)
    settings["guardian"]["thread_id"] = thread_id
    settings["guardian"]["title_hint"] = title_hint or thread.get("name") or thread.get("preview", "")[:80]
    save_settings(layout, settings)
    return {
        "thread_id": thread_id,
        "title_hint": settings["guardian"]["title_hint"],
        "cwd": thread.get("cwd"),
    }


def send_test_alert(layout: RuntimeLayout, thread_id: str | None, wait: bool) -> dict[str, Any]:
    settings = load_settings(layout)
    target_thread = thread_id or settings["guardian"]["thread_id"]
    if not target_thread:
        raise SystemExit("Guardian thread is not configured.")
    prompt = (
        "这是 hooks-monitor 的联通性测试消息。\n"
        "如果你能看到这条消息，请只回复：ACK hooks-monitor test。\n"
        "不要运行任何工具，不要改文件。\n"
    )
    with CodexAppServerClient(timeout_seconds=60) as client:
        client.thread_resume(target_thread)
        result = client.turn_start(
            target_thread,
            prompt,
            model=settings["guardian"].get("send_model") or None,
            effort=settings["guardian"].get("reasoning_effort") or None,
            wait_for_completion=wait,
            timeout_seconds=60,
        )
    return {"thread_id": target_thread, "turn_id": result["turn"]["id"], "waited": wait}


def interrupt_turn(thread_id: str, turn_id: str) -> dict[str, Any]:
    with CodexAppServerClient() as client:
        return client.turn_interrupt(thread_id, turn_id)


def kill_process(pid: int, scope: str) -> dict[str, Any]:
    try:
        proc = psutil.Process(pid)
    except (psutil.Error, OSError) as exc:
        return {"ok": False, "pid": pid, "scope": scope, "error": repr(exc)}

    targets = [proc]
    if scope == "process_tree":
        try:
            targets.extend(proc.children(recursive=True))
        except (psutil.Error, OSError):
            pass

    target_ids = []
    for item in targets:
        try:
            target_ids.append(item.pid)
        except (psutil.Error, OSError):
            continue

    errors: list[str] = []
    for item in reversed(targets):
        try:
            item.terminate()
        except (psutil.Error, OSError) as exc:
            errors.append(repr(exc))
    gone, alive = psutil.wait_procs(targets, timeout=5)
    for item in alive:
        try:
            item.kill()
        except (psutil.Error, OSError) as exc:
            errors.append(repr(exc))
    gone2, alive2 = psutil.wait_procs(alive, timeout=5)
    del gone, gone2
    return {
        "ok": len(alive2) == 0,
        "pid": pid,
        "scope": scope,
        "target_pids": target_ids,
        "alive_after": [item.pid for item in alive2 if item.is_running()],
        "errors": errors,
    }


def hooks_status(layout: RuntimeLayout) -> list[dict[str, Any]]:
    with CodexAppServerClient() as client:
        entries = client.hooks_list().get("data", [])
    rows: list[dict[str, Any]] = []
    runtime_fragment = str(layout.root).lower()
    for entry in entries:
        for hook in entry.get("hooks", []):
            source_path = str(hook.get("sourcePath", ""))
            command = str(hook.get("command") or "")
            if runtime_fragment in command.lower() or runtime_fragment in source_path.lower():
                rows.append(
                    {
                        "event_name": hook.get("eventName"),
                        "matcher": hook.get("matcher"),
                        "trust_status": hook.get("trustStatus"),
                        "enabled": hook.get("enabled"),
                        "source_path": source_path,
                    }
                )
    return rows


def show_status(layout: RuntimeLayout) -> dict[str, Any]:
    settings = load_settings(layout)
    action_mode = effective_action_mode(settings)
    guardian_enabled = guardian_delivery_enabled(settings)
    popup_enabled = user_popup_enabled(settings)
    if action_mode == "interrupt":
        last_requested_mode_profile = "interrupt"
    elif guardian_enabled:
        last_requested_mode_profile = "guardian"
    else:
        last_requested_mode_profile = "observe"
    pid = None
    pid_alive = False
    if layout.pid_file.exists():
        try:
            pid = int(layout.pid_file.read_text(encoding="utf-8").strip())
            pid_alive = psutil.pid_exists(pid)  # type: ignore[name-defined]
        except Exception:
            pid = None
    hooks = hooks_status(layout)
    enabled = bool(settings.get("enabled"))
    hooks_present = bool(hooks)
    all_hooks_trusted = hooks_present and all(
        str(item.get("trust_status") or "").lower() not in {"", "untrusted"} and bool(item.get("enabled", True))
        for item in hooks
    )
    if not enabled and not pid_alive and hooks_present and all_hooks_trusted:
        lifecycle_state = "prepared_idle"
    elif not enabled and not pid_alive and hooks_present:
        lifecycle_state = "hooks_installed_untrusted"
    elif not enabled and not pid_alive and not hooks_present:
        lifecycle_state = "fully_stopped"
    elif enabled and hooks_present and not all_hooks_trusted:
        lifecycle_state = "awaiting_hook_trust"
    elif enabled and pid_alive and hooks_present and all_hooks_trusted:
        lifecycle_state = "running"
    elif enabled and not pid_alive:
        lifecycle_state = "enabled_but_watchdog_stopped"
    elif enabled and pid_alive and not hooks_present:
        lifecycle_state = "enabled_but_hooks_missing"
    elif not enabled and (pid_alive or hooks_present):
        lifecycle_state = "stop_incomplete"
    else:
        lifecycle_state = "degraded"
    mode_profile = "stopped" if lifecycle_state == "fully_stopped" else last_requested_mode_profile
    return {
        "runtime_root": str(layout.root),
        "settings_file": str(layout.settings_file),
        "hooks_file": str(layout.hooks_file),
        "enabled": enabled,
        "lifecycle_state": lifecycle_state,
        "guardian_thread_id": settings["guardian"].get("thread_id"),
        "mode_profile": mode_profile,
        "last_requested_mode_profile": last_requested_mode_profile,
        "configured_action_mode": settings.get("actions", {}).get("mode"),
        "effective_action_mode": action_mode,
        "supported_action_modes": list(SUPPORTED_ACTION_MODES),
        "guardian_delivery_enabled": guardian_enabled,
        "user_popup_enabled": popup_enabled,
        "watchdog_pid": pid,
        "watchdog_pid_alive": pid_alive,
        "hooks": hooks,
    }


def quiesce_state(layout: RuntimeLayout) -> dict[str, Any]:
    ensure_layout(layout)
    state = load_json(
        layout.state_file,
        {
            "file_offsets": {},
            "open_commands": {},
            "alerts": {},
            "session_thread_cache": {},
            "last_cleanup_at": "",
        },
    )
    offsets = state.setdefault("file_offsets", {})
    for path in sorted(layout.events_dir.glob("events-*.jsonl")):
        try:
            offsets[str(path)] = path.stat().st_size
        except FileNotFoundError:
            continue
    cleared_open_commands = len(state.get("open_commands", {}))
    cleared_alerts = len(state.get("alerts", {}))
    state["open_commands"] = {}
    state["alerts"] = {}
    state["last_quiesced_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    write_json_atomic(layout.state_file, state)
    return {
        "state_file": str(layout.state_file),
        "cleared_open_commands": cleared_open_commands,
        "cleared_alerts": cleared_alerts,
        "tracked_event_files": len(offsets),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    deploy = sub.add_parser("deploy-runtime")
    deploy.add_argument("--project-root", required=True)
    deploy.add_argument("--runtime-root", required=True)

    enable = sub.add_parser("enable-hooks")
    enable.add_argument("--runtime-root", required=True)

    disable = sub.add_parser("disable-hooks")
    disable.add_argument("--runtime-root", required=True)

    status = sub.add_parser("status")
    status.add_argument("--runtime-root", required=True)

    quiesce = sub.add_parser("quiesce-state")
    quiesce.add_argument("--runtime-root", required=True)

    list_cmd = sub.add_parser("list-threads")
    list_cmd.add_argument("--search", default="")
    list_cmd.add_argument("--limit", type=int, default=20)

    create_guardian = sub.add_parser("create-guardian-thread")
    create_guardian.add_argument("--runtime-root", required=True)
    create_guardian.add_argument("--cwd", required=True)
    create_guardian.add_argument("--title", default="Hooks Guardian")
    create_guardian.add_argument("--model", default="gpt-5.4")

    register = sub.add_parser("register-guardian")
    register.add_argument("--runtime-root", required=True)
    register.add_argument("--thread-id", required=True)
    register.add_argument("--title-hint", default="")

    send = sub.add_parser("send-test-alert")
    send.add_argument("--runtime-root", required=True)
    send.add_argument("--thread-id", default="")
    send.add_argument("--wait", action="store_true")

    interrupt = sub.add_parser("interrupt")
    interrupt.add_argument("--runtime-root", required=False)
    interrupt.add_argument("--thread-id", required=True)
    interrupt.add_argument("--turn-id", required=True)

    kill_cmd = sub.add_parser("kill-process")
    kill_cmd.add_argument("--pid", required=True, type=int)
    kill_cmd.add_argument("--scope", choices=["process", "process_tree"], default="process")

    args = parser.parse_args()

    if args.cmd == "deploy-runtime":
        layout = RuntimeLayout(Path(args.runtime_root))
        result = deploy_runtime(Path(args.project_root), layout)
    elif args.cmd == "enable-hooks":
        result = enable_hooks(RuntimeLayout(Path(args.runtime_root)))
    elif args.cmd == "disable-hooks":
        result = disable_hooks(RuntimeLayout(Path(args.runtime_root)))
    elif args.cmd == "status":
        result = show_status(RuntimeLayout(Path(args.runtime_root)))
    elif args.cmd == "quiesce-state":
        result = quiesce_state(RuntimeLayout(Path(args.runtime_root)))
    elif args.cmd == "list-threads":
        result = list_threads(args.search or None, args.limit)
    elif args.cmd == "create-guardian-thread":
        result = create_guardian_thread(RuntimeLayout(Path(args.runtime_root)), args.cwd, args.title, args.model)
    elif args.cmd == "register-guardian":
        result = register_guardian(RuntimeLayout(Path(args.runtime_root)), args.thread_id, args.title_hint or None)
    elif args.cmd == "send-test-alert":
        result = send_test_alert(RuntimeLayout(Path(args.runtime_root)), args.thread_id or None, args.wait)
    elif args.cmd == "interrupt":
        result = interrupt_turn(args.thread_id, args.turn_id)
    elif args.cmd == "kill-process":
        result = kill_process(args.pid, args.scope)
    else:  # pragma: no cover
        raise SystemExit(f"Unsupported command: {args.cmd}")

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
