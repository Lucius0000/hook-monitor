from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from codex_hooks_monitor.common import RuntimeLayout, append_jsonl, ensure_layout, load_settings, utc_now_iso


def shorten(value: str | None, limit: int = 500) -> str | None:
    if not value:
        return value
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def build_event_record(payload: dict[str, Any]) -> dict[str, Any]:
    tool_input = payload.get("tool_input")
    return {
        "observed_at": utc_now_iso(),
        "hook_event_name": payload.get("hook_event_name"),
        "session_id": payload.get("session_id"),
        "turn_id": payload.get("turn_id"),
        "cwd": payload.get("cwd"),
        "transcript_path": payload.get("transcript_path"),
        "model": payload.get("model"),
        "permission_mode": payload.get("permission_mode"),
        "source": payload.get("source"),
        "tool_name": payload.get("tool_name"),
        "tool_use_id": payload.get("tool_use_id"),
        "tool_input": tool_input,
        "tool_input_command": tool_input.get("command") if isinstance(tool_input, dict) else None,
        "stop_hook_active": payload.get("stop_hook_active"),
        "last_assistant_message_excerpt": shorten(payload.get("last_assistant_message")),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", required=True)
    args = parser.parse_args()

    payload = json.load(sys.stdin)
    layout = RuntimeLayout(Path(args.runtime_root))
    ensure_layout(layout)
    settings = load_settings(layout)
    if not settings.get("enabled", False):
        return 0

    record = build_event_record(payload)
    day = utc_now_iso()[:10]
    append_jsonl(layout.events_dir / f"events-{day}.jsonl", record)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
