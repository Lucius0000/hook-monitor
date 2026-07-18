from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Any


class AppServerError(RuntimeError):
    pass


def resolve_codex_exe() -> str:
    env_path = Path(str((__import__("os")).environ.get("CODEX_CLI_PATH", "")))
    if env_path.is_file():
        return str(env_path)

    local_bin = Path.home() / "AppData" / "Local" / "OpenAI" / "Codex" / "bin"
    if local_bin.exists():
        matches = sorted(local_bin.rglob("codex.exe"), key=lambda p: p.stat().st_mtime, reverse=True)
        if matches:
            return str(matches[0])
    raise FileNotFoundError("Could not locate codex.exe under LocalAppData.")


class CodexAppServerClient:
    def __init__(self, timeout_seconds: int = 30) -> None:
        self.timeout_seconds = timeout_seconds
        self._stderr_lines: Queue[str] = Queue()
        self._next_id = 1
        self._proc = subprocess.Popen(
            [resolve_codex_exe(), "app-server", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        if self._proc.stdin is None or self._proc.stdout is None or self._proc.stderr is None:
            raise AppServerError("Failed to start codex app-server stdio transport.")
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        self.initialize()

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.kill()

    def __enter__(self) -> "CodexAppServerClient":
        return self

    def __exit__(self, *_exc_info) -> None:
        self.close()

    def _drain_stderr(self) -> None:
        assert self._proc.stderr is not None
        for line in self._proc.stderr:
            self._stderr_lines.put(line.rstrip())

    def _read_message(self, timeout_seconds: int | None = None) -> dict[str, Any]:
        deadline = time.time() + (timeout_seconds or self.timeout_seconds)
        assert self._proc.stdout is not None
        while time.time() < deadline:
            if self._proc.poll() is not None:
                raise AppServerError(f"app-server exited early: {self._proc.returncode}")
            line = self._proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError as exc:
                raise AppServerError(f"Invalid app-server JSON line: {line!r}") from exc
        raise AppServerError("Timed out waiting for app-server response.")

    def request(self, method: str, params: dict[str, Any] | None = None, timeout_seconds: int | None = None) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        assert self._proc.stdin is not None
        self._proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self._proc.stdin.flush()

        while True:
            msg = self._read_message(timeout_seconds=timeout_seconds)
            if msg.get("id") != request_id:
                continue
            if "error" in msg:
                raise AppServerError(json.dumps(msg["error"], ensure_ascii=False))
            return msg["result"]

    def wait_for_notification(self, method: str, *, matcher: callable | None = None, timeout_seconds: int | None = None) -> dict[str, Any]:
        deadline = time.time() + (timeout_seconds or self.timeout_seconds)
        while time.time() < deadline:
            msg = self._read_message(timeout_seconds=timeout_seconds)
            if msg.get("method") != method:
                continue
            params = msg.get("params", {})
            if matcher is None or matcher(params):
                return params
        raise AppServerError(f"Timed out waiting for notification {method}.")

    def initialize(self) -> dict[str, Any]:
        return self.request(
            "initialize",
            {
                "clientInfo": {"name": "hooks-monitor", "version": "0.1"},
                "capabilities": {
                    "experimentalApi": False,
                    "requestAttestation": False,
                },
            },
        )

    def thread_list(self, **params: Any) -> dict[str, Any]:
        return self.request("thread/list", params)

    def thread_read(self, thread_id: str, include_turns: bool = True) -> dict[str, Any]:
        return self.request("thread/read", {"threadId": thread_id, "includeTurns": include_turns})

    def thread_resume(self, thread_id: str, **overrides: Any) -> dict[str, Any]:
        params = {"threadId": thread_id}
        params.update({key: value for key, value in overrides.items() if value is not None})
        return self.request("thread/resume", params)

    def thread_start(self, **params: Any) -> dict[str, Any]:
        return self.request("thread/start", params)

    def thread_set_name(self, thread_id: str, name: str) -> dict[str, Any]:
        return self.request("thread/name/set", {"threadId": thread_id, "name": name})

    def hooks_list(self) -> dict[str, Any]:
        return self.request("hooks/list", {})

    def turn_start(
        self,
        thread_id: str,
        text: str,
        *,
        model: str | None = None,
        effort: str | None = None,
        wait_for_completion: bool = False,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "threadId": thread_id,
            "input": [{"type": "text", "text": text, "text_elements": []}],
        }
        if model:
            params["model"] = model
        if effort:
            params["effort"] = effort
        result = self.request("turn/start", params, timeout_seconds=timeout_seconds)
        if wait_for_completion:
            turn_id = result["turn"]["id"]
            self.wait_for_notification(
                "turn/completed",
                matcher=lambda data: data.get("threadId") == thread_id and data.get("turn", {}).get("id") == turn_id,
                timeout_seconds=timeout_seconds or self.timeout_seconds,
            )
        return result

    def turn_interrupt(self, thread_id: str, turn_id: str) -> dict[str, Any]:
        return self.request("turn/interrupt", {"threadId": thread_id, "turnId": turn_id})

