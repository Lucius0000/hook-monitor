# Hook Monitor for Codex

A Windows watchdog for detecting long-running or potentially stuck local Codex tool calls without continuously invoking a model.

The design separates fast event capture from slow inspection:

```text
Codex user hooks -> lightweight JSONL event logger -> local watchdog
                                                     |-> desktop alert
                                                     `-> optional guardian task
```

Hooks only record lifecycle events. The watchdog checks open commands at a low frequency, combines timing, log freshness, process, CPU, GPU, stderr, and Codex task state, and escalates only when configured thresholds are met.

## Highlights

- Four user-level hooks: `SessionStart`, `PreToolUse`, `PostToolUse`, and `Stop`.
- No model calls during normal hook logging or watchdog polling.
- 10-minute multi-signal detection plus a 20-minute hard-timeout review threshold.
- Three operating modes: local observation, guardian notification, and guardian-gated interruption.
- Per-day JSONL logs with retention for event and alert files.
- User-level Windows shortcuts, startup recovery task, and reversible integration removal.
- Existing unrelated Codex hooks are preserved when this project adds or removes its own definitions.

## Safety model

`observe` is the safest mode and never contacts a guardian task. `guardian` sends structured context to a fixed task but does not automatically stop a process. `interrupt` is intentionally high risk: a process is terminated only after the guardian returns a strict `decision=kill` response and executes the generated, PID-scoped command.

Start with `observe`. Review the thresholds and code before enabling `guardian` or `interrupt`.

## Requirements

- Windows 10 or 11.
- ChatGPT/Codex desktop app and Codex CLI installed under the current user.
- PowerShell 7 (`pwsh.exe`).
- Python 3.11+ available as `python.exe` on `PATH`.
- Python dependency: `python -m pip install -r requirements.txt`.

The project uses local Codex app-server interfaces whose behavior may change between Codex releases. Hook trust still requires interactive review in the Codex CLI.

## Install and trust hooks

```powershell
python -m pip install -r requirements.txt
.\scripts\install.ps1
.\scripts\review-hooks.ps1
```

In the opened Codex CLI, run `/hooks`, review the four entries, and trust them. The runtime is deployed to `%USERPROFILE%\.codex\hooks-monitor`; hook definitions are merged into `%USERPROFILE%\.codex\hooks.json` with a timestamped backup before changes.

## Run

Start with local-only observation:

```powershell
.\scripts\start-watchdog.ps1 -Mode observe
```

Other modes require a fixed guardian task:

```powershell
.\scripts\create-guardian-thread.ps1
.\scripts\start-watchdog.ps1 -Mode guardian
```

Register an existing guardian instead:

```powershell
.\scripts\register-guardian-thread.ps1 -ThreadId <THREAD_ID>
```

Use interruption only after validating the guardian flow:

```powershell
.\scripts\start-watchdog.ps1 -Mode interrupt
```

## Operate and remove

```powershell
.\scripts\status.ps1
.\scripts\stop-watchdog.ps1
.\scripts\remove-hooks.ps1
```

- `stop-watchdog.ps1` stops monitoring but keeps the hook definitions and their trust state.
- `remove-hooks.ps1` stops monitoring and removes only this project's four hook groups.
- `install-windows-integration.ps1` adds one desktop/Start Menu management entry and a user-logon recovery task.
- `remove-windows-integration.ps1` removes that Windows shell integration without deleting runtime state or Codex hooks.

## Tests

Run the safe local smoke suite first:

```powershell
python .\tests\smoke_verify.py
python -m compileall .\src
```

`tests/live_verify_function_call_watchdog.py` performs a real end-to-end Codex/watchdog exercise and temporarily changes runtime thresholds. Read it before running it on an active environment.

## Runtime data

Runtime state is stored under `%USERPROFILE%\.codex\hooks-monitor`:

- `events/`: hook event JSONL, retained for 14 days by default.
- `alerts/`: escalated alert JSONL, retained for 30 days by default.
- `state/`: open-command and watchdog state.
- `logs/`: watchdog stdout, stderr, and runtime errors.
- `settings.json`: mode, thresholds, guardian reference, and retention settings.

Runtime data, guardian IDs, user paths, process IDs, and local logs are not included in this repository.

## Project layout

```text
src/codex_hooks_monitor/  Logger, watchdog, Codex client, and admin commands
scripts/                  Install, trust, start, stop, status, and Windows integration
tests/                    Smoke and opt-in live verification
templates/                Redacted hook shape example
```
