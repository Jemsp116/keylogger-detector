# Keylogger Detector

> Heuristic, host-based scanner that flags background processes behaving like
> keystroke-capture malware — the way an EDR agent triages, by scoring many
> signals rather than trusting one.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)

It is **read-only**: it never hooks the keyboard, injects into processes, or reads
another process's memory. It only inspects metadata the OS already exposes
(`psutil`, a single `EnumWindows` pass on Windows, `/proc` on Linux) and scores it.

---

## Why heuristic, not signature-based

You can't keep a hash list of every keylogger — most are one-off scripts or lightly
modified samples. What they have trouble hiding are their *behaviors*: reading the
raw input device, running headless from a temp folder, quietly appending to a log
file, persisting across reboots, phoning home. This tool scores those behaviors and
surfaces the processes where the evidence **corroborates**, so one weak signal never
raises an alarm on its own.

## How it works

Every process is scored across independent checks. Strong signals are worth a look on
their own; weak signals only matter when they stack or accompany a strong one.

| Signal | Points | Why |
|---|---|---|
| Process name matches a keylogger pattern (`keylog`, `keystroke`, `spykey`, `kbdhook`, …) | **+4** | Explicit intent in the name |
| **Linux:** open FD to a raw input device (`/dev/input/event*`, `/dev/uinput`) | **+5** | Directly reading the kernel keystroke stream — the strongest signal |
| Executable runs from a volatile/temp dir (`%TEMP%`, `Windows\Temp`, `/tmp`, `/dev/shm`, …) | **+3** | Where droppers execute from |
| Executable no longer exists on disk (deleted after launch) | **+3** | Classic anti-forensics |
| Open handle to a `.log`/`.txt`/`.dat` file **in a volatile/temp dir** | **+3** | Where captured keystrokes get written (`--deep` on Windows) |
| Process name contains a generic-suspicious token (`hook`, `spy`, `sniff`, `stealer`, `grabber`) | +2 | Suspicious but common in legit tools |
| Headless — no visible window | +1 | Keyloggers have no UI (but so do many services) |
| Headless **and** an established outbound connection | +2 | Plausible exfil channel |
| Registered for persistence (Run key / autostart / cron) | +2 | Wants to survive reboot |
| Lightweight footprint (≤3 threads, <25 MB RSS) | +1 | Consistent with a background hook |

Scores roll up into risk bands: **LOW 4–5 · MEDIUM 6–8 · HIGH 9+**, sorted worst-first.
See [docs/architecture.md](docs/architecture.md) for the full pipeline.

> **Corroboration in practice:** on the development machine the naive version of this
> scorer flagged **133 of ~300 processes** (VS Code scored 79 — each of its ~25 open
> `.log` handles added +3). The corroboration model flags **2**, both explainable.

## Install

```bash
pip install -r requirements.txt
```

Only dependency is `psutil`.

## Usage

```bash
python keylogger_detector.py                    # quick scan (score >= 4)
python keylogger_detector.py --deep             # also inspect open handles (Windows: slower)
python keylogger_detector.py --min-score 2      # widen the net
python keylogger_detector.py --watch 30         # rescan every 30 seconds
python keylogger_detector.py --deep --json report.json
```

On Linux, run with `sudo` — without root, `/proc/*/fd` is unreadable and you lose the
raw-input-device check, which is the strongest signal there.

## Sample output

```
Scan @ 2026-08-21T09:14:05 — 1 flagged process(es) (platform: Windows, min-score 4)

PID     RISK    SCORE  PROCESS                     USER
--------------------------------------------------------------------------
6840    HIGH    13     winkeylog.exe               DESKTOP\me

Details:

PID 6840 — winkeylog.exe [HIGH, score 13]
  exe: C:\Users\me\AppData\Local\Temp\winkeylog.exe
  [+4] Process name matches keylogger pattern 'key\s*log'
  [+3] Executable runs from a volatile/temp directory (C:\Users\me\AppData\Local\Temp\winkeylog.exe)
  [+3] Open handle to a log-like file in a volatile/temp location (C:\Users\me\AppData\Local\Temp\keys.log)
  [+1] Runs without a visible window (headless/background)
  [+2] Headless process with an established outbound connection (203.0.113.9:443)
```

A fuller machine-readable example is in [examples/sample_report.json](examples/sample_report.json)
(illustrative — a malicious HIGH detection alongside a benign installer that correctly
lands at LOW, the kind of pair an analyst triages).

## Try it safely

`examples/benign_fake_keylogger.py` is a **safe, non-capturing** fixture. It installs no
keyboard hook and reads nothing you type — it only exhibits the harmless side effects a
keylogger tends to have (a headless process holding an open handle to a temp log file),
so you can watch the detector flag it.

```bash
# terminal 1
python examples/benign_fake_keylogger.py

# terminal 2
python keylogger_detector.py --deep --min-score 4
# ...then stop the fixture with Ctrl-C
```

## Platform support

| Platform | Status | Notes |
|---|---|---|
| Linux | ✅ Full | Raw input-device FD detection (strongest signal), autostart/cron persistence, cheap open-files. Run as root. |
| Windows | ✅ Good | Hidden-window detection, `Run`-key persistence, temp-exe / temp-logfile. The deep handle scan is slow, so it's opt-in via `--deep`. |
| macOS | ⚠️ Partial | Name/path, temp-logfile, and footprint signals only; no window map or raw-input check. |

## Limitations

These are behavioral heuristics over user-space metadata — a **detection surface, not a
guarantee**:

- **Kernel-mode keyloggers** (driver / filter) are invisible to a user-space scanner.
- A Windows **`SetWindowsHookEx`** low-level hook that never loads through an obvious DLL
  and writes nothing to disk can dodge every check here.
- Detection is **best-effort without elevated privileges** — many processes' file handles
  and connections are unreadable as a normal user.
- Heuristics mean **false positives** (installers and updaters legitimately run from
  `%TEMP%`) and **false negatives** (a well-behaved logger that only buffers in memory and
  exfiltrates rarely). Treat output as triage leads, not verdicts.

## Roadmap

- Windows ETW-based low-level-hook detection (`SetWindowsHookEx` / raw input registration)
- YARA rule matching on flagged executables
- Faster deep scan via a single `NtQuerySystemInformation` handle enumeration
- Baseline/allowlist mode to suppress known-good processes across scans

## Development

```bash
pip install psutil pytest flake8
python -m pytest tests/ -q      # unit tests over the scoring functions
flake8 keylogger_detector.py tests/
```

Tests exercise the pure heuristics with synthetic process metadata, so they're fast and
deterministic and don't depend on what's running. CI runs lint + tests on every push
(`.github/workflows/lint.yml`).

## License

MIT — see [LICENSE](LICENSE). Update the copyright line with your name before publishing.
