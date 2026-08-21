# Keylogger Detector

> Heuristic, host-based scanner that flags background processes behaving like keystroke-capture malware — the way an EDR agent triages, by scoring many corroborating signals rather than trusting one.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![Status](https://img.shields.io/badge/status-active-brightgreen)
[![Download](https://img.shields.io/badge/download-Windows%20.exe-0078d4)](https://github.com/Jemsp116/keylogger-detector/releases/latest)

It is **read-only**: it never hooks the keyboard, injects into processes, or reads another process's memory. It only inspects metadata the OS already exposes — `psutil`, a single `EnumWindows` pass on Windows, `/proc` on Linux — and scores it.

---

## Table of Contents

- [Why heuristic, not signature-based](#why-heuristic-not-signature-based)
- [How it works](#how-it-works)
- [Download & run (Windows .exe)](#download--run-windows-exe)
- [Install](#install)
- [Usage](#usage)
- [Sample output](#sample-output)
- [Try it safely](#try-it-safely)
- [Platform support](#platform-support)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Development](#development)
- [License](#license)

---

## Why heuristic, not signature-based

You can't maintain a hash list of every keylogger — most are one-off scripts or lightly modified samples. What they struggle to hide is *behavior*: reading the raw input device, running headless from a temp folder, quietly appending to a log file, persisting across reboots, phoning home.

This tool scores those behaviors and surfaces only the processes where the evidence **corroborates** — so one weak signal never raises an alarm on its own.

## How it works

Every running process is scored across independent checks. Strong signals stand on their own; weak signals only matter when they stack or accompany a strong one.

| Signal | Points | Why it matters |
|---|---|---|
| Process name matches a keylogger pattern (`keylog`, `keystroke`, `spykey`, `kbdhook`, …) | **+4** | Explicit intent in the name |
| **Linux:** open FD to a raw input device (`/dev/input/event*`, `/dev/uinput`) | **+5** | Directly reading the kernel keystroke stream — the strongest signal available |
| Executable runs from a volatile/temp directory (`%TEMP%`, `Windows\Temp`, `/tmp`, `/dev/shm`, …) | **+3** | Where droppers execute from |
| Executable no longer exists on disk (deleted after launch) | **+3** | Classic anti-forensics |
| Open handle to a `.log`/`.txt`/`.dat` file in a volatile/temp directory | **+3** | Where captured keystrokes typically get written (`--deep` on Windows) |
| Process name contains a generic-suspicious token (`hook`, `spy`, `sniff`, `stealer`, `grabber`) | +2 | Suspicious, but also common in legitimate tools |
| Headless — no visible window | +1 | Keyloggers have no UI (but so do many legitimate services) |
| Headless **and** an established outbound connection | +2 | Plausible exfiltration channel |
| Registered for persistence (Run key / autostart / cron) | +2 | Wants to survive a reboot |
| Lightweight footprint (≤3 threads, <25 MB RSS) | +1 | Consistent with a quiet background hook |

Scores roll up into risk bands — **LOW 4–5 · MEDIUM 6–8 · HIGH 9+** — sorted worst-first. Full pipeline details in [docs/architecture.md](docs/architecture.md).

> **Corroboration in practice:** on the development machine, a naive single-signal version of this scorer flagged **133 of ~300 processes** (VS Code alone scored 79 — each of its ~25 open `.log` handles added +3). The corroboration model flags **2**, both explainable.

The detector also never reports **itself** — the released binary is called `keylogger-detector.exe`, which matches its own `keylog` name pattern. That exclusion keys off process *identity* (our PID, plus our executable path in the frozen build), never off the name, so a hostile binary can't hide by calling itself `keylogger-detector.exe`.

## Download & run (Windows .exe)

No Python needed — grab the latest `keylogger-detector.exe` from the [Releases page](https://github.com/Jemsp116/keylogger-detector/releases/latest).

**There is no installer, and nothing to set up.** The build is a PyInstaller `--onefile` binary: the CPython interpreter, the standard library, and psutil's compiled extension are all packed inside the single `.exe`. Copy that one file to any machine below and double-click it — it leaves no installation behind, and deleting the file uninstalls it completely.

| Requirement | Detail |
|---|---|
| OS | Windows 10 or 11 (x64). Also runs on Windows on ARM via x64 emulation. |
| Architecture | 64-bit. Built for x86-64; there is no 32-bit build. |
| Python | **Not required** on the target machine. |
| Runtime libs | None to install — the MSVC runtime is bundled. |
| Disk | ~7.3 MB. Unpacks to a temp folder at each launch, which is why the first start takes a second or two. |

**SmartScreen warning.** Windows will show "Windows protected your PC" the first time you run it — expected for an unsigned indie binary (a code-signing certificate costs a few hundred dollars a year, which this project doesn't have). To proceed: click **More info → Run anyway**. Two honest alternatives if you'd rather not: verify the SHA-256 published with each release, or skip the binary and [run from source](#install).

```bash
certutil -hashfile keylogger-detector.exe SHA256
```

Your antivirus may also flag it. A single-file executable that enumerates every process on the machine looks, to a scanner, a lot like the thing it's built to catch — the irony is unavoidable. The source is right here in this repo if you want to read it before trusting it.

**Admin rights / UAC prompt.** The exe embeds a `requireAdministrator` manifest, so Windows shows its normal elevation consent prompt at launch. That is deliberate, and nothing is auto-elevated behind your back — decline the prompt and the program simply doesn't start. Elevation is what lets the detector:

- inspect **open file handles** of processes owned by other users (`--deep`) — the signal that finds keystroke logs in `%TEMP%`
- read the **`HKLM\...\Run`** persistence key and resolve executable paths for protected processes

Run it unelevated and it still works, but those checks quietly return less.

**Quick start:**

```
keylogger-detector.exe                  # quick scan (score >= 4)
keylogger-detector.exe --deep           # also inspect open handles (slower)
keylogger-detector.exe --json out.json  # write the full report as JSON
keylogger-detector.exe --version
```

Double-clicking is fine: an elevated process always gets a fresh console window, so the exe waits for **Enter** before closing rather than letting the report flash past. Launched from an existing terminal it exits immediately instead, leaving piping and scripting unaffected (`--no-pause` forces that behaviour).

## Install

Prefer running from source, or on Linux/macOS:

```bash
pip install -r requirements.txt
```

Only dependency: `psutil`.

## Usage

```bash
python keylogger_detector.py                      # quick scan (score >= 4)
python keylogger_detector.py --deep                # also inspect open handles (Windows: slower)
python keylogger_detector.py --min-score 2          # widen the net
python keylogger_detector.py --watch 30             # rescan every 30 seconds
python keylogger_detector.py --top 20               # more below-threshold context
python keylogger_detector.py --quiet                # findings only, no banner (for scripts)
python keylogger_detector.py --deep --json report.json
```

On Linux, run with `sudo` — without root, `/proc/*/fd` is unreadable and you lose the raw-input-device check, which is the strongest signal on that platform.

**Exit codes:** `0` = nothing flagged, `1` = at least one process flagged. Handy in a scheduled task:

```bash
python keylogger_detector.py --quiet || echo "something was flagged - investigate"
```

## Sample output

Every run reports what it inspected, so a clean result is visibly a *completed scan* rather than an empty screen:

```
==========================================================================
  Keylogger Detector 1.1.0  -  heuristic process scan
==========================================================================
  Host        : DESKTOP-ABC (Windows 11)
  Started     : 2026-08-21 14:07:25
  Mode        : QUICK (add --deep to inspect open file handles)
  Privileges  : standard user - limited visibility (run as administrator to inspect all processes)
  Threshold   : report score >= 4   (LOW 4-5 / MEDIUM 6-8 / HIGH 9+)
--------------------------------------------------------------------------
Scanning running processes ...

  Inspected 273 running processes in 2.9s
  3 could only be read partially (protected or owned by another user)
  Note: open file handles were NOT inspected in quick mode (use --deep for that signal)

RESULT: CLEAN - no process reached a score of 4.
        Nothing on this system looks like a keylogger by these heuristics.

  Highest scores seen, all BELOW the threshold of 4 - context, NOT alerts:

    SCORE  PID     PROCESS                   SIGNALS
    ------------------------------------------------------------------
    3      6060    svchost.exe               Runs without a visible window; Headless process with an established outbound connection
    3      6508    msedge.exe                Runs without a visible window; Registered in a Windows Run autostart key
    ... and 265 more scoring 1-3 (--top 268 to list them all)

  Reminder: these are behavioural heuristics, not proof of absence.
  A kernel-mode or in-memory-only logger can evade every check here.
```

The near-miss table is deliberately labelled *not alerts*: it exists so you can see the scan
did real work and how far the closest process was from the threshold. When something **is**
flagged, the report leads with the verdict and then itemises the evidence per process:

```
RESULT: 1 process(es) flagged (1 HIGH) at score >= 4.
        Treat these as leads to triage, not verdicts.

PID     RISK    SCORE  PROCESS                     USER
--------------------------------------------------------------------------
6840    HIGH    13     winkeylog.exe               DESKTOP\me

Why each was flagged:

  PID 6840 - winkeylog.exe [HIGH, score 13]
    exe: C:\Users\me\AppData\Local\Temp\winkeylog.exe
    [+4] Process name matches keylogger pattern 'key\s*log'
    [+3] Executable runs from a volatile/temp directory (C:\Users\me\AppData\Local\Temp\winkeylog.exe)
    [+3] Open handle to a log-like file in a volatile/temp location (C:\Users\me\AppData\Local\Temp\keys.log)
    [+1] Runs without a visible window (headless/background)
    [+2] Headless process with an established outbound connection (203.0.113.9:443)
```

A fuller machine-readable example — a malicious HIGH detection alongside a benign installer that correctly lands at LOW — is in [examples/sample_report.json](examples/sample_report.json).

## Try it safely

`examples/benign_fake_keylogger.py` is a **safe, non-capturing** fixture. It installs no keyboard hook and reads nothing you type — it only reproduces the harmless side effects a keylogger tends to have (a headless process holding an open handle to a temp log file), so you can watch the detector flag it without running anything malicious.

```bash
# terminal 1
python examples/benign_fake_keylogger.py

# terminal 2
python keylogger_detector.py --deep --min-score 4

# then stop the fixture with Ctrl-C
```

## Platform support

| Platform | Status | Notes |
|---|---|---|
| Linux | ✅ Full | Raw input-device FD detection (strongest signal), autostart/cron persistence, cheap open-files check. Run as root. |
| Windows | ✅ Good | Hidden-window detection, `Run`-key persistence, temp-exe / temp-logfile checks. Deep handle scan is slower, so it's opt-in via `--deep`. |
| macOS | ⚠️ Partial | Name/path, temp-logfile, and footprint signals only — no window map or raw-input check. |

## Limitations

These are behavioral heuristics over user-space metadata — a **detection surface, not a guarantee**:

- **Kernel-mode keyloggers** (driver / filter) are invisible to a user-space scanner.
- A Windows **`SetWindowsHookEx`** low-level hook that never loads through an obvious DLL and writes nothing to disk can dodge every check here.
- Detection is **best-effort without elevated privileges** — many processes' file handles and connections are unreadable as a normal user.
- Heuristics mean **false positives** (installers/updaters legitimately running from `%TEMP%`) and **false negatives** (a well-behaved logger that only buffers in memory and exfiltrates rarely).

Treat every result as a triage lead, not a verdict.

## Roadmap

- [ ] Windows ETW-based low-level-hook detection (`SetWindowsHookEx` / raw input registration)
- [ ] YARA rule matching on flagged executables
- [ ] Faster deep scan via a single `NtQuerySystemInformation` handle enumeration
- [ ] Baseline/allowlist mode to suppress known-good processes across scans

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q                    # unit tests over the scoring functions
flake8 keylogger_detector.py build.py tests/
```

Tests exercise the pure heuristics against synthetic process metadata, so they're fast, deterministic, and don't depend on what happens to be running. CI runs lint + tests on every push (`.github/workflows/lint.yml`).

### Building the Windows .exe

```bash
python build.py                # release build -> dist/keylogger-detector.exe
python build.py --no-uac       # local test build, no elevation prompt
python build.py --resources-only
```

`build.py` drives PyInstaller with `--onefile --console`, embeds a Windows version resource (product name, version, description) generated from `__version__`, and embeds the `requireAdministrator` manifest. It prints the exe's size and SHA-256 when it finishes.

To brand the binary, drop a 256×256 multi-resolution icon at **`assets/icon.ico`** — `build.py` picks it up automatically, and builds fine without one.

> The `--no-uac` build exists because an elevated exe opens its own console window, so a normal shell can't capture its stdout. Use it for local output testing; never ship it.

### Cutting a release

The version lives in exactly one place — `__version__` in `keylogger_detector.py`. `build.py` reads it, so bump it there first and everything else follows.

```bash
# 1. Gate: lint and tests must pass, working tree must be clean
python -m flake8 keylogger_detector.py tests/ examples/ build.py
python -m pytest tests/ -q
git status --short

# 2. Build the release binary (embeds the UAC manifest and version resource)
python build.py

# 3. Sanity-check the artifact you are about to publish
dist\keylogger-detector.exe --version
certutil -hashfile dist\keylogger-detector.exe SHA256

# 4. Tag the commit and push the tag
git tag -a v1.1.0 -m "keylogger-detector v1.1.0"
git push origin main
git push origin v1.1.0
```

Then attach the binary to the tag. Never commit `dist/` — the exe is a release asset, not source (it's in `.gitignore` for that reason).

**With the GitHub web UI:** open [Releases → Draft a new release](https://github.com/Jemsp116/keylogger-detector/releases/new), choose the existing tag `v1.1.0`, drag `dist/keylogger-detector.exe` into the *Attach binaries* box, paste the SHA-256 from step 3 into the notes, then **Publish release**.

**With the GitHub CLI** (`winget install GitHub.cli`, then `gh auth login`):

```bash
gh release create v1.1.0 dist/keylogger-detector.exe \
  --title "keylogger-detector v1.1.0" \
  --notes "Windows x64 build. No Python required. Unsigned - SmartScreen will warn on first run.

SHA-256: <paste from step 3>"
```

Always publish the hash alongside the binary: it's the only way a downloader can verify an unsigned executable.

Contributions welcome — open an issue for new heuristic ideas or platform coverage before sending a PR.

## License

MIT — see [LICENSE](LICENSE).
