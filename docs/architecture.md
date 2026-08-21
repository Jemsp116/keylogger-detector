# Architecture

`keylogger_detector.py` is a single-file, read-only host scanner. It never hooks
input, injects into processes, or reads another process's memory — it only reads
metadata the OS already exposes (via `psutil`, one `EnumWindows` pass on Windows,
and `/proc` on Linux) and scores it.

## Pipeline

```
                       ┌─────────────────────────────┐
   psutil.process_iter │  enumerate processes         │
        + one          │  (pid, name, exe, user, …)   │
     EnumWindows pass   └──────────────┬──────────────┘
   (visible-window PIDs)               │
                                        ▼
                        ┌──────────────────────────────┐
                        │ per process → run heuristics  │
                        │                                │
   STRONG (stand out):  │  name (explicit)        +4     │
                        │  raw input FD (Linux)   +5     │
                        │  exe in temp/volatile   +3     │
                        │  exe deleted from disk  +3     │
                        │  log file in temp       +3     │  (--deep on Windows)
                        │                                │
   WEAK (corroborate):  │  name (generic)         +2     │
                        │  headless                +1    │
                        │  headless + exfil conn   +2    │
                        │  persistence entry       +2    │
                        │  lightweight footprint   +1    │
                        └──────────────┬───────────────┘
                                        ▼
                        ┌──────────────────────────────┐
                        │ sum → risk band               │
                        │   LOW 4–5 · MEDIUM 6–8 · HIGH 9+
                        │ filter ≥ min-score, sort desc  │
                        └──────────────────────────────┘
```

## Design principle: require corroboration

No single **weak** signal can cross the default threshold (4). Weak signals only
matter when they stack or accompany a strong one. This is what keeps a clean
machine at ~0 flagged instead of drowning the analyst in every headless service
and every app that keeps a log file.

Concretely, on the development machine the pre-rewrite scorer flagged **133/≈300**
processes (VS Code scored 79 because each of its ~25 open `.log` handles added
+3). The corroboration model flags **2**, both explainable (an installer running
from `%TEMP%`).

## Why `--deep` exists (Windows)

The "open handle to a log file in a temp directory" signal needs
`psutil.Process.open_files()`. On Windows that call re-enumerates the entire
system handle table per process and does not release the GIL, so it costs ~18s
across a full process list and cannot be parallelized with threads (measured).
It is therefore opt-in via `--deep`. On Linux/macOS the `/proc`-backed call is
cheap and always runs.

## Detection surface, not a guarantee

These are behavioral heuristics over user-space metadata. A kernel-mode logger,
or a Windows `SetWindowsHookEx` low-level hook that never loads through an obvious
DLL and writes nothing to disk, can evade every check here. See the README's
*Limitations* section.
