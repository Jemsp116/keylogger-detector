#!/usr/bin/env python3
"""
Keylogger Detector
-------------------
Heuristic, host-based scanner that flags processes exhibiting behavior
commonly associated with keyloggers / keystroke-capture malware.

No single signal is proof of a keylogger. This scores processes across
several signals (like an EDR heuristic engine) and surfaces only the ones
where evidence *corroborates* — a lone weak signal never crosses the
reporting threshold. It does NOT intercept keystrokes, inject into
processes, or read other processes' memory; it only reads process
metadata the OS already exposes (via psutil + a single EnumWindows pass).

Tech: Python 3, psutil, OS-level filesystem/registry introspection.

Usage:
    python keylogger_detector.py                  # quick scan (score >= 4)
    python keylogger_detector.py --deep            # also inspect open file handles
    python keylogger_detector.py --min-score 2     # widen the net
    python keylogger_detector.py --watch 30        # rescan every 30s
    python keylogger_detector.py --json out.json   # dump full report
    python keylogger_detector.py --top 10          # show more near-miss context
    python keylogger_detector.py --quiet           # findings only, no banner

Every run prints what it inspected (process count, timing, privilege level)
and the highest scores it saw, so a clean result is visibly a completed scan
rather than an empty screen.
"""

import argparse
import json
import os
import platform
import re
import sys
import time
from datetime import datetime

try:
    import psutil
except ImportError:
    sys.exit("psutil is required: pip install psutil")

__version__ = "1.1.0"

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MAC = platform.system() == "Darwin"
IS_FROZEN = getattr(sys, "frozen", False)


def configure_stdout():
    """Make stdout tolerate any console code page.

    The released .exe runs on machines we do not control: a fresh Windows
    console is typically code page 437/850/932, and Python then encodes stdout
    as cp1252/cp932. Printing a character the code page lacks raises
    UnicodeEncodeError mid-report -- i.e. the tool would crash on someone
    else's computer while printing its own findings. Process names and file
    paths come from the OS and may contain anything at all.

    So: ask for UTF-8, and fall back to replacing unencodable characters. The
    tool's own output is deliberately plain ASCII (see ASCII-only banner /
    table drawing below); this protects the parts that echo OS-supplied text.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            # Python < 3.7, or a stream that is not reconfigurable (piped,
            # redirected to a file, or absent under a GUI host). Printing
            # still works; only exotic characters degrade.
            pass


# ---------------------------------------------------------------------------
# Heuristic signal definitions
# ---------------------------------------------------------------------------

# Names that are essentially only chosen by keystroke-capture tooling.
EXPLICIT_KEYLOGGER_PATTERNS = [
    r"key\s*log", r"keystroke", r"logkeys", r"spykey",
    r"kbd\s*hook", r"key\s*capture", r"key\s*grab", r"key\s*sniff",
    r"\bklog\b", r"pykeylog",
]

# Names that are suspicious but also appear in legitimate software, so they
# only earn a small, corroborating score — never enough to flag on their own.
# Substring matches (they cannot cross the threshold alone, so a broad net is
# safe here and catches variants like keyhook / nethook / winhook).
GENERIC_SUSPICIOUS_PATTERNS = [
    r"hook", r"spy", r"sniff", r"stealer", r"grabber",
]

# Volatile / world-writable locations where droppers and captured-key logs
# actually land. Deliberately tight: normal apps live in Program Files and in
# their own AppData\<Vendor> folders, NOT in these.
VOLATILE_DIR_PATTERNS = [
    r"\\appdata\\local\\temp\\",
    r"\\windows\\temp\\",
    r"^[a-z]:\\temp\\",
    r"\\programdata\\temp\\",
    r"/tmp/",
    r"/var/tmp/",
    r"/dev/shm/",
    r"/run/user/",
]

LOG_FILE_EXT = (".log", ".txt", ".dat", ".keys")

# Linux compositors / input stack that legitimately hold /dev/input handles.
KNOWN_INPUT_HOLDERS = {
    "xorg", "x", "wayland", "systemd-logind", "gnome-shell",
    "kwin_wayland", "kwin_x11", "libinput", "weston", "sway",
    "mutter", "ibus-daemon",
}

# Windows-only optional dependency for the persistence check.
winreg = None
if IS_WINDOWS:
    try:
        import winreg  # noqa: F401
    except ImportError:
        winreg = None


def score_add(reasons, score, points, message):
    reasons.append(f"[+{points}] {message}")
    return score + points


def is_volatile_path(path):
    """True if `path` sits in a volatile/world-writable directory where
    keyloggers tend to run from or drop their capture files."""
    if not path:
        return False
    p = path.lower()
    return any(re.search(pat, p) for pat in VOLATILE_DIR_PATTERNS)


def _is_loopback(ip):
    return ip.startswith("127.") or ip == "::1" or ip == "0.0.0.0"


# ---------------------------------------------------------------------------
# Runtime environment (privilege level, console ownership)
# ---------------------------------------------------------------------------

def is_elevated():
    """Return True if we have admin/root rights, False if not, None if unknown.

    This is reported in the banner because privilege directly determines how
    much of the system is visible: without it, other users' processes deny
    open_files()/net_connections() and HKLM Run keys may be unreadable, so a
    "clean" verdict covers less ground. Being explicit about that beats
    silently under-reporting.
    """
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return None
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return None


def _own_console_pids():
    """PIDs on our console that are really *us* rather than a separate program.

    A PyInstaller --onefile binary runs as two processes: the bootloader that
    unpacks the archive and the child that runs the actual code. Both attach to
    the same console. A double-clicked .py can likewise be py.exe launching
    python.exe. Those halves must not be mistaken for "a shell is watching us".
    """
    us = {os.getpid()}
    try:
        me = psutil.Process()
        try:
            own_exe = os.path.normcase(me.exe())
        except (psutil.Error, OSError):
            own_exe = None
        launchers = {"python.exe", "pythonw.exe", "py.exe", "python", "python3"}
        for ancestor in me.parents():
            try:
                name = (ancestor.name() or "").lower()
                exe = ancestor.exe()
            except (psutil.Error, OSError):
                continue
            same_binary = bool(own_exe) and os.path.normcase(exe or "") == own_exe
            # Unfrozen, the interpreter (or the py launcher that started it) is
            # part of our own invocation, not an independent shell.
            interpreter = (not IS_FROZEN) and name in launchers
            if same_binary or interpreter:
                us.add(ancestor.pid)
            else:
                # Anything else above us is a real parent program (cmd, bash,
                # explorer): stop, its console outlives us.
                break
    except (psutil.Error, OSError):
        pass
    return us


def owns_console():
    """True if this console window is destroyed the moment we exit.

    That is the double-clicked / UAC-elevated case: Windows hands the program a
    brand-new console and tears it down with the process, so the report flashes
    past unread -- which is exactly what "the terminal closes" looks like.

    Measured, not assumed: GetConsoleProcessList on a --onefile build returns
    the bootloader *and* the child, so an equality test against 1 never fires.
    We therefore subtract our own halves and ask whether anybody else is left.

    Returns False on non-Windows and whenever the answer cannot be determined,
    so a scripted run is never left blocking on a keypress.
    """
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        kernel32.GetConsoleProcessList.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
        kernel32.GetConsoleProcessList.restype = wintypes.DWORD

        # Ask for the real count first: the buffer must be large enough or the
        # call reports the required size instead of filling it in.
        size = kernel32.GetConsoleProcessList((wintypes.DWORD * 1)(), 1)
        if size == 0:
            return False
        buf = (wintypes.DWORD * max(size, 2))()
        count = kernel32.GetConsoleProcessList(buf, len(buf))
        if count == 0:
            return False
        console_pids = {buf[i] for i in range(min(count, len(buf)))}
        return not (console_pids - _own_console_pids())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Visible-window map (Windows) — built once per scan
# ---------------------------------------------------------------------------

def get_visible_window_pids():
    """Return the set of PIDs owning at least one visible top-level window.

    Windows only. Correctly typed for 64-bit: HWND/LPARAM are pointer-sized,
    so the EnumWindows callback must not use c_int (that truncates the handle
    on Win64 and makes GetWindowThreadProcessId return garbage). Returns an
    empty set on other platforms, where the 'headless' signal is not used.
    """
    if not IS_WINDOWS:
        return set()
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
        user32.EnumWindows.restype = wintypes.BOOL
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        user32.IsWindowVisible.argtypes = [wintypes.HWND]
        user32.IsWindowVisible.restype = wintypes.BOOL

        pids = set()

        def _cb(hwnd, lparam):
            if user32.IsWindowVisible(hwnd):
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value:
                    pids.add(pid.value)
            return True

        user32.EnumWindows(WNDENUMPROC(_cb), 0)
        return pids
    except Exception:
        # If the enumeration fails, return an empty set and let the caller
        # treat "headless" as unknown (i.e. skip that signal) rather than
        # flagging everything.
        return None


# ---------------------------------------------------------------------------
# Individual heuristics
# ---------------------------------------------------------------------------

def check_name(proc_info, reasons, score):
    name = (proc_info.get("name") or "").lower()
    for pat in EXPLICIT_KEYLOGGER_PATTERNS:
        if re.search(pat, name):
            return score_add(reasons, score, 4, f"Process name matches keylogger pattern '{pat}'")
    for pat in GENERIC_SUSPICIOUS_PATTERNS:
        if re.search(pat, name):
            return score_add(reasons, score, 2, f"Process name matches generic-suspicious pattern '{pat}'")
    return score


def check_exe_path(proc_info, reasons, score):
    exe = proc_info.get("exe") or ""
    if not exe:
        return score
    if is_volatile_path(exe):
        score = score_add(reasons, score, 3, f"Executable runs from a volatile/temp directory ({exe})")
    # Only meaningful for a real filesystem path. Kernel pseudo-processes
    # (Registry, MemCompression, vmmemWSL, ...) report a bare name as their
    # "exe", which is not a path that can be missing from disk.
    if os.path.isabs(exe):
        try:
            if not os.path.exists(exe):
                score = score_add(reasons, score, 3,
                                  "Executable no longer exists on disk (possibly deleted after launch)")
        except Exception:
            pass
    return score


def check_raw_input_device_access_linux(proc, reasons, score):
    """On Linux, raw keystrokes come through /dev/input/event*. A process
    (that isn't a compositor / input daemon) holding an open FD to these is
    the single strongest signal for an evdev-based keylogger."""
    if not IS_LINUX:
        return score
    try:
        fd_dir = f"/proc/{proc.pid}/fd"
        if not os.path.isdir(fd_dir):
            return score
        for fd in os.listdir(fd_dir):
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except (OSError, PermissionError):
                continue
            if "/dev/input/event" in target or target == "/dev/input" or "/dev/uinput" in target:
                name = (proc.name() or "").lower()
                if name not in KNOWN_INPUT_HOLDERS:
                    score = score_add(reasons, score, 5,
                                      f"Holds an open file descriptor to a raw input device ({target})")
                    break
    except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError, FileNotFoundError):
        pass
    return score


def check_open_log_like_files(proc, deep, reasons, score):
    """Keyloggers write captured keystrokes somewhere. A handle to a
    .log/.txt/.dat file *in a volatile/temp directory* is the signal — an app
    logging into its own AppData\\<Vendor> folder is normal and ignored.
    Counted once, never stacked per file.

    On Windows, open_files() re-enumerates the entire system handle table per
    process (~18s over a full process list) and doesn't release the GIL, so it
    only runs under --deep. On Linux/macOS the /proc-backed call is cheap and
    always runs.
    """
    if IS_WINDOWS and not deep:
        return score
    try:
        files = proc.open_files()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return score
    except Exception:
        return score

    hits = [f.path for f in files
            if f.path.lower().endswith(LOG_FILE_EXT) and is_volatile_path(f.path)]
    if hits:
        extra = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
        score = score_add(reasons, score, 3,
                          f"Open handle to a log-like file in a volatile/temp location ({hits[0]}){extra}")
    return score


def check_headless_and_network(proc, headless, reasons, score):
    """A process with no visible window is 'headless'. On its own that's weak
    (Electron/Chromium spawn many headless helpers), so it earns just +1. But
    a headless process holding an ESTABLISHED outbound connection to a remote
    host is a plausible exfil channel and earns a bit more."""
    if not headless:
        return score
    score = score_add(reasons, score, 1, "Runs without a visible window (headless/background)")

    try:
        if hasattr(proc, "net_connections"):
            conns = proc.net_connections(kind="inet")
        else:  # psutil < 6
            conns = proc.connections(kind="inet")
    except Exception:
        conns = []

    established = []
    for c in conns:
        if c.status == psutil.CONN_ESTABLISHED and c.raddr and not _is_loopback(c.raddr.ip):
            established.append(c)
    if established:
        remote = f"{established[0].raddr.ip}:{established[0].raddr.port}"
        extra = f" (+{len(established) - 1} more)" if len(established) > 1 else ""
        score = score_add(reasons, score, 2,
                          f"Headless process with an established outbound connection ({remote}){extra}")
    return score


def check_persistence_windows(proc_info, reasons, score):
    if not IS_WINDOWS or winreg is None:
        return score
    exe = proc_info.get("exe") or ""
    if not exe:
        return score
    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]
    try:
        for hive, subkey in run_keys:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    i = 0
                    while True:
                        try:
                            _, value, _ = winreg.EnumValue(key, i)
                            if isinstance(value, str) and exe.lower() in value.lower():
                                return score_add(reasons, score, 2,
                                                 "Registered in a Windows Run autostart key (persistence)")
                        except OSError:
                            break
                        i += 1
            except FileNotFoundError:
                continue
    except Exception:
        pass
    return score


def check_persistence_linux(proc_info, reasons, score):
    if not IS_LINUX:
        return score
    exe = proc_info.get("exe") or ""
    if not exe:
        return score
    base = os.path.basename(exe)
    autostart_dirs = [os.path.expanduser("~/.config/autostart"), "/etc/xdg/autostart"]
    for d in autostart_dirs:
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    try:
                        with open(os.path.join(d, f), "r", errors="ignore") as fh:
                            if base in fh.read():
                                return score_add(reasons, score, 2, f"Registered in autostart entry ({d}/{f})")
                    except Exception:
                        continue
            except Exception:
                continue

    for d in ("/etc/cron.d", "/var/spool/cron/crontabs"):
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    try:
                        with open(os.path.join(d, f), "r", errors="ignore") as fh:
                            if base in fh.read():
                                return score_add(reasons, score, 2, f"Referenced in cron persistence ({d}/{f})")
                    except Exception:
                        continue
            except Exception:
                continue
    return score


def check_resource_footprint(proc, reasons, score):
    """Few threads + small RSS is consistent with a lightweight background
    hook rather than a real application. Weak signal (+1), non-blocking:
    no CPU sampling, so it doesn't add seconds per process."""
    try:
        threads = proc.num_threads()
        mem_mb = proc.memory_info().rss / (1024 * 1024)
        if threads <= 3 and mem_mb < 25:
            score = score_add(reasons, score, 1,
                              f"Lightweight background footprint ({threads} threads, {mem_mb:.1f}MB)")
    except Exception:
        pass
    return score


# ---------------------------------------------------------------------------
# Self-exclusion
# ---------------------------------------------------------------------------

def get_self_identity():
    """Return ``(own_pid, own_exe)`` used to keep the detector out of its own report.

    This is deliberately **identity-based, never name-based**: we suppress *this
    running program*, not anything that happens to be called
    "keylogger-detector". A malicious binary cannot dodge detection by renaming
    itself to match us.

    Why it is needed: the released binary is ``keylogger-detector.exe``, whose
    name matches our own EXPLICIT_KEYLOGGER_PATTERNS (``key\\s*log``, +4), so
    without this the scanner would flag itself every run.

    ``own_exe`` is only populated when frozen by PyInstaller, because a
    ``--onefile`` build runs as two processes (bootloader parent + app child)
    that share one executable path. Unfrozen, we return None so that other
    Python processes stay fully scannable — a keylogger written in Python must
    remain detectable.
    """
    own_pid = os.getpid()
    own_exe = None
    if getattr(sys, "frozen", False):
        try:
            own_exe = os.path.normcase(os.path.realpath(sys.executable))
        except Exception:
            own_exe = None
    return own_pid, own_exe


def is_self(proc_info, own_pid, own_exe):
    """True if `proc_info` describes this detector process (or its bootloader)."""
    if proc_info.get("pid") == own_pid:
        return True
    if own_exe:
        exe = proc_info.get("exe")
        if exe:
            try:
                if os.path.normcase(os.path.realpath(exe)) == own_exe:
                    return True
            except Exception:
                pass
    return False


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def _score_process(proc, have_window_map, visible_pids, deep):
    """Score a single process. Returns a result dict (with score/reasons) or
    None if the process vanished / is inaccessible."""
    try:
        info = proc.info
        reasons = []
        score = 0
        headless = have_window_map and (info["pid"] not in visible_pids)

        score = check_name(info, reasons, score)
        score = check_exe_path(info, reasons, score)
        score = check_raw_input_device_access_linux(proc, reasons, score)
        score = check_open_log_like_files(proc, deep, reasons, score)
        score = check_headless_and_network(proc, headless, reasons, score)
        score = check_persistence_windows(info, reasons, score)
        score = check_persistence_linux(info, reasons, score)
        score = check_resource_footprint(proc, reasons, score)

        return {
            "pid": info["pid"],
            "name": info.get("name"),
            "exe": info.get("exe"),
            "user": info.get("username"),
            "started": datetime.fromtimestamp(info["create_time"]).isoformat()
            if info.get("create_time") else None,
            "score": score,
            "risk": classify(score),
            "reasons": reasons,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def scan(min_score=4, deep=False, stats=None, progress=None):
    """Score every visible process and return those at or above `min_score`.

    If `stats` is a dict it is filled in with what the scan actually did --
    process counts, how many were only partially readable, elapsed time, every
    scored process, and the highest-scoring ones that stayed *below* the
    threshold. main() prints those so that a clean run still shows evidence of
    work instead of a bare "nothing found". `progress`, if given, is called with
    the running process count so a slow --deep scan can show it is alive. Both
    are optional, which keeps the older two-argument call signature working.
    """
    started = time.perf_counter()

    visible_pids = get_visible_window_pids()
    # None => enumeration failed; don't trust the headless signal at all.
    have_window_map = IS_WINDOWS and visible_pids is not None
    if visible_pids is None:
        visible_pids = set()

    own_pid, own_exe = get_self_identity()

    total = 0
    vanished = 0
    restricted = 0
    scored = []
    for proc in psutil.process_iter(["pid", "name", "exe", "username", "create_time"]):
        # Read the cached attribute dict defensively: one process raising here
        # must never abort the whole scan and leave the user with no report.
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            total += 1
            vanished += 1
            continue
        if is_self(info, own_pid, own_exe):
            continue
        total += 1
        if progress is not None and total % 20 == 0:
            progress(total)
        r = _score_process(proc, have_window_map, visible_pids, deep)
        if r is None:
            # Exited between enumeration and inspection, or wholly unreadable.
            vanished += 1
            continue
        if not r["exe"]:
            # psutil blanks attributes it cannot read rather than raising, so a
            # missing image path is the observable marker of a process we could
            # only partially inspect (protected, or owned by another user).
            restricted += 1
        scored.append(r)

    scored.sort(key=lambda r: r["score"], reverse=True)
    results = [r for r in scored if r["score"] >= min_score]

    if stats is not None:
        stats.update({
            "total": total,
            "scored": len(scored),
            "vanished": vanished,
            "restricted": restricted,
            "flagged": len(results),
            "elapsed": time.perf_counter() - started,
            "window_map": have_window_map,
            "near_misses": [r for r in scored if r["score"] < min_score],
            "all": scored,
        })

    return results


def classify(score):
    if score >= 9:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    return "LOW"


RULE = "=" * 74
THIN = "-" * 74


def _short_reasons(reasons, limit=2):
    """Condense scoring reasons into one short line for the context table.

    "[+1] Runs without a visible window (headless/background)" -> "Runs
    without a visible window". The parenthetical detail is dropped because the
    full text is already available in --json and in the flagged-process
    details block.
    """
    out = []
    for reason in reasons[:limit]:
        text = re.sub(r"^\[\+\d+\]\s*", "", reason)
        out.append(text.split(" (")[0])
    extra = len(reasons) - len(out)
    if extra > 0:
        out.append(f"+{extra} more")
    return "; ".join(out) if out else "no signals"


def print_banner(min_score, deep, elevated):
    """Print what this run is about to do, before any scanning happens.

    Deliberately ASCII-only: this is the first thing a downloaded .exe prints
    on an unknown machine, and box-drawing characters raise
    UnicodeEncodeError on a cp437/cp850 console.
    """
    print(RULE)
    print(f"  Keylogger Detector {__version__}  -  heuristic process scan")
    print(RULE)
    print(f"  Host        : {platform.node()} ({platform.system()} {platform.release()})")
    print(f"  Started     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if deep:
        print("  Mode        : DEEP (inspects open file handles; slower)")
    else:
        print("  Mode        : QUICK (add --deep to inspect open file handles)")

    if elevated is True:
        print(f"  Privileges  : {'administrator' if IS_WINDOWS else 'root'} - full visibility")
    elif elevated is False:
        label = "standard user" if IS_WINDOWS else "non-root"
        hint = "run as administrator" if IS_WINDOWS else "re-run with sudo"
        print(f"  Privileges  : {label} - limited visibility ({hint} to inspect all processes)")
    else:
        print("  Privileges  : unknown")

    print(f"  Threshold   : report score >= {min_score}   (LOW 4-5 / MEDIUM 6-8 / HIGH 9+)")
    print(THIN)


def print_scan_stats(stats, deep):
    """Print evidence that the scan ran: counts, timing, coverage caveats."""
    print(f"  Inspected {stats['total']} running processes in {stats['elapsed']:.1f}s")
    if stats["restricted"]:
        print(f"  {stats['restricted']} could only be read partially "
              "(protected or owned by another user)")
    if stats["vanished"]:
        print(f"  {stats['vanished']} exited while the scan was in progress")
    if IS_WINDOWS and not stats["window_map"]:
        print("  [!] Could not enumerate windows - the headless signal was skipped")
    if IS_WINDOWS and not deep:
        print("  Note: open file handles were NOT inspected in quick mode "
              "(use --deep for that signal)")
    print()


def print_report(results):
    """Print the flagged processes: summary table, then per-process evidence."""
    print(f"{'PID':<8}{'RISK':<8}{'SCORE':<7}{'PROCESS':<28}USER")
    print(THIN)
    for r in results:
        name = (r["name"] or "?")[:27]
        print(f"{r['pid']:<8}{r['risk']:<8}{r['score']:<7}{name:<28}{r['user'] or ''}")

    print("\nWhy each was flagged:\n")
    for r in results:
        print(f"  PID {r['pid']} - {r['name']} [{r['risk']}, score {r['score']}]")
        print(f"    exe: {r['exe'] or '(unreadable)'}")
        for reason in r["reasons"]:
            print(f"    {reason}")
        print()


def print_near_misses(stats, min_score, top):
    """Show the highest scores that stayed below the threshold.

    This is the antidote to a blank screen on a clean machine: it proves the
    scan examined real processes and shows how far the closest one was from
    being reported. Explicitly labelled as not-an-alert, because an analyst
    reading a list of process names will otherwise assume they are findings.
    """
    candidates = [r for r in stats.get("near_misses", []) if r["score"] > 0]
    if not candidates:
        print(f"  Not one process scored above 0, so nothing came close to the "
              f"threshold of {min_score}.")
        return

    shown = candidates[:top]
    print(f"  Highest scores seen, all BELOW the threshold of {min_score} "
          "- context, NOT alerts:\n")
    print(f"    {'SCORE':<7}{'PID':<8}{'PROCESS':<26}SIGNALS")
    print("    " + "-" * 66)
    for r in shown:
        name = (r["name"] or "?")[:25]
        print(f"    {r['score']:<7}{r['pid']:<8}{name:<26}{_short_reasons(r['reasons'])}")
    remaining = len(candidates) - len(shown)
    if remaining:
        print(f"    ... and {remaining} more scoring 1-{min_score - 1} "
              f"(--top {len(candidates)} to list them all)")


def print_verdict(results, stats, min_score, top, show_context=True):
    """Print the headline conclusion, then either findings or near-miss context."""
    if not results:
        print(f"RESULT: CLEAN - no process reached a score of {min_score}.")
        print("        Nothing on this system looks like a keylogger by these heuristics.\n")
        if show_context:
            print_near_misses(stats, min_score, top)
        print("\n  Reminder: these are behavioural heuristics, not proof of absence."
              "\n  A kernel-mode or in-memory-only logger can evade every check here.")
        return

    bands = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        bands[r["risk"]] = bands.get(r["risk"], 0) + 1
    headline = ", ".join(f"{bands[b]} {b}" for b in ("HIGH", "MEDIUM", "LOW") if bands[b])

    print(f"RESULT: {len(results)} process(es) flagged ({headline}) "
          f"at score >= {min_score}.")
    print("        Treat these as leads to triage, not verdicts.\n")
    print_report(results)


def print_process_table(stats, min_score):
    """List every process the scan inspected, highest score first.

    The scoring report answers "is anything wrong"; this answers "what did you
    actually look at", which is the question a first-time user asks when a
    clean scan prints no process names at all. Rows at or above the threshold
    are marked so the flagged ones stay findable in a 300-row list.
    """
    rows = stats.get("all", [])
    if not rows:
        print("  No processes could be inspected at all - this is not a normal result.\n")
        return

    print(f"  All {len(rows)} inspected processes, highest score first "
          f"('>>' = at or above the threshold of {min_score}):\n")
    print(f"    {'':<3}{'SCORE':<7}{'PID':<8}{'PROCESS':<26}{'USER':<22}SIGNALS")
    print("    " + "-" * 96)
    for r in rows:
        mark = ">>" if r["score"] >= min_score else ""
        name = (r["name"] or "?")[:25]
        user = (r["user"] or "-")[:21]
        signals = _short_reasons(r["reasons"]) if r["score"] else "-"
        print(f"    {mark:<3}{r['score']:<7}{r['pid']:<8}{name:<26}{user:<22}{signals}")
    print()


def _progress_writer():
    """Return a live scanned-process counter, or None when output isn't a console.

    The counter rewrites one line with a carriage return, so it must never run
    into a redirected file or a pipe -- control characters in a saved log are
    worse than no progress at all.
    """
    try:
        if not sys.stdout.isatty():
            return None
    except (AttributeError, ValueError):
        return None

    def write(count):
        sys.stdout.write(f"\r  inspected {count} processes ...")
        sys.stdout.flush()

    return write


def _clear_progress(progress):
    """Erase the counter line so the report starts on a clean row."""
    if progress is None:
        return
    try:
        sys.stdout.write("\r" + " " * 40 + "\r")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass


def pause_before_exit(force=False, never=False):
    """Hold the window open so the report can actually be read.

    Automatic when the console dies with us (double-clicked or UAC-elevated
    launch). `--pause` forces it for the cases the heuristic cannot see -- a
    terminal emulator that closes on exit, a shortcut, a Task Scheduler action
    -- and `--no-pause` disables it outright for scripts and pipes.
    """
    if never:
        return
    if not force and not owns_console():
        return
    if not sys.stdin or not sys.stdin.isatty():
        # No keyboard attached (input redirected, or launched with no stdin):
        # waiting would hang forever instead of pausing.
        return
    try:
        input("\nPress Enter to close this window...")
    except (EOFError, KeyboardInterrupt):
        pass


def main():
    parser = argparse.ArgumentParser(
        prog="keylogger-detector",
        description="Heuristic keylogger / input-hook detector",
        epilog="Exit code: 0 = nothing flagged, 1 = at least one process flagged.")
    parser.add_argument("--version", action="version",
                        version=f"keylogger-detector {__version__}")
    parser.add_argument("--min-score", type=int, default=4,
                        help="Only report processes scoring at or above this threshold (default: 4)")
    parser.add_argument("--watch", type=int, default=0,
                        help="Rescan every N seconds (0 = single scan)")
    parser.add_argument("--deep", action="store_true",
                        help="Also inspect open file handles for temp keystroke logs "
                             "(Windows: slower, ~20s; always on elsewhere)")
    parser.add_argument("--json", type=str, default=None,
                        help="Write the full report to this path as JSON")
    parser.add_argument("--top", type=int, default=5, metavar="N",
                        help="How many below-threshold processes to show as context (default: 5)")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress the banner and context table; print findings only")
    parser.add_argument("--list-all", action="store_true",
                        help="List every process that was inspected, with its score, "
                             "not just the ones that crossed the threshold")
    parser.add_argument("--pause", action="store_true",
                        help="Always wait for Enter before exiting, so the window "
                             "cannot close before the report has been read")
    parser.add_argument("--no-pause", action="store_true",
                        help="Never wait for Enter before exiting (for scripts and pipes)")
    args = parser.parse_args()

    elevated = is_elevated()
    exit_code = 0
    try:
        while True:
            if not args.quiet:
                print_banner(args.min_score, args.deep, elevated)
                print("Scanning running processes ...\n")

            stats = {}
            progress = None if args.quiet else _progress_writer()
            results = scan(min_score=args.min_score, deep=args.deep, stats=stats,
                           progress=progress)
            _clear_progress(progress)
            exit_code = 1 if results else 0

            if args.quiet:
                print(f"Scan @ {datetime.now().isoformat(timespec='seconds')} - "
                      f"{len(results)} flagged (min-score {args.min_score})")
                if results:
                    print()
                    print_report(results)
                if args.list_all:
                    print()
                    print_process_table(stats, args.min_score)
            else:
                print_scan_stats(stats, args.deep)
                # The full listing goes before the verdict so the conclusion is
                # the last thing left on screen after 300 rows have scrolled by.
                if args.list_all:
                    print_process_table(stats, args.min_score)
                print_verdict(results, stats, args.min_score, args.top,
                              show_context=not args.list_all)

            if args.json:
                try:
                    parent = os.path.dirname(os.path.abspath(args.json))
                    os.makedirs(parent, exist_ok=True)
                    with open(args.json, "w", encoding="utf-8") as f:
                        json.dump(results, f, indent=2)
                    print(f"\nFull report written to {args.json}")
                except OSError as exc:
                    # A released binary should not greet the user with a traceback.
                    print(f"\n[!] Could not write report to {args.json}: {exc}")

            if args.watch <= 0:
                break
            print(f"\n{THIN}\nRescanning in {args.watch}s -- press Ctrl-C to stop.\n")
            # Flush before sleeping. Redirected to a file or pipe, Python
            # block-buffers stdout, so a --watch run that is later killed
            # (Ctrl-C, SIGTERM, machine shutdown) would otherwise discard the
            # findings it had already printed -- the worst possible moment to
            # lose a monitoring log.
            try:
                sys.stdout.flush()
            except (OSError, ValueError):
                pass
            time.sleep(args.watch)
    except KeyboardInterrupt:
        # Ctrl-C is how --watch is meant to end; don't dump a traceback for it.
        print("\nStopped.")
    finally:
        pause_before_exit(force=args.pause, never=args.no_pause)

    return exit_code


if __name__ == "__main__":
    configure_stdout()
    sys.exit(main())
