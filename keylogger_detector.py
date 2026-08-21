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

__version__ = "1.0.0"

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MAC = platform.system() == "Darwin"

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


def scan(min_score=4, deep=False):
    visible_pids = get_visible_window_pids()
    # None => enumeration failed; don't trust the headless signal at all.
    have_window_map = IS_WINDOWS and visible_pids is not None
    if visible_pids is None:
        visible_pids = set()

    own_pid, own_exe = get_self_identity()

    results = []
    for proc in psutil.process_iter(["pid", "name", "exe", "username", "create_time"]):
        if is_self(proc.info, own_pid, own_exe):
            continue
        r = _score_process(proc, have_window_map, visible_pids, deep)
        if r and r["score"] >= min_score:
            results.append(r)

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def classify(score):
    if score >= 9:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    return "LOW"


def print_report(results):
    if not results:
        print("No processes crossed the score threshold. System looks clean by these heuristics.")
        return

    print(f"\n{'PID':<8}{'RISK':<8}{'SCORE':<7}{'PROCESS':<28}USER")
    print("-" * 74)
    for r in results:
        name = (r["name"] or "")[:27]
        print(f"{r['pid']:<8}{r['risk']:<8}{r['score']:<7}{name:<28}{r['user'] or ''}")

    print("\nDetails:\n")
    for r in results:
        print(f"PID {r['pid']} — {r['name']} [{r['risk']}, score {r['score']}]")
        print(f"  exe: {r['exe']}")
        for reason in r["reasons"]:
            print(f"  {reason}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Heuristic keylogger / input-hook detector")
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
    args = parser.parse_args()

    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Not running as root — /proc/*/fd access and some checks will be limited.\n")
    if IS_WINDOWS and not args.deep:
        print("[i] Quick scan. Add --deep to inspect open file handles for temp keystroke logs (slower).\n")

    while True:
        results = scan(min_score=args.min_score, deep=args.deep)
        print(f"Scan @ {datetime.now().isoformat(timespec='seconds')} — "
              f"{len(results)} flagged process(es) (platform: {platform.system()}, min-score {args.min_score})")
        print_report(results)

        if args.json:
            try:
                parent = os.path.dirname(os.path.abspath(args.json))
                os.makedirs(parent, exist_ok=True)
                with open(args.json, "w") as f:
                    json.dump(results, f, indent=2)
                print(f"Full report written to {args.json}")
            except OSError as exc:
                # A released binary should not greet the user with a traceback.
                print(f"[!] Could not write report to {args.json}: {exc}")

        if args.watch <= 0:
            break
        time.sleep(args.watch)


if __name__ == "__main__":
    main()
