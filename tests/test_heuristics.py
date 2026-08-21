"""
Unit tests for keylogger_detector heuristics.

These exercise the pure scoring functions with synthetic process metadata —
no real processes are inspected — so they run fast and deterministically on
any platform / in CI.

    python -m pytest tests/ -q
"""

from collections import namedtuple

import os

import psutil

import keylogger_detector as kd


# --------------------------------------------------------------------------
# is_volatile_path
# --------------------------------------------------------------------------

def test_volatile_paths_match():
    assert kd.is_volatile_path(r"C:\Users\me\AppData\Local\Temp\x.exe")
    assert kd.is_volatile_path(r"C:\Windows\Temp\y.exe")
    assert kd.is_volatile_path("/tmp/dropper")
    assert kd.is_volatile_path("/var/tmp/dropper")
    assert kd.is_volatile_path("/dev/shm/thing")


def test_non_volatile_paths_do_not_match():
    # Normal install / per-app data locations must NOT be treated as volatile.
    assert not kd.is_volatile_path(r"C:\Program Files\App\app.exe")
    assert not kd.is_volatile_path(r"C:\Users\me\AppData\Roaming\Code\logs\main.log")
    assert not kd.is_volatile_path("/usr/bin/python3")
    assert not kd.is_volatile_path("")
    assert not kd.is_volatile_path(None)


# --------------------------------------------------------------------------
# check_name — two tiers
# --------------------------------------------------------------------------

def test_explicit_keylogger_name_scores_4():
    score = kd.check_name({"name": "spykeylogger.exe"}, [], 0)
    assert score == 4


def test_generic_suspicious_name_scores_2():
    score = kd.check_name({"name": "nethook.exe"}, [], 0)
    assert score == 2


def test_clean_name_scores_0():
    assert kd.check_name({"name": "chrome.exe"}, [], 0) == 0
    assert kd.check_name({"name": "explorer.exe"}, [], 0) == 0


# --------------------------------------------------------------------------
# check_exe_path — volatile dir, deleted binary, kernel pseudo-processes
# --------------------------------------------------------------------------

def test_exe_in_temp_flags_volatile():
    reasons = []
    kd.check_exe_path({"exe": "/tmp/evil/keylog"}, reasons, 0)
    assert any("volatile/temp directory" in r for r in reasons)


def test_bare_name_exe_is_not_flagged_as_deleted():
    # Kernel pseudo-processes report a bare name (Registry, MemCompression,
    # vmmemWSL) as their "exe" — must NOT be scored as a deleted binary.
    reasons = []
    score = kd.check_exe_path({"exe": "Registry"}, reasons, 0)
    assert score == 0
    assert reasons == []


def test_missing_absolute_exe_flags_deleted():
    reasons = []
    fake_abs = kd.os.path.join(kd.os.getcwd(), "definitely_missing_binary_zzz.exe")
    kd.check_exe_path({"exe": fake_abs}, reasons, 0)
    assert any("no longer exists on disk" in r for r in reasons)


# --------------------------------------------------------------------------
# check_open_log_like_files — counted once, volatile-only
# --------------------------------------------------------------------------

_FakeFile = namedtuple("_FakeFile", ["path"])


class _FakeProc:
    def __init__(self, paths):
        self._paths = paths

    def open_files(self):
        return [_FakeFile(p) for p in self._paths]


def test_temp_logfiles_score_once_not_stacked():
    proc = _FakeProc(["/tmp/a.log", "/tmp/b.log", "/tmp/c.log"])
    reasons = []
    score = kd.check_open_log_like_files(proc, True, reasons, 0)
    assert score == 3                      # not 9
    assert any("(+2 more)" in r for r in reasons)


def test_logfile_outside_temp_is_ignored():
    proc = _FakeProc([r"C:\Users\me\AppData\Roaming\Code\logs\main.log"])
    assert kd.check_open_log_like_files(proc, True, [], 0) == 0


# --------------------------------------------------------------------------
# check_headless_and_network
# --------------------------------------------------------------------------

_Addr = namedtuple("_Addr", ["ip", "port"])
_Conn = namedtuple("_Conn", ["status", "raddr"])


class _NetProc:
    def __init__(self, conns):
        self._conns = conns

    def net_connections(self, kind="inet"):
        return self._conns


def test_not_headless_scores_0():
    assert kd.check_headless_and_network(_NetProc([]), False, [], 0) == 0


def test_headless_no_conn_scores_1():
    assert kd.check_headless_and_network(_NetProc([]), True, [], 0) == 1


def test_headless_with_established_outbound_scores_3():
    conns = [_Conn(psutil.CONN_ESTABLISHED, _Addr("203.0.113.9", 443))]
    score = kd.check_headless_and_network(_NetProc(conns), True, [], 0)
    assert score == 3                      # +1 headless, +2 exfil channel


def test_headless_loopback_connection_is_ignored():
    conns = [_Conn(psutil.CONN_ESTABLISHED, _Addr("127.0.0.1", 5000))]
    score = kd.check_headless_and_network(_NetProc(conns), True, [], 0)
    assert score == 1                      # headless only; loopback doesn't count


# --------------------------------------------------------------------------
# classify — risk bands
# --------------------------------------------------------------------------

def test_classify_bands():
    assert kd.classify(3) == "LOW"
    assert kd.classify(5) == "LOW"
    assert kd.classify(6) == "MEDIUM"
    assert kd.classify(8) == "MEDIUM"
    assert kd.classify(9) == "HIGH"
    assert kd.classify(15) == "HIGH"


def test_realistic_keylogger_scores_high():
    """name + temp-exe + temp-logfile + headless + exfil => HIGH."""
    reasons, score = [], 0
    score = kd.check_name({"name": "spykey.exe"}, reasons, score)          # +4
    score = kd.check_exe_path({"exe": "/tmp/spykey.exe"}, reasons, score)  # +3 (temp)
    score = kd.check_open_log_like_files(
        _FakeProc(["/tmp/keys.log"]), True, reasons, score)               # +3
    conns = [_Conn(psutil.CONN_ESTABLISHED, _Addr("203.0.113.9", 443))]
    score = kd.check_headless_and_network(_NetProc(conns), True, reasons, score)  # +3
    assert kd.classify(score) == "HIGH"


# --------------------------------------------------------------------------
# self-exclusion — the detector must not report itself
# --------------------------------------------------------------------------

def test_is_self_matches_own_pid():
    assert kd.is_self({"pid": os.getpid()}, os.getpid(), None) is True


def test_is_self_ignores_unrelated_pid():
    other = os.getpid() + 12345
    assert kd.is_self({"pid": other, "exe": "C:\\Windows\\explorer.exe"},
                      os.getpid(), None) is False


def test_is_self_matches_frozen_bootloader_by_exe_path():
    """A --onefile build runs as bootloader + child sharing one exe path;
    both halves are 'us' and neither should be reported."""
    own_exe = os.path.normcase(os.path.realpath(__file__))
    assert kd.is_self({"pid": os.getpid() + 999, "exe": __file__},
                      os.getpid(), own_exe) is True


def test_is_self_is_identity_based_not_name_based():
    """A hostile binary merely *named* like us must stay detectable — the
    exclusion keys off our real executable path, never off the process name."""
    own_exe = os.path.normcase(os.path.realpath(__file__))
    impostor = {"pid": os.getpid() + 999,
                "name": "keylogger-detector.exe",
                "exe": os.path.join(os.path.dirname(__file__), "keylogger-detector.exe")}
    assert kd.is_self(impostor, os.getpid(), own_exe) is False


def test_get_self_identity_unfrozen_has_no_exe_match():
    """Running as a .py, only our own PID is excluded — so other Python
    processes (e.g. a keylogger written in Python) stay fully scannable."""
    own_pid, own_exe = kd.get_self_identity()
    assert own_pid == os.getpid()
    assert own_exe is None


# --------------------------------------------------------------------------
# _short_reasons — the one-line signal summary in the context table
# --------------------------------------------------------------------------

def test_short_reasons_strips_points_prefix_and_detail():
    reasons = [r"[+3] Executable runs from a volatile/temp directory (C:\Temp\x.exe)"]
    assert kd._short_reasons(reasons) == "Executable runs from a volatile/temp directory"


def test_short_reasons_caps_at_limit_and_counts_the_rest():
    reasons = ["[+1] One (detail)", "[+2] Two (detail)", "[+3] Three", "[+1] Four"]
    out = kd._short_reasons(reasons, limit=2)
    assert out == "One; Two; +2 more"


def test_short_reasons_handles_no_signals():
    assert kd._short_reasons([]) == "no signals"


# --------------------------------------------------------------------------
# scan() statistics — what makes a clean run visibly a completed scan
# --------------------------------------------------------------------------

class _ScanProc:
    """Minimal stand-in for psutil.Process as scan() uses it."""

    def __init__(self, pid, name, exe, threads=40, rss_mb=200):
        self.pid = pid
        self.info = {"pid": pid, "name": name, "exe": exe,
                     "username": "tester", "create_time": 0}
        self._threads = threads
        self._rss = int(rss_mb * 1024 * 1024)

    def open_files(self):
        return []

    def net_connections(self, kind="inet"):
        return []

    def num_threads(self):
        return self._threads

    def memory_info(self):
        return namedtuple("_Mem", ["rss"])(self._rss)


# An absolute path that really exists and is not in a temp directory, so the
# only signal these fakes trip is the one each test is about. Using a made-up
# path instead would silently add +3 for "executable no longer on disk".
_REAL_EXE = os.path.abspath(__file__)


def test_scan_populates_stats_and_separates_near_misses(monkeypatch):
    """A clean scan must still report counts, timing and near-miss context;
    that is what turns an empty-looking screen into evidence of work."""
    procs = [
        _ScanProc(101, "winkeylog.exe", _REAL_EXE),   # +4 explicit name -> flagged
        _ScanProc(102, "nethook.exe", _REAL_EXE),     # +2 generic name  -> near miss
        _ScanProc(103, "explorer.exe", _REAL_EXE),    # 0 signals
        _ScanProc(104, "protected.exe", None),        # unreadable image path
    ]
    monkeypatch.setattr(kd.psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(kd, "get_visible_window_pids", lambda: set())
    monkeypatch.setattr(kd, "IS_WINDOWS", False)   # disable the headless signal

    stats = {}
    results = kd.scan(min_score=4, deep=False, stats=stats)

    assert [r["pid"] for r in results] == [101]
    assert stats["total"] == 4
    assert stats["flagged"] == 1
    assert stats["restricted"] == 1                      # pid 104
    assert stats["vanished"] == 0
    assert stats["elapsed"] >= 0
    # Near misses exclude the flagged process and are sorted worst-first.
    assert 102 in [r["pid"] for r in stats["near_misses"]]
    assert 101 not in [r["pid"] for r in stats["near_misses"]]
    scores = [r["score"] for r in stats["near_misses"]]
    assert scores == sorted(scores, reverse=True)


def test_scan_counts_processes_that_vanish_mid_scan(monkeypatch):
    """A process whose attribute dict cannot be read must be counted and
    skipped -- never allowed to abort the scan and leave the user no report."""
    class _VanishedProc:
        pid = 201

        @property
        def info(self):
            raise psutil.NoSuchProcess(201)

    monkeypatch.setattr(kd.psutil, "process_iter", lambda attrs=None: iter([_VanishedProc()]))
    monkeypatch.setattr(kd, "get_visible_window_pids", lambda: set())
    monkeypatch.setattr(kd, "IS_WINDOWS", False)

    stats = {}
    results = kd.scan(min_score=4, deep=False, stats=stats)
    assert results == []
    assert stats["total"] == 1
    assert stats["vanished"] == 1


def test_scan_without_stats_still_works(monkeypatch):
    """The stats argument is optional; omitting it must not break callers."""
    monkeypatch.setattr(kd.psutil, "process_iter",
                        lambda attrs=None: iter([_ScanProc(301, "calc.exe", _REAL_EXE)]))
    monkeypatch.setattr(kd, "get_visible_window_pids", lambda: set())
    monkeypatch.setattr(kd, "IS_WINDOWS", False)
    assert kd.scan(min_score=4, deep=False) == []


# --------------------------------------------------------------------------
# Output is ASCII-only — a cp437/cp850 console must never crash mid-report
# --------------------------------------------------------------------------

def test_printed_output_is_ascii_only(capsys, monkeypatch):
    """Every line the tool prints must survive a legacy Windows code page.
    Non-ASCII here would raise UnicodeEncodeError on someone else's machine."""
    monkeypatch.setattr(kd, "IS_WINDOWS", True)
    kd.print_banner(4, False, False)
    kd.print_banner(9, True, True)
    kd.print_scan_stats({"total": 3, "restricted": 1, "vanished": 1,
                         "elapsed": 1.5, "window_map": False}, False)

    flagged = [{"pid": 1, "name": "winkeylog.exe", "exe": r"C:\Temp\winkeylog.exe",
                "user": "me", "score": 13, "risk": "HIGH",
                "reasons": [r"[+4] Process name matches keylogger pattern 'key\s*log'"]}]
    near = {"near_misses": [{"pid": 2, "name": "nethook.exe", "score": 2,
                             "reasons": ["[+2] Generic name (detail)"]}]}
    kd.print_verdict(flagged, near, 4, 5)
    kd.print_verdict([], near, 4, 5)
    kd.print_verdict([], {"near_misses": []}, 4, 5)

    out = capsys.readouterr().out
    assert out.strip()
    out.encode("cp437")        # raises UnicodeEncodeError if any char is non-ASCII
    assert all(ord(ch) < 128 for ch in out)
