"""
Unit tests for keylogger_detector heuristics.

These exercise the pure scoring functions with synthetic process metadata —
no real processes are inspected — so they run fast and deterministically on
any platform / in CI.

    python -m pytest tests/ -q
"""

from collections import namedtuple

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
