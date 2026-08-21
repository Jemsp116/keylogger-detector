"""Throwaway probe: how many processes are attached to our console?

Frozen with PyInstaller --onefile and launched three ways (double-click via
`start`, from cmd, from git-bash) to find out what GetConsoleProcessList
actually returns for a onefile build. Deleted after the experiment.
"""
import ctypes
import os
import sys
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32
kernel32.GetConsoleProcessList.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
kernel32.GetConsoleProcessList.restype = wintypes.DWORD

buf = (wintypes.DWORD * 16)()
count = kernel32.GetConsoleProcessList(buf, 16)
pids = [buf[i] for i in range(min(count, 16))]

names = []
try:
    import psutil
    for p in pids:
        try:
            names.append("%s(%d)" % (psutil.Process(p).name(), p))
        except Exception:
            names.append("?(%d)" % p)
except Exception as exc:
    names = ["psutil failed: %s" % exc]

lines = [
    "argv0        : %s" % sys.argv[0],
    "frozen       : %s" % getattr(sys, "frozen", False),
    "own pid      : %d" % os.getpid(),
    "console count: %d" % count,
    "console pids : %s" % ", ".join(names),
    "stdin isatty : %s" % sys.stdin.isatty(),
    "stdout isatty: %s" % sys.stdout.isatty(),
]
out = os.environ.get("PROBE_OUT", "probe_result.txt")
with open(out, "a", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n" + "-" * 50 + "\n")
print("\n".join(lines))
