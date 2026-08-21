#!/usr/bin/env python3
"""
benign_fake_keylogger.py — SAFE detection-test fixture.

*** THIS DOES NOT CAPTURE KEYSTROKES. ***

It installs no keyboard hook, opens no input device, and reads nothing you
type. Its ONLY purpose is to exhibit the harmless, observable *side effects*
a keylogger tends to have — a headless background process holding an open
handle to a log-like file in a temp directory — so you can confirm that
keylogger_detector.py flags it. It simply appends a fixed dummy line on a
timer and keeps the handle open.

Usage:
    python examples/benign_fake_keylogger.py
    # then, in another terminal:
    python keylogger_detector.py --deep --min-score 4
    # stop this fixture with Ctrl-C when done.
"""

import os
import sys
import tempfile
import time


def main():
    demo_dir = os.path.join(tempfile.gettempdir(), "keylog_demo")
    os.makedirs(demo_dir, exist_ok=True)
    log_path = os.path.join(demo_dir, "keys.log")

    print("benign_fake_keylogger — NOT capturing any input (safe demo fixture).")
    print(f"PID {os.getpid()} holding an open handle to: {log_path}")
    print("Scan it with:  python keylogger_detector.py --deep")
    print("Press Ctrl-C to stop.\n")
    sys.stdout.flush()

    # Hold the handle open the way a real logger would, and append on a timer.
    with open(log_path, "a", buffering=1) as fh:
        i = 0
        try:
            while True:
                i += 1
                fh.write(f"[demo {i}] no real keystrokes were captured\n")
                time.sleep(1)
        except KeyboardInterrupt:
            print("stopped.")


if __name__ == "__main__":
    main()
