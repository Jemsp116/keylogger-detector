@echo off
rem Throwaway: launch the exe in its OWN console window, the way a
rem double-click does, so we can observe whether it waits before closing.
start "kd-double-click-test" dist\keylogger-detector.exe --top 2
