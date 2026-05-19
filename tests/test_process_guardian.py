"""Tests for the ``ProcessGuardian`` cross-platform child container."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import time

import pytest

from torbrowser_driver._process_guardian import ProcessGuardian

IS_WINDOWS = platform.system() == "Windows"


def test_singleton_returns_same_instance() -> None:
    g1 = ProcessGuardian.instance()
    g2 = ProcessGuardian.instance()
    assert g1 is g2


def test_adopt_negative_or_zero_pid_is_rejected() -> None:
    guardian = ProcessGuardian.instance()
    assert guardian.adopt(0) is False
    assert guardian.adopt(-1) is False
    assert 0 not in guardian.adopted_pids()


def test_adopt_is_idempotent() -> None:
    guardian = ProcessGuardian.instance()
    pid = os.getpid()
    first = guardian.adopt(pid)
    second = guardian.adopt(pid)
    assert first == second
    assert pid in guardian.adopted_pids()


@pytest.mark.skipif(not IS_WINDOWS, reason="Job Object semantics only meaningful on Windows")
def test_windows_job_kills_orphan_when_handle_closes(tmp_path) -> None:
    """A child adopted by a guardian dies when the guardian's job handle closes.

    Spawns a private Python interpreter that creates a guardian, spawns a
    long-sleeping subprocess, adopts the subprocess into the guardian, and
    exits without cleanup. The Job Object's ``KILL_ON_JOB_CLOSE`` flag
    should reap the subprocess when the parent interpreter exits.
    """

    helper = tmp_path / "spawn.py"
    helper.write_text(
        "import subprocess, sys, time\n"
        "from torbrowser_driver._process_guardian import ProcessGuardian\n"
        "guardian = ProcessGuardian.instance()\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        "guardian.adopt(child.pid)\n"
        "print(child.pid, flush=True)\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(helper)],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    child_pid = int(proc.stdout.strip())

    deadline = time.time() + 10.0
    while time.time() < deadline:
        if not _windows_pid_alive(child_pid):
            return
        time.sleep(0.2)
    pytest.fail(f"orphan pid {child_pid} survived parent exit")


def _windows_pid_alive(pid: int) -> bool:
    if not IS_WINDOWS:
        return False
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    process_query_limited_information = 0x1000
    still_active = 259

    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE

    get_exit_code = kernel32.GetExitCodeProcess
    get_exit_code.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    get_exit_code.restype = wintypes.BOOL

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = open_process(process_query_limited_information, False, pid)
    if not handle:
        return False
    try:
        code = wintypes.DWORD()
        if not get_exit_code(handle, ctypes.byref(code)):
            return False
        return code.value == still_active
    finally:
        close_handle(handle)
