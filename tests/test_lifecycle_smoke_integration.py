"""Integration smoke for child-process containment under hard parent kill.

Opt-in: skipped unless ``TBB_ROOT`` is set. Run with ``pytest -m integration``.

The test spawns a child Python interpreter that enters the
:class:`TorBrowserDriver` context, then terminates that subprocess
abruptly (``kill``) without giving it a chance to run ``__exit__``. The
guardian Job Object (Windows) / process group (POSIX) should reap every
descendant. The test asserts no bundled ``tor``, ``geckodriver``, or
``firefox`` from the configured ``TBB_ROOT`` is still running after the
parent has been killed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


IS_WINDOWS = sys.platform == "win32"


def _list_descendant_image_paths(tbb_root: Path) -> list[Path]:
    """Return image paths of running processes that live under ``tbb_root``."""

    if IS_WINDOWS:
        return _list_descendant_image_paths_windows(tbb_root)
    return _list_descendant_image_paths_posix(tbb_root)


def _list_descendant_image_paths_windows(tbb_root: Path) -> list[Path]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    th32cs_snapprocess = 0x00000002
    invalid_handle_value = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    create_snapshot.restype = wintypes.HANDLE
    process_first = kernel32.Process32FirstW
    process_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    process_first.restype = wintypes.BOOL
    process_next = kernel32.Process32NextW
    process_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    process_next.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    query_image = kernel32.QueryFullProcessImageNameW
    query_image.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    query_image.restype = wintypes.BOOL

    process_query_limited_information = 0x1000
    tbb_resolved = tbb_root.resolve()

    snap = create_snapshot(th32cs_snapprocess, 0)
    if snap == invalid_handle_value:
        return []
    matches: list[Path] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not process_first(snap, ctypes.byref(entry)):
            return []
        while True:
            handle = open_process(
                process_query_limited_information, False, entry.th32ProcessID
            )
            if handle:
                try:
                    buf = ctypes.create_unicode_buffer(32768)
                    size = wintypes.DWORD(len(buf))
                    if query_image(handle, 0, buf, ctypes.byref(size)):
                        path = Path(buf.value)
                        try:
                            path.resolve().relative_to(tbb_resolved)
                        except (OSError, ValueError):
                            pass
                        else:
                            matches.append(path)
                finally:
                    close_handle(handle)
            if not process_next(snap, ctypes.byref(entry)):
                break
    finally:
        close_handle(snap)
    return matches


def _list_descendant_image_paths_posix(tbb_root: Path) -> list[Path]:
    matches: list[Path] = []
    tbb_resolved = tbb_root.resolve()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            exe = (entry / "exe").readlink()
        except OSError:
            continue
        try:
            exe.resolve().relative_to(tbb_resolved)
        except (OSError, ValueError):
            continue
        matches.append(exe)
    return matches


def test_hard_kill_parent_reaps_children(
    tbb_root: Path, geckodriver_path: Path | None, tmp_path: Path
) -> None:
    """Force-kill the parent Python; bundled tor and geckodriver must die too."""

    output_dir = tmp_path / "out"
    output_dir.mkdir()

    helper = tmp_path / "boot_then_block.py"
    geckodriver_str = repr(str(geckodriver_path)) if geckodriver_path else "None"
    helper.write_text(
        textwrap.dedent(
            f"""
            import sys, time
            from pathlib import Path
            from torbrowser_driver import (
                DriverConfig,
                PathPolicy,
                TorBrowserDriver,
            )

            policy = PathPolicy.from_config(
                output_dir=Path({str(output_dir)!r}),
                cwd=Path({str(tmp_path)!r}),
            )
            config = DriverConfig(
                tbb_root=Path({str(tbb_root)!r}),
                path_policy=policy,
                geckodriver_path=(Path({geckodriver_str}) if {geckodriver_str} else None),
                headless=False,
            )
            drv = TorBrowserDriver(config)
            drv.__enter__()
            print("ready", flush=True)
            time.sleep(600)
            """
        ),
        encoding="utf-8",
    )

    proc = subprocess.Popen(
        [sys.executable, str(helper)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        assert proc.stdout is not None
        deadline = time.time() + 180.0
        ready = False
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    pytest.fail(
                        f"child exited before reporting ready: rc={proc.returncode}"
                    )
                time.sleep(0.1)
                continue
            if line.strip() == "ready":
                ready = True
                break
        if not ready:
            pytest.fail("child did not become ready within 180s")

        if IS_WINDOWS:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/F"],
                capture_output=True,
                check=False,
            )
        else:
            os.kill(proc.pid, 9)

        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)

    deadline = time.time() + 60.0
    last_matches: list[Path] = []
    while time.time() < deadline:
        last_matches = _list_descendant_image_paths(tbb_root)
        if not last_matches:
            return
        time.sleep(1.0)
    pytest.fail(
        "TBB-rooted descendant processes survived parent hard-kill: "
        + ", ".join(str(p) for p in last_matches)
    )
