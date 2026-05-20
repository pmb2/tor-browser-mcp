"""Cross-platform container that kills adopted child processes on parent exit.

On Windows a Job Object with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` is the
canonical primitive: closing the last handle to the job (which happens
when the Python parent dies for any reason) terminates every process that
was assigned to it. Child processes spawned by job members are themselves
in the job by default, so geckodriver's firefox grandchild is covered
without additional bookkeeping.

On POSIX a process-group plus an ``atexit`` ``SIGTERM`` covers ordinary
exit and ``Ctrl-C``. A truly hard kill of the Python parent (``SIGKILL``,
segfault) cannot run cleanup code; on Linux the equivalent of the Windows
job is ``prctl(PR_SET_PDEATHSIG)``, but that has to run in the child after
fork — which we cannot inject into ``stem.process.launch_tor_with_config``.
For now the POSIX path is best-effort.
"""

from __future__ import annotations

import atexit
import logging
import os
import signal
import sys
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

log = logging.getLogger(__name__)


class ProcessGuardian:
    """Adopt child PIDs so they die when this process dies.

    The guardian is intentionally process-global: a single Job Object on
    Windows is shared by every driver session in the same Python process.
    Closing the Python process closes the job handle and the kernel reaps
    everything that was assigned. Multiple driver sessions in the same
    process therefore all hang off the same job — that is fine, since they
    all want the same parent-lifetime contract.
    """

    _instance: ProcessGuardian | None = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._adopted: set[int] = set()
        self._job_handle: int | None = None
        self._closed = False
        if sys.platform == "win32":
            self._job_handle = _create_windows_job()
            if self._job_handle is not None:
                atexit.register(self._close_atexit)
        else:
            self._pgid: int | None = None
            getpgrp = getattr(os, "getpgrp", None)
            if getpgrp is not None:
                try:
                    self._pgid = getpgrp()
                except OSError:
                    self._pgid = None
            atexit.register(self._close_atexit)

    @classmethod
    def instance(cls) -> ProcessGuardian:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def adopt(self, pid: int) -> bool:
        """Assign ``pid`` to the kill-on-parent-exit container.

        Returns ``True`` if assignment succeeded, ``False`` otherwise. A
        failure here is logged at WARNING and does not raise: the driver
        still works, the guarantee just degrades to "best effort".
        """

        if pid <= 0:
            return False
        with self._lock:
            if pid in self._adopted:
                return True
            if sys.platform == "win32":
                ok = self._job_handle is not None and _assign_to_job(
                    self._job_handle, pid
                )
            else:
                ok = self._adopt_posix(pid)
            if ok:
                self._adopted.add(pid)
            else:
                log.warning(
                    "ProcessGuardian: failed to adopt pid %d; "
                    "containment is best-effort for this child",
                    pid,
                )
            return ok

    def adopted_pids(self) -> frozenset[int]:
        with self._lock:
            return frozenset(self._adopted)

    def _adopt_posix(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    def _close_atexit(self) -> None:
        if self._closed:
            return
        self._closed = True
        if sys.platform == "win32":
            if self._job_handle is not None:
                _close_windows_job(self._job_handle)
                self._job_handle = None
        else:
            self._signal_posix(signal.SIGTERM)

    def _signal_posix(self, sig: int) -> None:
        with self._lock:
            pids = list(self._adopted)
        for pid in pids:
            try:
                os.kill(pid, sig)
            except OSError:
                pass


def _create_windows_job() -> int | None:
    """Create a Job Object with ``KILL_ON_JOB_CLOSE``.

    Returns the raw HANDLE as an integer (``ctypes`` treats handles as
    ``c_void_p``) or ``None`` if any Win32 call failed. Failure is logged
    once at WARNING; the caller falls back to no containment.
    """

    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    create_job.restype = wintypes.HANDLE

    set_info = kernel32.SetInformationJobObject
    set_info.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_info.restype = wintypes.BOOL

    handle = create_job(None, None)
    if not handle:
        err = ctypes.get_last_error()
        log.warning("CreateJobObjectW failed (err=%d); child containment disabled", err)
        return None

    job_info = _JobObjectExtendedLimitInformation()
    job_info.BasicLimitInformation.LimitFlags = (
        _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_BREAKAWAY_OK
    )

    ok = set_info(
        handle,
        _JobObjectExtendedLimitInformationClass,
        ctypes.byref(job_info),
        ctypes.sizeof(job_info),
    )
    if not ok:
        err = ctypes.get_last_error()
        log.warning(
            "SetInformationJobObject failed (err=%d); child containment disabled",
            err,
        )
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        close_handle(handle)
        return None

    return int(handle)


def _assign_to_job(job_handle: int, pid: int) -> bool:
    if sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    process_set_quota = 0x0100
    process_terminate = 0x0001

    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE

    assign = kernel32.AssignProcessToJobObject
    assign.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    assign.restype = wintypes.BOOL

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    process_handle = open_process(
        process_set_quota | process_terminate, False, pid
    )
    if not process_handle:
        err = ctypes.get_last_error()
        log.warning("OpenProcess(pid=%d) failed (err=%d)", pid, err)
        return False
    try:
        ok = assign(job_handle, process_handle)
        if not ok:
            err = ctypes.get_last_error()
            log.warning(
                "AssignProcessToJobObject(pid=%d) failed (err=%d)", pid, err
            )
            return False
        return True
    finally:
        close_handle(process_handle)


def _close_windows_job(handle: int) -> None:
    if sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    close_handle(handle)


# Win32 constants and structures. Defined unconditionally at import time
# so the platform-gated functions above stay readable; ctypes is only
# touched inside those functions.

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
_JobObjectExtendedLimitInformationClass = 9


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JobObjectBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JobObjectExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JobObjectBasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]
else:
    # On non-Windows the structure is never instantiated. A trivial stand-in
    # keeps the symbol importable so the platform-gated code paths above
    # do not need additional branching.
    class _JobObjectExtendedLimitInformation:
        pass


def adopt_pids(pids: Iterable[int]) -> None:
    """Adopt every pid in ``pids`` into the process-wide guardian."""

    guardian = ProcessGuardian.instance()
    for pid in pids:
        guardian.adopt(pid)
