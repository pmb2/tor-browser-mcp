"""Launch and manage the bundled tor process via :mod:`stem`."""

from __future__ import annotations

import logging
import os
import platform
import re
import socket
import subprocess
import threading
from contextlib import closing, contextmanager, suppress
from pathlib import Path
from typing import TYPE_CHECKING

import stem.process
from stem.control import Controller

from ._process_guardian import ProcessGuardian
from .exceptions import DriverConfigError, TorBootstrapTimeout

if TYPE_CHECKING:
    from collections.abc import Callable
    from subprocess import Popen

    from .config import DriverConfig

log = logging.getLogger(__name__)


_BOOTSTRAP_LINE_TOKENS = ("Bootstrapped", "Problem", "[warn]", "[err]")


@contextmanager
def _tor_lib_env(tor_dir: Path):
    """Temporarily prepend *tor_dir* to ``LD_LIBRARY_PATH`` on Linux.

    The bundled tor binary links against libevent and OpenSSL shipped inside
    the bundle.  Those libraries are not on the system library path, so the
    dynamic linker fails with exit 127 unless the bundle directory is
    prepended.  stem launches tor via :mod:`subprocess` without an explicit
    ``env=`` argument, so it inherits whatever ``os.environ`` holds at call
    time.  This context manager sets the variable before the stem call and
    restores the original value (or removes the variable if it was absent)
    after the call returns or raises.
    """
    if platform.system() != "Linux":
        yield
        return

    key = "LD_LIBRARY_PATH"
    old = os.environ.get(key)
    prepend = str(tor_dir)
    os.environ[key] = prepend + os.pathsep + old if old else prepend
    try:
        yield
    finally:
        if old is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = old


def _default_init_handler(line: str) -> None:
    if any(tok in line for tok in _BOOTSTRAP_LINE_TOKENS):
        log.info("tor: %s", line)


def launch_tor(
    config: DriverConfig,
    *,
    bootstrap_timeout: float = 120.0,
    init_msg_handler: Callable[[str], None] | None = None,
) -> tuple[Popen[bytes], Controller]:
    """Launch the bundled tor and return its process plus an authenticated controller.

    The bundled tor binary at ``<tbb_root>/Browser/TorBrowser/Tor/tor`` is
    launched with a non-standard SOCKS/control port pair (so it does not
    collide with a system tor on 9050/9051), cookie authentication, and the
    GeoIP databases shipped alongside the Tor Browser bundle.

    Before invoking the launcher the function pre-flights both ports. The
    pre-flight distinguishes three cases and turns each into an explicit
    error rather than letting tor itself fail with ``WSAEADDRINUSE``:

    * A previous run's bundled tor is still bound (an orphan from this same
      bundle). The error names the PID and points the user at the recovery
      action.
    * Some other process is listening on one of the ports. The error names
      the port but does not name the foreign PID.
    * Both ports are free. The launcher runs.

    On Windows :func:`stem.process.launch_tor_with_config` cannot honour a
    timeout: passing ``timeout`` there raises immediately. To keep behaviour
    uniform across platforms the call always passes ``timeout=None`` and a
    watchdog thread terminates the process if bootstrap does not finish in
    ``bootstrap_timeout`` seconds.

    ``take_ownership=False`` is also deliberate. In earlier smoke tests
    enabling take-ownership caused the bundled tor to exit after subsequent
    control-port traffic; child containment is handled by the
    :class:`ProcessGuardian` Job Object on Windows instead.
    """

    handler = init_msg_handler or _default_init_handler

    tor_data = config.tor_data_dir
    if tor_data is None:
        raise DriverConfigError(
            "DriverConfig.tor_data_dir must be set before launch_tor; the "
            "driver context manager allocates a session directory."
        )
    Path(tor_data).mkdir(parents=True, exist_ok=True)

    preflight_ports(
        socks_port=config.socks_port,
        control_port=config.control_port,
        expected_tor_exe=config.tor_path,
    )

    tor_config: dict[str, str | list[str]] = {
        "SocksPort": f"127.0.0.1:{config.socks_port}",
        "ControlPort": f"127.0.0.1:{config.control_port}",
        "CookieAuthentication": "1",
        "DataDirectory": str(tor_data),
        "GeoIPFile": str(config.geoip_file),
        "GeoIPv6File": str(config.geoip6_file),
        "ClientUseIPv6": "1",
    }

    log.info(
        "launching bundled tor: socks=%d control=%d data=%s",
        config.socks_port,
        config.control_port,
        tor_data,
    )

    bootstrap_done = threading.Event()

    def _watch(line: str) -> None:
        if "Bootstrapped 100%" in line:
            bootstrap_done.set()
        handler(line)

    with _tor_lib_env(config.tor_path.parent):
        process = stem.process.launch_tor_with_config(
            tor_cmd=str(config.tor_path),
            config=tor_config,
            init_msg_handler=_watch,
            timeout=None,
            take_ownership=False,
            close_output=False,
        )

    ProcessGuardian.instance().adopt(process.pid)

    if (
        not bootstrap_done.is_set()
        and process.poll() is None
        and not bootstrap_done.wait(timeout=bootstrap_timeout)
    ):
        _terminate(process)
        raise TorBootstrapTimeout(
            f"tor did not finish bootstrapping in {bootstrap_timeout:.0f} seconds"
        )

    try:
        controller = Controller.from_port(
            address="127.0.0.1", port=config.control_port
        )
        controller.authenticate()
    except Exception:
        _terminate(process)
        raise

    return process, controller


def _terminate(process: Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    with suppress(Exception):
        process.terminate()
    try:
        process.wait(timeout=20)
    except Exception:
        with suppress(Exception):
            process.kill()
        with suppress(Exception):
            process.wait(timeout=10)


def shutdown_tor(process: Popen[bytes], controller: Controller | None) -> None:
    """Idempotently close ``controller`` and stop the bundled tor process."""

    if controller is not None:
        with suppress(Exception):
            controller.close()
    _terminate(process)


def preflight_ports(
    *, socks_port: int, control_port: int, expected_tor_exe: Path
) -> None:
    """Raise :class:`DriverConfigError` if either port is unavailable.

    When the holder of ``control_port`` answers the tor control protocol
    and its executable path matches ``expected_tor_exe``, the error names
    the orphan PID and the recovery action. Otherwise the error names the
    busy port without speculating about who holds it.
    """

    socks_holder = _probe_port_holder(socks_port)
    control_holder = _probe_port_holder(control_port)

    if socks_holder is None and control_holder is None:
        return

    orphan = _identify_orphan_tor(
        control_port=control_port, expected_tor_exe=expected_tor_exe
    )
    if orphan is not None:
        pid_str = f"pid {orphan.pid}" if orphan.pid is not None else "pid unknown"
        exe_str = str(orphan.exe) if orphan.exe is not None else str(expected_tor_exe)
        kill_hint = (
            f"taskkill /PID {orphan.pid} /F"
            if orphan.pid is not None
            else "kill the stale tor process"
        )
        raise DriverConfigError(
            f"bundled tor already running on 127.0.0.1:{control_port} "
            f"({pid_str}, exe {exe_str}). This is an orphan from a previous "
            f"run that did not shut down cleanly. Run `{kill_hint}` and "
            "retry, or pass --socks-port/--control-port to use a different "
            "port pair."
        )

    busy = [
        str(port)
        for port, holder in (
            (socks_port, socks_holder),
            (control_port, control_holder),
        )
        if holder is not None
    ]
    raise DriverConfigError(
        f"port(s) {', '.join(busy)} on 127.0.0.1 already in use by another "
        "process. Either stop that process or pass --socks-port/"
        "--control-port to use a different port pair."
    )


def _probe_port_holder(port: int) -> bool | None:
    """Return ``True`` if ``port`` is bound on loopback, else ``None``.

    The probe attempts to bind a fresh socket to ``127.0.0.1:port`` with
    ``SO_REUSEADDR`` off. A successful bind is released immediately and
    returns ``None`` (free). A bind failure indicates the port is in use.
    """

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError:
        return True
    else:
        return None
    finally:
        probe.close()


class _OrphanInfo:
    __slots__ = ("exe", "pid")

    def __init__(self, *, pid: int | None, exe: Path | None) -> None:
        self.pid = pid
        self.exe = exe


def _identify_orphan_tor(
    *, control_port: int, expected_tor_exe: Path
) -> _OrphanInfo | None:
    """Return an :class:`_OrphanInfo` if the control port holder is our tor.

    The function first speaks the minimal subset of the tor control
    protocol that distinguishes tor from arbitrary listeners
    (``PROTOCOLINFO 1``). Only when the listener responds with the
    expected ``250-PROTOCOLINFO`` line does it attempt to resolve the
    listener's PID and executable. PID resolution is platform-specific
    and best-effort; if it fails, the function still returns an
    :class:`_OrphanInfo` so the caller can emit a useful diagnostic
    (without a PID) instead of mistaking a confirmed tor for a
    foreign listener.
    """

    if not _speaks_tor_control_protocol(control_port):
        return None

    pid = _tcp_listener_pid("127.0.0.1", control_port)
    if pid is None:
        return _OrphanInfo(pid=None, exe=None)

    exe = _process_exe(pid)
    expected_resolved = expected_tor_exe.resolve(strict=False)
    if exe is not None and exe.resolve(strict=False) == expected_resolved:
        return _OrphanInfo(pid=pid, exe=exe)
    if exe is None:
        return _OrphanInfo(pid=pid, exe=None)
    return None


def _speaks_tor_control_protocol(port: int) -> bool:
    try:
        with closing(socket.create_connection(("127.0.0.1", port), timeout=2.0)) as sock:
            sock.settimeout(2.0)
            sock.sendall(b"PROTOCOLINFO 1\r\n")
            data = b""
            while b"250 OK" not in data and len(data) < 4096:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return False
    return b"250-PROTOCOLINFO" in data


_NETSTAT_LINE = re.compile(
    r"^\s*TCP\s+127\.0\.0\.1:(?P<port>\d+)\s+\S+\s+LISTENING\s+(?P<pid>\d+)\s*$"
)


def _tcp_listener_pid(host: str, port: int) -> int | None:
    """Return the PID listening on ``host:port``, or ``None`` if not resolvable.

    On Windows shells out to ``netstat -ano``. The function is best-effort
    and degrades to ``None`` on any error.
    """

    import platform as _platform

    if _platform.system() != "Windows":
        return _tcp_listener_pid_posix(host, port)
    try:
        completed = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in completed.stdout.splitlines():
        match = _NETSTAT_LINE.match(line)
        if match is None:
            continue
        if int(match.group("port")) != port:
            continue
        return int(match.group("pid"))
    return None


def _tcp_listener_pid_posix(host: str, port: int) -> int | None:
    proc_net = Path("/proc/net/tcp")
    if not proc_net.is_file():
        return None
    try:
        target_hex = _encode_proc_net_endpoint(host, port)
    except OSError:
        return None
    try:
        lines = proc_net.read_text(encoding="ascii", errors="replace").splitlines()
    except OSError:
        return None
    inode: str | None = None
    for line in lines[1:]:
        cols = line.split()
        if len(cols) < 10:
            continue
        if cols[1] != target_hex:
            continue
        if cols[3] != "0A":
            continue
        inode = cols[9]
        break
    if inode is None:
        return None
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            fd_dir = entry / "fd"
            try:
                fds = list(fd_dir.iterdir())
            except OSError:
                continue
            for fd in fds:
                try:
                    target = str(fd.readlink())
                except OSError:
                    continue
                if target == f"socket:[{inode}]":
                    return int(entry.name)
    except OSError:
        return None
    return None


def _encode_proc_net_endpoint(host: str, port: int) -> str:
    packed = socket.inet_aton(host)
    little_endian = packed[::-1].hex().upper()
    return f"{little_endian}:{port:04X}"


def _process_exe(pid: int) -> Path | None:
    import platform as _platform

    if _platform.system() == "Windows":
        return _process_exe_windows(pid)
    try:
        return Path(f"/proc/{pid}/exe").readlink()
    except OSError:
        return None


def _process_exe_windows(pid: int) -> Path | None:
    """Resolve a PID's executable image path via ``QueryFullProcessImageNameW``.

    Uses ``ctypes`` rather than shelling out to ``wmic``/PowerShell so the
    lookup is fast and does not pull in subprocess overhead on the common
    "ports are free" path.
    """

    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    process_query_limited_information = 0x1000

    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    query = kernel32.QueryFullProcessImageNameW
    query.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    query.restype = wintypes.BOOL

    handle = open_process(process_query_limited_information, False, pid)
    if not handle:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        ok = query(handle, 0, buf, ctypes.byref(size))
        if not ok:
            return None
        return Path(buf.value)
    finally:
        close_handle(handle)
