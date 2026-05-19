"""Launch and manage the bundled tor process via :mod:`stem`."""

from __future__ import annotations

import logging
import threading
from contextlib import suppress
from pathlib import Path
from subprocess import Popen
from typing import Callable

import stem.process
from stem.control import Controller

from .config import DriverConfig
from .exceptions import DriverConfigError, TorBootstrapTimeout

log = logging.getLogger(__name__)


_BOOTSTRAP_LINE_TOKENS = ("Bootstrapped", "Problem", "[warn]", "[err]")


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

    On Windows :func:`stem.process.launch_tor_with_config` cannot honour a
    timeout: passing ``timeout`` there raises immediately. To keep behaviour
    uniform across platforms the call always passes ``timeout=None`` and a
    watchdog thread terminates the process if bootstrap does not finish in
    ``bootstrap_timeout`` seconds.

    ``take_ownership=False`` is also deliberate. In earlier smoke tests
    enabling take-ownership caused the bundled tor to exit after subsequent
    control-port traffic; the driver manages the process lifetime explicitly
    instead.
    """

    handler = init_msg_handler or _default_init_handler

    tor_data = config.tor_data_dir
    if tor_data is None:
        raise DriverConfigError(
            "DriverConfig.tor_data_dir must be set before launch_tor; the "
            "driver context manager allocates a session directory."
        )
    Path(tor_data).mkdir(parents=True, exist_ok=True)

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

    process = stem.process.launch_tor_with_config(
        tor_cmd=str(config.tor_path),
        config=tor_config,
        init_msg_handler=_watch,
        timeout=None,
        take_ownership=False,
        close_output=False,
    )

    # If stem returned without seeing "Bootstrapped 100%" but tor is still
    # running, hold here until the watchdog fires. In practice stem already
    # blocks until bootstrap completes; the timer is a safety net for the
    # Windows path where stem's own timeout argument is unavailable.
    if not bootstrap_done.is_set() and process.poll() is None:
        if not bootstrap_done.wait(timeout=bootstrap_timeout):
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
