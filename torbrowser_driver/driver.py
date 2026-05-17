"""Composed Tor Browser driver context manager."""

from __future__ import annotations

import logging
import shutil
import tempfile
from contextlib import suppress
from pathlib import Path
from subprocess import Popen
from types import TracebackType

from selenium import webdriver
from stem.control import Controller

from ._core_primitives import _CoreCapabilityMixin
from ._diagnostics_primitives import _DiagnosticsCapabilityMixin
from ._extract_primitives import _ExtractCapabilityMixin
from ._network_observe_primitives import _NetworkObserveCapabilityMixin
from ._state_primitives import _StateCapabilityMixin
from ._tor_primitives import _TorCapabilityMixin
from .browser_process import launch_browser
from .config import DriverConfig
from .tor_process import launch_tor, shutdown_tor

log = logging.getLogger(__name__)


class TorBrowserDriver(
    _CoreCapabilityMixin,
    _StateCapabilityMixin,
    _ExtractCapabilityMixin,
    _DiagnosticsCapabilityMixin,
    _TorCapabilityMixin,
    _NetworkObserveCapabilityMixin,
):
    """Boot tor + Tor Browser, expose the underlying selenium/stem handles.

    Used as a context manager. On enter, the driver:

    1. Allocates a per-session work directory (an ephemeral profile copy
       and the bundled-tor ``DataDirectory`` both live under it when the
       caller did not specify their own).
    2. Launches the bundled tor through :mod:`stem` and waits for bootstrap.
    3. Launches geckodriver and Tor Browser, configured to send all traffic
       to the just-launched tor's SOCKS port.

    On exit (and on enter-side failures), every resource that was started
    is torn down, in reverse order, regardless of exceptions. The teardown
    is idempotent so calling :meth:`close` directly is safe.
    """

    def __init__(self, config: DriverConfig) -> None:
        self.config = config
        self.webdriver: webdriver.Firefox | None = None
        self.controller: Controller | None = None
        self._tor_process: Popen[bytes] | None = None
        self._session_dir: Path | None = None
        self._owns_session_dir = False
        self._owns_tor_data_dir = False
        self._closed = False

    def __enter__(self) -> "TorBrowserDriver":
        self._session_dir = Path(tempfile.mkdtemp(prefix="torbrowser-driver-"))
        self._owns_session_dir = True

        config = self.config
        if config.tor_data_dir is None:
            tor_data = self._session_dir / "tor-data"
            tor_data.mkdir(parents=True, exist_ok=True)
            config = type(config)(  # frozen dataclass shallow copy with override
                **{**config.__dict__, "tor_data_dir": tor_data}
            )
            self._owns_tor_data_dir = True
            self.config = config

        try:
            self._tor_process, self.controller = launch_tor(config)
            self.webdriver, _ = launch_browser(
                config, session_dir=self._session_dir
            )
        except Exception:
            self.close()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Shut down the browser, controller, and bundled tor.

        Safe to call multiple times. Errors from any one component do not
        prevent the others from being cleaned up.
        """

        if self._closed:
            return
        self._closed = True

        if self.webdriver is not None:
            with suppress(Exception):
                self.webdriver.quit()
            self.webdriver = None

        if self._tor_process is not None:
            shutdown_tor(self._tor_process, self.controller)
            self._tor_process = None
            self.controller = None
        elif self.controller is not None:
            with suppress(Exception):
                self.controller.close()
            self.controller = None

        if self._owns_session_dir and self._session_dir is not None:
            with suppress(Exception):
                shutil.rmtree(self._session_dir, ignore_errors=True)
