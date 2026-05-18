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

import secrets
import socket

from ._core_primitives import _CoreCapabilityMixin
from ._diagnostics_primitives import _DiagnosticsCapabilityMixin
from ._extract_primitives import _ExtractCapabilityMixin
from ._helper_extension_bridge import HelperBridge
from ._helper_extension_install import (
    install_helper,
    prepare_helper_install,
    uninstall_helper,
)
from ._helper_extension_primitives import _HelperExtensionCapabilityMixin
from ._highlight_primitives import _HighlightCapabilityMixin
from ._http_over_tor_primitives import _HttpOverTorCapabilityMixin
from ._network_observe_primitives import _NetworkObserveCapabilityMixin
from ._pdf_primitives import _PdfCapabilityMixin
from ._state_primitives import _StateCapabilityMixin
from ._tor_primitives import _TorCapabilityMixin
from ._tor_routing_primitives import _TorRoutingCapabilityMixin
from ._unsafe_primitives import _UnsafeCapabilityMixin
from ._vision_primitives import _VisionCapabilityMixin
from .browser_process import launch_browser
from .config import DriverConfig
from .exceptions import BrowserLaunchError
from .tor_process import launch_tor, shutdown_tor

log = logging.getLogger(__name__)


class TorBrowserDriver(
    _CoreCapabilityMixin,
    _StateCapabilityMixin,
    _ExtractCapabilityMixin,
    _DiagnosticsCapabilityMixin,
    _TorCapabilityMixin,
    _NetworkObserveCapabilityMixin,
    _VisionCapabilityMixin,
    _HighlightCapabilityMixin,
    _TorRoutingCapabilityMixin,
    _UnsafeCapabilityMixin,
    _PdfCapabilityMixin,
    _HttpOverTorCapabilityMixin,
    _HelperExtensionCapabilityMixin,
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
        self._helper_bridge: HelperBridge | None = None
        self._helper_addon_id: str | None = None

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
            if "helper-extension" in config.enabled_caps:
                self._helper_bridge = self._build_helper_bridge(config)
                prepare_helper_install(self, config, self._helper_bridge)
                try:
                    self._helper_bridge.start()
                except OSError as exc:
                    raise BrowserLaunchError(
                        f"helper-extension bridge failed to bind "
                        f"{self._helper_bridge.host}:{self._helper_bridge.port}: {exc}"
                    ) from exc
            self.webdriver, _ = launch_browser(
                config, session_dir=self._session_dir
            )
            if self._helper_bridge is not None:
                install_helper(self, config, self._helper_bridge)
        except Exception:  # pragma: no cover - teardown branch
            self.close()
            raise
        return self

    @staticmethod
    def _allocate_localhost_port(host: str) -> int:
        """Bind a transient socket to ``host:0`` and return the kernel-chosen port."""

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((host, 0))
            return probe.getsockname()[1]
        finally:
            probe.close()

    def _build_helper_bridge(self, config: DriverConfig) -> HelperBridge:
        host = config.helper_bridge_host
        port = config.helper_bridge_port
        if port is None:
            port = self._allocate_localhost_port(host)
        token = secrets.token_hex(16)
        return HelperBridge(host=host, port=port, token=token)

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

        if self._helper_bridge is not None:
            with suppress(Exception):
                uninstall_helper(self, self.config, self._helper_bridge)
            self._helper_bridge = None

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
