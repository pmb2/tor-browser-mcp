"""Composed Tor Browser driver context manager."""

from __future__ import annotations

import dataclasses
import logging
import os
import secrets
import shutil
import socket
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

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
from ._proxy_intercept_ca import generate_session_ca
from ._proxy_intercept_policies import (
    install_certificate_policy,
    restore_certificate_policy,
)
from ._proxy_intercept_primitives import _ProxyInterceptCapabilityMixin
from ._proxy_intercept_substrate import ProxyManager
from ._state_primitives import _StateCapabilityMixin
from ._tor_primitives import _TorCapabilityMixin
from ._tor_routing_primitives import _TorRoutingCapabilityMixin
from ._tor_security_primitives import _TorSecurityCapabilityMixin
from ._unsafe_primitives import _UnsafeCapabilityMixin
from ._vision_primitives import _VisionCapabilityMixin
from .browser_process import launch_browser
from .exceptions import BrowserLaunchError, ProxyInterceptError
from .tor_process import launch_tor, shutdown_tor

if TYPE_CHECKING:
    from subprocess import Popen
    from types import TracebackType

    from selenium import webdriver
    from stem.control import Controller

    from .config import DriverConfig

log = logging.getLogger(__name__)


class TorBrowserDriver(
    _CoreCapabilityMixin,
    _StateCapabilityMixin,
    _ExtractCapabilityMixin,
    _DiagnosticsCapabilityMixin,
    _TorCapabilityMixin,
    _TorSecurityCapabilityMixin,
    _NetworkObserveCapabilityMixin,
    _VisionCapabilityMixin,
    _HighlightCapabilityMixin,
    _TorRoutingCapabilityMixin,
    _UnsafeCapabilityMixin,
    _PdfCapabilityMixin,
    _HttpOverTorCapabilityMixin,
    _HelperExtensionCapabilityMixin,
    _ProxyInterceptCapabilityMixin,
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
        self._proxy_manager: ProxyManager | None = None
        self._proxy_ca_pem_path: Path | None = None
        self._proxy_ca_fingerprint: str | None = None
        self._policies_snapshot_dir: Path | None = None

    def __enter__(self) -> TorBrowserDriver:
        _reap_stale_session_dirs()
        self._session_dir = Path(tempfile.mkdtemp(prefix="torbrowser-driver-"))
        self._owns_session_dir = True

        config = self.config
        if config.tor_data_dir is None:
            tor_data = self._session_dir / "tor-data"
            tor_data.mkdir(parents=True, exist_ok=True)
            config = dataclasses.replace(config, tor_data_dir=tor_data)
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
            if "proxy-intercept" in config.enabled_caps:
                self._start_proxy_intercept(config)
            self.webdriver, _ = launch_browser(
                config, session_dir=self._session_dir
            )
            if self._helper_bridge is not None:
                install_helper(self, config, self._helper_bridge)
        except Exception:  # pragma: no cover - teardown branch
            self.close()
            raise
        return self

    def _start_proxy_intercept(self, config: DriverConfig) -> None:
        """Generate the CA, install policies.json, and boot the intercept proxy.

        Pre-probes the tor SOCKS endpoint so a tor-bootstrap failure
        surfaces as a clear error rather than a downstream mitmproxy
        upstream failure. ``self._proxy_manager``,
        ``self._proxy_ca_pem_path``, ``self._proxy_ca_fingerprint``,
        and ``self._policies_snapshot_dir`` are populated on success.
        """

        assert self._session_dir is not None
        session_dir = self._session_dir

        ca_dir = session_dir / "intercept-ca"
        ca_pem_path, fingerprint = generate_session_ca(ca_dir)
        self._proxy_ca_pem_path = ca_pem_path
        self._proxy_ca_fingerprint = fingerprint

        snapshot_dir = session_dir / "policies-snapshot"
        install_certificate_policy(
            tbb_root=config.tbb_root,
            ca_pem_path=ca_pem_path,
            snapshot_dir=snapshot_dir,
        )
        self._policies_snapshot_dir = snapshot_dir

        self._probe_socks_reachable("127.0.0.1", config.socks_port)

        manager = ProxyManager(
            listen_host="127.0.0.1",
            listen_port=config.intercept_port,
            socks_host="127.0.0.1",
            socks_port=config.socks_port,
            max_flows=1000,
            ca_dir=ca_dir,
        )
        manager.start()
        self._proxy_manager = manager

    @staticmethod
    def _probe_socks_reachable(host: str, port: int) -> None:
        """Open a transient TCP connect to ``host:port`` to confirm tor is up.

        The probe is intentionally minimal: it asserts the SOCKS
        listener accepts TCP. The full SOCKS handshake happens later
        when mitmproxy dials its first flow.
        """

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(5.0)
        try:
            probe.connect((host, port))
        except OSError as exc:
            raise ProxyInterceptError(
                f"tor SOCKS endpoint {host}:{port} is not reachable: {exc}"
            ) from exc
        finally:
            probe.close()

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

        if self._proxy_manager is not None:
            try:
                self._proxy_manager.stop()
            except Exception:
                log.exception("intercept proxy stop raised during teardown")
            self._proxy_manager = None

        if self._policies_snapshot_dir is not None:
            try:
                restore_certificate_policy(
                    tbb_root=self.config.tbb_root,
                    snapshot_dir=self._policies_snapshot_dir,
                )
            except Exception:
                log.exception("policies.json restore raised during teardown")
            self._policies_snapshot_dir = None

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
                _secure_wipe_dir(self._session_dir, passes=1)


def _secure_wipe_dir(path: Path, passes: int = 1) -> None:
    """Overwrite all files in *path* with random data before deletion.

    Performs *passes* overwrite passes (default 1 for speed; 3 for
    paranoid). Directories themselves are removed with ``rmtree`` after
    their contents have been scrubbed. Best-effort: any error during
    wipe is suppressed so teardown can continue.
    """
    if not path.is_dir():
        return
    try:
        for root_str, dirs, files in os.walk(str(path), topdown=False):
            root = Path(root_str)
            for name in files:
                fpath = root / name
                try:
                    _secure_wipe_file(fpath, passes)
                except Exception:
                    pass
            for name in dirs:
                try:
                    dpath = root / name
                    _secure_wipe_dir(dpath, passes)
                except Exception:
                    pass
    except Exception:
        pass
    shutil.rmtree(path, ignore_errors=True)


def _secure_wipe_file(path: Path, passes: int = 1) -> None:
    """Overwrite *path* with random data *passes* times, then unlink."""
    if not path.is_file():
        return
    length = path.stat().st_size
    if length < 1:
        path.unlink(missing_ok=True)
        return
    for _ in range(passes):
        try:
            with open(path, "wb") as f:
                f.write(os.urandom(length))
        except Exception:
            pass
    path.unlink(missing_ok=True)


_STALE_SESSION_DIR_MAX_AGE_SECONDS = 24 * 3600


def _reap_stale_session_dirs(
    *,
    tempdir: Path | None = None,
    max_age_seconds: float = _STALE_SESSION_DIR_MAX_AGE_SECONDS,
) -> list[Path]:
    """Delete abandoned ``torbrowser-driver-*`` temp dirs older than ``max_age_seconds``.

    Best-effort: any error during enumeration or removal is suppressed.
    Returns the list of paths that were removed (mainly for tests).
    """

    import time

    base = tempdir if tempdir is not None else Path(tempfile.gettempdir())
    now = time.time()
    removed: list[Path] = []
    try:
        candidates = list(base.iterdir())
    except OSError:
        return removed
    for entry in candidates:
        if not entry.name.startswith("torbrowser-driver-"):
            continue
        try:
            age = now - entry.stat().st_mtime
        except OSError:
            continue
        if age < max_age_seconds:
            continue
        try:
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)
        except OSError:
            continue
        else:
            removed.append(entry)
    return removed
